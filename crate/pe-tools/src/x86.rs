#[allow(non_snake_case)]
use crate::shared::*;

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use pelite::*;
use pelite::pe32::Pe;
use pelite::pe32::exports::GetProcAddress;

use anyhow::*;
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{DWORD, PUCHAR, UCHAR},
        ntdef::{BOOLEAN, HANDLE, LPCSTR, PVOID, ULONG},
    },
    um::{
        memoryapi::{ReadProcessMemory, WriteProcessMemory},
        winnt::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_ORDINAL32, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32, IMAGE_SECTION_HEADER,
            LIST_ENTRY, IMAGE_SNAP_BY_ORDINAL32, IMAGE_THUNK_DATA32,
            PIMAGE_NT_HEADERS32, PIMAGE_SECTION_HEADER, PSTR,
        }
    },
};

#[derive(Debug, PartialEq)]
pub enum X96 {
    X86,
    X64,
    Unknown,
}

#[repr(C)]
pub struct LOADED_IMAGE {
    pub ModuleName: PSTR,
    pub hFile: HANDLE,
    pub MappedAddress: PUCHAR,
    pub FileHeader: PIMAGE_NT_HEADERS32,
    pub LastRvaSection: PIMAGE_SECTION_HEADER,
    pub NumberOfSections: ULONG,
    pub Sections: PIMAGE_SECTION_HEADER,
    pub Characteristics: ULONG,
    pub fSystemImage: BOOLEAN,
    pub fDOSImage: BOOLEAN,
    pub fReadOnly: BOOLEAN,
    pub Version: UCHAR,
    pub Links: LIST_ENTRY,
    pub SizeOfImage: ULONG,
}

pub struct PE_Container<'a> {
    pub target_image_base: *mut c_void,
    pub pe: pelite::pe32::PeView<'a>,
    pub payload_image: LOADED_IMAGE,
    pub payload_buffer: *mut c_void,
}

impl PE_Container<'_> {
    pub fn new(target_image_base: *mut c_void, payload_buffer: *mut c_void) -> PE_Container<'static> {
        let image = unsafe { read_image(payload_buffer) };

        PE_Container {
            target_image_base: target_image_base,
            payload_image: image,
            payload_buffer,
            pe: unsafe { pe32::PeView::module(payload_buffer as _) },
        }
    }

    pub fn payload_base(&self) -> *mut c_void {
        unsafe { (*self.payload_image.FileHeader).OptionalHeader.ImageBase as _ }
    }

    pub fn get_payload_optional_headers(&self) -> IMAGE_OPTIONAL_HEADER32 {
        (unsafe { *self.payload_image.FileHeader }).OptionalHeader
    }

    pub fn get_payload_section_headers(&self) -> &[IMAGE_SECTION_HEADER] {
        unsafe {
            std::slice::from_raw_parts(
                self.payload_image.Sections,
                self.payload_image.NumberOfSections as usize,
            )
        }
    }

    pub fn change_target_image_base(&mut self, new_image_base: *mut c_void) {
        self.target_image_base = new_image_base;
    }

    pub fn change_payload_image_base(&self, new_image_base: *mut c_void) {
        unsafe { (*self.payload_image.FileHeader).OptionalHeader.ImageBase = new_image_base as _ };
    }

    pub fn copy_headers(&self) -> anyhow::Result<()> {
        unsafe {
            for i in 0..self.get_payload_optional_headers().SizeOfHeaders {
                *((self.target_image_base as u32 + i as u32) as *mut u8) = *((self.payload_base() as u32 + i as u32) as *mut u8)
            }
            Ok(())
        }
    }

    pub fn copy_remote_headers(&self, hp: *mut c_void) -> anyhow::Result<()> {
        if unsafe {
            WriteProcessMemory(
                hp,
                self.target_image_base as _,
                self.payload_buffer,
                self.pe.optional_header().SizeOfHeaders as usize,
                null_mut(),
            )
        } == 0
        {
            bail!("could not write process memory.");
        }
        Ok(())
    }

    pub fn copy_section_headers(&self) -> anyhow::Result<()> {
        unsafe {
            for section in self.pe.section_headers().image() {
                let p_dest_section = self.target_image_base as u32 + section.VirtualAddress as u32;
                for i in 0..section.SizeOfRawData {
                    *((p_dest_section + i as u32) as *mut u8) =
                        *((self.payload_base() as u32 + section.PointerToRawData as u32 + i as u32) as *mut u8);
                }
            }
            Ok(())
        }
    }

    pub fn copy_remote_section_headers(&self, hp: *mut c_void) -> anyhow::Result<()> {
        for section in self.pe.section_headers().image() {
            let p_dest_section = self.target_image_base as usize + section.VirtualAddress as usize;
            if unsafe {
                WriteProcessMemory(
                    hp,
                    p_dest_section as *mut _,
                    (self.payload_buffer as usize + section.PointerToRawData as usize)
                        as *const c_void as *mut _,
                    section.SizeOfRawData as usize,
                    null_mut(),
                ) == 0
            } {
                bail!("could not write process memory.");
            }
        }

        Ok(())
    }

    // TODO: check this is correct
    pub fn resolve_import(&self, p_LoadLiberay: pLoadLibraryA, p_GetProcAdress: pGetProcAddress) -> anyhow::Result<()> {
        unsafe {
            let import_directory = (*self.payload_image.FileHeader)
                .OptionalHeader
                .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            let mut import_discriptor = (self.target_image_base as usize
                + import_directory.VirtualAddress as usize)
                as *mut IMAGE_IMPORT_DESCRIPTOR;

            while (*import_discriptor).Name != 0x0 {
                let lib_name = (self.target_image_base as u32 + (*import_discriptor).Name) as LPCSTR;
                let lib = p_LoadLiberay(lib_name);

                let mut orig_thunk = (self.target_image_base as usize
                    + *(*import_discriptor).u.OriginalFirstThunk() as usize)
                    as *mut IMAGE_THUNK_DATA32;
                let mut thunk = (self.target_image_base as usize + (*import_discriptor).FirstThunk as usize)
                    as *mut IMAGE_THUNK_DATA32;

                while (*thunk).u1.AddressOfData() != &0x0 {
                    if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL32(*(*thunk).u1.Ordinal()) {
                        let fn_ordinal = IMAGE_ORDINAL32(*(*thunk).u1.Ordinal()) as LPCSTR;
                        *(*thunk).u1.Function_mut() = p_GetProcAdress(lib, fn_ordinal) as _;
                    } else {
                        let fn_name = (self.target_image_base as u32 + *(*thunk).u1.AddressOfData()) as *mut IMAGE_IMPORT_BY_NAME;
                        *(*thunk).u1.Function_mut() = p_GetProcAdress(lib, (*fn_name).Name[0] as _) as _;
                    }

                    thunk = (thunk as usize + size_of::<DWORD>()) as _;
                    if orig_thunk != null_mut() {
                        orig_thunk = (orig_thunk as usize + size_of::<DWORD>()) as _;
                    }
                }

                import_discriptor = (import_discriptor as usize + size_of::<DWORD>()) as _;
            }

            Ok(())
        }
    }

    // TODO: rewrite with pelite
    pub fn delta_relocation(
        &self,
        delta: Delta
    ) -> anyhow::Result<()> {
        unsafe {
            let sections = self.get_payload_section_headers();

            for section in sections {
                if section.Name != DOT_RELOC {
                    continue;
                }

                let reloc_address = section.PointerToRawData as u32;
                let mut offset = 0 as u32;
                let reloc_data = (*self.payload_image.FileHeader)
                    .OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

                while offset < reloc_data.Size as u32 {
                    let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(
                        (self.payload_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                    );

                    offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32;

                    // 2 is relocation entry size.
                    // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                    let entry_count = (block_header.BlockSize
                        - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32)
                        / 2;

                    let block_entry = std::slice::from_raw_parts::<[u8; 2]>(
                        (self.payload_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                        entry_count as usize,
                    );

                    for block in block_entry {
                        let block = BASE_RELOCATION_ENTRY(*block);

                        offset = offset + 2;

                        if block.block_type() == 0 {
                            continue;
                        }

                        let target = self.target_image_base as u32 + block_header.PageAddress as u32 + block.offset() as u32;
                        if delta.is_minus {
                            *(target as *mut u32) = *(target as *mut u32) - delta.offset as u32;
                        } else {
                            *(target as *mut u32) = *(target as *mut u32) + delta.offset as u32;
                        }
                    }
                }
            }

            Ok(())
        }
    }

    pub fn remote_delta_relocation(
        &self,
        hp: *mut c_void,
        delta: Delta
    ) -> anyhow::Result<()> {
        unsafe {
            let sections = self.get_payload_section_headers();

            for section in sections {
                if section.Name != DOT_RELOC {
                    continue;
                }

                let reloc_address = section.PointerToRawData as usize;
                let mut offset = 0 as usize;
                let reloc_data = (*self.payload_image.FileHeader)
                    .OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

                while offset < reloc_data.Size as usize {
                    let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(
                        (self.payload_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                    );

                    offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as usize;

                    // 2 is relocation entry size.
                    // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                    let entry_count = (block_header.BlockSize
                        - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32)
                        / 2;

                    let block_entry = std::slice::from_raw_parts::<[u8; 2]>(
                        (self.payload_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                        entry_count as usize,
                    );

                    for block in block_entry {
                        let block = BASE_RELOCATION_ENTRY(*block);

                        offset = offset + 2;

                        if block.block_type() == 0 {
                            continue;
                        }

                        let field_address =
                            block_header.PageAddress as usize + block.offset() as usize;

                        let mut d_buffer = 0 as usize;

                        if ReadProcessMemory(
                            hp,
                            (self.target_image_base as usize + field_address) as PVOID,
                            &mut d_buffer as *const _ as *mut _,
                            size_of::<usize>(),
                            null_mut(),
                        ) == 0
                        {
                            bail!("could not read memory from new dest image.")
                        }

                        d_buffer = if delta.is_minus {
                            d_buffer - delta.offset
                        } else {
                            d_buffer + delta.offset
                        };

                        if WriteProcessMemory(
                            hp,
                            (self.target_image_base as usize + field_address) as PVOID,
                            &mut d_buffer as *const _ as *mut _,
                            size_of::<usize>(),
                            null_mut(),
                        ) == 0
                        {
                            bail!("could not write memory to new dest image.")
                        }
                    }
                }
            }

            Ok(())
        }
    }

    pub fn search_proc_address(&self, function_name: impl Into<String>) -> anyhow::Result<*mut c_void> {
        let function_name = function_name.into();
        Ok(self.pe.get_proc_address(&function_name)? as _)
    }
}

pub unsafe fn get_image_base_address(buffer: *mut c_void) -> *mut c_void {
    (*read_image(buffer).FileHeader).OptionalHeader.ImageBase as _
}

pub unsafe fn read_image(buffer: *mut c_void) -> LOADED_IMAGE {
    let mut loaded_image = zeroed::<LOADED_IMAGE>();

    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as _);
    let p_nt_header = buffer as usize + dos_header.e_lfanew as usize;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS32>(p_nt_header as *mut _);
    let p_sections =
        buffer as usize + dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS32>() as usize;

    loaded_image.FileHeader = p_nt_header as *mut IMAGE_NT_HEADERS32;
    loaded_image.NumberOfSections = nt_header.FileHeader.NumberOfSections as u32;
    loaded_image.Sections = p_sections as *mut _;

    loaded_image
}
