#[allow(non_snake_case)]
use crate::shared::*;

use std::ffi::CString;
use std::fs::File;
use std::io::prelude::*;
use std::mem::{size_of, size_of_val, zeroed};
use std::ptr::null_mut;

use anyhow::*;
use bitfield;
use ntapi::{
    ntpebteb::{PEB, PPEB},
    ntpsapi::{NtQueryInformationProcess, PROCESS_BASIC_INFORMATION},
};
use winapi::ctypes::c_void;
use winapi::shared::{
    basetsd::DWORD64,
    minwindef::{DWORD, LPCVOID, PUCHAR, UCHAR},
    ntdef::{BOOLEAN, HANDLE, PVOID, ULONG},
};
use winapi::um::{
    errhandlingapi::GetLastError,
    memoryapi::{ReadProcessMemory, VirtualAlloc, VirtualAllocEx, VirtualFree, WriteProcessMemory},
    processthreadsapi::{
        CreateProcessA,
        GetThreadContext,
        ResumeThread,
        SetThreadContext, // SuspendThread
        PROCESS_INFORMATION,
        STARTUPINFOA,
    },
    winbase::{Wow64GetThreadContext, Wow64SetThreadContext, CREATE_SUSPENDED},
    winnt::{
        CONTEXT, CONTEXT_FULL, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
        IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32,
        IMAGE_NT_HEADERS64, IMAGE_ORDINAL32, IMAGE_ORDINAL64, IMAGE_REL_BASED_DIR64,
        IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, IMAGE_SECTION_HEADER,
        IMAGE_SNAP_BY_ORDINAL32, IMAGE_SNAP_BY_ORDINAL64, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64,
        LIST_ENTRY, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PIMAGE_NT_HEADERS32,
        PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER, PSTR, WOW64_CONTEXT, WOW64_CONTEXT_FULL,
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

pub struct PE_Container {
    pub target_base: *mut c_void,
    pub payload_image: LOADED_IMAGE,
    pub payload_buffer: *mut c_void,
}

impl PE_Container {
    pub fn new(target_image_base: *mut c_void, payload_buffer: *mut c_void) -> PE_Container {
        let image = unsafe { read_image(payload_buffer) };

        PE_Container {
            target_base: target_image_base,
            payload_image: image,
            payload_buffer,
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

    pub fn change_imabe_base(&self, new_image_base: *mut c_void) {
        unsafe { (*self.payload_image.FileHeader).OptionalHeader.ImageBase = new_image_base as _ };
    }

    pub fn copy_remote_headers(&self, hp: *mut c_void) -> Result<()> {
        if unsafe {
            WriteProcessMemory(
                hp,
                self.target_base as _,
                self.payload_buffer,
                (*self.payload_image.FileHeader)
                    .OptionalHeader
                    .SizeOfHeaders as usize,
                null_mut(),
            )
        } == 0
        {
            bail!("could not write process memory.");
        }
        Ok(())
    }

    pub fn copy_remote_section_headers(&self, hp: *mut c_void) -> Result<()> {
        let sections = self.get_payload_section_headers();

        for section in sections {
            let p_dest_section = self.target_base as usize + section.VirtualAddress as usize;
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

    pub unsafe fn resolve_import(&self) -> Result<()> {
        let import_directory = (*self.payload_image.FileHeader)
            .OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        let mut import_discriptor = (self.payload_base() as usize
            + import_directory.VirtualAddress as usize)
            as *mut IMAGE_IMPORT_DESCRIPTOR;

        while (*import_discriptor).Name != 0x0 {
            let mut orig_thunk = (self.payload_base() as usize
                + *(*import_discriptor).u.OriginalFirstThunk() as usize)
                as *mut IMAGE_THUNK_DATA32;
            let mut thunk = (self.payload_base() as usize + (*import_discriptor).FirstThunk as usize)
                as *mut IMAGE_THUNK_DATA32;

            while (*thunk).u1.AddressOfData() != &0x0 {
                if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL32(*(*thunk).u1.Ordinal()) {
                    // TODO:
                } else {
                    // TODO:
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

    pub fn remote_delta_relocation(
        &self,
        hp: *mut c_void,
        delta: Delta
    ) -> Result<()> {
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
                            (self.target_base as usize + field_address) as PVOID,
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
                            (self.target_base as usize + field_address) as PVOID,
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
