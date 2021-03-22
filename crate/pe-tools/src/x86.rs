#[allow(non_snake_case)]
use crate::shared::*;

use std::mem::size_of;
use std::ptr::null_mut;

use anyhow::*;
use pelite::pe32::{
    self, Pe,
    exports::GetProcAddress
};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::DWORD,
        ntdef::{LPCSTR, PVOID},
    },
    um::{
        memoryapi::{ReadProcessMemory, WriteProcessMemory},
        winnt::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_ORDINAL32, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32,
            IMAGE_SNAP_BY_ORDINAL32, IMAGE_THUNK_DATA32,
            PIMAGE_TLS_CALLBACK, DLL_PROCESS_ATTACH
        }
    },
};

#[derive(Debug, PartialEq)]
pub enum X96 {
    X86,
    X64,
    Unknown,
}

pub struct PE_Container<'a> {
    pub target_image_base: *mut c_void,
    pub pe: pelite::pe32::PeView<'a>,
    pub payload_buffer: *mut c_void,
}

impl PE_Container<'_> {
    pub fn new(target_image_base: *mut c_void, payload_buffer: *mut c_void) -> PE_Container<'static> {
        PE_Container {
            target_image_base: target_image_base,
            payload_buffer,
            pe: unsafe { pe32::PeView::module(payload_buffer as _) },
        }
    }

    pub fn payload_base(&self) -> *mut c_void {
        self.get_payload_optional_headers().ImageBase as _
    }

    pub fn get_payload_optional_headers(&self) -> &pelite::image::IMAGE_OPTIONAL_HEADER32 {
        self.pe.optional_header()
    }

    pub fn get_payload_section_headers(&self) -> &[pelite::image::IMAGE_SECTION_HEADER] {
        self.pe.section_headers().image()
    }

    pub fn change_target_image_base(&mut self, new_image_base: *mut c_void) {
        self.target_image_base = new_image_base;
    }

    pub fn refresh_pe(&mut self) {
        self.pe = unsafe { pe32::PeView::module(self.payload_buffer as _) };
    }

    pub fn change_payload_image_base(&mut self, new_image_base: *mut c_void) {
        unsafe {
            let dos_header = self.payload_buffer as *mut IMAGE_DOS_HEADER;
            let nt_header = (self.payload_buffer as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;
            (*nt_header).OptionalHeader.ImageBase = new_image_base as _;
        };
        self.refresh_pe();
    }

    pub fn copy_headers(&self) -> anyhow::Result<()> {
        unsafe {
            for i in 0..self.get_payload_optional_headers().SizeOfHeaders {
                *((self.target_image_base as u64 + i as u64) as *mut u8) = *((self.payload_base() as u64 + i as u64) as *mut u8)
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
            let import_directory = self.pe.data_directory()[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
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
                    if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL32(*(*orig_thunk).u1.Ordinal()) {
                        let fn_ordinal = IMAGE_ORDINAL32(*(*orig_thunk).u1.Ordinal()) as LPCSTR;
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
        Ok(unsafe {
            self.delta_relocation_closure(delta, |target, delta| {
                if delta.is_minus {
                    *(target as *mut u32) = *(target as *mut u32) - delta.offset as u32;
                } else {
                    *(target as *mut u32) = *(target as *mut u32) + delta.offset as u32;
                }
                Ok(())
            })?;
        })
    }

    // TODO: rewrite with pelite
    pub fn remote_delta_relocation(
        &self,
        hp: *mut c_void,
        delta: Delta
    ) -> anyhow::Result<()> {
        Ok(unsafe {
            self.delta_relocation_closure(delta, |target, delta| {
                let mut d_buffer = 0 as u32;

                if ReadProcessMemory(
                    hp,
                    (target) as PVOID,
                    &mut d_buffer as *const _ as *mut _,
                    size_of::<u32>(),
                    null_mut(),
                ) == 0
                {
                    bail!("could not read memory from new dest image.")
                }
                
                d_buffer = if delta.is_minus {
                    d_buffer - delta.offset as u32
                } else {
                    d_buffer + delta.offset as u32
                };

                if WriteProcessMemory(
                    hp,
                    (target) as PVOID,
                    &mut d_buffer as *const _ as *mut _,
                    size_of::<u32>(),
                    null_mut(),
                ) == 0
                {
                    bail!("could not write memory to new dest image.")
                }

                Ok(())
            })?;
        })
    }

    pub fn exec_tls_callback(&self) -> Result<()> {
        for callback in self.pe.tls()?.callbacks()? {
            if *callback == 0 { continue }
            unsafe {
                match std::mem::transmute::<*const c_void, PIMAGE_TLS_CALLBACK>(*(*callback as *const *const c_void)) {
                    Some(cb) => {
                        cb(
                            self.target_image_base,
                            DLL_PROCESS_ATTACH,
                            0 as _,
                        );
                    },
                    None => continue
                }
            }
        }

        Ok(())
    }

    pub fn search_proc_address(&self, function_name: impl Into<String>) -> anyhow::Result<*mut c_void> {
        let function_name = function_name.into();
        Ok(self.pe.get_proc_address(&function_name)? as _)
    }

    fn delta_relocation_closure<T: Fn(u32, &Delta) -> anyhow::Result<()>>(
        &self,
        delta: Delta,
        process_fn: T
    ) -> anyhow::Result<()> {
        unsafe {
            for section in self.pe.section_headers().image() {
                if section.Name != DOT_RELOC {
                    continue;
                }

                let reloc_address = section.PointerToRawData as u32;
                let mut offset = 0 as u32;
                let reloc_data = self.pe.data_directory()[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

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

                        process_fn(self.target_image_base as u32 + block_header.PageAddress as u32 + block.offset() as u32, &delta)?;
                    }
                }
            }
        }

        Ok(())
    }
}
