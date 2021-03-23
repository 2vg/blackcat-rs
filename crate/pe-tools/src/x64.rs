#[allow(non_snake_case)]
use crate::shared::*;

use std::mem::size_of;
use std::ptr::null_mut;

use anyhow::*;
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
    winapi_local::um::winnt::__readgsqword
};
use pelite::pe64::{
    self, Pe,
    exports::GetProcAddress
};
use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::DWORD64,
        ntdef::{LPCSTR, PVOID},
    },
    um::{
        memoryapi::{ReadProcessMemory, WriteProcessMemory},
        winnt::{
            IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_ORDINAL64, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
            IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
            IMAGE_SNAP_BY_ORDINAL64, IMAGE_THUNK_DATA64,
            DLL_PROCESS_ATTACH
        },
    }
};

pub struct PE_Container<'a> {
    pub target_image_base: *mut c_void,
    pub pe: pelite::pe64::PeView<'a>,
    pub payload_buffer: *mut c_void,
}

impl PE_Container<'_> {
    pub fn new(target_image_base: *mut c_void, payload_buffer: *mut c_void) -> PE_Container<'static> {
        PE_Container {
            target_image_base,
            payload_buffer,
            pe: unsafe { pe64::PeView::module(payload_buffer as _) },
        }
    }

    pub fn payload_base(&self) -> *mut c_void {
        self.get_payload_optional_headers().ImageBase as _
    }

    pub fn get_payload_optional_headers(&self) -> &pelite::image::IMAGE_OPTIONAL_HEADER64 {
        self.pe.optional_header()
    }

    pub fn get_payload_section_headers(&self) -> &[pelite::image::IMAGE_SECTION_HEADER] {
        self.pe.section_headers().image()
    }

    pub fn change_target_image_base(&mut self, new_image_base: *mut c_void) {
        self.target_image_base = new_image_base;
    }

    pub fn refresh_pe(&mut self) {
        self.pe = unsafe { pe64::PeView::module(self.payload_buffer as _) };
    }

    pub fn change_payload_image_base(&mut self, new_image_base: *mut c_void) {
        unsafe {
            let dos_header = self.payload_buffer as *mut IMAGE_DOS_HEADER;
            let nt_header = (self.payload_buffer as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
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
                let p_dest_section = self.target_image_base as u64 + section.VirtualAddress as u64;
                for i in 0..section.SizeOfRawData {
                    *((p_dest_section + i as u64) as *mut u8) =
                        *((self.payload_base() as u64 + section.PointerToRawData as u64 + i as u64) as *mut u8);
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
    pub fn resolve_import(&self, p_load_liberay: PLoadLibraryA, p_get_proc_adress: PGetProcAddress) -> anyhow::Result<()> {
        unsafe {
            let import_directory = self.pe.data_directory()[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            let mut import_discriptor = (self.target_image_base as u64
                + import_directory.VirtualAddress as u64)
                as *mut IMAGE_IMPORT_DESCRIPTOR;

            while (*import_discriptor).Name != 0x0 {
                let lib_name = (self.target_image_base as u32 + (*import_discriptor).Name) as LPCSTR;
                let lib = p_load_liberay(lib_name);

                let mut orig_thunk = (self.target_image_base as u64
                    + *(*import_discriptor).u.OriginalFirstThunk() as u64)
                    as *mut IMAGE_THUNK_DATA64;
                let mut thunk = (self.target_image_base as u64 + (*import_discriptor).FirstThunk as u64)
                    as *mut IMAGE_THUNK_DATA64;

                while (*thunk).u1.AddressOfData() != &0x0 {
                    if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL64(*(*orig_thunk).u1.Ordinal()) {
                        let fn_ordinal = IMAGE_ORDINAL64(*(*orig_thunk).u1.Ordinal()) as LPCSTR;
                        *(*thunk).u1.Function_mut() = p_get_proc_adress(lib, fn_ordinal) as _;
                    } else {
                        let fn_name = (self.target_image_base as u64 + *(*thunk).u1.AddressOfData()) as *mut IMAGE_IMPORT_BY_NAME;
                        *(*thunk).u1.Function_mut() = p_get_proc_adress(lib, (*fn_name).Name[0] as _) as _;
                    }

                    thunk = (thunk as usize + size_of::<DWORD64>()) as _;
                    if orig_thunk != null_mut() {
                        orig_thunk = (orig_thunk as usize + size_of::<DWORD64>()) as _;
                    }
                }

                import_discriptor = (import_discriptor as usize + size_of::<DWORD64>()) as _;
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
            self.delta_relocation_closure(self.target_image_base, delta, |target, delta| {
                if delta.is_minus {
                    *(target as *mut u64) = *(target as *mut u64) - delta.offset as u64;
                } else {
                    *(target as *mut u64) = *(target as *mut u64) + delta.offset as u64;
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
            self.delta_relocation_closure(self.payload_buffer, delta, |target, delta| {
                let mut d_buffer = 0 as u64;

                if ReadProcessMemory(
                    hp,
                    (target) as PVOID,
                    &mut d_buffer as *const _ as *mut _,
                    size_of::<u64>(),
                    null_mut(),
                ) == 0
                {
                    bail!("could not read memory from new dest image.")
                }
                
                d_buffer = if delta.is_minus {
                    d_buffer - delta.offset as u64
                } else {
                    d_buffer + delta.offset as u64
                };

                if WriteProcessMemory(
                    hp,
                    (target) as PVOID,
                    &mut d_buffer as *const _ as *mut _,
                    size_of::<u64>(),
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
                std::mem::transmute::<*const c_void, TLS_CALLBACK>(*(*callback as *const *const c_void))(
                    self.target_image_base,
                    DLL_PROCESS_ATTACH,
                    0 as _,
                );
            }
        }

        Ok(())
    }

    pub fn search_proc_address(&self, function_name: impl Into<String>) -> anyhow::Result<*mut c_void> {
        unsafe {
            let function_name = function_name.into();
            let ppeb = __readgsqword(0x60) as *mut PEB;

            let p_peb_ldr_data = (*ppeb).Ldr;
            let mut module_list = (*p_peb_ldr_data).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;

            while !(*module_list).DllBase.is_null() {
                let dll_base = (*module_list).DllBase;

                module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;

                let dll_container = PE_Container::new(0x0 as _, dll_base);

                let exports = dll_container.pe.exports();
                if exports.is_err() { continue }

                let fn_addr = dll_container.pe.get_proc_address(&function_name);
                if fn_addr.is_err() { continue }

                return Ok(fn_addr? as _)
            }

            bail!("could not find {}", function_name);
        }
    }

    fn delta_relocation_closure<T: Fn(u64, &Delta) -> anyhow::Result<()>>(
        &self,
        block_buffer: *mut c_void,
        delta: Delta,
        process_fn: T
    ) -> anyhow::Result<()> {
        unsafe {
            for section in self.pe.section_headers().image() {
                if section.Name != DOT_RELOC {
                    continue;
                }

                let reloc_address = section.PointerToRawData as u64;
                let mut offset = 0 as u64;
                let reloc_data = self.pe.data_directory()[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

                while offset < reloc_data.Size as u64 {
                    let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(
                        (block_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                    );

                    offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u64;

                    // 2 is relocation entry size.
                    // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                    let entry_count = (block_header.BlockSize
                        - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32)
                        / 2;

                    let block_entry = std::slice::from_raw_parts::<[u8; 2]>(
                        (block_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                        entry_count as usize,
                    );

                    for block in block_entry {
                        let block = BASE_RELOCATION_ENTRY(*block);

                        offset = offset + 2;

                        if block.block_type() == 0 {
                            continue;
                        }

                        process_fn(self.target_image_base as u64 + block_header.PageAddress as u64 + block.offset() as u64, &delta)?;
                    }
                }
            }
        }

        Ok(())
    }
}
