#[allow(non_snake_case)]
use crate::shared::*;

use std::mem::size_of;
use std::ptr::null_mut;

use anyhow::*;
use ntapi::{
    ntwow64::{
        PEB32, PEB_LDR_DATA32, LDR_DATA_TABLE_ENTRY32
    }, winapi_local::um::winnt::__readfsdword
};
use goblin::pe::{
    PE,
    optional_header::OptionalHeader,
    section_table::SectionTable
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
            IMAGE_TLS_DIRECTORY32, DLL_PROCESS_ATTACH
        }
    },
};

pub struct PE_Container<'a> {
    pub pe: PE<'a>,
    target_image_base: *mut c_void,
    payload_first_pointer: *mut c_void
}

impl PE_Container<'_> {
    pub fn new(target_image_base: *mut c_void, payload_first_pointer: *mut c_void) -> Result<PE_Container<'static>> {
        Ok(PE_Container {
            pe: goblin::pe::PE::parse(ptr_to_u8slice(payload_first_pointer))?,
            target_image_base,
            payload_first_pointer
        })
    }

    pub fn new_from_u8(target_image_base: *mut c_void, payload: &'static [u8]) -> Result<PE_Container<'static>> {
        Ok(PE_Container {
            pe: goblin::pe::PE::parse(payload)?,
            target_image_base,
            payload_first_pointer: &payload[0] as *const _ as *mut c_void
        })
    }

    pub fn payload_first_pointer(&self) -> *mut c_void {
        self.payload_first_pointer
    }

    pub fn payload_base_address(&self) -> *mut c_void {
        match self.pe.header.optional_header {
            Some(optional_header) => {
                optional_header.windows_fields.image_base as _
            },
            None => { 0x0 as _ }
        }
    }

    pub fn change_payload_image_base(&mut self, new_image_base: *mut c_void) {
        unsafe {
            let dos_header = self.payload_first_pointer as *mut IMAGE_DOS_HEADER;
            let nt_header = (self.payload_first_pointer as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS32;
            (*nt_header).OptionalHeader.ImageBase = new_image_base as _;
        };
        self.pe = goblin::pe::PE::parse(ptr_to_u8slice(self.payload_first_pointer)).unwrap();
    }

    pub fn target_base_address(&self) -> *mut c_void {
        self.target_image_base
    }

    pub fn change_target_image_base(&mut self, new_image_base: *mut c_void) {
        self.target_image_base = new_image_base;
    }

    pub fn to_va(&self, rva: usize) -> *mut c_void {
        (self.payload_base_address() as usize + rva) as *mut c_void
    }

    pub fn get_payload_optional_headers(&self) -> OptionalHeader {
        self.pe.header.optional_header.unwrap()
    }

    pub fn get_payload_image_size(&self) -> usize {
        self.pe.header.optional_header.unwrap().windows_fields.size_of_image as _
    }

    pub fn get_payload_section_headers(&self) -> &Vec<SectionTable> {
        &self.pe.sections
    }

    pub fn copy_headers(&self) -> anyhow::Result<()> {
        unsafe {
            for i in 0..self.get_payload_optional_headers().windows_fields.size_of_headers {
                *((self.target_image_base as usize + i as usize) as *mut u8) = *((self.payload_base_address() as usize + i as usize) as *mut u8)
            }
            Ok(())
        }
    }

    pub fn copy_remote_headers(&self, hp: *mut c_void) -> anyhow::Result<()> {
        if unsafe {
            WriteProcessMemory(
                hp,
                self.target_image_base as _,
                self.payload_first_pointer(),
                self.get_payload_optional_headers().windows_fields.size_of_headers as usize,
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
            for section in self.get_payload_section_headers() {
                let p_dest_section = self.target_image_base as usize + section.virtual_address as usize;
                for i in 0..section.size_of_raw_data {
                    *((p_dest_section + i as usize) as *mut u8) =
                        *((self.payload_base_address() as usize + section.pointer_to_raw_data as usize + i as usize) as *mut u8);
                }
            }
            Ok(())
        }
    }

    pub fn copy_remote_section_headers(&self, hp: *mut c_void) -> anyhow::Result<()> {
        for section in self.get_payload_section_headers() {
            let p_dest_section = self.target_image_base as usize + section.virtual_address as usize;
            if unsafe {
                WriteProcessMemory(
                    hp,
                    p_dest_section as *mut _,
                    (self.payload_first_pointer() as usize + section.pointer_to_raw_data as usize)
                        as *const c_void as *mut _,
                    section.size_of_raw_data as usize,
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
            let import_directory = self.get_payload_optional_headers().data_directories.get_import_table().unwrap();
            let mut import_discriptor = (self.target_image_base as usize
                + import_directory.virtual_address as usize)
                as *mut IMAGE_IMPORT_DESCRIPTOR;

            while (*import_discriptor).Name != 0x0 {
                let lib_name = (self.target_image_base as usize + (*import_discriptor).Name as usize) as LPCSTR;
                let lib = p_load_liberay(lib_name);

                let mut orig_thunk = (self.target_image_base as usize
                    + *(*import_discriptor).u.OriginalFirstThunk() as usize)
                    as *mut IMAGE_THUNK_DATA32;
                let mut thunk = (self.target_image_base as usize + (*import_discriptor).FirstThunk as usize)
                    as *mut IMAGE_THUNK_DATA32;

                while (*thunk).u1.AddressOfData() != &0x0 {
                    if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL32(*(*orig_thunk).u1.Ordinal()) {
                        let fn_ordinal = IMAGE_ORDINAL32(*(*orig_thunk).u1.Ordinal()) as LPCSTR;
                        *(*thunk).u1.Function_mut() = p_get_proc_adress(lib, fn_ordinal) as _;
                    } else {
                        let fn_name = (self.target_image_base as usize + *(*thunk).u1.AddressOfData() as usize) as *mut IMAGE_IMPORT_BY_NAME;
                        *(*thunk).u1.Function_mut() = p_get_proc_adress(lib, (*fn_name).Name[0] as _) as _;
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

    pub fn exec_tls_callback(&self) -> Result<()> {
        unsafe { 
            let tls_table = self.get_payload_optional_headers().data_directories.get_tls_table().unwrap();
            let tls_directry = std::slice::from_raw_parts::<*mut c_void>(self.to_va(tls_table.virtual_address as _) as _, tls_table.size as _);

            for tls in tls_directry {
                let callback = (*(*(tls) as *mut IMAGE_TLS_DIRECTORY32)).AddressOfCallBacks;
                std::mem::transmute::<*const c_void, TLS_CALLBACK>(*(callback as *const *const c_void))(
                    self.target_image_base,
                    DLL_PROCESS_ATTACH,
                    0 as _,
                );
            }
            Ok(())
        }
    }

    pub fn delta_relocation(
        &self,
        delta: Delta
    ) -> anyhow::Result<()> {
        Ok(unsafe {
            self.delta_relocation_closure(self.target_image_base, delta, |target, delta| {
                if delta.is_minus {
                    *(target as *mut usize) = *(target as *mut usize) - delta.offset as usize;
                } else {
                    *(target as *mut usize) = *(target as *mut usize) + delta.offset as usize;
                }
                Ok(())
            })?;
        })
    }

    pub fn remote_delta_relocation(
        &self,
        hp: *mut c_void,
        delta: Delta
    ) -> anyhow::Result<()> {
        Ok(unsafe {
            self.delta_relocation_closure(self.payload_first_pointer(), delta, |target, delta| {
                let mut d_buffer = 0 as usize;

                if ReadProcessMemory(
                    hp,
                    (target) as PVOID,
                    &mut d_buffer as *const _ as *mut _,
                    size_of::<usize>(),
                    null_mut(),
                ) == 0
                {
                    bail!("could not read memory from new dest image.")
                }
                
                d_buffer = if delta.is_minus {
                    d_buffer - delta.offset as usize
                } else {
                    d_buffer + delta.offset as usize
                };

                if WriteProcessMemory(
                    hp,
                    (target) as PVOID,
                    &mut d_buffer as *const _ as *mut _,
                    size_of::<usize>(),
                    null_mut(),
                ) == 0
                {
                    bail!("could not write memory to new dest image.")
                }

                Ok(())
            })?;
        })
    }

    fn delta_relocation_closure<T: Fn(usize, &Delta) -> anyhow::Result<()>>(
        &self,
        block_buffer: *mut c_void,
        delta: Delta,
        process_fn: T
    ) -> anyhow::Result<()> {
        unsafe {
            for section in self.get_payload_section_headers() {
                if section.name != DOT_RELOC { continue }

                let reloc_address = section.pointer_to_raw_data as usize;
                let mut offset = 0 as usize;
                let reloc_data = self.get_payload_optional_headers().data_directories.get_base_relocation_table().unwrap();

                while offset < reloc_data.size as usize {
                    let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(
                        (block_buffer as usize + (reloc_address + offset) as usize)
                            as *const _,
                    );

                    offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as usize;

                    // 2 is relocation entry size.
                    // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                    let entry_count = (block_header.BlockSize as usize
                        - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as usize)
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

                        process_fn(self.target_image_base as usize + block_header.PageAddress as usize + block.offset() as usize, &delta)?;
                    }
                }
            }
        }

        Ok(())
    }
}

pub fn search_proc_address(function_name: impl Into<String>) -> anyhow::Result<*mut c_void> {
    unsafe {
        let function_name = function_name.into();
        let ppeb = __readfsdword(0x30) as *mut PEB32;

        let p_peb_ldr_data = (*ppeb).Ldr as *mut PEB_LDR_DATA32;;
        let mut module_list = (*p_peb_ldr_data).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY32;

        while !((*module_list).DllBase as PVOID).is_null() {
            let dll_base = (*module_list).DllBase;

            module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY32;

            let dll_container = PE_Container::new(0x0 as _, dll_base as _)?;

            for e in &dll_container.pe.exports {
                match e.name {
                    Some(symbol) => {
                        if symbol == function_name {
                            return Ok(dll_container.to_va(e.offset as _));
                        }
                    },
                    None => {}
                }
            }
        }

        bail!("could not find {}", function_name);
    }
}
