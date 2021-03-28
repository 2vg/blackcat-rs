#[allow(non_snake_case)]
#[allow(non_camel_case_types)]

extern crate pe_tools;

use std::ptr::null_mut;

use anyhow::*;
use ntapi::{ntpebteb::PEB, winapi_local::um::winnt::__readgsqword};
use pe_tools::shared::*;
use pe_tools::x64::*;
use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{
            BOOL, DWORD, HINSTANCE, LPVOID
        },
        ntdef::{
            HANDLE, NTSTATUS, PVOID
        }
    },
    um::winnt::{
        DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE
    }
};

pub type PVirtualAlloc = fn(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID;
pub type PNtFlushInstructionCache = fn(ProcessHandle:HANDLE, BaseAddress:PVOID, Length:SIZE_T) ->NTSTATUS;
pub type DllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;

#[no_mangle]
pub extern "system" fn reflective_load() -> bool {
    match __reflective_load() {
        Ok(_) => { true },
        Err(_) => { false }
    }
}

pub fn __reflective_load() -> Result<()> {
    unsafe {
        // 1: get image base address of own, create pe container
        let ppeb = __readgsqword(0x60) as *mut PEB;
        let my_base_address = (*ppeb).ImageBaseAddress;
        let mut container = PE_Container::new(0x0 as _, my_base_address)?;

        // 2: get address needed by the loading process
        let pLoadLibraryA = ptr_to_fn::<PLoadLibraryA>(search_proc_address_from_loaded_module("LoadLibraryA")?);
        let pGetProcAddress = ptr_to_fn::<PGetProcAddress>(search_proc_address_from_loaded_module("GetProcAddress")?);
        let pVirtualAlloc = ptr_to_fn::<PVirtualAlloc>(search_proc_address_from_loaded_module("VirtualAlloc")?);
        let pNtFlushInstructionCache = ptr_to_fn::<PNtFlushInstructionCache>(search_proc_address_from_loaded_module("NtFlushInstructionCache")?);

        // 3: allocate new v memory, and change target base address to it
        let mut allocated = pVirtualAlloc(container.payload_base_address(), container.get_payload_image_size() as _, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        if allocated as u64 == 0x0 as u64 {
            allocated = pVirtualAlloc(null_mut(), container.get_payload_image_size() as _, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        };

        if allocated as u64 == 0x0 as u64 {
            bail!("could not allocate of the remote process image. VirtualAlloc calling was failed.")
        };

        container.change_target_image_base(allocated);

        // 4: copy over headers
        container.copy_headers()?;

        // 5: copy over section headers
        container.copy_section_headers()?;

        // 6: calculate delta, then relocate it if needed.(this is need in almost case)
        let delta = Delta::calculate_delta(container.target_base_address() as _, container.payload_base_address() as _);
        container.delta_relocation(delta)?;

        // 7: resolve import table
        container.resolve_import(pLoadLibraryA, pGetProcAddress)?;

        // TODO: 8: resolve delayed import?

        // TODO: 9: call protect memory?

        // 10: flush the instruction cache to avoid stale code being used
        pNtFlushInstructionCache(-1 as _, null_mut(), 0);

        // 11: execute tls callbacks
        container.exec_tls_callback()?;

        // TODO: 12: register exception handler?

        // 13: call DllMain
        let p_dll_main = container.target_base_address() as u64 + container.pe.entry as u64;
        let dll_main = ptr_to_fn::<DllMain>(p_dll_main as _);

        dll_main(container.target_base_address() as _, DLL_PROCESS_ATTACH, 1 as _);

        Ok(())
    }
}

// for debug
use winapi::um::winuser::{MessageBoxW, MB_OK};
use std::ptr;

fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}

fn debug(t: impl Into<String>, c: impl Into<String>) {
    let t = t.into();
    let c = c.into();
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            e(&c).as_ptr(),
            e(&t).as_ptr(),
            MB_OK
        );
    }
}
