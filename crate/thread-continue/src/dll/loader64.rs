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
        let ppeb = __readgsqword(0x60) as *mut PEB;
        let my_base_address = (*ppeb).ImageBaseAddress;
        let mut container = PE_Container::new(0x0 as _, my_base_address);

        let pLoadLibraryA = ptr_to_fn::<PLoadLibraryA>(container.search_proc_address("LoadLibraryA")?);
        let pGetProcAddress = ptr_to_fn::<PGetProcAddress>(container.search_proc_address("GetProcAddress")?);
        let pVirtualAlloc = ptr_to_fn::<PVirtualAlloc>(container.search_proc_address("VirtualAlloc")?);
        let pNtFlushInstructionCache = ptr_to_fn::<PNtFlushInstructionCache>(container.search_proc_address("NtFlushInstructionCache")?);

        let mut allocated = pVirtualAlloc(container.payload_base(), container.get_payload_optional_headers().SizeOfImage as _, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        if allocated as u64 == 0x0 as u64 {
            allocated = pVirtualAlloc(null_mut(), container.get_payload_optional_headers().SizeOfImage as _, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
        };

        if allocated as u64 == 0x0 as u64 {
            bail!("could not allocate of the remote process image. VirtualAlloc calling was failed.")
        };

        container.change_target_image_base(allocated);

        let delta = Delta::calculate_delta(container.target_image_base as _, container.payload_base() as _);
        container.delta_relocation(delta)?;

        container.resolve_import(pLoadLibraryA, pGetProcAddress)?;

        pNtFlushInstructionCache(-1 as _, null_mut(), 0);

        container.exec_tls_callback()?;

        // TODO: register exception handler

        let p_dll_main = container.target_image_base as u64 + container.get_payload_optional_headers().AddressOfEntryPoint as u64;
        let dll_main = ptr_to_fn::<DllMain>(p_dll_main as _);

        dll_main(container.target_image_base as _, DLL_PROCESS_ATTACH, 1 as _);

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
