use anyhow::*;
use minhook_sys::*;
use ntapi::ntexapi::{ NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION };
use winapi::{
    shared::{
        minwindef::{ FARPROC },
        ntdef::{ HANDLE, LARGE_INTEGER, NTSTATUS, PULONG, PVOID, ULONG, UNICODE_STRING }
    },
    um::libloaderapi::{ GetModuleHandleA, GetProcAddress }
};

use std::{ffi::CString, mem::{size_of, size_of_val}, ptr::null_mut};
use std::mem::zeroed;

type SYSTEM_INFORMATION_CLASS = u32;

struct SYSTEM_PROCESS_INFO {
    NextEntryOffset: ULONG,
    NumberOfThreads: ULONG,
    Reserved: [LARGE_INTEGER; 3],
    CreateTime: LARGE_INTEGER,
    UserTime: LARGE_INTEGER,
    KernelTime: LARGE_INTEGER,
    ImageName: UNICODE_STRING,
    BasePriority: ULONG,
    ProcessId: HANDLE,
    InheritedFromProcessId: HANDLE
}

unsafe fn detour_NtQuerySystemInformation(SystemInformationClass: SYSTEM_INFORMATION_CLASS, SystemInformation: PVOID, SystemInformationLength: ULONG, ReturnLength: PULONG) -> NTSTATUS {
    let p_current = zeroed::<SYSTEM_PROCESS_INFORMATION>();
    let p_next = zeroed::<SYSTEM_PROCESS_INFORMATION>();

    let status = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    println!("debug");

    if SystemInformationClass == 0x39 {
        let processes = std::slice::from_raw_parts::<SYSTEM_PROCESS_INFORMATION>(SystemInformation as *mut _, ((SystemInformationLength / std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() as u32)) as usize);

        for process in processes {
            println!("process: {}", 1);
        }
    };

    status
}

pub fn hook_init() -> Result<()> {
    match unsafe { MH_Initialize() } {
        MH_OK => {
            println!("done hook init.");
            Ok(())
        },
        _ => { bail!("error on hook init process.") }
    }
}

pub fn set_hook() -> Result<()> {
    let module = CString::new::<String>("ntdll.dll".into()).expect("CString::new failed");
    let api = CString::new::<String>("NtQuerySystemInformation".into()).expect("CString::new failed");

    let hook_fn: FARPROC = detour_NtQuerySystemInformation as unsafe fn(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS as _;
    let mut p_ntquery = unsafe { GetProcAddress(GetModuleHandleA(module.as_ptr() as *const _), api.as_ptr() as *const _) } ;
    let pp_ntquery: *mut FARPROC = &mut p_ntquery as _;

    let status = unsafe { MH_CreateHookApi(e("ntdll.dll").as_ptr(), api.as_ptr(), hook_fn as _,pp_ntquery as _) };

    match status {
        MH_OK => { },
        _ => { bail!("could not craete hook. error code: {}", status) }
    };

    let status = unsafe { MH_EnableHook(hook_fn as _) };

    match status {
        MH_OK => { },
        _ => { bail!("could not enable the hook. error code: {}", status) }
    };

    // unsafe { test_call() };

    Ok(())
}

fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}

unsafe fn test_call() {
    let sys_class = zeroed::<SYSTEM_INFORMATION_CLASS>();
    let mut buffer = zeroed::<[u8; 0xFF0000]>();

    let status = NtQuerySystemInformation(sys_class, &mut buffer as *const _ as *mut _, 0x10000 as u32, std::ptr::null_mut()) as i64;

    println!("call result: {}", status);
}
