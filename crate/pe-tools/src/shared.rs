#[allow(non_snake_case)]
#[allow(non_camel_case_types)]

use std::fs::File;
use std::io::prelude::*;
use std::mem::{size_of, zeroed};
use std::ptr::null_mut;

use anyhow::*;
use bitfield;
use ntapi::{
    ntpebteb::PEB,
    ntpsapi::{NtQueryInformationProcess, PROCESS_BASIC_INFORMATION},
    winapi_local::um::winnt::__readfsdword
};
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::DWORD,
        ntdef::PVOID
    }
};
use winapi::shared::{
    minwindef::{FARPROC, HMODULE},
    ntdef::{HANDLE, LPCSTR},
};
use winapi::um::{
    memoryapi::ReadProcessMemory,
    winnt::{
        IMAGE_DOS_HEADER, IMAGE_NT_HEADERS,
    },
};

#[derive(Debug, PartialEq)]
pub enum X96 {
    X86,
    X64,
    Unknown,
}

#[repr(C)]
pub struct BASE_RELOCATION_BLOCK {
    pub PageAddress: u32,
    pub BlockSize: u32,
}

bitfield! {
    pub struct BASE_RELOCATION_ENTRY([u8]);
    impl Debug;
    u8;
    pub u16, offset, _: 11, 0;
    pub u8, block_type, _: 15, 12;
}

pub struct Delta {
    pub is_minus: bool,
    pub offset: usize,
}

impl Delta {
    pub fn calculate_delta(target: usize, src: usize) -> Delta {
        let is_minus = target < src;
    
        if is_minus {
            Delta {
                is_minus,
                offset: src - target,
            }
        } else {
            Delta {
                is_minus,
                offset: target - src,
            }
        }
    }
}

// ".reloc" binary
pub const DOT_RELOC: [u8; 8] = [46, 114, 101, 108, 111, 99, 0, 0];

pub type PLoadLibraryA = unsafe extern "system" fn(lpFileName: LPCSTR) -> HMODULE;
pub type PGetProcAddress = unsafe extern "system" fn(hModule: HMODULE, lpProcName: LPCSTR) -> FARPROC;
pub type TLS_CALLBACK = unsafe extern "system" fn(DllHandle: PVOID, Reason: DWORD, Reserved: PVOID);

pub fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name)
        .with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}

pub unsafe fn x96_check<T>(buffer: *mut T) -> X96 {
    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as *mut _);
    let p_buffer = buffer as usize + dos_header.e_lfanew as usize;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS>(p_buffer as *mut _);

    match nt_header.FileHeader.Machine {
        0x014C => X96::X86,
        0x8664 => X96::X64,
        _ => X96::Unknown,
    }
}

pub unsafe fn check_same_architecture(target: *mut c_void, src: *mut c_void) -> Result<()> {
    let t = x96_check(target);
    let s = x96_check(src);

    if t == X96::Unknown {
        bail!("Error. target is unsupported architecture.")
    }

    if s == X96::Unknown {
        bail!("Error. payload is unsupported architecture.")
    }

    if t != s {
        bail!("target and payload must have the same architecture.")
    }

    Ok(())
}

pub unsafe fn get_remote_image_base_address(h_process: HANDLE) -> Result<*mut c_void> {
    let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
    let mut peb = zeroed::<PEB>();

    NtQueryInformationProcess(
        h_process,
        0,
        &mut pbi as *const _ as *mut _,
        size_of::<PROCESS_BASIC_INFORMATION>() as _,
        null_mut(),
    );

    let peb_address = pbi.PebBaseAddress;

    if ReadProcessMemory(
        h_process,
        peb_address as *mut c_void,
        &mut peb as *const _ as *mut _,
        size_of::<PEB>(),
        null_mut(),
    ) == 1
    {
        Ok(peb.ImageBaseAddress)
    } else {
        bail!("Error. could not get image address.")
    }
}
/*
pub fn search_syscall(syscall_name: impl Into<String>, is_64bit: bool) -> Result<Vec<u8>> {
    let syscall_name = syscall_name.into();

    let ntdll = if is_64bit {
        "c:\\windows\\system32\\ntdll.dll"
    } else {
        "c:\\windows\\SysWOW64\\ntdll.dll"
    };

    let ntdll_buffer = get_binary_from_file(ntdll)?;

    let pe = goblin::pe::PE::parse(&ntdll_buffer)?;

    for e in pe.exports {
        match e.name {
            Some(symbol) => {
                if symbol == syscall_name {
                    if pe.is_64 {
                        let syscall_number = ntdll_buffer[e.offset + 4];
                        /*
                         *    asm
                         *    mov    r10, rcx
                         *    mov    eax, syscall_number
                         *    syscall
                         *    ret
                         */
                        let b = [
                            0x4C, 0x8B, 0xD1,
                            0xB8, syscall_number,  0x0, 0x0, 0x0,
                            0xF, 0x5,
                            0xC3
                        ];
                    } else {
                        let b = [0];
                    }
                    println!("fs: 0x{:x}", unsafe { __readfsdword(0xC0) });
                    println!("0x{:x}", e.offset);
                    for i in 0..12 {
                        print!("0x{:x} ", ntdll_buffer[e.offset + i]);
                    }
                }
            },
            None => {}
        }
    }

    Ok(Vec::new())
}
*/

pub fn ptr_to_u8slice(p: *mut c_void) -> &'static [u8] {
    unsafe { std::mem::transmute_copy::<*mut c_void, &[u8]>(&p) }
}

pub fn ptr_to_fn<T>(p: *mut c_void) -> T {
    unsafe { std::mem::transmute_copy::<usize, T>(&(p as usize)) as T }
}

pub fn ptr_to_str(p: &mut *mut u8) -> String {
    unsafe {
        let mut str = Vec::new();
        while **p != 0x0 {
            str.push(**p);
            *p = (*p as usize + 1) as _;
        };
        String::from_utf8(str).unwrap()
    }
}

pub fn from_wide_ptr(ptr: *const u16) -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    unsafe {
        assert!(!ptr.is_null());
        let len = (0..std::isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}
