#[macro_use]
extern crate bitfield;

// For debug
use std::column;
use std::file;
use std::line;

pub const fn echo_debug() -> (&'static str, u32, u32) {
    (file!(), line!(), column!())
}

use std::fs::File;
use std::ffi::CString;
use std::mem::{ size_of, zeroed };
use std::io::prelude::*;
use std::ptr::null_mut;

use anyhow::*;
use winapi::ctypes::c_void;
use winapi::shared::{
    ntdef::{ BOOLEAN, HANDLE, ULONG, PVOID },
    minwindef::{ LPCVOID, PUCHAR, UCHAR }
};
use winapi::um::{
    errhandlingapi::{ GetLastError },
    memoryapi::{ VirtualAlloc, VirtualAllocEx, VirtualFree, ReadProcessMemory, WriteProcessMemory },
    processthreadsapi::{
        CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, ResumeThread,
        GetThreadContext, SetThreadContext, // SuspendThread
    },
    winbase:: {
        CREATE_SUSPENDED,
        Wow64GetThreadContext, Wow64SetThreadContext
    },
    winnt::{
        IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, LIST_ENTRY, PSTR,
        PIMAGE_NT_HEADERS32, PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER, IMAGE_SECTION_HEADER,
        IMAGE_DIRECTORY_ENTRY_BASERELOC, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        CONTEXT, WOW64_CONTEXT, CONTEXT_FULL, WOW64_CONTEXT_FULL
    }
};
use ntapi::{
  ntpsapi::{
    NtQueryInformationProcess, PROCESS_BASIC_INFORMATION,
  },
  ntpebteb::{ PEB, PPEB }
};

#[derive(Debug)]
pub enum X96 {
    X86,
    X64,
    Unknown
}

pub enum XIMAGE {
    X86(LOADED_IMAGE32),
    X64(LOADED_IMAGE64),
}

#[repr(C)]
pub struct LOADED_IMAGE32 {
    pub ModuleName: PSTR,
    pub hFile: HANDLE,
    pub MappedAddress: PUCHAR,
    pub FileHeader: PIMAGE_NT_HEADERS32,
    pub LastRvaSection: PIMAGE_SECTION_HEADER,
    pub NumberOfSections: ULONG,
    pub Sections: PIMAGE_SECTION_HEADER,
    pub Characteristics: ULONG,
    pub fSystemImage: BOOLEAN,
    pub fDOSImage: BOOLEAN,
    pub fReadOnly: BOOLEAN,
    pub Version: UCHAR,
    pub Links: LIST_ENTRY,
    pub SizeOfImage: ULONG,
}

#[repr(C)]
pub struct LOADED_IMAGE64 {
    pub ModuleName: PSTR,
    pub hFile: HANDLE,
    pub MappedAddress: PUCHAR,
    pub FileHeader: PIMAGE_NT_HEADERS64,
    pub LastRvaSection: PIMAGE_SECTION_HEADER,
    pub NumberOfSections: ULONG,
    pub Sections: PIMAGE_SECTION_HEADER,
    pub Characteristics: ULONG,
    pub fSystemImage: BOOLEAN,
    pub fDOSImage: BOOLEAN,
    pub fReadOnly: BOOLEAN,
    pub Version: UCHAR,
    pub Links: LIST_ENTRY,
    pub SizeOfImage: ULONG,
}

pub trait T_LOADED_IMAGE {
    unsafe fn get_sections_headers(&self) -> &[IMAGE_SECTION_HEADER];
}

impl T_LOADED_IMAGE for LOADED_IMAGE32 {
    unsafe fn get_sections_headers(&self) -> &[IMAGE_SECTION_HEADER] {
        std::slice::from_raw_parts(self.Sections, self.NumberOfSections as usize)
    }
}

impl T_LOADED_IMAGE for LOADED_IMAGE64 {
    unsafe fn get_sections_headers(&self) -> &[IMAGE_SECTION_HEADER] {
        std::slice::from_raw_parts(self.Sections, self.NumberOfSections as usize)
    }
}

#[repr(C)]
struct BASE_RELOCATION_BLOCK {
    PageAddress: u32,
    BlockSize: u32,
}

bitfield! {
    struct BASE_RELOCATION_ENTRY([u8]);
    impl Debug;
    u8;
    u16, offset, _: 11, 0;
    u8, block_type, _: 15, 12;
}

pub struct Delta {
    pub is_minus: bool,
    pub offset: usize
}

pub fn calculate_delta(target: usize, src: usize) -> Delta {
    let is_minus = target < src;

    if is_minus {
        Delta { is_minus, offset: src - target }
    }
    else {
        Delta { is_minus, offset: src - target }
    }
}

pub fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name).with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}

pub unsafe fn x96_check<T>(buffer: *mut T) -> X96 {
    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as *mut _);
    let p_buffer = buffer as usize + dos_header.e_lfanew as usize;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS>(p_buffer as *mut _);

    match nt_header.FileHeader.Machine {
        0x014C => X96::X86,
        0x8664 => X96::X64,
        _ => X96::Unknown
    }
}

pub unsafe fn get_image_base_address<T>(buffer: *mut T) -> Result<LPCVOID> {
    match x96_check(buffer) {
        X96::X86 => {
            Ok((*read_image32(buffer).FileHeader).OptionalHeader.ImageBase as _)
        },
        X96::X64 => {
            Ok((*read_image64(buffer).FileHeader).OptionalHeader.ImageBase as _)
        },
        X96::Unknown => { bail!("Error. unsupported architecture.") }
    }
}

pub unsafe fn get_remote_image_base_address(h_process: HANDLE) -> Result<LPCVOID> {
    let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();
    let mut peb = zeroed::<PEB>();

    NtQueryInformationProcess(h_process, 0, &mut pbi as *const _ as *mut _, size_of::<PROCESS_BASIC_INFORMATION> as u32, null_mut());

    let peb_address = pbi.PebBaseAddress;

    if ReadProcessMemory(h_process, peb_address as LPCVOID, &mut peb as *const _ as *mut _, size_of::<PEB>(), null_mut()) == 1 {
        Ok(peb.ImageBaseAddress)
    }
    else {
        let (f, l, c) = echo_debug();
        let d = format!("\nfile: {}, line: {}, column: {}", f, l, c);
        bail!("Error. could not get image address.{}", d)
    }
}

pub unsafe fn read_image32<T>(buffer: *mut T) -> LOADED_IMAGE32 {
    let mut loaded_image = zeroed::<LOADED_IMAGE32>();

    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as *const _ as *mut _);
    let p_nt_header = buffer as usize + dos_header.e_lfanew as usize;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS32>(p_nt_header as *mut _);
    let p_sections = buffer as usize + dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS32>();

    loaded_image.FileHeader = p_nt_header as *mut IMAGE_NT_HEADERS32;
    loaded_image.NumberOfSections = nt_header.FileHeader.NumberOfSections as u32;
    loaded_image.Sections = p_sections as *mut _;

    loaded_image
}

pub unsafe fn read_image64<T>(buffer: *mut T) -> LOADED_IMAGE64 {
    let mut loaded_image = zeroed::<LOADED_IMAGE64>();

    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as *const _ as *mut _);
    let p_nt_header = buffer as u64 + dos_header.e_lfanew as u64;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS64>(p_nt_header as *mut _);
    let p_sections = buffer as u64 + dos_header.e_lfanew as u64 + size_of::<IMAGE_NT_HEADERS64>() as u64;

    loaded_image.FileHeader = p_nt_header as *mut IMAGE_NT_HEADERS64;
    loaded_image.NumberOfSections = nt_header.FileHeader.NumberOfSections as u32;
    loaded_image.Sections = p_sections as *mut _;

    loaded_image
}

pub unsafe fn copy_remote_headers(hp: *mut c_void, target: LPCVOID, src: LPCVOID) -> Result<()> {
    match x96_check(src as *mut c_void) {
        X96::X86 => {
            let image = read_image32(src as *mut c_void);
            if WriteProcessMemory(
                hp, target as _, src,
                (*image.FileHeader).OptionalHeader.SizeOfHeaders as usize, null_mut()) == 0 {
                bail!("could not write process memory.");
            }
        },
        X96::X64 => {
            let image = read_image64(src as *mut c_void);
            if WriteProcessMemory(
                hp, target as _, src,
                (*image.FileHeader).OptionalHeader.SizeOfHeaders as usize, null_mut()) == 0 {
                bail!("could not write process memory.");
            }
        },
        X96::Unknown => { bail!("Error. unsupported architecture.") }
    };

    Ok(())
}

pub unsafe fn copy_remote_section_headers<T: T_LOADED_IMAGE>(hp: *mut c_void, target: LPCVOID, src: T, buffer: LPCVOID) -> Result<()> {
    let sections = src.get_sections_headers();

    for section in sections {
        let p_dest_section = target as usize + section.VirtualAddress as usize;
        if WriteProcessMemory(
            hp, p_dest_section as *mut _, (buffer as usize + section.PointerToRawData as usize) as *const c_void as *mut _,
            section.SizeOfRawData as usize, null_mut()) == 0 {
            bail!("could not write process memory.");
        }
    }

    Ok(())
}
