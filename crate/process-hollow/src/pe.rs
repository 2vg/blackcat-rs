use std::ffi::CString;
use std::mem::{ size_of, size_of_val, zeroed };
use std::ptr::null_mut;

use anyhow::*;
use winapi::shared::{
    ntdef::{ BOOLEAN, HANDLE, ULONG },
    minwindef::{ LPCVOID, PUCHAR, UCHAR }
};
use winapi::um::{
    fileapi:: { CreateFileA, OPEN_ALWAYS },
    handleapi::{ INVALID_HANDLE_VALUE },
    memoryapi::{ ReadProcessMemory },
    winnt::{ GENERIC_READ, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, LIST_ENTRY, PSTR,
             PIMAGE_NT_HEADERS32, PIMAGE_NT_HEADERS64, PIMAGE_SECTION_HEADER
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
    X86_64,
    X64,
    Unknown
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

pub unsafe fn find_remote_peb(h_process: HANDLE) -> PPEB {
    let mut pbi = zeroed::<PROCESS_BASIC_INFORMATION>();

    NtQueryInformationProcess(h_process, 0, &mut pbi as *const _ as *mut _, size_of_val(&pbi) as u32, null_mut());

    pbi.PebBaseAddress
}

pub unsafe fn read_remote_peb(h_process: HANDLE) -> Result<PEB> {
    let peb_address = find_remote_peb(h_process);
    let mut peb = zeroed::<PEB>();

    if ReadProcessMemory(h_process, peb_address as LPCVOID, &mut peb as *const _ as *mut _, size_of::<PEB>(), null_mut()) == 1 {
        Ok(peb)
    }
    else {
        // TODO: Error handle
        bail!("")
    }
}

pub unsafe fn get_image_base_address(h_process: HANDLE) -> LPCVOID {
    let peb = read_remote_peb(h_process).unwrap();
    peb.ImageBaseAddress
}

pub unsafe fn x96_check_from_remote<T>(h_process: HANDLE, image: *const T) -> X96 {
    let mut buffer = zeroed::<[u8; 0x2000]>();

    if ReadProcessMemory(h_process, image as *const _, &buffer as *const _ as *mut _, size_of_val(&buffer), null_mut()) == 0 { return X96::Unknown }

    x96_check(&buffer as *const _ as *mut u8)
}

pub unsafe fn x96_check<T>(buffer: *mut T) -> X96 {
    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as *mut _);
    let p_buffer = buffer as u64 + dos_header.e_lfanew as u64;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS>(p_buffer as *mut _);

    match nt_header.FileHeader.Machine {
        0x014C => X96::X86_64,
        0x8664 => X96::X64,
        _ => X96::Unknown
    }
}

pub unsafe fn read_remote_image32(h_process: HANDLE, lp_image_base_address: LPCVOID) -> Result<LOADED_IMAGE32> {
    let mut buffer = zeroed::<[u8; 0x2000]>();

    // TODO: Error handle
    if ReadProcessMemory(h_process, lp_image_base_address as *const _, &mut buffer as *const _ as *mut _, size_of_val(&buffer), null_mut()) == 0 { bail!("") }

    Ok(read_image32(&mut buffer as *const _ as *mut _))
}

pub unsafe fn read_remote_image64(h_process: HANDLE, lp_image_base_address: LPCVOID) -> Result<LOADED_IMAGE64> {
    let mut buffer = zeroed::<[u8; 0x4000]>();

    // TODO: Error handle
    if ReadProcessMemory(h_process, lp_image_base_address as *const _, &mut buffer as *const _ as *mut _, size_of_val(&buffer), null_mut()) == 0 { bail!("") }

    Ok(read_image64(&mut buffer as *const _ as*mut _))
}

pub unsafe fn read_image32(buffer: *mut &[u8]) -> LOADED_IMAGE32 {
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

pub unsafe fn read_image64(buffer: *mut &[u8]) -> LOADED_IMAGE64 {
    let mut loaded_image = zeroed::<LOADED_IMAGE64>();

    let dos_header = std::ptr::read::<IMAGE_DOS_HEADER>(buffer as *const _ as *mut _);
    let p_nt_header = buffer as usize + dos_header.e_lfanew as usize;
    let nt_header = std::ptr::read::<IMAGE_NT_HEADERS64>(p_nt_header as *mut _);
    let p_sections = buffer as usize + dos_header.e_lfanew as usize + size_of::<IMAGE_NT_HEADERS64>();

    loaded_image.FileHeader = p_nt_header as *mut IMAGE_NT_HEADERS64;
    loaded_image.NumberOfSections = nt_header.FileHeader.NumberOfSections as u32;
    loaded_image.Sections = p_sections as *mut _;

    loaded_image
}
