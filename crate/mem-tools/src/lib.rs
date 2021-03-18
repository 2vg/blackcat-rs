#[macro_use]
extern crate bitfield;

// For debug
use std::{column, ptr::null};
use std::file;
use std::line;

pub const fn echo_debug() -> (&'static str, u32, u32) {
    (file!(), line!(), column!())
}

use std::fs::File;
use std::ffi::CString;
use std::mem::{ size_of, size_of_val, zeroed };
use std::io::prelude::*;
use std::ptr::null_mut;

use anyhow::*;
use winapi::ctypes::c_void;
use winapi::shared::{
    basetsd::{ DWORD64 },
    ntdef::{ BOOLEAN, HANDLE, ULONG, PVOID },
    minwindef::{ DWORD, LPCVOID, PUCHAR, UCHAR }
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
        IMAGE_DIRECTORY_ENTRY_BASERELOC,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_DESCRIPTOR, IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64,
        IMAGE_SNAP_BY_ORDINAL32, IMAGE_SNAP_BY_ORDINAL64, IMAGE_ORDINAL32, IMAGE_ORDINAL64,
        IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_LOW,
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        CONTEXT, WOW64_CONTEXT, CONTEXT_FULL, WOW64_CONTEXT_FULL
    }
};
use ntapi::{
    ntpsapi::{
        NtQueryInformationProcess, PROCESS_BASIC_INFORMATION,
    },
    ntpebteb::{ PEB, PPEB }
};

#[derive(Debug, PartialEq)]
pub enum X96 {
    X86,
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

// ".reloc" binary
const DOT_RELOC: [u8; 8] = [46, 114, 101, 108, 111, 99, 0, 0];

pub struct Delta {
    pub is_minus: bool,
    pub offset: usize
}

impl Delta {
    pub unsafe fn remote_delta_relocation(&self, hp: *mut c_void, target: *mut c_void, buffer: *mut c_void) -> Result<()> {
        if self.offset == 0 { return Ok(()) };

        match x96_check(buffer) {
            X96::X86 => {
                let image = read_image32(buffer);
                let sections = std::slice::from_raw_parts(image.Sections, image.NumberOfSections as usize);

                for section in sections {
                    if section.Name != DOT_RELOC { continue }

                    let reloc_address = section.PointerToRawData as u64;
                    let mut offset = 0 as u64;
                    let reloc_data = (*image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

                    while offset < reloc_data.Size as u64 {
                        let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>((buffer as usize + (reloc_address + offset) as usize) as *const _);

                        offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u64;

                        // 2 is relocation entry size.
                        // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                        let entry_count = (block_header.BlockSize - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32) / 2;

                        let block_entry = std::slice::from_raw_parts::<[u8; 2]>((buffer as usize + (reloc_address + offset) as usize) as *const _, entry_count as usize);

                        for block in block_entry {
                            let block = BASE_RELOCATION_ENTRY(*block);

                            offset = offset + 2;

                            if block.block_type() == 0 { continue }

                            let field_address = block_header.PageAddress as u64 + block.offset() as u64;

                            let mut d_buffer = 0 as u64;

                            if ReadProcessMemory(
                                hp, (target as u64 + field_address) as PVOID,
                                &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                                    bail!("could not read memory from new dest image.")
                            }

                            d_buffer =
                                if self.is_minus {
                                    d_buffer - self.offset as u64
                                }
                                else {
                                    d_buffer + self.offset as u64
                                };

                            if WriteProcessMemory(
                                hp, (target as u64 + field_address) as PVOID,
                                &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                                    bail!("could not write memory to new dest image.")
                            }
                        }
                    }
                }
            },
            X96::X64 => {
                let image = read_image64(buffer);
                let sections = std::slice::from_raw_parts(image.Sections, image.NumberOfSections as usize);

                for section in sections {
                    if section.Name != DOT_RELOC { continue }

                    let reloc_address = section.PointerToRawData as u64;
                    let mut offset = 0 as u64;
                    let reloc_data = (*image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

                    while offset < reloc_data.Size as u64 {
                        let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>((buffer as usize + (reloc_address + offset) as usize) as *const _ );

                        offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u64;

                        // 2 is relocation entry size.
                        // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                        let entry_count = (block_header.BlockSize - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32) / 2;

                        let block_entry = std::slice::from_raw_parts::<[u8; 2]>((buffer as usize + (reloc_address + offset) as usize) as *const _, entry_count as usize);

                        for block in block_entry {
                            let block = BASE_RELOCATION_ENTRY(*block);

                            offset = offset + 2;

                            if block.block_type() == 0 { continue }

                            let field_address = block_header.PageAddress as u64 + block.offset() as u64;

                            let mut d_buffer = 0 as u64;

                            if ReadProcessMemory(
                                hp, (target as u64 + field_address) as PVOID,
                                &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                                    bail!("could not read memory from new dest image.")
                            }

                            d_buffer =
                                if self.is_minus {
                                    d_buffer - self.offset as u64
                                }
                                else {
                                    d_buffer + self.offset as u64
                                };

                            if WriteProcessMemory(
                                hp, (target as u64 + field_address) as PVOID,
                                &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                                    bail!("could not write memory to new dest image.")
                            }
                        }
                    }
                }
            },
            X96::Unknown => { bail!("Error. unsupported architecture.") }
        }

        Ok(())
    }

    pub fn calc_offset(&self, offset: usize, block_type: u8) -> usize {
        0
    }
}

pub fn calculate_delta(target: usize, src: usize) -> Delta {
    let is_minus = target < src;

    if is_minus {
        Delta { is_minus, offset: src - target }
    }
    else {
        Delta { is_minus, offset: target - src }
    }
}

pub fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name).with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}

pub unsafe fn rva2offset<T: T_LOADED_IMAGE>(rva: u32, image: &T) -> u32 {
    let sections = image.get_sections_headers();

    if rva < sections[0].PointerToRawData { return rva; }

    for section in sections {
        if rva > section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData {
            return rva - section.VirtualAddress + section.PointerToRawData;
        }
    }

    0
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

    NtQueryInformationProcess(h_process, 0, &mut pbi as *const _ as *mut _, size_of_val(&pbi) as u32, null_mut());

    let peb_address = pbi.PebBaseAddress;

    if ReadProcessMemory(h_process, peb_address as LPCVOID, &mut peb as *const _ as *mut _, size_of::<PEB>(), null_mut()) == 1 {
        Ok(peb.ImageBaseAddress)
    }
    else {
        bail!("Error. could not get image address.")
    }
}

pub unsafe fn check_same_architecture(target: *mut c_void, src: *mut c_void) -> Result<()> {
    let t = x96_check(target);
    let s = x96_check(src);

    if t == X96::Unknown || s == X96::Unknown { bail!("Error. unsupported architecture.") }
    
    if t != s { bail!("target and payload must have the same architecture.") }

    Ok(())
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

pub unsafe fn copy_remote_section_headers<T: T_LOADED_IMAGE>(hp: *mut c_void, target: LPCVOID, src: &T, buffer: LPCVOID) -> Result<()> {
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

pub unsafe fn resolve_import(src: *mut c_void) -> Result<()> {
    match x96_check(src as *mut c_void) {
        X96::X86 => {
            let image = read_image32(src as *mut c_void);
            let image_base = (*image.FileHeader).OptionalHeader.ImageBase;
            let import_directory = (*image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            let mut import_discriptor = (image_base + import_directory.VirtualAddress) as *mut IMAGE_IMPORT_DESCRIPTOR;

            while (*import_discriptor).Name != 0x0 {
                let mut orig_thunk = (image_base + (*import_discriptor).u.OriginalFirstThunk()) as *mut IMAGE_THUNK_DATA32;
                let mut thunk = (image_base + (*import_discriptor).FirstThunk) as *mut IMAGE_THUNK_DATA32;

                while (*orig_thunk).u1.AddressOfData() != &0x0 {
                    if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL32(*(*orig_thunk).u1.Ordinal()) {
                        // TODO:
                    }
                    else {
                        // TODO:
                    }

                    thunk = (thunk as usize + size_of::<DWORD>()) as _;
                    if orig_thunk != null_mut() { orig_thunk = (orig_thunk as usize + size_of::<DWORD>()) as _; }
                }

                import_discriptor = (import_discriptor as usize + size_of::<DWORD>()) as _;
            }
        },
        X96::X64 => {
            let image = read_image64(src as *mut c_void);
            let image_base = (*image.FileHeader).OptionalHeader.ImageBase;
            let import_directory = (*image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            let mut import_discriptor = (image_base + import_directory.VirtualAddress as u64) as *mut IMAGE_IMPORT_DESCRIPTOR;

            while (*import_discriptor).Name != 0x0 {
                let mut orig_thunk = (image_base + *(*import_discriptor).u.OriginalFirstThunk() as u64) as *mut IMAGE_THUNK_DATA64;
                let mut thunk = (image_base + (*import_discriptor).FirstThunk as u64) as *mut IMAGE_THUNK_DATA64;

                while (*thunk).u1.AddressOfData() != &0x0 {
                    if orig_thunk != null_mut() && IMAGE_SNAP_BY_ORDINAL64(*(*thunk).u1.Ordinal()) {
                        // TODO:
                    }
                    else {
                        // TODO:
                    }

                    thunk = (thunk as usize + size_of::<DWORD64>()) as _;
                    if orig_thunk != null_mut() { orig_thunk = (orig_thunk as usize + size_of::<DWORD64>()) as _; }
                }

                import_discriptor = (import_discriptor as usize + size_of::<DWORD64>()) as _;
            }
        },
        X96::Unknown => { bail!("Error. unsupported architecture.") }
    };

    Ok(())
}
