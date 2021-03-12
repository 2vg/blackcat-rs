pub mod pe;

// TODO: remove this module
pub mod mem;

use crate::pe::{
    read_image32, read_image64, read_remote_image32, read_remote_image64, get_image_base_address,
    X96, x96_check, x96_check_from_remote
};
use anyhow::*;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::{
    memoryapi::{ VirtualAllocEx },
    processthreadsapi::{ CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION },
    winbase::CREATE_SUSPENDED,
    winnt:: { MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE }
};
use ntapi::ntmmapi:: NtUnmapViewOfSection;

use std::fs::File;
use std::ffi::CString;
use std::mem::zeroed;
use std::io;
use std::io::prelude::*;
use std::ptr::null_mut;

pub unsafe fn hollow(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    // Create dest process
    let mut startup = zeroed::<STARTUPINFOA>();
    let mut process_info = zeroed::<PROCESS_INFORMATION>();

    let dest = CString::new(dest.into()).expect("CString::new failed");
    CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

    // Get dest image, image_address
    let hp = process_info.hProcess;
    let image_address = get_image_base_address(hp);
    let mut dest_image = read_remote_image64(hp, image_address)?;

    // TODO: remove debug print
    println!("dest Signature: {:?}", (*dest_image.FileHeader).Signature);
    println!("dest Machine: {:?}", (*dest_image.FileHeader).FileHeader.Machine);
    println!("dest Architecture: {:?}", x96_check_from_remote(process_info.hProcess, image_address));

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
    let mut src_image = read_image64(&mut buffer[0] as *const _ as *mut _);
    println!("src Signature: {:?}", (*src_image.FileHeader).Signature);
    println!("src Machine: {:?}", (*src_image.FileHeader).FileHeader.Machine);
    println!("src Architecture: {:?}", x96_check(&mut buffer[0]));

    // Unmapping image from dest process
    if NtUnmapViewOfSection(hp, image_address as *mut _) != STATUS_SUCCESS {
        bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
    };

    // TODO: Allocate memory for src program
    let dest_nt_header = (*src_image.FileHeader);
    let dest_image_memory = VirtualAllocEx(
        hp, image_address as *mut _, dest_nt_header.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if dest_image_memory as usize == 0x0 {
        bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.")
    };

    // TODO: Delta relocation
    if false { unimplemented!() }

    // TODO: Get thread context of dest, and modify entry point
    if false { unimplemented!() }

    // TODO: Resume thread of dest
    if false { unimplemented!() }

    // TODO: remove debug print
    println!("process was hollowed ε٩(๑> 3 <)۶з");

    Ok(())
}
