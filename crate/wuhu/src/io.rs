use crate::prelude::*;

use core::{mem::zeroed, ptr::null_mut};

use num_traits::Num;

pub fn read<T>(addr: *const T) -> T {
    read_with_offset(addr, 0)
}

pub fn read_with_offset<T>(addr: *const T, offset: usize) -> T {
    unsafe { core::ptr::read((addr as usize + offset) as _) }
}

pub fn read_as_slice<'a, T>(addr: *const T, len: usize) -> &'a [T] {
    unsafe { core::slice::from_raw_parts(addr, len) }
}

pub fn copy<T: Num>(src: LPVOID, dst: LPVOID, size: usize) {
    copy_with_offset::<T>(src, 0, dst, 0, size)
}

pub fn copy_with_offset<T: Num>(
    src: LPVOID,
    src_offset: usize,
    dst: LPVOID,
    dst_offset: usize,
    size: usize,
) {
    unsafe {
        core::ptr::copy_nonoverlapping(
            (src as usize + src_offset) as *mut T,
            (dst as usize + dst_offset) as *mut T,
            size,
        )
    }
}

pub fn read_process<T>(process: HANDLE, addr: LPVOID, size: usize) -> T {
    read_process_with_offset(process, addr, 0, size)
}

pub fn write_process(process: HANDLE, addr: LPVOID, src: LPVOID, size: usize) {
    write_process_with_offset(process, addr, 0, src, 0, size)
}

pub fn read_process_with_offset<T>(process: HANDLE, addr: LPVOID, offset: usize, size: usize) -> T {
    unsafe {
        let mut buffer = zeroed::<T>();
        ReadProcessMemory(
            process,
            (addr as usize + offset) as _,
            &mut buffer as *const _ as LPVOID,
            size,
            null_mut(),
        );
        buffer
    }
}

pub fn write_process_with_offset(
    process: HANDLE,
    addr: LPVOID,
    offset: usize,
    src: LPVOID,
    src_offset: usize,
    size: usize,
) {
    unsafe {
        WriteProcessMemory(
            process,
            (addr as usize + offset) as _,
            (src as usize + src_offset) as _,
            size,
            null_mut(),
        );
    }
}
