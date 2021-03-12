// TODO: remove this module
use std::mem::size_of;

pub unsafe fn malloc(len: usize) -> *mut u8 {
    let mut vec = Vec::<u8>::with_capacity(len);
    vec.set_len(len);
    Box::into_raw(vec.into_boxed_slice()) as *mut u8
}

pub unsafe fn mfree(raw: *mut u8, len : usize) {
    let s = std::slice::from_raw_parts_mut(raw, len);
    let _ = Box::from_raw(s);
}

pub unsafe fn alloc<T>() -> *mut T {
    let len = size_of::<T>();
    let mut vec = Vec::<u8>::with_capacity(len);
    vec.set_len(len);
    Box::into_raw(vec.into_boxed_slice()) as *mut T
}

pub unsafe fn free<T>(raw: *mut T) {
    let s = std::slice::from_raw_parts_mut(raw, size_of::<T>());
    let _ = Box::from_raw(s);
}
