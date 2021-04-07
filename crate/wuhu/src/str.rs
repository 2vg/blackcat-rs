extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use num_traits::Num;

pub fn to_c_char(str: &str) -> Vec<u8> {
    unsafe {
        let mut v = Vec::with_capacity(str.len() + 1);
        v.set_len(str.len() + 1);

        for (i, c) in str.as_bytes().into_iter().enumerate() {
            v[i] = *c;
        }

        v[str.len()] = 0;

        v
    }
}

pub fn to_wide(str: &str) -> Vec<u16> {
    str.encode_utf16().chain(Some(0)).collect::<Vec<_>>()
}

pub fn from_c_char(w: *const u8) -> String {
    unsafe {
        let w_len = (0..).take_while(|&i| *w.offset(i) != 0).count();
        String::from_utf8_lossy(core::slice::from_raw_parts(w, w_len)).into_owned()
    }
}

pub fn from_wide(w: *const u16) -> String {
    unsafe {
        let w_len = (0..).take_while(|&i| *w.offset(i) != 0).count();
        String::from_utf16_lossy(core::slice::from_raw_parts(w, w_len))
    }
}

pub fn concat(src: &str, dst: *const i8) -> Vec<i8> {
    unsafe {
        let dst_len = (0..).take_while(|&i| *dst.offset(i) != 0).count();
        let dst_slice = core::slice::from_raw_parts(dst, dst_len);
        let mut v = vec![0; src.len() + dst_len + 1];

        for (i, b) in src.as_bytes().into_iter().enumerate() {
            v[i] = *b as _;
        }

        for (i, b) in dst_slice.into_iter().enumerate() {
            v[src.len() + i] = *b;
        }

        v
    }
}

pub fn concat_wide(src: &str, dst: *const u16) -> Vec<u16> {
    unsafe {
        let src_wide = src.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();

        let dst_len = (0..).take_while(|&i| *dst.offset(i) != 0).count();
        let dst_slice = core::slice::from_raw_parts(dst, dst_len);
        let mut v = vec![0; src.len() + dst_len + 1];

        for (i, b) in src_wide.into_iter().enumerate() {
            v[i] = b;
        }

        for (i, b) in dst_slice.into_iter().enumerate() {
            v[src.len() + i] = *b;
        }

        v
    }
}

pub fn compare(x: &str, y: *const i8) -> bool {
    compare_raw(to_c_char(x).as_ptr() as *const i8, y)
}

pub fn compare_wide(x: &str, y: *const u16) -> bool {
    compare_raw(to_wide(x).as_ptr(), y)
}

pub fn compare_raw<T: Num>(x: *const T, y: *const T) -> bool {
    unsafe {
        let x_len = (0..).take_while(|&i| !(*x.offset(i)).is_zero()).count();
        let x_slice = core::slice::from_raw_parts(x, x_len);

        let y_len = (0..).take_while(|&i| !(*y.offset(i)).is_zero()).count();
        let y_slice = core::slice::from_raw_parts(y, y_len);

        if x_len != y_len {
            return false;
        }

        for i in 0..x_len {
            if x_slice[i] != y_slice[i] {
                return false;
            }
        }

        true
    }
}
