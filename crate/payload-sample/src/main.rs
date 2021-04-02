#![windows_subsystem = "windows"]

use std::ptr;
use winapi::um::winuser::{MessageBoxW, MB_OK};

fn main() {
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            e("ur machine hacked ฅ( ̳• ε • ̳").as_ptr(),
            e("Hello ♡").as_ptr(),
            MB_OK,
        );
    }
}

fn e(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(Some(0)).collect()
}
