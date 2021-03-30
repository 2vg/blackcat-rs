extern crate code_cave;

use std::os::windows::io::AsRawHandle;

use anyhow::*;
use winapi::um::{processthreadsapi::OpenThread, winnt::{THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME}};
use winproc;

fn main() -> Result<()> {
    let p = winproc::Process::from_name("notepad.exe").unwrap();
    let hp = p.handle().as_raw_handle();
    println!("process: {:?}", hp);

    let thread_id = p.thread_ids().unwrap().next().unwrap();
    println!("thread id: {:?}", thread_id);

    unsafe {
        let thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false as _, thread_id);
        println!("thread: {:?}", thread);

        code_cave::x64::inject(hp as _, thread as _, "dll64.dll")?;
    }

    Ok(())
}
