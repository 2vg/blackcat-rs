extern crate process_hollow;

use anyhow::*;

fn main() -> Result<()> {
    unsafe { process_hollow::hollow("c:\\windows\\syswow64\\calc.exe", "c:\\windows\\syswow64\\notepad.exe")? };
    println!("Exit after 3secs...");
    std::thread::sleep(std::time::Duration::from_millis(3000));
    Ok(())
}
