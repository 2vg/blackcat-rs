extern crate process_hide;

use anyhow::*;

fn main() -> Result<()> {
  process_hide::hook_init()?;
  process_hide::set_hook()?;
  std::thread::sleep(std::time::Duration::from_millis(30000000));
  Ok(())
}
