maidism
===

shellcode runner for debugging and disassembler.

## Disclaimer
**Code samples are provided for educational purposes. Adequate defenses can only be built by researching attack techniques available to malicious actors. Using this code against target systems without prior permission is illegal in most jurisdictions. The authors are not liable for any damages from misuse of this information or code**.</br>

## Required
tested Windows 10 x64 with `1.53.0-nightly`

## Usage

as a simple disassembler

```rust
const SHELLCODE_PATH: &'static str = r"<DLL path>";

fn main() -> Result<()> {
    let bitness = 64; // 64bit

    /*
     * disassemble(
     *     buffer: &[u8],
     *     ip: u64,
     *     start_address: u64,
     *     size: usize,
     *     bitness: u32,
     *     colorized: bool,
     * ) -> Result<()>
     */

    // display 16 instructions from 0x0 address with colorized format text, instructions pointer is 0x0
    maidism::disassemble([...], 0x0, 8, bitness, true)?;

    /*
     * disassemble_file(
     *     file: impl Into<String>,
     *     ip: u64,
     *     start_address: u64,
     *     size: usize,
     *     bitness: u32,
     *     colorized: bool,
     * ) -> Result<()>
     */

    // display 16 instructions from 0x0 address with colorized format text, instructions pointer is 0x0
    maidism::disassemble_file(SHELLCODE_PATH, 0x0, 0x0, 16, bitness, true)?;

    // display 32 instructions from 0x100 address with normal format text, instructions pointer is 0x0
    maidism::disassemble_file(SHELLCODE_PATH, 0x0, 0x100, 32, bitness, false)?;

    Ok(())
}
```

as a shellcode runner

```rust
const SHELLCODE_PATH: &'static str = r"<DLL path>";

fn main() -> Result<()> {
    /* shellcode_runner(file: impl Into<String>, with_suspended: bool, time_out: u32) -> Result<()> */

    // exec shellcode on current process, with infinity time-out
    maidism::shellcode_runner(SHELLCODE_PATH, true, 0xFFFFFFFF)?;

    // exec shellcode on current process, with specify time-out
    maidism::shellcode_runner(SHELLCODE_PATH, true, 0x0)?;

    // exec shellcode on current process, Run immediately
    maidism::shellcode_runner(SHELLCODE_PATH, false, 0x0)?;

    /*
     * remote_shellcode_runner(
     *     process_name: impl Into<String>,
     *     file: impl Into<String>,
     *     with_suspended: bool,
     * ) -> Result<()>
     */

    // with suspended thread
    maidism::remote_shellcode_runner("notepad.exe", SHELLCODE_PATH, true)?;

    // Run immediately
    maidism::remote_shellcode_runner("notepad.exe", SHELLCODE_PATH, false)?;
    Ok(())
}
```
