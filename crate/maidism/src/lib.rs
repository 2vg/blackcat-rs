use anyhow::*;
use colored::{ColoredString, Colorize};
use iced_x86::{
    Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction,
    IntelFormatter,
};
use std::io::prelude::*;
use std::{fs::File, ptr::null_mut};
use winapi::um::synchapi::WaitForSingleObject;
use wuhu::{
    self,
    prelude::{
        CreateRemoteThread, OpenProcess, LPVOID, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    },
};

pub fn shellcode_runner(
    file: impl Into<String>,
    with_suspended: bool,
    time_out: u32,
) -> Result<()> {
    let buffer = get_binary_from_file(file)?;

    let thread_flag = if with_suspended { 0x4 } else { 0x0 };

    let allocated = wuhu::mem::alloc(buffer.len());
    wuhu::io::copy::<u8>(&buffer[0] as *const _ as LPVOID, allocated, buffer.len());

    let mut thread_id = 0;
    let h_thread = unsafe {
        CreateRemoteThread(
            null_mut(),
            null_mut(),
            0,
            std::mem::transmute(allocated),
            null_mut(),
            thread_flag,
            &mut thread_id,
        )
    };

    if h_thread.is_null() {
        bail!("CreateRemoteThread failed.");
    } else {
        println!("created thread. thread_id {}", thread_id);
    };

    unsafe { WaitForSingleObject(h_thread, time_out) };

    Ok(())
}

pub fn remote_shellcode_runner(
    process_name: impl Into<String>,
    file: impl Into<String>,
    with_suspended: bool,
) -> Result<()> {
    let process_name = process_name.into();
    let buffer = get_binary_from_file(file)?;

    let p = winproc::Process::from_name(&process_name).map_err(Error::msg)?;
    let pid = p.id();

    let hp = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            false as _,
            pid,
        )
    };

    let thread_flag = if with_suspended { 0x4 } else { 0x0 };

    let allocated = wuhu::mem::alloc_process(hp, buffer.len());
    wuhu::io::write_process(
        hp,
        allocated,
        &buffer[0] as *const _ as LPVOID,
        buffer.len(),
    );

    let mut thread_id = 0;
    let h_thread = unsafe {
        CreateRemoteThread(
            hp,
            null_mut(),
            0,
            std::mem::transmute(allocated),
            null_mut(),
            thread_flag,
            &mut thread_id,
        )
    };

    if h_thread.is_null() {
        bail!("CreateRemoteThread failed. process name: {}", &process_name);
    } else {
        println!("created thread. thread_id {}", thread_id);
    };

    Ok(())
}

pub fn disassemble_file(
    file: impl Into<String>,
    ip: u64,
    start_offset: u64,
    size: usize,
    bitness: u32,
    colorized: bool,
) -> Result<()> {
    let buffer = get_binary_from_file(file)?;
    disassemble(&buffer, ip, start_offset, size, bitness, colorized)
}

pub fn disassemble(
    buffer: &[u8],
    ip: u64,
    start_offset: u64,
    size: usize,
    bitness: u32,
    colorized: bool,
) -> Result<()> {
    let mut decoder = Decoder::with_ip(bitness, buffer, ip, DecoderOptions::NONE);

    let mut c = 0;
    let mut address_found = false;
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_digit_separator("_");
    formatter.options_mut().set_first_operand_char_index(8);
    let mut output = MaidismFormatterOutput::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        output.vec.clear();
        formatter.format(&instruction, &mut output);

        let offset = instruction.ip() + start_offset;

        if instruction.ip() >  offset && !address_found {
            bail!("start_offset has passed. check addres is correct.");
        } else if instruction.ip() < offset {
            continue;
        }

        address_found = true;

        print!("{:016X} ", instruction.ip());

        let start_index = (instruction.ip() - ip) as usize;
        let instr_bytes = &buffer[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X} ", b);
        }

        if instr_bytes.len() < 10 {
            for _ in 0..12 * 2 - (instr_bytes.len() * 2 + instr_bytes.len() - 1) {
                print!(" ");
            }
        }

        for (text, kind) in output.vec.iter() {
            if colorized {
                print!("{}", get_color(text.as_str(), *kind));
            } else {
                print!("{}", text.as_str());
            }
        }

        println!();

        if c == size {
            break;
        }

        c += 1;
    }

    Ok(())
}

fn get_binary_from_file(file_name: impl Into<String>) -> Result<Vec<u8>> {
    let file_name = file_name.into();
    let mut f = File::open(&file_name)
        .with_context(|| format!("could not opening the file: {}", &file_name))?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)
        .with_context(|| format!("could not reading from the file: {}", &file_name))?;
    Ok(buffer)
}

struct MaidismFormatterOutput {
    vec: Vec<(String, FormatterTextKind)>,
}

impl MaidismFormatterOutput {
    pub fn new() -> Self {
        Self { vec: Vec::new() }
    }
}

impl FormatterOutput for MaidismFormatterOutput {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        self.vec.push((String::from(text), kind));
    }
}

fn get_color(s: &str, kind: FormatterTextKind) -> ColoredString {
    match kind {
        FormatterTextKind::Directive | FormatterTextKind::Keyword => s.bright_yellow(),
        FormatterTextKind::Prefix | FormatterTextKind::Mnemonic => s.bright_red(),
        FormatterTextKind::Register => s.bright_blue(),
        FormatterTextKind::Number => s.bright_cyan(),
        FormatterTextKind::LabelAddress => s.bright_green(),
        FormatterTextKind::FunctionAddress => s.bright_green(),
        _ => s.white(),
    }
}
