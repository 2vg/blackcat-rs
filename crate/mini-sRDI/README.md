mini-sRDI
===

shellcode reflective dll injection.

## Disclaimer
**Code samples are provided for educational purposes. Adequate defenses can only be built by researching attack techniques available to malicious actors. Using this code against target systems without prior permission is illegal in most jurisdictions. The authors are not liable for any damages from misuse of this information or code**.</br>

## Required
tested Windows 10 x64 with `1.53.0-nightly`

## Build

```
cd mini-sRDI

# build RDI code
cd shellcode
cargo build --release

# create shellcode from RDI exe
cd ../
cargo run

# done, inject shellcode\\target\\x86_64-pc-windows-msvc\\release\\shellcode.bin to any process :3
```

## TODO
- [ ] 32bit
- [ ] more easy to build process :>
