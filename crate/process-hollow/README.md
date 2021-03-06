process-hollow
===

A kind of RunPE technique that hollows out a Process and executes another code.

## Disclaimer
**Code samples are provided for educational purposes. Adequate defenses can only be built by researching attack techniques available to malicious actors. Using this code against target systems without prior permission is illegal in most jurisdictions. The authors are not liable for any damages from misuse of this information or code**.

## Details
This code was written in Rust based on [m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing).</br>
The original checked only Eax at the entry point, so it looked like 32bit.</br>
I made it compatible with 64bit.</br>
It also includes minor fixes and fixes when the base address is different.</br>
Currently, only file to file functions are implemented.</br>

payload-sample.exe is crate/payload-sample.</br>
But yes, I can't prove that it's not a real bad sample here, so set your own responsibility or put another payload yourself.</br>

## Usage
`If you are interested in these, you should know how to use them`

## Sample

these tested my env:
Windows10 Home x64 20H2 19042.867

for 32bit to 32bit:
![alt](./images/sample_32_to_32.gif)

for 64bit to 64bit:
![alt](./images/sample_64_to_64.gif)

## Todo
- [x] refactoring code
- [x] 32bit -> 32bit
- [x] 64bit -> 64bit
- [ ] create the function from binary
- [ ] 32bit -> 64bit (someday, low priority)
- [ ] 64bit -> 32bit (someday, low priority)

## Contribute
WELCOME ANYTIME
