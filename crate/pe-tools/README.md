pe-tools
===

Utilities related to PE, memory, etc.

## Disclaimer
**Code samples are provided for educational purposes. Adequate defenses can only be built by researching attack techniques available to malicious actors. Using this code against target systems without prior permission is illegal in most jurisdictions. The authors are not liable for any damages from misuse of this information or code**.

## Details
This library contains various functions related to PE, etc manipulation and so on.</br>
Add functions that will need little by little.</br>
**Most are unsafe operation.**</br>
so, please be careful when using it.</br>

## There are other crates like the PE parser, why not use it?
I am using goblin as a PE parser.</br>
pe-tools do a lot of memory writes, which are more, ah no, very very unsafe than they are.</br>
They are good for "analysis", pe-tools focuses on "manipulating" PE.</br>

## Usage
`If you are interested in these, you should know how to use them`

## info
shared:</br>
contains methods shared by x86 and 64 and util functions</br>
</br>
x86, x64:</br>
Most of the methods for PE manipulations are here.</br>
contains the main PEContainer structure and a few util functions.</br>
x86 and x64 are almost the same code, but it's split into two because some structures have different types and pointer sizes.</br>

## Contribute
WELCOME ANYTIME
