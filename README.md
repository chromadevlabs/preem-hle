
# Preem-HLE

This an attempt at emulating the Gizmondo, an ARM/WinCE gaming handheld console.

So far it can load a wince PE image, properly patch the dynamically linked functions, and begin execution... Until it gets a couple of functions in and it does some weird expection shenanigans which I don't know how to handle.

scripts/generate_api_table.py parses functions.cc and generates some bridging code so normal C functions can interop with the emulated CPU.

It depends on capstone for disassembly and unicorn for the CPU emulation.
