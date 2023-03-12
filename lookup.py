#!/bin/python

import pefile

pe = pefile.PE("C:/Users/oli/Desktop/preem-hle/COREDLL1.DLL")

print("struct { uint16_t ord; const char* name; } static const coredll_symbols[] = {")

for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(f"{{ {hex(sym.ordinal)}, \"{sym.name.decode()}\" }},")

print("};")
