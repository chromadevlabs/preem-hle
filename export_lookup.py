#!/bin/python

import pefile
import sys;

pe = pefile.PE(sys.env[1])

print(f"struct {{ uint16_t ord; const char* name; }} static const {sys.env[2]}_symbols[] = {{")

for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    print(f"{{ {hex(sym.ordinal)}, \"{sym.name.decode()}\" }},")

print("};")
