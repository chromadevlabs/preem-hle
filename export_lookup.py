#!/bin/python

import pefile
import os
import sys
import pathlib

def symbol_find(name):
    for root, dir, files in os.walk("C:/Users/oli/Downloads/Armv4i/Armv4i"):
        for file in files:
            if file.endswith(".h"):
                with open(os.path.join(root, file)) as f:
                    for line in f.readlines():
                        if line.__contains__(name):
                            print(f"Found {name} in {file}: {line.rstrip()}")
                            return

pe = pefile.PE(sys.argv[1])

for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    symbol_find(sym.name.decode())

#print(f"struct {{ uint16_t ord; const char* name; }} static const {sys.env[2]}_symbols[] = {{")
#for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
#    print(f"{{ {hex(sym.ordinal)}, \"{sym.name.decode()}\" }},")
#print("};")
