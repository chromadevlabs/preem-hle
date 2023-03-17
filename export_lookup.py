#!/bin/python

import sys, re, os

functions = []

def extract_functions(code):
    pattern = r'^(\w+)\s+(\w+)\s*\(([^)]*)\);'
    regex = re.compile(pattern, re.MULTILINE)

    blacklist = [ "WINAPI", "STDAPI",  "HRESULT",
                  "__in",    "__out",  "struct" ]

    for word in blacklist:
        code = code.replace(word, "")

    matches = regex.findall(code)
    functions = [(match[0], match[1], match[2].split(',')) for match in matches]

    return functions

# load all functions
for root, directories, files in os.walk(sys.argv[1]):
    for file in files:
        with open(os.path.join(root, file)) as sourceFile:
            for func in extract_functions(sourceFile.read()):
                ret  = func[0].strip()
                name = func[1].strip()

                args = [re.sub(r'//.*?\n', '', arg.strip()) for arg in func[2]]
                args = [re.sub(r'//.*?\n|/\*.*?\*/', '', arg, flags=re.DOTALL) for arg in args]
                args = [re.sub(r'\s{2,}', ' ', arg) for arg in args]

                print(f"{ret} {name} {args}")