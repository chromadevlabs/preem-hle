from collections import namedtuple
from sys         import argv

Type = namedtuple("Type", [ "Name", "Size", "Pointer", "FloatingPoint" ])

module_list = []
type_table  = [
    Type("HANDLE",  4, True,  False),
    Type("BOOL",    4, False, False),
    Type("int",     4, False, False),
    Type("void*",   4, True,  False),
    Type("LPCSTR",  4, True,  False),
    Type("LPCWSTR", 4, True,  False)
]

class ABIRegisterAllocator:
    def __init__(self):
        self.r = 0
        self.f = 0

    def next(self, Type):
        type = get_type(Type)

        if type.FloatingPoint == False:
            index = self.r
            assert index < 4
            self.r = self.r + 1
            return f"r{index}"
        else:
            index = self.f
            assert index < 8
            self.f = self.f + 1
            return f"f{index}"

def get_type(Name):
    for type in type_table:
        if type.Name == Name:
            return type;

    raise Exception(f"Unknown type '{Name}'")

def parse_func(line):
    abi = ABIRegisterAllocator()
    ret_type = line[0:line.find(" ")].strip()
    name = line[line.find(" "):line.find("(")].strip()
    args = line[line.find("(") + 1 :line.find(")")].split(",")
    code = ""

    module_list.append(name)
    code += f"static void {name}_trampoline(Process* p) {{\n"

    code += "\t"
    if ret_type == "void":
        code += f"{name}("
    else:
        code += f"const auto r = {name}(\n"

    for i, arg in enumerate(args):
        type = arg.split()[0]
        name = arg.split()[1]
        srcReg  = abi.next(type)

        if get_type(type).Pointer:
            code += f"\t\t({type})process_mem_target_to_host(p, process_reg_read(p, Register::{srcReg}))"
        else:
            code += f"\t\t({type})process_reg_read(p, Register::{srcReg})"

        if i < len(args) - 1:
            code += ",\n"

    code += "\n\t);\n"

    if ret_type != "void":
        code += "\tprocess_reg_write(p, Register::r0, r);\n"

    code += "}"

    return code

with open(argv[1], "r") as inputFile:
    out = ""

    for line in inputFile.readlines():
        if line.startswith("FUNC"):
            line = line.replace("FUNC", "").strip()
            line = line[0:line.rfind(")") + 1]
            out += parse_func(line);

    out += "\n\n"
    out += f"struct {{ const char* name; void* ptr; }} static const {argv[2]}_modules[] = {{\n"
    for module in module_list:
        out += f"{{ \"{module}\", {module}_trampoline }},\n"
    out += "};"

    print(out.replace("\t", "    "))