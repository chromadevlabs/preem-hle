
from collections import namedtuple
from sys import argv

ModuleEntry = namedtuple("ModuleEntry", ["module", "symbol"])

symbols = []
current_namespace = ""

#-----------------------------------------------------------------------
class TypeParser:
    def __init__(self, type):
        self.const   = "const" in type
        self.float   = "float" in type
        self.pointer = "*"     in type

        if self.const:
            type = type.replace("const", "")

        if self.pointer:
            type = type.replace("*", "")

        split = type.split()
        self.type = split[0].strip()
        self.name = split[1].strip() if len(split) > 1 else ""

    def getType(self):
        out = ""

        if self.isConst():
            out += "const "

        out += self.type

        if self.isPointer():
            out += "*"

        return out

    def getName(self):
        return self.name

    def isNamed(self):
        return True if self.name != "" else False

    def isVariadic(self):
        return True if self.type == "..." else False

    def isConst(self):
        return self.const

    def isFloat(self):
        return self.float

    def isPointer(self):
        return self.pointer
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
# https://learn.microsoft.com/en-us/cpp/build/overview-of-arm-abi-conventions?view=msvc-170
class ABIAllocator:
    def __init__(self):
        self.reg_index = 0
        self.float_reg_index = 0
        self.stack_offset = 0

    def nextStackSlot(self):
        index = self.stack_offset
        self.stack_offset = self.stack_offset + 1
        return f"process_stack_read(p, {index})"

    def nextRegister(self, type):
        if type.isFloat():
            if self.float_reg_index == 8:
                return self.nextStackSlot()
            else:
                index = self.float_reg_index
                self.float_reg_index = self.float_reg_index + 1
                return f"process_reg_read_f32(p, Register::s{index})"
        else:
            if self.reg_index == 4:
                return self.nextStackSlot()
            else:
                index = self.reg_index
                self.reg_index = self.reg_index + 1
                return f"process_reg_read_u32(p, Register::r{index})"
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
def parse_func(line):
    code = ""
    abi = ABIAllocator()

    name_start = line.find("(")
    name_end = line.rfind(" ", 0, name_start)
    name = line[name_end : name_start].strip()
    ret_type = line[0 : name_end].strip()
    args = line[name_start + 1 : line.find(")")].split(",")
    args = list(filter(None, map(lambda arg: arg.strip(), args)))

    symbols.append(name)
    code += f"static void {name}_trampoline(Process* p) {{\n"
    
    if len(args):
        for i, arg in enumerate(args):
            type   = TypeParser(arg)
            srcReg = abi.nextRegister(type)

            code += f"\tauto "
            code += f"_{i}{type.getName()} = " if type.isNamed() else f"_{i} = "

            if type.isPointer():
                code += f"({type.getType()})process_mem_target_to_host(p, {srcReg})"
            elif type.isVariadic():
                code += f"0"
            else:
                code += f"({type.getType()}){srcReg}"

            code += ";\n"

        code += "\n\t"

    if ret_type == "void":
        code += f"{current_namespace}::{name}("
    else:
        code += f"const auto r = {current_namespace}::{name}("

    for i, arg in enumerate(args):
        type = TypeParser(arg)
        code += f"_{i}{type.getName()}" if type.isNamed() else f"_{i}"

        if i < len(args) - 1:
            code += ", "

    code += ");\n\n"

    if ret_type != "void":
        if TypeParser(ret_type).isPointer():
            code += "\tprocess_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));\n"
        elif TypeParser(ret_type).isFloat():
            code += "\tprocess_reg_write_f32(p, Register::s0, (float)r);\n"
        else:
            code += "\tprocess_reg_write_u32(p, Register::r0, (uint32_t)r);\n"
    else:
        code += "\tprocess_reg_write_u32(p, Register::r0, 0);\n"

    code += "}\n\n"

    return code
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
with open(argv[1], "r") as inputFile:
    out = ""

    out += "#include \"process.h\"\n"

    for line in inputFile.readlines():
        if line.startswith("namespace"):
            current_namespace = line.split()[1]
        if line.startswith("FUNC"):
            line = line.replace("FUNC", "").strip()
            line = line[0:line.rfind(")") + 1]
            out += parse_func(line)

    out += f"struct {{ const char* name; void* ptr; }} static const sym_table[] = {{\n"
    for symbol in symbols:
        out += f"\t{{ \"{symbol}\", (void*){symbol}_trampoline }},\n"
    out += "};\n\n"

    out += "#include <string_view>\n"
    out += "void* symbol_find(const char* name) {\n"
    out += "\tfor (auto sym : sym_table) {\n"
    out += "\t\tif (std::string_view{ name } == sym.name) return sym.ptr;\n"
    out += "\t}\n"
    out += "\treturn nullptr;\n"
    out += "}\n"

    print(out.replace("\t", "    "))
#-----------------------------------------------------------------------
