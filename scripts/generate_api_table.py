from sys         import argv

module_list = []

#-----------------------------------------------------------------------
class TypeParser:
    def __init__(self, type):
        self.const   = "const" in type
        self.pointer = "*"     in type
        self.float   = "float" in type

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

    def isConst(self):
        return self.const

    def isFloat(self):
        return self.float

    def isPointer(self):
        return self.pointer
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
class ABIAllocator:
    def __init__(self):
        self.r = 0
        self.f = 0
        self.s = 0

    def next(self, type):
        if type.isFloat():
            if self.r == 7:
                index = self.s
                self.s = self.s + 1
                return f"process_stack_read(p, -{index})"
            else:
                index = self.f
                self.f = self.f + 1
                return f"process_reg_read(p, Register::f{index})"
        else:
            if self.r == 3:
                index = self.s
                self.s = self.s + 1
                return f"process_stack_read(p, -{index})"
            else:
                index = self.r
                self.r = self.r + 1
                return f"process_reg_read(p, Register::r{index})"
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
def parse_func(line):
    abi = ABIAllocator()

    if line.startswith("const"):
        name = line[line.find(" "):line.find("(")].strip()
        ret_type = line[0:line.find(" ")].strip()
    else:
        ret_type = line[0:line.find(" ")].strip()
        name = line[line.find(" "):line.find("(")].strip()

    args = line[line.find("(") + 1 :line.find(")")].split(",")
    args = list(filter(None, map(lambda arg: arg.strip(), args)))

    code = ""

    module_list.append(name)
    code += f"static void {name}_trampoline(Process* p) {{\n"

    code += "\t"
    if ret_type == "void":
        code += f"{name}("
    else:
        code += f"const auto r = {name}("

    if len(args):
        code += "\n"
        for i, arg in enumerate(args):
            type   = TypeParser(arg)
            srcReg = abi.next(type)

            code += "\t\t"
            if type.isNamed():
                code += f"/*{type.getName()}*/ "

            if type.isPointer():
                code += f"({type.getType()})process_mem_target_to_host(p, {srcReg})"
            else:
                code += f"({type.getType()}){srcReg}"

            if i < len(args) - 1:
                code += ",\n"

        code += "\n\t"

    code += ");\n\n"

    if ret_type != "void":
        if TypeParser(ret_type).isPointer():
            code += "\tprocess_reg_write(p, Register::r0, process_mem_host_to_target(p, r));\n"
        elif TypeParser(ret_type).isFloat():
            code += "\tprocess_reg_write(p, Register::f0, r);\n"
        else:
            code += "\tprocess_reg_write(p, Register::r0, r);\n"

    code += "}\n\n"

    return code
#-----------------------------------------------------------------------

#-----------------------------------------------------------------------
with open(argv[1], "r") as inputFile:
    out = ""

    out += "#include \"process.h\"\n\n"

    for line in inputFile.readlines():
        if line.startswith("FUNC"):
            line = line.replace("FUNC", "").strip()
            line = line[0:line.rfind(")") + 1]
            out += parse_func(line)

    out += f"struct {{ const char* name; void* ptr; }} static const sym_table[] = {{\n"
    for module in module_list:
        out += f"\t{{ \"{module}\", {module}_trampoline }},\n"
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
