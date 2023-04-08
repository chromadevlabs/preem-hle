
#include <unicorn/unicorn.h>

#include "pe.h"
#include "modules.h"
#include "utils.h"
#include "disassembler.h"

namespace specs {
    const auto ram = mb(128);
}

struct JumpEntry {
    std::string module;
    std::string func;
    void* ptr;
};

/* ------------ MemoryMap ------------
0x07FFFFFF -> STACK_END
0x07E00000 -> STACK_START      <0x07E00000 - 0x07FFFFFF>
0x07DFFFFF -> MEMORY_END
0x00A00000 -> MEMORY_START     <0x00A00000 - 0x07DFFFFF>
0x009B2430 -> SECTIONS_END
0x00011000 -> SECTIONS_START   <0x00011000 - 0x009B2430>
0x00010000 -> IMAGEBASE
0x00001000 -> JUMP_TABLE_END
0x00000000 -> JUMP_TABLE_START <0x00000000 - 0x00001000>
   ------------------------------------*/

// global
uc_engine* uc = nullptr;

static std::vector<uint8_t>   process;
static std::vector<uint32_t>  jumpTable;
static std::vector<JumpEntry> jumpMap;
static uint32_t               imageBase        = 0;
static const Range<uint32_t>  stackRange       = { 0x07E00000, 0x08000000 };
static const Range<uint32_t>  memoryRange      = { 0x00A00000, 0x07DFFFFF };
static const Range<uint32_t>  jumpTableRange   = { 0x00000000, 0x00001000 };

#include "coredll.cc"

#include <cstdio>

void print(const string_view& format, ...) {
    va_list args;

    va_start(args, format);
    vfprintf(stdout, format.data(), args);
    va_end(args);
}

void print_string(string& string, const string_view& format, ...) {
    char local[512]{};

    va_list args;

    va_start(args, format);
    vsnprintf(local, sizeof(local), format.data(), args);
    va_end(args);

    string += local;
}

template<typename T>
constexpr auto hostToTarget(const T* ptr) {
    auto addr = uintptr_t(ptr);
    addr -= uintptr_t(process.data());
    return addr - imageBase;
}

template<typename T>
constexpr auto targetToHost(uint32_t addr) {
    auto* ptr = process.data() + addr - imageBase;
    return (T*)ptr;
}

namespace virt {
    auto reg_read_r(uc_engine* uc, int index) {
        uint32_t v;
        uc_reg_read(uc, UC_ARM_REG_R0 + index, &v);
        return v;
    }

    auto reg_write_r(uc_engine* uc, int index, uint32_t v) {
        uc_reg_write(uc, UC_ARM_REG_R0 + index, &v);
    }

    auto reg_read_lr(uc_engine* uc)              { uint32_t v; uc_reg_read(uc, UC_ARM_REG_LR, &v); return v; }
    auto reg_read_sp(uc_engine* uc)              { uint32_t v; uc_reg_read(uc, UC_ARM_REG_SP, &v); return v; }
    auto reg_read_pc(uc_engine* uc)              { uint32_t v; uc_reg_read(uc, UC_ARM_REG_PC, &v); return v; }
    auto reg_read_ip(uc_engine* uc)              { uint32_t v; uc_reg_read(uc, UC_ARM_REG_IP, &v); return v; }

    auto reg_write_lr(uc_engine* uc, uint32_t v) { uc_reg_write(uc, UC_ARM_REG_LR, &v); }
    auto reg_write_sp(uc_engine* uc, uint32_t v) { uc_reg_write(uc, UC_ARM_REG_SP, &v); }
    auto reg_write_pc(uc_engine* uc, uint32_t v) { uc_reg_write(uc, UC_ARM_REG_PC, &v); }
    auto reg_write_ip(uc_engine* uc, uint32_t v) { uc_reg_write(uc, UC_ARM_REG_IP, &v); }
}

static bool badMemAccessCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void*) {
    switch (type) {
        case uc_mem_type::UC_MEM_FETCH_PROT: {
            const auto  index   = (address - jumpTableRange.getStart()) / 4;
            const auto& p       = jumpMap[index];

            printf("0x%08llX: [%s][%s]\n", address, p.module.c_str(), p.func.c_str());

            using namespace coredll;
            switch (StringHash{p.func}) {
                case StringHash{"GlobalMemoryStatus"}: {
                    __debugbreak();
                } break;

                case StringHash{"malloc"}: {
                    __debugbreak();
                } break;

                default: return false;
            }

            // jump back
            const auto lr = virt::reg_read_lr(uc);
            virt::reg_write_pc(uc, lr);
            return true;
        } break;

        default: {
            printf("0x%08llX: UNHANDLED ERROR (%d)!!\n", address, type);
        } break;
    }

    return false;
}

void traceCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    uint8_t code[4]{};

    uc_mem_read(uc, address, code, size);
    //disassemble_single(code, size, address);
}

int main(int argc, const char** argv) {
    const auto path = argc > 1 ? argv[1]
                               : PREEM_HLE_ROM_PATH "/test/main.exe";

    auto file = file_load(path);
    check(file, "failed to open file");

    const auto* dos = cast<const pe::DOS_HEADER*>(file->data());
    const auto* nt  = cast<const pe::NT_HEADER*>(file->data() + dos->e_lfanew);

    // Gizmondo is a ARM thumb device running Window CE.
    check(nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);

    const auto sections = [=] {
        const auto first = cast<pe::SECTION_HEADER*>(cast<uintptr_t>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
        return make_view(first, first + nt->FileHeader.NumberOfSections);
    }();

               imageBase  = nt->OptionalHeader.ImageBase;
    const auto entryPoint = nt->OptionalHeader.AddressOfEntryPoint;

    check(!(nt->OptionalHeader.DllCharacteristics & pe::DLLFlags::DynamicBase), "Erghhh I dont want to support relocations yet");

    process.resize(specs::ram);
    auto* base = process.data();

    // Copy sections into process space
    for (const auto& s : sections) {
        const auto dstOffset = s.VirtualAddress;
        const auto srcOffset = s.PointerToRawData;

              auto dst = base + dstOffset;
        const auto src = file->data() + srcOffset;

        printf("[%-8s]: 0x%08X -> [ 0x%08X - 0x%08X]\n", s.Name, srcOffset, dstOffset, dstOffset + s.Misc.VirtualSize);

        memset(dst, 0, s.Misc.VirtualSize);

        if (s.SizeOfRawData > 0) {
            check(srcOffset + s.SizeOfRawData <= file->size(),
                  "source is out of bounds. { 0x%08X - 0x%08X } is out of bounds of %08X",
                  s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, file->size());
            memcpy(dst, src, s.SizeOfRawData);
        }
    }

    auto ptr = [sections](uint32_t address)->uint8_t* {
        return process.data() + address;
    };

    // Apply import table fixups
    const auto idir        = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
    auto*      desc        = cast<pe::IMPORT_DESCRIPTOR*>(ptr(idir.VirtualAddress));

    while (desc->Name) {
        const auto moduleName = cast<const char*>(ptr(desc->Name));
        auto*      thunk      = cast<pe::THUNK_DATA*>(ptr(desc->FirstThunk));

        while (thunk->u1.AddressOfData) {
            const auto symbolName = [&]{
                if (thunk->u1.Ordinal & pe::Flag::ImportOrdinal) {
                    check(std::string_view{moduleName} == "COREDLL.dll", "We don't know about '%s'", moduleName);
                    return module_ordinal_lookup(moduleName, pe::ordinal(thunk->u1.Ordinal));
                }

                return cast<const char*>(ptr(thunk->u1.AddressOfData + 2));
            }();

            jumpMap.push_back({ moduleName, symbolName, nullptr });
            const auto addr = jumpTableRange.getStart() + (jumpTable.size() * 4);

            printf("[%s][%s]: 0x%08lX\n", moduleName, symbolName, addr);
            jumpTable.push_back(addr);
            thunk->u1.Function = addr;

            thunk++;
        }

        desc++;
    }

    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_ARM, &uc);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, imageBase, process.size(), UC_PROT_ALL, base);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, jumpTableRange.getStart(), jumpTableRange.length(), UC_PROT_READ, jumpTable.data());
    check(r == UC_ERR_OK, "failed to map jump table. %s", uc_strerror(r));

    // TODO:
    const uint32_t value = 0;
    uc_reg_write(uc, UC_ARM_REG_R0,  &value);
    uc_reg_write(uc, UC_ARM_REG_R1,  &value);
    uc_reg_write(uc, UC_ARM_REG_R2,  &value);
    uc_reg_write(uc, UC_ARM_REG_R3,  &value);
    uc_reg_write(uc, UC_ARM_REG_R4,  &value);
    uc_reg_write(uc, UC_ARM_REG_R5,  &value);
    uc_reg_write(uc, UC_ARM_REG_R6,  &value);
    uc_reg_write(uc, UC_ARM_REG_R7,  &value);
    uc_reg_write(uc, UC_ARM_REG_R8,  &value);
    uc_reg_write(uc, UC_ARM_REG_R9,  &value);
    uc_reg_write(uc, UC_ARM_REG_R10, &value);
    uc_reg_write(uc, UC_ARM_REG_R11, &value);
    uc_reg_write(uc, UC_ARM_REG_R12, &value);
    uc_reg_write(uc, UC_ARM_REG_R13, &value);
    uc_reg_write(uc, UC_ARM_REG_R14, &value);

    const auto sp = stackRange.getEnd();    // assuming the stack grows down..
    auto       pc = imageBase + entryPoint;

    uc_reg_write(uc, UC_ARM_REG_SP,  &sp);
    uc_reg_write(uc, UC_ARM_REG_PC,  &pc);

    uc_hook hook = 0;
    r = uc_hook_add(uc, &hook, UC_HOOK_MEM_INVALID,
                    cast<void*>(badMemAccessCallback), nullptr,
                    0, process.size());
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    hook = 0;
    r = uc_hook_add(uc, &hook, UC_HOOK_CODE,
                    cast<void*>(traceCallback), nullptr,
                    0, process.size());
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    printf("ImageBase:  0x%08X\n", imageBase);
    printf("EntryPoint: 0x%08X\n", pc);

    allocator_init(memoryRange.getStart(), memoryRange.getEnd());

    if ((r = uc_emu_start(uc, pc, pc + process.size(), 0, 0)); r != UC_ERR_OK) {
        const Interop inter{uc};

        printf("r[0]  = 0x%08X\t", inter.read(0));  printf("r[1]  = 0x%08X\n", inter.read(1));
        printf("r[2]  = 0x%08X\t", inter.read(2));  printf("r[3]  = 0x%08X\n", inter.read(3));
        printf("r[4]  = 0x%08X\t", inter.read(4));  printf("r[5]  = 0x%08X\n", inter.read(5));
        printf("r[6]  = 0x%08X\t", inter.read(6));  printf("r[7]  = 0x%08X\n", inter.read(7));
        printf("r[8]  = 0x%08X\t", inter.read(8));  printf("r[9]  = 0x%08X\n", inter.read(9));
        printf("r[10] = 0x%08X\t", inter.read(10)); printf("r[11] = 0x%08X\n", inter.read(11));
        printf("r[12] = 0x%08X\t", inter.read(12)); printf("r[13] = 0x%08X\n", inter.read(13));
        printf("r[14] = 0x%08X\t", inter.read(14)); printf("r[15] = 0x%08X\n", inter.read(15));
        printf("sp    = 0x%08X\t", inter.readSP()); printf("pc    = 0x%08X\n", inter.readPC());
        printf("lr    = 0x%08X\t", inter.readLR()); printf("ip    = 0x%08X\n", inter.readIP());

        printf("%s\n", uc_strerror(r));
    }


    uc_close(uc);

    return 0;
}