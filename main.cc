
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

#include <string>

#include "pe.h"
#include "modules.h"
#include "utils.h"

namespace specs {
    const auto ram = mb(128);
}

struct JumpEntry {
    std::string module;
    std::string func;
    void* ptr;
};

static std::vector<uint8_t>     process;
static std::vector<uint32_t>    jumpTable;
static std::vector<JumpEntry>   jumpMap;

static uc_engine*               uc               = nullptr;
static csh                      cs               = 0;
static int                      imageBase        = 0;
static constexpr auto           jumpTableAddress = 0x0000;
static constexpr auto           jumpTableSize    = 0x1000;

#include "coredll.cc"

void dump(const char* path, const void* src, int len) {
    if (auto* f = fopen(path, "wb")) {
        fwrite(src, 1, len, f);
        fclose(f);
    }
}

static bool jumpTableCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user) {
    printf("0x%08X: 0x%08X\n", address, value);
    return false;
}

static bool badMemAccessCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void*) {
    switch (type) {
        case uc_mem_type::UC_MEM_READ_UNMAPPED: {
            printf("0x%08X: UNMAPPED READ!!\n", address);
        } break;

        case uc_mem_type::UC_MEM_FETCH_PROT: {
            const auto  index = (address - jumpTableAddress) / 4;
            const auto& p     = jumpMap[index];

            uint32_t r[13]{};

            for (int i = 0; i <= 12; i++) {
                uc_reg_read(uc, UC_ARM_REG_R0 + i, &r[i]);
                printf("r[%d]: 0x%08X\n", i, r[i]);
            }

            auto arg0 = process.data() + r[0] - imageBase;

            GlobalMemoryStatus((MEMORYSTATUS*)arg0);
            printf("API CALL!!! [%s][%s]\n", p.module.c_str(), p.func.c_str());

            // br lr
            uint32_t addr;
            uc_reg_read(uc,  UC_ARM_REG_LR, &addr);
            uc_reg_write(uc, UC_ARM_REG_PC, &addr);

            return true;
        } break;

        default: {
            printf("0x%08X: UNHANDLED ERROR (%d)!!\n", address, type);
        } break;
    }

    return false;
}

void traceCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    uint8_t code[32]{};
    cs_insn* insn = nullptr;

    uc_mem_read(uc, address, code, size);

    printf("0x%08X: ", address);

    for (int i = 0; i < 4; i++) {
        if (i < size) printf("%02X", code[i]); else printf("  ");
    }

    if (const auto n = cs_disasm(cs, code, size, address, 1, &insn)) {
        printf("\t%s %s\n", insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, n);
        return;
    }

    printf("\tUnknown???\n");
}

int main(int argc, const char** argv) {
    const auto path = argc > 1 ? argv[1]
                               : PREEM_HLE_ROM_PATH "/quake/Quake.exe";

    auto file = file_load(path);
    check(file, "failed to open file");

    const auto* dos = cast<const pe::DOS_HEADER*>(file->data());
    const auto* nt  = cast<const pe::NT_HEADER*>(file->data() + dos->e_lfanew);

    // Gizmondo is a ARM thumb device running Window CE.
    check (nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);

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
            check(srcOffset + s.SizeOfRawData < file->size(), "source is out of bounds");
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
            const auto addr = jumpTableAddress + (jumpTable.size() * 4);

            //printf("[%s][%s]: 0x%08X\n", moduleName, symbolName, addr);
            jumpTable.push_back(addr);
            thunk->u1.Function = addr;

            thunk++;
        }

        desc++;
    }

    {
        auto r = cs_open(cs_arch::CS_ARCH_ARM, cs_mode::CS_MODE_ARM, &cs);
        check(r == CS_ERR_OK, "failed to init capstone. %s\n", cs_strerror(r));
    }

    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_ARM, &uc);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, imageBase, process.size(), UC_PROT_ALL, base);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, jumpTableAddress, jumpTableSize, UC_PROT_READ, jumpTable.data());
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

    const auto sp = process.size() - mb(2);
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

    hook = 0;
    r = uc_hook_add(uc, &hook, UC_HOOK_MEM_READ,
                    cast<void*>(jumpTableCallback), nullptr,
                    jumpTableAddress, jumpTableAddress + jumpTableSize);
    check(r == UC_ERR_OK, "failed to hook jump table: %s\n", uc_strerror(r));

    printf("ImageBase:  0x%08X\n", imageBase);
    printf("EntryPoint: 0x%08X\n", pc);

    r = uc_emu_start(uc, pc, pc + process.size(), 0, 0);
    if (r != UC_ERR_OK) {
        printf("%s\n", uc_strerror(r));
    }

    cs_close(&cs);
    uc_close(uc);

    return 0;
}