
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <vector>

#include "pe.h"
#include "modules.h"
#include "utils.h"

csh cs_context{};

static void disassembler_init() {
    const auto r = cs_open(cs_arch::CS_ARCH_ARM, cs_mode::CS_MODE_THUMB, &cs_context);
    check(r == CS_ERR_OK, "capstone failed to init");
}

static void disassembler_shutdown() {
    cs_close(&cs_context);
}

struct ProcessContext {
    uint8_t* base;
    size_t size;
};

static ProcessContext process;

static bool badMemAccessCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user) {
    printf("0x%08X: BAD MEMORY ACCESS!!\n", address);
    return false;
}

int main(int argc, const char** argv) {
    check(argc > 1, "need rom path");

    auto file = file_load(argv[1]);
    check(file, "failed to open file");

    const auto* dos = cast<const pe::DOS_HEADER*>(file->data());
    const auto* nt  = cast<const pe::NT_HEADER*>(file->data() + dos->e_lfanew);

    // Gizmondo is a ARM thumb device running Window CE.
    check (nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);

    const auto sections = [=] {
        const auto first = cast<pe::SECTION_HEADER*>(cast<uintptr_t>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
        return make_view(first, first + nt->FileHeader.NumberOfSections);
    }();

    auto load = [&](uint32_t rva) {
        return file->data() + *pe::relativeToOffset(sections, rva);
    };

    const auto imageBase   = nt->OptionalHeader.ImageBase;
    const auto entryPoint  = pe::relativeToVirtual(sections, nt->OptionalHeader.AddressOfEntryPoint);
    const auto processSize = [nt, sections] {
        size_t size = 0;

        // I know, I know. I can just use the last section but I dont care.
        for (const auto& s : sections) {
            size = std::max<size_t>(size, s.VirtualAddress + s.Misc.VirtualSize);
        }

        return align<size_t>(size, nt->OptionalHeader.SectionAlignment);
    }();

    check(!(nt->OptionalHeader.DllCharacteristics & pe::DLLFlags::DynamicBase), "Erghhh I dont want to support relocations yet");

    // Apply import table fixups to file data and copy sections after
    const auto idir  = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
    const auto* desc = cast<const pe::IMPORT_DESCRIPTOR*>(load(idir.VirtualAddress));

    while (desc->Name) {
        const auto moduleName = cast<const char*>(load(desc->Name));
        const auto* thunk     = cast<const pe::THUNK_DATA*>(load(desc->FirstThunk));

        while (thunk->u1.AddressOfData) {
            const auto symbolName = [&]{
                if (thunk->u1.Ordinal & pe::Flag::ImportOrdinal) {
                    // COREDLL.dll is the only dll we support ordinals
                    check(std::string_view{moduleName} == "COREDLL.dll", "We don't know about '%s'", moduleName);
                    return module_ordinal_lookup(moduleName, pe::ordinal(thunk->u1.Ordinal));
                }

                return cast<const char*>(load(thunk->u1.AddressOfData + 2));
            }();

            printf("[%s][%s]\n", moduleName, symbolName);

            thunk++;
        }

        desc++;
    }

    process.base  = new uint8_t[mb(128)];
    process.size  = processSize;
    check(process.base, "failed to allocate ram");

    // Copy sections into process space
    for (const auto& s : sections) {
        const auto dstOffset = s.VirtualAddress;
        const auto srcOffset = s.PointerToRawData;

        printf("[%s]: 0x%08X -> 0x%08X\n", s.Name, srcOffset, dstOffset);

        check(dstOffset + s.Misc.VirtualSize < processSize,  "dst is out of bounds");
        memset(process.base + dstOffset, 0, s.Misc.VirtualSize);

        if (s.SizeOfRawData > 0) {
            check(srcOffset + s.SizeOfRawData < file->size(), "source is out of bounds");
            memcpy(process.base + dstOffset, file->data() + srcOffset, s.SizeOfRawData);
        }
    }

    uc_engine* uc{};
    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_THUMB, &uc);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, imageBase, processSize, UC_PROT_ALL, process.base);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    uint32_t value = 0;
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

    value = 0x1000 - 4;
    uc_reg_write(uc, UC_ARM_REG_SP,  &value);

    auto pc = *entryPoint;
    uc_reg_write(uc, UC_ARM_REG_PC,  &pc);

    uc_hook hook;
    r = uc_hook_add(uc, &hook, UC_HOOK_MEM_INVALID, cast<void*>(badMemAccessCallback), nullptr, 0, processSize);
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    printf("ImageBase:  0x%08X\n", imageBase);
    printf("EntryPoint: 0x%08X\n", pc);
    disassembler_init();

    while (true) {
        cs_insn* ins{};
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);

        printf("0x%08X:\t", pc);

        const auto c = cs_disasm(cs_context, process.base, 4, pc, 1, &ins);

        if (c) {
            for (int i = 0; i < c; i++)
                printf("%02X %02X %s", pc, process.base[0], process.base[1], ins->mnemonic);

            cs_free (ins, c);
        }

        printf("\n");

        r = uc_emu_start(uc, pc, pc + 4, 0, 0);
        check(r == UC_ERR_OK, "execution failed: %s\n", uc_strerror(r));
    }

    disassembler_shutdown();
    uc_close(uc);

    delete[] process.base;

    return 0;
}