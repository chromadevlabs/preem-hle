
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <vector>

#include "pe.h"
#include "modules.h"
#include "utils.h"

csh cs_context{};

static void disassembler_init() {
    const auto r = cs_open(cs_arch::CS_ARCH_ARM, cs_mode::CS_MODE_THUMB, &cs_context);
    check(r == CS_ERR_OK, "capstone failed to init: %s", cs_strerror (r));
}

static void disassembler_shutdown() {
    cs_close(&cs_context);
}

struct ProcessContext {
    std::vector<uint8_t> base;
};

static ProcessContext process;

static bool badMemAccessCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user) {
    printf("0x%08X: BAD MEMORY ACCESS!!\n", address);
    return false;
}

static void dump_mem (uint32_t address, size_t length) {
    const auto end = address + length;

    printf("          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n");

    while (address < end) {
        const auto stride = std::min<size_t>(16, end - address);

        printf("%08X: ", address);
        for (size_t j = 0; j < stride; j++)
            printf("%02X ", process.base[address + j]);

        printf("\n");
        address += stride;
    }
}

int main(int argc, const char** argv) {
    //check(argc > 1, "need rom path");

    auto file = file_load("c:/users/oli/Desktop/preem-hle/roms/quake/Quake.exe");
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

            //printf("[%s][%s]\n", moduleName, symbolName);

            thunk++;
        }

        desc++;
    }

    process.base.resize(mb(128));
    auto* base = process.base.data();

    // Copy sections into process space
    for (const auto& s : sections) {
        const auto dstOffset = s.VirtualAddress;
        const auto srcOffset = s.PointerToRawData;

              auto dst = base + dstOffset;
        const auto src = file->data() + srcOffset;

        printf("[%s]: 0x%08X -> [ 0x%08X - 0x%08X]\n", s.Name, srcOffset, dstOffset, dstOffset + s.Misc.VirtualSize);

        memset(dst, 0, s.Misc.VirtualSize);

        if (s.SizeOfRawData > 0) {
            check(srcOffset + s.SizeOfRawData < file->size(), "source is out of bounds");
            memcpy(dst, src, s.SizeOfRawData);
        }
    }

    uc_engine* uc{};
    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_THUMB, &uc);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, imageBase, process.base.size(), UC_PROT_ALL, base);
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

    auto pc = 0x1000 + *entryPoint;
    uc_reg_write(uc, UC_ARM_REG_PC,  &pc);

    //uc_hook hook;
    //r = uc_hook_add(uc, &hook, UC_HOOK_MEM_INVALID, cast<void*>(badMemAccessCallback), nullptr, 0, processSize);
    //check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    //file_save ("dump.bin", process.base);
    dump_mem(pc, 512);

    printf("ImageBase:  0x%08X\n", imageBase);
    printf("EntryPoint: 0x%08X\n", pc);
    disassembler_init();

    while (true) {
        cs_insn* ins{};
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);

        const auto c = cs_disasm(cs_context, base, 32, pc, 1, &ins);

        if (c) {
            for (int i = 0; i < c; i++) {
                const auto inst = ins[i];
                 
                printf("0x%08X: ", inst.address);

                for (int c = 0; c < 4; c++) {
                    if (c < inst.size)
                        printf("%02X ", inst.bytes[c]);
                    else
                        printf("   ");
                }
                    
                printf("\t%s %s\n", inst.mnemonic, inst.op_str);
            }

            cs_free (ins, c);
        }

        r = uc_emu_start(uc, pc, pc + 0x1000, 0, 0);
        if (r != UC_ERR_OK) {
            printf("%s\n", uc_strerror(r));
            break;
        }
    }

    disassembler_shutdown();
    uc_close(uc);

    return 0;
}