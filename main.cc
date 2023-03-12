
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <vector>

#include "pe.h"
#include "modules.h"
#include "utils.h"

int main(int argc, const char** argv) {
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
    const auto entryPoint  = nt->OptionalHeader.AddressOfEntryPoint;
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

    auto* process = new byte[mb(128)];
    check(process, "failed to allocate ram");

    // Copy sections into process space
    for (const auto& s : sections) {
        const auto dstOffset = s.VirtualAddress;
        const auto srcOffset = s.PointerToRawData;

        printf("[%s]: 0x%08X -> 0x%08X\n", s.Name, srcOffset, dstOffset);

        check(dstOffset + s.Misc.VirtualSize < processSize,  "dst is out of bounds");
        memset(process + dstOffset, 0, s.Misc.VirtualSize);

        if (s.SizeOfRawData > 0) {
            check(srcOffset + s.SizeOfRawData < file->size(), "source is out of bounds");
            memcpy(process + dstOffset, file->data() + srcOffset, s.SizeOfRawData);
        }
    }

    uc_engine* uc{};
    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_THUMB, &uc);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(uc, imageBase, processSize, UC_PROT_ALL, process);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    using uc_registers = std::initializer_list<std::pair<int, uint32_t>>;
    auto reg_write32 = [uc](uc_registers&& registers) {
        for (auto reg : registers)
            uc_reg_write(uc, reg.first, &reg.second);
    };

    reg_write32({
        { UC_ARM_REG_R0,  0 },
        { UC_ARM_REG_R1,  0 },
        { UC_ARM_REG_R2,  0 },
        { UC_ARM_REG_R3,  0 },
        { UC_ARM_REG_R4,  0 },
        { UC_ARM_REG_R5,  0 },
        { UC_ARM_REG_R6,  0 },
        { UC_ARM_REG_R7,  0 },
        { UC_ARM_REG_R8,  0 },
        { UC_ARM_REG_R9,  0 },
        { UC_ARM_REG_R10, 0 },
        { UC_ARM_REG_R11, 0 },
        { UC_ARM_REG_R12, 0 },
        { UC_ARM_REG_R13, 0 },
        { UC_ARM_REG_R14, 0 },
        { UC_ARM_REG_R15, 0 },
        { UC_ARM_REG_SP,  0x1000 - 4 }, // TODO

        // Lord help me
        { UC_ARM_REG_PC,  entryPoint }
    });

    r = uc_emu_start(uc, entryPoint, entryPoint + 4, 0, 1);
    check(r == UC_ERR_OK, "execution failed: %s\n", uc_strerror(r));

    uc_close(uc);

    delete[] process;

    return 0;
}