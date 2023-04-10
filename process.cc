
#include "process.h"
#include "pe.h"
#include "utils.h"

#include <memory>
#include <unicorn/unicorn.h>

#define cast reinterpret_cast

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

const auto ram = mb(128);

//static std::vector<uint32_t>  jumpTable;
//static std::vector<JumpEntry> jumpMap;
static const Range<uint32_t>  stackRange       = { 0x07E00000, 0x08000000 };
static const Range<uint32_t>  memoryRange      = { 0x00A00000, 0x07DFFFFF };
static const Range<uint32_t>  jumpTableRange   = { 0x00000000, 0x00001000 };

struct Process {
    uc_engine* context;
    uint32_t   imagebase;
    uint32_t   entrypoint;
    uint8_t*   memory;
};

/*static bool badMemAccessCallback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void*) {
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
}*/

Process* process_create(const uint8_t* peImage, int peImageSize) {
    std::unique_ptr<Process> p { new Process{} };

    const auto* dos = cast<const pe::DOS_HEADER*>(peImage);
    const auto* nt  = cast<const pe::NT_HEADER*>(peImage + dos->e_lfanew);

    // Gizmondo is a ARM thumb device running Window CE.
    check(nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);

    const auto sections = [=] {
        const auto first = cast<pe::SECTION_HEADER*>(cast<uintptr_t>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
        return make_view(first, first + nt->FileHeader.NumberOfSections);
    }();

    p->imagebase  = nt->OptionalHeader.ImageBase;
    p->entrypoint = nt->OptionalHeader.AddressOfEntryPoint;

    check(!(nt->OptionalHeader.DllCharacteristics & pe::DLLFlags::DynamicBase), "Erghhh I dont want to support relocations yet");

    auto* base = p->memory = new uint8_t[mb(128)];

    // Copy sections into process space
    for (const auto& s : sections) {
        const auto dstOffset = s.VirtualAddress;
        const auto srcOffset = s.PointerToRawData;

        auto dst = base + dstOffset;
        const auto src = peImage + srcOffset;

        print("[%-8s]: 0x%08X -> [ 0x%08X - 0x%08X]\n", s.Name, srcOffset, dstOffset, dstOffset + s.Misc.VirtualSize);

        memset(dst, 0, s.Misc.VirtualSize);

        if (s.SizeOfRawData > 0) {
            check(srcOffset + s.SizeOfRawData <= peImageSize,
                  "source is out of bounds. { 0x%08X - 0x%08X } is out of bounds of %08X",
                  s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, peImageSize);

            memcpy(dst, src, s.SizeOfRawData);
        }
    }

    auto ptr = [&p, sections](uint32_t address)->uint8_t* {
        return p->memory + address;
    };

    // Apply import table fixups
    const auto idir        = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
    auto*      desc        = cast<pe::IMPORT_DESCRIPTOR*>(ptr(idir.VirtualAddress));

    while (desc->Name) {
        const auto moduleName = cast<const char*>(ptr(desc->Name));
        auto*      thunk      = cast<pe::THUNK_DATA*>(ptr(desc->FirstThunk));

        while (thunk->u1.AddressOfData) {
            /*const auto symbolName = [&]{
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
            thunk->u1.Function = addr;*/

            thunk++;
        }

        desc++;
    }

    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_ARM, &p->context);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(p->context, p->imagebase, mb(128), UC_PROT_ALL, base);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    //r = uc_mem_map_ptr(uc, jumpTableRange.getStart(), jumpTableRange.length(), UC_PROT_READ, jumpTable.data());
    //check(r == UC_ERR_OK, "failed to map jump table. %s", uc_strerror(r));

    /*uc_hook hook = 0;
    r = uc_hook_add(uc, &hook, UC_HOOK_MEM_INVALID,
                    cast<void*>(badMemAccessCallback), nullptr,
                    0, process.size());
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    hook = 0;
    r = uc_hook_add(uc, &hook, UC_HOOK_CODE,
                    cast<void*>(traceCallback), nullptr,
                    0, process.size());
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));*/

    return p.release();
}

void process_destroy(Process* p) {
    uc_close(p->context);
    delete[] p->memory;
    delete p;
}

void process_register_imported_function(Process* p, const char* module, const char* func, const void* ptr) {
}

void process_register_imported_function(Process* p, const char* module, int ord, const void* ptr) {
}

uint32_t process_register_read(const Process* p, int reg) {
    check(reg < 16, "too many registers");

    uint32_t value{};
    uc_reg_read(p->context, UC_ARM_REG_R0 + reg, &value);
    return value;
}

void process_register_write(Process* p, int reg, uint32_t value) {
    check(reg < 16, "too many registers");

    uc_reg_write(p->context, UC_ARM_REG_R0 + reg, &value);
}

void process_reset(Process* p) {
    // TODO:
    const uint32_t value = 0;
    for (int i = 0; i < 16; i++)
        process_register_write(p, i, 0);

    process_register_write(p, RegisterIndex::Reg_sp, stackRange.getEnd() - 4);
    process_register_write(p, RegisterIndex::Reg_pc, p->imagebase + p->entrypoint);
}

bool process_step(Process* p) {
    const auto pc = 0;

    return uc_emu_start(p->context, pc, pc + 1, 0, 0) != UC_ERR_OK;
}

void process_panic_dump(const Process* p) {
    for (int i = 0; i < 16; i += 2) {
        print("r[%d]  = 0x%08X\t", i + 0, process_register_read(p, (RegisterIndex)i + 0));
        print("r[%d]  = 0x%08X\n", i + 1, process_register_read(p, (RegisterIndex)i + 1));
    }
}