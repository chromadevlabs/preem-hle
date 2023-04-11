
#include <memory>
#include <vector>
#include <string>
#include <unicorn/unicorn.h>

#include "process.h"
#include "utils.h"
#include "pe.h"

using jump_callback_t = void(*)(Process*);

static constexpr auto JumpTableSize = 1000;

struct Process {
    uc_engine* context;
    uint8_t*   memory;
    uint32_t   imagebase;
    uint32_t   entrypoint;

    std::vector<uc_hook> hooks;
    process_trace_callback_t tracecb;

    uint32_t jumptable[JumpTableSize];
    jump_callback_t jumpfuncs[JumpTableSize];
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

static const Range<uint32_t>  stackRange       = { 0x07E00000, 0x08000000 };
static const Range<uint32_t>  memoryRange      = { 0x00A00000, 0x07DFFFFF };
static const Range<uint32_t>  jumpTableRange   = { 0x00000000, 0x00001000 };

static const char* coredll_get_name_from_ordinal(uint16_t ord) {
    #include "coredll_ordinals.inl"

    for (const auto& symbol : coredll_symbols) {
        if (symbol.ord == ord)
            return symbol.name;
    }

    return nullptr;
}

// Implemented in symbols.inl
void* symbol_find(const char*);

static void trace_proxy(uc_engine* uc, uint64_t address, uint64_t size, void* user) {
    auto* p = cast<Process*>(user);
    p->tracecb(p, address);
}

static bool api_trampoline_callback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user) {
    auto* p = cast<Process*>(user);

    const auto index = address / 4;



    auto ret = process_reg_read(p, Register::lr);
    process_reg_write(p, Register::pc, ret);

    return true;
}

static constexpr int uc_reg_map(Register r) {
    switch (r) {
    case Register::r0:  return UC_ARM_REG_R0;
    case Register::r1:  return UC_ARM_REG_R1;
    case Register::r2:  return UC_ARM_REG_R2;
    case Register::r3:  return UC_ARM_REG_R3;
    case Register::r4:  return UC_ARM_REG_R4;
    case Register::r5:  return UC_ARM_REG_R5;
    case Register::r6:  return UC_ARM_REG_R6;
    case Register::r7:  return UC_ARM_REG_R7;
    case Register::r8:  return UC_ARM_REG_R8;
    case Register::r9:  return UC_ARM_REG_R9;
    case Register::r10: return UC_ARM_REG_R10;
    case Register::r11: return UC_ARM_REG_R11;
    case Register::r12: return UC_ARM_REG_R12;
    case Register::sp:  return UC_ARM_REG_SP;
    case Register::lr:  return UC_ARM_REG_LR;
    case Register::pc:  return UC_ARM_REG_PC;
    case Register::ip:  return UC_ARM_REG_IP;
    }

    check(false, "bad register enum");
    return 0;
}

Process* process_create(const uint8_t* peImage, int peImageSize) {
    std::unique_ptr<Process> p { new Process{} };

    // Map PE into memory
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

    // Just allocate the whole 128mb space, I don't care about being strict with the CE memory layout.
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

    // Apply import table fixups. Essentially the run time linker.
    const auto idir = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
    auto*      desc = cast<pe::IMPORT_DESCRIPTOR*>(ptr(idir.VirtualAddress));

    auto jumpTableAddressOffset = jumpTableRange.getStart();
    bool linkedOK = true;

    while (desc->Name) {
        const auto moduleName = cast<const char*>(ptr(desc->Name));
        auto*      thunk      = cast<pe::THUNK_DATA*>(ptr(desc->FirstThunk));

        while (thunk->u1.AddressOfData) {
            const auto symbolName = [&] {
                if (thunk->u1.Ordinal & pe::Flag::ImportOrdinal) {
                    check(std::string_view{moduleName} == "COREDLL.dll", "We don't know about '%s'", moduleName);
                    return coredll_get_name_from_ordinal(pe::ordinal(thunk->u1.Ordinal));
                }

                return cast<const char*>(ptr(thunk->u1.AddressOfData + 2));
            }();

            print("Linking [%s][%s]...", moduleName, symbolName);

            if (auto* s = symbol_find(symbolName)) {
                p->jumpfuncs[jumpTableAddressOffset] = (jump_callback_t)s;
                thunk->u1.Function = jumpTableAddressOffset;
                print("OK!! Loaded at address 0x%08X\n", jumpTableAddressOffset);

                jumpTableAddressOffset += 4;
                thunk++;
                continue;
            }

            print("Failed :(\n");
            linkedOK = false;
            thunk++;
        }

        desc++;
    }

    check(linkedOK, "failed to link");

    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_ARM, &p->context);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(p->context, p->imagebase, mb(128), UC_PROT_ALL, p->memory);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    // Jump table is how we translate target API calls into Host calls.
    // We protect the whole page to trigger a callback when the table is touched.
    r = uc_mem_map_ptr(p->context, jumpTableRange.getStart(), jumpTableRange.length(), UC_PROT_NONE, p->jumptable);
    check(r == UC_ERR_OK, "failed to map jump table. %s", uc_strerror(r));

    uc_hook hook;
    r = uc_hook_add(p->context, &hook, UC_HOOK_MEM_PROT, (void*)api_trampoline_callback, p.get(), jumpTableRange.getStart(), jumpTableRange.getEnd());
    p->hooks.push_back(hook);
    check(r == UC_ERR_OK, "failed to hook jump table. %s", uc_strerror(r));

    return p.release();
}

void process_destroy(Process* p) {
    for (auto hook : p->hooks)
        uc_hook_del(p->context, hook);

    uc_close(p->context);
    delete[] p->memory;
    delete p;
}

uint8_t* process_mem_map(Process* p, uint32_t addr) {
    return p->memory + (addr - p->imagebase);
}

const uint8_t* process_mem_map(const Process* p, uint32_t addr) {
    return p->memory + (addr - p->imagebase);
}

void process_install_trace_callback(Process* p, process_trace_callback_t&& callback) {
    uc_hook hook = 0;

    const auto r = uc_hook_add(p->context, &hook, UC_HOOK_CODE, (void*)trace_proxy, p, p->imagebase, p->imagebase + mb(128));
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    p->hooks.push_back(hook);
    p->tracecb = std::move(callback);
}

PeInfo process_pe_get(const Process* p) {
    return { p->imagebase, p->entrypoint };
}

uint32_t process_reg_read(const Process* p, Register reg) {
    uint32_t value{};
    uc_reg_read(p->context, uc_reg_map(reg), &value);
    return value;
}

void process_reg_write(Process* p, Register reg, uint32_t value) {
    uc_reg_write(p->context, uc_reg_map(reg), &value);
}

uint32_t process_stack_read(const Process* p, int offset) {
    uint32_t value;
    memcpy(&value, p->memory + process_reg_read(p, Register::sp) + offset, 4);
    return value;
}

void process_stack_write(Process* p, int offset, uint32_t value) {
    memcpy(p->memory + process_reg_read(p, Register::sp) + offset, &value, 4);
}

uint32_t process_mem_host_to_target(Process* p, void* ptr) {
    if (ptr) {
        check(Range<uintptr_t>(0, mb(128)).contains((uintptr_t)ptr), "host pointer out of range");
        BREAK();
    }

    return 0;
}

void* process_mem_target_to_host(Process* p, uint32_t addr) {
    // TODO: actually test this is correct, simple math confuses me.
    return p->memory + (addr - p->imagebase);
}

void process_reset(Process* p) {
    // TODO: correct CPU state when creating a process
    process_reg_write(p, Register::r0, 0);
    process_reg_write(p, Register::r1, 0);
    process_reg_write(p, Register::r2, 0);
    process_reg_write(p, Register::r3, 0);
    process_reg_write(p, Register::r4, 0);
    process_reg_write(p, Register::r5, 0);
    process_reg_write(p, Register::r6, 0);
    process_reg_write(p, Register::r7, 0);
    process_reg_write(p, Register::r8, 0);
    process_reg_write(p, Register::r9, 0);
    process_reg_write(p, Register::r10, 0);
    process_reg_write(p, Register::r11, 0);
    process_reg_write(p, Register::r12, 0);
    process_reg_write(p, Register::sp, 0);
    process_reg_write(p, Register::pc, 0);
    process_reg_write(p, Register::ip, 0);
    process_reg_write(p, Register::lr, 0);

    // I assume the stack grows down???
    process_reg_write(p, Register::sp, stackRange.getEnd() - 4);
    process_reg_write(p, Register::pc, p->imagebase + p->entrypoint);
}

bool process_run(Process* p) {
    const auto pc = process_reg_read(p, Register::pc);
    return uc_emu_start(p->context, pc, mb(128), 0, 0) == UC_ERR_OK;
}

void process_panic_dump(const Process* p) {
    #define dump(name, reg)   print(name "  = 0x%08X\t", process_reg_read(p, reg))

    dump("r0", Register::r0);
    dump("r1", Register::r1);
    dump("r2", Register::r2);
    dump("r3", Register::r3);
    dump("r4", Register::r4);
    dump("r5", Register::r5);
    dump("r6", Register::r6);
    dump("r7", Register::r7);
    dump("r8", Register::r8);
    dump("r9", Register::r9);
    dump("r10", Register::r10);
    dump("r11", Register::r11);
    dump("r12", Register::r12);

    dump("sp", Register::sp);
    dump("ip", Register::ip);
    dump("lr", Register::lr);
    dump("pc", Register::pc);

    #undef dump
}