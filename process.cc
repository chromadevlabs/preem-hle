
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

static std::vector<std::string> debug_name_table;

// Implemented in symbols.inl
void* symbol_find(const char*);

static void instruction_trace_callback(uc_engine* uc, uint64_t address, uint64_t size, void* user) {
    auto* p = cast<Process*>(user);
    p->tracecb(p, (uint32_t) address);
}

static void jump_table_callback(uc_engine* uc, uint64_t address, uint64_t size, void* user) {
    auto* p = cast<Process*>(user);
    
    const auto index = address / 4;
    const auto f = p->jumpfuncs[index];
    print("apicall: 0x%08X '%s' (%d)\n", address, debug_name_table[index].c_str(), index);
    check(f, "bad link");
    f(p);

    //getchar();

    process_reg_write_u32(p, Register::pc, process_reg_read_u32(p, Register::lr));
}

static bool invalid_mem_callback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user) {
    
    switch (type)
    {
        case UC_MEM_READ_UNMAPPED:   break;
        case UC_MEM_WRITE_UNMAPPED:  break;
        case UC_MEM_FETCH_UNMAPPED:  break;
        case UC_MEM_WRITE_PROT:      break;
        case UC_MEM_READ_PROT:       break;
        case UC_MEM_FETCH_PROT:      break;
    }

    return false;
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

    case Register::s0:  return UC_ARM_REG_S0;
    case Register::s1:  return UC_ARM_REG_S1;
    case Register::s2:  return UC_ARM_REG_S2;
    case Register::s3:  return UC_ARM_REG_S3;
    case Register::s4:  return UC_ARM_REG_S4;
    case Register::s5:  return UC_ARM_REG_S5;
    case Register::s6:  return UC_ARM_REG_S6;
    case Register::s7:  return UC_ARM_REG_S7;

    case Register::sp:  return UC_ARM_REG_SP;
    case Register::lr:  return UC_ARM_REG_LR;
    case Register::pc:  return UC_ARM_REG_PC;
    case Register::ip:  return UC_ARM_REG_IP;
    case Register::fp:  return UC_ARM_REG_FP;
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
            check(srcOffset + s.SizeOfRawData <= (uint32_t)peImageSize,
                  "source is out of bounds. { 0x%08X - 0x%08X } is out of bounds of %08X",
                  s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, peImageSize);

            memcpy(dst, src, s.SizeOfRawData);
        }
    }

    auto ptr = [&p, sections](uint32_t address)->uint8_t* {
        return p->memory + address;
    };

    {
        // Apply import table fixups. Essentially the run time linker.
        const auto idir = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
        auto*      desc = cast<pe::IMPORT_DESCRIPTOR*>(ptr(idir.VirtualAddress));

        auto jumpTableAddressOffset = jumpTableRange.getStart();

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

                auto* s = symbol_find(symbolName);
                check(s != nullptr, "failed to link");

                debug_name_table.push_back(symbolName);
                p->jumpfuncs[jumpTableAddressOffset] = (jump_callback_t)s;
                thunk->u1.Function = jumpTableAddressOffset * 4;
                print("OK!! Loaded at offset %d\n", jumpTableAddressOffset);

                jumpTableAddressOffset++;
                thunk++;
            }

            desc++;
        }
    }

    {
        // Parse exception table
        const auto idir      = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ExceptionTable];
        auto*      desc      = cast<pe::ARM_EXCEPTION_TABLE_ENTRY*>(ptr(idir.VirtualAddress));
        const auto tableSize = idir.Size / sizeof(pe::ARM_EXCEPTION_TABLE_ENTRY);

        for (const auto& exc : make_view(desc, desc + tableSize)) {
            print("Exception:\n");
            print("\tAddress:     0x%08X\n", exc.BeginAddress);
            print("\tProlog:      0x%X\n",   exc.PrologLength);
            print("\tFunctionLen: 0x%X\n",   exc.FunctionLength);
            print("\t32bit:       %s\n",     exc.Is32Bit ? "true" : "false");
            print("\thandler:     %s\n",     exc.HandlerPresent ? "true" : "false");
        }
    }

    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_ARM, &p->context);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    r = uc_mem_map_ptr(p->context, p->imagebase, mb(128), UC_PROT_NONE, p->memory);
    check(r == UC_ERR_OK, "failed to map process memory. %s", uc_strerror(r));

    // Apply memory protection flags
    for (const auto& s : sections) {
        uint32_t protFlag = UC_PROT_NONE;

        if ((s.Characteristics & pe::SectionFlags::memoryExec) != 0) {
            protFlag |= UC_PROT_EXEC;
        }
        if ((s.Characteristics & pe::SectionFlags::memoryRead) != 0) {
            protFlag |= UC_PROT_READ;
        }
        if ((s.Characteristics & pe::SectionFlags::memoryWrite) != 0) {
            protFlag |= UC_PROT_WRITE;
        }

        size_t pageAlign = 0;
        uc_query(p->context, UC_QUERY_PAGE_SIZE, &pageAlign);
        const auto alignedSize = align<uint32_t>(s.Misc.VirtualSize, pageAlign);
        r = uc_mem_protect(p->context, p->imagebase + s.VirtualAddress, alignedSize, protFlag);
        check(r == UC_ERR_OK, "failed to protect section memory flags: %s", uc_strerror(r));
    }

    uc_mem_protect(p->context, stackRange.getStart(), stackRange.length(), UC_PROT_READ | UC_PROT_WRITE);
    check(r == UC_ERR_OK, "failed to protect stack memory", uc_strerror(r));

    // Jump table is how we translate target API calls into Host calls.
    // We protect the whole page to trigger a callback when the table is touched.
    r = uc_mem_map_ptr(p->context, jumpTableRange.getStart(), jumpTableRange.length(), UC_PROT_ALL, p->jumptable);
    check(r == UC_ERR_OK, "failed to map jump table. %s", uc_strerror(r));

    uc_hook hook = 0;
    r = uc_hook_add(p->context, &hook, UC_HOOK_CODE, (void*)jump_table_callback, p.get(), jumpTableRange.getStart(), jumpTableRange.length());
    check(r == UC_ERR_OK, "bad api hook install: %s\n", uc_strerror(r));
    p->hooks.push_back(hook);

    hook = 0;
    r = uc_hook_add(p->context, &hook, UC_HOOK_MEM_INVALID, (void*)invalid_mem_callback, p.get(), 0, 0xFFFFFFFF);
    check(r == UC_ERR_OK, "bad memory hook %s\n", uc_strerror(r));
    p->hooks.push_back(hook);

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

    const auto r = uc_hook_add(p->context, &hook, UC_HOOK_CODE, (void*)instruction_trace_callback, p, p->imagebase, p->imagebase + mb(128));
    check(r == UC_ERR_OK, "bad hook install: %s\n", uc_strerror(r));

    p->hooks.push_back(hook);
    p->tracecb = std::move(callback);
}

PeInfo process_pe_get(const Process* p) {
    return { p->imagebase, p->entrypoint };
}

uint32_t process_reg_read_u32(const Process* p, Register reg) {
    uint32_t value{};
    uc_reg_read(p->context, uc_reg_map(reg), &value);
    return value;
}

float process_reg_read_f32(const Process* p, Register reg) {
    float value{};
    uc_reg_read(p->context, uc_reg_map(reg), &value);
    return value;
}

void process_reg_write_u32(Process* p, Register reg, uint32_t value) {
    uc_reg_write(p->context, uc_reg_map(reg), &value);
}

void process_reg_write_f32(Process* p, Register reg, float value) {
    uc_reg_write(p->context, uc_reg_map(reg), &value);
}

uint32_t process_stack_read(Process* p, int offset) {
    uint32_t value;
    const auto addr = process_reg_read_u32(p, Register::sp) + (offset * 4);
    const auto src = process_mem_target_to_host(p, addr);
    memcpy(&value, src, 4);
    return value;
}

void process_stack_write(Process* p, int offset, uint32_t value) {
    const auto addr = process_reg_read_u32(p, Register::sp) + (offset * 4);
    const auto dst = process_mem_target_to_host(p, addr);
    memcpy(dst, &value, 4);
}

uint32_t process_mem_host_to_target(Process* p, void* ptr) {
    if (ptr) {
        auto addr = uintptr_t(ptr) - (uintptr_t)p->memory;
        return addr & 0x00000000FFFFFFFF;
    }

    return 0;
}

void* process_mem_target_to_host(Process* p, uint32_t addr) {
    if (addr)
        return p->memory + (addr - p->imagebase);

    return nullptr;
}

void process_reset(Process* p) {
    // TODO: correct CPU state when creating a process
    process_reg_write_u32(p, Register::r0, 0);
    process_reg_write_u32(p, Register::r1, 0);
    process_reg_write_u32(p, Register::r2, 0);
    process_reg_write_u32(p, Register::r3, 0);
    process_reg_write_u32(p, Register::r4, 0);
    process_reg_write_u32(p, Register::r5, 0);
    process_reg_write_u32(p, Register::r6, 0);
    process_reg_write_u32(p, Register::r7, 0);
    process_reg_write_u32(p, Register::r8, 0);
    process_reg_write_u32(p, Register::r9, 0);
    process_reg_write_u32(p, Register::r10, 0);
    process_reg_write_u32(p, Register::r11, 0);
    process_reg_write_u32(p, Register::r12, 0);
    process_reg_write_f32(p, Register::s0, 0);
    process_reg_write_f32(p, Register::s1, 0);
    process_reg_write_f32(p, Register::s2, 0);
    process_reg_write_f32(p, Register::s3, 0);
    process_reg_write_f32(p, Register::s4, 0);
    process_reg_write_f32(p, Register::s5, 0);
    process_reg_write_f32(p, Register::s6, 0);
    process_reg_write_f32(p, Register::s7, 0);
    process_reg_write_u32(p, Register::sp, 0);
    process_reg_write_u32(p, Register::pc, 0);
    process_reg_write_u32(p, Register::ip, 0);
    process_reg_write_u32(p, Register::lr, 0);

    // I assume the stack grows down???
    process_reg_write_u32(p, Register::sp, stackRange.getEnd() - 4);
    process_reg_write_u32(p, Register::fp, stackRange.getEnd() - 4);
    process_reg_write_u32(p, Register::pc, p->imagebase + p->entrypoint);
}

bool process_run(Process* p) {
    const auto pc = process_reg_read_u32(p, Register::pc);
    const auto r = uc_emu_start(p->context, pc, mb(128), 0, 0);

    if (r != UC_ERR_OK) {
        print("CPU ERROR: %s\n", uc_strerror (r));
        return false;
    }

    return true;
}

void process_panic_dump(const Process* p) {
    #define dump_u32(reg)   print(#reg "  = 0x%08X\n", process_reg_read_u32(p, Register::reg))
    #define dump_f32(reg)   print(#reg "  = %f\n",     process_reg_read_f32(p, Register::reg))

    dump_u32(r0);
    dump_u32(r1);
    dump_u32(r2);
    dump_u32(r3);
    dump_u32(r4);
    dump_u32(r5);
    dump_u32(r6);
    dump_u32(r7);
    dump_u32(r8);
    dump_u32(r9);
    dump_u32(r10);
    dump_u32(r11);
    dump_u32(r12);

    dump_f32(s0);
    dump_f32(s1);
    dump_f32(s2);
    dump_f32(s3);
    dump_f32(s4);
    dump_f32(s5);
    dump_f32(s6);
    dump_f32(s7);

    dump_u32(sp);
    dump_u32(ip);
    dump_u32(lr);
    dump_u32(pc);
    dump_u32(fp);

    #undef dump_u32
    #undef dump_f32
    
    const auto sp = process_reg_read_u32(p, Register::sp);
    const auto* stack = (const uint32_t*)process_mem_map(p, sp);

    stackRange.getEnd();

    for (int i = 0; i < 8; i++) {
        const auto index = 8 - i;
        print("   SP-%d [0x%08X]\n", index, stack[-index]);
    }

        print("-> SP   [0x%08X]\n", stack[0]);

    for (int i = 1; i < 8; i++) {
        const auto index = i;
        print("   SP+%d [0x%08X]\n", index, stack[index]);
    }

    file_save("dump.bin", p->memory, mb(128));
}