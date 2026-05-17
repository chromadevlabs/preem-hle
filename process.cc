
#include <vector>
#include <string>
#include <map>

#include <unicorn/unicorn.h>

#include "disassembler.h"
#include "process.h"
#include "utils.h"
#include "pe.h"

using jump_callback_t  = void(*)();

namespace MemoryLayout {
    static constexpr Range<target_address_t> kdatapage       = { 0xFFFFC000, 0xFFFFC000 + 4096 };
    static constexpr Range<target_address_t> memory          = { 0x00200000, 0x08200000 };
    static constexpr Range<target_address_t> imagebase       = { 0x00010000, 0x00200000 - 4096 };
    static constexpr Range<target_address_t> importJumpTable = { 0x00001000, 0x00002000 };
    static constexpr Range<target_address_t> tlsHack         = { 0x00000000, 0x00001000 };
}

static constexpr auto doRangesOverlap() -> bool {
    constexpr Range<target_address_t> ranges[] = {
        MemoryLayout::tlsHack,
        MemoryLayout::importJumpTable,
        MemoryLayout::imagebase,
        MemoryLayout::memory,
        MemoryLayout::kdatapage,
    };

    for (const auto& outer : ranges) {
        for (const auto& inner : ranges) {
            if (outer != inner) {
                if (outer.contains(inner.getStart()) || outer.contains(inner.getEnd() - 1) ||
                    inner.contains(outer.getStart()) || inner.contains(outer.getEnd() - 1)) {
                        return true;
                    }
            }
        }
    }

    return false;
}

static_assert(! doRangesOverlap(), "Oh no, they overlap");

// nkarm.h
// TODO: I need to confirm how structs are packed in WINCE land.
struct KDataStruct {
    enum HandleID {
        CurrentProcess,
        CurrentThread
    };

    target_address_t tlsAddress;
    target_address_t handles[32];

    char padding[1024 - ((1 + 32) * 4)];
};

static_assert(sizeof (KDataStruct) == 1024, "KDataStruct needs to padded to 1024");

// WinCE maps KData at 0xFFFFC800, which is 0x800 bytes into a 4K page.
// uc_mem_map_ptr requires a page-aligned base, so we wrap KDataStruct in a
// full page with the struct at the correct intra-page offset.
struct alignas (4096) KDataPage {
    uint8_t     prefix[0x800];
    KDataStruct kdata;
    uint8_t     suffix[4096 - 0x800 - sizeof (KDataStruct)];
};

static_assert(sizeof (KDataPage) == 4096, "KDataPage must be exactly 4096 bytes");

// Indeed, a very useful allocator
struct Allocator {
    auto allocate(size_t size, size_t alignment) -> uint32_t {
        const auto alignedSize = align<size_t>(size, alignment);
        auto r = MemoryLayout::memory.getStart() + heapHead;
        heapHead += alignedSize;
        printf("Heap allocated %d bytes at address 0x%X \n", alignedSize, r);
        return r;
    }

    uint32_t heapHead = 0;
};

struct Process {
    uc_engine* uc = nullptr;

    host_memory_t imagebaseHostPtr = nullptr;
    host_memory_t memoryHostPtr = nullptr;
    host_memory_t tlsHackHostPtr = nullptr;

    KDataPage kdataPage;

    target_address_t processEntrypointAddr = 0;

    std::vector<Thread*> threads;
    Thread* currentThread = nullptr;

    target_address_t jumpTable[MemoryLayout::importJumpTable.length() / 4];
    jump_callback_t  jumpFuncs[MemoryLayout::importJumpTable.length() / 4];

    Allocator allocator;
    uint32_t pageAlignment = 1024;
    size_t sizeofimage = 0;
};

static Process* process = nullptr;

uint32_t process_mem_allocate(uint32_t size) {
    return process->allocator.allocate(size, 8);
}

auto process_mem_free(uint32_t) -> void {
}

// "coredll.dll" is usually linked with ordinals, but we dont link the OG dll.
// I scraped the ordinals from coredll so we could look up at runtime :thumbsup:
static const char* coredll_get_name_from_ordinal(uint16_t ord) {
    #include "coredll_ordinals.inl"

    auto iter = std::find_if(std::cbegin(coredll_symbols), std::cend(coredll_symbols), [ord](const auto& sym) {
            return sym.ord == ord;
        });

    return iter != std::cend(coredll_symbols) ? iter->name
                                              : nullptr;
}

// debug shenanigans
static std::vector<std::string> debug_name_table;

// Implemented in symbols.inl
void* symbol_find(const char*);

static void jump_table_callback(uc_engine* uc, uint64_t address, uint64_t size, void* user) {
    // Return to LR, handling Thumb interwork bit
    auto return_to_lr = [] {
        const auto lr = process_reg_read_u32(Register::lr);

        if (lr & 1) {
            const auto cpsr = process_reg_read_u32(Register::cpsr);
            process_reg_write_u32(Register::cpsr, cpsr | (1u << 5));
        }

        process_reg_write_u32(Register::pc, lr & ~1u);
    };

    // API calls
    if (MemoryLayout::importJumpTable.contains(address)) {
        const auto index = (address - MemoryLayout::importJumpTable.getStart()) / 4;
        const auto f = process->jumpFuncs[index];
        printf("Thread %d - apicall: 0x%X '%s' (%llu)\n",
               process->currentThread->id,
               address,
               debug_name_table[index].c_str(),
               index);
        check(f, "bad link");
        f();
        return_to_lr();
        return;
    }
}

static bool invalid_mem_callback(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user) {
    switch (type) {
        case UC_MEM_READ_UNMAPPED:
        case UC_MEM_WRITE_UNMAPPED:
        case UC_MEM_FETCH_UNMAPPED: {
            printf("Memory error unmapped access. Address: 0x%llX - Size: %d\n", address, size);
        } break;

        case UC_MEM_WRITE_PROT: {
            printf("Memory Error. Address: 0x%llX - Size: %d is not writable\n", address, size);
        } break;

        case UC_MEM_READ_PROT: {
            printf("Memory Error. Address: 0x%llX - Size: %d is not readable\n", address, size);
        } break;

        case UC_MEM_FETCH_PROT: {
            printf("Memory Error. Address: 0x%llX - Size: %d is not executable\n", address, size);
        } break;

        default:
            break;
    }

    return false;
}

static constexpr int uc_reg_map(Register r) {
    switch (r) {
        case Register::r0:    return UC_ARM_REG_R0;
        case Register::r1:    return UC_ARM_REG_R1;
        case Register::r2:    return UC_ARM_REG_R2;
        case Register::r3:    return UC_ARM_REG_R3;
        case Register::r4:    return UC_ARM_REG_R4;
        case Register::r5:    return UC_ARM_REG_R5;
        case Register::r6:    return UC_ARM_REG_R6;
        case Register::r7:    return UC_ARM_REG_R7;
        case Register::r8:    return UC_ARM_REG_R8;
        case Register::r9:    return UC_ARM_REG_R9;
        case Register::r10:   return UC_ARM_REG_R10;
        case Register::r11:   return UC_ARM_REG_R11;
        case Register::r12:   return UC_ARM_REG_R12;

        case Register::s0:    return UC_ARM_REG_S0;
        case Register::s1:    return UC_ARM_REG_S1;
        case Register::s2:    return UC_ARM_REG_S2;
        case Register::s3:    return UC_ARM_REG_S3;
        case Register::s4:    return UC_ARM_REG_S4;
        case Register::s5:    return UC_ARM_REG_S5;
        case Register::s6:    return UC_ARM_REG_S6;
        case Register::s7:    return UC_ARM_REG_S7;

        case Register::sp:    return UC_ARM_REG_SP;
        case Register::lr:    return UC_ARM_REG_LR;
        case Register::pc:    return UC_ARM_REG_PC;
        case Register::ip:    return UC_ARM_REG_IP;
        case Register::fp:    return UC_ARM_REG_FP;

        case Register::cpsr:  return UC_ARM_REG_CPSR;
        case Register::fpscr: return UC_ARM_REG_FPSCR;
    }

    check(false, "bad register enum");
    return 0;
}

static void instructionTraceCallback(uc_engine* uc, uint64_t address, uint64_t size, void* user) {
    disassembler_oneshot((const uint8_t*) process_mem_target_to_host(address),
                         size,
                         address);
};

static auto memory_map_range(Range<target_address_t> range, int flags, void* hostPtr) -> void {
    check(hostPtr != nullptr, "host pointer is null");
    check(range.getStart() == align<size_t>(range.getStart(), 4096), "range::start is not 4k aligned");
    check(range.getEnd()   == align<size_t>(range.getEnd(), 4096),   "range::end is not 4k aligned");

    printf("Mapping { 0x%X 0x%X } into memory (%dkb)\n", range.getStart(), range.getEnd(), range.length() / 1024);
    const auto r = uc_mem_map_ptr(process->uc, range.getStart(), range.length(), flags, hostPtr);
    check(r == UC_ERR_OK, "Fail to map memory pointer: %s", uc_strerror(r));
}

static auto memory_set_flags(Range<target_address_t> range, int flags) -> void {
    check(range.getStart() == align<size_t>(range.getStart(), 4096), "range::start is not 4k aligned");
    check(range.getEnd()   == align<size_t>(range.getEnd(), 4096),   "range::end is not 4k aligned");

    printf("Setting memory flags for range { 0x%X 0x%X }\n", range.getStart(), range.getEnd());
    const auto r = uc_mem_map(process->uc, range.getStart(), range.length(), flags);
    check(r == UC_ERR_OK, "Fail to set memory flags: %s", uc_strerror(r));
}

bool process_init(const uint8_t* peImage, size_t peImageSize) {
    process = new Process{};

    disassembler_init();

    auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_ARM, &process->uc);
    check(r == UC_ERR_OK, "failed to init unicorn. %s", uc_strerror(r));

    // I dont think im using this properly
    size_t pageAlign = 0;
    uc_query(process->uc, UC_QUERY_PAGE_SIZE, &pageAlign);
    process->pageAlignment = pageAlign;
    printf("UC_QUERY_PAGE_SIZE: %lu\n", pageAlign);

    // Map PE into memory
    const auto* dos = cast<const pe::DOS_HEADER*>(peImage);
    const auto* nt  = cast<const pe::NT_HEADER*>(peImage + dos->e_lfanew);

    // Gizmondo is a ARM thumb device running Window CE.
    check(nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);

    const auto sections = [=] {
        const auto first = cast<pe::SECTION_HEADER*>(cast<uintptr_t>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
        return make_view(first, first + nt->FileHeader.NumberOfSections);
    }();

    process->processEntrypointAddr = nt->OptionalHeader.AddressOfEntryPoint;

    check(nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::BaseRelocTable].Size == 0,
          "Erghhh I dont want to support relocations yet");

    // calculate the size of the image
    const auto sizeOfImage = [nt, sections] {
        size_t size = 0;

        for (auto s : sections)
            size += align(s.Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);

        return align<size_t>(size, 4096);
    }();

    printf("Size of sections/image: 0x%X (%dkb)\n", sizeOfImage, sizeOfImage / 1024);

    // I think the lower 0x1000 is used for some TLS related stuff????
    process->tlsHackHostPtr = new uint8_t[MemoryLayout::tlsHack.length()];
    memory_map_range(MemoryLayout::tlsHack, UC_PROT_ALL, process->tlsHackHostPtr);

    process->sizeofimage = sizeOfImage;
    process->imagebaseHostPtr = new uint8_t[sizeOfImage];
    memory_map_range(MemoryLayout::imagebase, UC_PROT_ALL, process->imagebaseHostPtr);

    process->memoryHostPtr = new uint8_t[MemoryLayout::memory.length()];
    memory_map_range(MemoryLayout::memory, UC_PROT_ALL, process->memoryHostPtr);

    memory_map_range(MemoryLayout::kdatapage, UC_PROT_READ, &process->kdataPage);

    static uint8_t kernelpagehack[0x4000];
    memory_map_range({ 0x8200000, 0x8204000 }, UC_PROT_READ | UC_PROT_WRITE, kernelpagehack);

    // Copy sections into process space
    for (const auto& s : sections) {
        const auto protFlags = [s] {
            uint32_t protFlag = UC_PROT_NONE;

            if ((s.Characteristics & pe::SectionFlags::memoryExec) != 0 ||
                (s.Characteristics & pe::SectionFlags::containsCode) != 0) {
                protFlag |= UC_PROT_EXEC;
            }
            if ((s.Characteristics & pe::SectionFlags::memoryRead) != 0) {
                protFlag |= UC_PROT_READ;
            }
            if ((s.Characteristics & pe::SectionFlags::memoryWrite) != 0) {
                protFlag |= UC_PROT_WRITE;
            }

            return protFlag;
        }();

        const auto dstOffset = s.VirtualAddress;
        const auto srcOffset = s.PointerToRawData;

        auto dst = process->imagebaseHostPtr + dstOffset;
        const auto src = peImage + srcOffset;

        printf("[%-8s]: 0x%08X -> [ 0x%08X - 0x%08X] (%c %c %c)\n",
               s.Name,
               srcOffset,
               dstOffset,
               dstOffset + s.Misc.VirtualSize,
               (protFlags & UC_PROT_READ)  ? 'R' : '|',
               (protFlags & UC_PROT_WRITE) ? 'W' : '|',
               (protFlags & UC_PROT_EXEC)  ? 'X' : '|');

        // I should probably make sure the alignment doesn't overlap.. but.. fuck it.
        //auto size = s.Misc.VirtualSize;
        //size = align(size, nt->OptionalHeader.SectionAlignment);
        //size = align<size_t>(size, 4096);
        //memory_set_flags(Range{ MemoryLayout::imagebase.getStart() + s.VirtualAddress,
        //                        MemoryLayout::imagebase.getStart() + s.VirtualAddress + size },
        //                 protFlags);

        memset(dst, 0, s.Misc.VirtualSize);

        if (s.SizeOfRawData > 0) {
            check(srcOffset + s.SizeOfRawData <= (uint32_t) peImageSize,
                  "source is out of bounds. { 0x%08X - 0x%08X } is out of bounds of %08X",
                  s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, peImageSize);

            memcpy(dst, src, s.SizeOfRawData);
        }
    }

    // ------------------------------------------------------------------------
    // Imported functions and exception handlers
    // ------------------------------------------------------------------------
    {
        auto ptr = [=](uint32_t va)->uint8_t* {
            return process->imagebaseHostPtr + va;
        };

        // Apply import table fixups. Essentially the run time linker.
        const auto idir = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
        auto*      desc = cast<pe::IMPORT_DESCRIPTOR*>(ptr(idir.VirtualAddress));

        size_t jumpTableIndex = 0;

        while (desc->Name) {
            static constexpr auto maxJumpTableSize = MemoryLayout::importJumpTable.length() / 4;
            check(jumpTableIndex < maxJumpTableSize, "Too many imported functions");

            const auto moduleName = cast<const char*>(ptr(desc->Name));
            auto* thunk = cast<pe::THUNK_DATA*>(ptr(desc->FirstThunk));

            while (thunk->u1.AddressOfData) {
                const auto symbolName = [&] {
                    if (thunk->u1.Ordinal & pe::Flag::ImportOrdinal) {
                        check(std::string_view{moduleName} == "COREDLL.dll", "We don't know about '%s'", moduleName);
                        return coredll_get_name_from_ordinal(pe::ordinal(thunk->u1.Ordinal));
                    }

                    return cast<const char*>(ptr(thunk->u1.AddressOfData + 2));
                }();

                printf("Linking [%s][%s]... ", moduleName, symbolName);

                const auto* s = symbol_find(symbolName);
                check(s != nullptr, "failed to link");

                debug_name_table.push_back(symbolName);
                process->jumpFuncs[jumpTableIndex] = (jump_callback_t) s;
                thunk->u1.Function = MemoryLayout::importJumpTable.getStart() + (jumpTableIndex * 4);
                printf("OK!! Loaded at offset 0x%X\n", thunk->u1.Function);

                jumpTableIndex++;
                thunk++;
            }

            desc++;
        }
    }

    memory_map_range(MemoryLayout::importJumpTable,
                     UC_PROT_READ | UC_PROT_EXEC,
                     process->jumpTable);

    uc_hook hook = 0;
    r = uc_hook_add(process->uc,
                    &hook,
                    UC_HOOK_CODE,
                    (void*) jump_table_callback,
                    process,
                    MemoryLayout::importJumpTable.getStart(),
                    MemoryLayout::importJumpTable.getEnd());
    check(r == UC_ERR_OK, "bad api hook install: %s", uc_strerror(r));

    hook = 0;
    r = uc_hook_add(process->uc,
                    &hook,
                    UC_HOOK_MEM_INVALID,
                    (void*) invalid_mem_callback,
                    process,
                    0, 0xFFFFFFFF);
    check(r == UC_ERR_OK, "bad api hook install: %s", uc_strerror(r));

    constexpr auto trace = false;
    if (trace) {
        // We only want hooks in the data section for now.
        r = uc_hook_add(process->uc,
                        &hook, UC_HOOK_CODE,
                        (void*) instructionTraceCallback,
                        process,
                        MemoryLayout::imagebase.getStart() + sections[0].VirtualAddress,
                        MemoryLayout::imagebase.getEnd());
        check(r == UC_ERR_OK, "bad hook install: %s", uc_strerror(r));
    }

    // We need to populate some bits of memory that the process expects (kernel page/SEH/TLB etc).
    process->kdataPage.kdata.tlsAddress = 0; // TODO
    process->kdataPage.kdata.handles[KDataStruct::CurrentProcess] = 0;
    process->kdataPage.kdata.handles[KDataStruct::CurrentThread]  = 0;

    return true;
}

void process_shutdown() {
    // TODO: obvs
}

Thread* process_create_thread(size_t   stackSize,
                              uint32_t entrypoint,
                              uint32_t user) {
    static uint32_t tidCounter = 0;

    printf("process_create_thread(0x%X, 0x%X, 0x%X)\n", stackSize, entrypoint, user);

    auto* thread = new Thread {
        .id           = tidCounter++,
        .context      = nullptr,
        .stackAddress = 0,
        .tlsAddress   = 0,
        .state        = Thread::Stopped
    };

    thread->stackAddress = process->allocator.allocate(stackSize, 8);
    thread->tlsAddress   = process->allocator.allocate(kb(4), 8);

    printf("Creating new thread (%d): Stack range: { 0x%X, 0x%X } - Entrypoint: 0x%X\n",
            thread->id,
            thread->stackAddress, thread->stackAddress + stackSize,
            entrypoint);

    // Snapshot the engine's live registers so we don't corrupt the calling
    // thread's state when we write this new thread's initial register values.
    uc_context* liveContext = nullptr;
    uc_context_alloc(process->uc, &liveContext);
    uc_context_save(process->uc, liveContext);

    auto reg_write = [&](Register r, uint32_t value) {
        uint64_t v = value;
        uc_reg_write(process->uc, uc_reg_map(r), &v);
    };

    uc_context_alloc(process->uc, &thread->context);

    reg_write(Register::r0,  user);
    reg_write(Register::r1,  0);
    reg_write(Register::r2,  0);
    reg_write(Register::r3,  0);
    reg_write(Register::r4,  0);
    reg_write(Register::r5,  0);
    reg_write(Register::r6,  0);
    reg_write(Register::r7,  0);
    reg_write(Register::r8,  0);
    reg_write(Register::r9,  0);
    reg_write(Register::r10, 0);
    reg_write(Register::r11, 0);
    reg_write(Register::r12, 0);

    reg_write(Register::s0,  0);
    reg_write(Register::s1,  0);
    reg_write(Register::s2,  0);
    reg_write(Register::s3,  0);
    reg_write(Register::s4,  0);
    reg_write(Register::s5,  0);
    reg_write(Register::s6,  0);
    reg_write(Register::s7,  0);

    // Set CPSR first so that SP/FP writes land in the correct User-mode banked register.
    // If CPSR is written after SP, Unicorn may be in a different mode (e.g. SVC) when
    // SP is written, storing into a banked register that isn't used during User-mode exec.
    const bool isThumb = (entrypoint & 1) != 0;
    reg_write(Register::cpsr, isThumb ? 0x30 : 0x10);
    reg_write(Register::fpscr, 0);

    reg_write(Register::ip, 0);
    reg_write(Register::lr, 0);

    // Full-descending stack: SP starts at first address above the stack region.
    // Must be 8-byte aligned per ARM AAPCS at function entry.
    reg_write(Register::sp, thread->stackAddress + stackSize);
    reg_write(Register::fp, thread->stackAddress + stackSize);

    // Will the entry point always be a virtual address, should it be treated as absolute here??
    reg_write(Register::pc, entrypoint & ~1u);

    uc_context_save(process->uc, thread->context);

    uc_context_restore(process->uc, liveContext);
    uc_context_free(liveContext);

    process->kdataPage.kdata.tlsAddress = thread->tlsAddress;
    process->kdataPage.kdata.handles[KDataStruct::CurrentThread] = thread->id;

    process->threads.push_back(thread);

    return thread;
}

Thread* process_get_current_thread() {
    return process->currentThread;
}

void process_thread_start(Thread* thread) {
    thread->state = Thread::Running;
}

void process_thread_yield() {
    // Kicks us out of the scheduler loop below
    uc_emu_stop(process->uc);
}

void process_run() {
    const auto ep = (MemoryLayout::imagebase.getStart() + process->processEntrypointAddr);
    auto mainThread = process_create_thread(mb(1), ep, ep);
    process_thread_start(mainThread);

    static constexpr uint64_t instructionsPerSlice = 10000;
    bool running = true;

    while (running) {
        // make a local copy to prevent iterator invalidation
        auto threads = process->threads;

        auto switchThread = [](Thread* thread) {
            process->currentThread = thread;
            process->kdataPage.kdata.tlsAddress = thread->tlsAddress;
            process->kdataPage.kdata.handles[KDataStruct::CurrentThread] = thread->id;

            auto r = uc_context_restore(process->uc, thread->context);
            check(r == UC_ERR_OK, "Failed to restore thread context");

            uint64_t pc = 0;
            r = uc_context_reg_read(thread->context, uc_reg_map(Register::pc), &pc);
            check(r == UC_ERR_OK, "Failed to load PC register");

            uc_emu_start(process->uc, pc, 0, 0, instructionsPerSlice);

            uc_context_save(process->uc, thread->context);
        };

        for (auto* thread : threads) {
            switch (thread->state) {
                case Thread::Stopped: {
                    // Do nothing
                } break;

                case Thread::Running: {
                    switchThread(thread);
                } break;

                case Thread::Waiting: {
                    check(thread->waitFunc, "No wait func set to thread!!");
                    thread->waitFunc(thread);
                } break;
            }
        }
    }
}

uint32_t process_reg_read_u32(Register reg) {
    uint32_t value{};
    uc_reg_read(process->uc, uc_reg_map(reg), &value);
    return value;
}

float process_reg_read_f32(Register reg) {
    float value{};
    uc_reg_read(process->uc, uc_reg_map(reg), &value);
    return value;
}

void process_reg_write_u32(Register reg, uint32_t value) {
    uc_reg_write(process->uc, uc_reg_map(reg), &value);
}

void process_reg_write_f32(Register reg, float value) {
    uc_reg_write(process->uc, uc_reg_map(reg), &value);
}

uint32_t process_stack_read(int offset) {
    uint32_t value;
    const auto addr = process_reg_read_u32(Register::sp) + (offset * 4);
    const auto src  = process_mem_target_to_host(addr);
    memcpy(&value, src, 4);
    return value;
}

void process_stack_write(int offset, uint32_t value) {
    const auto addr = process_reg_read_u32(Register::sp) + (offset * 4);
    const auto dst  = process_mem_target_to_host(addr);
    memcpy(dst, &value, 4);
}

// TODO: test me
uint32_t process_mem_host_to_target(void* ptr) {
    if (! ptr)
        return 0;

    struct Translation {
        Range<host_memory_t> range;
        target_address_t target;
    };

    static const auto table = {
        Translation {
            rangeFromLength((host_memory_t) &process->kdataPage, MemoryLayout::kdatapage.length()),
            MemoryLayout::kdatapage.getStart()
        },
        Translation {
            rangeFromLength(process->memoryHostPtr, MemoryLayout::memory.length()),
            MemoryLayout::memory.getStart()
        },
        Translation {
            rangeFromLength(process->imagebaseHostPtr, process->sizeofimage),
            MemoryLayout::imagebase.getStart()
        },
        Translation {
            rangeFromLength(process->tlsHackHostPtr, 4096),
            MemoryLayout::tlsHack.getStart()
        }
    };

    for (const auto entry : table) {
        if (entry.range.contains((uint8_t*) ptr)) {
            const auto offset = uintptr_t(ptr) - uintptr_t(entry.range.getStart());
            return uint32_t(entry.target + offset);
        }
    }

    check(false, "Out of range host to target memory operation: 0x%X", ptr);
    return 0;
}

// TODO: Test me
void* process_mem_target_to_host(uint32_t addr) {
    if (addr == 0)
        return nullptr;

    struct Translation {
        Range<target_address_t> range;
        host_memory_t host;
    };

    static const auto table = {
        Translation { MemoryLayout::kdatapage, (host_memory_t) &process->kdataPage },
        Translation { MemoryLayout::memory,    process->memoryHostPtr },
        Translation { MemoryLayout::imagebase, process->imagebaseHostPtr },
        Translation { MemoryLayout::tlsHack,   process->tlsHackHostPtr },
    };

    for (const auto entry : table) {
        if (entry.range.contains(addr)) {
            return entry.host + (addr - entry.range.getStart());
        }
    }

    check(false, "Out of range target to host memory operation: 0x%X", addr);
    return nullptr;
}
