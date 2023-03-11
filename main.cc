
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <cstdio>
#include <cstdint>
#include <vector>
#include <optional>
#include <string_view>
#include <memory>

template<typename RT, typename PT>
constexpr RT cast(PT pt) { return reinterpret_cast<RT>(pt); }

template<typename T>
constexpr T align(T value, T alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

#define stringify(value)    # value
#define concat(a, b)        a # b
#define check(expr, ...)    if (!bool(expr)) { printf("ASSERT - %s[%d]: ", __FILE__, __LINE__);    \
                                               printf(__VA_ARGS__); printf("\n"); fflush(stdout);  \
                                               throw nullptr; }

namespace file {
    std::optional<std::vector<std::byte>> read(std::string_view path) {
        using ptr   = std::unique_ptr<FILE, void(*)(FILE*)>;
        auto closer = [](FILE* f){ if (f) fclose(f); };

        if (auto file = ptr(fopen(path.data(), "rb"), closer)) {
            fseek(file.get(), 0, SEEK_END);
            if (auto size = ftell(file.get()); size > 0) {
                std::vector<std::byte> data;

                data.resize(size);
                fseek(file.get(), 0, SEEK_SET);
                fread(data.data(), 1, size, file.get());

                return std::make_optional(data);
            }
        }

        return {};
    }
}

template<typename T>
struct View {

private:
};

namespace pe {
    using BYTE  = uint8_t;
    using WORD  = uint16_t;
    using LONG  = uint32_t;
    using DWORD = uint32_t;

    struct DATA_DIRECTORY {
        DWORD   VirtualAddress;
        DWORD   Size;
    };

    struct DOS_HEADER {                     // DOS .EXE header
        WORD   e_magic;                     // Magic number
        WORD   e_cblp;                      // Bytes on last page of file
        WORD   e_cp;                        // Pages in file
        WORD   e_crlc;                      // Relocations
        WORD   e_cparhdr;                   // Size of header in paragraphs
        WORD   e_minalloc;                  // Minimum extra paragraphs needed
        WORD   e_maxalloc;                  // Maximum extra paragraphs needed
        WORD   e_ss;                        // Initial (relative) SS value
        WORD   e_sp;                        // Initial SP value
        WORD   e_csum;                      // Checksum
        WORD   e_ip;                        // Initial IP value
        WORD   e_cs;                        // Initial (relative) CS value
        WORD   e_lfarlc;                    // File address of relocation table
        WORD   e_ovno;                      // Overlay number
        WORD   e_res[4];                    // Reserved words
        WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
        WORD   e_oeminfo;                   // OEM information; e_oemid specific
        WORD   e_res2[10];                  // Reserved words
        LONG   e_lfanew;                    // File address of new exe header
    };

    struct FILE_HEADER {
        WORD    Machine;
        WORD    NumberOfSections;
        DWORD   TimeDateStamp;
        DWORD   PointerToSymbolTable;
        DWORD   NumberOfSymbols;
        WORD    SizeOfOptionalHeader;
        WORD    Characteristics;
    };

    struct OPTIONAL_HEADER {
        WORD    Magic;
        BYTE    MajorLinkerVersion;
        BYTE    MinorLinkerVersion;
        DWORD   SizeOfCode;
        DWORD   SizeOfInitializedData;
        DWORD   SizeOfUninitializedData;
        DWORD   AddressOfEntryPoint;
        DWORD   BaseOfCode;
        DWORD   BaseOfData;
        DWORD   ImageBase;
        DWORD   SectionAlignment;
        DWORD   FileAlignment;
        WORD    MajorOperatingSystemVersion;
        WORD    MinorOperatingSystemVersion;
        WORD    MajorImageVersion;
        WORD    MinorImageVersion;
        WORD    MajorSubsystemVersion;
        WORD    MinorSubsystemVersion;
        DWORD   Win32VersionValue;
        DWORD   SizeOfImage;
        DWORD   SizeOfHeaders;
        DWORD   CheckSum;
        WORD    Subsystem;
        WORD    DllCharacteristics;
        DWORD   SizeOfStackReserve;
        DWORD   SizeOfStackCommit;
        DWORD   SizeOfHeapReserve;
        DWORD   SizeOfHeapCommit;
        DWORD   LoaderFlags;
        DWORD   NumberOfRvaAndSizes;
        DATA_DIRECTORY DataDirectory[16];
    };

    struct NT_HEADER {
        DWORD           Signature;
        FILE_HEADER     FileHeader;
        OPTIONAL_HEADER OptionalHeader;
    };

    struct SECTION_HEADER {
        BYTE    Name[8];
        union {
                DWORD   PhysicalAddress;
                DWORD   VirtualSize;
        } Misc;
        DWORD   VirtualAddress;
        DWORD   SizeOfRawData;
        DWORD   PointerToRawData;
        DWORD   PointerToRelocations;
        DWORD   PointerToLinenumbers;
        WORD    NumberOfRelocations;
        WORD    NumberOfLinenumbers;
        DWORD   Characteristics;
    };

    constexpr auto rvaToVA(uint32_t rva, )
}

namespace cpu {
    struct Context {
        constexpr operator auto() const { return e; }
        uc_engine* e;
    };

    Context init() {
        Context c{};

        const auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_THUMB, &c.e);
        check(r == UC_ERR_OK, "failed to init unicorn: %s", uc_strerror(r));

        return c;
    }

    void shutdown(Context& c) {
        uc_close(c.e);
        c = {};
    }

    void mem_map(Context& c, uint32_t address, uint32_t length) {
        const auto r = uc_mem_map(c, address, length, UC_PROT_ALL);
        check(r == UC_ERR_OK, "failed to map memory range { 0x%08X - 0x%08X }", address, address + length);
    }

    void mem_read(Context& c, uint32_t address, void* dst, uint32_t length) {
        const auto r = uc_mem_read(c, address, dst, length);
        check(r == UC_ERR_OK, "failed to read memory: %s", uc_strerror(r));
    }

    void mem_write(Context& c, uint32_t address, const void* src, uint32_t length) {
        const auto r = uc_mem_write(c, address, src, length);
        check(r == UC_ERR_OK, "failed to write memory: %s", uc_strerror(r));
    }
}

int main(int, const char**) {
    const auto file = file::read("/Users/chroma/Desktop/preem/roms/Quake/Quake.exe");
    check(file, "failed to open file");

    const auto* dos = cast<const pe::DOS_HEADER*>(file->data());
    const auto* nt  = cast<const pe::NT_HEADER*>(file->data() + dos->e_lfanew);

    check (nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);
    const auto* sec = cast<const pe::SECTION_HEADER*>(cast<uintptr_t>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);

    auto emu = cpu::init();

    // load sections into proc space
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    }

    cpu::shutdown(emu);
    return 0;
}