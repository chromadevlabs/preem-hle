#pragma once

#include "utils.h"

namespace pe {
enum DirectoryIndex {
    ExportTable,
    ImportTable,
    ResourceTable,
    ExceptionTable,
    CertificateTable,
    BaseRelocTable,
    Debug,
    Architecture,
    GlobalPtr,
    TLSTable,
    LoadConfigTable,
    BoundImportTable,
    IAT,
    DelayImportDescriptor,
    CLRHeader,
    Reserved
};

enum Flag {
    ImportOrdinal = 0x80000000
};

struct DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct OPTIONAL_HEADER {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct NT_HEADER {
    uint32_t        Signature;
    FILE_HEADER     FileHeader;
    OPTIONAL_HEADER OptionalHeader;
};

struct SECTION_HEADER {
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct THUNK_DATA {
    union {
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;
        uint32_t ForwarderString;
    } u1;
};

constexpr auto ordinal(uint32_t value) {
    return value & 0xFFFF;
}

constexpr auto relativeToSection(const View<SECTION_HEADER>& sections, uint32_t rva) {
    optional<SECTION_HEADER> sec;

    for (const auto& s : sections) {
        const auto sva = s.VirtualAddress;
        if (Range<uint32_t>{ sva, sva + s.SizeOfRawData }.contains(rva)) {
            sec = s;
            break;
        }
    }

    return sec;
}

constexpr auto relativeToVirtual(const View<SECTION_HEADER>& sections, uint32_t rva) {
    optional<uint32_t> va;

    if (auto s = relativeToSection(sections, rva)) {
        va = make_optional(rva - s->VirtualAddress);
    }

    return va;
}

constexpr auto relativeToOffset(const View<SECTION_HEADER>& sections, uint32_t rva) {
    optional<uint32_t> offset;

    if (auto s = relativeToSection(sections, rva)) {
        offset = make_optional(rva - s->VirtualAddress + s->PointerToRawData);
    }

    return offset;
}
}
