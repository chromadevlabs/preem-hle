
#include <cstdint>

#include "allocator.h"

namespace coredll {
    using DWORD  = uint32_t;
    using SIZE_T = uint64_t;

    #pragma pack(push, 1)
    struct MEMORYSTATUS {
        DWORD dwLength;
        DWORD dwMemoryLoad;
        DWORD dwTotalPhys;
        DWORD dwAvailPhys;
        DWORD dwTotalPageFile;
        DWORD dwAvailPageFile;
        DWORD dwTotalVirtual;
        DWORD dwAvailVirtual;
    };
    #pragma pack(pop)

    void GlobalMemoryStatus(MEMORYSTATUS* ms) {
        ms->dwMemoryLoad     = 0;
        ms->dwTotalPhys      = 128 * 1024 * 1024;
        ms->dwAvailPhys      = 128 * 1024 * 1024;
        ms->dwTotalPageFile  = 128 * 1024 * 1024;
        ms->dwAvailPageFile  = 128 * 1024 * 1024;
        ms->dwTotalVirtual   = 100 * 1024 * 1024;
        ms->dwAvailVirtual   = 82  * 1024 * 1024;
    }

    void* LocalFree(void*) {
        return nullptr;
    }

    int32_t __rt_sdiv(int32_t value, int32_t div) {
        return value / div;
    }

    uint32_t __rt_udiv(uint32_t value, uint32_t div) {
        return value / div;
    }
}
