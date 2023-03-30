#pragma once

#include <cstdint>
#include <cstddef>

namespace disassembler {
    void init();
    void shutdown();
    void oneshit(const uint8_t* code, size_t size, uint32_t address);
}