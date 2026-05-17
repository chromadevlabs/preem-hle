#pragma once

#include <cstdint>

void disassembler_init();
void disassembler_shutdown();
void disassembler_oneshot(const uint8_t* code, uint32_t size, uint32_t address);
