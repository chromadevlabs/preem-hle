#pragma once

#include "process.h"

void disassembler_init();
void disassembler_shutdown();
void disassembler_oneshot(Process* p, const uint8_t* code, size_t size, uint32_t address);