#pragma once

#include <cstdint>

void     allocator_init(uint32_t base, uint32_t size);
uint32_t allocator_alloc(uint32_t size);
void     allocator_free(uint32_t addr);
