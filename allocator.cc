

#include "allocator.h"
#include "utils.h"

constexpr auto BLOCK_SIZE = 256;

static Range<uint32_t> range;
static uint32_t head = 0;

void allocator_init(uint32_t base, uint32_t size) {
    range = { base, base + size };
}

uint32_t allocator_alloc(uint32_t size) {
    head += align<uint32_t>(size, 32);
    check(head < range.length(), "out of memeory");
    return range.getStart() + head - size;
}

void allocator_free(uint32_t) {
}