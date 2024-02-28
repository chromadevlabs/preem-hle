#pragma once

#include <cstdint>
#include <cstddef>

struct Process;

enum class Register {
    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12,
    s0, s1, s2, s3, s4, s5, s6, s7,
    sp, lr, pc, ip, fp,
    cpsr, fpscr
};

using process_trace_callback_t = void(*)(Process*, uint32_t);

Process* process_create(const uint8_t* peImage, size_t imageSize);
void     process_destroy(Process*);

void     process_install_trace_callback(Process* p, process_trace_callback_t&& callback);

uint32_t process_reg_read_u32(const Process* p, Register reg);
float    process_reg_read_f32(const Process* p, Register reg);

void     process_reg_write_u32(Process* p, Register reg, uint32_t value);
void     process_reg_write_f32(Process* p, Register reg, float value);

uint32_t process_stack_read(Process* p, int offset);
void     process_stack_write(Process* p, int offset, uint32_t value);

void     process_reset(Process* p);
bool     process_run(Process* p);

void     process_panic_dump(const Process* p);

uint32_t process_mem_host_to_target(Process* p, void* ptr);
void*    process_mem_target_to_host(Process* p, uint32_t addr);

uint8_t* process_mem_map(Process* p, uint32_t addr);
const uint8_t* process_mem_map(const Process* p, uint32_t addr);