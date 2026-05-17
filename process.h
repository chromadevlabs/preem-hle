#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>

using target_address_t = uint32_t;
using host_memory_t    = uint8_t*;

enum class Register {
    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12,
    s0, s1, s2, s3, s4, s5, s6, s7,
    sp, lr, pc, ip, fp,
    cpsr, fpscr
};

struct RegisterState {
    Register reg;
    union {
        uint32_t u32;
        float f32;
    };
};

struct uc_context;
struct Thread {
    enum ExecutionState {
        Stopped,
        Running,
        Waiting
    };

    uint32_t id;
    uc_context* context = nullptr;

    target_address_t tlsAddress   = 0;
    target_address_t stackAddress = 0;
    ExecutionState   state{Stopped};

    std::function<void(Thread*)> waitFunc;
};

bool     process_init(const uint8_t* peImage, size_t imageSize);
void     process_shutdown();
void     process_run();

Thread*  process_create_thread(size_t stackSize, uint32_t entrypoint, uint32_t user);
Thread*  process_get_current_thread();
void     process_thread_start(Thread*);
void     process_thread_yield();

uint32_t process_reg_read_u32(Register reg);
float    process_reg_read_f32(Register reg);

void     process_reg_write_u32(Register reg, uint32_t value);
void     process_reg_write_f32(Register reg, float value);

uint32_t process_stack_read(int offset);
void     process_stack_write(int offset, uint32_t value);

uint32_t process_mem_host_to_target(void*);
void*    process_mem_target_to_host(uint32_t addr);
uint32_t process_mem_allocate(uint32_t size);
