#pragma once

#include <cstdint>

struct Process;

enum RegisterIndex {
    Reg_r0, Reg_r1, Reg_r2,  Reg_r3,  Reg_r4,  Reg_r5,  Reg_r6,  Reg_r7,
    Reg_r8, Reg_r9, Reg_r10, Reg_r11, Reg_r12,
    Reg_sp, Reg_lr, Reg_pc, Reg_ip
};

Process* process_create(const void* peImage, int imageSize);
void process_destroy(Process*);

void process_register_imported_function(Process* p, const char* module, const char* func, const void* ptr);
void process_register_imported_function(Process* p, const char* module, int ord, const void* ptr);

uint32_t process_register_read(const Process* p, int reg);
void process_register_write(Process* p, int reg, uint32_t value);

void process_reset(Process* p);
bool process_step(Process* p);