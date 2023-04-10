static void CreateMutexW_trampoline(Process* p) {
    const auto r = CreateMutexW(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (BOOL)process_reg_read(p, Register::r1),
        (LPCWSTR)process_mem_target_to_host(p, process_reg_read(p, Register::r2))
    );
    process_reg_write(p, Register::r0, r);
}

struct { const char* name; void* ptr; } static const coredll_modules[] = {
{ "CreateMutexW", CreateMutexW_trampoline },
};
