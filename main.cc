
#include "utils.h"
#include "process.h"
#include "disassembler.h"

#include <cstdio>
#include <cstdarg>

int print(const char* format, ...) {
    va_list args;

    va_start(args, format);
    const auto r = vfprintf(stdout, format, args);
    va_end(args);

    return r;
}

static void trace(Process* p, uint32_t address) {
    disassembler_oneshot(p, process_mem_map(p, address), 4, address);
}

int main(int argc, const char** argv) {
    const auto path = argc > 1 ? argv[1]
                               : PREEM_HLE_ROM_PATH "/TrailBlazer/TrailBlazer.exe";

    auto file = file_load(path);
    check(file, "failed to open file");

    print("Loading '%s'...\n", path);

    disassembler_init();

    if (auto* p = process_create(file->data(), file->size())) {
        process_install_trace_callback(p, trace);
        
        process_reset(p);

        if (! process_run(p)) {
            print("PANIC:\n");
            process_panic_dump(p);
        }

        process_destroy(p);
    }

    disassembler_shutdown();

    return 0;
}