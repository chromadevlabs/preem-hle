
#include "utils.h"
#include "process.h"
//#include "disassembler.h"

#include <cstdio>
#include <cstdarg>

int main(int argc, const char** argv) {
    const auto path = argc > 1 ? argv[1]
                               : PREEM_HLE_ROM_PATH "/TrailBlazer/TrailBlazer.exe";

    auto file = file_load(path);
    check(file, "failed to open file");

    printf("Loading '%s'...\n", path);

    process_init(file->data(), file->size());
    process_run();

    fflush(stdout);
    return 0;
}
