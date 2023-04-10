
#include <unicorn/unicorn.h>

#include "utils.h"

#include <cstdio>
#include <cstdarg>

void print(const char* format, ...) {
    va_list args;

    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}

int main(int argc, const char** argv) {
    const auto path = argc > 1 ? argv[1]
                               : PREEM_HLE_ROM_PATH "/test/main.exe";

    auto file = file_load(path);
    check(file, "failed to open file");

    return 0;
}