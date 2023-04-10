#include <cstdio>

#define FUNC

using HANDLE  = void*;
using BOOL    = int;
using LPCSTR  = const char*;
using LPCWSTR = const wchar_t*;

FUNC HANDLE CreateMutexW(void* attributes, BOOL initialOwner, LPCWSTR name) {
    return nullptr;
}