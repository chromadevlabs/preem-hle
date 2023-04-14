#include <cstdint>
#include <cstring>
#include <vector>
#include <cmath>
#include <cstdio>

constexpr uint32_t INVALID_HANDLE_VALUE = 0xffffffff;

using GLenum = unsigned int;

int print(const char* format, ...);

// All functions have to be declared on a single line because I'm lazy and the python parser will break.
#define FUNC

#pragma pack(push, 1)
struct SECURITY_ATTRIBUTES {
    uint32_t length;
    void* desc;
    bool inherit;
};
#pragma pack(pop)

struct Object {
    enum class Type {
        Mutex, Event, File
    };

    uint32_t sentinel = 0xdeadbeef;
    Type type;
    union {
        struct {
            bool locked;
            const void* name;
        } mutex;

        struct {
        } event;

        FILE* file;
    };
};

// I make some pretty stupid assumptions about the upper 32 bits of the memory space.
// It wouldn't change on me between allocations... would it?
static std::vector<Object*> objects;

static Object* object_alloc() {
    auto* object = new Object;
    objects.push_back(object);
    return object;
}

static void object_free(Object* object) {
    // who the fuck came up with this and thought it was a good idea?
    objects.erase(std::remove(objects.begin(), objects.end(), object), objects.end());
    delete object;
}

static Object* object_get(uint32_t handle) {
    const auto upper = uintptr_t(objects.data()) & 0xFFFFFFFF00000000;
    const auto address = upper | static_cast<uint64_t> (handle);
    auto* ptr = reinterpret_cast<void*>(address);
    auto* obj = static_cast<Object*>(ptr);

    // TODO: do this check
    //obj->sentinal == 0xdeadbeef;

    return obj;
}

static uint32_t object_get(const Object* object) {
    return (uint32_t) uintptr_t(object) & 0x00000000FFFFFFFF;
}

struct String {
    template<typename CharType>
    static constexpr size_t length(const CharType* str) {
        auto start = str;

        while (*str)
            str++;

        return static_cast<size_t>(str - start);
    }

    template<typename CharType>
    static constexpr CharType* copy(CharType* dst, const CharType* src) {
        const auto len = length(src) + 1;
        ::memcpy(dst, src, len * sizeof(CharType));
        return dst;
    }
};


namespace coredll {
FUNC bool DeviceIoControl(uint32_t device, uint32_t code, void* inBuf, uint32_t inBufSize, void* outBuf, uint32_t outBufSize, uint32_t bytesRet, void* lpOverlapped) {
    return false;
}

FUNC uint32_t CreateEventW(void* attributes, bool reset, bool state, const wchar_t* name) {
    return INVALID_HANDLE_VALUE;
}

FUNC uint32_t CreateMutexW(SECURITY_ATTRIBUTES* attributes, bool initialOwner, const wchar_t* name) {
    auto* object = object_alloc();
    object->type = Object::Type::Mutex;
    object->mutex.name = name;
    return object_get(object);
}

FUNC void Sleep(uint32_t time) {
}

FUNC uint32_t WaitForSingleObject(uint32_t handle, uint32_t timeout) {
    return 0;
}

FUNC uint32_t GetLastError() {
    return 0;
}

FUNC uint32_t CreateFileW(const wchar_t* rawPath, uint32_t access, uint32_t share, void* attr, uint32_t create, uint32_t flags, uint32_t temp) {
    constexpr auto CREATE_NEW         = 1;
    constexpr auto CREATE_ALWAYS      = 2;
    constexpr auto OPEN_EXISTING      = 3;
    constexpr auto OPEN_ALWAYS        = 4;
    constexpr auto TRUNCATE_EXISTING  = 5;

    constexpr auto GENERIC_READ       = 0x80000000;
    constexpr auto GENERIC_WRITE      = 0x40000000;

    std::vector<char> rw;
    
    if (access == GENERIC_READ)
        rw.push_back('r');
    if (access == GENERIC_WRITE)
        rw.push_back('w');
    if (create == TRUNCATE_EXISTING)
        rw.push_back('+');

    rw.push_back('b');
    rw.push_back('\0');

    // MAX_PATH???
    char path[255]{};
    
    snprintf(path, sizeof(path), "%s\\Trailblazer\\%ls", PREEM_HLE_ROM_PATH, rawPath);
    print("CreateFileW: %ls (%s)...", path, rw.data());

    // Apparently fopen on mac will handle wide char strings???
    if (auto* file = ::fopen(path, rw.data())) {
        auto* object = object_alloc();
        object->file = file;
        printf("OK!\n");
        return object_get(object);
    }

    printf("Failed!\n");
    return INVALID_HANDLE_VALUE;
}

FUNC void CloseHandle(uint32_t handle) {
    auto* object = object_get(handle);

    switch (object->type) {
        case Object::Type::Event: break;
        case Object::Type::Mutex: break;
        case Object::Type::File: {
            fclose(object->file);
        } break;
    }

    object_free(object);
}

FUNC uint32_t SetFilePointer(uint32_t hfile, uint32_t distance, uint32_t* highDist, uint32_t method) {
    return 0;
}

FUNC uint32_t ReadFile(uint32_t hfile, void* buffer, uint32_t size, uint32_t* outSize, void* overlapped) {
    return 0;
}

FUNC uint32_t OpenEventW(uint32_t dwDesiredAccess, bool bInherituint32_t, const wchar_t* lpName) {
    return 0;
}

FUNC bool EventModify(uint32_t hEvent, uint32_t dwFunc) {
    return false;
}

FUNC uint32_t RegSetValueExW(uint32_t uint32, const wchar_t* lpValueName, uint32_t Reserved, uint32_t dwType, const uint8_t* lpData, uint32_t cbData) {
    return 0;
}

FUNC uint32_t RegOpenKeyExW(uint32_t uint32, const wchar_t* lpSubKey, uint32_t ulOptions, int samDesired, uint32_t* phkResult) {
    return 0;
}

FUNC uint32_t RegQueryValueExW(uint32_t uint32, const wchar_t* lpValueName, uint32_t* lpReserved, uint32_t* lpType, uint8_t* lpData, uint32_t* lpcbData) {
    return 0;
}

FUNC bool SetSystemMemoryDivision(uint32_t dwNumberOfPages, uint32_t dwNumberOfPagesReserved, uint32_t dwNumberOfPagesShared) {
    return true;
}

FUNC uint32_t WaitForMultipleObjects(uint32_t nCount, const uint32_t *lpuint32_ts, bool bWaitAll, uint32_t dwMilliseconds) {
    return 0;
}

FUNC bool FindCloseChangeNotification(uint32_t hChangeuint32_t) {
    return false;
}

FUNC bool FindNextChangeNotification(uint32_t hChangeuint32_t) {
    return false;
}

FUNC uint32_t FindFirstChangeNotificationW(const wchar_t* lpPathName, bool bWatchSubtree, uint32_t dwNotifyFilter) {
    return 0;
}

FUNC uint32_t GetFileAttributesW(const wchar_t* lpFileName) {
    return 0;
}

FUNC void* LocalReAlloc(void* hMem, uint32_t uBytes, uint32_t uFlags) {
    return nullptr;
}

FUNC void* LocalAlloc(uint32_t uFlags, uint32_t uBytes) {
    return nullptr;
}

FUNC void* LocalFree(void* hMem) {
    return nullptr;
}

FUNC bool SetThreadPriority(uint32_t handle, int priority) {
    return false;
}

FUNC bool TerminateThread(uint32_t handle, uint32_t code) {
    return false;
}

FUNC uint32_t SuspendThread(uint32_t handle) {
    return 0;
}

FUNC uint32_t ResumeThread(uint32_t handle) {
    return 0;
}

FUNC bool CreateThread(void* attr, uint32_t stacksize, void* callback, void* user, uint32_t flags, uint32_t* threadid) {
    return false;
}

FUNC void GetLocalTime(void* lpSystemTime) {
}

FUNC bool CreateDirectoryW(const wchar_t* lpPathName, void* lpSecurityAttributes) {
    return false;
}

FUNC int MultiByteToWideChar(uint32_t CodePage, uint32_t dwFlags, const char* lpMultiByteStr, int cbMultiByte, wchar_t* lpWideCharStr, int cchWideChar) {
    if (cbMultiByte == 0)
        return 0;

    if (cbMultiByte == -1)
        cbMultiByte = String::length(lpMultiByteStr) + 1;

    if (cchWideChar == 0) {
        return cbMultiByte;
    }
    
    const auto len = cbMultiByte + 1;
    for (int i = 0; i < len; i++) {
        lpWideCharStr[i] = lpMultiByteStr[i];
    }

    return len;
}

FUNC int WideCharToMultiByte(uint32_t CodePage, uint32_t dwFlags, const wchar_t* lpWideCharStr, int cchWideChar, char* lpMultiByteStr, int cbMultiByte, const char* lpDefaultChar, bool* lpUsedDefaultChar) {
    print("MultiByteToWideChar: %s\n", lpMultiByteStr);

    if (cchWideChar == 0)
        return 0;

    if (cchWideChar == -1)
        cchWideChar = String::length(lpWideCharStr) + 1;

    if (cbMultiByte == 0) {
        return cchWideChar;
    }

    const auto len = cchWideChar + 1;
    for (int i = 0; i < len; i++) {
        lpMultiByteStr[i] = lpWideCharStr[i];
    }

    return len;
}


FUNC bool DeleteFileW(const wchar_t* lpFileName) {
    return false;
}

FUNC bool FindClose(uint32_t hFindFile) {
    return false;
}

FUNC bool FindNextFileW(uint32_t hFindFile, void* lpFindFileData) {
    return false;
}

FUNC uint32_t FindFirstFileW(const wchar_t* lpFileName, void* lpFindFileData) {
    return 0;
}

FUNC uint32_t GetModuleFileNameW(uint32_t hModule, wchar_t* lpFilename, uint32_t nSize) {
    if (hModule == 0) {
        constexpr auto str = L"\\trailblazer.exe";
        constexpr auto len = String::length(str) + 1;
        String::copy(lpFilename, str);
        return len;
    }

    return 0;
}

FUNC void InitializeCriticalSection(void* lpCriticalSection) {

}

FUNC void DeleteCriticalSection(void* lpCriticalSection) {

}

FUNC void EnterCriticalSection(void* lpCriticalSection) {

}

FUNC void LeaveCriticalSection(void* lpCriticalSection) {

}

FUNC bool QueryPerformanceFrequency(void* lpFrequency) {
    return false;
}

FUNC bool QueryPerformanceCounter(void* lpPerformanceCount) {
    return false;
}

enum MMSYS {
    NOERROR = 0
};

FUNC uint32_t waveOutGetDevCaps(uint32_t uDeviceID, void* pwoc, int cbwoc) {
    return 0;
}

FUNC int waveOutGetNumDevs() {
    return 0;
}

FUNC uint32_t waveOutOpen(uint32_t* phwo, int uDeviceID, void* pwfx, uint32_t dwCallback, uint32_t dwCallbackInstance, uint32_t fdwOpen) {
    return 0;
}

FUNC uint32_t waveOutClose(uint32_t hwo) {
    return 0;
}

FUNC uint32_t waveOutPrepareHeader(uint32_t hwo, void* pwh, int cbwh) {
    return 0;
}

FUNC uint32_t waveOutUnprepareHeader(uint32_t hwo, void* pwh, int cbwh) {
    return 0;
}

FUNC uint32_t waveOutWrite(uint32_t hwo, void* pwh, uint32_t cbwh) {
    return 0;
}

FUNC uint32_t waveOutReset(uint32_t hwo) {
    return 0;
}

FUNC uint32_t waveOutGetPosition(uint32_t hwo, void* pmmt, uint32_t cbmmt) {
    return 0;
}

FUNC uint32_t waveInAddBuffer(uint32_t hwi, void* pwh, uint32_t cbwh) {
    return 0;
}

FUNC uint32_t waveInPrepareHeader(uint32_t hwi, void* pwh, uint32_t cbwh) {
    return 0;
}

FUNC uint32_t waveInUnprepareHeader(uint32_t hwi, void* pwh, uint32_t cbwh) {
    return 0;
}

FUNC uint32_t waveInGetDevCaps(uint32_t uDeviceID, void* pwic, uint32_t cbwic) {
    return 0;
}

FUNC uint32_t waveInGetNumDevs() {
    return 0;
}

FUNC uint32_t waveInStart(uint32_t hwi) {
    return 0;
}

FUNC uint32_t waveInOpen(uint32_t* phwi, uint32_t uDeviceID, void* pwfx, uint32_t dwCallback, uint32_t dwCallbackInstance, uint32_t fdwOpen) {
    return 0;
}

FUNC uint32_t waveInClose(uint32_t hwi) {
    return 0;
}

FUNC uint32_t waveInReset(uint32_t hwi) {
    return 0;
}

struct {
    uint32_t volume = 0x00ff00ff;
} static wave{};

FUNC uint32_t waveOutGetVolume(uint32_t hwo, uint32_t* pdwVolume) {
    *pdwVolume = wave.volume;
    return MMSYS::NOERROR;
}

FUNC uint32_t waveOutSetVolume(uint32_t hwo, uint32_t dwVolume) {
    wave.volume = dwVolume;
    print("waveOutSetVolume: %08X\n", dwVolume);
    return MMSYS::NOERROR;
}

FUNC uint32_t RegisterWindowMessageW(const wchar_t* string) {
    return 0;
}

FUNC uint32_t SendMessageW(uint32_t hwnd, uint32_t msg, uint32_t wparam, uint32_t lparam) {
    return 0;
}

FUNC uint32_t DefWindowProcW(uint32_t hwnd, uint32_t msg, uint32_t wparam, uint32_t lparam) {
    return 0;
}

FUNC uint32_t DispatchMessageW(const void* msg) {
    return 0;
}

FUNC bool TranslateMessage(const void* msg) {
    return false;
}

FUNC bool PeekMessageW(void* msg, uint32_t hwnd, int min, int max, int mode) {
    return false;
}

FUNC void PostQuitMessage(int code) {

}

FUNC int ShowCursor(bool show) {
    return 0;
}

FUNC uint32_t SetCursor(uint32_t cursor) {
    return 0;
}

FUNC bool EndPaint(uint32_t hwnd, const void* paint) {
    return false;
}

FUNC uint32_t BeginPaint(uint32_t hwnd, void* paint) {
    return 0;
}

FUNC uint32_t GetStockObject(uint32_t) {
    return 0;
}

FUNC uint32_t LoadCursorW(void* instance, const wchar_t* name) {
    return 0;
}

FUNC bool SetForegroundWindow(uint32_t hwnd) {
    return false;
}

FUNC bool BringWindowToTop(uint32_t hwnd) {
    return false;
}

FUNC uint32_t SetFocus(uint32_t hwnd) {
    return hwnd;
}

FUNC bool UpdateWindow(uint32_t hwnd) {
    return false;
}

FUNC bool ShowWindow(uint32_t hwnd, int show) {
    return false;
}

FUNC bool RegisterClassW(const void* wnd) {
    return false;
}

FUNC bool CreateWindowExW(uint32_t dwExStyle, const wchar_t* lpClassName, const wchar_t* lpWindowName, uint32_t dwStyle, int X, int Y, int nWidth, int nHeight, uint32_t hWndParent, uint32_t hMenu, void* hInstance, void* lpParam) {
    return false;
}

FUNC bool DestroyWindow(uint32_t uint32_t) {
    return false;
}

FUNC int strlen(const char* s) { 
    return String::length(s);
}

FUNC char* strcpy(char* dst, const char* src) {
    return String::copy(dst, src);
}

FUNC int         strcmp(const char* s1, const char* s2)         { return std::strcmp(s1, s2); }
FUNC char*       strstr(char* s1, const char* s2)               { return std::strstr(s1, s2); }
FUNC int         strncmp(const char* s1, const char* s2, int n) { return std::strncmp(s1, s2, n); }
FUNC char*       strchr(char* s, int n)                         { return std::strchr(s, n); }
FUNC char*       strrchr(char* s, int n)                        { return std::strrchr(s, n); }

FUNC wchar_t*    wcsrchr(wchar_t* s, wchar_t c)
{
    if (s) {
        const auto start = s;
        s += String::length(s);

        while (s > start) {
            if (*s-- == c)
                return s;
        }
    }

    return nullptr;
}

FUNC const char* __itos(int v)           { throw nullptr; return ""; };
FUNC int         __stoi(const char*)     { throw nullptr; return 0; }
FUNC int         atoi(const char* s)     { return ::atoi(s); }
FUNC float       atof(const char* s)     { return ::atof(s); }
FUNC uint32_t    strtoul(const char* s1, void* s2, int n)       { return ::strtoul(s1, (char**)s2, n); }

FUNC int toupper(int c) { 
    if (c >= 97 && c <= 122) {
        return c - 32;
    }

    return c;
}

// Fuck knows what this is supposed to be.. Maybe truncate func???
// truncate deees nuts
FUNC uint16_t __C_specific_uint32_tr(uint32_t v) {
    return v & 0xFFFF;
}

// int CDECL _XcptFilter(NTSTATUS ex, PEXCEPTION_POINTERS ptr) ????
FUNC int _XcptFilter(int, void*) {
    return 0;
}

FUNC void __C_specific_handler(void*, uint64_t, void*, void*) {

}

// these are from gcc source, might not be correct???
FUNC bool __lts(int32_t a, int32_t b) {
    return -(a < b);
}

FUNC bool __gts(int32_t a, int32_t b) {
    return a > b;
}

FUNC uint32_t __stou(int32_t v) {
    return v;
}

FUNC int32_t __rt_sdiv(int32_t a, int32_t b) {
    return a / b;
}

FUNC uint32_t __rt_udiv(uint32_t a, uint32_t b) {
    return a / b;
}

FUNC int32_t __divs(int32_t a, int32_t b) {
    return a / b;
}

// Hmmm need to look at how 64bit variables are passed
FUNC int64_t __rt_sdiv64by64(int64_t a, int64_t b) {
    return a / b;
}

FUNC uint64_t __rt_udiv64by64(uint64_t a, uint64_t b) {
    return a / b;
}

FUNC uint64_t __rt_urem64by64(uint64_t a, uint64_t b) {
    return a % b;
}

FUNC int32_t __adds(int32_t a, int32_t b) {
    return a + b;
}

FUNC int32_t __subs(int32_t a, int32_t b) {
    return a - b;
}

FUNC int32_t __negs(int32_t a) {
    return -a;
}

FUNC int32_t __muls(int32_t a, int32_t b) {
    return a * b;
}

FUNC uint32_t __utos(uint32_t v) { return 0; }
FUNC float    __utod(float v)    { return v; }

FUNC float __stod(int32_t v) {
    return v;
}

FUNC int32_t __muld(int32_t a, int32_t b) {
    return a * b;
}

FUNC int __dtoi(float v) {
    return v;
}

FUNC int32_t __dtos(float v) {
    return (int32_t) std::round(v);
}

FUNC float ldexp(float x, int exp) { return std::ldexp(x, exp); }
FUNC float atan2(float y, float x) { return std::atan2(y, x); }
FUNC float pow(float v, float a)   { return std::pow(v, a); }
FUNC float atan(float x)           { return std::atan(x); }
FUNC float acos(float v)           { return std::acos(v); }
FUNC float sqrt(float v)           { return std::sqrt(v); }
FUNC float asin(float v)           { return std::asin(v); }
FUNC float cos(float v)            { return std::cos(v); }
FUNC float sin(float v)            { return std::sin(v); }
FUNC float tan(float v)            { return std::tan(v); }

// Erghhhh variadic
FUNC int vsprintf(char*, const char*, ...) {
    return 0;
}

FUNC int sprintf(const char*, ...) {
    return 0;
}

FUNC int _snwprintf(wchar_t* buf, int, const wchar_t*, ...) {
    return 0;
}

FUNC int mbstowcs(wchar_t* dst, const char* src, int len) {
    return ::mbstowcs(dst, src, len);
}

FUNC void* memcpy(void* dst, const void* src, int len) {
    return ::memcpy(dst, src, len);
}

FUNC void* memset(void* ptr, int value, int num) {
    return ::memset(ptr, value, num);
}

FUNC int fclose(uint32_t handle) {
    auto* obj = object_get(handle);
    const auto r = ::fclose(obj->file);
    object_free(obj);
    return r;
}

FUNC int ftell(uint32_t handle) {
    return ::ftell(object_get(handle)->file);
}

FUNC int feof(uint32_t handle) {
    return ::feof(object_get(handle)->file);
}

FUNC int fseek(uint32_t handle, int seek, int offset) {
    return ::fseek(object_get(handle)->file, seek, offset);
}

FUNC int _wfopen(const wchar_t* path, const wchar_t* mode) {
    return 0;
}

FUNC int fopen(const char* path, const char* mode) {
    return 0;
}

FUNC int fread(void* dst, int size, int count, uint32_t handle) {
    return ::fread(dst, size, count, object_get(handle)->file);
}

FUNC int fwrite(const void* src, int size, int count, uint32_t handle) {
    return ::fwrite(src, size, count, object_get(handle)->file);
}

FUNC int rand() {
    return 0;
}

FUNC void* malloc(int size) {
    return nullptr;
}

FUNC void* realloc(void*, int size) {
    return nullptr;
}

FUNC void free(void*) {
}

FUNC void* memmove(void*, void*, int) {
    return nullptr;
}

FUNC int memcmp(const void*, const void*, int) {
    return 0;
}

FUNC void qsort(void*, int, int, void*) {
}
}

namespace libGLES_CM {
FUNC void eglSwapIntervalNV() {
}

FUNC void glEnableClientState(GLenum arr) { }

FUNC void glDisableClientState(GLenum arr) { }

FUNC void glVertexPointer(uint32_t size, GLenum type, uint32_t stride, const void* pointer) {}

FUNC void glColorPointer() {}

FUNC void glClientActiveTexture() {}

FUNC void glTexCoordPointer() {}

FUNC void glDrawElements() {}

FUNC void glTexEnvf() {}

FUNC void glDepthRangef() {}
FUNC void glDepthMask() {}
FUNC void glDepthFunc() {}
FUNC void glCullFace() {}
FUNC void glEnable(GLenum feat) {}
FUNC void glDisable(GLenum feat) {}
FUNC void glGetIntegerv() {}

FUNC const char* glGetString() {
    return nullptr;
}

FUNC void eglMakeCurrent(void*) {}
FUNC void eglCreateWindowSurface() {}
FUNC void eglCreateContext() {}
FUNC void eglChooseConfig() {}
FUNC void eglGetConfigs() {}
FUNC void eglInitialize() {}
FUNC void eglGetDisplay() {}
FUNC void eglTerminate() {}
FUNC void eglDestroySurface() {}
FUNC void eglDestroyContext() {}
FUNC void glClear() {}
FUNC void glClearColorx() {}
FUNC void eglSwapBuffers() {}
FUNC void glFinish() {}
FUNC void glLoadMatrixx() {}
FUNC void glMatrixMode(GLenum mode) {}
FUNC void glViewport(float x, float y, float w, float h) {}
FUNC void glScissor() {}

FUNC void glGenTextures(int count, uint32_t* uint32_ts) {}
FUNC void glDeleteTextures(int count, uint32_t* uint32_ts) {}
FUNC void glTexImage2D(GLenum  target, int level, int internalformat, int width, int height, int border, int format, GLenum type, const void* pixels) {}
FUNC void glTexParameterf() {}
FUNC void glBindTexture(GLenum mode, uint32_t uint32_t) {}
FUNC void glCompressedTexImage2D() {}
FUNC void glActiveTexture(GLenum mode) {}

FUNC void glAlphaFunc(GLenum func, float ref) {}
FUNC void glBlendFunc(GLenum sfactor, GLenum dfactor) {}

FUNC void glDrawArrays(GLenum mode, int index, int count) {}
}

#include "symbols.inl"