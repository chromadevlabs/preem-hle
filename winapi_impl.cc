#include <cstdint>  // uint*
#include <cstring>  // memcpy, strlen etc
#include <string>   // std::string
#include <vector>   // std::vector
#include <cmath>    // sin/cos etc
#include <cstdio>   // sprintf
#include <chrono>
#include <ctime>

#include "process.h"
#include "utils.h"

auto debug_hex_dump(const void* in, size_t len) -> void;

template <typename T>
struct NullTerminatorPred {
    auto operator()(T ch) const -> bool { return ch != '\0'; }
};

template <typename Data, typename Pred>
static auto count_until(Data data, Pred&& pred) -> size_t {
    size_t count = 0;

    while (pred(*data)) {
        data++;
        count++;
    }

    return count;
}

template <typename Dst, typename Src, typename Pred>
static auto copy_until(Dst dst, Src src, Pred&& pred) -> void {
    while (pred(*src)) {
        *dst = *src;
        dst++;
        src++;
    }
}

// Some Windows API functions accept a pointer to something OR a predefined value in its place,
// This breaks the memory mapping look up logic when its the latter. Using this to prevent the
// script from generating memory look up code when building its trampoline function.
using pointer_or_integer_t = uint32_t;

// The windows API uses 16 bit wide unicode characters, where as macOS uses 32 bits.
// These functions don't actually do any conversions except copying the bytes to and
// from. If I encounter a ROM that actually uses unicode I will implement a proper method.
using TCharType = char16_t;
static_assert(sizeof(TCharType) == 2, "char16_t is not 16 bits");

namespace string {
    static auto toWide(TCharType* dst, const char* multi, int32_t maxNumCharacters) -> int32_t {
        const auto srcLen = count_until(multi, NullTerminatorPred<char>());
        const auto copyLen = std::min<size_t>(maxNumCharacters, srcLen);

        std::transform(multi, multi + copyLen, dst, [](char ch){ return (TCharType) ch; });
        dst[maxNumCharacters] = L'\0';
        return copyLen;
    }

    static auto toMulti(char* dst, const TCharType* wide, int32_t maxNumCharacters) -> int32_t {
        const auto srcLen = count_until(wide, NullTerminatorPred<TCharType>());
        const auto copyLen = std::min<size_t>(maxNumCharacters, srcLen);

        std::transform(wide, wide + copyLen, dst, [](TCharType ch){ return (char) ch; });
        //dst[maxNumCharacters] = '\0';
        return copyLen;
    }

    static auto toMulti(const TCharType* wide) -> std::string {
        const auto len = count_until(wide, NullTerminatorPred<TCharType>());
        std::string string;
        string.resize(len);
        std::transform(wide, wide + len, string.data(), [](auto ch){ return ch; });
        return string;
    }

    static auto toWide(TCharType* dst, const std::string& string) -> int32_t {
        return toWide(dst, string.data(), string.length());
    }

    static auto withSectionReplaced(const std::string& string,
                                    const char* before,
                                    const char* after) -> std::string {
        auto copy = string;

        if (auto start = copy.find(before); start != -1)
        {
            copy.erase(start, strlen(before));
            copy.insert(start, after);
        }

        return copy;
    }
}

constexpr uint32_t INVALID_HANDLE_VALUE = (uint32_t) -1;

#define not_implemented_warn() \
    printf("%s[%d]: %s - NOT IMPLEMENTED YET. IGNORING!\n", __FILE__, __LINE__, __FUNCTION__);

#define not_implemented() \
    printf("%s[%d]: %s - NOT IMPLEMENTED YET. CRASHING!\n", __FILE__, __LINE__, __FUNCTION__); \
    exit(-1)

// All functions have to be declared on a single line because I'm lazy and the python parser will break otherwise.
#define FUNC

#pragma pack(push, 1)
struct CRITICAL_SECTION {
    std::optional<int16_t> holder;
};

struct SECURITY_ATTRIBUTES {
    uint32_t length;
    void* desc;
    bool inherit;
};

struct WAVEFORMATEX {
    uint16_t wFormatTag;
    uint16_t nChannels;
    uint32_t nSamplesPerSec;
    uint32_t nAvgBytesPerSec;
    uint16_t nBlockAlign;
    uint16_t wBitsPerSample;
    uint16_t cbSize;
};

struct LARGE_INTEGER {
    union {
        struct {
            uint32_t lowPart;
            uint32_t highPart;
        };

        uint64_t quadpart;
    };
};
#pragma pack(pop)

struct Object {
    enum class Type {
        Mutex,
        Event,
        File
    };

    uint32_t sentinel;
    Type type;
    struct {
        CRITICAL_SECTION cs;
        //std::string name;
    } mutex;

    struct {
        bool manualReset;
        bool currentState;
        //std::string name;
    } event;

    FILE* file = nullptr;
};

static constexpr uint32_t SENTINAL_MAGIC_CODE = 0xdeadbeef;
static std::vector<Object*> objects;

static Object* object_alloc() {
    auto* object = new Object;
    object->sentinel = SENTINAL_MAGIC_CODE;
    objects.push_back(object);
    printf("Allocated object. Host Address: 0x%016X\n", object);
    return object;
}

static void object_free(Object* object) {
    // who the fuck came up with this and thought it was a good idea?
    objects.erase(std::remove(objects.begin(), objects.end(), object), objects.end());
    delete object;
}

// -----------------------------------------------------------------------------------
// I make some pretty stupid assumptions about the upper 32 bits of the memory space.
// It wouldn't change on me between allocations... would it?
static Object* object_from_handle(uint32_t handle) {
    auto iter = std::find_if(objects.begin(), objects.end(), [handle](const Object* o) {
        return (uintptr_t(o) & 0xFFFFFFFF) == handle;
    });

    if (iter == objects.end()) {
        printf("UNABLE TO FIND OBJECT!\n");
        exit(-1);
    }

    auto* obj = static_cast<Object*>(*iter);

    if (obj->sentinel != SENTINAL_MAGIC_CODE) {
        printf("ooops.. my memory thing doesn't work\n"
              "Expected %X. Got %X",
              SENTINAL_MAGIC_CODE,
              obj->sentinel);
        exit(-1);
    }

    return obj;
}

static uint32_t object_to_handle(const Object* object) {
    return (uint32_t) (uintptr_t(object) & 0x00000000FFFFFFFF);
}
// -----------------------------------------------------------------------------------

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

struct GlfwContext {
    GlfwContext() {
        glfwInit();

        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);
    }

    ~GlfwContext() {
        glfwTerminate();
    }
};

// leak but i dont care
static GlfwContext* glfwContext = nullptr;
static GLFWwindow*  window      = nullptr;

/*  You need to run "python scripts/generate_api_table.py winapi_impl.cc > symbols.inl" if you change any of
    function prototypes below :)
*/

static auto get_time_ms() -> uint64_t {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

void Sleep_trampoline() {
    auto sleepDurationMs = process_reg_read_u32(Register::r0);
    auto* thread = process_get_current_thread();

    thread->state = Thread::Waiting;
    thread->waitFunc = [sleepStart = get_time_ms(), sleepDurationMs](Thread* thread) {
        if (get_time_ms() - sleepStart >= sleepDurationMs) {
            thread->state = Thread::Running;
        }
    };
    process_thread_yield();
}

void WaitForSingleObject_trampoline() {
    enum {
        WAIT_ABANDONED = 0x00000080L,
        WAIT_OBJECT_0  = 0x00000000L,
        WAIT_TIMEOUT   = 0x00000102L,
        WAIT_FAILED    = 0xFFFFFFFF
    };

    auto handle  = process_reg_read_u32(Register::r0);
    auto timeout = process_reg_read_u32(Register::r1);

    auto event = object_from_handle(handle);

    // We can return immediatly if set
    if (event->event.currentState) {
        if (! event->event.manualReset)
            event->event.currentState = false;

        process_reg_write_u32(Register::r0, WAIT_OBJECT_0);
        return;
    }

    // zero timeout check immediatly
    if (timeout == 0) {
        process_reg_write_u32(Register::r0,
            event->event.currentState ? WAIT_OBJECT_0
                                      : WAIT_TIMEOUT
        );
        return;
    }

    // otherwise we need to sleep the thread
    auto* thread     = process_get_current_thread();
    thread->state    = Thread::Waiting;
    thread->waitFunc = [event, timeout, start = get_time_ms()](Thread* thd) {
        if (event->event.currentState) {
            if (! event->event.manualReset)
                event->event.currentState = false;

            process_reg_write_u32(Register::r0, WAIT_OBJECT_0);
            thd->state = Thread::Running;
            return;
        }

        if (get_time_ms() - start >= timeout) {
            process_reg_write_u32(Register::r0, WAIT_TIMEOUT);
            thd->state = Thread::Running;
            return;
        }
    };
    process_thread_yield();
}

void WaitForMultipleObjects_trampoline() {
    not_implemented();
}

void EnterCriticalSection_trampoline() {
    auto cs = (CRITICAL_SECTION*) process_mem_target_to_host(process_reg_read_u32(Register::r0));
    auto thread = process_get_current_thread();

    if (cs->holder.has_value()) {
        if (cs->holder != thread->id) {
            thread->state = Thread::Waiting;
            thread->waitFunc = [cs](Thread* thread) {
                if (! cs->holder) {
                    thread->state = Thread::Running;
                }
            };
            process_thread_yield();
            return;
        }
    }
}

// int64_t  __rt_sdiv64by64(int64_t a, int64_t b);
// uint64_t __rt_udiv64by64(uint64_t a, uint64_t b);
// uint64_t __rt_urem64by64(uint64_t a, uint64_t b);

void __rt_sdiv64by64_trampoline() {
    int64_t a = 0;
    int64_t b = 0;

    a = ((int64_t) process_reg_read_u32(Register::r1) << 32) | process_reg_read_u32(Register::r0);
    b = ((int64_t) process_reg_read_u32(Register::r3) << 32) | process_reg_read_u32(Register::r2);

    auto r = a / b;

    process_reg_write_u32(Register::r1, (r & 0xFFFFFFFF00000000) >> 32);
    process_reg_write_u32(Register::r0, (r & 0x00000000FFFFFFFF));
}

void __rt_udiv64by64_trampoline() {
    uint64_t a = 0;
    uint64_t b = 0;

    a = ((uint64_t) process_reg_read_u32(Register::r1) << 32) | process_reg_read_u32(Register::r0);
    b = ((uint64_t) process_reg_read_u32(Register::r3) << 32) | process_reg_read_u32(Register::r2);

    auto r = a / b;

    process_reg_write_u32(Register::r1, (r & 0xFFFFFFFF00000000) >> 32);
    process_reg_write_u32(Register::r0, (r & 0x00000000FFFFFFFF));
}

void __rt_urem64by64_trampoline() {
    uint64_t a = 0;
    uint64_t b = 0;

    a = ((uint64_t) process_reg_read_u32(Register::r1) << 32) | process_reg_read_u32(Register::r0);
    b = ((uint64_t) process_reg_read_u32(Register::r3) << 32) | process_reg_read_u32(Register::r2);

    auto r = a % b;

    process_reg_write_u32(Register::r1, (r & 0xFFFFFFFF00000000) >> 32);
    process_reg_write_u32(Register::r0, (r & 0x00000000FFFFFFFF));
}

namespace coredll {
FUNC void Sleep(int) {
}

FUNC bool DeviceIoControl(uint32_t device, uint32_t code, void* inBuf, uint32_t inBufSize, void* outBuf, uint32_t outBufSize, uint32_t bytesRet, void* lpOverlapped) {
    not_implemented();
    return false;
}

FUNC uint32_t CreateEventW(void* attributes, bool manualReset, bool initialState, const TCharType* name) {
    auto* object = object_alloc();
    object->type = Object::Type::Event;
    object->event = {
        .manualReset = manualReset,
        .currentState = initialState,
        //.name = string::toMulti(name)
    };

    return object_to_handle(object);
}

FUNC uint32_t CreateMutexW(SECURITY_ATTRIBUTES* attributes, bool initialOwner, const TCharType* name) {
    auto* object = object_alloc();
    object->type = Object::Type::Mutex;
    object->mutex = {
        .cs = CRITICAL_SECTION{ initialOwner ? std::make_optional(process_get_current_thread()->id)
                                             : std::nullopt },
        //.name = string::toMulti(name)
    };

    printf("CreateMutexW(attr: 0x%X, initialOwner: %s)\n",
           attributes,
           (initialOwner ? "yes" : "no"));

    return object_to_handle(object);
}

// This is never called, we handle it manually
FUNC uint32_t WaitForSingleObject(uint32_t handle, uint32_t timeout) {
    return 0;
}

FUNC uint32_t GetLastError() {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t CreateFileW(const TCharType* rawPath, uint32_t access, uint32_t share, void* attr, uint32_t create, uint32_t flags, uint32_t temp) {
    constexpr auto CREATE_NEW         = 1;
    constexpr auto CREATE_ALWAYS      = 2;
    constexpr auto OPEN_EXISTING      = 3;
    constexpr auto OPEN_ALWAYS        = 4;
    constexpr auto TRUNCATE_EXISTING  = 5;

    constexpr auto GENERIC_READ       = 0x80000000;
    constexpr auto GENERIC_WRITE      = 0x40000000;

    auto path = string::toMulti(rawPath);

    printf("CreateFileW:\n"
        "\trawPath: %p (%s)\n"
        "\taccess:  %d\n"
        "\tshare:   %d\n"
        "\tattr:    %p\n"
        "\tcreate:  %d\n"
        "\tflags:   %d\n"
        "\ttemp:    %d\n",
        rawPath, path.c_str(),
        access,
        share,
        attr,
        create,
        flags,
        temp
    );

    auto mode = [access] {
            std::string s;

            if (access & GENERIC_WRITE)
            {
                s += "w";
            }
            if (access & GENERIC_READ)
            {
                s += "rb";
            }

            return s;
        }();

    static constexpr auto Actual = "/Users/chroma/Desktop/preem-hle/roms/Trailblazer/";
    static constexpr auto SDRoot = "D:\\SD CARD\\";

    //if (access & GENERIC_WRITE) {
    //    path = "/Users/chroma/Desktop/preem-hle/memory/" + string::withSectionReplaced(path, ":", ".bin");
    //}
    //else
    //if (access & GENERIC_READ) {
        path = string::withSectionReplaced(path, SDRoot, Actual);
        //}

    for (auto& c : path)
        if (c == '\\')
            c = '/';

    printf("%s: %s\n", mode.c_str(), path.c_str());

    auto handle = ::fopen(path.c_str(), mode.c_str());

    if (handle) {
        auto* object = object_alloc();
        object->file = handle;
        printf("OK!\n");
        return object_to_handle(object);
    }

    printf("Failed!\n");
    return INVALID_HANDLE_VALUE;
}

FUNC void CloseHandle(uint32_t handle) {
    auto* object = object_from_handle(handle);

    switch (object->type) {
        case Object::Type::Event: {
            printf("CloseHandle: Released event\n");
        } break;

        case Object::Type::Mutex: {
            printf("CloseHandle: Released mutex\n");
        } break;

        case Object::Type::File: {
            printf("CloseHandle: Released file handle\n");
            fclose(object->file);
        } break;

        default: {
            printf("Unknown object type\n");
        } break;
    }

    object_free(object);
}

FUNC uint32_t SetFilePointer(uint32_t hfile, uint32_t distance, uint32_t* highDist, uint32_t method) {
    not_implemented();
    return 0;
}

FUNC uint32_t ReadFile(uint32_t hfile, void* buffer, uint32_t size, uint32_t* outSize, void* overlapped) {
    not_implemented();
    return 0;
}

FUNC uint32_t OpenEventW(uint32_t dwDesiredAccess, bool bInherituint32_t, const TCharType* lpName) {
    not_implemented();
    return 0;
}

FUNC bool EventModify(uint32_t hEvent, uint32_t dwFunc) {
    not_implemented();
    return false;
}

FUNC uint32_t RegSetValueExW(uint32_t uint32, const TCharType* lpValueName, uint32_t Reserved, uint32_t dwType, const uint8_t* lpData, uint32_t cbData) {
    not_implemented();
    return 0;
}

FUNC uint32_t RegOpenKeyExW(uint32_t uint32, const TCharType* lpSubKey, uint32_t ulOptions, int32_t samDesired, uint32_t* phkResult) {
    not_implemented();
    return 0;
}

FUNC uint32_t RegQueryValueExW(uint32_t uint32, const TCharType* lpValueName, uint32_t* lpReserved, uint32_t* lpType, uint8_t* lpData, uint32_t* lpcbData) {
    not_implemented();
    return 0;
}

FUNC bool SetSystemMemoryDivision(uint32_t dwNumberOfPages, uint32_t dwNumberOfPagesReserved, uint32_t dwNumberOfPagesShared) {
    return true;
}

FUNC uint32_t WaitForMultipleObjects(uint32_t nCount, const uint32_t *lpuint32_ts, bool bWaitAll, uint32_t dwMilliseconds) {
    not_implemented();
    return true;
}

FUNC bool FindCloseChangeNotification(uint32_t hChangeuint32_t) {
    not_implemented();
    return false;
}

FUNC bool FindNextChangeNotification(uint32_t hChangeuint32_t) {
    not_implemented();
    return false;
}

FUNC uint32_t FindFirstChangeNotificationW(const TCharType* lpPathName, bool bWatchSubtree, uint32_t dwNotifyFilter) {
    not_implemented();
    return 0;
}

FUNC uint32_t GetFileAttributesW(const TCharType* lpFileName) {
    not_implemented();
    return 0;
}

FUNC void* LocalReAlloc(void* hMem, uint32_t uBytes, uint32_t uFlags) {
    not_implemented();
    return nullptr;
}

FUNC void* LocalAlloc(uint32_t uFlags, uint32_t uBytes) {
    not_implemented();
    return nullptr;
}

FUNC void* LocalFree(void* hMem) {
    not_implemented();
    return nullptr;
}

FUNC bool SetThreadPriority(uint32_t handle, int32_t priority) {
    not_implemented_warn();
    return false;
}

FUNC bool TerminateThread(uint32_t handle, uint32_t code) {
    not_implemented();
    return false;
}

FUNC uint32_t SuspendThread(uint32_t handle) {
    not_implemented();
    return 0;
}

FUNC uint32_t ResumeThread(uint32_t handle) {
    not_implemented();
    return 0;
}

FUNC bool CreateThread(void* attr, uint32_t stacksize, void* callback, void* user, uint32_t flags, uint32_t* threadid) {
    enum ThreadFlags {
        CREATE_SUSPENDED = 0x00000004,
        STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
    };

    auto thread = process_create_thread(stacksize != 0 ? align<size_t>(stacksize, 0x1000) : mb(1),
                                        process_mem_host_to_target((host_memory_t) callback),
                                        user ? process_mem_host_to_target((host_memory_t) user) : 0);

    if (threadid != nullptr)
        *threadid = thread->id;

    if (! isBitSet(flags, ThreadFlags::CREATE_SUSPENDED)) {
        process_thread_start(thread);
    }

    return true;
}

struct SYSTEMTIME {
    uint16_t wYear;
    uint16_t wMonth;
    uint16_t wDayOfWeek;
    uint16_t wDay;
    uint16_t wHour;
    uint16_t wMinute;
    uint16_t wSecond;
    uint16_t wMilliseconds;
};

FUNC void GetLocalTime(void* lpSystemTime) {
    if (! lpSystemTime)
        return;

    auto t = time(nullptr);
    auto tm = localtime(&t);
    auto st = (SYSTEMTIME*) lpSystemTime;

    st->wYear         = tm->tm_year + 1900;
    st->wMonth        = tm->tm_mon + 1;
    st->wDayOfWeek    = tm->tm_wday;
    st->wDay          = tm->tm_mday;
    st->wHour         = tm->tm_hour;
    st->wMinute       = tm->tm_min;
    st->wSecond       = tm->tm_sec;
    st->wMilliseconds = 0;
}

FUNC bool CreateDirectoryW(const TCharType* lpPathName, void* lpSecurityAttributes) {
    not_implemented();
    return false;
}

FUNC int32_t MultiByteToWideChar(uint32_t CodePage, uint32_t dwFlags, const char* lpMultiByteStr, int32_t cbMultiByte, TCharType* lpWideCharStr, int32_t cchWideChar) {
    printf("MultiByteToWideChar:\n"
        "\tCodePage:        %d\n"
        "\tdwFlags:         %d\n"
        "\tlpMultiByteStr:  %s\n"
        "\tcbMultiByte:     %d\n"
        "\tlpWideCharStr:   %ls\n"
        "\tcchWideChar:     %d\n",
        CodePage,
        dwFlags,
        lpMultiByteStr,
        cbMultiByte,
        lpWideCharStr,
        cchWideChar);

    TCharType buffer[1024]{};
    const auto len = string::toWide(buffer, lpMultiByteStr, std::min<int32_t>(std::size(buffer), cchWideChar));

    if (cchWideChar == 0)
    {
        // return the number of bytes required for the destination string
        printf("Returning dest string length: %d\n", len);
        return len;
    }

    memcpy(lpWideCharStr, buffer, len * 2);
    return len;
}

FUNC int32_t WideCharToMultiByte(uint32_t CodePage, uint32_t dwFlags, const TCharType* lpWideCharStr, int32_t cchWideChar, char* lpMultiByteStr, int32_t cbMultiByte, const char* lpDefaultChar, bool* lpUsedDefaultChar) {
    printf("WideCharToMultiByte: %ls\n", lpWideCharStr);

    char buffer[1024]{};
    const auto len = string::toMulti(buffer, lpWideCharStr, std::min<int32_t>(std::size(buffer), cbMultiByte)) + 1;

    if (cchWideChar == 0 || cbMultiByte == 0)
    {
        // return the number of bytes required for the destination string
        printf("Returning dest string length: %d\n", len);
        return len;
    }

    memcpy(lpMultiByteStr, buffer, len);
    return len;
}

FUNC bool DeleteFileW(const TCharType* lpFileName) {
    not_implemented();
    return false;
}

FUNC bool FindClose(uint32_t hFindFile) {
    not_implemented();
    return false;
}

FUNC bool FindNextFileW(uint32_t hFindFile, void* lpFindFileData) {
    not_implemented();
    return false;
}

FUNC uint32_t FindFirstFileW(const TCharType* lpFileName, void* lpFindFileData) {
    not_implemented();
    return 0;
}

FUNC uint32_t GetModuleFileNameW(uint32_t hModule, TCharType* lpFilename, uint32_t nSize) {
    printf("GetModuleFileNameW(%x, %x, %d)\n", hModule, lpFilename, nSize);

    if (hModule == 0) {
        static const auto modulePath = "D:\\SD CARD\\TrailBlazer.exe";

        return string::toWide(lpFilename, modulePath, std::min<int32_t>(nSize, strlen(modulePath)));
    }

    not_implemented();
    return 0;
}

FUNC void InitializeCriticalSection(void* lpCriticalSection) {
    auto cs = reinterpret_cast<CRITICAL_SECTION*>(lpCriticalSection);

    // I Assume initialising doesn't immediatly take the lock?
    cs->holder = std::nullopt;
}

FUNC void DeleteCriticalSection(void* lpCriticalSection) {
    auto cs = reinterpret_cast<CRITICAL_SECTION*>(lpCriticalSection);
    *cs = {};
}

FUNC void EnterCriticalSection(void* lpCriticalSection) {
}

FUNC void LeaveCriticalSection(void* lpCriticalSection) {
    auto cs = reinterpret_cast<CRITICAL_SECTION*>(lpCriticalSection);
    //check(cs->holder == process_get_current_tid(), "Out of order critial section");
    cs->holder = {};
}

FUNC bool QueryPerformanceFrequency(void* lpFrequency) {
    *(LARGE_INTEGER*) lpFrequency = {
        .quadpart = 1000000
    };

    return true;
}

FUNC bool QueryPerformanceCounter(void* lpPerformanceCount) {
    *(LARGE_INTEGER*) lpPerformanceCount = {
        .quadpart = (uint64_t) std::chrono::high_resolution_clock::now().time_since_epoch().count()
    };

    return true;
}

FUNC int32_t ShowCursor(bool show) {
    not_implemented();
    return 0;
}

FUNC uint32_t SetCursor(uint32_t cursor) {
    not_implemented();
    return 0;
}

FUNC bool EndPaint(uint32_t hwnd, const void* paint) {
    not_implemented();
    return false;
}

FUNC uint32_t BeginPaint(uint32_t hwnd, void* paint) {
    not_implemented();
    return 0;
}

FUNC uint32_t GetStockObject(uint32_t) {
    not_implemented_warn();
    static uint32_t counter = 0;
    return ++counter;
}

FUNC uint32_t LoadCursorW(void* instance, pointer_or_integer_t name) {
    not_implemented_warn();
    static uint32_t counter = 0;
    return ++counter;
}

FUNC bool SetForegroundWindow(uint32_t hwnd) {
    not_implemented_warn();
    return true;
}

FUNC bool BringWindowToTop(uint32_t hwnd) {
    not_implemented_warn();
    return true;
}

FUNC uint32_t SetFocus(uint32_t hwnd) {
    return hwnd;
}

FUNC bool UpdateWindow(uint32_t hwnd) {
    glfwPollEvents();
    return true;
}

FUNC bool ShowWindow(uint32_t hwnd, int32_t show) {
    not_implemented_warn();
    return true;
}

FUNC bool RegisterClassW(const void* wnd) {
    not_implemented_warn();
    return true;
}

FUNC bool CreateWindowExW(uint32_t dwExStyle, const TCharType* lpClassName, const TCharType* lpWindowName, uint32_t dwStyle, int32_t X, int32_t Y, int32_t nWidth, int32_t nHeight, uint32_t hWndParent, uint32_t hMenu, void* hInstance, void* lpParam) {
    if (! glfwContext) {
        glfwContext = new GlfwContext;
    }

    auto name = string::toMulti(lpWindowName);
    window = glfwCreateWindow(nWidth, nHeight, name.c_str(), nullptr, nullptr);
    check(window != nullptr, "Failed to create GLFW window");
    glfwSetWindowUserPointer(window, lpParam);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    glfwPollEvents();

    return true;
}

FUNC bool DestroyWindow(uint32_t uint32_t) {
    glfwDestroyWindow(window);
    return true;
}

FUNC uint32_t RegisterWindowMessageW(const TCharType* string) {
    not_implemented();
    return 0;
}

FUNC uint32_t SendMessageW(uint32_t hwnd, uint32_t msg, uint32_t wparam, uint32_t lparam) {
    not_implemented();
    return 0;
}

FUNC uint32_t DefWindowProcW(uint32_t hwnd, uint32_t msg, uint32_t wparam, uint32_t lparam) {
    not_implemented();
    return 0;
}

FUNC uint32_t DispatchMessageW(const void* msg) {
    not_implemented();
    return 0;
}

FUNC bool TranslateMessage(const void* msg) {
    not_implemented();
    return false;
}

FUNC bool PeekMessageW(void* msg, uint32_t hwnd, int32_t min, int32_t max, int32_t mode) {
    not_implemented();
    return false;
}

FUNC void PostQuitMessage(int32_t code) {
    not_implemented();
}

enum MMSYS {
    NOERROR = 0
};

struct WAVEOUTCAPS {
    uint16_t wMid;
    uint16_t wPid;
    uint16_t vDriverVersion;
    char     szPname[32];
    uint32_t dwFormats;
    uint16_t wChannels;
    uint32_t dwSupport;
};

FUNC uint32_t waveOutGetDevCaps(uint32_t uDeviceID, void* pwoc, int32_t cbwoc) {
    auto caps = (WAVEOUTCAPS*) pwoc;

    std::strcpy(caps->szPname, "RealAudioDevice");
    caps->dwFormats = 0x800;
    caps->wChannels = 2;
    caps->dwSupport = 0x8 | 0x10 | 0x4;

    return MMSYS::NOERROR;
}

FUNC int32_t waveOutGetNumDevs() {
    return 1;
}

FUNC uint32_t waveOutOpen(void* phwo, uint32_t uDeviceID, const WAVEFORMATEX* pwfx, void* dwCallback, void* dwInstance, uint32_t fdwOpen) {
    return 0;
}

FUNC uint32_t waveOutClose(uint32_t hwo) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveOutPrepareHeader(uint32_t hwo, void* pwh, int32_t cbwh) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveOutUnprepareHeader(uint32_t hwo, void* pwh, int32_t cbwh) {
    not_implemented();
    return 0;
}

FUNC uint32_t waveOutWrite(uint32_t hwo, void* pwh, uint32_t cbwh) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveOutReset(uint32_t hwo) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveOutGetPosition(uint32_t hwo, void* pmmt, uint32_t cbmmt) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInAddBuffer(uint32_t hwi, void* pwh, uint32_t cbwh) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInPrepareHeader(uint32_t hwi, void* pwh, uint32_t cbwh) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInUnprepareHeader(uint32_t hwi, void* pwh, uint32_t cbwh) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInGetDevCaps(uint32_t uDeviceID, void* pwic, uint32_t cbwic) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInGetNumDevs() {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInStart(uint32_t hwi) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInOpen(uint32_t* phwi, uint32_t uDeviceID, void* pwfx, uint32_t dwCallback, uint32_t dwCallbackInstance, uint32_t fdwOpen) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInClose(uint32_t hwi) {
    not_implemented_warn();
    return 0;
}

FUNC uint32_t waveInReset(uint32_t hwi) {
    not_implemented_warn();
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
    return MMSYS::NOERROR;
}

FUNC int32_t strlen(const char* s) {
    return std::strlen(s);
}

FUNC char* strcpy(char* dst, const char* src) {
    return std::strcpy(dst, src);
}

FUNC int32_t     strcmp(const char* s1, const char* s2)             { return std::strcmp(s1, s2); }
FUNC char*       strstr(char* s1, const char* s2)                   { return std::strstr(s1, s2); }
FUNC int32_t     strncmp(const char* s1, const char* s2, int32_t n) { return std::strncmp(s1, s2, n); }
FUNC const char* strchr(char* s, int32_t n)                         { return std::strchr(s, n); }
FUNC const char* strrchr(const char* s, int32_t c)                  { return std::strrchr(s, c); }

static auto printTChar(const TCharType* s) -> const char* {
    static char buffer[1024]{};
    auto len = string::toMulti(buffer, s, sizeof(buffer));
    buffer[len] = '\0';
    return buffer;
}

FUNC const TCharType* wcsrchr(const TCharType* s, TCharType c) {
    const TCharType* last = nullptr;

    while(s && *s) {
        if (*s == c)
            last = s;

        s++;
    }

    return last;
}

FUNC const char* __itos(int32_t v) {
    static auto buffer = (char*) process_mem_target_to_host(process_mem_allocate(32));
    memset(buffer, 0, 32);
    snprintf(buffer, sizeof (buffer), "%d", v);
    return buffer;
};

FUNC int32_t __stoi(const char* str) {
    int32_t i;

    if (! str)
        return 0;

    std::sscanf(str, "%d", &i);
    return i;
}

FUNC int32_t  atoi(const char* s) { return ::atoi(s); }
FUNC float    atof(const char* s) { return ::atof(s); }
FUNC uint32_t strtoul(const char* s1, void* s2, int32_t n) { return ::strtoul(s1, (char**)s2, n); }
FUNC int32_t  toupper(int32_t c) { return std::toupper(c); }

// Fuck knows what this is supposed to be.. Maybe truncate func???
// truncate deees nuts
FUNC uint16_t __C_specific_uint32_tr(uint32_t v) {
    return v & 0xFFFF;
}

// int32_t CDECL _XcptFilter(NTSTATUS ex, PEXCEPTION_POINTERS ptr) ????
FUNC int32_t _XcptFilter(int32_t, void*) {
    not_implemented();
    return 0;
}

FUNC void __C_specific_handler(void*, uint64_t, void*, void*) {
    not_implemented();
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

FUNC uint32_t __utos(uint32_t v) { not_implemented(); return 0; }
FUNC float    __utod(float v)    { return v; }

FUNC float __stod(int32_t v) {
    return v;
}

FUNC int32_t __muld(int32_t a, int32_t b) {
    return a * b;
}

FUNC int32_t __dtoi(float v) {
    return v;
}

FUNC int32_t __dtos(float v) {
    return (int32_t) std::round(v);
}

FUNC float ldexp(float x, int32_t exp) { return std::ldexp(x, exp); }
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
FUNC int32_t vsprintf(char*, const char*, ...) {
    not_implemented();
    return 0;
}

FUNC int32_t sprintf(const char*, ...) {
    not_implemented();
    return 0;
}

FUNC int32_t _snwprintf(TCharType* buf, int32_t, const TCharType*, ...) {
    not_implemented();
    return 0;
}

FUNC int32_t mbstowcs(TCharType* dst, const char* src, int32_t len) {
    return string::toWide(dst, src, len);
}

FUNC void* memcpy(void* dst, const void* src, int32_t len) {
    return ::memcpy(dst, src, len);
}

FUNC void* memset(void* ptr, int32_t value, int32_t num) {
    return ::memset(ptr, value, num);
}

FUNC int32_t fclose(uint32_t handle) {
    auto* obj = object_from_handle(handle);
    const auto r = ::fclose(obj->file);
    object_free(obj);
    return r;
}

FUNC int32_t ftell(uint32_t handle) {
    return ::ftell(object_from_handle(handle)->file);
}

FUNC int32_t feof(uint32_t handle) {
    return ::feof(object_from_handle(handle)->file);
}

FUNC int32_t fseek(uint32_t handle, int32_t seek, int32_t offset) {
    return ::fseek(object_from_handle(handle)->file, seek, offset);
}

FUNC int32_t _wfopen(const TCharType* path, const TCharType* mode) {
    not_implemented();
    return 0;
}

FUNC int32_t fopen(const char* path, const char* mode) {
    not_implemented();
    return 0;
}

FUNC int32_t fread(void* dst, int32_t size, int32_t count, uint32_t handle) {
    return ::fread(dst, size, count, object_from_handle(handle)->file);
}

FUNC int32_t fwrite(const void* src, int32_t size, int32_t count, uint32_t handle) {
    return ::fwrite(src, size, count, object_from_handle(handle)->file);
}

FUNC int32_t rand() {
    return std::rand();
}

FUNC void* malloc(int32_t size) {
    return process_mem_target_to_host(process_mem_allocate(size));
}

FUNC void* realloc(void*, int32_t size) {
    not_implemented();
    return nullptr;
}

FUNC void free(void*) {
    not_implemented();
}

FUNC void* memmove(void* a, void* b, int32_t n) {
    return ::memmove(a, b, n);
}

FUNC int32_t memcmp(const void* s1, const void* s2, int32_t n) {
    return ::memcmp(s1, s2, n);
}

FUNC void qsort(void*, int32_t, int32_t, void*) {
    not_implemented();
}
}

#include "dependencies/glad-4.1/src/glad.c"

namespace libGLES_CM {
FUNC void eglSwapIntervalNV() {
    not_implemented();
}

FUNC void glEnableClientState(GLenum arr) {
    not_implemented();
}

FUNC void glDisableClientState(GLenum arr) {
    not_implemented();
}

FUNC void glVertexPointer(uint32_t size, GLenum type, uint32_t stride, const void* pointer) {
    not_implemented();
}

FUNC void glColorPointer(int32_t size, GLenum type, int32_t stride, const void* pointer) {
    not_implemented();
}

FUNC void glClientActiveTexture(GLenum texture) {
    not_implemented();
}

FUNC void glTexCoordPointer(int32_t size, GLenum type, int32_t stride, const void* pointer) {
    not_implemented();
}

FUNC void glDrawElements(GLenum mode, int32_t count, GLenum type, const void* indices) {
    not_implemented();
}

FUNC void glTexEnvf(GLenum target, GLenum pname, float param) {
    not_implemented_warn();
}

FUNC void glDepthRangef(float near, float far) {
    ::glDepthRangef(near, far);
}
FUNC void glDepthMask(bool enabled) {
    ::glDepthMask(enabled);
}

FUNC void glDepthFunc(GLenum func) {
    ::glDepthFunc(func);
}

FUNC void glCullFace(GLenum face) {
    ::glCullFace(face);
}

FUNC void glEnable(GLenum feat) {
    ::glEnable(feat);
}

FUNC void glDisable(GLenum feat) {
    ::glDisable(feat);
}

FUNC void glGetIntegerv(GLenum val, int32_t* params) {
    GLint paramsActual;
    ::glGetIntegerv(val, &paramsActual);
    *params = paramsActual;
}

FUNC const char* glGetString(GLenum name) {
    static auto targetStringBuffer = (char*) process_mem_target_to_host(process_mem_allocate(256));
    const auto hostString = ::glGetString(name);

    if (! hostString)
        return nullptr;

    ::memset(targetStringBuffer, 0, 256);
    ::strcpy(targetStringBuffer, (const char*) hostString);

    return targetStringBuffer;
}

FUNC void glClear(GLenum bits) {
    ::glClear(bits);
}

FUNC void glClearColorx(float r, float g, float b, float a) {
    ::glClearColor(r, g, b, a);
}

FUNC void eglSwapBuffers() {
    glfwSwapBuffers(window);
}

FUNC void glFinish() {
    ::glFinish();
}

FUNC void glLoadMatrixx() {
    not_implemented();
}

FUNC void glMatrixMode(GLenum mode) {
    ::glMatrixMode(mode);
}

FUNC void glViewport(float x, float y, float w, float h) {
    ::glViewport(x, y, w, h);
}

FUNC void glScissor(GLint x, GLint y, GLsizei width, GLsizei height) {
    ::glScissor(x, y, width, height);
}

FUNC void glGenTextures(int32_t count, uint32_t* textures) {
    not_implemented();
}

FUNC void glDeleteTextures(int32_t count, uint32_t* textures) {
    not_implemented();
}

FUNC void glTexImage2D(GLenum  target, int32_t level, int32_t internalformat, int32_t width, int32_t height, int32_t border, int32_t format, GLenum type, const void* pixels) {
    not_implemented();
}

FUNC void glTexParameterf() {
    not_implemented();
}

FUNC void glBindTexture(GLenum mode, uint32_t tex) {
    ::glBindTexture(mode, tex);
}

FUNC void glCompressedTexImage2D() {
    not_implemented();
}

FUNC void glActiveTexture(GLenum mode) {
    ::glActiveTexture(mode);
}

FUNC void glAlphaFunc(GLenum func, float ref) {
    ::glAlphaFunc(func, ref);
}

FUNC void glBlendFunc(GLenum sfactor, GLenum dfactor) {
    ::glBlendFunc(sfactor, dfactor);
}

FUNC void glDrawArrays(GLenum mode, int32_t index, int32_t count) {
    ::glDrawArrays(mode, index, count);
}

//using EGLDisplay = void*;
//using EGLConfig  = void*;
//using EGLSurface = void*;
//using EGLContext = void*;
//
//enum NativeDisplayType : int32_t {
//};

FUNC bool eglMakeCurrent(void* dpy, void* draw, void* read, void* ctx) {
    not_implemented_warn();
    return true;
}

struct Context {
};

struct WindowSurface {
};

struct Display {
};

template <typename T>
static auto allocate_in_process() -> T* {
    return (T*) process_mem_target_to_host(process_mem_allocate(sizeof (T)));
}

FUNC void* eglCreateWindowSurface(void* display, void* config, int32_t native_window, int32_t const* attrib_list) {
    return allocate_in_process<WindowSurface>();
}

FUNC void* eglCreateContext(void* dpy, void* config, void* share_list, const int32_t* attrib_list) {
    return allocate_in_process<Context>();
}

FUNC bool eglChooseConfig(void* dpy, const int32_t* attrib_list, void* configs, int32_t config_size, int32_t* num_config) {
    not_implemented_warn();
    return true;
}

FUNC bool eglGetConfigs(void* dpy, void* configs, int32_t config_size, int32_t* num_config) {
    *num_config = 1;
    return true;
}

FUNC bool eglInitialize(void* dpy, int32_t* major, int32_t* minor) {
    *major = 1;
    *minor = 0;

    gladLoadGL();

    return true;
}

FUNC void* eglGetDisplay(int32_t display) {
    check(display == 0, "too many displays!!");
    return allocate_in_process<Display>();
}

FUNC bool eglTerminate(void* dpy) {
    not_implemented_warn();
    return true;
}

FUNC bool eglDestroySurface(void* dpy, void* surface) {
    not_implemented_warn()
    return true;
}

FUNC bool eglDestroyContext(void* dpy, void* ctx) {
    not_implemented_warn()
    return true;
}

}

#include "symbols.inl"
