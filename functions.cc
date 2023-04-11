#include <cstdint>

using GLenum = unsigned int;

// All functions have to be declared on a single line because I'm lazy and the python parser will break.
#define FUNC

FUNC bool DeviceIoControl(uint32_t device, uint32_t code, void* inBuf, uint32_t inBufSize, void* outBuf, uint32_t outBufSize, uint32_t bytesRet, void* lpOverlapped) {
    return false;
}

FUNC void CloseHandle(uint32_t handle) {

}

FUNC uint32_t CreateEventW(void* attributes, bool reset, bool state, const wchar_t* name) {
    return 0;
}

FUNC uint32_t CreateFileW(const wchar_t* path, uint32_t access, uint32_t share, void* attr, uint32_t create, uint32_t flags, uint32_t temp) {
    return 0;
}

FUNC uint32_t CreateMutexW(void* attributes, bool initialOwner, const wchar_t* name) {
    return 0;
}

FUNC void Sleep(uint32_t time) {
}

FUNC uint32_t WaitForSingleObject(uint32_t handle, uint32_t ms) {
    return 0;
}

FUNC char* strcpy(char* dst, const char* src) {
    return nullptr;
}

// waveOutGetVolume
// waveOutSetVolume
// GetLastError
// SetFilePointer
// ReadFile
// RegisterWindowMessageW
// OpenEventW
// EventModify
// RegSetValueExW
// RegOpenKeyExW
// RegQueryValueExW
// SendMessageW
// DefWindowProcW
// DispatchMessageW
// TranslateMessage
// PeekMessageW
// SetSystemMemoryDivision
// WaitForMultipleObjects
// CreateThread
// FindCloseChangeNotification
// FindNextChangeNotification
// FindFirstChangeNotificationW
// GetFileAttributesW
// LocalReAlloc
// LocalAlloc
// LocalFree
// TerminateThread
// SetThreadPriority
// InitializeCriticalSection
// DeleteCriticalSection
// EnterCriticalSection
// LeaveCriticalSection
// QueryPerformanceFrequency
// QueryPerformanceCounter
// waveOutGetDevCaps
// waveOutGetNumDevs
// waveOutOpen
// waveOutClose
// waveOutPrepareHeader
// waveOutUnprepareHeader
// waveOutWrite
// waveOutReset
// waveOutGetPosition
// waveInAddBuffer
// waveInPrepareHeader
// waveInUnprepareHeader
// waveInGetDevCaps
// waveInGetNumDevs
// waveInStart
// waveInOpen
// waveInClose
// waveInReset
// GetLocalTime
// CreateDirectoryW
// MultiByteToWideChar
// DeleteFileW
// FindClose
// WideCharToMultiByte
// FindNextFileW
// FindFirstFileW
// GetModuleFileNameW
// SuspendThread
// ResumeThread
// PostQuitMessage
// ShowCursor
// SetCursor
// EndPaint
// BeginPaint
// SetForegroundWindow
// BringWindowToTop
// SetFocus
// UpdateWindow
// ShowWindow
// CreateWindowExW
// RegisterClassW
// GetStockObject
// LoadCursorW
// DestroyWindow

// __rt_sdiv
// __itos
// __muls
// __stod
// __muld
// __dtoi
// __stoi
// __rt_sdiv64by64
// __rt_udiv
// __dtos
// __C_specific_handler
// __lts
// __gts
// __stou
// _XcptFilter
// __rt_udiv64by64
// __rt_urem64by64
// _wfopen
// _snwprintf
// __utos
// __divs
// __adds
// __negs
// __subs
// __utod

// vsprintf
// sin
// memcpy
// sprintf
// strlen
// mbstowcs
// strcmp
// memset
// cos
// strstr
// pow
// atan2
// acos
// fclose
// fread
// atoi
// strncmp
// strtoul
// rand
// malloc
// realloc
// free
// ldexp
// strchr
// atan
// ftell
// fseek
// memmove
// memcmp
// qsort
// fopen
// feof
// fwrite
// strrchr
// wcsrchr
// sqrt
// toupper
// atof
// tan
// asin

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
FUNC const char* glGetString() {}
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

FUNC void glGenTextures(int count, uint32_t* handles) {}
FUNC void glDeleteTextures(int count, uint32_t* handles) {}
FUNC void glTexImage2D(GLenum  target, int level, int internalformat, int width, int height, int border, int format, GLenum type, const void* pixels) {}
FUNC void glTexParameterf() {}
FUNC void glBindTexture(GLenum mode, uint32_t handle) {}
FUNC void glCompressedTexImage2D() {}
FUNC void glActiveTexture(GLenum mode) {}

FUNC void glAlphaFunc(GLenum func, float ref) {}
FUNC void glBlendFunc(GLenum sfactor, GLenum dfactor) {}

FUNC void glDrawArrays(GLenum mode, int index, int count) {}

#include "symbols.inl"