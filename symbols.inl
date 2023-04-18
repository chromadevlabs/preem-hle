#include "process.h"
static void DeviceIoControl_trampoline(Process* p) {
    auto _0device = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1code = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2inBuf = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3inBufSize = (uint32_t)process_reg_read_u32(p, Register::r3);
    auto _4outBuf = (void*)process_mem_target_to_host(p, process_stack_read(p, 0));
    auto _5outBufSize = (uint32_t)process_stack_read(p, 1);
    auto _6bytesRet = (uint32_t)process_stack_read(p, 2);
    auto _7lpOverlapped = (void*)process_mem_target_to_host(p, process_stack_read(p, 3));

    const auto r = coredll::DeviceIoControl(_0device, _1code, _2inBuf, _3inBufSize, _4outBuf, _5outBufSize, _6bytesRet, _7lpOverlapped);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void CreateEventW_trampoline(Process* p) {
    auto _0attributes = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1reset = (bool)process_reg_read_u32(p, Register::r1);
    auto _2state = (bool)process_reg_read_u32(p, Register::r2);
    auto _3name = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));

    const auto r = coredll::CreateEventW(_0attributes, _1reset, _2state, _3name);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void CreateMutexW_trampoline(Process* p) {
    auto _0attributes = (SECURITY_ATTRIBUTES*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1initialOwner = (bool)process_reg_read_u32(p, Register::r1);
    auto _2name = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));

    const auto r = coredll::CreateMutexW(_0attributes, _1initialOwner, _2name);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void Sleep_trampoline(Process* p) {
    auto _0time = (uint32_t)process_reg_read_u32(p, Register::r0);

    coredll::Sleep(_0time);

    process_reg_write_u32(p, Register::r0, 0);
}

static void WaitForSingleObject_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1timeout = (uint32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::WaitForSingleObject(_0handle, _1timeout);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void GetLastError_trampoline(Process* p) {
const auto r = coredll::GetLastError();

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void CreateFileW_trampoline(Process* p) {
    auto _0rawPath = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1access = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2share = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3attr = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));
    auto _4create = (uint32_t)process_stack_read(p, 0);
    auto _5flags = (uint32_t)process_stack_read(p, 1);
    auto _6temp = (uint32_t)process_stack_read(p, 2);

    const auto r = coredll::CreateFileW(_0rawPath, _1access, _2share, _3attr, _4create, _5flags, _6temp);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void CloseHandle_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);

    coredll::CloseHandle(_0handle);

    process_reg_write_u32(p, Register::r0, 0);
}

static void SetFilePointer_trampoline(Process* p) {
    auto _0hfile = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1distance = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2highDist = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3method = (uint32_t)process_reg_read_u32(p, Register::r3);

    const auto r = coredll::SetFilePointer(_0hfile, _1distance, _2highDist, _3method);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void ReadFile_trampoline(Process* p) {
    auto _0hfile = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1buffer = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2size = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3outSize = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));
    auto _4overlapped = (void*)process_mem_target_to_host(p, process_stack_read(p, 0));

    const auto r = coredll::ReadFile(_0hfile, _1buffer, _2size, _3outSize, _4overlapped);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void OpenEventW_trampoline(Process* p) {
    auto _0dwDesiredAccess = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1bInherituint32_t = (bool)process_reg_read_u32(p, Register::r1);
    auto _2lpName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));

    const auto r = coredll::OpenEventW(_0dwDesiredAccess, _1bInherituint32_t, _2lpName);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void EventModify_trampoline(Process* p) {
    auto _0hEvent = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1dwFunc = (uint32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::EventModify(_0hEvent, _1dwFunc);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void RegSetValueExW_trampoline(Process* p) {
    auto _0uint32 = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpValueName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2Reserved = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3dwType = (uint32_t)process_reg_read_u32(p, Register::r3);
    auto _4lpData = (const uint8_t*)process_mem_target_to_host(p, process_stack_read(p, 0));
    auto _5cbData = (uint32_t)process_stack_read(p, 1);

    const auto r = coredll::RegSetValueExW(_0uint32, _1lpValueName, _2Reserved, _3dwType, _4lpData, _5cbData);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void RegOpenKeyExW_trampoline(Process* p) {
    auto _0uint32 = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpSubKey = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2ulOptions = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3samDesired = (int)process_reg_read_u32(p, Register::r3);
    auto _4phkResult = (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, 0));

    const auto r = coredll::RegOpenKeyExW(_0uint32, _1lpSubKey, _2ulOptions, _3samDesired, _4phkResult);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void RegQueryValueExW_trampoline(Process* p) {
    auto _0uint32 = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpValueName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2lpReserved = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3lpType = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));
    auto _4lpData = (uint8_t*)process_mem_target_to_host(p, process_stack_read(p, 0));
    auto _5lpcbData = (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, 1));

    const auto r = coredll::RegQueryValueExW(_0uint32, _1lpValueName, _2lpReserved, _3lpType, _4lpData, _5lpcbData);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void SetSystemMemoryDivision_trampoline(Process* p) {
    auto _0dwNumberOfPages = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1dwNumberOfPagesReserved = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2dwNumberOfPagesShared = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::SetSystemMemoryDivision(_0dwNumberOfPages, _1dwNumberOfPagesReserved, _2dwNumberOfPagesShared);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void WaitForMultipleObjects_trampoline(Process* p) {
    auto _0nCount = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpuint32_ts = (const uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2bWaitAll = (bool)process_reg_read_u32(p, Register::r2);
    auto _3dwMilliseconds = (uint32_t)process_reg_read_u32(p, Register::r3);

    const auto r = coredll::WaitForMultipleObjects(_0nCount, _1lpuint32_ts, _2bWaitAll, _3dwMilliseconds);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void FindCloseChangeNotification_trampoline(Process* p) {
    auto _0hChangeuint32_t = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::FindCloseChangeNotification(_0hChangeuint32_t);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void FindNextChangeNotification_trampoline(Process* p) {
    auto _0hChangeuint32_t = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::FindNextChangeNotification(_0hChangeuint32_t);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void FindFirstChangeNotificationW_trampoline(Process* p) {
    auto _0lpPathName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1bWatchSubtree = (bool)process_reg_read_u32(p, Register::r1);
    auto _2dwNotifyFilter = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::FindFirstChangeNotificationW(_0lpPathName, _1bWatchSubtree, _2dwNotifyFilter);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void GetFileAttributesW_trampoline(Process* p) {
    auto _0lpFileName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::GetFileAttributesW(_0lpFileName);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void LocalReAlloc_trampoline(Process* p) {
    auto _0hMem = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1uBytes = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2uFlags = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::LocalReAlloc(_0hMem, _1uBytes, _2uFlags);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void LocalAlloc_trampoline(Process* p) {
    auto _0uFlags = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1uBytes = (uint32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::LocalAlloc(_0uFlags, _1uBytes);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void LocalFree_trampoline(Process* p) {
    auto _0hMem = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::LocalFree(_0hMem);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void SetThreadPriority_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1priority = (int)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::SetThreadPriority(_0handle, _1priority);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void TerminateThread_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1code = (uint32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::TerminateThread(_0handle, _1code);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void SuspendThread_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::SuspendThread(_0handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void ResumeThread_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::ResumeThread(_0handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void CreateThread_trampoline(Process* p) {
    auto _0attr = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1stacksize = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2callback = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3user = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));
    auto _4flags = (uint32_t)process_stack_read(p, 0);
    auto _5threadid = (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, 1));

    const auto r = coredll::CreateThread(_0attr, _1stacksize, _2callback, _3user, _4flags, _5threadid);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void GetLocalTime_trampoline(Process* p) {
    auto _0lpSystemTime = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    coredll::GetLocalTime(_0lpSystemTime);

    process_reg_write_u32(p, Register::r0, 0);
}

static void CreateDirectoryW_trampoline(Process* p) {
    auto _0lpPathName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1lpSecurityAttributes = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::CreateDirectoryW(_0lpPathName, _1lpSecurityAttributes);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void MultiByteToWideChar_trampoline(Process* p) {
    auto _0CodePage = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1dwFlags = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2lpMultiByteStr = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3cbMultiByte = (int)process_reg_read_u32(p, Register::r3);
    auto _4lpWideCharStr = (wchar_t*)process_mem_target_to_host(p, process_stack_read(p, 0));
    auto _5cchWideChar = (int)process_stack_read(p, 1);

    const auto r = coredll::MultiByteToWideChar(_0CodePage, _1dwFlags, _2lpMultiByteStr, _3cbMultiByte, _4lpWideCharStr, _5cchWideChar);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void WideCharToMultiByte_trampoline(Process* p) {
    auto _0CodePage = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1dwFlags = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2lpWideCharStr = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3cchWideChar = (int)process_reg_read_u32(p, Register::r3);
    auto _4lpMultiByteStr = (char*)process_mem_target_to_host(p, process_stack_read(p, 0));
    auto _5cbMultiByte = (int)process_stack_read(p, 1);
    auto _6lpDefaultChar = (const char*)process_mem_target_to_host(p, process_stack_read(p, 2));
    auto _7lpUsedDefaultChar = (bool*)process_mem_target_to_host(p, process_stack_read(p, 3));

    const auto r = coredll::WideCharToMultiByte(_0CodePage, _1dwFlags, _2lpWideCharStr, _3cchWideChar, _4lpMultiByteStr, _5cbMultiByte, _6lpDefaultChar, _7lpUsedDefaultChar);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void DeleteFileW_trampoline(Process* p) {
    auto _0lpFileName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::DeleteFileW(_0lpFileName);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void FindClose_trampoline(Process* p) {
    auto _0hFindFile = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::FindClose(_0hFindFile);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void FindNextFileW_trampoline(Process* p) {
    auto _0hFindFile = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpFindFileData = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::FindNextFileW(_0hFindFile, _1lpFindFileData);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void FindFirstFileW_trampoline(Process* p) {
    auto _0lpFileName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1lpFindFileData = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::FindFirstFileW(_0lpFileName, _1lpFindFileData);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void GetModuleFileNameW_trampoline(Process* p) {
    auto _0hModule = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpFilename = (wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2nSize = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::GetModuleFileNameW(_0hModule, _1lpFilename, _2nSize);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void InitializeCriticalSection_trampoline(Process* p) {
    auto _0lpCriticalSection = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    coredll::InitializeCriticalSection(_0lpCriticalSection);

    process_reg_write_u32(p, Register::r0, 0);
}

static void DeleteCriticalSection_trampoline(Process* p) {
    auto _0lpCriticalSection = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    coredll::DeleteCriticalSection(_0lpCriticalSection);

    process_reg_write_u32(p, Register::r0, 0);
}

static void EnterCriticalSection_trampoline(Process* p) {
    auto _0lpCriticalSection = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    coredll::EnterCriticalSection(_0lpCriticalSection);

    process_reg_write_u32(p, Register::r0, 0);
}

static void LeaveCriticalSection_trampoline(Process* p) {
    auto _0lpCriticalSection = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    coredll::LeaveCriticalSection(_0lpCriticalSection);

    process_reg_write_u32(p, Register::r0, 0);
}

static void QueryPerformanceFrequency_trampoline(Process* p) {
    auto _0lpFrequency = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::QueryPerformanceFrequency(_0lpFrequency);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void QueryPerformanceCounter_trampoline(Process* p) {
    auto _0lpPerformanceCount = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::QueryPerformanceCounter(_0lpPerformanceCount);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void RegisterWindowMessageW_trampoline(Process* p) {
    auto _0string = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::RegisterWindowMessageW(_0string);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void SendMessageW_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1msg = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2wparam = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3lparam = (uint32_t)process_reg_read_u32(p, Register::r3);

    const auto r = coredll::SendMessageW(_0hwnd, _1msg, _2wparam, _3lparam);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void DefWindowProcW_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1msg = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2wparam = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3lparam = (uint32_t)process_reg_read_u32(p, Register::r3);

    const auto r = coredll::DefWindowProcW(_0hwnd, _1msg, _2wparam, _3lparam);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void DispatchMessageW_trampoline(Process* p) {
    auto _0msg = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::DispatchMessageW(_0msg);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void TranslateMessage_trampoline(Process* p) {
    auto _0msg = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::TranslateMessage(_0msg);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void PeekMessageW_trampoline(Process* p) {
    auto _0msg = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1hwnd = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2min = (int)process_reg_read_u32(p, Register::r2);
    auto _3max = (int)process_reg_read_u32(p, Register::r3);
    auto _4mode = (int)process_stack_read(p, 0);

    const auto r = coredll::PeekMessageW(_0msg, _1hwnd, _2min, _3max, _4mode);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void PostQuitMessage_trampoline(Process* p) {
    auto _0code = (int)process_reg_read_u32(p, Register::r0);

    coredll::PostQuitMessage(_0code);

    process_reg_write_u32(p, Register::r0, 0);
}

static void ShowCursor_trampoline(Process* p) {
    auto _0show = (bool)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::ShowCursor(_0show);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void SetCursor_trampoline(Process* p) {
    auto _0cursor = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::SetCursor(_0cursor);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void EndPaint_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1paint = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::EndPaint(_0hwnd, _1paint);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void BeginPaint_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1paint = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::BeginPaint(_0hwnd, _1paint);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void GetStockObject_trampoline(Process* p) {
    auto _0 = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::GetStockObject(_0);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void LoadCursorW_trampoline(Process* p) {
    auto _0instance = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1name = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::LoadCursorW(_0instance, _1name);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void SetForegroundWindow_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::SetForegroundWindow(_0hwnd);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void BringWindowToTop_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::BringWindowToTop(_0hwnd);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void SetFocus_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::SetFocus(_0hwnd);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void UpdateWindow_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::UpdateWindow(_0hwnd);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void ShowWindow_trampoline(Process* p) {
    auto _0hwnd = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1show = (int)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::ShowWindow(_0hwnd, _1show);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void RegisterClassW_trampoline(Process* p) {
    auto _0wnd = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::RegisterClassW(_0wnd);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void CreateWindowExW_trampoline(Process* p) {
    auto _0dwExStyle = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1lpClassName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2lpWindowName = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3dwStyle = (uint32_t)process_reg_read_u32(p, Register::r3);
    auto _4X = (int)process_stack_read(p, 0);
    auto _5Y = (int)process_stack_read(p, 1);
    auto _6nWidth = (int)process_stack_read(p, 2);
    auto _7nHeight = (int)process_stack_read(p, 3);
    auto _8hWndParent = (uint32_t)process_stack_read(p, 4);
    auto _9hMenu = (uint32_t)process_stack_read(p, 5);
    auto _10hInstance = (void*)process_mem_target_to_host(p, process_stack_read(p, 6));
    auto _11lpParam = (void*)process_mem_target_to_host(p, process_stack_read(p, 7));

    const auto r = coredll::CreateWindowExW(_0dwExStyle, _1lpClassName, _2lpWindowName, _3dwStyle, _4X, _5Y, _6nWidth, _7nHeight, _8hWndParent, _9hMenu, _10hInstance, _11lpParam);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void DestroyWindow_trampoline(Process* p) {
    auto _0uint32_t = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::DestroyWindow(_0uint32_t);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutGetDevCaps_trampoline(Process* p) {
    auto _0uDeviceID = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwoc = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwoc = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveOutGetDevCaps(_0uDeviceID, _1pwoc, _2cbwoc);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutGetNumDevs_trampoline(Process* p) {
const auto r = coredll::waveOutGetNumDevs();

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutOpen_trampoline(Process* p) {
    auto _0phwo = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1uDeviceID = (int)process_reg_read_u32(p, Register::r1);
    auto _2pwfx = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3dwCallback = (uint32_t)process_reg_read_u32(p, Register::r3);
    auto _4dwCallbackInstance = (uint32_t)process_stack_read(p, 0);
    auto _5fdwOpen = (uint32_t)process_stack_read(p, 1);

    const auto r = coredll::waveOutOpen(_0phwo, _1uDeviceID, _2pwfx, _3dwCallback, _4dwCallbackInstance, _5fdwOpen);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutClose_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::waveOutClose(_0hwo);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutPrepareHeader_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwh = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwh = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveOutPrepareHeader(_0hwo, _1pwh, _2cbwh);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutUnprepareHeader_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwh = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwh = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveOutUnprepareHeader(_0hwo, _1pwh, _2cbwh);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutWrite_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwh = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwh = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveOutWrite(_0hwo, _1pwh, _2cbwh);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutReset_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::waveOutReset(_0hwo);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutGetPosition_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pmmt = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbmmt = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveOutGetPosition(_0hwo, _1pmmt, _2cbmmt);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInAddBuffer_trampoline(Process* p) {
    auto _0hwi = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwh = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwh = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveInAddBuffer(_0hwi, _1pwh, _2cbwh);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInPrepareHeader_trampoline(Process* p) {
    auto _0hwi = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwh = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwh = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveInPrepareHeader(_0hwi, _1pwh, _2cbwh);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInUnprepareHeader_trampoline(Process* p) {
    auto _0hwi = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwh = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwh = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveInUnprepareHeader(_0hwi, _1pwh, _2cbwh);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInGetDevCaps_trampoline(Process* p) {
    auto _0uDeviceID = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pwic = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2cbwic = (uint32_t)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::waveInGetDevCaps(_0uDeviceID, _1pwic, _2cbwic);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInGetNumDevs_trampoline(Process* p) {
const auto r = coredll::waveInGetNumDevs();

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInStart_trampoline(Process* p) {
    auto _0hwi = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::waveInStart(_0hwi);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInOpen_trampoline(Process* p) {
    auto _0phwi = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1uDeviceID = (uint32_t)process_reg_read_u32(p, Register::r1);
    auto _2pwfx = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3dwCallback = (uint32_t)process_reg_read_u32(p, Register::r3);
    auto _4dwCallbackInstance = (uint32_t)process_stack_read(p, 0);
    auto _5fdwOpen = (uint32_t)process_stack_read(p, 1);

    const auto r = coredll::waveInOpen(_0phwi, _1uDeviceID, _2pwfx, _3dwCallback, _4dwCallbackInstance, _5fdwOpen);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInClose_trampoline(Process* p) {
    auto _0hwi = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::waveInClose(_0hwi);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveInReset_trampoline(Process* p) {
    auto _0hwi = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::waveInReset(_0hwi);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutGetVolume_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1pdwVolume = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::waveOutGetVolume(_0hwo, _1pdwVolume);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void waveOutSetVolume_trampoline(Process* p) {
    auto _0hwo = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1dwVolume = (uint32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::waveOutSetVolume(_0hwo, _1dwVolume);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void strlen_trampoline(Process* p) {
    auto _0s = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::strlen(_0s);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void strcpy_trampoline(Process* p) {
    auto _0dst = (char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1src = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::strcpy(_0dst, _1src);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void strcmp_trampoline(Process* p) {
    auto _0s1 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1s2 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::strcmp(_0s1, _1s2);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void strstr_trampoline(Process* p) {
    auto _0s1 = (char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1s2 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::strstr(_0s1, _1s2);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void strncmp_trampoline(Process* p) {
    auto _0s1 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1s2 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2n = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::strncmp(_0s1, _1s2, _2n);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void strchr_trampoline(Process* p) {
    auto _0s = (char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1n = (int)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::strchr(_0s, _1n);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void strrchr_trampoline(Process* p) {
    auto _0s = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1c = (int)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::strrchr(_0s, _1c);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void wcsrchr_trampoline(Process* p) {
    auto _0s = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1c = (wchar_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::wcsrchr(_0s, _1c);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void __itos_trampoline(Process* p) {
    auto _0v = (int)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::__itos(_0v);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void __stoi_trampoline(Process* p) {
    auto _0 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::__stoi(_0);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void atoi_trampoline(Process* p) {
    auto _0s = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::atoi(_0s);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void atof_trampoline(Process* p) {
    auto _0s = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    const auto r = coredll::atof(_0s);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void strtoul_trampoline(Process* p) {
    auto _0s1 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1s2 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2n = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::strtoul(_0s1, _1s2, _2n);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void toupper_trampoline(Process* p) {
    auto _0c = (int)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::toupper(_0c);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __C_specific_uint32_tr_trampoline(Process* p) {
    auto _0v = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::__C_specific_uint32_tr(_0v);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void _XcptFilter_trampoline(Process* p) {
    auto _0 = (int)process_reg_read_u32(p, Register::r0);
    auto _1 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::_XcptFilter(_0, _1);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __C_specific_handler_trampoline(Process* p) {
    auto _0 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = (uint64_t)process_reg_read_u32(p, Register::r1);
    auto _2 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));

    coredll::__C_specific_handler(_0, _1, _2, _3);

    process_reg_write_u32(p, Register::r0, 0);
}

static void __lts_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__lts(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __gts_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__gts(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __stou_trampoline(Process* p) {
    auto _0v = (int32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::__stou(_0v);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __rt_sdiv_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__rt_sdiv(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __rt_udiv_trampoline(Process* p) {
    auto _0a = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (uint32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__rt_udiv(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __divs_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__divs(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __rt_sdiv64by64_trampoline(Process* p) {
    auto _0a = (int64_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int64_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__rt_sdiv64by64(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __rt_udiv64by64_trampoline(Process* p) {
    auto _0a = (uint64_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (uint64_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__rt_udiv64by64(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __rt_urem64by64_trampoline(Process* p) {
    auto _0a = (uint64_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (uint64_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__rt_urem64by64(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __adds_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__adds(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __subs_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__subs(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __negs_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::__negs(_0a);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __muls_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__muls(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __utos_trampoline(Process* p) {
    auto _0v = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::__utos(_0v);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __utod_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::__utod(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void __stod_trampoline(Process* p) {
    auto _0v = (int32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::__stod(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void __muld_trampoline(Process* p) {
    auto _0a = (int32_t)process_reg_read_u32(p, Register::r0);
    auto _1b = (int32_t)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::__muld(_0a, _1b);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __dtoi_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::__dtoi(_0v);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void __dtos_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::__dtos(_0v);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void ldexp_trampoline(Process* p) {
    auto _0x = (float)process_reg_read_f32(p, Register::s0);
    auto _1exp = (int)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::ldexp(_0x, _1exp);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void atan2_trampoline(Process* p) {
    auto _0y = (float)process_reg_read_f32(p, Register::s0);
    auto _1x = (float)process_reg_read_f32(p, Register::s1);

    const auto r = coredll::atan2(_0y, _1x);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void pow_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);
    auto _1a = (float)process_reg_read_f32(p, Register::s1);

    const auto r = coredll::pow(_0v, _1a);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void atan_trampoline(Process* p) {
    auto _0x = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::atan(_0x);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void acos_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::acos(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void sqrt_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::sqrt(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void asin_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::asin(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void cos_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::cos(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void sin_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::sin(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void tan_trampoline(Process* p) {
    auto _0v = (float)process_reg_read_f32(p, Register::s0);

    const auto r = coredll::tan(_0v);

    process_reg_write_f32(p, Register::s0, (float)r);
}

static void vsprintf_trampoline(Process* p) {
    auto _0 = (char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2 = 0;

    const auto r = coredll::vsprintf(_0, _1, _2);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void sprintf_trampoline(Process* p) {
    auto _0 = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = 0;

    const auto r = coredll::sprintf(_0, _1);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void _snwprintf_trampoline(Process* p) {
    auto _0buf = (wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = (int)process_reg_read_u32(p, Register::r1);
    auto _2 = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r2));
    auto _3 = 0;

    const auto r = coredll::_snwprintf(_0buf, _1, _2, _3);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void mbstowcs_trampoline(Process* p) {
    auto _0dst = (wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1src = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2len = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::mbstowcs(_0dst, _1src, _2len);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void memcpy_trampoline(Process* p) {
    auto _0dst = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1src = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2len = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::memcpy(_0dst, _1src, _2len);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void memset_trampoline(Process* p) {
    auto _0ptr = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1value = (int)process_reg_read_u32(p, Register::r1);
    auto _2num = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::memset(_0ptr, _1value, _2num);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void fclose_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::fclose(_0handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void ftell_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::ftell(_0handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void feof_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::feof(_0handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void fseek_trampoline(Process* p) {
    auto _0handle = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1seek = (int)process_reg_read_u32(p, Register::r1);
    auto _2offset = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::fseek(_0handle, _1seek, _2offset);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void _wfopen_trampoline(Process* p) {
    auto _0path = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1mode = (const wchar_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::_wfopen(_0path, _1mode);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void fopen_trampoline(Process* p) {
    auto _0path = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1mode = (const char*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    const auto r = coredll::fopen(_0path, _1mode);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void fread_trampoline(Process* p) {
    auto _0dst = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1size = (int)process_reg_read_u32(p, Register::r1);
    auto _2count = (int)process_reg_read_u32(p, Register::r2);
    auto _3handle = (uint32_t)process_reg_read_u32(p, Register::r3);

    const auto r = coredll::fread(_0dst, _1size, _2count, _3handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void fwrite_trampoline(Process* p) {
    auto _0src = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1size = (int)process_reg_read_u32(p, Register::r1);
    auto _2count = (int)process_reg_read_u32(p, Register::r2);
    auto _3handle = (uint32_t)process_reg_read_u32(p, Register::r3);

    const auto r = coredll::fwrite(_0src, _1size, _2count, _3handle);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void rand_trampoline(Process* p) {
const auto r = coredll::rand();

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void malloc_trampoline(Process* p) {
    auto _0size = (int)process_reg_read_u32(p, Register::r0);

    const auto r = coredll::malloc(_0size);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void realloc_trampoline(Process* p) {
    auto _0 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1size = (int)process_reg_read_u32(p, Register::r1);

    const auto r = coredll::realloc(_0, _1size);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void free_trampoline(Process* p) {
    auto _0 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    coredll::free(_0);

    process_reg_write_u32(p, Register::r0, 0);
}

static void memmove_trampoline(Process* p) {
    auto _0 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2 = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::memmove(_0, _1, _2);

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void memcmp_trampoline(Process* p) {
    auto _0 = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));
    auto _2 = (int)process_reg_read_u32(p, Register::r2);

    const auto r = coredll::memcmp(_0, _1, _2);

    process_reg_write_u32(p, Register::r0, (uint32_t)r);
}

static void qsort_trampoline(Process* p) {
    auto _0 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));
    auto _1 = (int)process_reg_read_u32(p, Register::r1);
    auto _2 = (int)process_reg_read_u32(p, Register::r2);
    auto _3 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));

    coredll::qsort(_0, _1, _2, _3);

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglSwapIntervalNV_trampoline(Process* p) {
libGLES_CM::eglSwapIntervalNV();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glEnableClientState_trampoline(Process* p) {
    auto _0arr = (GLenum)process_reg_read_u32(p, Register::r0);

    libGLES_CM::glEnableClientState(_0arr);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDisableClientState_trampoline(Process* p) {
    auto _0arr = (GLenum)process_reg_read_u32(p, Register::r0);

    libGLES_CM::glDisableClientState(_0arr);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glVertexPointer_trampoline(Process* p) {
    auto _0size = (uint32_t)process_reg_read_u32(p, Register::r0);
    auto _1type = (GLenum)process_reg_read_u32(p, Register::r1);
    auto _2stride = (uint32_t)process_reg_read_u32(p, Register::r2);
    auto _3pointer = (const void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r3));

    libGLES_CM::glVertexPointer(_0size, _1type, _2stride, _3pointer);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glColorPointer_trampoline(Process* p) {
libGLES_CM::glColorPointer();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glClientActiveTexture_trampoline(Process* p) {
libGLES_CM::glClientActiveTexture();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glTexCoordPointer_trampoline(Process* p) {
libGLES_CM::glTexCoordPointer();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDrawElements_trampoline(Process* p) {
libGLES_CM::glDrawElements();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glTexEnvf_trampoline(Process* p) {
libGLES_CM::glTexEnvf();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDepthRangef_trampoline(Process* p) {
libGLES_CM::glDepthRangef();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDepthMask_trampoline(Process* p) {
libGLES_CM::glDepthMask();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDepthFunc_trampoline(Process* p) {
libGLES_CM::glDepthFunc();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glCullFace_trampoline(Process* p) {
libGLES_CM::glCullFace();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glEnable_trampoline(Process* p) {
    auto _0feat = (GLenum)process_reg_read_u32(p, Register::r0);

    libGLES_CM::glEnable(_0feat);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDisable_trampoline(Process* p) {
    auto _0feat = (GLenum)process_reg_read_u32(p, Register::r0);

    libGLES_CM::glDisable(_0feat);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glGetIntegerv_trampoline(Process* p) {
libGLES_CM::glGetIntegerv();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glGetString_trampoline(Process* p) {
const auto r = libGLES_CM::glGetString();

    process_reg_write_u32(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void eglMakeCurrent_trampoline(Process* p) {
    auto _0 = (void*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r0));

    libGLES_CM::eglMakeCurrent(_0);

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglCreateWindowSurface_trampoline(Process* p) {
libGLES_CM::eglCreateWindowSurface();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglCreateContext_trampoline(Process* p) {
libGLES_CM::eglCreateContext();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglChooseConfig_trampoline(Process* p) {
libGLES_CM::eglChooseConfig();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglGetConfigs_trampoline(Process* p) {
libGLES_CM::eglGetConfigs();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglInitialize_trampoline(Process* p) {
libGLES_CM::eglInitialize();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglGetDisplay_trampoline(Process* p) {
libGLES_CM::eglGetDisplay();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglTerminate_trampoline(Process* p) {
libGLES_CM::eglTerminate();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglDestroySurface_trampoline(Process* p) {
libGLES_CM::eglDestroySurface();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglDestroyContext_trampoline(Process* p) {
libGLES_CM::eglDestroyContext();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glClear_trampoline(Process* p) {
libGLES_CM::glClear();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glClearColorx_trampoline(Process* p) {
libGLES_CM::glClearColorx();

    process_reg_write_u32(p, Register::r0, 0);
}

static void eglSwapBuffers_trampoline(Process* p) {
libGLES_CM::eglSwapBuffers();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glFinish_trampoline(Process* p) {
libGLES_CM::glFinish();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glLoadMatrixx_trampoline(Process* p) {
libGLES_CM::glLoadMatrixx();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glMatrixMode_trampoline(Process* p) {
    auto _0mode = (GLenum)process_reg_read_u32(p, Register::r0);

    libGLES_CM::glMatrixMode(_0mode);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glViewport_trampoline(Process* p) {
    auto _0x = (float)process_reg_read_f32(p, Register::s0);
    auto _1y = (float)process_reg_read_f32(p, Register::s1);
    auto _2w = (float)process_reg_read_f32(p, Register::s2);
    auto _3h = (float)process_reg_read_f32(p, Register::s3);

    libGLES_CM::glViewport(_0x, _1y, _2w, _3h);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glScissor_trampoline(Process* p) {
libGLES_CM::glScissor();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glGenTextures_trampoline(Process* p) {
    auto _0count = (int)process_reg_read_u32(p, Register::r0);
    auto _1uint32_ts = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    libGLES_CM::glGenTextures(_0count, _1uint32_ts);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDeleteTextures_trampoline(Process* p) {
    auto _0count = (int)process_reg_read_u32(p, Register::r0);
    auto _1uint32_ts = (uint32_t*)process_mem_target_to_host(p, process_reg_read_u32(p, Register::r1));

    libGLES_CM::glDeleteTextures(_0count, _1uint32_ts);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glTexImage2D_trampoline(Process* p) {
    auto _0target = (GLenum)process_reg_read_u32(p, Register::r0);
    auto _1level = (int)process_reg_read_u32(p, Register::r1);
    auto _2internalformat = (int)process_reg_read_u32(p, Register::r2);
    auto _3width = (int)process_reg_read_u32(p, Register::r3);
    auto _4height = (int)process_stack_read(p, 0);
    auto _5border = (int)process_stack_read(p, 1);
    auto _6format = (int)process_stack_read(p, 2);
    auto _7type = (GLenum)process_stack_read(p, 3);
    auto _8pixels = (const void*)process_mem_target_to_host(p, process_stack_read(p, 4));

    libGLES_CM::glTexImage2D(_0target, _1level, _2internalformat, _3width, _4height, _5border, _6format, _7type, _8pixels);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glTexParameterf_trampoline(Process* p) {
libGLES_CM::glTexParameterf();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glBindTexture_trampoline(Process* p) {
    auto _0mode = (GLenum)process_reg_read_u32(p, Register::r0);
    auto _1uint32_t = (uint32_t)process_reg_read_u32(p, Register::r1);

    libGLES_CM::glBindTexture(_0mode, _1uint32_t);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glCompressedTexImage2D_trampoline(Process* p) {
libGLES_CM::glCompressedTexImage2D();

    process_reg_write_u32(p, Register::r0, 0);
}

static void glActiveTexture_trampoline(Process* p) {
    auto _0mode = (GLenum)process_reg_read_u32(p, Register::r0);

    libGLES_CM::glActiveTexture(_0mode);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glAlphaFunc_trampoline(Process* p) {
    auto _0func = (GLenum)process_reg_read_u32(p, Register::r0);
    auto _1ref = (float)process_reg_read_f32(p, Register::s0);

    libGLES_CM::glAlphaFunc(_0func, _1ref);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glBlendFunc_trampoline(Process* p) {
    auto _0sfactor = (GLenum)process_reg_read_u32(p, Register::r0);
    auto _1dfactor = (GLenum)process_reg_read_u32(p, Register::r1);

    libGLES_CM::glBlendFunc(_0sfactor, _1dfactor);

    process_reg_write_u32(p, Register::r0, 0);
}

static void glDrawArrays_trampoline(Process* p) {
    auto _0mode = (GLenum)process_reg_read_u32(p, Register::r0);
    auto _1index = (int)process_reg_read_u32(p, Register::r1);
    auto _2count = (int)process_reg_read_u32(p, Register::r2);

    libGLES_CM::glDrawArrays(_0mode, _1index, _2count);

    process_reg_write_u32(p, Register::r0, 0);
}

struct { const char* name; void* ptr; } static const sym_table[] = {
    { "DeviceIoControl", (void*)DeviceIoControl_trampoline },
    { "CreateEventW", (void*)CreateEventW_trampoline },
    { "CreateMutexW", (void*)CreateMutexW_trampoline },
    { "Sleep", (void*)Sleep_trampoline },
    { "WaitForSingleObject", (void*)WaitForSingleObject_trampoline },
    { "GetLastError", (void*)GetLastError_trampoline },
    { "CreateFileW", (void*)CreateFileW_trampoline },
    { "CloseHandle", (void*)CloseHandle_trampoline },
    { "SetFilePointer", (void*)SetFilePointer_trampoline },
    { "ReadFile", (void*)ReadFile_trampoline },
    { "OpenEventW", (void*)OpenEventW_trampoline },
    { "EventModify", (void*)EventModify_trampoline },
    { "RegSetValueExW", (void*)RegSetValueExW_trampoline },
    { "RegOpenKeyExW", (void*)RegOpenKeyExW_trampoline },
    { "RegQueryValueExW", (void*)RegQueryValueExW_trampoline },
    { "SetSystemMemoryDivision", (void*)SetSystemMemoryDivision_trampoline },
    { "WaitForMultipleObjects", (void*)WaitForMultipleObjects_trampoline },
    { "FindCloseChangeNotification", (void*)FindCloseChangeNotification_trampoline },
    { "FindNextChangeNotification", (void*)FindNextChangeNotification_trampoline },
    { "FindFirstChangeNotificationW", (void*)FindFirstChangeNotificationW_trampoline },
    { "GetFileAttributesW", (void*)GetFileAttributesW_trampoline },
    { "LocalReAlloc", (void*)LocalReAlloc_trampoline },
    { "LocalAlloc", (void*)LocalAlloc_trampoline },
    { "LocalFree", (void*)LocalFree_trampoline },
    { "SetThreadPriority", (void*)SetThreadPriority_trampoline },
    { "TerminateThread", (void*)TerminateThread_trampoline },
    { "SuspendThread", (void*)SuspendThread_trampoline },
    { "ResumeThread", (void*)ResumeThread_trampoline },
    { "CreateThread", (void*)CreateThread_trampoline },
    { "GetLocalTime", (void*)GetLocalTime_trampoline },
    { "CreateDirectoryW", (void*)CreateDirectoryW_trampoline },
    { "MultiByteToWideChar", (void*)MultiByteToWideChar_trampoline },
    { "WideCharToMultiByte", (void*)WideCharToMultiByte_trampoline },
    { "DeleteFileW", (void*)DeleteFileW_trampoline },
    { "FindClose", (void*)FindClose_trampoline },
    { "FindNextFileW", (void*)FindNextFileW_trampoline },
    { "FindFirstFileW", (void*)FindFirstFileW_trampoline },
    { "GetModuleFileNameW", (void*)GetModuleFileNameW_trampoline },
    { "InitializeCriticalSection", (void*)InitializeCriticalSection_trampoline },
    { "DeleteCriticalSection", (void*)DeleteCriticalSection_trampoline },
    { "EnterCriticalSection", (void*)EnterCriticalSection_trampoline },
    { "LeaveCriticalSection", (void*)LeaveCriticalSection_trampoline },
    { "QueryPerformanceFrequency", (void*)QueryPerformanceFrequency_trampoline },
    { "QueryPerformanceCounter", (void*)QueryPerformanceCounter_trampoline },
    { "RegisterWindowMessageW", (void*)RegisterWindowMessageW_trampoline },
    { "SendMessageW", (void*)SendMessageW_trampoline },
    { "DefWindowProcW", (void*)DefWindowProcW_trampoline },
    { "DispatchMessageW", (void*)DispatchMessageW_trampoline },
    { "TranslateMessage", (void*)TranslateMessage_trampoline },
    { "PeekMessageW", (void*)PeekMessageW_trampoline },
    { "PostQuitMessage", (void*)PostQuitMessage_trampoline },
    { "ShowCursor", (void*)ShowCursor_trampoline },
    { "SetCursor", (void*)SetCursor_trampoline },
    { "EndPaint", (void*)EndPaint_trampoline },
    { "BeginPaint", (void*)BeginPaint_trampoline },
    { "GetStockObject", (void*)GetStockObject_trampoline },
    { "LoadCursorW", (void*)LoadCursorW_trampoline },
    { "SetForegroundWindow", (void*)SetForegroundWindow_trampoline },
    { "BringWindowToTop", (void*)BringWindowToTop_trampoline },
    { "SetFocus", (void*)SetFocus_trampoline },
    { "UpdateWindow", (void*)UpdateWindow_trampoline },
    { "ShowWindow", (void*)ShowWindow_trampoline },
    { "RegisterClassW", (void*)RegisterClassW_trampoline },
    { "CreateWindowExW", (void*)CreateWindowExW_trampoline },
    { "DestroyWindow", (void*)DestroyWindow_trampoline },
    { "waveOutGetDevCaps", (void*)waveOutGetDevCaps_trampoline },
    { "waveOutGetNumDevs", (void*)waveOutGetNumDevs_trampoline },
    { "waveOutOpen", (void*)waveOutOpen_trampoline },
    { "waveOutClose", (void*)waveOutClose_trampoline },
    { "waveOutPrepareHeader", (void*)waveOutPrepareHeader_trampoline },
    { "waveOutUnprepareHeader", (void*)waveOutUnprepareHeader_trampoline },
    { "waveOutWrite", (void*)waveOutWrite_trampoline },
    { "waveOutReset", (void*)waveOutReset_trampoline },
    { "waveOutGetPosition", (void*)waveOutGetPosition_trampoline },
    { "waveInAddBuffer", (void*)waveInAddBuffer_trampoline },
    { "waveInPrepareHeader", (void*)waveInPrepareHeader_trampoline },
    { "waveInUnprepareHeader", (void*)waveInUnprepareHeader_trampoline },
    { "waveInGetDevCaps", (void*)waveInGetDevCaps_trampoline },
    { "waveInGetNumDevs", (void*)waveInGetNumDevs_trampoline },
    { "waveInStart", (void*)waveInStart_trampoline },
    { "waveInOpen", (void*)waveInOpen_trampoline },
    { "waveInClose", (void*)waveInClose_trampoline },
    { "waveInReset", (void*)waveInReset_trampoline },
    { "waveOutGetVolume", (void*)waveOutGetVolume_trampoline },
    { "waveOutSetVolume", (void*)waveOutSetVolume_trampoline },
    { "strlen", (void*)strlen_trampoline },
    { "strcpy", (void*)strcpy_trampoline },
    { "strcmp", (void*)strcmp_trampoline },
    { "strstr", (void*)strstr_trampoline },
    { "strncmp", (void*)strncmp_trampoline },
    { "strchr", (void*)strchr_trampoline },
    { "strrchr", (void*)strrchr_trampoline },
    { "wcsrchr", (void*)wcsrchr_trampoline },
    { "__itos", (void*)__itos_trampoline },
    { "__stoi", (void*)__stoi_trampoline },
    { "atoi", (void*)atoi_trampoline },
    { "atof", (void*)atof_trampoline },
    { "strtoul", (void*)strtoul_trampoline },
    { "toupper", (void*)toupper_trampoline },
    { "__C_specific_uint32_tr", (void*)__C_specific_uint32_tr_trampoline },
    { "_XcptFilter", (void*)_XcptFilter_trampoline },
    { "__C_specific_handler", (void*)__C_specific_handler_trampoline },
    { "__lts", (void*)__lts_trampoline },
    { "__gts", (void*)__gts_trampoline },
    { "__stou", (void*)__stou_trampoline },
    { "__rt_sdiv", (void*)__rt_sdiv_trampoline },
    { "__rt_udiv", (void*)__rt_udiv_trampoline },
    { "__divs", (void*)__divs_trampoline },
    { "__rt_sdiv64by64", (void*)__rt_sdiv64by64_trampoline },
    { "__rt_udiv64by64", (void*)__rt_udiv64by64_trampoline },
    { "__rt_urem64by64", (void*)__rt_urem64by64_trampoline },
    { "__adds", (void*)__adds_trampoline },
    { "__subs", (void*)__subs_trampoline },
    { "__negs", (void*)__negs_trampoline },
    { "__muls", (void*)__muls_trampoline },
    { "__utos", (void*)__utos_trampoline },
    { "__utod", (void*)__utod_trampoline },
    { "__stod", (void*)__stod_trampoline },
    { "__muld", (void*)__muld_trampoline },
    { "__dtoi", (void*)__dtoi_trampoline },
    { "__dtos", (void*)__dtos_trampoline },
    { "ldexp", (void*)ldexp_trampoline },
    { "atan2", (void*)atan2_trampoline },
    { "pow", (void*)pow_trampoline },
    { "atan", (void*)atan_trampoline },
    { "acos", (void*)acos_trampoline },
    { "sqrt", (void*)sqrt_trampoline },
    { "asin", (void*)asin_trampoline },
    { "cos", (void*)cos_trampoline },
    { "sin", (void*)sin_trampoline },
    { "tan", (void*)tan_trampoline },
    { "vsprintf", (void*)vsprintf_trampoline },
    { "sprintf", (void*)sprintf_trampoline },
    { "_snwprintf", (void*)_snwprintf_trampoline },
    { "mbstowcs", (void*)mbstowcs_trampoline },
    { "memcpy", (void*)memcpy_trampoline },
    { "memset", (void*)memset_trampoline },
    { "fclose", (void*)fclose_trampoline },
    { "ftell", (void*)ftell_trampoline },
    { "feof", (void*)feof_trampoline },
    { "fseek", (void*)fseek_trampoline },
    { "_wfopen", (void*)_wfopen_trampoline },
    { "fopen", (void*)fopen_trampoline },
    { "fread", (void*)fread_trampoline },
    { "fwrite", (void*)fwrite_trampoline },
    { "rand", (void*)rand_trampoline },
    { "malloc", (void*)malloc_trampoline },
    { "realloc", (void*)realloc_trampoline },
    { "free", (void*)free_trampoline },
    { "memmove", (void*)memmove_trampoline },
    { "memcmp", (void*)memcmp_trampoline },
    { "qsort", (void*)qsort_trampoline },
    { "eglSwapIntervalNV", (void*)eglSwapIntervalNV_trampoline },
    { "glEnableClientState", (void*)glEnableClientState_trampoline },
    { "glDisableClientState", (void*)glDisableClientState_trampoline },
    { "glVertexPointer", (void*)glVertexPointer_trampoline },
    { "glColorPointer", (void*)glColorPointer_trampoline },
    { "glClientActiveTexture", (void*)glClientActiveTexture_trampoline },
    { "glTexCoordPointer", (void*)glTexCoordPointer_trampoline },
    { "glDrawElements", (void*)glDrawElements_trampoline },
    { "glTexEnvf", (void*)glTexEnvf_trampoline },
    { "glDepthRangef", (void*)glDepthRangef_trampoline },
    { "glDepthMask", (void*)glDepthMask_trampoline },
    { "glDepthFunc", (void*)glDepthFunc_trampoline },
    { "glCullFace", (void*)glCullFace_trampoline },
    { "glEnable", (void*)glEnable_trampoline },
    { "glDisable", (void*)glDisable_trampoline },
    { "glGetIntegerv", (void*)glGetIntegerv_trampoline },
    { "glGetString", (void*)glGetString_trampoline },
    { "eglMakeCurrent", (void*)eglMakeCurrent_trampoline },
    { "eglCreateWindowSurface", (void*)eglCreateWindowSurface_trampoline },
    { "eglCreateContext", (void*)eglCreateContext_trampoline },
    { "eglChooseConfig", (void*)eglChooseConfig_trampoline },
    { "eglGetConfigs", (void*)eglGetConfigs_trampoline },
    { "eglInitialize", (void*)eglInitialize_trampoline },
    { "eglGetDisplay", (void*)eglGetDisplay_trampoline },
    { "eglTerminate", (void*)eglTerminate_trampoline },
    { "eglDestroySurface", (void*)eglDestroySurface_trampoline },
    { "eglDestroyContext", (void*)eglDestroyContext_trampoline },
    { "glClear", (void*)glClear_trampoline },
    { "glClearColorx", (void*)glClearColorx_trampoline },
    { "eglSwapBuffers", (void*)eglSwapBuffers_trampoline },
    { "glFinish", (void*)glFinish_trampoline },
    { "glLoadMatrixx", (void*)glLoadMatrixx_trampoline },
    { "glMatrixMode", (void*)glMatrixMode_trampoline },
    { "glViewport", (void*)glViewport_trampoline },
    { "glScissor", (void*)glScissor_trampoline },
    { "glGenTextures", (void*)glGenTextures_trampoline },
    { "glDeleteTextures", (void*)glDeleteTextures_trampoline },
    { "glTexImage2D", (void*)glTexImage2D_trampoline },
    { "glTexParameterf", (void*)glTexParameterf_trampoline },
    { "glBindTexture", (void*)glBindTexture_trampoline },
    { "glCompressedTexImage2D", (void*)glCompressedTexImage2D_trampoline },
    { "glActiveTexture", (void*)glActiveTexture_trampoline },
    { "glAlphaFunc", (void*)glAlphaFunc_trampoline },
    { "glBlendFunc", (void*)glBlendFunc_trampoline },
    { "glDrawArrays", (void*)glDrawArrays_trampoline },
};

#include <string_view>
void* symbol_find(const char* name) {
    for (auto sym : sym_table) {
        if (std::string_view{ name } == sym.name) return sym.ptr;
    }
    return nullptr;
}

