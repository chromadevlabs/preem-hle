#include "process.h"
static void DeviceIoControl_trampoline(Process* p) {
    const auto r = coredll::DeviceIoControl(
        /*device*/ (uint32_t)process_reg_read(p, Register::r0),
        /*code*/ (uint32_t)process_reg_read(p, Register::r1),
        /*inBuf*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*inBufSize*/ (uint32_t)process_stack_read(p, -0),
        /*outBuf*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -1)),
        /*outBufSize*/ (uint32_t)process_stack_read(p, -2),
        /*bytesRet*/ (uint32_t)process_stack_read(p, -3),
        /*lpOverlapped*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -4))
    );

    process_reg_write(p, Register::r0, r);
}

static void CreateEventW_trampoline(Process* p) {
    const auto r = coredll::CreateEventW(
        /*attributes*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*reset*/ (bool)process_reg_read(p, Register::r1),
        /*state*/ (bool)process_reg_read(p, Register::r2),
        /*name*/ (const wchar_t*)process_mem_target_to_host(p, process_stack_read(p, -0))
    );

    process_reg_write(p, Register::r0, r);
}

static void CreateMutexW_trampoline(Process* p) {
    const auto r = coredll::CreateMutexW(
        /*attributes*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*initialOwner*/ (bool)process_reg_read(p, Register::r1),
        /*name*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2))
    );

    process_reg_write(p, Register::r0, r);
}

static void Sleep_trampoline(Process* p) {
    coredll::Sleep(
        /*time*/ (uint32_t)process_reg_read(p, Register::r0)
    );

}

static void WaitForSingleObject_trampoline(Process* p) {
    const auto r = coredll::WaitForSingleObject(
        /*handle*/ (uint32_t)process_reg_read(p, Register::r0),
        (uint32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void GetLastError_trampoline(Process* p) {
    const auto r = coredll::GetLastError();

    process_reg_write(p, Register::r0, r);
}

static void CreateFileW_trampoline(Process* p) {
    const auto r = coredll::CreateFileW(
        /*path*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*access*/ (uint32_t)process_reg_read(p, Register::r1),
        /*share*/ (uint32_t)process_reg_read(p, Register::r2),
        /*attr*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -0)),
        /*create*/ (uint32_t)process_stack_read(p, -1),
        /*flags*/ (uint32_t)process_stack_read(p, -2),
        /*temp*/ (uint32_t)process_stack_read(p, -3)
    );

    process_reg_write(p, Register::r0, r);
}

static void CloseHandle_trampoline(Process* p) {
    coredll::CloseHandle(
        /*handle*/ (uint32_t)process_reg_read(p, Register::r0)
    );

}

static void SetFilePointer_trampoline(Process* p) {
    const auto r = coredll::SetFilePointer(
        /*hfile*/ (uint32_t)process_reg_read(p, Register::r0),
        /*distance*/ (uint32_t)process_reg_read(p, Register::r1),
        /*highDist*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*method*/ (uint32_t)process_stack_read(p, -0)
    );

    process_reg_write(p, Register::r0, r);
}

static void ReadFile_trampoline(Process* p) {
    const auto r = coredll::ReadFile(
        /*hfile*/ (uint32_t)process_reg_read(p, Register::r0),
        /*buffer*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*size*/ (uint32_t)process_reg_read(p, Register::r2),
        /*outSize*/ (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, -0)),
        /*overlapped*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -1))
    );

    process_reg_write(p, Register::r0, r);
}

static void OpenEventW_trampoline(Process* p) {
    const auto r = coredll::OpenEventW(
        /*dwDesiredAccess*/ (uint32_t)process_reg_read(p, Register::r0),
        /*bInherituint32_t*/ (bool)process_reg_read(p, Register::r1),
        /*lpName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2))
    );

    process_reg_write(p, Register::r0, r);
}

static void EventModify_trampoline(Process* p) {
    const auto r = coredll::EventModify(
        /*hEvent*/ (uint32_t)process_reg_read(p, Register::r0),
        /*dwFunc*/ (uint32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void RegSetValueExW_trampoline(Process* p) {
    const auto r = coredll::RegSetValueExW(
        /*uint32*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpValueName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*Reserved*/ (uint32_t)process_reg_read(p, Register::r2),
        /*dwType*/ (uint32_t)process_stack_read(p, -0),
        /*lpData*/ (const uint8_t*)process_mem_target_to_host(p, process_stack_read(p, -1)),
        /*cbData*/ (uint32_t)process_stack_read(p, -2)
    );

    process_reg_write(p, Register::r0, r);
}

static void RegOpenKeyExW_trampoline(Process* p) {
    const auto r = coredll::RegOpenKeyExW(
        /*uint32*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpSubKey*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*ulOptions*/ (uint32_t)process_reg_read(p, Register::r2),
        /*samDesired*/ (int)process_stack_read(p, -0),
        /*phkResult*/ (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, -1))
    );

    process_reg_write(p, Register::r0, r);
}

static void RegQueryValueExW_trampoline(Process* p) {
    const auto r = coredll::RegQueryValueExW(
        /*uint32*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpValueName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*lpReserved*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*lpType*/ (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, -0)),
        /*lpData*/ (uint8_t*)process_mem_target_to_host(p, process_stack_read(p, -1)),
        /*lpcbData*/ (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, -2))
    );

    process_reg_write(p, Register::r0, r);
}

static void SetSystemMemoryDivision_trampoline(Process* p) {
    const auto r = coredll::SetSystemMemoryDivision(
        /*dwNumberOfPages*/ (uint32_t)process_reg_read(p, Register::r0),
        /*dwNumberOfPagesReserved*/ (uint32_t)process_reg_read(p, Register::r1),
        /*dwNumberOfPagesShared*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void WaitForMultipleObjects_trampoline(Process* p) {
    const auto r = coredll::WaitForMultipleObjects(
        /*nCount*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpuint32_ts*/ (const uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*bWaitAll*/ (bool)process_reg_read(p, Register::r2),
        /*dwMilliseconds*/ (uint32_t)process_stack_read(p, -0)
    );

    process_reg_write(p, Register::r0, r);
}

static void FindCloseChangeNotification_trampoline(Process* p) {
    const auto r = coredll::FindCloseChangeNotification(
        /*hChangeuint32_t*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void FindNextChangeNotification_trampoline(Process* p) {
    const auto r = coredll::FindNextChangeNotification(
        /*hChangeuint32_t*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void FindFirstChangeNotificationW_trampoline(Process* p) {
    const auto r = coredll::FindFirstChangeNotificationW(
        /*lpPathName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*bWatchSubtree*/ (bool)process_reg_read(p, Register::r1),
        /*dwNotifyFilter*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void GetFileAttributesW_trampoline(Process* p) {
    const auto r = coredll::GetFileAttributesW(
        /*lpFileName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void LocalReAlloc_trampoline(Process* p) {
    const auto r = coredll::LocalReAlloc(
        /*hMem*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*uBytes*/ (uint32_t)process_reg_read(p, Register::r1),
        /*uFlags*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void LocalAlloc_trampoline(Process* p) {
    const auto r = coredll::LocalAlloc(
        /*uFlags*/ (uint32_t)process_reg_read(p, Register::r0),
        /*uBytes*/ (uint32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void LocalFree_trampoline(Process* p) {
    const auto r = coredll::LocalFree(
        /*hMem*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void SetThreadPriority_trampoline(Process* p) {
    const auto r = coredll::SetThreadPriority(
        /*handle*/ (uint32_t)process_reg_read(p, Register::r0),
        /*priority*/ (int)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void TerminateThread_trampoline(Process* p) {
    const auto r = coredll::TerminateThread(
        /*handle*/ (uint32_t)process_reg_read(p, Register::r0),
        /*code*/ (uint32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void SuspendThread_trampoline(Process* p) {
    const auto r = coredll::SuspendThread(
        /*handle*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void ResumeThread_trampoline(Process* p) {
    const auto r = coredll::ResumeThread(
        /*handle*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void CreateThread_trampoline(Process* p) {
    const auto r = coredll::CreateThread(
        /*attr*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*stacksize*/ (uint32_t)process_reg_read(p, Register::r1),
        /*callback*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*user*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -0)),
        /*flags*/ (uint32_t)process_stack_read(p, -1),
        /*threadid*/ (uint32_t*)process_mem_target_to_host(p, process_stack_read(p, -2))
    );

    process_reg_write(p, Register::r0, r);
}

static void GetLocalTime_trampoline(Process* p) {
    coredll::GetLocalTime(
        /*lpSystemTime*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void CreateDirectoryW_trampoline(Process* p) {
    const auto r = coredll::CreateDirectoryW(
        /*lpPathName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*lpSecurityAttributes*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void MultiByteToWideChar_trampoline(Process* p) {
    const auto r = coredll::MultiByteToWideChar(
        /*CodePage*/ (uint32_t)process_reg_read(p, Register::r0),
        /*dwFlags*/ (uint32_t)process_reg_read(p, Register::r1),
        /*lpMultiByteStr*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*cbMultiByte*/ (int)process_stack_read(p, -0),
        /*lpWideCharStr*/ (wchar_t*)process_mem_target_to_host(p, process_stack_read(p, -1)),
        /*cchWideChar*/ (int)process_stack_read(p, -2)
    );

    process_reg_write(p, Register::r0, r);
}

static void DeleteFileW_trampoline(Process* p) {
    const auto r = coredll::DeleteFileW(
        /*lpFileName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void FindClose_trampoline(Process* p) {
    const auto r = coredll::FindClose(
        /*hFindFile*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void WideCharToMultiByte_trampoline(Process* p) {
    const auto r = coredll::WideCharToMultiByte(
        /*CodePage*/ (uint32_t)process_reg_read(p, Register::r0),
        /*dwFlags*/ (uint32_t)process_reg_read(p, Register::r1),
        /*lpWideCharStr*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*cchWideChar*/ (int)process_stack_read(p, -0),
        /*lpMultiByteStr*/ (char*)process_mem_target_to_host(p, process_stack_read(p, -1)),
        /*cbMultiByte*/ (int)process_stack_read(p, -2),
        /*lpDefaultChar*/ (const char*)process_mem_target_to_host(p, process_stack_read(p, -3)),
        /*lpUsedDefaultChar*/ (bool*)process_mem_target_to_host(p, process_stack_read(p, -4))
    );

    process_reg_write(p, Register::r0, r);
}

static void FindNextFileW_trampoline(Process* p) {
    const auto r = coredll::FindNextFileW(
        /*hFindFile*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpFindFileData*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void FindFirstFileW_trampoline(Process* p) {
    const auto r = coredll::FindFirstFileW(
        /*lpFileName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*lpFindFileData*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void GetModuleFileNameW_trampoline(Process* p) {
    const auto r = coredll::GetModuleFileNameW(
        /*hModule*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpFilename*/ (wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*nSize*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void InitializeCriticalSection_trampoline(Process* p) {
    coredll::InitializeCriticalSection(
        /*lpCriticalSection*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void DeleteCriticalSection_trampoline(Process* p) {
    coredll::DeleteCriticalSection(
        /*lpCriticalSection*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void EnterCriticalSection_trampoline(Process* p) {
    coredll::EnterCriticalSection(
        /*lpCriticalSection*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void LeaveCriticalSection_trampoline(Process* p) {
    coredll::LeaveCriticalSection(
        /*lpCriticalSection*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void QueryPerformanceFrequency_trampoline(Process* p) {
    const auto r = coredll::QueryPerformanceFrequency(
        /*lpFrequency*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void QueryPerformanceCounter_trampoline(Process* p) {
    const auto r = coredll::QueryPerformanceCounter(
        /*lpPerformanceCount*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutGetDevCaps_trampoline(Process* p) {
    const auto r = coredll::waveOutGetDevCaps(
        /*uDeviceID*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwoc*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwoc*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutGetNumDevs_trampoline(Process* p) {
    const auto r = coredll::waveOutGetNumDevs();

    process_reg_write(p, Register::r0, r);
}

static void waveOutOpen_trampoline(Process* p) {
    const auto r = coredll::waveOutOpen(
        /*phwo*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*uDeviceID*/ (int)process_reg_read(p, Register::r1),
        /*pwfx*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*dwCallback*/ (uint32_t)process_stack_read(p, -0),
        /*dwCallbackInstance*/ (uint32_t)process_stack_read(p, -1),
        /*fdwOpen*/ (uint32_t)process_stack_read(p, -2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutClose_trampoline(Process* p) {
    const auto r = coredll::waveOutClose(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutPrepareHeader_trampoline(Process* p) {
    const auto r = coredll::waveOutPrepareHeader(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwh*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwh*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutUnprepareHeader_trampoline(Process* p) {
    const auto r = coredll::waveOutUnprepareHeader(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwh*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwh*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutWrite_trampoline(Process* p) {
    const auto r = coredll::waveOutWrite(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwh*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwh*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutReset_trampoline(Process* p) {
    const auto r = coredll::waveOutReset(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutGetPosition_trampoline(Process* p) {
    const auto r = coredll::waveOutGetPosition(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pmmt*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbmmt*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInAddBuffer_trampoline(Process* p) {
    const auto r = coredll::waveInAddBuffer(
        /*hwi*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwh*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwh*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInPrepareHeader_trampoline(Process* p) {
    const auto r = coredll::waveInPrepareHeader(
        /*hwi*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwh*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwh*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInUnprepareHeader_trampoline(Process* p) {
    const auto r = coredll::waveInUnprepareHeader(
        /*hwi*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwh*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwh*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInGetDevCaps_trampoline(Process* p) {
    const auto r = coredll::waveInGetDevCaps(
        /*uDeviceID*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pwic*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*cbwic*/ (uint32_t)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInGetNumDevs_trampoline(Process* p) {
    const auto r = coredll::waveInGetNumDevs();

    process_reg_write(p, Register::r0, r);
}

static void waveInStart_trampoline(Process* p) {
    const auto r = coredll::waveInStart(
        /*hwi*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInOpen_trampoline(Process* p) {
    const auto r = coredll::waveInOpen(
        /*phwi*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*uDeviceID*/ (uint32_t)process_reg_read(p, Register::r1),
        /*pwfx*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*dwCallback*/ (uint32_t)process_stack_read(p, -0),
        /*dwCallbackInstance*/ (uint32_t)process_stack_read(p, -1),
        /*fdwOpen*/ (uint32_t)process_stack_read(p, -2)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInClose_trampoline(Process* p) {
    const auto r = coredll::waveInClose(
        /*hwi*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveInReset_trampoline(Process* p) {
    const auto r = coredll::waveInReset(
        /*hwi*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutGetVolume_trampoline(Process* p) {
    const auto r = coredll::waveOutGetVolume(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0),
        /*pdwVolume*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void waveOutSetVolume_trampoline(Process* p) {
    const auto r = coredll::waveOutSetVolume(
        /*hwo*/ (uint32_t)process_reg_read(p, Register::r0),
        /*dwVolume*/ (uint32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void RegisterWindowMessageW_trampoline(Process* p) {
    const auto r = coredll::RegisterWindowMessageW(
        /*string*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void SendMessageW_trampoline(Process* p) {
    const auto r = coredll::SendMessageW(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0),
        /*msg*/ (uint32_t)process_reg_read(p, Register::r1),
        /*wparam*/ (uint32_t)process_reg_read(p, Register::r2),
        /*lparam*/ (uint32_t)process_stack_read(p, -0)
    );

    process_reg_write(p, Register::r0, r);
}

static void DefWindowProcW_trampoline(Process* p) {
    const auto r = coredll::DefWindowProcW(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0),
        /*msg*/ (uint32_t)process_reg_read(p, Register::r1),
        /*wparam*/ (uint32_t)process_reg_read(p, Register::r2),
        /*lparam*/ (uint32_t)process_stack_read(p, -0)
    );

    process_reg_write(p, Register::r0, r);
}

static void DispatchMessageW_trampoline(Process* p) {
    const auto r = coredll::DispatchMessageW(
        /*msg*/ (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void TranslateMessage_trampoline(Process* p) {
    const auto r = coredll::TranslateMessage(
        /*msg*/ (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void PeekMessageW_trampoline(Process* p) {
    const auto r = coredll::PeekMessageW(
        /*msg*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r1),
        /*min*/ (int)process_reg_read(p, Register::r2),
        /*max*/ (int)process_stack_read(p, -0),
        /*mode*/ (int)process_stack_read(p, -1)
    );

    process_reg_write(p, Register::r0, r);
}

static void PostQuitMessage_trampoline(Process* p) {
    coredll::PostQuitMessage(
        /*code*/ (int)process_reg_read(p, Register::r0)
    );

}

static void ShowCursor_trampoline(Process* p) {
    const auto r = coredll::ShowCursor(
        /*show*/ (bool)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void SetCursor_trampoline(Process* p) {
    const auto r = coredll::SetCursor(
        /*cursor*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void EndPaint_trampoline(Process* p) {
    const auto r = coredll::EndPaint(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0),
        /*paint*/ (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void BeginPaint_trampoline(Process* p) {
    const auto r = coredll::BeginPaint(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0),
        /*paint*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void GetStockObject_trampoline(Process* p) {
    const auto r = coredll::GetStockObject(
        (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void LoadCursorW_trampoline(Process* p) {
    const auto r = coredll::LoadCursorW(
        /*instance*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*name*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void SetForegroundWindow_trampoline(Process* p) {
    const auto r = coredll::SetForegroundWindow(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void BringWindowToTop_trampoline(Process* p) {
    const auto r = coredll::BringWindowToTop(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void SetFocus_trampoline(Process* p) {
    const auto r = coredll::SetFocus(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void UpdateWindow_trampoline(Process* p) {
    const auto r = coredll::UpdateWindow(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void ShowWindow_trampoline(Process* p) {
    const auto r = coredll::ShowWindow(
        /*hwnd*/ (uint32_t)process_reg_read(p, Register::r0),
        /*show*/ (int)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void RegisterClassW_trampoline(Process* p) {
    const auto r = coredll::RegisterClassW(
        /*wnd*/ (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void CreateWindowExW_trampoline(Process* p) {
    const auto r = coredll::CreateWindowExW(
        /*dwExStyle*/ (uint32_t)process_reg_read(p, Register::r0),
        /*lpClassName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*lpWindowName*/ (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        /*dwStyle*/ (uint32_t)process_stack_read(p, -0),
        /*X*/ (int)process_stack_read(p, -1),
        /*Y*/ (int)process_stack_read(p, -2),
        /*nWidth*/ (int)process_stack_read(p, -3),
        /*nHeight*/ (int)process_stack_read(p, -4),
        /*hWndParent*/ (uint32_t)process_stack_read(p, -5),
        /*hMenu*/ (uint32_t)process_stack_read(p, -6),
        /*hInstance*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -7)),
        /*lpParam*/ (void*)process_mem_target_to_host(p, process_stack_read(p, -8))
    );

    process_reg_write(p, Register::r0, r);
}

static void DestroyWindow_trampoline(Process* p) {
    const auto r = coredll::DestroyWindow(
        /*uint32_t*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void strcpy_trampoline(Process* p) {
    const auto r = coredll::strcpy(
        /*dst*/ (char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*src*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void __itos_trampoline(Process* p) {
    const auto r = coredll::__itos(
        /*v*/ (int)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void __stoi_trampoline(Process* p) {
    const auto r = coredll::__stoi(
        (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void atoi_trampoline(Process* p) {
    const auto r = coredll::atoi(
        /*str*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void atof_trampoline(Process* p) {
    const auto r = coredll::atof(
        /*str*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::s0, r);
}

static void strcmp_trampoline(Process* p) {
    const auto r = coredll::strcmp(
        /*s1*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*s2*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void strstr_trampoline(Process* p) {
    const auto r = coredll::strstr(
        /*s1*/ (char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*s2*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void strncmp_trampoline(Process* p) {
    const auto r = coredll::strncmp(
        /*s1*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*s2*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*n*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void strtoul_trampoline(Process* p) {
    const auto r = coredll::strtoul(
        /*s1*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*s2*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*n*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void strchr_trampoline(Process* p) {
    const auto r = coredll::strchr(
        /*s*/ (char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*n*/ (int)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void strrchr_trampoline(Process* p) {
    const auto r = coredll::strrchr(
        /*s*/ (char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*n*/ (int)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void wcsrchr_trampoline(Process* p) {
    const auto r = coredll::wcsrchr(
        /*s*/ (wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*c*/ (wchar_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void toupper_trampoline(Process* p) {
    const auto r = coredll::toupper(
        /*c*/ (int)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void strlen_trampoline(Process* p) {
    const auto r = coredll::strlen(
        (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

    process_reg_write(p, Register::r0, r);
}

static void __C_specific_uint32_tr_trampoline(Process* p) {
    const auto r = coredll::__C_specific_uint32_tr(
        /*v*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void _XcptFilter_trampoline(Process* p) {
    const auto r = coredll::_XcptFilter(
        (int)process_reg_read(p, Register::r0),
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void __C_specific_handler_trampoline(Process* p) {
    coredll::__C_specific_handler(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (uint64_t)process_reg_read(p, Register::r1),
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        (void*)process_mem_target_to_host(p, process_stack_read(p, -0))
    );

}

static void __lts_trampoline(Process* p) {
    const auto r = coredll::__lts(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __gts_trampoline(Process* p) {
    const auto r = coredll::__gts(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __stou_trampoline(Process* p) {
    const auto r = coredll::__stou(
        /*v*/ (int32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void __rt_sdiv_trampoline(Process* p) {
    const auto r = coredll::__rt_sdiv(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __rt_udiv_trampoline(Process* p) {
    const auto r = coredll::__rt_udiv(
        /*a*/ (uint32_t)process_reg_read(p, Register::r0),
        /*b*/ (uint32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __divs_trampoline(Process* p) {
    const auto r = coredll::__divs(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __rt_sdiv64by64_trampoline(Process* p) {
    const auto r = coredll::__rt_sdiv64by64(
        /*a*/ (int64_t)process_reg_read(p, Register::r0),
        /*b*/ (int64_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __rt_udiv64by64_trampoline(Process* p) {
    const auto r = coredll::__rt_udiv64by64(
        /*a*/ (uint64_t)process_reg_read(p, Register::r0),
        /*b*/ (uint64_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __rt_urem64by64_trampoline(Process* p) {
    const auto r = coredll::__rt_urem64by64(
        /*a*/ (uint64_t)process_reg_read(p, Register::r0),
        /*b*/ (uint64_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __adds_trampoline(Process* p) {
    const auto r = coredll::__adds(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __subs_trampoline(Process* p) {
    const auto r = coredll::__subs(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __negs_trampoline(Process* p) {
    const auto r = coredll::__negs(
        /*a*/ (int32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void __muls_trampoline(Process* p) {
    const auto r = coredll::__muls(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __utos_trampoline(Process* p) {
    const auto r = coredll::__utos(
        /*v*/ (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void __utod_trampoline(Process* p) {
    const auto r = coredll::__utod(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void __stod_trampoline(Process* p) {
    const auto r = coredll::__stod(
        /*v*/ (int32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::s0, r);
}

static void __muld_trampoline(Process* p) {
    const auto r = coredll::__muld(
        /*a*/ (int32_t)process_reg_read(p, Register::r0),
        /*b*/ (int32_t)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, r);
}

static void __dtoi_trampoline(Process* p) {
    const auto r = coredll::__dtoi(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::r0, r);
}

static void __dtos_trampoline(Process* p) {
    const auto r = coredll::__dtos(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::r0, r);
}

static void ldexp_trampoline(Process* p) {
    const auto r = coredll::ldexp(
        /*x*/ (float)process_reg_read(p, Register::s0),
        /*exp*/ (int)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::s0, r);
}

static void atan2_trampoline(Process* p) {
    const auto r = coredll::atan2(
        /*y*/ (float)process_reg_read(p, Register::s0),
        /*x*/ (float)process_reg_read(p, Register::s1)
    );

    process_reg_write(p, Register::s0, r);
}

static void pow_trampoline(Process* p) {
    const auto r = coredll::pow(
        /*v*/ (float)process_reg_read(p, Register::s0),
        /*a*/ (float)process_reg_read(p, Register::s1)
    );

    process_reg_write(p, Register::s0, r);
}

static void atan_trampoline(Process* p) {
    const auto r = coredll::atan(
        /*x*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void acos_trampoline(Process* p) {
    const auto r = coredll::acos(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void sqrt_trampoline(Process* p) {
    const auto r = coredll::sqrt(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void asin_trampoline(Process* p) {
    const auto r = coredll::asin(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void cos_trampoline(Process* p) {
    const auto r = coredll::cos(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void sin_trampoline(Process* p) {
    const auto r = coredll::sin(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void tan_trampoline(Process* p) {
    const auto r = coredll::tan(
        /*v*/ (float)process_reg_read(p, Register::s0)
    );

    process_reg_write(p, Register::s0, r);
}

static void vsprintf_trampoline(Process* p) {
    const auto r = coredll::vsprintf(
        (char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        0
    );

    process_reg_write(p, Register::r0, r);
}

static void sprintf_trampoline(Process* p) {
    const auto r = coredll::sprintf(
        (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        0
    );

    process_reg_write(p, Register::r0, r);
}

static void _snwprintf_trampoline(Process* p) {
    const auto r = coredll::_snwprintf(
        /*buf*/ (wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (int)process_reg_read(p, Register::r1),
        (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r2)),
        0
    );

    process_reg_write(p, Register::r0, r);
}

static void mbstowcs_trampoline(Process* p) {
    const auto r = coredll::mbstowcs(
        /*dst*/ (wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*src*/ (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*len*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void memcpy_trampoline(Process* p) {
    const auto r = coredll::memcpy(
        /*dst*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*src*/ (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        /*len*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void memset_trampoline(Process* p) {
    const auto r = coredll::memset(
        /*ptr*/ (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*value*/ (int)process_reg_read(p, Register::r1),
        /*num*/ (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void fclose_trampoline(Process* p) {
    const auto r = coredll::fclose(
        (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void ftell_trampoline(Process* p) {
    const auto r = coredll::ftell(
        (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void feof_trampoline(Process* p) {
    const auto r = coredll::feof(
        (uint32_t)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, r);
}

static void fseek_trampoline(Process* p) {
    const auto r = coredll::fseek(
        (uint32_t)process_reg_read(p, Register::r0),
        (int)process_reg_read(p, Register::r1),
        (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void _wfopen_trampoline(Process* p) {
    const auto r = coredll::_wfopen(
        (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (const wchar_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void fopen_trampoline(Process* p) {
    const auto r = coredll::fopen(
        (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (const char*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

    process_reg_write(p, Register::r0, r);
}

static void fread_trampoline(Process* p) {
    const auto r = coredll::fread(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (int)process_reg_read(p, Register::r1),
        (int)process_reg_read(p, Register::r2),
        (uint32_t)process_stack_read(p, -0)
    );

    process_reg_write(p, Register::r0, r);
}

static void fwrite_trampoline(Process* p) {
    const auto r = coredll::fwrite(
        (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (int)process_reg_read(p, Register::r1),
        (int)process_reg_read(p, Register::r2),
        (uint32_t)process_stack_read(p, -0)
    );

    process_reg_write(p, Register::r0, r);
}

static void rand_trampoline(Process* p) {
    const auto r = coredll::rand();

    process_reg_write(p, Register::r0, r);
}

static void malloc_trampoline(Process* p) {
    const auto r = coredll::malloc(
        /*size*/ (int)process_reg_read(p, Register::r0)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void realloc_trampoline(Process* p) {
    const auto r = coredll::realloc(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        /*size*/ (int)process_reg_read(p, Register::r1)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void free_trampoline(Process* p) {
    coredll::free(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void memmove_trampoline(Process* p) {
    const auto r = coredll::memmove(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void memcmp_trampoline(Process* p) {
    const auto r = coredll::memcmp(
        (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (const void*)process_mem_target_to_host(p, process_reg_read(p, Register::r1)),
        (int)process_reg_read(p, Register::r2)
    );

    process_reg_write(p, Register::r0, r);
}

static void qsort_trampoline(Process* p) {
    coredll::qsort(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0)),
        (int)process_reg_read(p, Register::r1),
        (int)process_reg_read(p, Register::r2),
        (void*)process_mem_target_to_host(p, process_stack_read(p, -0))
    );

}

static void eglSwapIntervalNV_trampoline(Process* p) {
    libGLES_CM::eglSwapIntervalNV();

}

static void glEnableClientState_trampoline(Process* p) {
    libGLES_CM::glEnableClientState(
        /*arr*/ (GLenum)process_reg_read(p, Register::r0)
    );

}

static void glDisableClientState_trampoline(Process* p) {
    libGLES_CM::glDisableClientState(
        /*arr*/ (GLenum)process_reg_read(p, Register::r0)
    );

}

static void glVertexPointer_trampoline(Process* p) {
    libGLES_CM::glVertexPointer(
        /*size*/ (uint32_t)process_reg_read(p, Register::r0),
        /*type*/ (GLenum)process_reg_read(p, Register::r1),
        /*stride*/ (uint32_t)process_reg_read(p, Register::r2),
        /*pointer*/ (const void*)process_mem_target_to_host(p, process_stack_read(p, -0))
    );

}

static void glColorPointer_trampoline(Process* p) {
    libGLES_CM::glColorPointer();

}

static void glClientActiveTexture_trampoline(Process* p) {
    libGLES_CM::glClientActiveTexture();

}

static void glTexCoordPointer_trampoline(Process* p) {
    libGLES_CM::glTexCoordPointer();

}

static void glDrawElements_trampoline(Process* p) {
    libGLES_CM::glDrawElements();

}

static void glTexEnvf_trampoline(Process* p) {
    libGLES_CM::glTexEnvf();

}

static void glDepthRangef_trampoline(Process* p) {
    libGLES_CM::glDepthRangef();

}

static void glDepthMask_trampoline(Process* p) {
    libGLES_CM::glDepthMask();

}

static void glDepthFunc_trampoline(Process* p) {
    libGLES_CM::glDepthFunc();

}

static void glCullFace_trampoline(Process* p) {
    libGLES_CM::glCullFace();

}

static void glEnable_trampoline(Process* p) {
    libGLES_CM::glEnable(
        /*feat*/ (GLenum)process_reg_read(p, Register::r0)
    );

}

static void glDisable_trampoline(Process* p) {
    libGLES_CM::glDisable(
        /*feat*/ (GLenum)process_reg_read(p, Register::r0)
    );

}

static void glGetIntegerv_trampoline(Process* p) {
    libGLES_CM::glGetIntegerv();

}

static void glGetString_trampoline(Process* p) {
    const auto r = libGLES_CM::glGetString();

    process_reg_write(p, Register::r0, process_mem_host_to_target(p, (void*)r));
}

static void eglMakeCurrent_trampoline(Process* p) {
    libGLES_CM::eglMakeCurrent(
        (void*)process_mem_target_to_host(p, process_reg_read(p, Register::r0))
    );

}

static void eglCreateWindowSurface_trampoline(Process* p) {
    libGLES_CM::eglCreateWindowSurface();

}

static void eglCreateContext_trampoline(Process* p) {
    libGLES_CM::eglCreateContext();

}

static void eglChooseConfig_trampoline(Process* p) {
    libGLES_CM::eglChooseConfig();

}

static void eglGetConfigs_trampoline(Process* p) {
    libGLES_CM::eglGetConfigs();

}

static void eglInitialize_trampoline(Process* p) {
    libGLES_CM::eglInitialize();

}

static void eglGetDisplay_trampoline(Process* p) {
    libGLES_CM::eglGetDisplay();

}

static void eglTerminate_trampoline(Process* p) {
    libGLES_CM::eglTerminate();

}

static void eglDestroySurface_trampoline(Process* p) {
    libGLES_CM::eglDestroySurface();

}

static void eglDestroyContext_trampoline(Process* p) {
    libGLES_CM::eglDestroyContext();

}

static void glClear_trampoline(Process* p) {
    libGLES_CM::glClear();

}

static void glClearColorx_trampoline(Process* p) {
    libGLES_CM::glClearColorx();

}

static void eglSwapBuffers_trampoline(Process* p) {
    libGLES_CM::eglSwapBuffers();

}

static void glFinish_trampoline(Process* p) {
    libGLES_CM::glFinish();

}

static void glLoadMatrixx_trampoline(Process* p) {
    libGLES_CM::glLoadMatrixx();

}

static void glMatrixMode_trampoline(Process* p) {
    libGLES_CM::glMatrixMode(
        /*mode*/ (GLenum)process_reg_read(p, Register::r0)
    );

}

static void glViewport_trampoline(Process* p) {
    libGLES_CM::glViewport(
        /*x*/ (float)process_reg_read(p, Register::s0),
        /*y*/ (float)process_reg_read(p, Register::s1),
        /*w*/ (float)process_reg_read(p, Register::s2),
        /*h*/ (float)process_reg_read(p, Register::s3)
    );

}

static void glScissor_trampoline(Process* p) {
    libGLES_CM::glScissor();

}

static void glGenTextures_trampoline(Process* p) {
    libGLES_CM::glGenTextures(
        /*count*/ (int)process_reg_read(p, Register::r0),
        /*uint32_ts*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

}

static void glDeleteTextures_trampoline(Process* p) {
    libGLES_CM::glDeleteTextures(
        /*count*/ (int)process_reg_read(p, Register::r0),
        /*uint32_ts*/ (uint32_t*)process_mem_target_to_host(p, process_reg_read(p, Register::r1))
    );

}

static void glTexImage2D_trampoline(Process* p) {
    libGLES_CM::glTexImage2D(
        /*target*/ (GLenum)process_reg_read(p, Register::r0),
        /*level*/ (int)process_reg_read(p, Register::r1),
        /*internalformat*/ (int)process_reg_read(p, Register::r2),
        /*width*/ (int)process_stack_read(p, -0),
        /*height*/ (int)process_stack_read(p, -1),
        /*border*/ (int)process_stack_read(p, -2),
        /*format*/ (int)process_stack_read(p, -3),
        /*type*/ (GLenum)process_stack_read(p, -4),
        /*pixels*/ (const void*)process_mem_target_to_host(p, process_stack_read(p, -5))
    );

}

static void glTexParameterf_trampoline(Process* p) {
    libGLES_CM::glTexParameterf();

}

static void glBindTexture_trampoline(Process* p) {
    libGLES_CM::glBindTexture(
        /*mode*/ (GLenum)process_reg_read(p, Register::r0),
        /*uint32_t*/ (uint32_t)process_reg_read(p, Register::r1)
    );

}

static void glCompressedTexImage2D_trampoline(Process* p) {
    libGLES_CM::glCompressedTexImage2D();

}

static void glActiveTexture_trampoline(Process* p) {
    libGLES_CM::glActiveTexture(
        /*mode*/ (GLenum)process_reg_read(p, Register::r0)
    );

}

static void glAlphaFunc_trampoline(Process* p) {
    libGLES_CM::glAlphaFunc(
        /*func*/ (GLenum)process_reg_read(p, Register::r0),
        /*ref*/ (float)process_reg_read(p, Register::s0)
    );

}

static void glBlendFunc_trampoline(Process* p) {
    libGLES_CM::glBlendFunc(
        /*sfactor*/ (GLenum)process_reg_read(p, Register::r0),
        /*dfactor*/ (GLenum)process_reg_read(p, Register::r1)
    );

}

static void glDrawArrays_trampoline(Process* p) {
    libGLES_CM::glDrawArrays(
        /*mode*/ (GLenum)process_reg_read(p, Register::r0),
        /*index*/ (int)process_reg_read(p, Register::r1),
        /*count*/ (int)process_reg_read(p, Register::r2)
    );

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
    { "DeleteFileW", (void*)DeleteFileW_trampoline },
    { "FindClose", (void*)FindClose_trampoline },
    { "WideCharToMultiByte", (void*)WideCharToMultiByte_trampoline },
    { "FindNextFileW", (void*)FindNextFileW_trampoline },
    { "FindFirstFileW", (void*)FindFirstFileW_trampoline },
    { "GetModuleFileNameW", (void*)GetModuleFileNameW_trampoline },
    { "InitializeCriticalSection", (void*)InitializeCriticalSection_trampoline },
    { "DeleteCriticalSection", (void*)DeleteCriticalSection_trampoline },
    { "EnterCriticalSection", (void*)EnterCriticalSection_trampoline },
    { "LeaveCriticalSection", (void*)LeaveCriticalSection_trampoline },
    { "QueryPerformanceFrequency", (void*)QueryPerformanceFrequency_trampoline },
    { "QueryPerformanceCounter", (void*)QueryPerformanceCounter_trampoline },
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
    { "strcpy", (void*)strcpy_trampoline },
    { "__itos", (void*)__itos_trampoline },
    { "__stoi", (void*)__stoi_trampoline },
    { "atoi", (void*)atoi_trampoline },
    { "atof", (void*)atof_trampoline },
    { "strcmp", (void*)strcmp_trampoline },
    { "strstr", (void*)strstr_trampoline },
    { "strncmp", (void*)strncmp_trampoline },
    { "strtoul", (void*)strtoul_trampoline },
    { "strchr", (void*)strchr_trampoline },
    { "strrchr", (void*)strrchr_trampoline },
    { "wcsrchr", (void*)wcsrchr_trampoline },
    { "toupper", (void*)toupper_trampoline },
    { "strlen", (void*)strlen_trampoline },
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

