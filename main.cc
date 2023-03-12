
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

#include <vector>
#include <string_view>
#include <memory>

#include "pe.h"
#include "utils.h"
#include "coredll_symbols.h"

namespace file {
    optional<std::vector<std::byte>> read(std::string_view path) {
        using ptr   = std::unique_ptr<FILE, void(*)(FILE*)>;
        auto closer = [](FILE* f){ if (f) fclose(f); };

        if (auto file = ptr(fopen(path.data(), "rb"), closer)) {
            fseek(file.get(), 0, SEEK_END);
            if (auto size = ftell(file.get()); size > 0) {
                std::vector<std::byte> data;

                data.resize(size);
                fseek(file.get(), 0, SEEK_SET);
                fread(data.data(), 1, size, file.get());

                return make_optional(data);
            }
        }

        return {};
    }
}

namespace cpu {
    struct Context {
        constexpr operator auto() const { return e; }
        uc_engine* e;
    };

    Context init() {
        Context c{};

        const auto r = uc_open(uc_arch::UC_ARCH_ARM, uc_mode::UC_MODE_THUMB, &c.e);
        check(r == UC_ERR_OK, "failed to init unicorn: %s", uc_strerror(r));

        return c;
    }

    void shutdown(Context& c) {
        uc_close(c.e);
        c = {};
    }

    void mem_map(Context& c, uint32_t address, uint32_t length) {
        const auto r = uc_mem_map(c, address, length, UC_PROT_ALL);
        check(r == UC_ERR_OK, "failed to map memory range { 0x%08X - 0x%08X }", address, address + length);
    }

    void mem_read(Context& c, uint32_t address, void* dst, uint32_t length) {
        const auto r = uc_mem_read(c, address, dst, length);
        check(r == UC_ERR_OK, "failed to read memory: %s", uc_strerror(r));
    }

    void mem_write(Context& c, uint32_t address, const void* src, uint32_t length) {
        const auto r = uc_mem_write(c, address, src, length);
        check(r == UC_ERR_OK, "failed to write memory: %s", uc_strerror(r));
    }
}

struct Module {
    const char* name;
    std::vector<std::pair<const char*, void*>> symbols;
};

static Module modules[] = {
    {
        "COREDLL.dll", {
            { "__subs", nullptr },
            { "__muls", nullptr },
            { "__adds", nullptr },
            { "__lts", nullptr },
            { "__divs", nullptr },
            { "__stod", nullptr },
            { "atan", nullptr },
            { "__muld", nullptr },
            { "__dtos", nullptr },
            { "fclose", nullptr },
            { "fflush", nullptr },
            { "fwrite", nullptr },
            { "fread", nullptr },
            { "__led", nullptr },
            { "fprintf", nullptr },
            { "fopen", nullptr },
            { "sprintf", nullptr },
            { "atoi", nullptr },
            { "strstr", nullptr },
            { "fgetc", nullptr },
            { "strcpy", nullptr },
            { "__subd", nullptr },
            { "__eqs", nullptr },
            { "__itos", nullptr },
            { "__nes", nullptr },
            { "__gts", nullptr },
            { "__stoi", nullptr },
            { "memset", nullptr },
            { "__ged", nullptr },
            { "__divd", nullptr },
            { "__ltd", nullptr },
            { "__gtd", nullptr },
            { "rand", nullptr },
            { "__ned", nullptr },
            { "__les", nullptr },
            { "__addd", nullptr },
            { "__itod", nullptr },
            { "memcpy", nullptr },
            { "__ges", nullptr },
            { "strncpy", nullptr },
            { "__dtoi", nullptr },
            { "sqrt", nullptr },
            { "atan2", nullptr },
            { "strlen", nullptr },
            { "strcmp", nullptr },
            { "vsprintf", nullptr },
            { "fseek", nullptr },
            { "free", nullptr },
            { "malloc", nullptr },
            { "__rt_sdiv", nullptr },
            { "LocalFree", nullptr },
            { "FormatMessageW", nullptr },
            { "DeleteFileW", nullptr },
            { "CreateDirectoryW", nullptr },
            { "WideCharToMultiByte", nullptr },
            { "MultiByteToWideChar", nullptr },
            { "SetFilePointer", nullptr },
            { "CreateFileW", nullptr },
            { "WriteFile", nullptr },
            { "CloseHandle", nullptr },
            { "__rt_sdiv64by64", nullptr },
            { "sin", nullptr },
            { "cos", nullptr },
            { "tan", nullptr },
            { "__utod", nullptr },
            { "__utos", nullptr },
            { "floor", nullptr },
            { "ceil", nullptr },
            { "fabs", nullptr },
            { "__negs", nullptr },
            { "__negd", nullptr },
            { "__rt_udiv", nullptr },
            { "asin", nullptr },
            { "__stou", nullptr },
            { "__eqd", nullptr },
            { "UpdateWindow", nullptr },
            { "ShowWindow", nullptr },
            { "CreateWindowExW", nullptr },
            { "strncmp", nullptr },
            { "DefWindowProcW", nullptr },
            { "MessageBoxW", nullptr },
            { "PostQuitMessage", nullptr },
            { "DestroyWindow", nullptr },
            { "RegisterClassW", nullptr },
            { "LoadCursorW", nullptr },
            { "pow", nullptr },
            { "longjmp", nullptr },
            { "setjmp", nullptr },
            { "printf", nullptr },
            { "feof", nullptr },
            { "fscanf", nullptr },
            { "DispatchMessageW", nullptr },
            { "TranslateMessage", nullptr },
            { "PeekMessageW", nullptr },
            { "GetLastError", nullptr },
            { "GetProcAddressW", nullptr },
            { "LoadLibraryW", nullptr },
            { "sscanf", nullptr },
            { "swprintf", nullptr },
            { "atof", nullptr },
            { "waveOutReset", nullptr },
            { "waveOutClose", nullptr },
            { "waveOutUnprepareHeader", nullptr },
            { "waveOutPrepareHeader", nullptr },
            { "LocalAlloc", nullptr },
            { "waveOutOpen", nullptr },
            { "waveOutWrite", nullptr },
            { "ftell", nullptr },
            { "VirtualProtect", nullptr },
            { "GetVersionExW", nullptr },
            { "QueryPerformanceFrequency", nullptr },
            { "UnmapViewOfFile", nullptr },
            { "QueryPerformanceCounter", nullptr },
            { "Sleep", nullptr },
            { "GetMessageW", nullptr },
            { "MsgWaitForMultipleObjectsEx", nullptr },
            { "CreateEventW", nullptr },
            { "MapViewOfFile", nullptr },
            { "CreateFileMappingW", nullptr },
            { "SetForegroundWindow", nullptr },
            { "SetWindowPos", nullptr },
            { "GetWindowRect", nullptr },
            { "CreateDialogIndirectParamW", nullptr },
            { "LoadResource", nullptr },
            { "FindResourceW", nullptr },
            { "GlobalMemoryStatus", nullptr },
            { "_XcptFilter", nullptr },
            { "__C_specific_handler", nullptr }
        }
    },
    { 
        "WS2.dll", {
            { "htonl",     nullptr },
            { "ntohs",     nullptr },
            { "bind",      nullptr },
            { "htons",     nullptr },
            { "ntohl",     nullptr },
            { "inet_addr", nullptr },
            { "inet_ntoa", nullptr }
        }
    },
    {
        "libgles_cm.dll", {
            { "eglGetConfigs", nullptr },
            { "eglQueryString", nullptr },
            { "eglInitialize", nullptr },
            { "eglGetDisplay", nullptr },
            { "glGetError", nullptr },
            { "glClientActiveTexture", nullptr },
            { "glActiveTexture", nullptr },
            { "glAlphaFunc", nullptr },
            { "glAlphaFuncx", nullptr },
            { "glBindTexture", nullptr },
            { "glBlendFunc", nullptr },
            { "glClear", nullptr },
            { "glClearColor", nullptr },
            { "glClearColorx", nullptr },
            { "glClearDepthf", nullptr },
            { "glClearDepthx", nullptr },
            { "glClearStencil", nullptr },
            { "glColorMask", nullptr },
            { "glColorPointer", nullptr },
            { "glCompressedTexImage2D", nullptr },
            { "glCompressedTexSubImage2D", nullptr },
            { "glCopyTexImage2D", nullptr },
            { "glCopyTexSubImage2D", nullptr },
            { "glCullFace", nullptr },
            { "glDeleteTextures", nullptr },
            { "glDepthFunc", nullptr },
            { "glDepthMask", nullptr },
            { "glDepthRangef", nullptr },
            { "glDepthRangex", nullptr },
            { "glDisable", nullptr },
            { "glDisableClientState", nullptr },
            { "glDrawArrays", nullptr },
            { "glDrawElements", nullptr },
            { "glEnable", nullptr },
            { "glEnableClientState", nullptr },
            { "glFinish", nullptr },
            { "glFlush", nullptr },
            { "glFrontFace", nullptr },
            { "eglChooseConfig", nullptr },
            { "glFrustumx", nullptr },
            { "glGenTextures", nullptr },
            { "glGetIntegerv", nullptr },
            { "glGetString", nullptr },
            { "glHint", nullptr },
            { "glLineWidth", nullptr },
            { "glLineWidthx", nullptr },
            { "glLoadIdentity", nullptr },
            { "glLoadMatrixf", nullptr },
            { "glLoadMatrixx", nullptr },
            { "glLogicOp", nullptr },
            { "glMatrixMode", nullptr },
            { "glNormalPointer", nullptr },
            { "glOrthof", nullptr },
            { "glOrthox", nullptr },
            { "glPopMatrix", nullptr },
            { "glPushMatrix", nullptr },
            { "glReadPixels", nullptr },
            { "glRotatef", nullptr },
            { "glRotatex", nullptr },
            { "glScalef", nullptr },
            { "glScalex", nullptr },
            { "glScissor", nullptr },
            { "glShadeModel", nullptr },
            { "glStencilFunc", nullptr },
            { "glStencilMask", nullptr },
            { "glStencilOp", nullptr },
            { "glTexCoordPointer", nullptr },
            { "glTexEnvf", nullptr },
            { "glTexImage2D", nullptr },
            { "glTexParameterf", nullptr },
            { "glTexSubImage2D", nullptr },
            { "glTranslatef", nullptr },
            { "glTranslatex", nullptr },
            { "glVertexPointer", nullptr },
            { "glViewport", nullptr },
            { "eglGetProcAddress", nullptr },
            { "eglCreateWindowSurface", nullptr },
            { "eglCreateContext", nullptr },
            { "eglGetConfigAttrib", nullptr },
            { "eglMakeCurrent", nullptr },
            { "eglDestroyContext", nullptr },
            { "eglDestroySurface", nullptr },
            { "eglTerminate", nullptr },
            { "glFrustumf", nullptr },
            { "eglGetError", nullptr },
            { "eglSwapBuffers", nullptr }
        }
    }
};

static void* getModulePointer(const std::string_view& moduleName, const std::string_view& symbolName) {
    for (auto& mod : modules) {
        if (mod.name == moduleName) {
            for (auto& sym : mod.symbols) {
                if (sym.first == symbolName) {
                    return &sym.second;
                }
            }
        }
    }

    return nullptr;
}

int main(int, const char**) {
    const auto file = file::read("c:/Users/Oli/Desktop/preem-hle/roms/Quake/Quake.exe");
    check(file, "failed to open file");

    const auto* dos = cast<const pe::DOS_HEADER*>(file->data());
    const auto* nt  = cast<const pe::NT_HEADER*>(file->data() + dos->e_lfanew);

    // Gizmondo is a ARM thumb device running Window CE.
    check (nt->FileHeader.Machine == 0x01c2, "expected ARM THUMB.. got (0x%04X)", nt->FileHeader.Machine);
    
    const auto sections = [=] {
        const auto first = cast<pe::SECTION_HEADER*>(cast<uintptr_t>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
        return make_view(first, first + nt->FileHeader.NumberOfSections);
    }();

    auto load = [&](uint32_t rva) {
        return file->data() + *pe::relativeToOffset(sections, rva);
    };

    const auto idir  = nt->OptionalHeader.DataDirectory[pe::DirectoryIndex::ImportTable];
    const auto* desc = cast<const pe::IMPORT_DESCRIPTOR*>(load(idir.VirtualAddress));

    while (desc->Name) {
        const auto moduleName = cast<const char*>(load(desc->Name));
        const auto* thunk     = cast<const pe::THUNK_DATA*>(load(desc->FirstThunk));

        while (thunk->u1.AddressOfData) {
            const auto symbolName = [&]{
                if (thunk->u1.Ordinal & pe::Flag::ImportOrdinal) {
                    // COREDLL.dll is the only dll we support ordinal looks up for
                    check(std::string_view{moduleName} == "COREDLL.dll", "We don't know about '%s'", moduleName);
                    return [=] {
                        const auto ord = pe::ordinal(thunk->u1.Ordinal);

                        for (const auto& sym : coredll_symbols) {
                            if (sym.ord == ord) {
                                return sym.name;
                            }
                        }

                        return (const char*)nullptr;
                    }();
                }

                return cast<const char*>(load(thunk->u1.AddressOfData + 2));
            }();

            auto ptr = getModulePointer(moduleName, symbolName);
            check(ptr, "We dont implement [%s][%s]", moduleName, symbolName);

            thunk++;
        }

        desc++;
    }

    return 0;
}