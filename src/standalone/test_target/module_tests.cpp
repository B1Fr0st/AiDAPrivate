#include "module_tests.h"
#include <cstdio>
#include <cstring>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace test_target {
namespace modules {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[MOD] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}


struct dll_info_t {
    const char* name;
    HMODULE     handle;
};

static dll_info_t s_loaded_dlls[5] = {
    { "kernel32.dll", nullptr },
    { "ntdll.dll",    nullptr },
    { "user32.dll",   nullptr },
    { "advapi32.dll", nullptr },
    { "ws2_32.dll",   nullptr },
};

struct resolved_fn_t {
    const char* dll_name;
    const char* fn_name;
    FARPROC     address;
};

static resolved_fn_t s_resolved_fns[30] = {0};
static int s_resolved_count = 0;

#pragma optimize("", off)


void __declspec(noinline) test_load_system_dlls(const config_t& cfg) {
    log("System DLL load test starting...");

    for (int i = 0; i < 5; ++i) {
        s_loaded_dlls[i].handle = LoadLibraryA(s_loaded_dlls[i].name);
        if (s_loaded_dlls[i].handle) {
            log("Loaded %-16s at %p", s_loaded_dlls[i].name, (void*)s_loaded_dlls[i].handle);
        } else {
            log("Failed to load %s: %lu", s_loaded_dlls[i].name, GetLastError());
        }
    }

    log("System DLL load test complete");
}


static void resolve_fn(const char* dll_name, HMODULE hMod, const char* fn_name) {
    if (!hMod || s_resolved_count >= 30) return;
    FARPROC addr = GetProcAddress(hMod, fn_name);
    s_resolved_fns[s_resolved_count].dll_name = dll_name;
    s_resolved_fns[s_resolved_count].fn_name = fn_name;
    s_resolved_fns[s_resolved_count].address = addr;
    s_resolved_count++;
    log("  GetProcAddress(%s, \"%s\") = %p", dll_name, fn_name, (void*)addr);
}

void __declspec(noinline) test_resolve_functions(const config_t& cfg) {
    log("Function resolution test starting...");
    s_resolved_count = 0;


    HMODULE hK32 = s_loaded_dlls[0].handle;
    resolve_fn("kernel32", hK32, "GetSystemTimeAsFileTime");
    resolve_fn("kernel32", hK32, "VirtualAlloc");
    resolve_fn("kernel32", hK32, "VirtualFree");
    resolve_fn("kernel32", hK32, "CreateFileW");
    resolve_fn("kernel32", hK32, "ReadFile");
    resolve_fn("kernel32", hK32, "GetCurrentProcessId");


    HMODULE hNtdll = s_loaded_dlls[1].handle;
    resolve_fn("ntdll", hNtdll, "NtQueryInformationProcess");
    resolve_fn("ntdll", hNtdll, "NtQuerySystemInformation");
    resolve_fn("ntdll", hNtdll, "RtlGetVersion");
    resolve_fn("ntdll", hNtdll, "NtClose");
    resolve_fn("ntdll", hNtdll, "NtAllocateVirtualMemory");


    HMODULE hUser32 = s_loaded_dlls[2].handle;
    resolve_fn("user32", hUser32, "GetForegroundWindow");
    resolve_fn("user32", hUser32, "GetWindowTextW");
    resolve_fn("user32", hUser32, "MessageBoxW");
    resolve_fn("user32", hUser32, "FindWindowW");
    resolve_fn("user32", hUser32, "EnumWindows");


    HMODULE hAdv = s_loaded_dlls[3].handle;
    resolve_fn("advapi32", hAdv, "RegOpenKeyExW");
    resolve_fn("advapi32", hAdv, "RegQueryValueExW");
    resolve_fn("advapi32", hAdv, "RegCloseKey");
    resolve_fn("advapi32", hAdv, "OpenProcessToken");
    resolve_fn("advapi32", hAdv, "LookupPrivilegeValueW");


    HMODULE hWs2 = s_loaded_dlls[4].handle;
    resolve_fn("ws2_32", hWs2, "socket");
    resolve_fn("ws2_32", hWs2, "connect");
    resolve_fn("ws2_32", hWs2, "send");
    resolve_fn("ws2_32", hWs2, "recv");
    resolve_fn("ws2_32", hWs2, "closesocket");

    log("Resolved %d functions total", s_resolved_count);
    log("Function resolution test complete");
}


void __declspec(noinline) test_call_resolved(const config_t& cfg) {
    log("Resolved function call test starting...");


    typedef DWORD(WINAPI* fn_GetCurrentProcessId)();
    for (int i = 0; i < s_resolved_count; ++i) {
        if (strcmp(s_resolved_fns[i].fn_name, "GetCurrentProcessId") == 0 && s_resolved_fns[i].address) {
            fn_GetCurrentProcessId fn = (fn_GetCurrentProcessId)s_resolved_fns[i].address;
            DWORD pid = fn();
            log("Called GetCurrentProcessId() via resolved ptr: PID=%lu", pid);
            break;
        }
    }


    typedef void(WINAPI* fn_GetSystemTimeAsFileTime)(LPFILETIME);
    for (int i = 0; i < s_resolved_count; ++i) {
        if (strcmp(s_resolved_fns[i].fn_name, "GetSystemTimeAsFileTime") == 0 && s_resolved_fns[i].address) {
            fn_GetSystemTimeAsFileTime fn = (fn_GetSystemTimeAsFileTime)s_resolved_fns[i].address;
            FILETIME ft = {};
            fn(&ft);
            log("Called GetSystemTimeAsFileTime() via resolved ptr: hi=%lu lo=%lu", ft.dwHighDateTime, ft.dwLowDateTime);
            break;
        }
    }


    typedef NTSTATUS(NTAPI* fn_RtlGetVersion)(PRTL_OSVERSIONINFOW);
    for (int i = 0; i < s_resolved_count; ++i) {
        if (strcmp(s_resolved_fns[i].fn_name, "RtlGetVersion") == 0 && s_resolved_fns[i].address) {
            fn_RtlGetVersion fn = (fn_RtlGetVersion)s_resolved_fns[i].address;
            RTL_OSVERSIONINFOW vi = {};
            vi.dwOSVersionInfoSize = sizeof(vi);
            NTSTATUS status = fn(&vi);
            if (status == 0) {
                log("Called RtlGetVersion(): %lu.%lu.%lu", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
            }
            break;
        }
    }


    typedef HWND(WINAPI* fn_GetForegroundWindow)();
    for (int i = 0; i < s_resolved_count; ++i) {
        if (strcmp(s_resolved_fns[i].fn_name, "GetForegroundWindow") == 0 && s_resolved_fns[i].address) {
            fn_GetForegroundWindow fn = (fn_GetForegroundWindow)s_resolved_fns[i].address;
            HWND hwnd = fn();
            log("Called GetForegroundWindow() via resolved ptr: HWND=%p", (void*)hwnd);
            break;
        }
    }


    log("Function pointer table at %p (%d entries):", (void*)s_resolved_fns, s_resolved_count);
    for (int i = 0; i < s_resolved_count; ++i) {
        if (s_resolved_fns[i].address) {
            log("  [%2d] %s!%s = %p", i, s_resolved_fns[i].dll_name, s_resolved_fns[i].fn_name, (void*)s_resolved_fns[i].address);
        }
    }

    log("Resolved function call test complete");
}


void __declspec(noinline) test_enumerate_modules(const config_t& cfg) {
    log("Module enumeration test starting...");

    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        log("CreateToolhelp32Snapshot(SNAPMODULE) failed: %lu", GetLastError());
        return;
    }

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    int module_count = 0;
    if (Module32FirstW(hSnap, &me)) {
        do {
            log("  Module: base=%p size=0x%08X name='%S'",
                (void*)me.modBaseAddr, me.modBaseSize, me.szModule);
            if (cfg.verbose) {
                log("    path='%S'", me.szExePath);
            }
            module_count++;
        } while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);
    log("Total modules: %d", module_count);

    log("Module enumeration test complete");
}


void __declspec(noinline) test_enumerate_threads(const config_t& cfg) {
    log("Thread enumeration test starting...");

    DWORD pid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        log("CreateToolhelp32Snapshot(SNAPTHREAD) failed: %lu", GetLastError());
        return;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    int thread_count = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                log("  Thread: tid=%lu priority=%ld", te.th32ThreadID, te.tpBasePri);
                thread_count++;
            }
        } while (Thread32Next(hSnap, &te));
    }

    CloseHandle(hSnap);
    log("Total threads in PID %lu: %d", pid, thread_count);

    log("Thread enumeration test complete");
}


void __declspec(noinline) test_get_peb(const config_t& cfg) {
    log("PEB query test starting...");

    typedef NTSTATUS(NTAPI* fn_NtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        log("ntdll.dll not loaded");
        return;
    }

    fn_NtQueryInformationProcess NtQueryInfoProc =
        (fn_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInfoProc) {
        log("Failed to resolve NtQueryInformationProcess");
        return;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG ret_len = 0;
    NTSTATUS status = NtQueryInfoProc(
        GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len);

    if (status == 0) {
        log("PEB address: %p", pbi.PebBaseAddress);
        log("Process ID: %llu", (uint64_t)pbi.UniqueProcessId);


        PEB* peb = pbi.PebBaseAddress;
        if (peb) {
            log("PEB->BeingDebugged: %u", peb->BeingDebugged);
            log("PEB->ImageBaseAddress: %p", peb->Reserved3[1]);
            log("PEB->Ldr: %p", peb->Ldr);


            if (peb->Ldr) {
                PEB_LDR_DATA* ldr = peb->Ldr;
                LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
                LIST_ENTRY* entry = head->Flink;
                int ldr_count = 0;
                while (entry != head && ldr_count < 10) {
                    LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                    if (mod->FullDllName.Buffer && mod->FullDllName.Length > 0) {
                        log("  LDR module: base=%p '%.*S'",
                            mod->DllBase,
                            mod->FullDllName.Length / 2,
                            mod->FullDllName.Buffer);
                    }
                    entry = entry->Flink;
                    ldr_count++;
                }
            }
        }
    } else {
        log("NtQueryInformationProcess failed: 0x%08X", (uint32_t)status);
    }

    log("PEB query test complete");
}


void __declspec(noinline) test_dynamic_load_unload(const config_t& cfg) {
    log("Dynamic load/unload test starting...");


    HMODULE hShell32 = LoadLibraryA("shell32.dll");
    if (hShell32) {
        log("Loaded shell32.dll at %p", (void*)hShell32);


        FARPROC fnSHGetFolderPath = GetProcAddress(hShell32, "SHGetFolderPathW");
        FARPROC fnShellExecute = GetProcAddress(hShell32, "ShellExecuteW");
        FARPROC fnSHGetKnownFolderPath = GetProcAddress(hShell32, "SHGetKnownFolderPath");

        log("  SHGetFolderPathW = %p", (void*)fnSHGetFolderPath);
        log("  ShellExecuteW = %p", (void*)fnShellExecute);
        log("  SHGetKnownFolderPath = %p", (void*)fnSHGetKnownFolderPath);

        FreeLibrary(hShell32);
        log("Unloaded shell32.dll");
    } else {
        log("Failed to load shell32.dll: %lu", GetLastError());
    }


    HMODULE hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (hDbgHelp) {
        log("Loaded dbghelp.dll at %p", (void*)hDbgHelp);

        FARPROC fnSymInit = GetProcAddress(hDbgHelp, "SymInitialize");
        FARPROC fnSymCleanup = GetProcAddress(hDbgHelp, "SymCleanup");
        FARPROC fnStackWalk = GetProcAddress(hDbgHelp, "StackWalk64");

        log("  SymInitialize = %p", (void*)fnSymInit);
        log("  SymCleanup = %p", (void*)fnSymCleanup);
        log("  StackWalk64 = %p", (void*)fnStackWalk);

        FreeLibrary(hDbgHelp);
        log("Unloaded dbghelp.dll");
    } else {
        log("Failed to load dbghelp.dll: %lu", GetLastError());
    }


    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (hWinHttp) {
        log("Loaded winhttp.dll at %p", (void*)hWinHttp);

        FARPROC fnOpen = GetProcAddress(hWinHttp, "WinHttpOpen");
        FARPROC fnConnect = GetProcAddress(hWinHttp, "WinHttpConnect");
        log("  WinHttpOpen = %p", (void*)fnOpen);
        log("  WinHttpConnect = %p", (void*)fnConnect);

        FreeLibrary(hWinHttp);
        log("Unloaded winhttp.dll");
    } else {
        log("Failed to load winhttp.dll: %lu", GetLastError());
    }

    log("Dynamic load/unload test complete");
}

#pragma optimize("", on)

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Module tests starting ===");

    test_load_system_dlls(cfg);
    test_resolve_functions(cfg);
    test_call_resolved(cfg);
    test_enumerate_modules(cfg);
    test_enumerate_threads(cfg);
    test_get_peb(cfg);
    test_dynamic_load_unload(cfg);

    log("=== Module tests complete ===");
}

}
}
