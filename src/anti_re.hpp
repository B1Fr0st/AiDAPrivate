#pragma once

#ifdef __NT__

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <thread>
#include <chrono>

#include "vmp.hpp"
#include "obfuscation.hpp"

namespace anti_re {

namespace opaque {

__forceinline uint64_t rdtsc_val()
{
    unsigned int aux;
    return __rdtscp(&aux);
}

__forceinline bool always_true()
{
    volatile uint64_t t = rdtsc_val();
    return (t | 1) != 0;
}

__forceinline bool always_false()
{
    volatile uint64_t t = rdtsc_val();
    return (t & 0) != 0;
}

} // namespace opaque

__forceinline bool check_peb_debugger()
{
    VMP_MUT("are_peb_dbg");
#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    bool detected = false;
    if (peb && peb->BeingDebugged)
        detected = true;
    VMP_END;
    return detected;
}

__forceinline bool check_nt_global_flag()
{
    VMP_MUT("are_ntgf");
#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
    constexpr size_t kOffset = 0xBC;
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
    constexpr size_t kOffset = 0x68;
#endif
    bool detected = false;
    if (peb)
    {
        ULONG flags = *reinterpret_cast<ULONG*>(
            reinterpret_cast<BYTE*>(peb) + kOffset);
        if (flags & 0x70)
            detected = true;
    }
    VMP_END;
    return detected;
}

__forceinline bool check_heap_flags()
{
    VMP_MUT("are_heap");
#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    bool detected = false;
    if (peb)
    {
#ifdef _WIN64
        void* heap = *reinterpret_cast<void**>(
            reinterpret_cast<BYTE*>(peb) + 0x30);
        if (heap)
        {
            DWORD force_flags = *reinterpret_cast<DWORD*>(
                reinterpret_cast<BYTE*>(heap) + 0x74);
            if (force_flags != 0)
                detected = true;
        }
#else
        void* heap = *reinterpret_cast<void**>(
            reinterpret_cast<BYTE*>(peb) + 0x18);
        if (heap)
        {
            DWORD force_flags = *reinterpret_cast<DWORD*>(
                reinterpret_cast<BYTE*>(heap) + 0x44);
            if (force_flags != 0)
                detected = true;
        }
#endif
    }
    VMP_END;
    return detected;
}

__forceinline bool check_hardware_breakpoints()
{
    VMP_MUT("are_hwbp");
    bool detected = false;
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx))
    {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
            detected = true;
    }
    VMP_END;
    return detected;
}

__forceinline bool check_timing_attack()
{
    VMP_MUT("are_timing");
    unsigned int aux;
    uint64_t t1 = __rdtscp(&aux);

    volatile int dummy = 0;
    for (int i = 0; i < 100; ++i)
        dummy += i;

    uint64_t t2 = __rdtscp(&aux);
    uint64_t delta = t2 - t1;

    bool detected = (delta > 10000000ULL);
    VMP_END;
    return detected;
}

__forceinline bool check_nt_query_debug()
{
    VMP_VIRT("are_ntquery");
    bool detected = false;

    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        auto pNtQuery = reinterpret_cast<NtQueryInformationProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (pNtQuery)
        {
            DWORD_PTR debug_port = 0;
            NTSTATUS status = pNtQuery(
                GetCurrentProcess(), 0x07,
                &debug_port, sizeof(debug_port), nullptr);
            if (status == 0 && debug_port != 0)
                detected = true;

            DWORD debug_flags = 0;
            status = pNtQuery(
                GetCurrentProcess(), 0x1F,
                &debug_flags, sizeof(debug_flags), nullptr);
            if (status == 0 && debug_flags == 0)
                detected = true;

            HANDLE debug_object = nullptr;
            status = pNtQuery(
                GetCurrentProcess(), 0x1E,
                &debug_object, sizeof(debug_object), nullptr);
            if (status == 0 && debug_object != nullptr)
            {
                CloseHandle(debug_object);
                detected = true;
            }
        }
    }
    VMP_END;
    return detected;
}

__forceinline bool check_debugger_windows()
{
    VMP_MUT("are_dbgwin");
    bool detected = false;

    if (FindWindowW(L"x64dbg", nullptr) != nullptr)
        detected = true;
    if (FindWindowW(L"OLLYDBG", nullptr) != nullptr)
        detected = true;
    if (FindWindowW(L"WinDbgFrameClass", nullptr) != nullptr)
        detected = true;
    if (FindWindowW(L"TfrmCheatEngine", nullptr) != nullptr)
        detected = true;

    VMP_END;
    return detected;
}

__forceinline bool check_function_hooks()
{
    VMP_VIRT("are_hooks");
    bool detected = false;

    struct check_entry {
        const wchar_t* module;
        const char* func;
    };

    const check_entry checks[] = {
        { L"ntdll.dll",    "NtQueryInformationProcess" },
        { L"ntdll.dll",    "NtSetInformationThread" },
        { L"ntdll.dll",    "NtClose" },
        { L"kernel32.dll", "IsDebuggerPresent" },
        { L"kernel32.dll", "CheckRemoteDebuggerPresent" },
        { L"kernel32.dll", "GetTickCount64" },
        { L"kernel32.dll", "QueryPerformanceCounter" },
    };

    for (const auto& entry : checks)
    {
        HMODULE mod = GetModuleHandleW(entry.module);
        if (!mod)
            continue;

        auto addr = reinterpret_cast<const uint8_t*>(
            GetProcAddress(mod, entry.func));
        if (!addr)
            continue;

        if (addr[0] == 0xE9 || addr[0] == 0xEB || addr[0] == 0xCC)
        {
            detected = true;
            break;
        }
        if (addr[0] == 0xFF && addr[1] == 0x25)
        {
            detected = true;
            break;
        }
    }

    VMP_END;
    return detected;
}

__forceinline bool check_analysis_tools_loaded()
{
    VMP_VIRT("are_analysis_tools");
    bool detected = false;

    const wchar_t* analysis_modules[] = {
        L"ScyllaHide.dll", L"SharpOD.dll",
        L"TitanHide.dll", L"HyperHide.dll",
        L"x64dbg.dll", L"x32dbg.dll",
        L"dbghelp_mod.dll",
    };

    for (const wchar_t* mod_name : analysis_modules)
    {
        if (GetModuleHandleW(mod_name) != nullptr)
        {
            detected = true;
            break;
        }
    }

    VMP_END;
    return detected;
}

__forceinline bool check_thread_hidden_from_debugger()
{
    VMP_VIRT("are_thread_hide");
    bool detected = false;

    using NtSetInformationThread_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        auto pNtSetInfo = reinterpret_cast<NtSetInformationThread_t>(
            GetProcAddress(ntdll, "NtSetInformationThread"));
        if (pNtSetInfo)
        {
            constexpr ULONG ThreadHideFromDebugger = 0x11;
            NTSTATUS status = pNtSetInfo(
                GetCurrentThread(), ThreadHideFromDebugger,
                nullptr, 0);
            if (status != 0)
                detected = true;
        }
    }

    VMP_END;
    return detected;
}

__forceinline bool check_remote_debugger()
{
    VMP_MUT("are_remote_dbg");
    bool detected = false;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote))
    {
        if (remote)
            detected = true;
    }
    VMP_END;
    return detected;
}

__forceinline bool check_debug_object_count()
{
    VMP_VIRT("are_dbg_obj_count");
    bool detected = false;

    using NtQueryObject_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        auto pNtQueryObject = reinterpret_cast<NtQueryObject_t>(
            GetProcAddress(ntdll, "NtQueryObject"));
        if (pNtQueryObject)
        {
            struct OBJECT_TYPE_INFORMATION_AIDA {
                UNICODE_STRING TypeName;
                ULONG TotalNumberOfObjects;
                ULONG TotalNumberOfHandles;
            };

            constexpr ULONG ObjectTypeInformation = 2;
            HANDLE debug_object = nullptr;

            using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
                HANDLE, ULONG, PVOID, ULONG, PULONG);
            auto pNtQuery = reinterpret_cast<NtQueryInformationProcess_t>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
            if (pNtQuery)
            {
                NTSTATUS status = pNtQuery(
                    GetCurrentProcess(), 0x1E,
                    &debug_object, sizeof(debug_object), nullptr);
                if (status == 0 && debug_object != nullptr)
                {
                    detected = true;
                    CloseHandle(debug_object);
                }
            }
        }
    }

    VMP_END;
    return detected;
}

__forceinline bool check_kernel_debugger()
{
    VMP_MUT("are_kd");
    bool detected = false;

    using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
        ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        auto pNtQuerySys = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (pNtQuerySys)
        {
            struct SYSTEM_KERNEL_DEBUGGER_INFORMATION_AIDA {
                BOOLEAN DebuggerEnabled;
                BOOLEAN DebuggerNotPresent;
            };

            constexpr ULONG SystemKernelDebuggerInformation = 0x23;
            SYSTEM_KERNEL_DEBUGGER_INFORMATION_AIDA kdi = {};
            NTSTATUS status = pNtQuerySys(
                SystemKernelDebuggerInformation,
                &kdi, sizeof(kdi), nullptr);
            if (status == 0 && kdi.DebuggerEnabled && !kdi.DebuggerNotPresent)
                detected = true;
        }
    }

    VMP_END;
    return detected;
}

__forceinline bool check_software_breakpoints_on_self()
{
    VMP_VIRT("are_swbp_self");
    bool detected = false;

    HMODULE self = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&check_software_breakpoints_on_self),
        &self);

    if (self)
    {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(self);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(dos) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
            {
                auto section = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
                {
                    if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    {
                        const uint8_t* code = reinterpret_cast<const uint8_t*>(self)
                            + section->VirtualAddress;
                        size_t code_size = section->Misc.VirtualSize;
                        size_t cc_count = 0;
                        for (size_t j = 0; j < code_size && j < 0x100000; ++j)
                        {
                            if (code[j] == 0xCC)
                                ++cc_count;
                        }
                        if (cc_count > 16)
                        {
                            detected = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    VMP_END;
    return detected;
}

__forceinline void corrupt_pe_header_for_anti_dump()
{
    VMP_MUT("are_antidump");
    HMODULE self = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&corrupt_pe_header_for_anti_dump),
        &self);

    if (self)
    {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(self);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(dos) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
            {
                DWORD old_protect = 0;
                if (VirtualProtect(nt, sizeof(IMAGE_NT_HEADERS),
                                   PAGE_READWRITE, &old_protect))
                {
                    nt->OptionalHeader.AddressOfEntryPoint = 0;
                    nt->FileHeader.TimeDateStamp = 0;
                    nt->OptionalHeader.MajorLinkerVersion = 0;
                    nt->OptionalHeader.MinorLinkerVersion = 0;
                    nt->OptionalHeader.MajorOperatingSystemVersion = 0;
                    nt->OptionalHeader.MinorOperatingSystemVersion = 0;

                    VirtualProtect(nt, sizeof(IMAGE_NT_HEADERS),
                                   old_protect, &old_protect);
                }
            }
        }
    }
    VMP_END;
}

__forceinline bool check_image_crc()
{
    VMP_VIRT("are_crc");
    bool valid = VMP_IS_VALID_CRC;
    VMP_END;
    return valid;
}

struct AIDA_PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

__forceinline bool check_parent_process()
{
    VMP_MUT("are_parent");
    bool suspicious = false;

    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        VMP_END;
        return false;
    }

    auto pNtQuery = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!pNtQuery)
    {
        VMP_END;
        return false;
    }

    AIDA_PROCESS_BASIC_INFORMATION pbi = {};
    NTSTATUS status = pNtQuery(
        GetCurrentProcess(), 0,
        &pbi, sizeof(pbi), nullptr);

    if (status == 0 && pbi.InheritedFromUniqueProcessId != 0)
    {
        HANDLE parent = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            static_cast<DWORD>(pbi.InheritedFromUniqueProcessId));
        if (parent)
        {
            wchar_t path[MAX_PATH] = {};
            DWORD path_len = MAX_PATH;
            if (QueryFullProcessImageNameW(parent, 0, path, &path_len))
            {
                for (DWORD i = 0; i < path_len; ++i)
                    path[i] = static_cast<wchar_t>(towlower(path[i]));

                const wchar_t* bad_parents[] = {
                    L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe",
                    L"windbg.exe", L"devenv.exe", L"dnspy.exe",
                    L"de4dot.exe", L"ilspy.exe",
                };
                for (const wchar_t* bad : bad_parents)
                {
                    if (wcsstr(path, bad) != nullptr)
                    {
                        suspicious = true;
                        break;
                    }
                }
            }
            CloseHandle(parent);
        }
    }

    VMP_END;
    return suspicious;
}

__declspec(noinline) static bool check_trap_flag()
{
    __try
    {
        __debugbreak();
        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT
                  ? EXCEPTION_EXECUTE_HANDLER
                  : EXCEPTION_CONTINUE_SEARCH)
    {
        return false;
    }
}

__declspec(noinline) static bool check_close_handle_trick()
{
    __try
    {
        CloseHandle(reinterpret_cast<HANDLE>(0xDEADBEEFULL));
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return true;
    }
}

__declspec(noinline) inline void terminate_with_prejudice()
{
    VMP_ULTRA("are_terminate");

    __fastfail(FAST_FAIL_FATAL_APP_EXIT);

    TerminateProcess(GetCurrentProcess(), 0xDEADu);

    volatile int* p = nullptr;
    *p = 0x41694441;

    for (;;) { __nop(); }

    VMP_END;
}

__forceinline bool run_all_checks()
{
    VMP_ULTRA("are_master");

    if (VMP_IS_DEBUGGER(true))
    {
        VMP_END;
        return false;
    }

    if (VMP_IS_VIRTUAL_MACHINE)
    {
        VMP_END;
        return false;
    }

    if (!check_image_crc())
    {
        VMP_END;
        return false;
    }

    if (check_peb_debugger())
    {
        VMP_END;
        return false;
    }

    if (check_nt_global_flag())
    {
        VMP_END;
        return false;
    }

    if (check_heap_flags())
    {
        VMP_END;
        return false;
    }

    if (check_hardware_breakpoints())
    {
        VMP_END;
        return false;
    }

    if (check_nt_query_debug())
    {
        VMP_END;
        return false;
    }

    if (check_timing_attack())
    {
        VMP_END;
        return false;
    }

    if (check_function_hooks())
    {
        VMP_END;
        return false;
    }

    if (check_debugger_windows())
    {
        VMP_END;
        return false;
    }

    if (check_close_handle_trick())
    {
        VMP_END;
        return false;
    }

    if (check_parent_process())
    {
        VMP_END;
        return false;
    }

    if (check_remote_debugger())
    {
        VMP_END;
        return false;
    }

    if (check_debug_object_count())
    {
        VMP_END;
        return false;
    }

    if (check_kernel_debugger())
    {
        VMP_END;
        return false;
    }

    if (check_software_breakpoints_on_self())
    {
        VMP_END;
        return false;
    }

    VMP_END;
    return true;
}

__forceinline bool run_fast_checks()
{
    VMP_MUT("are_fast");

    if (VMP_IS_DEBUGGER(false))
    {
        VMP_END;
        return false;
    }

    if (check_peb_debugger())
    {
        VMP_END;
        return false;
    }

    if (check_nt_global_flag())
    {
        VMP_END;
        return false;
    }

    if (check_hardware_breakpoints())
    {
        VMP_END;
        return false;
    }

    VMP_END;
    return true;
}

inline std::atomic<bool> g_sentinel_tripped{false};

inline int idaapi sentinel_timer_callback(void* /*ud*/)
{
    VMP_VIRT("are_sentinel");

    if (!run_fast_checks())
    {
        g_sentinel_tripped.store(true, std::memory_order_release);
        terminate_with_prejudice();
        VMP_END;
        return -1;
    }

    static int call_count = 0;
    if (++call_count % 5 == 0)
    {
        if (!run_all_checks())
        {
            g_sentinel_tripped.store(true, std::memory_order_release);
            terminate_with_prejudice();
            VMP_END;
            return -1;
        }
    }

    VMP_END;
    return 30000;
}

__forceinline void erase_pe_data_directories()
{
    VMP_MUT("are_erase_dd");
    HMODULE self = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&erase_pe_data_directories),
        &self);

    if (self)
    {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(self);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(dos) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
            {
                DWORD old_protect = 0;
                size_t total_hdr_size = dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)
                    + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

                if (VirtualProtect(dos, total_hdr_size,
                                   PAGE_READWRITE, &old_protect))
                {
                    for (DWORD i = 0; i < nt->OptionalHeader.NumberOfRvaAndSizes; ++i)
                    {
                        if (i == IMAGE_DIRECTORY_ENTRY_EXPORT
                            || i == IMAGE_DIRECTORY_ENTRY_IMPORT
                            || i == IMAGE_DIRECTORY_ENTRY_EXCEPTION
                            || i == IMAGE_DIRECTORY_ENTRY_BASERELOC
                            || i == IMAGE_DIRECTORY_ENTRY_TLS
                            || i == IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
                            || i == IMAGE_DIRECTORY_ENTRY_IAT
                            || i == IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
                            continue;

                        nt->OptionalHeader.DataDirectory[i].VirtualAddress = 0;
                        nt->OptionalHeader.DataDirectory[i].Size = 0;
                    }

                    VirtualProtect(dos, total_hdr_size,
                                   old_protect, &old_protect);
                }
            }
        }
    }
    VMP_END;
}

__forceinline void wipe_dos_stub()
{
    VMP_MUT("are_wipe_dos");
    HMODULE self = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&wipe_dos_stub),
        &self);

    if (self)
    {
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(self);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > sizeof(IMAGE_DOS_HEADER))
        {
            DWORD old_protect = 0;
            size_t stub_size = static_cast<size_t>(dos->e_lfanew) - sizeof(IMAGE_DOS_HEADER);
            BYTE* stub_start = reinterpret_cast<BYTE*>(dos) + sizeof(IMAGE_DOS_HEADER);

            if (VirtualProtect(stub_start, stub_size,
                               PAGE_READWRITE, &old_protect))
            {
                SecureZeroMemory(stub_start, stub_size);
                VirtualProtect(stub_start, stub_size,
                               old_protect, &old_protect);
            }
        }
    }
    VMP_END;
}

__forceinline void hide_current_thread_from_debugger()
{
    VMP_MUT("are_hide_thread");
    using NtSetInformationThread_t = NTSTATUS(NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll)
    {
        auto pNtSetInfo = reinterpret_cast<NtSetInformationThread_t>(
            GetProcAddress(ntdll, "NtSetInformationThread"));
        if (pNtSetInfo)
        {
            constexpr ULONG ThreadHideFromDebugger = 0x11;
            pNtSetInfo(GetCurrentThread(), ThreadHideFromDebugger, nullptr, 0);
        }
    }
    VMP_END;
}

struct AIDA_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

__forceinline void scramble_module_name_in_peb()
{
    VMP_ULTRA("are_scramble_peb");
    HMODULE self = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&scramble_module_name_in_peb),
        &self);

    if (!self)
    {
        VMP_END;
        return;
    }

#ifdef _WIN64
    PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (!peb || !peb->Ldr)
    {
        VMP_END;
        return;
    }

    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head)
    {
        auto* entry = reinterpret_cast<AIDA_LDR_DATA_TABLE_ENTRY*>(
            reinterpret_cast<BYTE*>(current) - offsetof(AIDA_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        if (entry->DllBase == self)
        {
            if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
            {
                for (USHORT i = 0; i < entry->FullDllName.Length / sizeof(wchar_t); ++i)
                    entry->FullDllName.Buffer[i] = static_cast<wchar_t>(L'A' + (i % 26));
            }
            if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
            {
                for (USHORT i = 0; i < entry->BaseDllName.Length / sizeof(wchar_t); ++i)
                    entry->BaseDllName.Buffer[i] = static_cast<wchar_t>(L'a' + (i % 26));
            }
            break;
        }
        current = current->Flink;
    }

    VMP_END;
}

inline void initialize()
{
    VMP_ULTRA("are_init");

    if (!run_all_checks())
    {
        terminate_with_prejudice();
        VMP_END;
        return;
    }

    corrupt_pe_header_for_anti_dump();
    erase_pe_data_directories();
    wipe_dos_stub();
    scramble_module_name_in_peb();
    register_timer(30000, sentinel_timer_callback, nullptr);

    VMP_END;
}

#define ANTI_RE_GUARD() do { \
    VMP_MUT("arg_" __FUNCTION__); \
    if (!::anti_re::run_fast_checks()) { \
        ::anti_re::terminate_with_prejudice(); \
    } \
    if (::anti_re::g_sentinel_tripped.load(std::memory_order_acquire)) { \
        ::anti_re::terminate_with_prejudice(); \
    } \
    VMP_END; \
} while (0)

#define ANTI_RE_GUARD_OPAQUE() do { \
    VMP_MUT("argo_" __FUNCTION__); \
    if (::anti_re::opaque::always_true()) { \
        if (!::anti_re::run_fast_checks()) { \
            ::anti_re::terminate_with_prejudice(); \
        } \
    } \
    if (::anti_re::opaque::always_false()) { \
        volatile int* _p = nullptr; *_p = 0; \
    } \
    VMP_END; \
} while (0)

} // namespace anti_re

#else // !__NT__

namespace anti_re {

inline void initialize() {}

inline bool run_all_checks() { return true; }
inline bool run_fast_checks() { return true; }
inline void terminate_with_prejudice() { _exit(1); }

inline std::atomic<bool> g_sentinel_tripped{false};

#define ANTI_RE_GUARD() ((void)0)
#define ANTI_RE_GUARD_OPAQUE() ((void)0)

} // namespace anti_re

#endif // __NT__
