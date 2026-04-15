#pragma once

#include <windows.h>
#include <intrin.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace anti_tamper {
namespace syscall {

namespace detail {

    struct syscall_stub_t
    {
        uint32_t ssn;
        void*    stub_addr;
    };

    struct syscall_table_t
    {
        syscall_stub_t NtQueryInformationProcess;
        syscall_stub_t NtQuerySystemInformation;
        syscall_stub_t NtQueryVirtualMemory;
        syscall_stub_t NtSetInformationThread;
        syscall_stub_t NtQueryInformationThread;
        syscall_stub_t NtClose;
        syscall_stub_t NtRaiseHardError;
        syscall_stub_t RtlAdjustPrivilege;
        void*          stub_page;
        uint32_t       stub_offset;
        bool           initialized;
    };

    inline syscall_table_t& table()
    {
        static syscall_table_t t{};
        return t;
    }

    inline std::mutex& init_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline uint32_t extract_ssn_from_bytes(const uint8_t* func_bytes)
    {
        if (func_bytes[0] == 0x4C && func_bytes[1] == 0x8B && func_bytes[2] == 0xD1
            && func_bytes[3] == 0xB8)
        {
            return *reinterpret_cast<const uint32_t*>(func_bytes + 4);
        }

        if (func_bytes[0] == 0xE9 || func_bytes[0] == 0xEB)
        {
            for (int offset = 0; offset < 32; ++offset)
            {
                if (func_bytes[offset] == 0x4C && func_bytes[offset + 1] == 0x8B
                    && func_bytes[offset + 2] == 0xD1 && func_bytes[offset + 3] == 0xB8)
                {
                    return *reinterpret_cast<const uint32_t*>(func_bytes + offset + 4);
                }
            }
        }

        return 0xFFFFFFFF;
    }

    inline void* build_stub(void* page, uint32_t& offset, uint32_t ssn)
    {
        auto* base = static_cast<uint8_t*>(page) + offset;

        base[0] = 0x4C; base[1] = 0x8B; base[2] = 0xD1;
        base[3] = 0xB8;
        memcpy(base + 4, &ssn, 4);
        base[8] = 0x0F; base[9] = 0x05;
        base[10] = 0xC3;

        offset += 16;
        return base;
    }

    inline bool resolve_from_disk_ntdll(const char* func_name, uint32_t& ssn_out,
                                        const uint8_t** disk_bytes_out = nullptr)
    {
        wchar_t sys_path[MAX_PATH];
        GetSystemDirectoryW(sys_path, MAX_PATH);
        wcscat_s(sys_path, L"\\ntdll.dll");

        HANDLE hFile = CreateFileW(sys_path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) { CloseHandle(hFile); return false; }

        auto* mapped = static_cast<const uint8_t*>(
            MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!mapped)
        {
            CloseHandle(hMap);
            CloseHandle(hFile);
            return false;
        }

        bool found = false;

        __try
        {
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;

            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(mapped + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

            auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exp_dir.VirtualAddress == 0) goto cleanup;

            auto rva_to_offset = [&](uint32_t rva) -> uint32_t {
                auto* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
                {
                    if (rva >= sec[i].VirtualAddress &&
                        rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                    {
                        return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
                    }
                }
                return 0;
            };

            uint32_t exp_offset = rva_to_offset(exp_dir.VirtualAddress);
            if (exp_offset == 0) goto cleanup;

            auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(mapped + exp_offset);

            uint32_t names_off  = rva_to_offset(exports->AddressOfNames);
            uint32_t funcs_off  = rva_to_offset(exports->AddressOfFunctions);
            uint32_t ords_off   = rva_to_offset(exports->AddressOfNameOrdinals);
            if (!names_off || !funcs_off || !ords_off) goto cleanup;

            auto* names = reinterpret_cast<const uint32_t*>(mapped + names_off);
            auto* funcs = reinterpret_cast<const uint32_t*>(mapped + funcs_off);
            auto* ords  = reinterpret_cast<const uint16_t*>(mapped + ords_off);

            for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
            {
                uint32_t name_off = rva_to_offset(names[i]);
                if (!name_off) continue;

                const char* exp_name = reinterpret_cast<const char*>(mapped + name_off);
                if (strcmp(exp_name, func_name) != 0) continue;

                uint16_t ordinal = ords[i];
                uint32_t func_rva = funcs[ordinal];
                uint32_t func_file_offset = rva_to_offset(func_rva);
                if (!func_file_offset) break;

                const uint8_t* func_bytes = mapped + func_file_offset;
                ssn_out = extract_ssn_from_bytes(func_bytes);
                found = (ssn_out != 0xFFFFFFFF);
                break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            found = false;
        }

    cleanup:
        UnmapViewOfFile(mapped);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return found;
    }

    inline bool compare_ntdll_function(const char* func_name, bool& is_hooked)
    {
        is_hooked = false;

        HMODULE mem_ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!mem_ntdll) return false;

        auto* mem_func = reinterpret_cast<const uint8_t*>(
            GetProcAddress(mem_ntdll, func_name));
        if (!mem_func) return false;

        wchar_t sys_path[MAX_PATH];
        GetSystemDirectoryW(sys_path, MAX_PATH);
        wcscat_s(sys_path, L"\\ntdll.dll");

        HANDLE hFile = CreateFileW(sys_path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) { CloseHandle(hFile); return false; }

        auto* mapped = static_cast<const uint8_t*>(
            MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
        if (!mapped)
        {
            CloseHandle(hMap);
            CloseHandle(hFile);
            return false;
        }

        bool result = false;

        __try
        {
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done;

            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(mapped + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) goto done;

            auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exp_dir.VirtualAddress == 0) goto done;

            {
                auto rva_to_offset = [&](uint32_t rva) -> uint32_t {
                    auto* sec = IMAGE_FIRST_SECTION(nt);
                    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
                    {
                        if (rva >= sec[i].VirtualAddress &&
                            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
                    }
                    return 0;
                };

                uint32_t exp_offset = rva_to_offset(exp_dir.VirtualAddress);
                if (exp_offset == 0) goto done;

                auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(mapped + exp_offset);
                uint32_t names_off  = rva_to_offset(exports->AddressOfNames);
                uint32_t funcs_off  = rva_to_offset(exports->AddressOfFunctions);
                uint32_t ords_off   = rva_to_offset(exports->AddressOfNameOrdinals);
                if (!names_off || !funcs_off || !ords_off) goto done;

                auto* names = reinterpret_cast<const uint32_t*>(mapped + names_off);
                auto* funcs = reinterpret_cast<const uint32_t*>(mapped + funcs_off);
                auto* ords  = reinterpret_cast<const uint16_t*>(mapped + ords_off);

                for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
                {
                    uint32_t name_off = rva_to_offset(names[i]);
                    if (!name_off) continue;

                    const char* exp_name = reinterpret_cast<const char*>(mapped + name_off);
                    if (strcmp(exp_name, func_name) != 0) continue;

                    uint16_t ordinal = ords[i];
                    uint32_t func_rva = funcs[ordinal];
                    uint32_t func_file_offset = rva_to_offset(func_rva);
                    if (!func_file_offset) break;

                    const uint8_t* disk_bytes = mapped + func_file_offset;

                    result = true;
                    is_hooked = (memcmp(mem_func, disk_bytes, 16) != 0);
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result = false;
        }

    done:
        UnmapViewOfFile(mapped);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return result;
    }

    inline bool resolve_stub(const char* func_name, syscall_stub_t& out)
    {
        auto& t = table();
        uint32_t ssn = 0;
        if (!resolve_from_disk_ntdll(func_name, ssn))
            return false;

        out.ssn = ssn;
        out.stub_addr = build_stub(t.stub_page, t.stub_offset, ssn);
        return true;
    }

}

using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength);

using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

using NtQueryVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    ULONG MemoryInformationClass, PVOID MemoryInformation,
    SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

using NtSetInformationThread_t = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);

using NtQueryInformationThread_t = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);

using NtClose_t = NTSTATUS(NTAPI*)(HANDLE Handle);

using NtRaiseHardError_t = NTSTATUS(NTAPI*)(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask, PULONG_PTR Parameters,
    ULONG ValidResponseOption, PULONG Response);

using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(
    ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);

inline bool initialize()
{
    std::lock_guard<std::mutex> lk(detail::init_mtx());
    auto& t = detail::table();
    if (t.initialized) return true;

    t.stub_page = VirtualAlloc(nullptr, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!t.stub_page) return false;

    t.stub_offset = 0;

    bool ok = true;
    ok &= detail::resolve_stub("NtQueryInformationProcess", t.NtQueryInformationProcess);
    ok &= detail::resolve_stub("NtQuerySystemInformation",  t.NtQuerySystemInformation);
    ok &= detail::resolve_stub("NtQueryVirtualMemory",      t.NtQueryVirtualMemory);
    ok &= detail::resolve_stub("NtSetInformationThread",    t.NtSetInformationThread);
    ok &= detail::resolve_stub("NtQueryInformationThread",  t.NtQueryInformationThread);
    ok &= detail::resolve_stub("NtClose",                   t.NtClose);
    ok &= detail::resolve_stub("NtRaiseHardError",          t.NtRaiseHardError);
    ok &= detail::resolve_stub("RtlAdjustPrivilege",        t.RtlAdjustPrivilege);

    if (ok)
    {
        DWORD old_protect;
        VirtualProtect(t.stub_page, 4096, PAGE_EXECUTE_READ, &old_protect);
    }

    t.initialized = ok;
    return ok;
}

inline NtQueryInformationProcess_t NtQueryInformationProcess()
{
    return reinterpret_cast<NtQueryInformationProcess_t>(
        detail::table().NtQueryInformationProcess.stub_addr);
}

inline NtQuerySystemInformation_t NtQuerySystemInformation()
{
    return reinterpret_cast<NtQuerySystemInformation_t>(
        detail::table().NtQuerySystemInformation.stub_addr);
}

inline NtQueryVirtualMemory_t NtQueryVirtualMemory()
{
    return reinterpret_cast<NtQueryVirtualMemory_t>(
        detail::table().NtQueryVirtualMemory.stub_addr);
}

inline NtSetInformationThread_t NtSetInformationThread()
{
    return reinterpret_cast<NtSetInformationThread_t>(
        detail::table().NtSetInformationThread.stub_addr);
}

inline NtQueryInformationThread_t NtQueryInformationThread()
{
    return reinterpret_cast<NtQueryInformationThread_t>(
        detail::table().NtQueryInformationThread.stub_addr);
}

inline NtClose_t NtClose()
{
    return reinterpret_cast<NtClose_t>(
        detail::table().NtClose.stub_addr);
}

inline NtRaiseHardError_t NtRaiseHardError()
{
    return reinterpret_cast<NtRaiseHardError_t>(
        detail::table().NtRaiseHardError.stub_addr);
}

inline RtlAdjustPrivilege_t RtlAdjustPrivilege()
{
    return reinterpret_cast<RtlAdjustPrivilege_t>(
        detail::table().RtlAdjustPrivilege.stub_addr);
}

inline bool is_initialized()
{
    return detail::table().initialized;
}

inline bool detect_ntdll_hooks(std::string& hooked_func)
{
    const char* critical_funcs[] = {
        "NtQueryInformationProcess",
        "NtQuerySystemInformation",
        "NtSetInformationThread",
        "NtClose",
        "NtProtectVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "LdrLoadDll",
        "NtCreateFile",
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtQueryVirtualMemory",
    };

    for (const auto& fn : critical_funcs)
    {
        bool is_hooked = false;
        if (detail::compare_ntdll_function(fn, is_hooked) && is_hooked)
        {
            hooked_func = fn;
            return true;
        }
    }
    return false;
}

inline void shutdown()
{
    auto& t = detail::table();
    if (t.stub_page)
    {
        VirtualFree(t.stub_page, 0, MEM_RELEASE);
        t.stub_page = nullptr;
    }
    t.initialized = false;
}

}
}
