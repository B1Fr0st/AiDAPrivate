#pragma once

#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "../../../obfuscation.hpp"

#pragma comment(lib, "ntdll.lib")

namespace anti_tamper {
namespace anti_dump
{

namespace detail
{

    struct region_t
    {
        uint64_t base;
        uint32_t size;
        uint32_t original_protect;
    };

    inline std::vector<region_t>& encrypted_regions()
    {
        static std::vector<region_t> v;
        return v;
    }

    inline std::mutex& region_mutex()
    {
        static std::mutex m;
        return m;
    }

    inline std::atomic<bool>& active()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<bool>& monitors_running()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline uint64_t& xor_key()
    {
        static uint64_t k = 0;
        return k;
    }

    inline uint64_t generate_session_key()
    {
        uint64_t k = __rdtsc();
        k ^= (k << 13);
        k ^= (k >> 7);
        k ^= (k << 17);
        k ^= GetCurrentProcessId();
        k ^= reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        if (k == 0) k = 0xDEADC0DEBEEFCAFEULL;
        return k;
    }

    inline void xor_region(uint8_t* base, uint32_t size, uint64_t key)
    {
        uint64_t* ptr64 = reinterpret_cast<uint64_t*>(base);
        uint32_t count64 = size / 8;
        uint64_t rolling = key;
        for (uint32_t i = 0; i < count64; ++i)
        {
            ptr64[i] ^= rolling;
            rolling = _rotl64(rolling, 13) ^ (rolling + i);
        }
        uint32_t remain = size % 8;
        uint8_t* tail = base + count64 * 8;
        uint8_t kb[8];
        memcpy(kb, &rolling, 8);
        for (uint32_t i = 0; i < remain; ++i)
            tail[i] ^= kb[i];
    }

}


namespace pe_header
{

    inline bool erase_dos_header()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        DWORD e_lfanew = dos->e_lfanew;

        DWORD old_prot = 0;
        if (!VirtualProtect(base, e_lfanew, PAGE_READWRITE, &old_prot))
            return false;

        uint16_t saved_magic = dos->e_magic;
        uint32_t saved_lfanew = dos->e_lfanew;

        volatile uint8_t* vb = reinterpret_cast<volatile uint8_t*>(base);
        for (DWORD i = 0; i < e_lfanew; ++i)
        {
            vb[i] = static_cast<uint8_t>(__rdtsc() & 0xFF);
        }

        auto* new_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        new_dos->e_magic = 0;
        new_dos->e_lfanew = static_cast<LONG>(e_lfanew);

        VirtualProtect(base, e_lfanew, old_prot, &old_prot);
        return true;
    }

    inline bool corrupt_nt_headers()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        uint32_t nt_offset = dos->e_lfanew;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + nt_offset);

        DWORD nt_size = sizeof(IMAGE_NT_HEADERS64);
        WORD num_sections = nt->FileHeader.NumberOfSections;
        DWORD total = nt_size + num_sections * sizeof(IMAGE_SECTION_HEADER);

        DWORD old_prot = 0;
        if (!VirtualProtect(nt, total, PAGE_READWRITE, &old_prot))
            return false;

        nt->Signature = 0;
        nt->OptionalHeader.Magic = 0;
        nt->OptionalHeader.AddressOfEntryPoint = 0xDEADDEAD;
        nt->OptionalHeader.ImageBase = 0;
        nt->OptionalHeader.SizeOfImage = 0;
        nt->OptionalHeader.SizeOfHeaders = 0;
        nt->OptionalHeader.CheckSum = 0xFFFFFFFF;

        nt->FileHeader.SizeOfOptionalHeader = 0;
        nt->FileHeader.Machine = 0;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < num_sections; ++i)
        {
            memset(sec[i].Name, 0, IMAGE_SIZEOF_SHORT_NAME);
            sec[i].VirtualAddress = 0;
            sec[i].Misc.VirtualSize = 0;
            sec[i].PointerToRawData = 0;
            sec[i].SizeOfRawData = 0;
            sec[i].Characteristics = 0;
        }

        nt->OptionalHeader.NumberOfRvaAndSizes = 0;
        memset(nt->OptionalHeader.DataDirectory, 0,
               sizeof(nt->OptionalHeader.DataDirectory));

        VirtualProtect(nt, total, old_prot, &old_prot);
        return true;
    }

    inline bool inject_fake_sections()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

        DWORD total = sizeof(IMAGE_NT_HEADERS64)
            + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

        DWORD old_prot = 0;
        if (!VirtualProtect(nt, total + 256, PAGE_READWRITE, &old_prot))
            return false;

        nt->FileHeader.NumberOfSections = 0xFF;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < 8; ++i)
        {
            char fake_name[IMAGE_SIZEOF_SHORT_NAME] = {};
            snprintf(fake_name, IMAGE_SIZEOF_SHORT_NAME, ".x%d%c", i, 'A' + (i % 26));
            memcpy(sec[i].Name, fake_name, IMAGE_SIZEOF_SHORT_NAME);
            sec[i].VirtualAddress = static_cast<DWORD>(__rdtsc() & 0x7FFFFFFF);
            sec[i].Misc.VirtualSize = static_cast<DWORD>(__rdtsc() & 0xFFFF) + 0x1000;
            sec[i].PointerToRawData = static_cast<DWORD>(__rdtsc() & 0x7FFFFFFF);
            sec[i].SizeOfRawData = sec[i].Misc.VirtualSize;
            sec[i].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
        }

        VirtualProtect(nt, total + 256, old_prot, &old_prot);
        return true;
    }

}


namespace module_stealth
{

    struct _PEB_LDR_DATA_FULL
    {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    };

    struct _LDR_DATA_TABLE_ENTRY_FULL
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    };

    inline void unlink_entry(LIST_ENTRY* entry)
    {
        entry->Blink->Flink = entry->Flink;
        entry->Flink->Blink = entry->Blink;
        entry->Flink = entry;
        entry->Blink = entry;
    }

    inline bool hide_from_peb()
    {
        auto* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
        if (!peb || !peb->Ldr) return false;

        auto* ldr = reinterpret_cast<_PEB_LDR_DATA_FULL*>(peb->Ldr);
        HMODULE our_mod = GetModuleHandleW(nullptr);
        if (!our_mod) return false;

        auto* head = &ldr->InLoadOrderModuleList;
        auto* cur = head->Flink;

        while (cur != head)
        {
            auto* entry = CONTAINING_RECORD(cur, _LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
            if (entry->DllBase == our_mod)
            {
                unlink_entry(&entry->InLoadOrderLinks);
                unlink_entry(&entry->InMemoryOrderLinks);
                unlink_entry(&entry->InInitializationOrderLinks);

                if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
                {
                    memset(entry->FullDllName.Buffer, 0, entry->FullDllName.Length);
                    entry->FullDllName.Length = 0;
                    entry->FullDllName.MaximumLength = 0;
                }
                if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
                {
                    memset(entry->BaseDllName.Buffer, 0, entry->BaseDllName.Length);
                    entry->BaseDllName.Length = 0;
                    entry->BaseDllName.MaximumLength = 0;
                }

                entry->DllBase = nullptr;
                entry->EntryPoint = nullptr;
                entry->SizeOfImage = 0;

                return true;
            }
            cur = cur->Flink;
        }
        return false;
    }

}


namespace read_intercept
{

    inline PVOID veh_handle = nullptr;
    inline std::atomic<uint64_t> trap_page_base{0};
    inline std::atomic<uint32_t> trap_page_size{0};

    inline LONG CALLBACK guard_page_handler(EXCEPTION_POINTERS* ep)
    {
        if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        {
            uint64_t fault_addr = static_cast<uint64_t>(
                ep->ExceptionRecord->ExceptionInformation[1]);
            uint64_t base = trap_page_base.load();
            uint32_t size = trap_page_size.load();

            if (base != 0 && fault_addr >= base && fault_addr < base + size)
            {
                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        if (ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
        {
            uint64_t base = trap_page_base.load();
            uint32_t size = trap_page_size.load();

            if (base != 0 && size != 0)
            {
                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(base), size,
                    PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    inline bool set_guard_pages()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base_ptr = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_ptr);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE && dos->e_magic != 0)
        {
            auto* nt_at_offset = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                base_ptr + dos->e_lfanew);

            MODULEINFO mi{};
            GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

            uint64_t header_end = reinterpret_cast<uint64_t>(mod) + 0x1000;
            uint64_t data_start = header_end;
            uint64_t data_end = reinterpret_cast<uint64_t>(mod) + mi.SizeOfImage;

            MEMORY_BASIC_INFORMATION mbi{};
            uint64_t scan = data_start;
            while (scan < data_end)
            {
                if (VirtualQuery(reinterpret_cast<void*>(scan), &mbi, sizeof(mbi)) == 0)
                    break;

                if (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE)
                {
                    trap_page_base.store(reinterpret_cast<uint64_t>(mbi.BaseAddress));
                    trap_page_size.store(static_cast<uint32_t>(mbi.RegionSize));

                    DWORD old_prot;
                    VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                        mbi.Protect | PAGE_GUARD, &old_prot);
                }

                scan = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
            }
        }
        return true;
    }

    inline bool install_veh()
    {
        if (veh_handle) return true;
        veh_handle = AddVectoredExceptionHandler(1, guard_page_handler);
        return veh_handle != nullptr;
    }

    inline void remove_veh()
    {
        if (veh_handle)
        {
            RemoveVectoredExceptionHandler(veh_handle);
            veh_handle = nullptr;
        }
    }

}


namespace section_encrypt
{

    inline bool encrypt_non_code_sections()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

        auto* base = reinterpret_cast<uint8_t*>(mod);
        uint64_t mod_base = reinterpret_cast<uint64_t>(mod);
        uint64_t mod_end = mod_base + mi.SizeOfImage;

        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t addr = mod_base + 0x1000;

        while (addr < mod_end)
        {
            if (VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) == 0)
                break;

            uint64_t region_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            uint32_t region_size = static_cast<uint32_t>(mbi.RegionSize);

            if (mbi.State == MEM_COMMIT
                && (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE)
                && !(mbi.Protect & PAGE_GUARD)
                && region_size >= 0x100)
            {
                DWORD old_prot = 0;
                if (VirtualProtect(reinterpret_cast<void*>(region_base), region_size,
                    PAGE_READWRITE, &old_prot))
                {
                    detail::xor_region(reinterpret_cast<uint8_t*>(region_base),
                        region_size, detail::xor_key());

                    VirtualProtect(reinterpret_cast<void*>(region_base), region_size,
                        old_prot, &old_prot);

                    std::lock_guard<std::mutex> lk(detail::region_mutex());
                    detail::encrypted_regions().push_back({region_base, region_size, old_prot});
                }
            }

            addr = region_base + region_size;
        }

        return true;
    }

    inline void decrypt_region_temporary(uint64_t addr, uint32_t size)
    {
        DWORD old_prot = 0;
        VirtualProtect(reinterpret_cast<void*>(addr), size, PAGE_READWRITE, &old_prot);
        detail::xor_region(reinterpret_cast<uint8_t*>(addr), size, detail::xor_key());
        VirtualProtect(reinterpret_cast<void*>(addr), size, old_prot, &old_prot);
    }

}


namespace dump_poison
{

    inline void flood_decoy_memory()
    {
        for (int i = 0; i < 32; ++i)
        {
            SIZE_T alloc_size = (1 << 14) + ((__rdtsc() & 0x3FFF));
            void* block = VirtualAlloc(nullptr, alloc_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (block)
            {
                auto* ptr = static_cast<uint8_t*>(block);
                for (SIZE_T j = 0; j < alloc_size; j += 8)
                {
                    uint64_t garbage = __rdtsc() ^ (j * 0x9E3779B97F4A7C15ULL);
                    if (j + 8 <= alloc_size)
                        *reinterpret_cast<uint64_t*>(ptr + j) = garbage;
                }

                DWORD old_prot;
                VirtualProtect(block, alloc_size, PAGE_EXECUTE_READ, &old_prot);
            }
        }
    }

    inline void corrupt_debug_directory()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

        auto& dbg_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (dbg_dir.VirtualAddress == 0) return;

        auto* dbg = reinterpret_cast<uint8_t*>(base + dbg_dir.VirtualAddress);
        DWORD old_prot;
        if (VirtualProtect(dbg, dbg_dir.Size, PAGE_READWRITE, &old_prot))
        {
            memset(dbg, 0xCC, dbg_dir.Size);
            VirtualProtect(dbg, dbg_dir.Size, old_prot, &old_prot);
        }
    }

    inline void scramble_thread_objects()
    {
        using NtSetInformationThread_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto pSet = reinterpret_cast<NtSetInformationThread_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"));
        if (!pSet) return;

        pSet(GetCurrentThread(), 0x11, nullptr, 0);
    }

}


namespace anti_minidump
{

    using MiniDumpWriteDump_t = BOOL(WINAPI*)(
        HANDLE, DWORD, HANDLE, DWORD, PVOID, PVOID, PVOID);

    inline MiniDumpWriteDump_t original_minidump = nullptr;

    inline BOOL WINAPI hooked_minidump(HANDLE proc, DWORD pid, HANDLE file,
        DWORD dump_type, PVOID except, PVOID user_stream, PVOID callback)
    {
        if (proc == GetCurrentProcess() || pid == GetCurrentProcessId())
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        if (original_minidump)
            return original_minidump(proc, pid, file, dump_type, except, user_stream, callback);
        return FALSE;
    }

    inline bool hook_minidump()
    {
        HMODULE dbghelp = GetModuleHandleW(L"dbghelp.dll");
        if (!dbghelp)
            dbghelp = LoadLibraryW(L"dbghelp.dll");
        if (!dbghelp) return false;

        auto* target = reinterpret_cast<uint8_t*>(
            GetProcAddress(dbghelp, "MiniDumpWriteDump"));
        if (!target) return false;

        original_minidump = reinterpret_cast<MiniDumpWriteDump_t>(target);

        DWORD old_prot;
        if (!VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old_prot))
            return false;

        auto* hook_addr = reinterpret_cast<uint8_t*>(&hooked_minidump);

        target[0] = 0xFF;
        target[1] = 0x25;
        *reinterpret_cast<uint32_t*>(target + 2) = 0;
        *reinterpret_cast<uint64_t*>(target + 6) = reinterpret_cast<uint64_t>(hook_addr);

        VirtualProtect(target, 14, old_prot, &old_prot);
        return true;
    }

}


namespace handle_strip
{

    inline void revoke_debug_privileges()
    {
        using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto pSet = reinterpret_cast<NtSetInformationProcess_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
        if (!pSet) return;

        ULONG break_on_term = 1;
        pSet(GetCurrentProcess(), 0x1D, &break_on_term, sizeof(break_on_term));
    }

    inline void strip_process_handle_access()
    {
        using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto pSet = reinterpret_cast<NtSetInformationProcess_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
        if (!pSet) return;

        ULONG protected_proc = 1;
        pSet(GetCurrentProcess(), 0x3D, &protected_proc, sizeof(protected_proc));
    }

}


namespace monitor
{

    inline void run_periodic_reencrypt()
    {
        while (detail::monitors_running().load())
        {
            Sleep(10000);

            if (!detail::active().load()) continue;

            uint64_t new_key = detail::generate_session_key();
            std::lock_guard<std::mutex> lk(detail::region_mutex());

            for (auto& r : detail::encrypted_regions())
            {
                DWORD old_prot;
                if (VirtualProtect(reinterpret_cast<void*>(r.base), r.size,
                    PAGE_READWRITE, &old_prot))
                {
                    detail::xor_region(reinterpret_cast<uint8_t*>(r.base),
                        r.size, detail::xor_key());
                    detail::xor_region(reinterpret_cast<uint8_t*>(r.base),
                        r.size, new_key);
                    VirtualProtect(reinterpret_cast<void*>(r.base), r.size,
                        old_prot, &old_prot);
                }
            }

            detail::xor_key() = new_key;
        }
    }

}


inline bool initialize()
{
    if (detail::active().load()) return true;

    detail::xor_key() = detail::generate_session_key();

    dump_poison::corrupt_debug_directory();
    dump_poison::flood_decoy_memory();
    dump_poison::scramble_thread_objects();

    handle_strip::revoke_debug_privileges();
    handle_strip::strip_process_handle_access();

    anti_minidump::hook_minidump();

    module_stealth::hide_from_peb();

    pe_header::erase_dos_header();
    pe_header::corrupt_nt_headers();
    pe_header::inject_fake_sections();

    section_encrypt::encrypt_non_code_sections();

    read_intercept::install_veh();
    read_intercept::set_guard_pages();

    detail::active().store(true);
    detail::monitors_running().store(true);
    std::thread(monitor::run_periodic_reencrypt).detach();

    return true;
}

inline void shutdown()
{
    detail::monitors_running().store(false);
    detail::active().store(false);
    read_intercept::remove_veh();
}

}

}