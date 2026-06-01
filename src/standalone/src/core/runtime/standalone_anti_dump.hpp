#pragma once

#include <windows.h>
#include "work_queue.hpp"
#include <psapi.h>
#include <intrin.h>
#include <winternl.h>
#include <aclapi.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <thread>
#include <vector>

#include "obfuscation.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#endif

namespace standalone_anti_dump
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

        new_dos->e_magic = saved_magic;
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


        IMAGE_DATA_DIRECTORY saved_tls = {};
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
            saved_tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        IMAGE_DATA_DIRECTORY saved_exception = {};
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            saved_exception = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        WORD saved_sizeof_opt = nt->FileHeader.SizeOfOptionalHeader;
        DWORD saved_sizeof_image = nt->OptionalHeader.SizeOfImage;
        ULONGLONG saved_image_base = nt->OptionalHeader.ImageBase;
        DWORD saved_signature = nt->Signature;
        WORD saved_magic = nt->OptionalHeader.Magic;
        WORD saved_machine = nt->FileHeader.Machine;
        DWORD saved_entry = nt->OptionalHeader.AddressOfEntryPoint;
        DWORD saved_headers = nt->OptionalHeader.SizeOfHeaders;
        DWORD saved_checksum = nt->OptionalHeader.CheckSum;
        DWORD saved_num_rva = nt->OptionalHeader.NumberOfRvaAndSizes;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        std::vector<IMAGE_SECTION_HEADER> saved_sections(sec, sec + num_sections);

        nt->Signature = 0;
        nt->OptionalHeader.Magic = 0;
        nt->OptionalHeader.AddressOfEntryPoint = 0xDEADDEAD;
        nt->OptionalHeader.SizeOfHeaders = 0;
        nt->OptionalHeader.CheckSum = 0xFFFFFFFF;

        nt->FileHeader.Machine = 0;

        for (WORD i = 0; i < num_sections; ++i)
        {
            memset(sec[i].Name, 0, IMAGE_SIZEOF_SHORT_NAME);
            sec[i].VirtualAddress = 0;
            sec[i].Misc.VirtualSize = 0;
            sec[i].PointerToRawData = 0;
            sec[i].SizeOfRawData = 0;
            sec[i].Characteristics = 0;
        }

        nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        memset(nt->OptionalHeader.DataDirectory, 0,
               sizeof(nt->OptionalHeader.DataDirectory));


        nt->Signature = saved_signature;
        nt->OptionalHeader.Magic = saved_magic;
        nt->FileHeader.SizeOfOptionalHeader = saved_sizeof_opt;
        nt->OptionalHeader.SizeOfImage = saved_sizeof_image;
        nt->OptionalHeader.ImageBase = saved_image_base;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = saved_tls;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = saved_exception;
        nt->FileHeader.Machine = saved_machine;
        nt->OptionalHeader.AddressOfEntryPoint = saved_entry;
        nt->OptionalHeader.SizeOfHeaders = saved_headers;
        nt->OptionalHeader.CheckSum = saved_checksum;
        nt->OptionalHeader.NumberOfRvaAndSizes = saved_num_rva;
        if (!saved_sections.empty())
            memcpy(sec, saved_sections.data(), saved_sections.size() * sizeof(IMAGE_SECTION_HEADER));

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

        WORD orig_num_sections = nt->FileHeader.NumberOfSections;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        std::vector<IMAGE_SECTION_HEADER> saved_sections(sec, sec + orig_num_sections);

        nt->FileHeader.NumberOfSections = 8;

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

        nt->FileHeader.NumberOfSections = orig_num_sections;
        if (!saved_sections.empty())
            memcpy(sec, saved_sections.data(), saved_sections.size() * sizeof(IMAGE_SECTION_HEADER));

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

    inline bool pointer_writable(const void* p, size_t bytes)
    {
        if (!p || bytes == 0) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
            return false;
        const DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if ((mbi.Protect & writable) == 0)
            return false;
        uintptr_t start = reinterpret_cast<uintptr_t>(p);
        uintptr_t end = start + bytes;
        uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return end >= start && end <= region_end;
    }

    inline void unlink_entry(LIST_ENTRY* entry)
    {
        if (!pointer_writable(entry, sizeof(LIST_ENTRY))) return;
        LIST_ENTRY* blink = entry->Blink;
        LIST_ENTRY* flink = entry->Flink;
        if (!blink || !flink || flink == entry) return;
        if (!pointer_writable(blink, sizeof(LIST_ENTRY))) return;
        if (!pointer_writable(flink, sizeof(LIST_ENTRY))) return;
        blink->Flink = flink;
        flink->Blink = blink;
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
        if (!pointer_writable(head, sizeof(LIST_ENTRY))) return false;
        auto* cur = head->Flink;

        while (cur != head)
        {
            if (!pointer_writable(cur, sizeof(LIST_ENTRY))) return false;
            auto* entry = CONTAINING_RECORD(cur, _LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
            if (!pointer_writable(entry, sizeof(_LDR_DATA_TABLE_ENTRY_FULL))) return false;
            if (entry->DllBase == our_mod)
            {
                unlink_entry(&entry->InLoadOrderLinks);
                unlink_entry(&entry->InMemoryOrderLinks);
                unlink_entry(&entry->InInitializationOrderLinks);

                if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0)
                {
                    if (pointer_writable(entry->FullDllName.Buffer, entry->FullDllName.Length))
                        memset(entry->FullDllName.Buffer, 0, entry->FullDllName.Length);
                    entry->FullDllName.Length = 0;
                    entry->FullDllName.MaximumLength = 0;
                }
                if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
                {
                    if (pointer_writable(entry->BaseDllName.Buffer, entry->BaseDllName.Length))
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
    inline thread_local uint64_t pending_trap_page_base = 0;
    inline thread_local uint32_t pending_trap_page_size = 0;
    inline void*& trap_page_allocation()
    {
        static void* p = nullptr;
        return p;
    }

    inline LONG CALLBACK guard_page_handler(EXCEPTION_POINTERS* ep)
    {
        static std::atomic<uint64_t> s_gpv_count{0};
        static std::atomic<uint64_t> s_ss_count{0};

        if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        {
            uint64_t gpv_n = s_gpv_count.fetch_add(1) + 1;
            if (gpv_n == 1) {
                uint64_t fault = (ep->ExceptionRecord->NumberParameters >= 2)
                    ? static_cast<uint64_t>(ep->ExceptionRecord->ExceptionInformation[1]) : 0;
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "GPV #%llu fault_addr=0x%llX rip=0x%llX tid=%lu trap_base=0x%llX trap_size=0x%X",
                    gpv_n, fault, ep->ContextRecord->Rip, GetCurrentThreadId(),
                    trap_page_base.load(), trap_page_size.load());
                anti_tamper::webhook::write_log("veh", dbg);
            }
            if (ep->ExceptionRecord->NumberParameters >= 2)
            {
                uint64_t fault_addr = static_cast<uint64_t>(
                    ep->ExceptionRecord->ExceptionInformation[1]);
                uint64_t base = trap_page_base.load();
                uint32_t size = trap_page_size.load();

                if (base != 0 && fault_addr >= base && fault_addr < base + size)
                {
                    pending_trap_page_base = base;
                    pending_trap_page_size = size;
                    ep->ContextRecord->EFlags |= 0x100;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        if (ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
        {
            uint64_t ss_n = s_ss_count.fetch_add(1) + 1;
            if (ss_n == 1) {
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "SS #%llu rip=0x%llX tid=%lu expecting=%d",
                    ss_n, ep->ContextRecord->Rip, GetCurrentThreadId(),
                    (pending_trap_page_base != 0 && pending_trap_page_size != 0) ? 1 : 0);
                anti_tamper::webhook::write_log("veh", dbg);
            }
            if (pending_trap_page_base != 0 && pending_trap_page_size != 0)
            {
                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(pending_trap_page_base), pending_trap_page_size,
                    PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
                pending_trap_page_base = 0;
                pending_trap_page_size = 0;
                if (ep->ContextRecord)
                    ep->ContextRecord->EFlags &= ~0x100u;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    inline bool set_guard_pages()
    {
        if (trap_page_allocation())
            return true;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        DWORD page_size = si.dwPageSize ? si.dwPageSize : 0x1000u;
        void* page = VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!page) return false;
        volatile uint64_t* words = reinterpret_cast<volatile uint64_t*>(page);
        for (DWORD i = 0; i < page_size / sizeof(uint64_t); ++i)
            words[i] = detail::generate_session_key() ^ i;

        DWORD old_prot = 0;
        if (!VirtualProtect(page, page_size, PAGE_READONLY | PAGE_GUARD, &old_prot))
        {
            VirtualFree(page, 0, MEM_RELEASE);
            return false;
        }
        trap_page_allocation() = page;
        trap_page_base.store(reinterpret_cast<uint64_t>(page));
        trap_page_size.store(page_size);
        anti_tamper::webhook::write_log("anti_dump", "sa_guard_pages_set count=1");
        return true;
    }

    inline bool install_veh()
    {
        if (veh_handle) return true;
        veh_handle = AddVectoredExceptionHandler(0, guard_page_handler);
        return veh_handle != nullptr;
    }

    inline void remove_veh()
    {
        if (veh_handle)
        {
            RemoveVectoredExceptionHandler(veh_handle);
            veh_handle = nullptr;
        }
        if (trap_page_allocation())
        {
            VirtualFree(trap_page_allocation(), 0, MEM_RELEASE);
            trap_page_allocation() = nullptr;
            trap_page_base.store(0);
            trap_page_size.store(0);
        }
    }

}


namespace section_encrypt
{

    __declspec(noinline) static bool xor_region_seh(uint64_t region_base,
                                                    uint32_t region_size,
                                                    uint64_t key,
                                                    int region_index)
    {
        bool ok = false;
        __try {
            detail::xor_region(reinterpret_cast<uint8_t*>(region_base),
                region_size, key);
            ok = true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "encrypt_non_code_region_xor_SEH #%d base=0x%llX size=0x%X code=0x%08X",
                region_index, region_base, region_size, GetExceptionCode());
        }
        return ok;
    }

    inline bool region_is_host_image(const MEMORY_BASIC_INFORMATION& mbi)
    {
        return mbi.Type == MEM_IMAGE;
    }

    inline bool encrypt_non_code_sections()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            anti_tamper::webhook::write_log_critical("anti_dump",
                "encrypt_non_code: GetModuleHandle null");
            return false;
        }

        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

        uint64_t mod_base = reinterpret_cast<uint64_t>(mod);
        uint64_t mod_end = mod_base + mi.SizeOfImage;

        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "encrypt_non_code_walk_start mod_base=0x%llX mod_end=0x%llX size=0x%X",
            mod_base, mod_end, mi.SizeOfImage);

        MEMORY_BASIC_INFORMATION mbi{};
        uint64_t addr = mod_base + 0x1000;
        int encrypted_count = 0;
        int region_index = 0;

        while (addr < mod_end)
        {
            if (VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) == 0) {
                anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                    "encrypt_non_code_walk_break_VirtualQuery_failed addr=0x%llX gle=%lu",
                    addr, GetLastError());
                break;
            }

            uint64_t region_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            uint32_t region_size = static_cast<uint32_t>(mbi.RegionSize);

            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "encrypt_non_code_region #%d base=0x%llX size=0x%X state=0x%X protect=0x%X type=0x%X",
                region_index, region_base, region_size,
                mbi.State, mbi.Protect, mbi.Type);

            if (mbi.State == MEM_COMMIT
                && (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE)
                && !(mbi.Protect & PAGE_GUARD)
                && region_size >= 0x100)
            {
                if (region_is_host_image(mbi))
                {
                    anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                        "encrypt_non_code_region_skipped #%d reason=host_image_live_data base=0x%llX size=0x%X",
                        region_index, region_base, region_size);
                    addr = region_base + region_size;
                    ++region_index;
                    continue;
                }

                anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                    "encrypt_non_code_region_pre_VirtualProtect #%d base=0x%llX size=0x%X protect=0x%X",
                    region_index, region_base, region_size, mbi.Protect);

                DWORD old_prot = 0;
                BOOL vp1_ok = VirtualProtect(reinterpret_cast<void*>(region_base), region_size,
                    PAGE_READWRITE, &old_prot);

                anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                    "encrypt_non_code_region_post_VirtualProtect #%d ok=%d old=0x%X gle=%lu",
                    region_index, vp1_ok ? 1 : 0, old_prot,
                    vp1_ok ? 0 : GetLastError());

                if (vp1_ok)
                {
                    anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                        "encrypt_non_code_region_pre_xor #%d base=0x%llX size=0x%X",
                        region_index, region_base, region_size);

                    bool xor_ok = xor_region_seh(region_base, region_size,
                        detail::xor_key(), region_index);

                    anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                        "encrypt_non_code_region_post_xor #%d ok=%d",
                        region_index, xor_ok ? 1 : 0);

                    DWORD discard = 0;
                    VirtualProtect(reinterpret_cast<void*>(region_base), region_size,
                        old_prot, &discard);

                    if (xor_ok) {
                        std::lock_guard<std::mutex> lk(detail::region_mutex());
                        detail::encrypted_regions().push_back({region_base, region_size, old_prot});
                        ++encrypted_count;
                    }

                    anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                        "encrypted_region #%d base=0x%llX size=0x%X prot=0x%X xor_ok=%d",
                        encrypted_count, region_base, region_size, old_prot,
                        xor_ok ? 1 : 0);
                }
            }
            else
            {
                anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                    "encrypt_non_code_region_skipped #%d reason=protect_or_size",
                    region_index);
            }

            addr = region_base + region_size;
            ++region_index;
        }

        {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "encrypt_non_code_done total_encrypted=%d total_regions_walked=%d",
                encrypted_count, region_index);
            anti_tamper::webhook::write_log_critical("anti_dump", dbg);
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
                detail::xor_region(ptr, static_cast<uint32_t>(alloc_size), detail::xor_key());

                DWORD old_prot;
                if (VirtualProtect(block, alloc_size, PAGE_EXECUTE_READ, &old_prot))
                {
                    std::lock_guard<std::mutex> lk(detail::region_mutex());
                    detail::encrypted_regions().push_back({
                        reinterpret_cast<uint64_t>(block),
                        static_cast<uint32_t>(alloc_size),
                        PAGE_EXECUTE_READ
                    });
                }
                else
                {
                    VirtualFree(block, 0, MEM_RELEASE);
                }
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

        auto* trampoline = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!trampoline) return false;

        memcpy(trampoline, target, 14);
        trampoline[14] = 0xFF;
        trampoline[15] = 0x25;
        *reinterpret_cast<uint32_t*>(trampoline + 16) = 0;
        *reinterpret_cast<uint64_t*>(trampoline + 20) = reinterpret_cast<uint64_t>(target + 14);
        FlushInstructionCache(GetCurrentProcess(), trampoline, 64);

        original_minidump = reinterpret_cast<MiniDumpWriteDump_t>(trampoline);

        DWORD old_prot;
        if (!VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old_prot))
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            original_minidump = nullptr;
            return false;
        }

        auto* hook_addr = reinterpret_cast<uint8_t*>(&hooked_minidump);

        target[0] = 0xFF;
        target[1] = 0x25;
        *reinterpret_cast<uint32_t*>(target + 2) = 0;
        *reinterpret_cast<uint64_t*>(target + 6) = reinterpret_cast<uint64_t>(hook_addr);

        VirtualProtect(target, 14, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), target, 14);
        return true;
    }

}


namespace handle_strip
{

    using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);

    inline bool copy_current_user_sid(std::vector<BYTE>& out_sid)
    {
        out_sid.clear();
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_token_open_failed gle=%lu", GetLastError());
            return false;
        }

        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed == 0)
        {
            CloseHandle(token);
            anti_tamper::webhook::write_log_critical("anti_dump",
                "sa_seal_dacl_token_size_failed");
            return false;
        }

        std::vector<BYTE> token_user(needed);
        if (!GetTokenInformation(token, TokenUser, token_user.data(), needed, &needed))
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_token_query_failed gle=%lu", GetLastError());
            CloseHandle(token);
            return false;
        }
        CloseHandle(token);

        auto* user = reinterpret_cast<TOKEN_USER*>(token_user.data());
        DWORD sid_len = GetLengthSid(user->User.Sid);
        out_sid.resize(sid_len);
        if (!CopySid(sid_len, out_sid.data(), user->User.Sid))
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_sid_copy_failed gle=%lu", GetLastError());
            out_sid.clear();
            return false;
        }
        return true;
    }

    inline bool apply_process_dacl_seal()
    {
        anti_tamper::webhook::write_log_critical("anti_dump", "sa_seal_dacl_begin");
        std::vector<BYTE> user_sid;
        if (!copy_current_user_sid(user_sid))
            return false;

        BYTE system_sid[SECURITY_MAX_SID_SIZE]{};
        DWORD system_sid_size = sizeof(system_sid);
        bool have_system = CreateWellKnownSid(WinLocalSystemSid, nullptr,
            system_sid, &system_sid_size) != FALSE;

        BYTE admins_sid[SECURITY_MAX_SID_SIZE]{};
        DWORD admins_sid_size = sizeof(admins_sid);
        bool have_admins = CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
            admins_sid, &admins_sid_size) != FALSE;

        constexpr DWORD limited_access =
            PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_SET_LIMITED_INFORMATION |
            SYNCHRONIZE |
            READ_CONTROL;

        EXPLICIT_ACCESSW entries[3]{};
        ULONG count = 0;

        entries[count].grfAccessPermissions = limited_access;
        entries[count].grfAccessMode = SET_ACCESS;
        entries[count].grfInheritance = NO_INHERITANCE;
        entries[count].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[count].Trustee.TrusteeType = TRUSTEE_IS_USER;
        entries[count].Trustee.ptstrName = reinterpret_cast<LPWSTR>(user_sid.data());
        ++count;

        if (have_system)
        {
            entries[count].grfAccessPermissions = PROCESS_ALL_ACCESS;
            entries[count].grfAccessMode = SET_ACCESS;
            entries[count].grfInheritance = NO_INHERITANCE;
            entries[count].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entries[count].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            entries[count].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system_sid);
            ++count;
        }

        if (have_admins)
        {
            entries[count].grfAccessPermissions = limited_access;
            entries[count].grfAccessMode = SET_ACCESS;
            entries[count].grfInheritance = NO_INHERITANCE;
            entries[count].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entries[count].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            entries[count].Trustee.ptstrName = reinterpret_cast<LPWSTR>(admins_sid);
            ++count;
        }

        PACL acl = nullptr;
        anti_tamper::webhook::write_log_critical("anti_dump", "sa_seal_dacl_set_entries_begin");
        DWORD acl_rc = SetEntriesInAclW(count, entries, nullptr, &acl);
        if (acl_rc != ERROR_SUCCESS || !acl)
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_set_entries_failed rc=%lu", acl_rc);
            return false;
        }

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_seal_dacl_set_security_begin");
        DWORD set_rc = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, acl, nullptr);
        LocalFree(acl);

        if (set_rc != ERROR_SUCCESS)
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_set_security_failed rc=%lu", set_rc);
            return false;
        }

        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_seal_dacl_ok entries=%lu mask=0x%08X", count, limited_access);
        return true;
    }

    struct dacl_seal_worker_state_t
    {
        HANDLE done_event = nullptr;
        std::atomic<bool> ok{false};
        std::atomic<DWORD> seh_code{0};
    };

    inline DWORD WINAPI dacl_seal_worker_proc(LPVOID ctx)
    {
        auto* state = static_cast<dacl_seal_worker_state_t*>(ctx);
        bool ok = false;
        __try { ok = apply_process_dacl_seal(); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            state->seh_code.store(GetExceptionCode(), std::memory_order_release);
        }
        state->ok.store(ok, std::memory_order_release);
        if (state->done_event)
            SetEvent(state->done_event);
        return 0;
    }

    inline bool apply_process_dacl_seal_bounded(DWORD timeout_ms)
    {
        auto* state = new (std::nothrow) dacl_seal_worker_state_t();
        if (!state)
        {
            anti_tamper::webhook::write_log_critical("anti_dump", "sa_seal_dacl_worker_alloc_failed");
            return false;
        }

        state->done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!state->done_event)
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_worker_event_failed gle=%lu", GetLastError());
            delete state;
            return false;
        }

        HANDLE thread = CreateThread(nullptr, 0, dacl_seal_worker_proc, state, 0, nullptr);
        if (!thread)
        {
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_worker_create_failed gle=%lu", GetLastError());
            CloseHandle(state->done_event);
            delete state;
            return false;
        }

        DWORD wait = WaitForSingleObject(state->done_event, timeout_ms);
        if (wait == WAIT_OBJECT_0)
        {
            bool ok = state->ok.load(std::memory_order_acquire);
            DWORD seh = state->seh_code.load(std::memory_order_acquire);
            CloseHandle(thread);
            CloseHandle(state->done_event);
            delete state;
            if (seh != 0)
            {
                anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                    "sa_seal_dacl_worker_seh code=0x%08lX", seh);
                return false;
            }
            return ok;
        }

        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_seal_dacl_worker_timeout wait=0x%08lX timeout_ms=%lu", wait, timeout_ms);
        CloseHandle(thread);
        return false;
    }

    inline NtSetInformationProcess_t get_nt_set_info()
    {
        return reinterpret_cast<NtSetInformationProcess_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
    }

    inline void revoke_debug_privileges()
    {
        auto pSet = get_nt_set_info();
        if (!pSet) return;

        ULONG break_on_term = 1;
        pSet(GetCurrentProcess(), 0x1D, &break_on_term, sizeof(break_on_term));
    }

    inline void strip_process_handle_access()
    {
        auto pSet = get_nt_set_info();
        if (!pSet)
        {
            anti_tamper::webhook::write_log_critical("anti_dump",
                "sa_seal_no_NtSetInformationProcess");
            bool dacl_ok = apply_process_dacl_seal_bounded(1500);
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_fallback_result ok=%d", dacl_ok ? 1 : 0);
            return;
        }

        ULONG protected_proc = 1;
        anti_tamper::webhook::write_log_critical("anti_dump", "sa_seal_ppl_attempt");
        NTSTATUS st = pSet(GetCurrentProcess(), 0x3D, &protected_proc, sizeof(protected_proc));
        bool ppl_ok = st >= 0;
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            ppl_ok ? "sa_seal_ppl_ok status=0x%08X" : "sa_seal_ppl_unavailable status=0x%08X",
            static_cast<unsigned>(st));
        if (!ppl_ok)
        {
            anti_tamper::webhook::write_log_critical("anti_dump", "sa_seal_dacl_fallback_begin");
            bool dacl_ok = apply_process_dacl_seal_bounded(1500);
            anti_tamper::webhook::write_log_critical_fmt("anti_dump",
                "sa_seal_dacl_fallback_result ok=%d", dacl_ok ? 1 : 0);
        }
    }

    inline void clear_critical_flags()
    {
        auto pSet = get_nt_set_info();
        if (!pSet) return;

        ULONG break_on_term = 0;
        pSet(GetCurrentProcess(), 0x1D, &break_on_term, sizeof(break_on_term));

        ULONG protected_proc = 0;
        pSet(GetCurrentProcess(), 0x3D, &protected_proc, sizeof(protected_proc));
    }

}


namespace monitor
{

    inline void run_periodic_reencrypt()
    {
        uint64_t reencrypt_iter = 0;
        while (detail::monitors_running().load())
        {
            Sleep(10000);

            if (!detail::active().load()) continue;

            ++reencrypt_iter;
            uint64_t new_key = detail::generate_session_key();
            std::lock_guard<std::mutex> lk(detail::region_mutex());

            size_t region_count = detail::encrypted_regions().size();
            {
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "reencrypt iter=%llu regions=%zu",
                    reencrypt_iter, region_count);
                anti_tamper::webhook::write_log("anti_dump", dbg);
            }

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


__declspec(noinline) static void sa_init_call_corrupt_debug_dir_seh()
{
    __try { dump_poison::corrupt_debug_directory(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_corrupt_debug_dir_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void sa_init_call_flood_decoy_seh()
{
    __try { dump_poison::flood_decoy_memory(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_flood_decoy_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void sa_init_call_scramble_threads_seh()
{
    __try { dump_poison::scramble_thread_objects(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_scramble_threads_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void sa_init_call_hook_minidump_seh()
{
    __try { anti_minidump::hook_minidump(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_hook_minidump_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void sa_init_call_inject_fake_sections_seh()
{
    __try { pe_header::inject_fake_sections(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_inject_fake_sections_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void sa_init_call_corrupt_nt_seh()
{
    __try { pe_header::corrupt_nt_headers(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_corrupt_nt_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static void sa_init_call_erase_dos_seh()
{
    __try { pe_header::erase_dos_header(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_erase_dos_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static bool sa_init_call_install_veh_seh()
{
    bool ok = false;
    __try { ok = read_intercept::install_veh(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_install_veh_SEH code=0x%08X", GetExceptionCode());
    }
    return ok;
}

__declspec(noinline) static void sa_init_call_encrypt_non_code_seh()
{
    __try { section_encrypt::encrypt_non_code_sections(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_encrypt_non_code_SEH code=0x%08X", GetExceptionCode());
    }
}

__declspec(noinline) static bool sa_init_call_set_guard_pages_seh()
{
    bool ok = false;
    __try { ok = read_intercept::set_guard_pages(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        anti_tamper::webhook::write_log_critical_fmt("anti_dump",
            "sa_set_guard_pages_SEH code=0x%08X", GetExceptionCode());
    }
    return ok;
}


inline bool initialize()
{
    if (detail::active().load()) return true;

    detail::xor_key() = detail::generate_session_key();
    anti_tamper::webhook::write_log_critical("anti_dump", "initialize_enter");

    HMODULE mod = GetModuleHandleW(nullptr);
    bool pe_intact = false;
    bool pe_already_corrupted_by_orchestrator = false;
    if (mod)
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);

            const bool machine_intact   = (nt->FileHeader.Machine != 0);
            const bool entry_intact     = (nt->OptionalHeader.AddressOfEntryPoint != 0xDEADDEAD);
            const bool headers_intact   = (nt->OptionalHeader.SizeOfHeaders != 0);
            const bool checksum_intact  = (nt->OptionalHeader.CheckSum != 0xFFFFFFFF);

            pe_intact = machine_intact && entry_intact && headers_intact && checksum_intact;
            pe_already_corrupted_by_orchestrator = machine_intact &&
                (!entry_intact || !headers_intact || !checksum_intact);

            char dbg2[512];
            _snprintf_s(dbg2, sizeof(dbg2), _TRUNCATE,
                "sa_pe_check: e_magic=0x%X sig=0x%X machine=0x%X entry=0x%X "
                "headers_size=0x%X checksum=0x%X "
                "machine_intact=%d entry_intact=%d headers_intact=%d checksum_intact=%d "
                "pe_intact=%d already_corrupted_by_orchestrator=%d",
                dos->e_magic, nt->Signature, nt->FileHeader.Machine,
                nt->OptionalHeader.AddressOfEntryPoint,
                nt->OptionalHeader.SizeOfHeaders,
                nt->OptionalHeader.CheckSum,
                machine_intact ? 1 : 0, entry_intact ? 1 : 0,
                headers_intact ? 1 : 0, checksum_intact ? 1 : 0,
                pe_intact ? 1 : 0, pe_already_corrupted_by_orchestrator ? 1 : 0);
            anti_tamper::webhook::write_log_critical("anti_dump", dbg2);
        }
        else
        {
            char dbg2[128];
            _snprintf_s(dbg2, sizeof(dbg2), _TRUNCATE,
                "sa_pe_check: e_magic=0x%X (not MZ), pe_intact=0", dos->e_magic);
            anti_tamper::webhook::write_log_critical("anti_dump", dbg2);
        }
    }

    {
        char dbg[128];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "pe_intact=%d xor_key_ready=1",
            pe_intact ? 1 : 0);
        anti_tamper::webhook::write_log_critical("anti_dump", dbg);
    }

    if (pe_intact)
    {
        anti_tamper::webhook::write_log_critical("anti_dump", "sa_corrupt_debug_dir_pre");
        sa_init_call_corrupt_debug_dir_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "corrupt_debug_dir_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_flood_decoy_pre");
        sa_init_call_flood_decoy_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "flood_decoy_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_scramble_threads_pre");
        sa_init_call_scramble_threads_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "scramble_threads_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_hook_minidump_pre");
        sa_init_call_hook_minidump_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "hook_minidump_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_inject_fake_sections_pre");
        sa_init_call_inject_fake_sections_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "inject_fake_sections_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_corrupt_nt_pre");
        sa_init_call_corrupt_nt_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "corrupt_nt_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_erase_dos_pre");
        sa_init_call_erase_dos_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "erase_dos_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_encrypt_non_code_entering");
        sa_init_call_encrypt_non_code_seh();
        anti_tamper::webhook::write_log_critical("anti_dump", "sa_encrypt_non_code_ok");

        anti_tamper::webhook::write_log_critical("anti_dump", "sa_install_veh_pre");
        bool sa_veh_ok = sa_init_call_install_veh_seh();
        anti_tamper::webhook::write_log_critical("anti_dump",
            sa_veh_ok ? "install_veh_ok" : "install_veh_fail");

        bool guard_pages_ok = false;
        if (sa_veh_ok)
        {
            anti_tamper::webhook::write_log_critical("anti_dump", "sa_set_guard_pages_entering");
            guard_pages_ok = sa_init_call_set_guard_pages_seh();
        }
        else
        {
            anti_tamper::webhook::write_log_critical("anti_dump", "sa_set_guard_pages_skipped_no_veh");
        }
        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "guard_pages_set ok=%d trap_base=0x%llX trap_size=0x%X",
                guard_pages_ok ? 1 : 0,
                read_intercept::trap_page_base.load(), read_intercept::trap_page_size.load());
            anti_tamper::webhook::write_log_critical("anti_dump", dbg);
        }
    }
    else if (pe_already_corrupted_by_orchestrator)
    {
        anti_tamper::webhook::write_log_critical("anti_dump",
            "sa_skip_corrupt_phase_already_done_by_orchestrator");
    }
    else
    {
        anti_tamper::webhook::write_log_critical("anti_dump",
            "sa_skip_corrupt_phase_pe_not_intact");
    }

    detail::active().store(true);
    anti_tamper::webhook::write_log("anti_dump", "active_store_ok");
    detail::monitors_running().store(true);
    anti_tamper::webhook::write_log("anti_dump", "monitors_store_ok");
    static std::atomic<bool> s_anti_dump_reencrypt_posted{false};
    bool expected_posted = false;
    if (s_anti_dump_reencrypt_posted.compare_exchange_strong(expected_posted, true, std::memory_order_acq_rel))
    {
        if (work_queue::post([]() { monitor::run_periodic_reencrypt(); }))
            anti_tamper::webhook::write_log("anti_dump", "sa_monitor_work_queue_ok");
        else
        {
            s_anti_dump_reencrypt_posted.store(false, std::memory_order_release);
            anti_tamper::webhook::write_log("anti_dump", "sa_monitor_work_queue_fail");
        }
    }

    if (pe_intact)
    {
        module_stealth::hide_from_peb();
    }

    return true;
}

inline void seal_handles()
{
    handle_strip::revoke_debug_privileges();
    anti_tamper::webhook::write_log("anti_dump", "sa_seal_revoke_privs_ok");

    handle_strip::strip_process_handle_access();
    anti_tamper::webhook::write_log("anti_dump", "sa_seal_strip_handle_ok");
}

inline void shutdown()
{
    detail::monitors_running().store(false);
    detail::active().store(false);
    read_intercept::remove_veh();
    handle_strip::clear_critical_flags();

    std::lock_guard<std::mutex> lk(detail::region_mutex());
    for (auto& r : detail::encrypted_regions())
    {
        DWORD old_prot;
        if (VirtualProtect(reinterpret_cast<void*>(r.base), r.size,
            PAGE_READWRITE, &old_prot))
        {
            detail::xor_region(reinterpret_cast<uint8_t*>(r.base),
                r.size, detail::xor_key());
            VirtualProtect(reinterpret_cast<void*>(r.base), r.size,
                old_prot, &old_prot);
        }
    }
    detail::encrypted_regions().clear();
}

}
