#pragma once

#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <winternl.h>
#include <bcrypt.h>
#include <aclapi.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <thread>
#include <vector>

#include "../infra/executor.hpp"
#include "webhook.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION 0x2000
#endif

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

    inline std::atomic<uint64_t>& scylla_iat_hits()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>& ollydump_text_hits()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline bool fill_secure_random(void* buf, size_t bytes)
    {
        return BCryptGenRandom(nullptr,
            static_cast<PUCHAR>(buf), static_cast<ULONG>(bytes),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline uint64_t generate_session_key()
    {
        uint64_t k = 0;
        if (!fill_secure_random(&k, sizeof(k)))
        {
            k = static_cast<uint64_t>(__rdtsc());
            k ^= GetCurrentProcessId();
            k ^= reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        }
        if (k == 0)
        {
            uint8_t fallback[8]{};
            fill_secure_random(fallback, sizeof(fallback));
            memcpy(&k, fallback, sizeof(k));
            if (k == 0) k = 0xDEADC0DEBEEFCAFEULL;
        }
        return k;
    }

    inline void fill_random_bytes(uint8_t* dst, size_t n)
    {
        if (fill_secure_random(dst, n)) return;
        uint64_t fallback = static_cast<uint64_t>(__rdtsc());
        for (size_t i = 0; i < n; ++i)
        {
            fallback = fallback * 6364136223846793005ULL + 1442695040888963407ULL;
            dst[i] = static_cast<uint8_t>(fallback >> 33);
        }
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

    inline IMAGE_NT_HEADERS64* safe_resolve_self_nt(uint8_t* base, const char* tag)
    {
        if (!base) return nullptr;

        IMAGE_NT_HEADERS64* nt = nullptr;
        __try
        {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE && dos->e_magic != 0)
            {
                if (tag) {
                    char buf[128];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "%s: bad e_magic=0x%X", tag, dos->e_magic);
                    webhook::write_log("anti_dump", buf);
                }
                return nullptr;
            }

            LONG e_lfanew = dos->e_lfanew;
            if (e_lfanew <= 0 || static_cast<uint32_t>(e_lfanew) > 0x10000u)
            {
                if (tag) {
                    char buf[160];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "%s: bad e_lfanew=0x%lX base=0x%llX",
                        tag, static_cast<unsigned long>(e_lfanew),
                        reinterpret_cast<unsigned long long>(base));
                    webhook::write_log("anti_dump", buf);
                }
                return nullptr;
            }

            nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE && nt->Signature != 0)
            {
                if (tag) {
                    char buf[128];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "%s: bad nt sig=0x%X", tag, nt->Signature);
                    webhook::write_log("anti_dump", buf);
                }
                return nullptr;
            }
            if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                nt->OptionalHeader.Magic != 0)
            {
                if (tag) {
                    char buf[128];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "%s: bad opt magic=0x%X", tag, nt->OptionalHeader.Magic);
                    webhook::write_log("anti_dump", buf);
                }
                return nullptr;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (tag) {
                char buf[128];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "%s: SEH on header read code=0x%08X",
                    tag, static_cast<unsigned int>(GetExceptionCode()));
                webhook::write_log("anti_dump", buf);
            }
            return nullptr;
        }
        return nt;
    }

    inline bool erase_dos_header()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            webhook::write_log("anti_dump", "erase_dos: GetModuleHandle null");
            return false;
        }

        auto* base = reinterpret_cast<uint8_t*>(mod);
        if (!safe_resolve_self_nt(base, "erase_dos")) {
            return false;
        }
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        DWORD e_lfanew = dos->e_lfanew;

        {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "erase_dos_pre: e_magic=0x%X e_lfanew=0x%X base=0x%llX",
                dos->e_magic, e_lfanew, reinterpret_cast<uint64_t>(base));
            webhook::write_log("anti_dump", buf);
        }

        DWORD old_prot = 0;
        if (!VirtualProtect(base, e_lfanew, PAGE_READWRITE, &old_prot)) {
            webhook::write_log("anti_dump", "erase_dos: VirtualProtect failed");
            return false;
        }

        uint16_t saved_magic = dos->e_magic;
        uint32_t saved_lfanew = dos->e_lfanew;

        constexpr DWORD k_first8_off = 0;
        if (e_lfanew >= 8)
        {
            uint64_t random_first8 = 0;
            detail::fill_random_bytes(reinterpret_cast<uint8_t*>(&random_first8),
                sizeof(random_first8));

            auto* first8 = reinterpret_cast<volatile LONG64*>(base + k_first8_off);
            LONG64 expected_orig = 0;
            memcpy(&expected_orig, base + k_first8_off, sizeof(expected_orig));
            InterlockedCompareExchange64(first8, static_cast<LONG64>(random_first8),
                expected_orig);
        }

        if (e_lfanew > 8)
        {
            volatile uint8_t* vb = reinterpret_cast<volatile uint8_t*>(base);
            uint8_t random_buf[256];
            DWORD remaining = e_lfanew - 8;
            DWORD off = 8;
            while (remaining > 0)
            {
                DWORD this_chunk = remaining > sizeof(random_buf)
                    ? static_cast<DWORD>(sizeof(random_buf)) : remaining;
                detail::fill_random_bytes(random_buf, this_chunk);
                for (DWORD i = 0; i < this_chunk; ++i)
                    vb[off + i] = random_buf[i];
                off += this_chunk;
                remaining -= this_chunk;
            }
        }

        auto* new_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        union dos_merge_u {
            struct { uint16_t magic; uint8_t pad[58]; uint32_t lfanew; } parts;
            LONG64 wide[8];
        };
        dos_merge_u merged{};
        memcpy(&merged, base, sizeof(merged));

        dos_merge_u restored = merged;
        restored.parts.magic = saved_magic;
        restored.parts.lfanew = saved_lfanew;

        for (size_t i = 0; i < 8; ++i)
        {
            volatile LONG64* slot = reinterpret_cast<volatile LONG64*>(base + i * sizeof(LONG64));
            LONG64 expected = merged.wide[i];
            InterlockedCompareExchange64(slot, restored.wide[i], expected);
        }

        VirtualProtect(base, e_lfanew, old_prot, &old_prot);

        {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "erase_dos_post: e_magic=0x%X e_lfanew=0x%X (preserved for loader)",
                new_dos->e_magic, new_dos->e_lfanew);
            webhook::write_log("anti_dump", buf);
        }

        return true;
    }

    inline bool corrupt_nt_headers()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            webhook::write_log("anti_dump", "corrupt_nt: GetModuleHandle null");
            return false;
        }

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* nt = safe_resolve_self_nt(base, "corrupt_nt");
        if (!nt) return false;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        uint32_t nt_offset = dos->e_lfanew;

        DWORD nt_size = sizeof(IMAGE_NT_HEADERS64);
        WORD num_sections = nt->FileHeader.NumberOfSections;
        DWORD total = nt_size + num_sections * sizeof(IMAGE_SECTION_HEADER);

        {
            char buf[512];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "corrupt_nt_pre: base=0x%llX nt_off=0x%X sig=0x%X magic=0x%X machine=0x%X "
                "num_sec=%u sizeof_opt=%u sizeof_image=0x%X imagebase=0x%llX "
                "tls_rva=0x%X tls_size=0x%X exc_rva=0x%X exc_size=0x%X numrva=%u",
                reinterpret_cast<uint64_t>(base), nt_offset,
                nt->Signature, nt->OptionalHeader.Magic, nt->FileHeader.Machine,
                num_sections, nt->FileHeader.SizeOfOptionalHeader,
                nt->OptionalHeader.SizeOfImage,
                static_cast<unsigned long long>(nt->OptionalHeader.ImageBase),
                (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
                    ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress : 0u,
                (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
                    ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size : 0u,
                (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                    ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress : 0u,
                (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                    ? nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size : 0u,
                nt->OptionalHeader.NumberOfRvaAndSizes);
            webhook::write_log("anti_dump", buf);
        }

        DWORD old_prot = 0;
        if (!VirtualProtect(nt, total, PAGE_READWRITE, &old_prot)) {
            webhook::write_log("anti_dump", "corrupt_nt: VirtualProtect failed");
            return false;
        }


        IMAGE_DATA_DIRECTORY saved_tls = {};
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS)
            saved_tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];


        IMAGE_DATA_DIRECTORY saved_exception = {};
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            saved_exception = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        IMAGE_DATA_DIRECTORY saved_import = {};
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            saved_import = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        IMAGE_DATA_DIRECTORY saved_iat = {};
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IAT)
            saved_iat = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];


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
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = saved_import;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = saved_iat;
        nt->FileHeader.Machine = saved_machine;
        nt->OptionalHeader.AddressOfEntryPoint = saved_entry;
        nt->OptionalHeader.SizeOfHeaders = saved_headers;
        nt->OptionalHeader.CheckSum = saved_checksum;
        nt->OptionalHeader.NumberOfRvaAndSizes = saved_num_rva;
        if (!saved_sections.empty())
            memcpy(sec, saved_sections.data(), saved_sections.size() * sizeof(IMAGE_SECTION_HEADER));

        VirtualProtect(nt, total, old_prot, &old_prot);

        {
            char buf[512];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "corrupt_nt_post: sig=0x%X magic=0x%X machine=0x%X "
                "sizeof_opt=%u sizeof_image=0x%X imagebase=0x%llX "
                "tls_rva=0x%X tls_size=0x%X exc_rva=0x%X exc_size=0x%X "
                "entry=0x%X checksum=0x%X headers_size=0x%X numrva=%u",
                nt->Signature, nt->OptionalHeader.Magic, nt->FileHeader.Machine,
                nt->FileHeader.SizeOfOptionalHeader,
                nt->OptionalHeader.SizeOfImage,
                static_cast<unsigned long long>(nt->OptionalHeader.ImageBase),
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
                nt->OptionalHeader.AddressOfEntryPoint,
                nt->OptionalHeader.CheckSum,
                nt->OptionalHeader.SizeOfHeaders,
                nt->OptionalHeader.NumberOfRvaAndSizes);
            webhook::write_log("anti_dump", buf);
        }

        return true;
    }

    inline bool erase_export_directory()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            webhook::write_log("anti_dump", "erase_export: GetModuleHandle null");
            return false;
        }

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* nt = safe_resolve_self_nt(base, "erase_export");
        if (!nt) return false;

        if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
            webhook::write_log("anti_dump", "erase_export: no export directory");
            return true;
        }

        auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_dir.VirtualAddress == 0 || export_dir.Size == 0) {
            webhook::write_log("anti_dump", "erase_export: empty export dir");
            return true;
        }

        auto* export_va = base + export_dir.VirtualAddress;
        DWORD export_size = export_dir.Size;

        {
            char buf[160];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "erase_export_pre: rva=0x%X size=0x%X va=0x%llX",
                export_dir.VirtualAddress, export_size,
                reinterpret_cast<uint64_t>(export_va));
            webhook::write_log("anti_dump", buf);
        }

        DWORD old_prot = 0;
        if (!VirtualProtect(export_va, export_size, PAGE_READWRITE, &old_prot)) {
            webhook::write_log("anti_dump", "erase_export: VirtualProtect failed");
            return false;
        }

        RtlSecureZeroMemory(export_va, export_size);

        DWORD nt_old_prot = 0;
        if (VirtualProtect(nt, sizeof(IMAGE_NT_HEADERS64), PAGE_READWRITE, &nt_old_prot)) {
            export_dir.VirtualAddress = 0;
            export_dir.Size = 0;
            VirtualProtect(nt, sizeof(IMAGE_NT_HEADERS64), nt_old_prot, &nt_old_prot);
        }

        VirtualProtect(export_va, export_size, old_prot, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), export_va, export_size);

        webhook::write_log("anti_dump", "erase_export_post: zeroed");
        return true;
    }

    struct header_verify_result_t {
        bool dos_zeroed;
        bool nt_zeroed;
        bool sections_zeroed;
        bool export_zeroed;
    };

    inline header_verify_result_t verify_headers_zeroed()
    {
        header_verify_result_t result{false, false, false, false};

        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return result;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        __try {
            result.dos_zeroed = (dos->e_magic == 0 || dos->e_magic == IMAGE_DOS_SIGNATURE);

            LONG e_lfanew = dos->e_lfanew;
            if (e_lfanew <= 0 || static_cast<uint32_t>(e_lfanew) > 0x10000u)
                return result;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + e_lfanew);
            result.nt_zeroed = (nt->Signature == 0 || nt->Signature == IMAGE_NT_SIGNATURE);

            auto* sec = IMAGE_FIRST_SECTION(nt);
            WORD num = nt->FileHeader.NumberOfSections;
            bool all_sections_zero = true;
            for (WORD i = 0; i < num; ++i) {
                if (sec[i].VirtualAddress != 0 || sec[i].Misc.VirtualSize != 0) {
                    all_sections_zero = false;
                    break;
                }
            }
            result.sections_zeroed = all_sections_zero;

            if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                auto& ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                result.export_zeroed = (ed.VirtualAddress == 0 && ed.Size == 0);
            } else {
                result.export_zeroed = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        return result;
    }

    inline bool inject_fake_sections()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* nt = safe_resolve_self_nt(base, "inject_fake_sections");
        if (!nt) return false;

        WORD orig_num_sections = nt->FileHeader.NumberOfSections;
        DWORD total = sizeof(IMAGE_NT_HEADERS64)
            + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

        {
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "inject_fake_sections: orig_num_sec=%d total_size=0x%X base=0x%llX",
                orig_num_sections, total, reinterpret_cast<uint64_t>(base));
            webhook::write_log("anti_dump", dbg);
        }

        DWORD old_prot = 0;
        if (!VirtualProtect(nt, total + 256, PAGE_READWRITE, &old_prot))
        {
            webhook::write_log("anti_dump", "inject_fake_sections: VirtualProtect failed");
            return false;
        }

        auto* sec = IMAGE_FIRST_SECTION(nt);
        std::vector<IMAGE_SECTION_HEADER> saved_sections(sec, sec + orig_num_sections);
        nt->FileHeader.NumberOfSections = 8;

        for (int i = 0; i < 8; ++i)
        {
            char fake_name[IMAGE_SIZEOF_SHORT_NAME] = {};
            snprintf(fake_name, IMAGE_SIZEOF_SHORT_NAME, ".x%d%c", i, 'A' + (i % 26));
            memcpy(sec[i].Name, fake_name, IMAGE_SIZEOF_SHORT_NAME);

            uint32_t rand_va = 0, rand_vsz = 0, rand_raw = 0;
            detail::fill_random_bytes(reinterpret_cast<uint8_t*>(&rand_va), sizeof(rand_va));
            detail::fill_random_bytes(reinterpret_cast<uint8_t*>(&rand_vsz), sizeof(rand_vsz));
            detail::fill_random_bytes(reinterpret_cast<uint8_t*>(&rand_raw), sizeof(rand_raw));

            sec[i].VirtualAddress = rand_va & 0x7FFFFFFFu;
            sec[i].Misc.VirtualSize = (rand_vsz & 0xFFFFu) + 0x1000u;
            sec[i].PointerToRawData = rand_raw & 0x7FFFFFFFu;
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

    inline int scrub_peb_ldr_entry(HMODULE self_module)
    {
        if (!self_module) return 0;

        auto* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
        if (!peb || !peb->Ldr) return 0;

        auto* ldr = reinterpret_cast<_PEB_LDR_DATA_FULL*>(peb->Ldr);
        auto* head = &ldr->InLoadOrderModuleList;
        if (!pointer_writable(head, sizeof(LIST_ENTRY))) return 0;
        auto* cur = head->Flink;

        int unlinked = 0;
        while (cur != head)
        {
            if (!pointer_writable(cur, sizeof(LIST_ENTRY))) return unlinked;
            auto* entry = CONTAINING_RECORD(cur, _LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
            if (!pointer_writable(entry, sizeof(_LDR_DATA_TABLE_ENTRY_FULL))) return unlinked;

            auto* next = cur->Flink;

            if (entry->DllBase == self_module)
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

                ++unlinked;
            }

            cur = next;
        }
        return unlinked;
    }

    inline bool hide_from_peb()
    {
        HMODULE our_mod = GetModuleHandleW(nullptr);
        if (!our_mod) return false;
        return scrub_peb_ldr_entry(our_mod) != 0;
    }

}


namespace iat_guard
{

    inline std::atomic<uint64_t>& iat_base()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint32_t>& iat_size()
    {
        static std::atomic<uint32_t> v{0};
        return v;
    }

    inline bool locate_iat_range(uint64_t& base_out, uint32_t& size_out)
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            webhook::write_log("anti_dump", "locate_iat_range_no_module");
            return false;
        }

        auto* base = reinterpret_cast<uint8_t*>(mod);

        __try
        {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE && dos->e_magic != 0)
            {
                char buf[96];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "locate_iat_range_bad_dos magic=0x%X", dos->e_magic);
                webhook::write_log("anti_dump", buf);
                return false;
            }

            LONG e_lfanew = dos->e_lfanew;
            if (e_lfanew <= 0 || static_cast<uint32_t>(e_lfanew) > 0x10000u)
            {
                char buf[128];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "locate_iat_range_bad_lfanew value=0x%lX",
                    static_cast<unsigned long>(e_lfanew));
                webhook::write_log("anti_dump", buf);
                return false;
            }

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE && nt->Signature != 0)
            {
                char buf[96];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "locate_iat_range_bad_nt sig=0x%X", nt->Signature);
                webhook::write_log("anti_dump", buf);
                return false;
            }
            if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                nt->OptionalHeader.Magic != 0)
            {
                char buf[96];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "locate_iat_range_bad_magic magic=0x%X", nt->OptionalHeader.Magic);
                webhook::write_log("anti_dump", buf);
                return false;
            }
            if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IAT)
            {
                char buf[128];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "locate_iat_range_no_iat_dir count=%u",
                    nt->OptionalHeader.NumberOfRvaAndSizes);
                webhook::write_log("anti_dump", buf);
                return false;
            }

            const auto& iat_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
            if (iat_dir.VirtualAddress == 0 || iat_dir.Size == 0)
            {
                const auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0)
                {
                    webhook::write_log("anti_dump", "locate_iat_range_empty_iat_and_import");
                    return false;
                }
                base_out = reinterpret_cast<uint64_t>(base) + imp_dir.VirtualAddress;
                size_out = imp_dir.Size;
                {
                    char buf[160];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "locate_iat_range_import_fallback rva=0x%X size=0x%X",
                        imp_dir.VirtualAddress, imp_dir.Size);
                    webhook::write_log("anti_dump", buf);
                }
                return true;
            }

            base_out = reinterpret_cast<uint64_t>(base) + iat_dir.VirtualAddress;
            size_out = iat_dir.Size;
            {
                char buf[160];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "locate_iat_range_iat rva=0x%X size=0x%X",
                    iat_dir.VirtualAddress, iat_dir.Size);
                webhook::write_log("anti_dump", buf);
            }
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            webhook::write_log("anti_dump", "locate_iat_range_seh_caught");
            return false;
        }
    }

    inline bool arm_guard()
    {
        uint64_t b = 0;
        uint32_t s = 0;
        if (!locate_iat_range(b, s)) return false;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        DWORD ps = si.dwPageSize ? si.dwPageSize : 0x1000;
        uint64_t aligned_base = b & ~static_cast<uint64_t>(ps - 1);
        uint64_t end = (b + s + ps - 1) & ~static_cast<uint64_t>(ps - 1);
        uint32_t aligned_size = static_cast<uint32_t>(end - aligned_base);

        DWORD old_prot = 0;
        if (!VirtualProtect(reinterpret_cast<void*>(aligned_base), aligned_size,
                PAGE_READONLY | PAGE_GUARD, &old_prot))
        {
            char buf[192];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "iat_guard_VirtualProtect_failed base=0x%llX size=0x%X gle=%lu",
                aligned_base, aligned_size, GetLastError());
            webhook::write_log("anti_dump", buf);
            return false;
        }

        iat_base().store(aligned_base);
        iat_size().store(aligned_size);
        {
            char buf[192];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "iat_guard_range base=0x%llX size=0x%X old=0x%X",
                aligned_base, aligned_size, old_prot);
            webhook::write_log("anti_dump", buf);
        }
        return true;
    }

    inline bool rearm_guard()
    {
        uint64_t b = iat_base().load();
        uint32_t s = iat_size().load();
        if (b == 0 || s == 0) return false;

        DWORD old_prot = 0;
        return VirtualProtect(reinterpret_cast<void*>(b), s,
            PAGE_READONLY | PAGE_GUARD, &old_prot) != 0;
    }

    inline DWORD page_size()
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return si.dwPageSize ? si.dwPageSize : 0x1000u;
    }

    inline bool page_for_fault(uint64_t fault_addr, uint64_t& page_base, uint32_t& page_span)
    {
        uint64_t b = iat_base().load();
        uint32_t s = iat_size().load();
        if (b == 0 || s == 0) return false;
        if (fault_addr < b || fault_addr >= b + s) return false;

        DWORD ps = page_size();
        page_base = fault_addr & ~static_cast<uint64_t>(ps - 1);
        page_span = ps;
        return true;
    }

    inline bool rearm_guard_page(uint64_t page_base, uint32_t page_span)
    {
        uint64_t b = iat_base().load();
        uint32_t s = iat_size().load();
        if (b == 0 || s == 0 || page_base == 0 || page_span == 0) return false;

        uint64_t page_end = page_base + page_span;
        uint64_t iat_end = b + s;
        if (page_base >= iat_end || page_end <= b) return false;

        DWORD old_prot = 0;
        return VirtualProtect(reinterpret_cast<void*>(page_base), page_span,
            PAGE_READONLY | PAGE_GUARD, &old_prot) != 0;
    }

    inline bool address_in_range(uint64_t addr)
    {
        uint64_t b = iat_base().load();
        uint32_t s = iat_size().load();
        if (b == 0 || s == 0) return false;
        return addr >= b && addr < b + s;
    }

    inline void register_hit()
    {
        detail::scylla_iat_hits().fetch_add(1, std::memory_order_relaxed);
    }

    inline uint64_t hit_count()
    {
        return detail::scylla_iat_hits().load(std::memory_order_relaxed);
    }

    inline void scrub_xor_key()
    {
        detail::xor_key() = detail::generate_session_key();
    }

}

namespace text_guard
{

    inline std::atomic<uint64_t>& text_base()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint32_t>& text_size()
    {
        static std::atomic<uint32_t> v{0};
        return v;
    }

    inline std::atomic<bool>& cycle_running()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline bool locate_text_range(uint64_t& base_out, uint32_t& size_out)
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        IMAGE_NT_HEADERS64* nt = nullptr;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
            nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        else
            nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

        if (!nt) return false;
        if (nt->Signature != IMAGE_NT_SIGNATURE && nt->Signature != 0)
            return false;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        WORD num = nt->FileHeader.NumberOfSections;
        for (WORD i = 0; i < num; ++i)
        {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                base_out = reinterpret_cast<uint64_t>(base) + sec[i].VirtualAddress;
                size_out = sec[i].Misc.VirtualSize;
                return true;
            }
        }

        return false;
    }

    inline void cycle_thread()
    {
        uint64_t b = text_base().load();
        uint32_t s = text_size().load();
        if (b == 0 || s == 0) return;

        bool in_noaccess = false;
        while (cycle_running().load())
        {
            DWORD old = 0;
            if (in_noaccess)
            {
                if (VirtualProtect(reinterpret_cast<void*>(b), s,
                    PAGE_EXECUTE_READ, &old))
                {
                    in_noaccess = false;
                }
            }
            else
            {
                in_noaccess = true;
            }
            Sleep(100);
        }
        DWORD old = 0;
        VirtualProtect(reinterpret_cast<void*>(b), s, PAGE_EXECUTE_READ, &old);
    }

    inline bool start_cycle()
    {
        uint64_t b = 0;
        uint32_t s = 0;
        if (!locate_text_range(b, s)) return false;

        text_base().store(b);
        text_size().store(s);
        cycle_running().store(true);
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "anti_tamper_anti_dump";
        sub.label = "anti_dump.cycle_thread";
        sub.thread_class = "security_loop";
        sub.domain = aida::infra::executor::domain_t::security_liveness;
        sub.priority = 0;
        sub.body = cycle_thread;
        if (!aida::infra::executor::submit(std::move(sub)).submitted)
        {
            cycle_running().store(false);
            return false;
        }
        return true;
    }

    inline void stop_cycle()
    {
        cycle_running().store(false);
    }

    inline bool address_in_range(uint64_t addr)
    {
        uint64_t b = text_base().load();
        uint32_t s = text_size().load();
        if (b == 0 || s == 0) return false;
        return addr >= b && addr < b + s;
    }

    inline void register_hit()
    {
        detail::ollydump_text_hits().fetch_add(1, std::memory_order_relaxed);
    }

    inline uint64_t hit_count()
    {
        return detail::ollydump_text_hits().load(std::memory_order_relaxed);
    }

}


namespace read_intercept
{

    inline PVOID veh_handle = nullptr;
    inline std::atomic<uint64_t> trap_page_base{0};
    inline std::atomic<uint32_t> trap_page_size{0};
    enum : uint32_t
    {
        pending_step_iat = 0x1u,
        pending_step_trap = 0x2u,
        pending_step_text = 0x4u
    };

    struct pending_step_slot
    {
        std::atomic<DWORD> tid;
        std::atomic<uint64_t> iat_page_base;
        std::atomic<uint32_t> iat_page_size;
        std::atomic<uint64_t> trap_page_base;
        std::atomic<uint32_t> trap_page_size;
        std::atomic<uint32_t> flags;
        std::atomic<uint64_t> tick;

        pending_step_slot() noexcept
            : tid(0),
              iat_page_base(0),
              iat_page_size(0),
              trap_page_base(0),
              trap_page_size(0),
              flags(0),
              tick(0)
        {
        }
    };

    inline pending_step_slot* pending_step_slots()
    {
        static pending_step_slot slots[64];
        return slots;
    }

    inline std::atomic<uint64_t>& iat_gpv_count()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>& iat_rearm_count()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>& orphan_single_step_grace_until_ms()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>& orphan_single_step_count()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline std::atomic<uint64_t>& orphan_single_step_reject_count()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline void arm_orphan_single_step_grace(uint64_t duration_ms)
    {
        if (duration_ms == 0)
            return;
        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        const uint64_t until = now + duration_ms;
        auto& slot = orphan_single_step_grace_until_ms();
        uint64_t cur = slot.load(std::memory_order_acquire);
        while (cur < until &&
            !slot.compare_exchange_weak(cur, until, std::memory_order_acq_rel, std::memory_order_acquire))
        {
        }
    }

    inline bool address_in_current_image(uint64_t address)
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod)
            return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        __try
        {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return false;
            if (dos->e_lfanew <= 0 || static_cast<uint32_t>(dos->e_lfanew) > 0x10000u)
                return false;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return false;
            const uint64_t image_base = reinterpret_cast<uint64_t>(base);
            const uint64_t image_size = nt->OptionalHeader.SizeOfImage;
            return image_size != 0 && address >= image_base && address < image_base + image_size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    struct trusted_system_image_info
    {
        MEMORY_BASIC_INFORMATION mbi{};
        DWORD vq_ok = 0;
        DWORD path_ok = 0;
        bool committed_image = false;
        bool non_writable = false;
        bool system32 = false;
        bool name_allowlisted = false;
        bool allowlisted = false;
        HMODULE module = nullptr;
        uint64_t module_base = 0;
        uint64_t module_offset = 0;
        char module_name[96] = "<unknown>";
        char module_path[MAX_PATH] = "<unknown>";
    };

    struct orphan_stack_evidence
    {
        int first_aida_return_index = -1;
        DWORD readable_slots = 0;
        DWORD read_failed = 0;
        char top_qwords[960] = "<none>";
    };

    inline const char* basename_from_path_a(const char* path)
    {
        if (!path || path[0] == '\0')
            return "<unknown>";
        const char* name = path;
        for (const char* p = path; *p; ++p)
        {
            if (*p == '\\' || *p == '/')
                name = p + 1;
        }
        return name && *name ? name : "<unknown>";
    }

    inline const wchar_t* basename_from_path_w(const wchar_t* path, DWORD len)
    {
        if (!path || len == 0)
            return L"<unknown>";
        const wchar_t* name = path;
        for (DWORD i = 0; i < len; ++i)
        {
            if (path[i] == L'\\' || path[i] == L'/')
                name = path + i + 1;
        }
        return name && *name ? name : L"<unknown>";
    }

    inline bool is_trusted_orphan_system_module_name(const wchar_t* name)
    {
        return lstrcmpiW(name, L"user32.dll") == 0 ||
            lstrcmpiW(name, L"win32u.dll") == 0 ||
            lstrcmpiW(name, L"ntdll.dll") == 0 ||
            lstrcmpiW(name, L"bcrypt.dll") == 0 ||
            lstrcmpiW(name, L"kernelbase.dll") == 0 ||
            lstrcmpiW(name, L"kernel32.dll") == 0;
    }

    inline bool collect_trusted_system_image_info(uint64_t address, trusted_system_image_info& info)
    {
        info = trusted_system_image_info{};
        info.vq_ok = VirtualQuery(reinterpret_cast<void*>(address), &info.mbi, sizeof(info.mbi)) != 0 ? 1u : 0u;
        if (!info.vq_ok)
            return false;
        info.committed_image = info.mbi.State == MEM_COMMIT && info.mbi.Type == MEM_IMAGE;
        const DWORD protect = info.mbi.Protect & 0xFFu;
        const DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        info.non_writable = (info.mbi.Protect & PAGE_GUARD) == 0 && protect != PAGE_NOACCESS && (protect & writable) == 0;

        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address), &info.module) || !info.module)
            return false;
        info.module_base = reinterpret_cast<uint64_t>(info.module);
        info.module_offset = info.module_base != 0 && address >= info.module_base ? address - info.module_base : 0;

        wchar_t path[MAX_PATH] = {};
        DWORD len = GetModuleFileNameW(info.module, path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
            return false;
        info.path_ok = 1;
        GetModuleFileNameA(info.module, info.module_path, MAX_PATH);
        _snprintf_s(info.module_name, sizeof(info.module_name), _TRUNCATE, "%s", basename_from_path_a(info.module_path));
        const wchar_t* name = basename_from_path_w(path, len);
        info.name_allowlisted = is_trusted_orphan_system_module_name(name);
        if (!info.committed_image || !info.non_writable)
            return false;

        wchar_t system_dir[MAX_PATH] = {};
        DWORD system_len = GetSystemDirectoryW(system_dir, MAX_PATH);
        if (system_len == 0 || system_len >= MAX_PATH || len <= system_len)
            return false;
        if (CompareStringOrdinal(path, static_cast<int>(system_len), system_dir, static_cast<int>(system_len), TRUE) != CSTR_EQUAL)
            return false;
        if (path[system_len] != L'\\' && path[system_len] != L'/')
            return false;
        info.system32 = true;

        info.allowlisted = info.committed_image && info.non_writable && info.system32 && info.name_allowlisted;
        return info.allowlisted;
    }

    inline bool address_in_trusted_system_image(uint64_t address)
    {
        trusted_system_image_info info{};
        return collect_trusted_system_image_info(address, info);
    }

    inline void format_module_label(uint64_t address, char* out, size_t out_size)
    {
        if (!out || out_size == 0)
            return;
        out[0] = '\0';
        if (address == 0)
        {
            _snprintf_s(out, out_size, _TRUNCATE, "<null>");
            return;
        }
        HMODULE mod = nullptr;
        char path[MAX_PATH] = "<unmapped>";
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(address), &mod) && mod)
        {
            GetModuleFileNameA(mod, path, MAX_PATH);
            const uint64_t base = reinterpret_cast<uint64_t>(mod);
            const uint64_t off = address >= base ? address - base : 0;
            _snprintf_s(out, out_size, _TRUNCATE, "%s+0x%llX", basename_from_path_a(path), static_cast<unsigned long long>(off));
            return;
        }
        _snprintf_s(out, out_size, _TRUNCATE, "<unmapped>");
    }

    inline orphan_stack_evidence inspect_orphan_stack(uint64_t rsp)
    {
        orphan_stack_evidence evidence{};
        if (rsp == 0)
        {
            _snprintf_s(evidence.top_qwords, sizeof(evidence.top_qwords), _TRUNCATE, "<rsp_null>");
            evidence.read_failed = 1;
            return evidence;
        }

        int off = 0;
        evidence.top_qwords[0] = '\0';
        for (uint32_t i = 0; i < 32; ++i)
        {
            uint64_t value = 0;
            __try
            {
                value = *(reinterpret_cast<const uint64_t*>(rsp) + i);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                evidence.read_failed = 1;
                break;
            }

            evidence.readable_slots = i + 1;
            if (evidence.first_aida_return_index < 0 && address_in_current_image(value))
                evidence.first_aida_return_index = static_cast<int>(i);

            if (i < 8 && off < static_cast<int>(sizeof(evidence.top_qwords) - 96))
            {
                char label[128] = {};
                format_module_label(value, label, sizeof(label));
                off += _snprintf_s(evidence.top_qwords + off, sizeof(evidence.top_qwords) - off, _TRUNCATE,
                    "%s[%u]=0x%016llX{%s}",
                    i == 0 ? "" : " ",
                    i,
                    static_cast<unsigned long long>(value),
                    label);
            }
        }
        if (evidence.top_qwords[0] == '\0')
            _snprintf_s(evidence.top_qwords, sizeof(evidence.top_qwords), _TRUNCATE, "<unreadable>");
        return evidence;
    }

    inline bool stack_has_current_image_return(uint64_t rsp)
    {
        return inspect_orphan_stack(rsp).first_aida_return_index >= 0;
    }

    inline void log_orphan_single_step_reject(
        EXCEPTION_POINTERS* ep,
        const char* source,
        const char* reason,
        uint64_t now,
        uint64_t grace_until,
        bool active,
        bool rip_current_image,
        bool rip_trusted_system,
        bool stack_current_image)
    {
        const uint64_t n = orphan_single_step_reject_count().fetch_add(1, std::memory_order_relaxed) + 1;
        if (n > 32 && (n % 128ULL) != 0ULL)
            return;

        CONTEXT* ctx = ep ? ep->ContextRecord : nullptr;
        const uint64_t rip = ctx ? static_cast<uint64_t>(ctx->Rip) : 0;
        const uint64_t rsp = ctx ? static_cast<uint64_t>(ctx->Rsp) : 0;
        const uint64_t dr6 = ctx ? static_cast<uint64_t>(ctx->Dr6) : 0;
        const uint64_t dr7 = ctx ? static_cast<uint64_t>(ctx->Dr7) : 0;
        const DWORD eflags = ctx ? ctx->EFlags : 0;

        trusted_system_image_info image{};
        collect_trusted_system_image_info(rip, image);
        orphan_stack_evidence stack = inspect_orphan_stack(rsp);
        const bool stack_check_skipped_non_allowlisted = !rip_current_image && !image.allowlisted;

        char dbg[4096];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "orphan_single_step_reject #%llu source=%s reason=%s rip=0x%llX rsp=0x%llX tid=%lu dr6=0x%llX dr7=0x%llX eflags=0x%08lX active=%d grace_until=%llu remaining_ms=%llu current_image=%d trusted_system=%d stack_current_image=%d allowlisted=%d name_allowlisted=%d system32=%d committed_image=%d non_writable=%d stack_check_skipped_non_allowlisted=%d first_aida_stack_index=%d stack_slots=%lu stack_read_failed=%lu module_name=%s module_offset=0x%llX module=%s vq=%lu path_ok=%lu mbi_base=0x%llX mbi_alloc=0x%llX mbi_size=0x%llX mbi_state=0x%08lX mbi_protect=0x%08lX mbi_type=0x%08lX top_stack=\"%s\" iat=0x%llX/0x%X trap=0x%llX/0x%X text=0x%llX/0x%X",
            static_cast<unsigned long long>(n),
            source ? source : "veh",
            reason ? reason : "unknown",
            static_cast<unsigned long long>(rip),
            static_cast<unsigned long long>(rsp),
            GetCurrentThreadId(),
            static_cast<unsigned long long>(dr6),
            static_cast<unsigned long long>(dr7),
            static_cast<unsigned long>(eflags),
            active ? 1 : 0,
            static_cast<unsigned long long>(grace_until),
            static_cast<unsigned long long>(grace_until >= now ? grace_until - now : 0),
            rip_current_image ? 1 : 0,
            rip_trusted_system ? 1 : 0,
            stack_current_image ? 1 : 0,
            image.allowlisted ? 1 : 0,
            image.name_allowlisted ? 1 : 0,
            image.system32 ? 1 : 0,
            image.committed_image ? 1 : 0,
            image.non_writable ? 1 : 0,
            stack_check_skipped_non_allowlisted ? 1 : 0,
            stack.first_aida_return_index,
            static_cast<unsigned long>(stack.readable_slots),
            static_cast<unsigned long>(stack.read_failed),
            image.module_name,
            static_cast<unsigned long long>(image.module_offset),
            image.module_path,
            static_cast<unsigned long>(image.vq_ok),
            static_cast<unsigned long>(image.path_ok),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(image.mbi.BaseAddress)),
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(image.mbi.AllocationBase)),
            static_cast<unsigned long long>(image.mbi.RegionSize),
            image.mbi.State,
            image.mbi.Protect,
            image.mbi.Type,
            stack.top_qwords,
            static_cast<unsigned long long>(iat_guard::iat_base().load(std::memory_order_acquire)),
            iat_guard::iat_size().load(std::memory_order_acquire),
            static_cast<unsigned long long>(trap_page_base.load(std::memory_order_acquire)),
            trap_page_size.load(std::memory_order_acquire),
            static_cast<unsigned long long>(text_guard::text_base().load(std::memory_order_acquire)),
            text_guard::text_size().load(std::memory_order_acquire));
        webhook::write_log("veh", dbg);
    }

    inline pending_step_slot* find_pending_step_slot(DWORD tid)
    {
        pending_step_slot* slots = pending_step_slots();
        for (size_t i = 0; i < 64; ++i)
        {
            if (slots[i].tid.load(std::memory_order_acquire) == tid)
                return &slots[i];
        }
        return nullptr;
    }

    inline pending_step_slot& reserve_pending_step_slot(DWORD tid)
    {
        pending_step_slot* existing = find_pending_step_slot(tid);
        if (existing)
            return *existing;

        pending_step_slot* slots = pending_step_slots();
        for (size_t i = 0; i < 64; ++i)
        {
            DWORD expected = 0;
            if (slots[i].tid.compare_exchange_strong(expected, tid, std::memory_order_acq_rel))
            {
                slots[i].iat_page_base.store(0, std::memory_order_release);
                slots[i].iat_page_size.store(0, std::memory_order_release);
                slots[i].trap_page_base.store(0, std::memory_order_release);
                slots[i].trap_page_size.store(0, std::memory_order_release);
                slots[i].flags.store(0, std::memory_order_release);
                slots[i].tick.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
                return slots[i];
            }
        }

        pending_step_slot& slot = slots[tid % 64u];
        slot.flags.store(0, std::memory_order_release);
        slot.iat_page_base.store(0, std::memory_order_release);
        slot.iat_page_size.store(0, std::memory_order_release);
        slot.trap_page_base.store(0, std::memory_order_release);
        slot.trap_page_size.store(0, std::memory_order_release);
        slot.tick.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        slot.tid.store(tid, std::memory_order_release);
        return slot;
    }

    inline void mark_iat_pending(uint64_t page_base, uint32_t page_size)
    {
        arm_orphan_single_step_grace(5000);
        pending_step_slot& slot = reserve_pending_step_slot(GetCurrentThreadId());
        slot.iat_page_base.store(page_base, std::memory_order_release);
        slot.iat_page_size.store(page_size, std::memory_order_release);
        slot.tick.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        slot.flags.fetch_or(pending_step_iat, std::memory_order_acq_rel);
    }

    inline void mark_trap_pending(uint64_t page_base, uint32_t page_size)
    {
        arm_orphan_single_step_grace(5000);
        pending_step_slot& slot = reserve_pending_step_slot(GetCurrentThreadId());
        slot.trap_page_base.store(page_base, std::memory_order_release);
        slot.trap_page_size.store(page_size, std::memory_order_release);
        slot.tick.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        slot.flags.fetch_or(pending_step_trap, std::memory_order_acq_rel);
    }

    inline void mark_text_pending()
    {
        arm_orphan_single_step_grace(5000);
        pending_step_slot& slot = reserve_pending_step_slot(GetCurrentThreadId());
        slot.tick.store(static_cast<uint64_t>(GetTickCount64()), std::memory_order_release);
        slot.flags.fetch_or(pending_step_text, std::memory_order_acq_rel);
    }

    inline bool consume_pending_single_step(EXCEPTION_POINTERS* ep, const char* source)
    {
        if (!ep || !ep->ExceptionRecord || ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP || !ep->ContextRecord)
            return false;

        const DWORD tid = GetCurrentThreadId();
        pending_step_slot* slot = find_pending_step_slot(tid);
        if (!slot)
            return false;

        const uint32_t flags = slot->flags.exchange(0, std::memory_order_acq_rel);
        if (flags == 0)
            return false;

        const uint64_t iat_base = slot->iat_page_base.exchange(0, std::memory_order_acq_rel);
        const uint32_t iat_size = slot->iat_page_size.exchange(0, std::memory_order_acq_rel);
        const uint64_t trap_base = slot->trap_page_base.exchange(0, std::memory_order_acq_rel);
        const uint32_t trap_size = slot->trap_page_size.exchange(0, std::memory_order_acq_rel);
        const uint64_t age_ms = static_cast<uint64_t>(GetTickCount64()) - slot->tick.load(std::memory_order_acquire);

        bool handled = false;
        if ((flags & pending_step_iat) != 0 && iat_base != 0 && iat_size != 0)
        {
            bool rearm_ok = iat_guard::rearm_guard_page(iat_base, iat_size);
            uint64_t n = iat_rearm_count().fetch_add(1, std::memory_order_relaxed) + 1;
            if (!rearm_ok || n <= 3)
            {
                char dbg[320];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "iat_guard_rearm_page #%llu ok=%d source=%s rip=0x%llX tid=%lu page=0x%llX size=0x%X age_ms=%llu",
                    n, rearm_ok ? 1 : 0, source ? source : "veh",
                    ep->ContextRecord->Rip, tid, iat_base, iat_size,
                    static_cast<unsigned long long>(age_ms));
                webhook::write_log("veh", dbg);
            }
            handled = true;
        }

        if ((flags & pending_step_trap) != 0 && trap_base != 0 && trap_size != 0)
        {
            DWORD old_prot = 0;
            VirtualProtect(reinterpret_cast<void*>(trap_base), trap_size,
                PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
            handled = true;
        }

        if ((flags & pending_step_text) != 0)
            handled = true;

        slot->tid.store(0, std::memory_order_release);

        if (handled)
        {
            ep->ContextRecord->EFlags &= ~0x100u;
            return true;
        }

        return false;
    }

    inline bool consume_orphan_single_step(EXCEPTION_POINTERS* ep, const char* source)
    {
        if (!ep || !ep->ExceptionRecord || ep->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP || !ep->ContextRecord)
            return false;

        const uint64_t now = static_cast<uint64_t>(GetTickCount64());
        const uint64_t grace_until = orphan_single_step_grace_until_ms().load(std::memory_order_acquire);
        if (grace_until == 0 || now > grace_until)
        {
            log_orphan_single_step_reject(ep, source,
                grace_until == 0 ? "grace_unarmed" : "grace_expired",
                now, grace_until, false, false, false, false);
            return false;
        }

        const bool active =
            iat_guard::iat_base().load(std::memory_order_acquire) != 0 ||
            trap_page_base.load(std::memory_order_acquire) != 0 ||
            text_guard::text_base().load(std::memory_order_acquire) != 0;
        if (!active)
        {
            log_orphan_single_step_reject(ep, source, "guards_inactive",
                now, grace_until, false, false, false, false);
            return false;
        }

        if (IsDebuggerPresent())
        {
            log_orphan_single_step_reject(ep, source, "debugger_present",
                now, grace_until, active, false, false, false);
            return false;
        }
        BOOL remote_debugger = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) && remote_debugger)
        {
            log_orphan_single_step_reject(ep, source, "remote_debugger_present",
                now, grace_until, active, false, false, false);
            return false;
        }

        const uint64_t dr6 = static_cast<uint64_t>(ep->ContextRecord->Dr6);
        if ((dr6 & 0xFULL) != 0)
        {
            log_orphan_single_step_reject(ep, source, "dr6_breakpoint_bits",
                now, grace_until, active, false, false, false);
            return false;
        }
        const uint64_t dr7 = static_cast<uint64_t>(ep->ContextRecord->Dr7);
        if ((dr7 & 0xFFULL) != 0)
        {
            log_orphan_single_step_reject(ep, source, "dr7_breakpoint_enabled",
                now, grace_until, active, false, false, false);
            return false;
        }

        const uint64_t rip = static_cast<uint64_t>(ep->ContextRecord->Rip);
        const bool rip_current_image = address_in_current_image(rip);
        trusted_system_image_info image{};
        const bool rip_system_allowlisted = collect_trusted_system_image_info(rip, image);
        const bool rip_trusted_system = !rip_current_image && rip_system_allowlisted;
        orphan_stack_evidence stack = inspect_orphan_stack(static_cast<uint64_t>(ep->ContextRecord->Rsp));
        const bool stack_current_image = rip_trusted_system && stack.first_aida_return_index >= 0;
        const bool rip_trusted_system_with_app_stack =
            rip_trusted_system && stack_current_image;
        if (!rip_current_image && !rip_trusted_system_with_app_stack)
        {
            log_orphan_single_step_reject(ep, source, "untrusted_rip_or_missing_aida_stack",
                now, grace_until, active, rip_current_image, rip_trusted_system, stack_current_image);
            return false;
        }

        const DWORD tid = GetCurrentThreadId();
        const DWORD old_eflags = ep->ContextRecord->EFlags;
        ep->ContextRecord->EFlags &= ~0x100u;
        ep->ContextRecord->Dr6 = 0;

        const uint64_t n = orphan_single_step_count().fetch_add(1, std::memory_order_relaxed) + 1;
        if (n <= 16 || (n % 128ULL) == 0ULL)
        {
            char dbg[4096];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "orphan_single_step_consumed #%llu source=%s rip=0x%llX scope=%s tid=%lu dr6=0x%llX dr7=0x%llX old_eflags=0x%08lX remaining_ms=%llu allowlisted=%d name_allowlisted=%d system32=%d committed_image=%d non_writable=%d first_aida_stack_index=%d stack_slots=%lu stack_read_failed=%lu module_name=%s module_offset=0x%llX module=%s top_stack=\"%s\" iat=0x%llX/0x%X trap=0x%llX/0x%X text=0x%llX/0x%X",
                static_cast<unsigned long long>(n),
                source ? source : "veh",
                static_cast<unsigned long long>(rip),
                rip_current_image ? "current_image" : "trusted_system_app_stack",
                tid,
                static_cast<unsigned long long>(dr6),
                static_cast<unsigned long long>(dr7),
                static_cast<unsigned long>(old_eflags),
                static_cast<unsigned long long>(grace_until >= now ? grace_until - now : 0),
                image.allowlisted ? 1 : 0,
                image.name_allowlisted ? 1 : 0,
                image.system32 ? 1 : 0,
                image.committed_image ? 1 : 0,
                image.non_writable ? 1 : 0,
                stack.first_aida_return_index,
                static_cast<unsigned long>(stack.readable_slots),
                static_cast<unsigned long>(stack.read_failed),
                image.module_name,
                static_cast<unsigned long long>(image.module_offset),
                image.module_path,
                stack.top_qwords,
                static_cast<unsigned long long>(iat_guard::iat_base().load(std::memory_order_acquire)),
                iat_guard::iat_size().load(std::memory_order_acquire),
                static_cast<unsigned long long>(trap_page_base.load(std::memory_order_acquire)),
                trap_page_size.load(std::memory_order_acquire),
                static_cast<unsigned long long>(text_guard::text_base().load(std::memory_order_acquire)),
                text_guard::text_size().load(std::memory_order_acquire));
            webhook::write_log("veh", dbg);
        }
        return true;
    }

    inline void*& trap_page_allocation()
    {
        static void* p = nullptr;
        return p;
    }

    inline LONG CALLBACK guard_page_handler(EXCEPTION_POINTERS* ep)
    {
        if (ep->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        {
            uint64_t fault_addr = static_cast<uint64_t>(
                ep->ExceptionRecord->ExceptionInformation[1]);

            if (iat_guard::address_in_range(fault_addr))
            {
                iat_guard::register_hit();
                iat_guard::scrub_xor_key();
                uint64_t page_base = 0;
                uint32_t page_size = 0;
                if (iat_guard::page_for_fault(fault_addr, page_base, page_size))
                {
                    mark_iat_pending(page_base, page_size);
                    uint64_t n = iat_gpv_count().fetch_add(1, std::memory_order_relaxed) + 1;
                    if (n == 1)
                    {
                        char dbg[256];
                        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                            "iat_guard_GPV #%llu fault_addr=0x%llX rip=0x%llX tid=%lu page=0x%llX size=0x%X",
                            n, fault_addr, ep->ContextRecord->Rip, GetCurrentThreadId(), page_base, page_size);
                        webhook::write_log("veh", dbg);
                    }
                }
                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (text_guard::address_in_range(fault_addr))
            {
                text_guard::register_hit();
                mark_text_pending();
                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            uint64_t base = trap_page_base.load();
            uint32_t size = trap_page_size.load();

            if (base != 0 && fault_addr >= base && fault_addr < base + size)
            {
                mark_trap_pending(base, size);
                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        if (ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
        {
            if (consume_pending_single_step(ep, "veh"))
                return EXCEPTION_CONTINUE_EXECUTION;
            if (consume_orphan_single_step(ep, "veh_orphan"))
                return EXCEPTION_CONTINUE_EXECUTION;
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
        webhook::write_log("anti_dump", "guard_pages_set count=1");
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

    inline bool region_overlaps_range(uint64_t left_base,
                                      uint64_t left_size,
                                      uint64_t right_base,
                                      uint64_t right_size)
    {
        if (left_size == 0 || right_size == 0)
            return false;
        uint64_t left_end = left_base + left_size;
        uint64_t right_end = right_base + right_size;
        if (left_end < left_base || right_end < right_base)
            return false;
        return left_base < right_end && right_base < left_end;
    }

    inline bool region_overlaps_self_section(uint8_t* module_base,
                                             uint64_t region_base,
                                             uint64_t region_size)
    {
        bool overlaps = false;
        __try
        {
            auto* nt = pe_header::safe_resolve_self_nt(module_base, nullptr);
            if (!nt)
                return false;
            WORD num_sections = nt->FileHeader.NumberOfSections;
            if (num_sections == 0 || num_sections > 96)
                return false;
            auto* sections = IMAGE_FIRST_SECTION(nt);
            uint64_t image_size = nt->OptionalHeader.SizeOfImage;
            for (WORD i = 0; i < num_sections; ++i)
            {
                uint64_t section_rva = sections[i].VirtualAddress;
                uint64_t section_size = sections[i].Misc.VirtualSize;
                if (sections[i].SizeOfRawData > section_size)
                    section_size = sections[i].SizeOfRawData;
                if (section_rva == 0 || section_size == 0 || section_rva >= image_size)
                    continue;
                if (section_size > image_size - section_rva)
                    section_size = image_size - section_rva;
                uint64_t section_base = reinterpret_cast<uint64_t>(module_base) + section_rva;
                if (region_overlaps_range(region_base, region_size, section_base, section_size))
                {
                    overlaps = true;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            overlaps = false;
        }
        return overlaps;
    }

    inline bool region_is_host_image(const MEMORY_BASIC_INFORMATION& mbi,
                                     uint8_t* module_base,
                                     uint64_t region_base,
                                     uint64_t region_size)
    {
        if (mbi.Type == MEM_IMAGE)
            return true;
        if (mbi.Type != MEM_PRIVATE)
            return false;
        if (reinterpret_cast<uint64_t>(mbi.AllocationBase) != reinterpret_cast<uint64_t>(module_base))
            return false;
        return region_overlaps_self_section(module_base, region_base, region_size);
    }

    inline bool encrypt_non_code_sections()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

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
                if (region_is_host_image(mbi, reinterpret_cast<uint8_t*>(mod), region_base, region_size))
                {
                    addr = region_base + region_size;
                    continue;
                }

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
            uint32_t rand_size_seed = 0;
            detail::fill_random_bytes(reinterpret_cast<uint8_t*>(&rand_size_seed),
                sizeof(rand_size_seed));
            SIZE_T alloc_size = (1u << 14) + (rand_size_seed & 0x3FFFu);
            void* block = VirtualAlloc(nullptr, alloc_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (block)
            {
                auto* ptr = static_cast<uint8_t*>(block);
                detail::fill_random_bytes(ptr, alloc_size);
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
        auto* nt = pe_header::safe_resolve_self_nt(base, "corrupt_debug_dir");
        if (!nt) return;
        if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
            return;

        uint32_t dbg_rva = 0;
        uint32_t dbg_size = 0;
        __try
        {
            const auto& dbg_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            dbg_rva = dbg_dir.VirtualAddress;
            dbg_size = dbg_dir.Size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            webhook::write_log("anti_dump", "corrupt_debug_dir: SEH on dbg_dir read");
            return;
        }

        if (dbg_rva == 0 || dbg_size == 0) return;

        auto* dbg = base + dbg_rva;
        DWORD old_prot = 0;
        if (VirtualProtect(dbg, dbg_size, PAGE_READWRITE, &old_prot))
        {
            __try
            {
                memset(dbg, 0xCC, dbg_size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                webhook::write_log("anti_dump", "corrupt_debug_dir: SEH on memset");
            }
            VirtualProtect(dbg, dbg_size, old_prot, &old_prot);
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

    inline bool copy_current_user_sid(std::vector<BYTE>& out_sid)
    {
        out_sid.clear();
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_token_open_failed gle=%lu", GetLastError());
            webhook::write_log("anti_dump", buf);
            return false;
        }

        DWORD needed = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
        if (needed == 0)
        {
            CloseHandle(token);
            webhook::write_log("anti_dump", "seal_dacl_token_size_failed");
            return false;
        }

        std::vector<BYTE> token_user(needed);
        if (!GetTokenInformation(token, TokenUser, token_user.data(), needed, &needed))
        {
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_token_query_failed gle=%lu", GetLastError());
            CloseHandle(token);
            webhook::write_log("anti_dump", buf);
            return false;
        }
        CloseHandle(token);

        auto* user = reinterpret_cast<TOKEN_USER*>(token_user.data());
        DWORD sid_len = GetLengthSid(user->User.Sid);
        out_sid.resize(sid_len);
        if (!CopySid(sid_len, out_sid.data(), user->User.Sid))
        {
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_sid_copy_failed gle=%lu", GetLastError());
            out_sid.clear();
            webhook::write_log("anti_dump", buf);
            return false;
        }
        return true;
    }

    inline bool apply_process_dacl_seal()
    {
        webhook::write_log("anti_dump", "seal_dacl_begin");
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
        webhook::write_log("anti_dump", "seal_dacl_set_entries_begin");
        DWORD acl_rc = SetEntriesInAclW(count, entries, nullptr, &acl);
        if (acl_rc != ERROR_SUCCESS || !acl)
        {
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_set_entries_failed rc=%lu", acl_rc);
            webhook::write_log("anti_dump", buf);
            return false;
        }

        webhook::write_log("anti_dump", "seal_dacl_set_security_begin");
        DWORD set_rc = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, acl, nullptr);
        LocalFree(acl);

        if (set_rc != ERROR_SUCCESS)
        {
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_set_security_failed rc=%lu", set_rc);
            webhook::write_log("anti_dump", buf);
            return false;
        }

        char buf[128];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "seal_dacl_ok entries=%lu mask=0x%08X", count, limited_access);
        webhook::write_log("anti_dump", buf);
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
            webhook::write_log("anti_dump", "seal_dacl_worker_alloc_failed");
            return false;
        }

        state->done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!state->done_event)
        {
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_worker_event_failed gle=%lu", GetLastError());
            webhook::write_log("anti_dump", buf);
            delete state;
            return false;
        }

        auto wait_for_worker = [&](const char* path) -> bool
        {
            DWORD wait = WaitForSingleObject(state->done_event, timeout_ms);
            if (wait == WAIT_OBJECT_0)
            {
                bool ok = state->ok.load(std::memory_order_acquire);
                DWORD seh = state->seh_code.load(std::memory_order_acquire);
                CloseHandle(state->done_event);
                delete state;
                if (seh != 0)
                {
                    char buf[128];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "seal_dacl_worker_seh path=%s code=0x%08lX",
                        path ? path : "unknown", seh);
                    webhook::write_log("anti_dump", buf);
                    return false;
                }
                return ok;
            }

            char buf[160];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_worker_timeout path=%s wait=0x%08lX timeout_ms=%lu",
                path ? path : "unknown", wait, timeout_ms);
            webhook::write_log("anti_dump", buf);
            return false;
        };

        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "anti_tamper_anti_dump";
        sub.label = "anti_dump.dacl_seal_worker";
        sub.thread_class = "security_task";
        sub.domain = aida::infra::executor::domain_t::critical;
        sub.priority = 0;
        sub.body = [state]() {
            dacl_seal_worker_proc(state);
        };
        bool posted = aida::infra::executor::submit(std::move(sub)).submitted;
        if (posted)
        {
            webhook::write_log("anti_dump", "seal_dacl_worker_executor_posted");
            return wait_for_worker("executor");
        }

        webhook::write_log("anti_dump", "seal_dacl_worker_executor_post_failed");
        CloseHandle(state->done_event);
        delete state;
        return false;
    }

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
        if (!pSet) {
            webhook::write_log("anti_dump", "seal_strip_no_NtSetInformationProcess");
            bool dacl_ok = apply_process_dacl_seal_bounded(1500);
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_fallback_result ok=%d", dacl_ok ? 1 : 0);
            webhook::write_log("anti_dump", buf);
            return;
        }

        ULONG protected_proc = 1;
        webhook::write_log("anti_dump", "seal_ppl_attempt");
        NTSTATUS st = pSet(GetCurrentProcess(), 0x3D, &protected_proc, sizeof(protected_proc));
        bool ppl_ok = st >= 0;
        {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                ppl_ok ? "seal_ppl_ok status=0x%08X" : "seal_ppl_unavailable status=0x%08X",
                static_cast<unsigned>(st));
            webhook::write_log("anti_dump", buf);
        }
        if (!ppl_ok)
        {
            webhook::write_log("anti_dump", "seal_dacl_fallback_begin");
            bool dacl_ok = apply_process_dacl_seal_bounded(1500);
            char buf[96];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_dacl_fallback_result ok=%d", dacl_ok ? 1 : 0);
            webhook::write_log("anti_dump", buf);
        }
    }

    inline void clear_critical_flags()
    {
        using NtSetInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
        auto pSet = reinterpret_cast<NtSetInformationProcess_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationProcess"));
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
        while (detail::monitors_running().load())
        {
            Sleep(500);

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
    webhook::write_log("anti_dump", "xor_key_ok");

    dump_poison::corrupt_debug_directory();
    webhook::write_log("anti_dump", "corrupt_debug_dir_ok");

    dump_poison::flood_decoy_memory();
    webhook::write_log("anti_dump", "flood_decoy_ok");

    dump_poison::scramble_thread_objects();
    webhook::write_log("anti_dump", "scramble_threads_ok");

    anti_minidump::hook_minidump();
    webhook::write_log("anti_dump", "hook_minidump_ok");


    detail::active().store(true);
    webhook::write_log("anti_dump", "active_store_ok");

    detail::monitors_running().store(true);
    webhook::write_log("anti_dump", "monitors_store_ok");

    static std::atomic<bool> s_anti_dump_reencrypt_posted{false};
    bool expected_posted = false;
    if (s_anti_dump_reencrypt_posted.compare_exchange_strong(expected_posted, true, std::memory_order_acq_rel))
    {
        aida::infra::executor::submission_t sub;
        sub.owner_subsystem = "anti_tamper_anti_dump";
        sub.label = "anti_dump.periodic_reencrypt";
        sub.thread_class = "service_loop";
        sub.domain = aida::infra::executor::domain_t::security_liveness;
        sub.priority = 0;
        sub.body = []() { monitor::run_periodic_reencrypt(); };
        if (aida::infra::executor::submit(std::move(sub)).submitted)
            webhook::write_log("anti_dump", "monitor_executor_ok");
        else
        {
            s_anti_dump_reencrypt_posted.store(false, std::memory_order_release);
            webhook::write_log("anti_dump", "monitor_executor_fail");
        }
    }


    bool veh_ok = read_intercept::install_veh();
    webhook::write_log("anti_dump", veh_ok ? "install_veh_ok" : "install_veh_fail");

    if (veh_ok)
    {
        if (iat_guard::arm_guard())
            webhook::write_log("anti_dump", "iat_guard_armed_ok");
        else
            webhook::write_log("anti_dump", "iat_guard_armed_fail");
    }
    else
    {
        webhook::write_log("anti_dump", "iat_guard_skipped_no_veh");
    }

    pe_header::inject_fake_sections();
    webhook::write_log("anti_dump", "inject_fake_sections_ok");

    pe_header::corrupt_nt_headers();
    webhook::write_log("anti_dump", "corrupt_nt_ok");

    pe_header::erase_dos_header();
    webhook::write_log("anti_dump", "erase_dos_ok");

    if (veh_ok)
    {
        if (text_guard::start_cycle())
            webhook::write_log("anti_dump", "text_guard_cycle_started");
        else
            webhook::write_log("anti_dump", "text_guard_cycle_failed");
    }
    else
    {
        webhook::write_log("anti_dump", "text_guard_cycle_skipped_no_veh");
    }

    return true;
}

inline void seal_handles()
{
    handle_strip::revoke_debug_privileges();
    webhook::write_log("anti_dump", "seal_revoke_privs_ok");

    handle_strip::strip_process_handle_access();
    webhook::write_log("anti_dump", "seal_strip_handle_ok");
}

inline void hide_module()
{
    module_stealth::hide_from_peb();
}

inline int scrub_peb_ldr_entry(HMODULE self_module)
{
    return module_stealth::scrub_peb_ldr_entry(self_module);
}

inline void shutdown()
{
    detail::monitors_running().store(false);
    detail::active().store(false);
    text_guard::stop_cycle();
    read_intercept::remove_veh();
}

}

}
