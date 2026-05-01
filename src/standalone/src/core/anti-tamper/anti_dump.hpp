#pragma once

#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <winternl.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "webhook.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")

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

    inline bool erase_dos_header()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) {
            webhook::write_log("anti_dump", "erase_dos: GetModuleHandle null");
            return false;
        }

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "erase_dos: e_magic=0x%X (not MZ), already erased?", dos->e_magic);
            webhook::write_log("anti_dump", buf);
            return false;
        }

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
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

        uint32_t nt_offset = dos->e_lfanew;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + nt_offset);

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


        WORD saved_sizeof_opt = nt->FileHeader.SizeOfOptionalHeader;
        DWORD saved_sizeof_image = nt->OptionalHeader.SizeOfImage;
        ULONGLONG saved_image_base = nt->OptionalHeader.ImageBase;
        DWORD saved_signature = nt->Signature;
        WORD saved_magic = nt->OptionalHeader.Magic;

        nt->Signature = 0;
        nt->OptionalHeader.Magic = 0;
        nt->OptionalHeader.AddressOfEntryPoint = 0xDEADDEAD;
        nt->OptionalHeader.SizeOfHeaders = 0;
        nt->OptionalHeader.CheckSum = 0xFFFFFFFF;

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

    inline bool inject_fake_sections()
    {
        HMODULE mod = GetModuleHandleW(nullptr);
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

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

        nt->FileHeader.NumberOfSections = 8;

        auto* sec = IMAGE_FIRST_SECTION(nt);
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
        __try
        {
            if (!entry->Blink || !entry->Flink) return;
            if (entry->Flink == entry) return;
            entry->Blink->Flink = entry->Flink;
            entry->Flink->Blink = entry->Blink;
            entry->Flink = entry;
            entry->Blink = entry;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
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
        if (!mod) return false;

        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE && dos->e_magic != 0)
            return false;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE && nt->Signature != 0)
            return false;
        if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IAT)
            return false;

        const auto& iat_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        if (iat_dir.VirtualAddress == 0 || iat_dir.Size == 0)
        {
            const auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0)
                return false;
            base_out = reinterpret_cast<uint64_t>(base) + imp_dir.VirtualAddress;
            size_out = imp_dir.Size;
            return true;
        }

        base_out = reinterpret_cast<uint64_t>(base) + iat_dir.VirtualAddress;
        size_out = iat_dir.Size;
        return true;
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
            return false;

        iat_base().store(aligned_base);
        iat_size().store(aligned_size);
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

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
            return false;
        base_out = reinterpret_cast<uint64_t>(mi.lpBaseOfDll) + 0x1000;
        size_out = mi.SizeOfImage > 0x1000 ? mi.SizeOfImage - 0x1000 : 0;
        return size_out != 0;
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
        try
        {
            std::thread(cycle_thread).detach();
        }
        catch (...)
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
                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            if (text_guard::address_in_range(fault_addr))
            {
                text_guard::register_hit();
                ep->ContextRecord->EFlags |= 0x100;
                return EXCEPTION_CONTINUE_EXECUTION;
            }

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
            iat_guard::rearm_guard();

            uint64_t base = trap_page_base.load();
            uint32_t size = trap_page_size.load();
            if (base != 0 && size != 0)
            {
                DWORD old_prot;
                VirtualProtect(reinterpret_cast<void*>(base), size,
                    PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot);
                return EXCEPTION_CONTINUE_EXECUTION;
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
            webhook::write_log("anti_dump", "set_guard_pages: pe_corrupted, setting guards");

            MODULEINFO mi{};
            GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi));

            uint64_t header_end = reinterpret_cast<uint64_t>(mod) + 0x1000;
            uint64_t data_start = header_end;
            uint64_t data_end = reinterpret_cast<uint64_t>(mod) + mi.SizeOfImage;

            int guard_count = 0;
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
                    ++guard_count;
                }

                scan = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
            }
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE, "guard_pages_set count=%d", guard_count);
            webhook::write_log("anti_dump", dbg);
        }
        else
        {
            char dbg[128];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "set_guard_pages: e_magic=0x%X (preserved or zero), skipping", dos->e_magic);
            webhook::write_log("anti_dump", dbg);
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
            return;
        }

        ULONG protected_proc = 1;
        NTSTATUS st = pSet(GetCurrentProcess(), 0x3D, &protected_proc, sizeof(protected_proc));
        {
            char buf[128];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "seal_strip_0x3D status=0x%08X", static_cast<unsigned>(st));
            webhook::write_log("anti_dump", buf);
        }
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

    try
    {
        std::thread(monitor::run_periodic_reencrypt).detach();
        webhook::write_log("anti_dump", "thread_detach_ok");
    }
    catch (const std::exception& ex)
    {
        char buf[256];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "thread_detach_fail: %s", ex.what());
        webhook::write_log("anti_dump", buf);
    }
    catch (...)
    {
        webhook::write_log("anti_dump", "thread_detach_fail_unknown");
    }


    pe_header::inject_fake_sections();
    webhook::write_log("anti_dump", "inject_fake_sections_ok");

    pe_header::corrupt_nt_headers();
    webhook::write_log("anti_dump", "corrupt_nt_ok");

    pe_header::erase_dos_header();
    webhook::write_log("anti_dump", "erase_dos_ok");

    read_intercept::install_veh();
    webhook::write_log("anti_dump", "install_veh_ok");

    if (iat_guard::arm_guard())
        webhook::write_log("anti_dump", "iat_guard_armed_ok");
    else
        webhook::write_log("anti_dump", "iat_guard_armed_fail");

    if (text_guard::start_cycle())
        webhook::write_log("anti_dump", "text_guard_cycle_started");
    else
        webhook::write_log("anti_dump", "text_guard_cycle_failed");

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

inline void shutdown()
{
    detail::monitors_running().store(false);
    detail::active().store(false);
    text_guard::stop_cycle();
    read_intercept::remove_veh();
}

}

}
