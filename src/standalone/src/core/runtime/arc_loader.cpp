#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "arc_loader.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    std::string g_last_error;

    inline uint64_t splitmix64_step(uint64_t& s)
    {
        uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    inline uint64_t rotl64(uint64_t x, int b)
    {
        return (x << b) | (x >> (64 - b));
    }

    inline uint64_t read_u64_le(const uint8_t* p)
    {
        uint64_t r = 0;
        for (int i = 0; i < 8; ++i)
            r |= static_cast<uint64_t>(p[i]) << (i * 8);
        return r;
    }

    uint64_t siphash_2_4(const uint8_t* data, size_t len, uint64_t k0, uint64_t k1)
    {
        uint64_t v0 = k0 ^ 0x736F6D6570736575ULL;
        uint64_t v1 = k1 ^ 0x646F72616E646F6DULL;
        uint64_t v2 = k0 ^ 0x6C7967656E657261ULL;
        uint64_t v3 = k1 ^ 0x7465646279746573ULL;

        const size_t blocks = len / 8u;
        for (size_t i = 0; i < blocks; ++i) {
            uint64_t m = read_u64_le(data + i * 8u);
            v3 ^= m;
            for (int r = 0; r < 2; ++r) {
                v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
                v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
                v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
                v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
            }
            v0 ^= m;
        }

        uint64_t b = static_cast<uint64_t>(len & 0xFFu) << 56;
        const uint8_t* tail = data + blocks * 8u;
        const size_t tail_len = len & 7u;
        for (size_t i = 0; i < tail_len; ++i)
            b |= static_cast<uint64_t>(tail[i]) << (i * 8);

        v3 ^= b;
        for (int r = 0; r < 2; ++r) {
            v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
            v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
        }
        v0 ^= b;

        v2 ^= 0xFFu;
        for (int r = 0; r < 4; ++r) {
            v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
            v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
        }
        return v0 ^ v1 ^ v2 ^ v3;
    }

    void derive_siphash_key(uint64_t salt, uint64_t& k0, uint64_t& k1)
    {
        uint64_t s = salt;
        k0 = splitmix64_step(s);
        k1 = splitmix64_step(s);
    }

    bool generate_random_u64(uint64_t& out)
    {
        out = 0;
        NTSTATUS st = BCryptGenRandom(nullptr,
                                      reinterpret_cast<PUCHAR>(&out),
                                      static_cast<ULONG>(sizeof(out)),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return st == 0 && out != 0;
    }

    bool hash_image_path(uint64_t k0, uint64_t k1, uint64_t& out_hash)
    {
        out_hash = 0;
        wchar_t buf[1024];
        DWORD len = static_cast<DWORD>(sizeof(buf) / sizeof(buf[0]));
        if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, buf, &len) || len == 0)
            return false;
        const size_t byte_count = static_cast<size_t>(len) * sizeof(wchar_t);
        out_hash = siphash_2_4(reinterpret_cast<const uint8_t*>(buf), byte_count, k0, k1);
        return true;
    }

    bool hash_loader_code(uint64_t k0, uint64_t k1, const void* loader_addr, uint64_t& out_hash)
    {
        out_hash = 0;
        const uint8_t* code = reinterpret_cast<const uint8_t*>(loader_addr);
        if (!code)
            return false;
        constexpr size_t kSampleBytes = 4096;
        uint8_t snapshot[kSampleBytes];
        bool ok = false;
        __try {
            std::memcpy(snapshot, code, kSampleBytes);
            ok = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
        }
        if (!ok)
            return false;
        out_hash = siphash_2_4(snapshot, kSampleBytes, k0, k1);
        return true;
    }

    void set_error(const char* msg)
    {
        g_last_error = msg;
        OutputDebugStringA("ARC Loader: ");
        OutputDebugStringA(msg);
        OutputDebugStringA("\n");
    }


    bool validate_pe(const uint8_t* buf, size_t size)
    {
        if (size < sizeof(IMAGE_DOS_HEADER)) {
            set_error("Buffer too small for DOS header.");
            return false;
        }

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            set_error("Invalid DOS signature.");
            return false;
        }

        if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > size) {
            set_error("PE header offset out of bounds.");
            return false;
        }

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buf + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            set_error("Invalid PE signature.");
            return false;
        }

        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
            set_error("Not an x64 PE image.");
            return false;
        }

        if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
            set_error("PE is not a DLL.");
            return false;
        }

        return true;
    }


    bool map_sections(uint8_t* image_base, const uint8_t* pe_buf, size_t pe_size,
                      const IMAGE_NT_HEADERS* nt)
    {

        size_t header_size = nt->OptionalHeader.SizeOfHeaders;
        if (header_size > pe_size) {
            set_error("SizeOfHeaders exceeds PE buffer.");
            return false;
        }
        memcpy(image_base, pe_buf, header_size);


        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].SizeOfRawData == 0)
                continue;


            if (static_cast<size_t>(sec[i].PointerToRawData) + sec[i].SizeOfRawData > pe_size) {
                set_error("Section raw data exceeds PE buffer.");
                return false;
            }


            if (static_cast<size_t>(sec[i].VirtualAddress) + sec[i].SizeOfRawData >
                nt->OptionalHeader.SizeOfImage) {
                set_error("Section virtual address exceeds image size.");
                return false;
            }

            memcpy(image_base + sec[i].VirtualAddress,
                   pe_buf + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }

        return true;
    }


    bool find_reloc_by_section(const IMAGE_NT_HEADERS* nt,
                                uint32_t& out_rva,
                                uint32_t& out_size)
    {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            char nm[9];
            std::memcpy(nm, sec[i].Name, 8);
            nm[8] = '\0';
            if (std::strcmp(nm, ".reloc") == 0) {
                uint32_t s = sec[i].Misc.VirtualSize;
                if (s == 0)
                    s = sec[i].SizeOfRawData;
                if (s == 0)
                    return false;
                out_rva = sec[i].VirtualAddress;
                out_size = s;
                return true;
            }
        }
        return false;
    }

    bool process_relocations(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        auto delta = reinterpret_cast<uintptr_t>(image_base) -
                     nt->OptionalHeader.ImageBase;
        if (delta == 0)
            return true;

        uint32_t reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        uint32_t reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (reloc_rva == 0 || reloc_size == 0) {
            if (!find_reloc_by_section(nt, reloc_rva, reloc_size)) {
                set_error("Image needs relocation but has no relocation directory or .reloc section.");
                return false;
            }
        }

        auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            image_base + reloc_rva);
        auto* reloc_end = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            image_base + reloc_rva + reloc_size);

        while (reloc < reloc_end && reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            uint32_t count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
            auto* entries = reinterpret_cast<uint16_t*>(
                reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));

            for (uint32_t i = 0; i < count; ++i) {
                uint16_t type   = entries[i] >> 12;
                uint16_t offset = entries[i] & 0xFFF;

                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                case IMAGE_REL_BASED_DIR64: {
                    auto* patch = reinterpret_cast<uint64_t*>(
                        image_base + reloc->VirtualAddress + offset);
                    *patch += delta;
                    break;
                }
                case IMAGE_REL_BASED_HIGHLOW: {
                    auto* patch = reinterpret_cast<uint32_t*>(
                        image_base + reloc->VirtualAddress + offset);
                    *patch += static_cast<uint32_t>(delta);
                    break;
                }
                default:
                    set_error("Unsupported relocation type.");
                    return false;
                }
            }

            reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
        }

        return true;
    }


    bool is_allowed_import_dll(const char* name)
    {

        static const char* allowed[] = {
            "kernel32.dll",
            "kernelbase.dll",
            "ntdll.dll",
            "bcrypt.dll",
            "advapi32.dll",
            "ws2_32.dll",
            "iphlpapi.dll",
            "winhttp.dll",
            "crypt32.dll",
            "secur32.dll",
            "msvcrt.dll",
            "msvcp140.dll",
            "msvcp140_1.dll",
            "msvcp140_2.dll",
            "msvcp140_atomic_wait.dll",
            "msvcp140_codecvt_ids.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
            "ucrtbase.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "api-ms-win-crt-heap-l1-1-0.dll",
            "api-ms-win-crt-stdio-l1-1-0.dll",
            "api-ms-win-crt-string-l1-1-0.dll",
            "api-ms-win-crt-math-l1-1-0.dll",
            "api-ms-win-crt-locale-l1-1-0.dll",
            "api-ms-win-crt-time-l1-1-0.dll",
            "api-ms-win-crt-environment-l1-1-0.dll",
            "api-ms-win-crt-convert-l1-1-0.dll",
            "api-ms-win-crt-utility-l1-1-0.dll",
            "api-ms-win-crt-filesystem-l1-1-0.dll",
            "api-ms-win-crt-multibyte-l1-1-0.dll",
            "api-ms-win-crt-conio-l1-1-0.dll",
            "api-ms-win-crt-process-l1-1-0.dll",
            "api-ms-win-crt-private-l1-1-0.dll",
        };

        for (const auto* a : allowed) {
            if (_stricmp(name, a) == 0)
                return true;
        }
        return false;
    }

    bool resolve_imports(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        const auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
            return true;

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            image_base + import_dir.VirtualAddress);

        for (; desc->Name != 0; ++desc) {
            const char* dll_name = reinterpret_cast<const char*>(image_base + desc->Name);

            if (!is_allowed_import_dll(dll_name)) {
                set_error("ARC imports from disallowed DLL.");
                return false;
            }

            HMODULE hMod = GetModuleHandleA(dll_name);
            if (!hMod) {
                hMod = LoadLibraryA(dll_name);
                if (!hMod) {
                    set_error("Failed to load import DLL.");
                    return false;
                }
            }

            auto* thunk_ref = reinterpret_cast<IMAGE_THUNK_DATA*>(
                image_base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
            auto* func_ref = reinterpret_cast<IMAGE_THUNK_DATA*>(
                image_base + desc->FirstThunk);

            for (; thunk_ref->u1.AddressOfData; ++thunk_ref, ++func_ref) {
                FARPROC proc = nullptr;

                if (IMAGE_SNAP_BY_ORDINAL64(thunk_ref->u1.Ordinal)) {
                    proc = GetProcAddress(hMod,
                        MAKEINTRESOURCEA(IMAGE_ORDINAL64(thunk_ref->u1.Ordinal)));
                } else {
                    auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        image_base + thunk_ref->u1.AddressOfData);
                    proc = GetProcAddress(hMod, import_by_name->Name);
                }

                if (!proc) {
                    set_error("Failed to resolve import function.");
                    return false;
                }

                func_ref->u1.Function = reinterpret_cast<uint64_t>(proc);
            }
        }

        return true;
    }


    void finalize_sections(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        const auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            DWORD protect = PAGE_NOACCESS;
            bool exec  = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)  != 0;
            bool read  = (sec[i].Characteristics & IMAGE_SCN_MEM_READ)     != 0;
            bool write = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)    != 0;

            if (exec && read && write)       protect = PAGE_EXECUTE_READWRITE;
            else if (exec && read)           protect = PAGE_EXECUTE_READ;
            else if (exec && write)          protect = PAGE_EXECUTE_WRITECOPY;
            else if (exec)                   protect = PAGE_EXECUTE;
            else if (read && write)          protect = PAGE_READWRITE;
            else if (read)                   protect = PAGE_READONLY;
            else if (write)                  protect = PAGE_WRITECOPY;

            size_t sec_size = sec[i].Misc.VirtualSize;
            if (sec_size == 0)
                sec_size = sec[i].SizeOfRawData;
            if (sec_size == 0)
                continue;

            DWORD old_protect = 0;
            VirtualProtect(image_base + sec[i].VirtualAddress,
                           sec_size, protect, &old_protect);
        }
    }


    bool process_tls(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_dir.VirtualAddress == 0 || tls_dir.Size == 0)
            return true;

        auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(
            image_base + tls_dir.VirtualAddress);
        auto** callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
        if (!callback)
            return true;

        for (; *callback; ++callback) {
            __try {
                (*callback)(image_base, DLL_PROCESS_ATTACH, nullptr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                set_error("TLS callback threw an exception.");
                return false;
            }
        }
        return true;
    }


    void install_guard_pages(uint8_t* image_base, const IMAGE_NT_HEADERS* nt)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        const size_t page_size = static_cast<size_t>(si.dwPageSize);
        if (page_size == 0)
            return;

        const auto* sec = IMAGE_FIRST_SECTION(nt);
        const size_t image_size = nt->OptionalHeader.SizeOfImage;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            if (va < 2u * page_size)
                continue;

            size_t sec_size = sec[i].Misc.VirtualSize;
            if (sec_size == 0)
                sec_size = sec[i].SizeOfRawData;
            if (sec_size == 0)
                continue;

            uint8_t* leading = image_base + va - page_size;
            if (VirtualFree(leading, page_size, MEM_DECOMMIT)) {
                VirtualAlloc(leading, page_size, MEM_COMMIT, PAGE_NOACCESS);
            }

            const size_t aligned_size = (sec_size + (page_size - 1u)) & ~(page_size - 1u);
            uint64_t trailing_off = static_cast<uint64_t>(va) + aligned_size;
            if (trailing_off + page_size > image_size)
                continue;

            uint8_t* trailing = image_base + trailing_off;
            if (VirtualFree(trailing, page_size, MEM_DECOMMIT)) {
                VirtualAlloc(trailing, page_size, MEM_COMMIT, PAGE_NOACCESS);
            }
        }
    }

    void* find_export(uint8_t* image_base, const IMAGE_NT_HEADERS* nt, const char* name)
    {
        const auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_dir.VirtualAddress == 0 || export_dir.Size == 0)
            return nullptr;

        auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            image_base + export_dir.VirtualAddress);

        auto* names     = reinterpret_cast<const uint32_t*>(image_base + exports->AddressOfNames);
        auto* ordinals  = reinterpret_cast<const uint16_t*>(image_base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<const uint32_t*>(image_base + exports->AddressOfFunctions);

        for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
            const char* export_name = reinterpret_cast<const char*>(image_base + names[i]);
            if (strcmp(export_name, name) == 0) {
                uint16_t ordinal = ordinals[i];
                uint32_t rva = functions[ordinal];


                if (rva >= export_dir.VirtualAddress &&
                    rva < export_dir.VirtualAddress + export_dir.Size) {

                    return nullptr;
                }

                return image_base + rva;
            }
        }

        return nullptr;
    }
}


namespace arc_loader
{
    loaded_module_t load(uint8_t* pe_buffer, size_t pe_size)
    {
        loaded_module_t result{};
        g_last_error.clear();

        if (!pe_buffer || pe_size == 0) {
            set_error("Null PE buffer.");
            return result;
        }

        if (!validate_pe(pe_buffer, pe_size))
            return result;

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe_buffer);
        auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(pe_buffer + dos->e_lfanew);

        size_t image_size = nt->OptionalHeader.SizeOfImage;
        size_t header_size_capture = nt->OptionalHeader.SizeOfHeaders;
        if (image_size == 0 || image_size > 64 * 1024 * 1024) {
            set_error("Image size is invalid (0 or > 64MB).");
            return result;
        }

        auto* image_base = static_cast<uint8_t*>(
            VirtualAlloc(reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase),
                         image_size,
                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (!image_base) {
            image_base = static_cast<uint8_t*>(
                VirtualAlloc(nullptr, image_size,
                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        }
        if (!image_base) {
            set_error("VirtualAlloc failed for image.");
            return result;
        }


        if (!map_sections(image_base, pe_buffer, pe_size, nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }


        auto* mapped_nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            image_base + dos->e_lfanew);


        if (!process_relocations(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }


        if (!resolve_imports(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }


        finalize_sections(image_base, mapped_nt);

        install_guard_pages(image_base, mapped_nt);

        if (!process_tls(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        SecureZeroMemory(pe_buffer, pe_size);

        using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto entry_point = reinterpret_cast<DllMain_t>(
            image_base + mapped_nt->OptionalHeader.AddressOfEntryPoint);

        BOOL dll_result = FALSE;
        __try {
            dll_result = entry_point(
                reinterpret_cast<HINSTANCE>(image_base),
                DLL_PROCESS_ATTACH,
                nullptr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            set_error("DllMain threw an exception during DLL_PROCESS_ATTACH.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        if (!dll_result) {
            set_error("DllMain returned FALSE.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        uint64_t binding_salt = 0;
        if (!generate_random_u64(binding_salt)) {
            set_error("BCryptGenRandom failed for binding salt.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        uint64_t k0 = 0, k1 = 0;
        derive_siphash_key(binding_salt, k0, k1);

        uint64_t image_path_hash = 0;
        if (!hash_image_path(k0, k1, image_path_hash)) {
            set_error("QueryFullProcessImageNameW failed for binding hash.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        uint64_t loader_code_hash = 0;
        if (!hash_loader_code(k0, k1, reinterpret_cast<const void*>(&load),
                              loader_code_hash)) {
            set_error("Loader code hash sampling faulted.");
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        result.base             = image_base;
        result.image_size       = image_size;
        result.header_size      = header_size_capture;
        result.entry_point      = image_base + mapped_nt->OptionalHeader.AddressOfEntryPoint;
        result.initialized      = true;
        result.sealed           = false;
        result.owning_pid       = GetCurrentProcessId();
        result.image_path_hash  = image_path_hash;
        result.loader_code_hash = loader_code_hash;
        result.binding_salt     = binding_salt;
        result.auto_seal_timer  = nullptr;
        return result;
    }

    void* get_export(const loaded_module_t& mod, const char* export_name)
    {
        g_last_error.clear();

        if (!mod.base || !mod.initialized || !export_name) {
            set_error("Invalid module or export name.");
            return nullptr;
        }

        auto* image_base = static_cast<uint8_t*>(mod.base);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
        auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + dos->e_lfanew);

        void* addr = find_export(image_base, nt, export_name);
        if (!addr) {
            set_error("Export not found.");
        }
        return addr;
    }

    bool seal(loaded_module_t& mod)
    {
        g_last_error.clear();

        if (!mod.base || !mod.initialized) {
            set_error("seal() called on uninitialized module.");
            return false;
        }

        if (mod.sealed)
            return true;

        if (mod.auto_seal_timer != nullptr) {
            DeleteTimerQueueTimer(NULL,
                                  reinterpret_cast<HANDLE>(mod.auto_seal_timer),
                                  NULL);
            mod.auto_seal_timer = nullptr;
        }

        const size_t header_size = mod.header_size;
        if (header_size == 0) {
            set_error("seal() module has zero header_size.");
            return false;
        }

        DWORD old_protect = 0;
        if (!VirtualProtect(mod.base, header_size, PAGE_READWRITE, &old_protect)) {
            set_error("VirtualProtect(PAGE_READWRITE) failed for header scrub.");
            return false;
        }

        auto* image_base = static_cast<uint8_t*>(mod.base);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image_base);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
            static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) <= header_size)
        {
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(image_base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                auto* sec = IMAGE_FIRST_SECTION(nt);
                const WORD num = nt->FileHeader.NumberOfSections;
                const uint8_t* hdr_end = image_base + header_size;
                if (reinterpret_cast<uint8_t*>(sec + num) <= hdr_end) {
                    for (WORD i = 0; i < num; ++i) {
                        uint8_t rnd[8] = {0};
                        BCryptGenRandom(nullptr, rnd, sizeof(rnd),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                        std::memcpy(sec[i].Name, rnd, 8);
                        sec[i].Characteristics = IMAGE_SCN_MEM_READ;
                    }
                }
            }
        }

        SecureZeroMemory(mod.base, header_size);

        DWORD discard = 0;
        if (!VirtualProtect(mod.base, header_size, PAGE_NOACCESS, &discard)) {
            set_error("VirtualProtect(PAGE_NOACCESS) failed after header scrub.");
            return false;
        }

        mod.sealed = true;
        return true;
    }

    bool verify_process_binding(const loaded_module_t& mod)
    {
        if (!mod.initialized || !mod.base)
            return false;

        if (GetCurrentProcessId() != mod.owning_pid)
            return false;

        uint64_t k0 = 0, k1 = 0;
        derive_siphash_key(mod.binding_salt, k0, k1);

        uint64_t actual_path = 0;
        if (!hash_image_path(k0, k1, actual_path))
            return false;
        if (actual_path != mod.image_path_hash)
            return false;

        uint64_t actual_loader = 0;
        if (!hash_loader_code(k0, k1, reinterpret_cast<const void*>(&load),
                              actual_loader))
            return false;
        if (actual_loader != mod.loader_code_hash)
            return false;

        return true;
    }

    void unload(loaded_module_t& mod)
    {
        g_last_error.clear();

        if (!mod.base)
            return;

        auto* image_base = static_cast<uint8_t*>(mod.base);

        if (mod.auto_seal_timer != nullptr) {
            DeleteTimerQueueTimer(NULL,
                                  reinterpret_cast<HANDLE>(mod.auto_seal_timer),
                                  NULL);
            mod.auto_seal_timer = nullptr;
        }

        if (mod.initialized && !mod.sealed && mod.entry_point != nullptr) {
            using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
            auto entry = reinterpret_cast<DllMain_t>(mod.entry_point);

            __try {
                entry(
                    reinterpret_cast<HINSTANCE>(image_base),
                    DLL_PROCESS_DETACH,
                    nullptr);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {

            }
        }


        __try {
            SecureZeroMemory(mod.base, mod.image_size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }
        VirtualFree(mod.base, 0, MEM_RELEASE);

        mod.base             = nullptr;
        mod.image_size       = 0;
        mod.header_size      = 0;
        mod.entry_point      = nullptr;
        mod.initialized      = false;
        mod.sealed           = false;
        mod.owning_pid       = 0;
        mod.image_path_hash  = 0;
        mod.loader_code_hash = 0;
        mod.binding_salt     = 0;
        mod.auto_seal_timer  = nullptr;
    }

    const std::string& last_error()
    {
        return g_last_error;
    }
}
