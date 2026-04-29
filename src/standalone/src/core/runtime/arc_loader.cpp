#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "arc_loader.hpp"

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <cstring>
#include <cctype>
#include <atomic>
#include <algorithm>
#include <cstdio>

#pragma comment(lib, "bcrypt.lib")

namespace
{
    std::string g_last_error;
    bool g_last_error_fatal = false;

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

    void set_error_text(const std::string& msg)
    {
        g_last_error = msg;
        g_last_error_fatal = false;
        OutputDebugStringA("ARC Loader: ");
        OutputDebugStringA(msg.c_str());
        OutputDebugStringA("\n");
    }

    void set_error_fatal(const std::string& msg)
    {
        g_last_error = msg;
        g_last_error_fatal = true;
        OutputDebugStringA("ARC Loader (FATAL): ");
        OutputDebugStringA(msg.c_str());
        OutputDebugStringA("\n");
    }

    void set_error(const char* msg)
    {
        set_error_text(msg ? std::string(msg) : std::string());
    }

    bool safe_read_bytes_seh(const uint8_t* src, uint8_t* dst, size_t n)
    {
        __try {
            for (size_t k = 0; k < n; ++k) dst[k] = src[k];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    void arc_breadcrumb(const char* tag)
    {
        if (!tag)
            return;

        static char s_path[MAX_PATH] = {};
        static bool s_path_init = false;
        if (!s_path_init) {
            DWORD ret = GetModuleFileNameA(nullptr, s_path, MAX_PATH);
            if (ret == 0 || ret >= MAX_PATH) {
                strcpy_s(s_path, "aida_debug.log");
            } else {
                char* last = strrchr(s_path, '\\');
                if (last)
                    *(last + 1) = '\0';
                else
                    s_path[0] = '\0';
                strcat_s(s_path, "aida_debug.log");
            }
            s_path_init = true;
        }

        HANDLE hf = CreateFileA(s_path, FILE_APPEND_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE)
            return;

        SYSTEMTIME st{};
        GetLocalTime(&st);
        char line[512];
        int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[%02d:%02d:%02d.%03d] [arc_loader] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, tag);
        if (len > 0) {
            DWORD written = 0;
            WriteFile(hf, line, static_cast<DWORD>(len), &written, nullptr);
        }
        CloseHandle(hf);
    }

    const char* runtime_import_name(const char* name)
    {
        if (!name)
            return "";
        if (_strnicmp(name, "api-ms-win-crt-", 15) == 0)
            return "ucrtbase.dll";
        if (_strnicmp(name, "api-ms-win-core-", 16) == 0)
            return "kernelbase.dll";
        return name;
    }

    bool names_equal_ci(const char* a, const char* b)
    {
        if (!a || !b)
            return false;
        return _stricmp(a, b) == 0;
    }

    struct primed_module_t
    {
        uint64_t  name_hash;
        uintptr_t xored_handle;
    };

    constexpr size_t kPrimedCacheCap = 64;

    primed_module_t* primed_cache_storage()
    {
        static primed_module_t s[kPrimedCacheCap]{};
        return s;
    }

    std::atomic<size_t>& primed_cache_count()
    {
        static std::atomic<size_t> n{0};
        return n;
    }

    uint64_t& primed_cache_xor_key()
    {
        static uint64_t k = 0;
        return k;
    }

    uint64_t& primed_cache_hash_k0()
    {
        static uint64_t k = 0;
        return k;
    }

    uint64_t& primed_cache_hash_k1()
    {
        static uint64_t k = 0;
        return k;
    }

    std::atomic<bool>& primed_cache_ready()
    {
        static std::atomic<bool> b{false};
        return b;
    }

    uint64_t primed_hash_name_ci(const char* s)
    {
        char buf[160];
        size_t i = 0;
        if (s) {
            for (; i + 1 < sizeof(buf) && s[i]; ++i)
                buf[i] = static_cast<char>(::tolower(static_cast<unsigned char>(s[i])));
        }
        buf[i] = 0;
        return siphash_2_4(reinterpret_cast<const uint8_t*>(buf), i,
                           primed_cache_hash_k0(), primed_cache_hash_k1());
    }

    void primed_cache_insert(const char* name)
    {
        if (!name || !*name)
            return;
        const size_t cur = primed_cache_count().load(std::memory_order_relaxed);
        if (cur >= kPrimedCacheCap)
            return;
        HMODULE h = LoadLibraryA(name);
        if (!h)
            h = GetModuleHandleA(name);
        if (!h)
            return;
        const uint64_t hash = primed_hash_name_ci(name);
        primed_module_t* arr = primed_cache_storage();
        for (size_t i = 0; i < cur; ++i) {
            if (arr[i].name_hash == hash)
                return;
        }
        arr[cur].name_hash    = hash;
        arr[cur].xored_handle = reinterpret_cast<uintptr_t>(h)
                              ^ static_cast<uintptr_t>(primed_cache_xor_key());
        primed_cache_count().store(cur + 1, std::memory_order_release);
    }

    HMODULE primed_cache_lookup(const char* name)
    {
        if (!primed_cache_ready().load(std::memory_order_acquire))
            return nullptr;
        if (!name || !*name)
            return nullptr;
        const uint64_t hash = primed_hash_name_ci(name);
        const size_t cur = primed_cache_count().load(std::memory_order_acquire);
        primed_module_t* arr = primed_cache_storage();
        for (size_t i = 0; i < cur; ++i) {
            if (arr[i].name_hash == hash) {
                return reinterpret_cast<HMODULE>(
                    arr[i].xored_handle
                    ^ static_cast<uintptr_t>(primed_cache_xor_key()));
            }
        }
        return nullptr;
    }

    void primed_cache_initialize()
    {
        if (primed_cache_ready().load(std::memory_order_acquire))
            return;

        uint64_t kx = 0;
        if (!generate_random_u64(kx))
            kx = 0xA1DA10ADCAFEBEEFull;
        uint64_t k0 = 0;
        if (!generate_random_u64(k0))
            k0 = 0xDEADBEEFCAFEBABEull;
        uint64_t k1 = 0;
        if (!generate_random_u64(k1))
            k1 = 0x1337C0DE5EEDF00Dull;

        primed_cache_xor_key()  = kx;
        primed_cache_hash_k0()  = k0;
        primed_cache_hash_k1()  = k1;

        static const char* kPrimes[] = {
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
            "ucrtbase.dll",
            "msvcp140.dll",
            "msvcp140_1.dll",
            "msvcp140_2.dll",
            "msvcp140_atomic_wait.dll",
            "msvcp140_codecvt_ids.dll",
            "vcruntime140.dll",
            "vcruntime140_1.dll",
        };

        for (const char* n : kPrimes)
            primed_cache_insert(n);

        primed_cache_ready().store(true, std::memory_order_release);
    }

    HMODULE load_import_module(const char* dll_name)
    {
        const char* runtime_name = runtime_import_name(dll_name);

        HMODULE hmod = primed_cache_lookup(runtime_name);
        if (!hmod && !names_equal_ci(runtime_name, dll_name))
            hmod = primed_cache_lookup(dll_name);

        if (!hmod)
            hmod = GetModuleHandleA(dll_name);
        if (!hmod && !names_equal_ci(runtime_name, dll_name))
            hmod = GetModuleHandleA(runtime_name);
        if (!hmod)
            hmod = LoadLibraryA(dll_name);
        if (!hmod && !names_equal_ci(runtime_name, dll_name))
            hmod = LoadLibraryA(runtime_name);

        if (!hmod) {
            const DWORD err = GetLastError();
            char buf[512];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                "Failed to load import DLL: %.180s resolved=%.180s err=%lu",
                dll_name ? dll_name : "<null>",
                runtime_name ? runtime_name : "<null>",
                static_cast<unsigned long>(err));
            set_error_text(buf);
        }
        return hmod;
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
                set_error_text(std::string("ARC imports from disallowed DLL: ") + dll_name);
                return false;
            }

            HMODULE hMod = load_import_module(dll_name);
            if (!hMod)
                return false;

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
                    if (IMAGE_SNAP_BY_ORDINAL64(thunk_ref->u1.Ordinal)) {
                        char buf[256];
                        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                            "Failed to resolve import ordinal: %.160s#%llu err=%lu",
                            dll_name,
                            static_cast<unsigned long long>(IMAGE_ORDINAL64(thunk_ref->u1.Ordinal)),
                            static_cast<unsigned long>(GetLastError()));
                        set_error_text(buf);
                    } else {
                        auto* import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            image_base + thunk_ref->u1.AddressOfData);
                        set_error_text(std::string("Failed to resolve import function: ") + dll_name + "!" + reinterpret_cast<const char*>(import_by_name->Name));
                    }
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
        auto overlaps_section = [&](uint64_t begin, uint64_t end) -> bool {
            for (WORD j = 0; j < nt->FileHeader.NumberOfSections; ++j) {
                size_t other_size = sec[j].Misc.VirtualSize;
                if (other_size == 0)
                    other_size = sec[j].SizeOfRawData;
                if (other_size == 0)
                    continue;
                uint64_t other_begin = sec[j].VirtualAddress;
                uint64_t other_end = other_begin + ((static_cast<uint64_t>(other_size) + (page_size - 1u)) & ~(static_cast<uint64_t>(page_size) - 1u));
                if (begin < other_end && end > other_begin)
                    return true;
            }
            return false;
        };
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            if (va < 2u * page_size)
                continue;

            size_t sec_size = sec[i].Misc.VirtualSize;
            if (sec_size == 0)
                sec_size = sec[i].SizeOfRawData;
            if (sec_size == 0)
                continue;

            uint64_t leading_off = static_cast<uint64_t>(va) - page_size;
            if (leading_off + page_size <= image_size && !overlaps_section(leading_off, leading_off + page_size)) {
                uint8_t* leading = image_base + leading_off;
                if (VirtualFree(leading, page_size, MEM_DECOMMIT)) {
                    VirtualAlloc(leading, page_size, MEM_COMMIT, PAGE_NOACCESS);
                }
            }

            const size_t aligned_size = (sec_size + (page_size - 1u)) & ~(page_size - 1u);
            uint64_t trailing_off = static_cast<uint64_t>(va) + aligned_size;
            if (trailing_off + page_size > image_size)
                continue;

            if (!overlaps_section(trailing_off, trailing_off + page_size)) {
                uint8_t* trailing = image_base + trailing_off;
                if (VirtualFree(trailing, page_size, MEM_DECOMMIT)) {
                    VirtualAlloc(trailing, page_size, MEM_COMMIT, PAGE_NOACCESS);
                }
            }
        }
    }

    bool register_function_table(uint8_t* image_base, const IMAGE_NT_HEADERS* nt,
                                  PRUNTIME_FUNCTION& out_table, uint32_t& out_count)
    {
        out_table = nullptr;
        out_count = 0;
        const auto& exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exception_dir.VirtualAddress == 0 || exception_dir.Size < sizeof(RUNTIME_FUNCTION))
            return false;
        if (exception_dir.VirtualAddress + exception_dir.Size > nt->OptionalHeader.SizeOfImage)
            return false;

        auto* table = reinterpret_cast<PRUNTIME_FUNCTION>(image_base + exception_dir.VirtualAddress);
        const uint32_t count = exception_dir.Size / static_cast<uint32_t>(sizeof(RUNTIME_FUNCTION));
        if (count == 0)
            return false;

        if (!RtlAddFunctionTable(table, count, reinterpret_cast<DWORD64>(image_base)))
            return false;

        out_table = table;
        out_count = count;
        return true;
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
        g_last_error_fatal = false;

        arc_breadcrumb("load_enter");

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

        arc_breadcrumb("load_validate_ok");

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

        arc_breadcrumb("load_alloc_ok");

        if (!map_sections(image_base, pe_buffer, pe_size, nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        arc_breadcrumb("load_map_ok");

        auto* mapped_nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
            image_base + dos->e_lfanew);


        if (!process_relocations(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        arc_breadcrumb("load_reloc_ok");

        if (!resolve_imports(image_base, mapped_nt)) {
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        arc_breadcrumb("load_imports_ok");

        finalize_sections(image_base, mapped_nt);

        arc_breadcrumb("load_finalize_ok");

        PRUNTIME_FUNCTION ft_table = nullptr;
        uint32_t ft_count = 0;
        if (register_function_table(image_base, mapped_nt, ft_table, ft_count)) {
            char ftbuf[96];
            _snprintf_s(ftbuf, sizeof(ftbuf), _TRUNCATE,
                "load_function_table_ok entries=%u", ft_count);
            arc_breadcrumb(ftbuf);
        } else {
            arc_breadcrumb("load_function_table_skipped");
        }

        install_guard_pages(image_base, mapped_nt);

        arc_breadcrumb("load_guard_pages_ok");

        if (!process_tls(image_base, mapped_nt)) {
            if (ft_table) RtlDeleteFunctionTable(ft_table);
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        arc_breadcrumb("load_tls_ok");

        SecureZeroMemory(pe_buffer, pe_size);

        arc_breadcrumb("load_zeroed_source_pe");

        using DllMain_t = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto entry_point = reinterpret_cast<DllMain_t>(
            image_base + mapped_nt->OptionalHeader.AddressOfEntryPoint);

        {
            const uint8_t* ep_bytes = reinterpret_cast<const uint8_t*>(entry_point);
            uint8_t b[16] = {};
            const bool ep_readable = safe_read_bytes_seh(ep_bytes, b, 16);
            char ep_dbg[256];
            if (!ep_readable) {
                _snprintf_s(ep_dbg, sizeof(ep_dbg), _TRUNCATE,
                    "load_dllmain_entry_unreadable ep=%p rva=0x%X",
                    static_cast<void*>(entry_point),
                    static_cast<unsigned>(mapped_nt->OptionalHeader.AddressOfEntryPoint));
                arc_breadcrumb(ep_dbg);
                set_error("ARC entry_point address is not readable.");
                if (ft_table) RtlDeleteFunctionTable(ft_table);
                VirtualFree(image_base, 0, MEM_RELEASE);
                return result;
            }
            _snprintf_s(ep_dbg, sizeof(ep_dbg), _TRUNCATE,
                "load_dllmain_entry ep=%p rva=0x%X first16=%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                static_cast<void*>(entry_point),
                static_cast<unsigned>(mapped_nt->OptionalHeader.AddressOfEntryPoint),
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
            arc_breadcrumb(ep_dbg);
        }

        arc_breadcrumb("load_dllmain_pre");

        struct watchdog_ctx_t { volatile LONG done; ULONGLONG start_tick; };
        watchdog_ctx_t wd_ctx{ 0, GetTickCount64() };
        DWORD wd_tid = 0;
        HANDLE wd_thread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            auto* c = reinterpret_cast<watchdog_ctx_t*>(p);
            int sec = 0;
            while (InterlockedCompareExchange(&c->done, 0, 0) == 0) {
                Sleep(1000);
                ++sec;
                ULONGLONG elapsed_ms = GetTickCount64() - c->start_tick;
                char tag[96];
                _snprintf_s(tag, sizeof(tag), _TRUNCATE, "load_dllmain_watchdog_tick_%ds_elapsed=%llums", sec, (unsigned long long)elapsed_ms);
                arc_breadcrumb(tag);
                if (sec >= 60) break;
            }
            return 0;
        }, &wd_ctx, 0, &wd_tid);
        if (wd_thread == nullptr) {
            char wd_err[96];
            _snprintf_s(wd_err, sizeof(wd_err), _TRUNCATE, "load_dllmain_watchdog_create_FAILED_err=%lu", (unsigned long)GetLastError());
            arc_breadcrumb(wd_err);
        } else {
            arc_breadcrumb("load_dllmain_watchdog_spawned");
        }

        constexpr size_t kPebImageBaseOffset = 0x10;
        auto* peb_bytes = reinterpret_cast<uint8_t*>(NtCurrentTeb()->ProcessEnvironmentBlock);
        auto** peb_image_base_slot = reinterpret_cast<void**>(peb_bytes + kPebImageBaseOffset);
        void* saved_peb_image_base = *peb_image_base_slot;

        {
            char pbuf[160];
            _snprintf_s(pbuf, sizeof(pbuf), _TRUNCATE,
                "load_dllmain_peb_image_base host=%p arc_target=%p",
                saved_peb_image_base,
                static_cast<void*>(image_base));
            arc_breadcrumb(pbuf);
        }

        *peb_image_base_slot = static_cast<void*>(image_base);
        arc_breadcrumb("load_dllmain_peb_swap_in");

        struct dllmain_invoker_ctx_t {
            DllMain_t entry;
            uint8_t* base;
            volatile LONG completed;
            volatile LONG seh_caught;
            volatile DWORD seh_code;
            BOOL result;
        };
        auto* inv_ctx = new dllmain_invoker_ctx_t{
            entry_point, image_base, 0, 0, 0, FALSE };

        auto inv_thread_proc = [](LPVOID p) -> DWORD {
            auto* c = reinterpret_cast<dllmain_invoker_ctx_t*>(p);
            BOOL ok = FALSE;
            __try {
                ok = c->entry(
                    reinterpret_cast<HINSTANCE>(c->base),
                    DLL_PROCESS_ATTACH,
                    nullptr);
            }
            __except (c->seh_code = GetExceptionCode(),
                      InterlockedExchange(&c->seh_caught, 1),
                      EXCEPTION_EXECUTE_HANDLER) {
                ok = FALSE;
            }
            c->result = ok;
            InterlockedExchange(&c->completed, 1);
            return 0;
        };

        DWORD inv_tid = 0;
        HANDLE inv_thread = CreateThread(nullptr, 0, inv_thread_proc, inv_ctx, 0, &inv_tid);

        const ULONGLONG kDllMainBudgetMs = 20000ull;
        bool timed_out = false;
        bool inline_path = false;

        if (inv_thread == nullptr) {
            char tbuf[160];
            _snprintf_s(tbuf, sizeof(tbuf), _TRUNCATE,
                "load_dllmain_thread_create_FAILED_err=%lu_falling_back_inline_tid=%lu",
                (unsigned long)GetLastError(),
                (unsigned long)GetCurrentThreadId());
            arc_breadcrumb(tbuf);
            inline_path = true;
            arc_breadcrumb("load_dllmain_inline_pre");
            inv_thread_proc(inv_ctx);
            arc_breadcrumb("load_dllmain_inline_post");
        } else {
            char tbuf[96];
            _snprintf_s(tbuf, sizeof(tbuf), _TRUNCATE,
                "load_dllmain_thread_spawned tid=%lu", (unsigned long)inv_tid);
            arc_breadcrumb(tbuf);
            DWORD wait = WaitForSingleObject(inv_thread, static_cast<DWORD>(kDllMainBudgetMs));
            if (wait != WAIT_OBJECT_0 ||
                InterlockedCompareExchange(&inv_ctx->completed, 0, 0) == 0) {
                timed_out = true;
            } else {
                CloseHandle(inv_thread);
            }
        }

        *peb_image_base_slot = saved_peb_image_base;
        arc_breadcrumb("load_dllmain_peb_swap_out");

        InterlockedExchange(&wd_ctx.done, 1);
        if (wd_thread) {
            WaitForSingleObject(wd_thread, 2000);
            CloseHandle(wd_thread);
        }

        ULONGLONG dllmain_elapsed = GetTickCount64() - wd_ctx.start_tick;

        if (timed_out) {
            char tobuf[160];
            _snprintf_s(tobuf, sizeof(tobuf), _TRUNCATE,
                "load_dllmain_timeout_after_ms=%llu budget_ms=%llu",
                (unsigned long long)dllmain_elapsed,
                (unsigned long long)kDllMainBudgetMs);
            arc_breadcrumb(tobuf);
            set_error_fatal("ARC DllMain did not return within the activation budget.");
            return result;
        }

        const BOOL dll_result = inv_ctx->result;
        const bool seh = InterlockedCompareExchange(&inv_ctx->seh_caught, 0, 0) != 0;
        const DWORD seh_code = inv_ctx->seh_code;
        delete inv_ctx;
        inv_ctx = nullptr;
        (void)inline_path;

        if (seh) {
            char sehbuf[160];
            _snprintf_s(sehbuf, sizeof(sehbuf), _TRUNCATE,
                "load_dllmain_seh_caught code=0x%08X elapsed_ms=%llu",
                static_cast<unsigned>(seh_code),
                static_cast<unsigned long long>(dllmain_elapsed));
            arc_breadcrumb(sehbuf);
            char errbuf[160];
            _snprintf_s(errbuf, sizeof(errbuf), _TRUNCATE,
                "DllMain raised SEH exception 0x%08X during DLL_PROCESS_ATTACH.",
                static_cast<unsigned>(seh_code));
            set_error(errbuf);
            if (ft_table) RtlDeleteFunctionTable(ft_table);
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        char post_tag[96];
        _snprintf_s(post_tag, sizeof(post_tag), _TRUNCATE, "load_dllmain_post_%s_elapsed=%llums",
            dll_result ? "ok" : "false", (unsigned long long)dllmain_elapsed);
        arc_breadcrumb(post_tag);

        if (!dll_result) {
            set_error("DllMain returned FALSE.");
            if (ft_table) RtlDeleteFunctionTable(ft_table);
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        uint64_t binding_salt = 0;
        if (!generate_random_u64(binding_salt)) {
            set_error("BCryptGenRandom failed for binding salt.");
            if (ft_table) RtlDeleteFunctionTable(ft_table);
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        uint64_t k0 = 0, k1 = 0;
        derive_siphash_key(binding_salt, k0, k1);

        uint64_t image_path_hash = 0;
        if (!hash_image_path(k0, k1, image_path_hash)) {
            set_error("QueryFullProcessImageNameW failed for binding hash.");
            if (ft_table) RtlDeleteFunctionTable(ft_table);
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        uint64_t loader_code_hash = 0;
        if (!hash_loader_code(k0, k1, reinterpret_cast<const void*>(&load),
                              loader_code_hash)) {
            set_error("Loader code hash sampling faulted.");
            if (ft_table) RtlDeleteFunctionTable(ft_table);
            VirtualFree(image_base, 0, MEM_RELEASE);
            return result;
        }

        arc_breadcrumb("load_binding_hashes_ok");

        result.base                 = image_base;
        result.image_size           = image_size;
        result.header_size          = header_size_capture;
        result.entry_point          = image_base + mapped_nt->OptionalHeader.AddressOfEntryPoint;
        result.initialized          = true;
        result.sealed               = false;
        result.owning_pid           = GetCurrentProcessId();
        result.image_path_hash      = image_path_hash;
        result.loader_code_hash     = loader_code_hash;
        result.binding_salt         = binding_salt;
        result.auto_seal_timer      = nullptr;
        result.function_table       = ft_table;
        result.function_table_count = ft_count;

        arc_breadcrumb("load_exit_ok");
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


        if (mod.function_table != nullptr) {
            RtlDeleteFunctionTable(static_cast<PRUNTIME_FUNCTION>(mod.function_table));
            mod.function_table = nullptr;
            mod.function_table_count = 0;
        }

        __try {
            SecureZeroMemory(mod.base, mod.image_size);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }
        VirtualFree(mod.base, 0, MEM_RELEASE);

        mod.base                 = nullptr;
        mod.image_size           = 0;
        mod.header_size          = 0;
        mod.entry_point          = nullptr;
        mod.initialized          = false;
        mod.sealed               = false;
        mod.owning_pid           = 0;
        mod.image_path_hash      = 0;
        mod.loader_code_hash     = 0;
        mod.binding_salt         = 0;
        mod.auto_seal_timer      = nullptr;
        mod.function_table       = nullptr;
        mod.function_table_count = 0;
    }

    const std::string& last_error()
    {
        return g_last_error;
    }

    bool last_error_is_fatal()
    {
        return g_last_error_fatal;
    }

    void prime_import_cache()
    {
        primed_cache_initialize();
    }
}
