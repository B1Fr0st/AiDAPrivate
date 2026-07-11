#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <winternl.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "webhook.hpp"
#include "state.hpp"
#include "syscall.hpp"
#include "../runtime/standalone_driver.hpp"
#include "standalone_driver.hpp"
#include "enforcement.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

namespace anti_tamper {
namespace anti_hook {

struct hook_report_t
{
    bool iat_modified = false;
    bool ntdll_inline_hooked = false;
    bool kernel32_inline_hooked = false;
    bool syscall_stubs_modified = false;
    bool eat_hooked = false;
    bool prologue_hash_mismatch = false;
    bool disk_image_mismatch = false;
    bool veh_chain_tampered = false;
    bool dr_in_text_range = false;
    bool dispatch_table_redirected = false;
    bool vtable_hooked = false;
    bool self_prologue_mismatch = false;
    bool server_hash_mismatch = false;
    bool self_hook_detected = false;
    bool kernel_callback_hooked = false;
    bool kernel_dispatch_hooked = false;
    std::string hooked_function;
    std::string vtable_mismatched_class;
    std::string summary;

    bool any_detected() const
    {
        return iat_modified || ntdll_inline_hooked || kernel32_inline_hooked
            || syscall_stubs_modified || eat_hooked
            || prologue_hash_mismatch || disk_image_mismatch
            || veh_chain_tampered || dr_in_text_range
            || dispatch_table_redirected
            || vtable_hooked || self_prologue_mismatch
            || server_hash_mismatch || self_hook_detected
            || kernel_callback_hooked || kernel_dispatch_hooked;
    }
};

namespace detail {

    inline BCRYPT_ALG_HANDLE get_sha256_alg()
    {
        thread_local BCRYPT_ALG_HANDLE h = nullptr;
        if (!h)
        {
            if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
            {
                h = nullptr;
            }
        }
        return h;
    }

    inline bool sha256_hash(const void* data, size_t size, uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE hAlg = get_sha256_alg();
        if (!hAlg) return false;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;

        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0)
        {
            return false;
        }

        if (BCryptHashData(hHash,
            const_cast<PUCHAR>(static_cast<const uint8_t*>(data)),
            static_cast<ULONG>(size), 0) == 0)
        {
            ok = (BCryptFinishHash(hHash, out, 32, 0) == 0);
        }

        BCryptDestroyHash(hHash);
        return ok;
    }

    inline bool check_inline_hook_bytes(const uint8_t* func, const char*)
    {
        __try
        {
            if (func[0] == 0xE9)
                return true;

            if (func[0] == 0xFF && func[1] == 0x25)
                return true;

            if (func[0] == 0x48 && func[1] == 0xB8 && func[10] == 0xFF && func[11] == 0xE0)
                return true;

            if (func[0] == 0x68 && func[5] == 0xC3)
                return true;

            if (func[0] == 0xEB)
                return true;

            if (func[0] == 0xCC)
                return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    inline bool check_inline_hook_deep(const uint8_t* func, const char*,
        size_t func_size = k_prologue_bytes,
        bool func_size_verified = false)
    {
        __try
        {
            const size_t scan_limit = (func_size < k_prologue_bytes)
                ? func_size : k_prologue_bytes;
            for (size_t off = 0; off < scan_limit; ++off)
            {
                if (off + 5 <= scan_limit && func[off] == 0xE9)
                    return true;

                if (off + 5 <= scan_limit && func[off] == 0xE8)
                    return true;

                if (off + 2 <= scan_limit && func[off] == 0xEB)
                    return true;

                if (off + 6 <= scan_limit && func[off] == 0xFF && func[off+1] == 0x25)
                    return true;

                if (off + 6 <= scan_limit && func[off] == 0xFF && func[off+1] == 0x15)
                    return true;

                if (off + 12 <= scan_limit &&
                    func[off] == 0x48 && func[off+1] == 0xB8 &&
                    func[off+10] == 0xFF && func[off+11] == 0xE0)
                    return true;

                if (off + 6 <= scan_limit && func[off] == 0x68 && func[off+5] == 0xC3)
                    return true;

                if (func[off] == 0xCC && (off == 0 || func_size_verified))
                    return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    inline bool lookup_runtime_function_size(HMODULE mod, uint64_t func_va,
        size_t& out_size)
    {
        out_size = 0;
        if (!mod || func_va == 0) return false;

        auto* base = reinterpret_cast<const uint8_t*>(mod);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            return false;

        const auto& exc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exc_dir.VirtualAddress == 0 || exc_dir.Size == 0) return false;

        const uint32_t func_count = exc_dir.Size / 12;
        if (func_count == 0) return false;

        const uint64_t mod_base = reinterpret_cast<uint64_t>(base);
        const uint32_t func_rva = static_cast<uint32_t>(func_va - mod_base);

        const RUNTIME_FUNCTION* rf_base = reinterpret_cast<const RUNTIME_FUNCTION*>(
            base + exc_dir.VirtualAddress);

        for (uint32_t i = 0; i < func_count; ++i)
        {
            if (rf_base[i].BeginAddress == func_rva)
            {
                out_size = rf_base[i].EndAddress - rf_base[i].BeginAddress;
                return out_size > 0;
            }
        }
        return false;
    }

    inline bool check_inline_hook_deep_at_export(HMODULE mod, const char* name)
    {
        if (!mod || !name) return false;
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(mod, name));
        if (!addr) return false;

        size_t func_size = k_prologue_bytes;
        bool verified = false;
        lookup_runtime_function_size(mod, reinterpret_cast<uint64_t>(addr), func_size);
        if (func_size > 0) verified = true;

        return check_inline_hook_deep(addr, name, func_size, verified);
    }

    inline bool verify_syscall_stub(const uint8_t* func)
    {
        __try
        {
            if (func[0] != 0x4C || func[1] != 0x8B || func[2] != 0xD1)
                return false;

            if (func[3] != 0xB8)
                return false;

            if (func[8] == 0xF6 && func[12] == 0x75)
                return true;

            if (func[8] == 0x0F && func[9] == 0x05)
                return true;

            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    inline void bytes16_hex(const uint8_t* addr, char out[33])
    {
        static constexpr char kHex[] = "0123456789ABCDEF";
        for (size_t i = 0; i < 16; ++i) {
            uint8_t b = 0;
            __try {
                b = addr ? addr[i] : 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                b = 0;
            }
            out[i * 2] = kHex[(b >> 4) & 0xF];
            out[i * 2 + 1] = kHex[b & 0xF];
        }
        out[32] = '\0';
    }

    struct module_range_t
    {
        uint64_t base;
        uint64_t end;
    };

    inline bool get_module_range(HMODULE mod, module_range_t& range)
    {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi)))
            return false;
        range.base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        range.end = range.base + mi.SizeOfImage;
        return true;
    }

    __declspec(noinline) inline bool safe_read_uint64(uint64_t addr, uint64_t* out)
    {
        __try {
            *out = *reinterpret_cast<const volatile uint64_t*>(addr);
            return true;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            *out = 0;
            return false;
        }
    }

    inline const char* const k_critical_ntdll_funcs[] = {
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

    inline const char* const k_critical_kernel32_funcs[] = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "VirtualProtect",
        "VirtualQuery",
        "GetModuleHandleW",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualFree",
    };

    constexpr size_t k_prologue_bytes = 32;

    struct prologue_baseline_t
    {
        std::string name;
        uint8_t hash[32];
        uint64_t cached_va;
    };

    inline std::vector<prologue_baseline_t>& ntdll_baselines()
    {
        static std::vector<prologue_baseline_t> v;
        return v;
    }

    inline std::vector<prologue_baseline_t>& kernel32_baselines()
    {
        static std::vector<prologue_baseline_t> v;
        return v;
    }

    inline std::atomic<bool>& baselines_captured()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::mutex& baseline_mtx()
    {
        static std::mutex m;
        return m;
    }

    struct disk_image_t
    {
        std::vector<uint8_t> bytes;
        std::vector<std::pair<std::string, uint32_t>> exports;
        bool valid = false;
    };

    inline disk_image_t& ntdll_disk_image()
    {
        static disk_image_t v;
        return v;
    }

    inline std::atomic<bool>& disk_image_loaded()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline bool load_disk_image_ntdll()
    {
        auto& img = ntdll_disk_image();
        if (img.valid) return true;

        wchar_t sys_path[MAX_PATH];
        GetSystemDirectoryW(sys_path, MAX_PATH);
        wcscat_s(sys_path, L"\\ntdll.dll");

        HANDLE hFile = CreateFileW(sys_path, GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(hFile, &size) || size.QuadPart <= 0
            || size.QuadPart > 0x4000000)
        {
            CloseHandle(hFile);
            return false;
        }

        img.bytes.resize(static_cast<size_t>(size.QuadPart));
        DWORD read_total = 0;
        DWORD this_read = 0;
        bool ok = true;
        while (read_total < img.bytes.size())
        {
            DWORD want = static_cast<DWORD>(img.bytes.size() - read_total);
            if (!ReadFile(hFile, img.bytes.data() + read_total, want, &this_read, nullptr)
                || this_read == 0)
            {
                ok = false;
                break;
            }
            read_total += this_read;
        }
        CloseHandle(hFile);
        if (!ok) return false;

        const uint8_t* mapped = img.bytes.data();
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            mapped + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const auto& exp_dir = nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir.VirtualAddress == 0) return false;

        auto rva_to_off = [&](uint32_t rva) -> uint32_t {
            const auto* sec = IMAGE_FIRST_SECTION(nt);
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

        uint32_t exp_off = rva_to_off(exp_dir.VirtualAddress);
        if (exp_off == 0) return false;

        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
            mapped + exp_off);
        uint32_t names_off = rva_to_off(exports->AddressOfNames);
        uint32_t funcs_off = rva_to_off(exports->AddressOfFunctions);
        uint32_t ords_off  = rva_to_off(exports->AddressOfNameOrdinals);
        if (!names_off || !funcs_off || !ords_off) return false;

        const uint32_t* names = reinterpret_cast<const uint32_t*>(mapped + names_off);
        const uint32_t* funcs = reinterpret_cast<const uint32_t*>(mapped + funcs_off);
        const uint16_t* ords  = reinterpret_cast<const uint16_t*>(mapped + ords_off);

        img.exports.reserve(exports->NumberOfNames);
        for (uint32_t i = 0; i < exports->NumberOfNames; ++i)
        {
            uint32_t name_off = rva_to_off(names[i]);
            if (!name_off) continue;
            const char* exp_name = reinterpret_cast<const char*>(mapped + name_off);
            uint16_t ord = ords[i];
            if (ord >= exports->NumberOfFunctions) continue;
            uint32_t func_rva = funcs[ord];
            uint32_t file_off = rva_to_off(func_rva);
            if (!file_off) continue;
            img.exports.emplace_back(std::string(exp_name), file_off);
        }

        img.valid = !img.exports.empty();
        return img.valid;
    }

    inline const uint8_t* disk_export_bytes(const char* name)
    {
        auto& img = ntdll_disk_image();
        if (!img.valid) return nullptr;
        for (const auto& kv : img.exports)
        {
            if (kv.first == name)
                return img.bytes.data() + kv.second;
        }
        return nullptr;
    }

    inline bool system_owned_nt_export_wrapper(const char* name,
                                               const uint8_t* addr,
                                               const char* log_tag = "prologue_hash",
                                               const char* nonfatal_marker = "prologue_mismatch_system_wrapper_nonfatal",
                                               const char* reject_marker = "prologue_mismatch_system_wrapper_reject")
    {
        if (!name || !addr || !anti_tamper::syscall::detail::nt_export_name(name))
            return false;

        if (!ntdll_disk_image().valid)
            load_disk_image_ntdll();

        const uint8_t* disk_bytes = disk_export_bytes(name);
        if (!disk_bytes || !anti_tamper::syscall::detail::standard_x64_syscall_stub_bytes(disk_bytes))
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T vq = VirtualQuery(addr, &mbi, sizeof(mbi));
        bool mem_writable = vq != 0 && anti_tamper::syscall::detail::writable_protection(mbi.Protect);
        bool mem_redirect = anti_tamper::syscall::detail::inline_redirect_bytes(addr);
        bool mem_syscall = anti_tamper::syscall::detail::standard_x64_syscall_stub_bytes(addr);
        bool disk_redirect = anti_tamper::syscall::detail::inline_redirect_bytes(disk_bytes);
        bool disk_syscall = anti_tamper::syscall::detail::standard_x64_syscall_stub_bytes(disk_bytes);

        HMODULE owner_mod = nullptr;
        BOOL owner_ok = GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(addr),
            &owner_mod);

        wchar_t owner_path_w[MAX_PATH]{};
        DWORD owner_path_len = owner_ok && owner_mod
            ? GetModuleFileNameW(owner_mod, owner_path_w, MAX_PATH)
            : 0;

        bool owner_system = owner_path_len != 0 &&
            anti_tamper::syscall::detail::system_image_module_path(owner_path_w);

        char owner_path[512]{};
        anti_tamper::syscall::detail::narrow_path(owner_path_w, owner_path, sizeof(owner_path));
        const uint64_t mem_va = reinterpret_cast<uint64_t>(addr);
        const uint8_t* ntdll_base_ptr = reinterpret_cast<const uint8_t*>(GetModuleHandleW(L"ntdll.dll"));
        const uint32_t ntdll_size = anti_tamper::syscall::detail::image_size_from_base(ntdll_base_ptr);
        const uint64_t ntdll_base = reinterpret_cast<uint64_t>(ntdll_base_ptr);
        const bool in_ntdll_range = ntdll_size != 0 &&
            mem_va >= ntdll_base &&
            mem_va < ntdll_base + ntdll_size;
        const uint64_t mem_rva = in_ntdll_range ? mem_va - ntdll_base : 0;
        const uint8_t* owner_base_ptr = reinterpret_cast<const uint8_t*>(owner_mod);
        const uint32_t owner_size = owner_ok && owner_mod
            ? anti_tamper::syscall::detail::image_size_from_base(owner_base_ptr)
            : 0;
        const uint64_t owner_base = reinterpret_cast<uint64_t>(owner_base_ptr);
        const bool in_owner_range = owner_size != 0 &&
            mem_va >= owner_base &&
            mem_va < owner_base + owner_size;
        const uint64_t owner_rva = in_owner_range ? mem_va - owner_base : 0;

        const bool ok =
            vq != 0 &&
            mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_IMAGE &&
            !mem_writable &&
            !mem_redirect &&
            owner_ok &&
            owner_system;

        anti_tamper::syscall::detail::log_nt_export_wrapper_diag(log_tag,
            ok ? nonfatal_marker : reject_marker,
            name,
            addr,
            disk_bytes,
            mem_va,
            mem_rva,
            0,
            vq,
            mbi,
            mem_writable,
            mem_redirect,
            disk_redirect,
            mem_syscall,
            disk_syscall,
            true,
            owner_ok,
            owner_base,
            owner_size,
            owner_rva,
            owner_system,
            owner_path_w,
            owner_path,
            ok);

        return ok;
    }

    struct self_hook_allowlist_entry_t
    {
        uint64_t hooked_va;
        uint64_t hook_dest_va;
        const char* subsystem;
    };

    inline std::vector<self_hook_allowlist_entry_t>& self_hook_allowlist()
    {
        static std::vector<self_hook_allowlist_entry_t> v;
        return v;
    }

    struct vtable_baseline_t
    {
        const char* class_name;
        uint64_t vtable_va;
        uint32_t entry_count;
        bool dynamic_vtable;
        std::vector<uint8_t> hash_snapshot;
    };

    inline std::vector<vtable_baseline_t>& vtable_baselines()
    {
        static std::vector<vtable_baseline_t> v;
        return v;
    }

    struct original_bytes_entry_t
    {
        uint64_t function_va;
        uint32_t byte_count;
        uint8_t encrypted_bytes[32];
        uint64_t encryption_key;
        char function_name[64];
    };

    inline std::vector<original_bytes_entry_t>& original_bytes_store()
    {
        static std::vector<original_bytes_entry_t> v;
        return v;
    }

    struct server_prologue_hash_t
    {
        std::string function_name;
        uint8_t expected_hash[32];
        std::string module_name;
    };

    inline std::vector<server_prologue_hash_t>& server_hash_table()
    {
        static std::vector<server_prologue_hash_t> v;
        return v;
    }

    inline std::atomic<uint32_t>& server_hash_version_tag()
    {
        static std::atomic<uint32_t> v{0};
        return v;
    }

    inline std::atomic<bool>& server_hash_version_ok()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<bool>& server_hash_hmac_valid()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::mutex& self_hook_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::mutex& vtable_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::mutex& original_bytes_mtx()
    {
        static std::mutex m;
        return m;
    }

}

namespace baseline {

    __declspec(noinline) inline bool seh_hash_prologue(const uint8_t* addr, uint8_t out_hash[32])
    {
        __try
        {
            return detail::sha256_hash(addr, detail::k_prologue_bytes, out_hash);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    inline bool capture_module_prologues(HMODULE mod,
        std::vector<detail::prologue_baseline_t>& out,
        const char* const* names, size_t name_count)
    {
        out.clear();
        if (!mod) return false;

        for (size_t i = 0; i < name_count; ++i)
        {
            const char* name = names[i];
            auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(mod, name));
            if (!addr) continue;

            detail::prologue_baseline_t b{};
            b.name = name;
            b.cached_va = reinterpret_cast<uint64_t>(addr);

            if (!seh_hash_prologue(addr, b.hash))
                continue;

            out.push_back(std::move(b));
        }

        return !out.empty();
    }

    inline bool capture_all()
    {
        std::lock_guard<std::mutex> lk(detail::baseline_mtx());
        if (detail::baselines_captured().load()) return true;

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        HMODULE k32   = GetModuleHandleW(L"kernel32.dll");

        bool ok_n = capture_module_prologues(ntdll, detail::ntdll_baselines(),
            detail::k_critical_ntdll_funcs,
            sizeof(detail::k_critical_ntdll_funcs) / sizeof(char*));

        bool ok_k = capture_module_prologues(k32, detail::kernel32_baselines(),
            detail::k_critical_kernel32_funcs,
            sizeof(detail::k_critical_kernel32_funcs) / sizeof(char*));

        if (detail::load_disk_image_ntdll())
            detail::disk_image_loaded().store(true);

        bool any = ok_n || ok_k;
        if (any)
            detail::baselines_captured().store(true);
        return any;
    }

}

namespace veh_chain {

    struct _VECTORED_HANDLER_LIST
    {
        LIST_ENTRY ListHead;
        SRWLOCK    Lock;
    };

    struct _VECTORED_HANDLER_ENTRY
    {
        LIST_ENTRY  Entry;
        ULONG       Refs;
        ULONG       Padding;
        PVOID       VectoredHandler;
    };

    inline std::atomic<uint32_t>& baseline_count()
    {
        static std::atomic<uint32_t> v{0};
        return v;
    }

    inline std::vector<uint64_t>& baseline_handlers()
    {
        static std::vector<uint64_t> v;
        return v;
    }

    inline std::mutex& chain_mtx()
    {
        static std::mutex m;
        return m;
    }

    inline std::atomic<bool>& baseline_set()
    {
        static std::atomic<bool> v{false};
        return v;
    }

    inline std::atomic<uint64_t>& list_head_addr()
    {
        static std::atomic<uint64_t> v{0};
        return v;
    }

    inline bool pointer_readable(const void* p, size_t bytes)
    {
        if (!p || bytes == 0) return false;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi)))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
            return false;
        uintptr_t start = reinterpret_cast<uintptr_t>(p);
        uintptr_t end = start + bytes;
        uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        return end >= start && end <= region_end;
    }

    inline uint64_t locate_veh_list_head()
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return 0;

        auto* probe1 = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "RtlAddVectoredExceptionHandler"));
        auto* probe2 = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, "RtlRemoveVectoredExceptionHandler"));
        if (!probe1 || !probe2) return 0;

        const uint8_t* scan_targets[] = { probe1, probe2 };
        for (const uint8_t* base : scan_targets)
        {
            __try
            {
                for (size_t off = 0; off < 0x200; ++off)
                {
                    if (base[off] == 0x48 && base[off + 1] == 0x8D
                        && (base[off + 2] == 0x0D || base[off + 2] == 0x15
                            || base[off + 2] == 0x05 || base[off + 2] == 0x1D))
                    {
                        int32_t disp = *reinterpret_cast<const int32_t*>(base + off + 3);
                        uint64_t target = reinterpret_cast<uint64_t>(base + off + 7) + disp;
                        MEMORY_BASIC_INFORMATION mbi{};
                        if (VirtualQuery(reinterpret_cast<LPCVOID>(target), &mbi, sizeof(mbi))
                            && (mbi.Protect == PAGE_READWRITE
                                || mbi.Protect == PAGE_READONLY))
                        {
                            return target;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                continue;
            }
        }
        return 0;
    }

    inline bool walk_chain(std::vector<uint64_t>& handlers, uint32_t& count)
    {
        handlers.clear();
        count = 0;

        uint64_t head_addr = list_head_addr().load();
        if (head_addr == 0)
        {
            head_addr = locate_veh_list_head();
            if (head_addr == 0) return false;
            list_head_addr().store(head_addr);
        }

        auto* head = reinterpret_cast<_VECTORED_HANDLER_LIST*>(head_addr);
        if (!pointer_readable(head, sizeof(_VECTORED_HANDLER_LIST)))
            return false;

        __try
        {
            LIST_ENTRY* cursor = head->ListHead.Flink;
            uint32_t guard = 0;
            while (cursor != &head->ListHead && guard < 256)
            {
                if (!pointer_readable(cursor, sizeof(LIST_ENTRY)))
                    return false;
                auto* entry = CONTAINING_RECORD(cursor, _VECTORED_HANDLER_ENTRY, Entry);
                if (!pointer_readable(entry, sizeof(_VECTORED_HANDLER_ENTRY)))
                    return false;
                handlers.push_back(reinterpret_cast<uint64_t>(entry->VectoredHandler));
                cursor = cursor->Flink;
                ++guard;
                if (!cursor) break;
            }
            count = guard;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return true;
    }

    inline bool capture_baseline()
    {
        std::lock_guard<std::mutex> lk(chain_mtx());
        if (baseline_set().load()) return true;

        uint32_t count = 0;
        std::vector<uint64_t> hs;
        if (!walk_chain(hs, count)) return false;

        baseline_count().store(count);
        baseline_handlers() = std::move(hs);
        baseline_set().store(true);
        return true;
    }

    inline bool verify_chain()
    {
        if (!baseline_set().load())
        {
            capture_baseline();
            return true;
        }

        std::lock_guard<std::mutex> lk(chain_mtx());
        std::vector<uint64_t> hs;
        uint32_t count = 0;
        if (!walk_chain(hs, count)) return true;

        if (count != baseline_count().load()) return false;

        const auto& base = baseline_handlers();
        if (hs.size() != base.size()) return false;
        for (size_t i = 0; i < hs.size(); ++i)
        {
            if (hs[i] != base[i]) return false;
        }
        return true;
    }

}

namespace dr_scan {

    inline bool context_has_enabled_dr_in_text(const CONTEXT& ctx, uint64_t text_base, uint64_t text_end)
    {
        const uint64_t drs[4] = { ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3 };
        const uint64_t dr7 = ctx.Dr7;
        for (int i = 0; i < 4; ++i)
        {
            if (drs[i] == 0) continue;
            const bool en_local  = (dr7 >> (i * 2))     & 1;
            const bool en_global = (dr7 >> (i * 2 + 1)) & 1;
            if (!en_local && !en_global) continue;
            if (drs[i] >= text_base && drs[i] < text_end)
                return true;
        }
        return false;
    }

    inline bool current_thread_has_dr_in_text(uint64_t text_base, uint64_t text_end)
    {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(GetCurrentThread(), &ctx))
            return false;
        return context_has_enabled_dr_in_text(ctx, text_base, text_end);
    }

    inline bool thread_has_dr_in_text(DWORD tid, uint64_t text_base, uint64_t text_end)
    {
        HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE, tid);
        if (!ht) return false;

        bool ok = false;
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        DWORD prev_susp = SuspendThread(ht);
        if (prev_susp != static_cast<DWORD>(-1))
        {
            if (GetThreadContext(ht, &ctx))
                ok = context_has_enabled_dr_in_text(ctx, text_base, text_end);
            ResumeThread(ht);
        }
        CloseHandle(ht);
        return ok;
    }

    inline bool any_dr_in_text_range(uint64_t text_base, uint64_t text_end)
    {
        if (text_base == 0 || text_end <= text_base) return false;

        DWORD self_pid = GetCurrentProcessId();
        DWORD self_tid = GetCurrentThreadId();

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        bool ok = false;

        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID != self_pid) continue;
                if (te.th32ThreadID == self_tid) continue;

                ok = thread_has_dr_in_text(te.th32ThreadID, text_base, text_end);
                if (ok) break;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);

        if (!ok)
            ok = current_thread_has_dr_in_text(text_base, text_end);

        return ok;
    }

    inline std::atomic<DWORD>& runtime_cursor_tid()
    {
        static std::atomic<DWORD> v{0};
        return v;
    }

    inline bool any_dr_in_text_range_incremental(uint64_t text_base, uint64_t text_end, uint32_t budget)
    {
        if (text_base == 0 || text_end <= text_base) return false;
        if (budget == 0) budget = 1;

        if (current_thread_has_dr_in_text(text_base, text_end))
            return true;

        const DWORD self_pid = GetCurrentProcessId();
        const DWORD self_tid = GetCurrentThreadId();
        const DWORD cursor = runtime_cursor_tid().load(std::memory_order_acquire);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        bool ok = false;
        DWORD last_seen = cursor;
        uint32_t scanned = 0;

        auto scan_pass = [&](bool wrap) {
            te.dwSize = sizeof(te);
            if (!Thread32First(snap, &te)) return;
            do
            {
                if (te.th32OwnerProcessID != self_pid) continue;
                if (te.th32ThreadID == self_tid) continue;
                if (!wrap && te.th32ThreadID <= cursor) continue;
                if (wrap && cursor != 0 && te.th32ThreadID > cursor) continue;
                last_seen = te.th32ThreadID;
                ++scanned;
                if (thread_has_dr_in_text(te.th32ThreadID, text_base, text_end))
                {
                    ok = true;
                    break;
                }
            } while (scanned < budget && Thread32Next(snap, &te));
        };

        scan_pass(false);
        if (!ok && scanned < budget && cursor != 0)
            scan_pass(true);

        CloseHandle(snap);
        runtime_cursor_tid().store(last_seen, std::memory_order_release);
        return ok;
    }

}

namespace dispatch_check {

    inline bool dispatch_redirected_to_foreign_module(std::string& which)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        detail::module_range_t ntdll_range{};
        if (!detail::get_module_range(ntdll, ntdll_range))
            return false;

        const char* const probes[] = {
            "NtClose",
            "NtQueryInformationProcess",
            "NtQuerySystemInformation",
            "NtSetInformationThread",
            "NtProtectVirtualMemory",
        };

        for (const char* name : probes)
        {
            auto* fn = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, name));
            if (!fn) continue;

            __try
            {
                for (size_t off = 0; off + 5 < 0x40; ++off)
                {
                    if (fn[off] == 0xE9 || fn[off] == 0xEB)
                    {
                        int32_t disp = (fn[off] == 0xE9)
                            ? *reinterpret_cast<const int32_t*>(fn + off + 1)
                            : static_cast<int32_t>(static_cast<int8_t>(fn[off + 1]));
                        size_t skip = (fn[off] == 0xE9) ? 5 : 2;
                        uint64_t target = reinterpret_cast<uint64_t>(fn + off) + skip + disp;

                        if (target < ntdll_range.base || target >= ntdll_range.end)
                        {
                            which = name;
                            return true;
                        }
                    }

                    if (fn[off] == 0xFF && fn[off + 1] == 0x25)
                    {
                        int32_t disp = *reinterpret_cast<const int32_t*>(fn + off + 2);
                        uint64_t slot = reinterpret_cast<uint64_t>(fn + off) + 6 + disp;
                        uint64_t target = 0;
                        if (!detail::safe_read_uint64(slot, &target)) break;
                        if (target == 0) break;
                        if (target < ntdll_range.base || target >= ntdll_range.end)
                        {
                            which = name;
                            return true;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                continue;
            }
        }
        return false;
    }

}

inline void register_self_hook(uint64_t hooked_va, uint64_t hook_dest_va,
    const char* subsystem)
{
    std::lock_guard<std::mutex> lk(detail::self_hook_mtx());
    detail::self_hook_allowlist().push_back({hooked_va, hook_dest_va, subsystem});
}

inline bool is_self_hooked(uint64_t func_va)
{
    std::lock_guard<std::mutex> lk(detail::self_hook_mtx());
    for (const auto& e : detail::self_hook_allowlist())
    {
        if (e.hooked_va != func_va)
            continue;

        auto* bytes = reinterpret_cast<const uint8_t*>(func_va);
        uint64_t current_dest = 0;
        __try
        {
            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
                int32_t disp = *reinterpret_cast<const int32_t*>(bytes + 2);
                uint64_t slot = func_va + 6 + disp;
                current_dest = *reinterpret_cast<const uint64_t*>(slot);
            }
            else if (bytes[0] == 0xE9)
            {
                int32_t disp = *reinterpret_cast<const int32_t*>(bytes + 1);
                current_dest = func_va + 5 + disp;
            }
            else if (bytes[0] == 0x48 && bytes[1] == 0xB8)
            {
                current_dest = *reinterpret_cast<const uint64_t*>(bytes + 2);
            }
            else if (bytes[0] == 0x68 && bytes[5] == 0xC3)
            {
                uint32_t imm32 = *reinterpret_cast<const uint32_t*>(bytes + 1);
                current_dest = static_cast<uint64_t>(imm32);
            }
        }
        __except(1) { return false; }

        if (current_dest == 0)
            return false;

        if (current_dest != e.hook_dest_va)
            return false;

        return true;
    }
    return false;
}

namespace vtable_check {

    inline void register_vtable(const char* class_name, void* vtable_ptr,
        uint32_t entry_count, bool dynamic_vtable = false)
    {
        if (!class_name || !vtable_ptr || entry_count == 0) return;
        std::lock_guard<std::mutex> lk(detail::vtable_mtx());
        auto* vt = reinterpret_cast<const uint8_t*>(vtable_ptr);
        detail::vtable_baseline_t b{};
        b.class_name = class_name;
        b.vtable_va = reinterpret_cast<uint64_t>(vtable_ptr);
        b.entry_count = entry_count;
        b.dynamic_vtable = dynamic_vtable;
        if (dynamic_vtable)
        {
            b.hash_snapshot.clear();
            detail::vtable_baselines().push_back(std::move(b));
            return;
        }
        uint8_t hash[32];
        if (detail::sha256_hash(vt, static_cast<size_t>(entry_count) * 8, hash))
        {
            b.hash_snapshot.assign(hash, hash + 32);
            detail::vtable_baselines().push_back(std::move(b));
        }
    }

    inline bool verify_vtables(std::string& mismatched_class)
    {
        std::lock_guard<std::mutex> lk(detail::vtable_mtx());
        for (const auto& b : detail::vtable_baselines())
        {
            if (b.dynamic_vtable)
                continue;

            auto* vt = reinterpret_cast<const uint8_t*>(b.vtable_va);
            uint8_t hash[32];
            if (!detail::sha256_hash(vt,
                static_cast<size_t>(b.entry_count) * 8, hash))
            {
                mismatched_class = b.class_name;
                return false;
            }
            if (memcmp(hash, b.hash_snapshot.data(), 32) != 0)
            {
                mismatched_class = b.class_name;
                return false;
            }
        }
        return true;
    }

    inline bool detect_vtable_hooks(std::string& mismatched_class)
    {
        return !verify_vtables(mismatched_class);
    }

}

namespace self_heal {

    inline void capture_original_bytes(void* fn, const char* name)
    {
        if (!fn || !name) return;
        std::lock_guard<std::mutex> lk(detail::original_bytes_mtx());
        detail::original_bytes_entry_t e{};
        e.function_va = reinterpret_cast<uint64_t>(fn);
        e.byte_count = static_cast<uint32_t>(detail::k_prologue_bytes);

        uint8_t plain[32];
        __try { memcpy(plain, fn, 32); } __except(1) { return; }

        uint64_t k0 = 0, k1 = 0;
        __try {
            auto& sip_k0 = anti_tamper::integrity::detail::s_siphash_k0_obf;
            auto& sip_k1 = anti_tamper::integrity::detail::s_siphash_k1_obf;
            k0 = sip_k0.load(std::memory_order_acquire);
            k1 = sip_k1.load(std::memory_order_acquire);
        } __except(1) {
            k0 = static_cast<uint64_t>(__rdtsc());
            k1 = static_cast<uint64_t>(GetCurrentProcessId());
        }
        e.encryption_key = k0 ^ k1 ^ 0xA1DA5EED12345678ULL;

        for (uint32_t i = 0; i < 32; ++i)
            e.encrypted_bytes[i] = plain[i] ^ static_cast<uint8_t>(
                (e.encryption_key >> ((i & 7) * 8)) & 0xFF);

        strncpy_s(e.function_name, name, 63);
        e.function_name[63] = 0;

        SecureZeroMemory(plain, sizeof(plain));
        detail::original_bytes_store().push_back(std::move(e));
    }

    inline bool restore_prologue(uint64_t function_va, const char* name)
    {
        detail::original_bytes_entry_t* found = nullptr;
        {
            std::lock_guard<std::mutex> lk(detail::original_bytes_mtx());
            for (auto& e : detail::original_bytes_store())
            {
                if (e.function_va == function_va)
                {
                    found = &e;
                    break;
                }
            }
        }
        if (!found) return false;

        uint8_t plain[32];
        for (uint32_t i = 0; i < 32; ++i)
            plain[i] = found->encrypted_bytes[i] ^ static_cast<uint8_t>(
                (found->encryption_key >> ((i & 7) * 8)) & 0xFF);

        const uint32_t byte_count = found->byte_count;
        const uint64_t va_start = function_va;
        const uint64_t va_end = function_va + byte_count;

        NTSTATUS susp_st = static_cast<NTSTATUS>(0xC0000001L);
        if (syscall::is_initialized())
        {
            susp_st = syscall::call_NtSuspendProcess(GetCurrentProcess());
        }

        bool abort_restore = false;
        if (susp_st >= 0 || !syscall::is_initialized())
        {
            DWORD self_pid = GetCurrentProcessId();
            DWORD self_tid = GetCurrentThreadId();
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap != INVALID_HANDLE_VALUE)
            {
                THREADENTRY32 te = {sizeof(te)};
                if (Thread32First(snap, &te))
                {
                    do {
                        if (te.th32OwnerProcessID != self_pid)
                            continue;
                        if (te.th32ThreadID == self_tid)
                            continue;

                        HANDLE th = OpenThread(
                            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                            FALSE, te.th32ThreadID);
                        if (!th) continue;

                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_CONTROL;
                        bool got_ctx = false;
                        if (syscall::is_initialized())
                        {
                            NTSTATUS ctx_st = syscall::call_NtGetContextThread(th, &ctx);
                            got_ctx = ctx_st >= 0;
                        }
                        if (!got_ctx)
                            got_ctx = GetThreadContext(th, &ctx) != FALSE;

                        if (got_ctx)
                        {
                            uint64_t rip = ctx.Rip;
                            if (rip >= va_start && rip < va_end)
                                abort_restore = true;
                        }
                        CloseHandle(th);
                    } while (Thread32Next(snap, &te) && !abort_restore);
                }
                CloseHandle(snap);
            }
        }

        if (abort_restore)
        {
            if (syscall::is_initialized())
                syscall::call_NtResumeProcess(GetCurrentProcess());
            SecureZeroMemory(plain, sizeof(plain));
            char dbg[256];
            _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                "hook_self_healing_aborted thread_in_range func=%s va=0x%llX",
                name ? name : "?",
                static_cast<unsigned long long>(function_va));
            webhook::write_log_critical("hook_heal", dbg);
            return false;
        }

        PVOID base = reinterpret_cast<PVOID>(function_va);
        SIZE_T region_size = byte_count;
        ULONG old_prot = 0;
        bool prot_ok = false;

        if (syscall::is_initialized())
        {
            NTSTATUS st = syscall::call_NtProtectVirtualMemory(
                GetCurrentProcess(), &base, &region_size,
                PAGE_EXECUTE_READWRITE, &old_prot);
            prot_ok = (st >= 0);
        }
        if (!prot_ok)
        {
            DWORD old_dw = 0;
            prot_ok = VirtualProtect(reinterpret_cast<void*>(function_va),
                byte_count, PAGE_EXECUTE_READWRITE, &old_dw) != FALSE;
            if (prot_ok) old_prot = old_dw;
        }

        if (!prot_ok)
        {
            if (syscall::is_initialized())
                syscall::call_NtResumeProcess(GetCurrentProcess());
            SecureZeroMemory(plain, sizeof(plain));
            return false;
        }

        __try {
            memcpy(reinterpret_cast<void*>(function_va), plain, byte_count);
        } __except(1) {
            if (syscall::is_initialized())
                syscall::call_NtResumeProcess(GetCurrentProcess());
            SecureZeroMemory(plain, sizeof(plain));
            return false;
        }

        if (syscall::is_initialized())
        {
            PVOID base2 = reinterpret_cast<PVOID>(function_va);
            SIZE_T rs2 = byte_count;
            ULONG dummy = 0;
            syscall::call_NtProtectVirtualMemory(
                GetCurrentProcess(), &base2, &rs2,
                old_prot, &dummy);
        }
        else
        {
            DWORD old_dw = 0;
            VirtualProtect(reinterpret_cast<void*>(function_va),
                byte_count, old_prot, &old_dw);
        }

        FlushInstructionCache(GetCurrentProcess(),
            reinterpret_cast<void*>(function_va), byte_count);

        if (syscall::is_initialized())
            syscall::call_NtResumeProcess(GetCurrentProcess());

        SecureZeroMemory(plain, sizeof(plain));

        char dbg[256];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "hook_self_healing_restored func=%s va=0x%llX bytes=%u",
            name ? name : "?",
            static_cast<unsigned long long>(function_va),
            byte_count);
        webhook::write_log_critical("hook_heal", dbg);
        return true;
    }

    inline uint32_t heal_detected_hooks(const hook_report_t& report)
    {
        uint32_t healed = 0;

        if (report.ntdll_inline_hooked && !report.hooked_function.empty())
        {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll)
            {
                auto* fn = GetProcAddress(ntdll, report.hooked_function.c_str());
                if (fn && restore_prologue(reinterpret_cast<uint64_t>(fn),
                    report.hooked_function.c_str()))
                    ++healed;
            }
        }

        if (report.kernel32_inline_hooked && !report.hooked_function.empty())
        {
            HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
            if (k32)
            {
                auto* fn = GetProcAddress(k32, report.hooked_function.c_str());
                if (fn && restore_prologue(reinterpret_cast<uint64_t>(fn),
                    report.hooked_function.c_str()))
                    ++healed;
            }
        }

        return healed;
    }

}

namespace server_hashes {

    inline void set_server_prologue_hashes(
        uint32_t version_tag,
        bool hmac_valid,
        const std::vector<detail::server_prologue_hash_t>& hashes)
    {
        detail::server_hash_version_tag().store(version_tag,
            std::memory_order_release);
        detail::server_hash_hmac_valid().store(hmac_valid,
            std::memory_order_release);

        OSVERSIONINFOEXW vi{};
        vi.dwOSVersionInfoSize = sizeof(vi);
        typedef LONG(NTAPI* RtlGetVersion_t)(POSVERSIONINFOEXW);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
        {
            auto pRtlGetVersion = reinterpret_cast<RtlGetVersion_t>(
                GetProcAddress(ntdll, "RtlGetVersion"));
            if (pRtlGetVersion && pRtlGetVersion(&vi) == 0)
            {
                uint32_t client_build = static_cast<uint32_t>(vi.dwBuildNumber);
                detail::server_hash_version_ok().store(
                    version_tag == client_build && hmac_valid,
                    std::memory_order_release);
            }
            else
            {
                detail::server_hash_version_ok().store(false,
                    std::memory_order_release);
            }
        }
        else
        {
            detail::server_hash_version_ok().store(false,
                std::memory_order_release);
        }

        if (hmac_valid)
        {
            detail::server_hash_table() = hashes;
        }
        else
        {
            detail::server_hash_table().clear();
        }

        char dbg[256];
        _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
            "server_prologue_hashes_set version_tag=0x%08X hmac_valid=%d count=%zu version_ok=%d",
            version_tag, hmac_valid ? 1 : 0,
            hashes.size(),
            detail::server_hash_version_ok().load() ? 1 : 0);
        webhook::write_log("server_hashes", dbg);
    }

    inline bool verify_against_server_hashes(std::string& mismatched_name)
    {
        if (detail::server_hash_table().empty())
            return true;

        if (!detail::server_hash_version_ok().load())
        {
            webhook::write_log("server_hashes",
                "server_hash_version_mismatch_skipping_verification");
            return true;
        }

        if (!detail::server_hash_hmac_valid().load())
        {
            webhook::write_log("server_hashes",
                "server_hash_hmac_fail_skipping_verification");
            return true;
        }

        for (const auto& sh : detail::server_hash_table())
        {
            HMODULE mod = GetModuleHandleW(
                sh.module_name == "ntdll.dll" ? L"ntdll.dll" : L"kernel32.dll");
            if (!mod) continue;

            auto* fn = reinterpret_cast<const uint8_t*>(
                GetProcAddress(mod, sh.function_name.c_str()));
            if (!fn) continue;

            uint8_t current_hash[32];
            if (!baseline::seh_hash_prologue(fn, current_hash))
                continue;

            if (memcmp(current_hash, sh.expected_hash, 32) != 0)
            {
                if (sh.module_name == "ntdll.dll" &&
                    detail::system_owned_nt_export_wrapper(
                        sh.function_name.c_str(), fn))
                    continue;

                mismatched_name = sh.function_name;
                return false;
            }
        }
        return true;
    }

}

inline bool verify_iat_entries(const std::vector<state::iat_entry_t>& snapshot)
{
    for (size_t idx = 0; idx < snapshot.size(); ++idx)
    {
        const auto& e = snapshot[idx];

        uint64_t current = 0;
        if (!detail::safe_read_uint64(e.slot_va, &current))
        {
            static int s_iat_exc_logged = 0;
            if (s_iat_exc_logged < 5) {
                ++s_iat_exc_logged;
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "iat_read_exception slot_va=0x%llX idx=%zu",
                    e.slot_va, idx);
                webhook::write_log("iat_hook", dbg);
            }
            return false;
        }

        if (current != e.resolved_va)
        {
            static int s_iat_fail_logged = 0;
            if (s_iat_fail_logged < 5) {
                ++s_iat_fail_logged;
                char dbg[256];
                _snprintf_s(dbg, sizeof(dbg), _TRUNCATE,
                    "iat_mismatch idx=%zu slot_va=0x%llX expected=0x%llX got=0x%llX",
                    idx, e.slot_va, e.resolved_va, current);
                webhook::write_log("iat_hook", dbg);
            }
            return false;
        }
    }
    return true;
}

inline bool verify_iat_target_modules(const std::vector<state::iat_entry_t>& snapshot)
{
    HMODULE mods[256] = {};
    DWORD cb = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &cb, LIST_MODULES_ALL))
        return true;

    DWORD count = cb / sizeof(HMODULE);

    struct mod_range { uint64_t base; uint64_t end; };
    std::vector<mod_range> ranges;
    ranges.reserve(count);

    for (DWORD i = 0; i < count; ++i)
    {
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi)))
        {
            uint64_t b = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
            ranges.push_back({b, b + mi.SizeOfImage});
        }
    }

    for (const auto& e : snapshot)
    {
        uint64_t current = 0;
        if (!detail::safe_read_uint64(e.slot_va, &current))
            return false;
        bool in_module = false;
        for (const auto& r : ranges)
        {
            if (current >= r.base && current < r.end)
            {
                in_module = true;
                break;
            }
        }
        if (!in_module)
            return false;
    }
    return true;
}

inline bool verify_prologue_hashes(std::string& mismatched_name)
{
    if (!detail::baselines_captured().load())
        baseline::capture_all();

    std::lock_guard<std::mutex> lk(detail::baseline_mtx());

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE k32   = GetModuleHandleW(L"kernel32.dll");

    const std::vector<detail::prologue_baseline_t>* sets[2] = {
        &detail::ntdll_baselines(), &detail::kernel32_baselines()
    };
    HMODULE mods[2] = { ntdll, k32 };

    for (size_t s = 0; s < 2; ++s)
    {
        if (!mods[s]) continue;
        for (const auto& b : *sets[s])
        {
            auto* addr = reinterpret_cast<const uint8_t*>(
                GetProcAddress(mods[s], b.name.c_str()));
            if (!addr) continue;

            uint8_t hash[32]{};
            if (!baseline::seh_hash_prologue(addr, hash))
                continue;

            if (memcmp(hash, b.hash, 32) != 0)
            {
                if (s == 0 && detail::system_owned_nt_export_wrapper(b.name.c_str(), addr))
                    continue;
                mismatched_name = b.name;
                return false;
            }
        }
    }

    return true;
}

inline bool verify_disk_image(std::string& mismatched_name)
{
    if (!detail::disk_image_loaded().load())
    {
        if (!detail::load_disk_image_ntdll())
            return true;
        detail::disk_image_loaded().store(true);
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return true;

    for (const char* name : detail::k_critical_ntdll_funcs)
    {
        const uint8_t* mem_bytes = reinterpret_cast<const uint8_t*>(
            GetProcAddress(ntdll, name));
        if (!mem_bytes) continue;

        const uint8_t* disk_bytes = detail::disk_export_bytes(name);
        if (!disk_bytes) continue;

        __try
        {
            if (memcmp(mem_bytes, disk_bytes, detail::k_prologue_bytes) == 0)
                continue;

            const uint8_t b0 = mem_bytes[0];
            const uint8_t b1 = mem_bytes[1];

            const bool inline_jmp_rel32 = (b0 == 0xE9);
            const bool inline_jmp_short = (b0 == 0xEB);
            const bool inline_indirect_jmp = (b0 == 0xFF && b1 == 0x25);
            const bool inline_movabs_jmp =
                (b0 == 0x48 && b1 == 0xB8 && mem_bytes[10] == 0xFF && mem_bytes[11] == 0xE0);
            const bool inline_push_ret = (b0 == 0x68 && mem_bytes[5] == 0xC3);
            const bool inline_int3 = (b0 == 0xCC);

            if (inline_jmp_rel32 || inline_jmp_short || inline_indirect_jmp ||
                inline_movabs_jmp || inline_push_ret || inline_int3)
            {
                mismatched_name = name;
                return false;
            }

            const bool standard_x64_syscall_stub =
                (b0 == 0x4C && b1 == 0x8B && mem_bytes[2] == 0xD1 &&
                 mem_bytes[3] == 0xB8);
            const bool wow64_indirect_call =
                (b0 == 0xB8 && mem_bytes[5] == 0xBA);

            if (standard_x64_syscall_stub || wow64_indirect_call)
                continue;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }
    return true;
}

inline bool scan_inline_hooks_ntdll(std::string& hooked_name)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    for (const char* name : detail::k_critical_ntdll_funcs)
    {
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, name));
        if (!addr) continue;

        uint64_t va = reinterpret_cast<uint64_t>(addr);
        if (is_self_hooked(va))
        {
            webhook::write_log("ntdll_hook",
                "self_hook_allowlisted skip (ghost_veh/protector)");
            continue;
        }

        if (detail::check_inline_hook_deep_at_export(ntdll, name))
        {
            hooked_name = name;
            return true;
        }
    }
    return false;
}

inline bool scan_inline_hooks_kernel32(std::string& hooked_name)
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return false;

    for (const char* name : detail::k_critical_kernel32_funcs)
    {
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(k32, name));
        if (!addr) continue;

        uint64_t va = reinterpret_cast<uint64_t>(addr);
        if (is_self_hooked(va))
        {
            webhook::write_log("k32_hook",
                "self_hook_allowlisted skip");
            continue;
        }

        if (detail::check_inline_hook_deep_at_export(k32, name))
        {
            hooked_name = name;
            return true;
        }
    }
    return false;
}

inline bool verify_syscall_stubs()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        webhook::write_log_critical("syscall_hook", "verify_syscall_stubs no_ntdll_module");
        return true;
    }

    const char* syscall_funcs[] = {
        "NtQueryInformationProcess",
        "NtQuerySystemInformation",
        "NtSetInformationThread",
        "NtProtectVirtualMemory",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtClose",
        "NtOpenProcess",
    };

    if (!detail::ntdll_disk_image().valid)
        detail::load_disk_image_ntdll();

    for (const auto& name : syscall_funcs)
    {
        auto* addr = reinterpret_cast<const uint8_t*>(GetProcAddress(ntdll, name));
        if (!addr) {
            webhook::write_log_critical_fmt("syscall_hook", "verify_syscall_stub export_missing func=%s", name);
            continue;
        }

        const bool ok = detail::verify_syscall_stub(addr);
        if (!ok)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            SIZE_T vq = VirtualQuery(addr, &mbi, sizeof(mbi));
            HMODULE owner_mod = nullptr;
            BOOL owner_ok = GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(addr),
                &owner_mod);
            wchar_t owner_path_w[MAX_PATH]{};
            DWORD owner_path_len = owner_ok && owner_mod
                ? GetModuleFileNameW(owner_mod, owner_path_w, MAX_PATH)
                : 0;
            char owner_path[512]{};
            anti_tamper::syscall::detail::narrow_path(owner_path_w, owner_path, sizeof(owner_path));
            MODULEINFO owner_info{};
            DWORD owner_size = 0;
            uint64_t owner_base = 0;
            uint64_t owner_rva = 0;
            if (owner_mod && GetModuleInformation(GetCurrentProcess(), owner_mod, &owner_info, sizeof(owner_info))) {
                owner_base = reinterpret_cast<uint64_t>(owner_info.lpBaseOfDll);
                owner_size = owner_info.SizeOfImage;
                owner_rva = reinterpret_cast<uint64_t>(addr) - owner_base;
            }
            char mem16[33]{};
            char disk16[33]{};
            detail::bytes16_hex(addr, mem16);
            const uint8_t* disk_bytes = detail::disk_export_bytes(name);
            detail::bytes16_hex(disk_bytes, disk16);
            if (detail::system_owned_nt_export_wrapper(name,
                                                       addr,
                                                       "syscall_hook",
                                                       "verify_syscall_stub_system_wrapper_nonfatal",
                                                       "verify_syscall_stub_system_wrapper_reject"))
                continue;
            bool owner_system = owner_path_len != 0 &&
                anti_tamper::syscall::detail::system_image_module_path(owner_path_w);
            webhook::write_log_critical_fmt("syscall_hook",
                "verify_syscall_stub_failed func=%s va=0x%llX vq=%llu protect=0x%lX state=0x%lX type=0x%lX type_name=%s owner_ok=%d owner_base=0x%llX owner_size=0x%lX owner_rva=0x%llX owner_system=%d owner_path=%s mem16=%s disk16=%s",
                name,
                static_cast<unsigned long long>(reinterpret_cast<uint64_t>(addr)),
                static_cast<unsigned long long>(vq),
                vq ? static_cast<unsigned long>(mbi.Protect) : 0ul,
                vq ? static_cast<unsigned long>(mbi.State) : 0ul,
                vq ? static_cast<unsigned long>(mbi.Type) : 0ul,
                vq ? anti_tamper::syscall::detail::memory_type_name(mbi.Type) : "none",
                owner_ok ? 1 : 0,
                static_cast<unsigned long long>(owner_base),
                static_cast<unsigned long>(owner_size),
                static_cast<unsigned long long>(owner_rva),
                owner_system ? 1 : 0,
                owner_path[0] ? owner_path : "<none>",
                mem16,
                disk16);
            return false;
        }
    }
    return true;
}

inline bool verify_export_addresses(HMODULE mod)
{
    if (!mod) return true;

    detail::module_range_t range{};
    if (!detail::get_module_range(mod, range))
        return true;

    const auto* base = reinterpret_cast<const uint8_t*>(mod);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return true;

    const auto& exp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0) return true;

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + exp_dir.VirtualAddress);
    const auto* funcs = reinterpret_cast<const DWORD*>(
        base + exports->AddressOfFunctions);

    uint64_t exp_start = reinterpret_cast<uint64_t>(base) + exp_dir.VirtualAddress;
    uint64_t exp_end = exp_start + exp_dir.Size;

    for (DWORD i = 0; i < exports->NumberOfFunctions; ++i)
    {
        uint64_t func_va = reinterpret_cast<uint64_t>(base) + funcs[i];

        if (func_va >= exp_start && func_va < exp_end)
            continue;

        if (func_va < range.base || func_va >= range.end)
            return false;
    }
    return true;
}

inline hook_report_t scan_impl(const std::vector<state::iat_entry_t>& iat_snap, bool incremental_dr)
{
    hook_report_t report{};

    if (!detail::baselines_captured().load())
        baseline::capture_all();
    if (!veh_chain::baseline_set().load())
        veh_chain::capture_baseline();

    report.iat_modified = !verify_iat_entries(iat_snap);
    if (report.iat_modified)
        webhook::send_debug_log("iat_hook", "iat_entry_modified", true);

    if (!report.iat_modified)
    {
        bool targets_ok = verify_iat_target_modules(iat_snap);
        if (!targets_ok)
        {
            report.iat_modified = true;
            webhook::send_debug_log("iat_target", "iat_target_outside_module", true);
        }
    }

    std::string ntdll_hooked;
    report.ntdll_inline_hooked = scan_inline_hooks_ntdll(ntdll_hooked);
    if (report.ntdll_inline_hooked)
    {
        report.hooked_function = ntdll_hooked;
        webhook::send_debug_log("ntdll_hook", "inline_hook: " + ntdll_hooked, true);
    }

    std::string k32_hooked;
    report.kernel32_inline_hooked = scan_inline_hooks_kernel32(k32_hooked);
    if (report.kernel32_inline_hooked)
    {
        report.hooked_function = k32_hooked;
        webhook::send_debug_log("k32_hook", "inline_hook: " + k32_hooked, true);
    }

    report.syscall_stubs_modified = !verify_syscall_stubs();
    if (report.syscall_stubs_modified)
    {
        webhook::write_log_critical_fmt("syscall_hook",
            "full_scan_syscall_stubs_modified pid=%lu tid=%lu",
            GetCurrentProcessId(),
            GetCurrentThreadId());
        webhook::send_debug_log("syscall_hook", "syscall_stub_modified", true);
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    report.eat_hooked = !verify_export_addresses(ntdll);
    if (report.eat_hooked)
        webhook::send_debug_log("eat_hook", "ntdll_eat_rva_outside_module", true);

    std::string proem;
    report.prologue_hash_mismatch = !verify_prologue_hashes(proem);
    if (report.prologue_hash_mismatch)
    {
        report.hooked_function = proem;
        webhook::send_debug_log("prologue_hash", "prologue_mismatch: " + proem, true);
    }

    std::string disk_name;
    report.disk_image_mismatch = !verify_disk_image(disk_name);
    if (report.disk_image_mismatch)
    {
        report.hooked_function = disk_name;
        webhook::send_debug_log("disk_image", "disk_mismatch: " + disk_name, true);
    }

    report.veh_chain_tampered = !veh_chain::verify_chain();
    if (report.veh_chain_tampered)
        webhook::send_debug_log("veh_chain", "veh_chain_modified", true);

    auto& rt = state::get();
    if (rt.code_snap.text_base != 0 && rt.code_snap.text_size != 0)
    {
        uint64_t text_end = rt.code_snap.text_base + rt.code_snap.text_size;
        report.dr_in_text_range = incremental_dr
            ? dr_scan::any_dr_in_text_range_incremental(rt.code_snap.text_base, text_end, 16)
            : dr_scan::any_dr_in_text_range(rt.code_snap.text_base, text_end);
        if (report.dr_in_text_range)
            webhook::send_debug_log("dr_scan", "dr_in_text_range", true);
    }

    std::string redir_name;
    report.dispatch_table_redirected = dispatch_check::dispatch_redirected_to_foreign_module(redir_name);
    if (report.dispatch_table_redirected)
    {
        report.hooked_function = redir_name;
        webhook::send_debug_log("dispatch_redirect", "redirected: " + redir_name, true);
    }

    if (syscall::is_initialized())
    {
        std::string disk_hooked;
        if (syscall::detect_ntdll_hooks(disk_hooked))
        {
            if (!report.ntdll_inline_hooked)
            {
                report.ntdll_inline_hooked = true;
                report.hooked_function = disk_hooked;
                ntdll_hooked = disk_hooked;
            }
            webhook::send_debug_log("disk_hook", "disk_mismatch: " + disk_hooked, true);
        }
    }

    std::string vtable_class;
    report.vtable_hooked = vtable_check::detect_vtable_hooks(vtable_class);
    if (report.vtable_hooked)
    {
        report.vtable_mismatched_class = vtable_class;
        webhook::send_debug_log("vtable_hook", "vtable_modified: " + vtable_class, true);
    }

    std::string server_mismatch;
    bool server_ok = server_hashes::verify_against_server_hashes(server_mismatch);
    if (!server_ok)
    {
        report.server_hash_mismatch = true;
        report.hooked_function = server_mismatch;
        webhook::send_debug_log("server_hashes",
            "server_hash_mismatch: " + server_mismatch, true);
    }

    if (report.any_detected())
    {
        self_heal::heal_detected_hooks(report);

        uint64_t evidence = static_cast<uint64_t>(__rdtsc()) ^
            (static_cast<uint64_t>(GetCurrentProcessId()) << 32) ^
            0xA1DA0004ULL;

        webhook::write_log_critical_fmt("hook_detect",
            "TIER2_BSOD trigger=0x%08X summary=%s pid=%lu tid=%lu",
            0xA1DA0004u,
            report.summary.c_str(),
            GetCurrentProcessId(),
            GetCurrentThreadId());

        if (driver_bridge::is_loaded() && driver_bridge::using_kernel_driver())
        {
            driver_bridge::trigger_kernel_bsod(0xA1DA0004u, evidence);
        }

        enforce_violation("hook_detected", report.summary);
    }

    if (report.iat_modified) report.summary += "iat ";
    if (report.ntdll_inline_hooked) report.summary += "ntdll:" + (!ntdll_hooked.empty() ? ntdll_hooked : report.hooked_function) + " ";
    if (report.kernel32_inline_hooked) report.summary += "k32:" + k32_hooked + " ";
    if (report.syscall_stubs_modified) report.summary += "syscall ";
    if (report.eat_hooked) report.summary += "eat ";
    if (report.prologue_hash_mismatch) report.summary += "prologue:" + proem + " ";
    if (report.disk_image_mismatch) report.summary += "disk:" + disk_name + " ";
    if (report.veh_chain_tampered) report.summary += "veh ";
    if (report.dr_in_text_range) report.summary += "dr ";
    if (report.dispatch_table_redirected) report.summary += "redir:" + redir_name + " ";
    if (report.vtable_hooked) report.summary += "vtable:" + vtable_class + " ";
    if (report.server_hash_mismatch) report.summary += "srvhash:" + server_mismatch + " ";

    return report;
}

inline hook_report_t full_scan(const std::vector<state::iat_entry_t>& iat_snap)
{
    return scan_impl(iat_snap, false);
}

inline hook_report_t runtime_scan(const std::vector<state::iat_entry_t>& iat_snap)
{
    return scan_impl(iat_snap, true);
}

}
}
