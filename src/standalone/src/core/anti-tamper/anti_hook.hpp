#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "webhook.hpp"
#include "state.hpp"
#include "syscall.hpp"

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
    std::string hooked_function;
    std::string summary;

    bool any_detected() const
    {
        return iat_modified || ntdll_inline_hooked || kernel32_inline_hooked
            || syscall_stubs_modified || eat_hooked
            || prologue_hash_mismatch || disk_image_mismatch
            || veh_chain_tampered || dr_in_text_range
            || dispatch_table_redirected;
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

    inline bool system_owned_nt_export_wrapper(const char* name, const uint8_t* addr)
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

        const bool ok =
            vq != 0 &&
            mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_IMAGE &&
            !mem_writable &&
            !mem_redirect &&
            owner_ok &&
            owner_system;

        webhook::write_log_critical_fmt("prologue_hash",
            "prologue_mismatch_system_wrapper func=%s ok=%d va=0x%llX vq=%llu protect=0x%lX state=0x%lX type=0x%lX type_name=%s mem_writable=%d mem_redirect=%d owner_ok=%d owner=0x%llX owner_system=%d owner_path=%s",
            name,
            ok ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<uint64_t>(addr)),
            static_cast<unsigned long long>(vq),
            vq ? static_cast<unsigned long>(mbi.Protect) : 0ul,
            vq ? static_cast<unsigned long>(mbi.State) : 0ul,
            vq ? static_cast<unsigned long>(mbi.Type) : 0ul,
            vq ? anti_tamper::syscall::detail::memory_type_name(mbi.Type) : "none",
            mem_writable ? 1 : 0,
            mem_redirect ? 1 : 0,
            owner_ok ? 1 : 0,
            static_cast<unsigned long long>(reinterpret_cast<uint64_t>(owner_mod)),
            owner_system ? 1 : 0,
            owner_path[0] ? owner_path : "<none>");

        return ok;
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

                HANDLE ht = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE, te.th32ThreadID);
                if (!ht) continue;

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

                DWORD prev_susp = SuspendThread(ht);
                if (prev_susp != static_cast<DWORD>(-1))
                {
                    if (GetThreadContext(ht, &ctx))
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
                            {
                                ok = true;
                                break;
                            }
                        }
                    }
                    ResumeThread(ht);
                }
                CloseHandle(ht);
                if (ok) break;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);

        if (!ok)
        {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx))
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
                    {
                        ok = true;
                        break;
                    }
                }
            }
        }

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

        if (detail::check_inline_hook_bytes(addr, name))
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

        if (detail::check_inline_hook_bytes(addr, name))
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

inline hook_report_t full_scan(const std::vector<state::iat_entry_t>& iat_snap)
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
        report.dr_in_text_range = dr_scan::any_dr_in_text_range(
            rt.code_snap.text_base, text_end);
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

    return report;
}

}
}
