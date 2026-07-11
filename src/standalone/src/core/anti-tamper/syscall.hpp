#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <intrin.h>

#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <vector>

#include "key_pipeline.hpp"
#include "webhook.hpp"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace anti_tamper {
namespace syscall {

namespace detail {

    constexpr uint32_t kSlotCount = 32;
    constexpr uint32_t kEntryNtQueryInformationProcess = 0;
    constexpr uint32_t kEntryNtQuerySystemInformation  = 1;
    constexpr uint32_t kEntryNtQueryVirtualMemory      = 2;
    constexpr uint32_t kEntryNtSetInformationThread    = 3;
    constexpr uint32_t kEntryNtQueryInformationThread  = 4;
    constexpr uint32_t kEntryNtClose                   = 5;
    constexpr uint32_t kEntryNtRaiseHardError          = 6;
    constexpr uint32_t kEntryNtOpenProcessToken        = 7;
    constexpr uint32_t kEntryNtOpenThreadToken         = 8;
    constexpr uint32_t kEntryNtAdjustPrivilegesToken   = 9;
    constexpr uint32_t kEntryNtSuspendProcess          = 10;
    constexpr uint32_t kEntryNtResumeProcess           = 11;
    constexpr uint32_t kEntryNtProtectVirtualMemory    = 12;
    constexpr uint32_t kEntryNtGetContextThread        = 13;
    constexpr uint32_t kEntryNtReadVirtualMemory       = 14;
    constexpr uint32_t kEntryNtWriteVirtualMemory      = 15;
    constexpr uint32_t kEntryNtAllocateVirtualMemory   = 16;
    constexpr uint32_t kEntryNtFreeVirtualMemory       = 17;
    constexpr uint32_t kEntryNtOpenProcess             = 18;
    constexpr uint32_t kEntryNtCreateFile              = 19;

    struct slot_t
    {
        uint32_t ssn_xor;
        uint32_t ssn_mask;
        uint64_t syscall_insn_va;
        uint64_t function_va;
        uint8_t  hmac_anchor[32];
    };

    struct table_t
    {
        std::mutex      init_mtx;
        std::atomic<bool> initialized{false};
        slot_t          slots[kSlotCount]{};
        uint8_t         pipeline_key[32]{};
        uint64_t        ntdll_base{0};
        uint32_t        ntdll_size{0};
    };

    inline table_t& table()
    {
        static table_t t{};
        return t;
    }

    inline std::atomic<uint64_t>& csprng_counter()
    {
        static std::atomic<uint64_t> c{0};
        return c;
    }

    inline bool gen_random(uint8_t* out, size_t n)
    {
        return BCryptGenRandom(nullptr, out, static_cast<ULONG>(n),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    inline uint8_t random_byte()
    {
        uint8_t b = 0;
        gen_random(&b, 1);
        return b;
    }

    inline uint32_t random_u32()
    {
        uint32_t v = 0;
        if (!gen_random(reinterpret_cast<uint8_t*>(&v), 4))
        {
            v = static_cast<uint32_t>(__rdtsc()) ^
                static_cast<uint32_t>(csprng_counter().fetch_add(1));
        }
        return v;
    }

    inline bool resolve_ntdll_function(const char* func_name,
                                       uint64_t& func_va_out,
                                       uint64_t& syscall_insn_va_out)
    {
        HMODULE mod = GetModuleHandleW(L"ntdll.dll");
        if (!mod) return false;
        auto* base = reinterpret_cast<uint8_t*>(mod);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.Size == 0) return false;
        auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
        auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
        auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
        auto* ords  = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);

        const uint8_t* fbytes = nullptr;
        for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
        {
            const char* n = reinterpret_cast<const char*>(base + names[i]);
            if (strcmp(n, func_name) != 0) continue;
            fbytes = base + funcs[ords[i]];
            break;
        }
        if (!fbytes) return false;

        func_va_out = reinterpret_cast<uint64_t>(fbytes);

        for (size_t i = 0; i < 64; ++i)
        {
            if (fbytes[i] == 0x0F && fbytes[i + 1] == 0x05)
            {
                syscall_insn_va_out =
                    reinterpret_cast<uint64_t>(fbytes + i);
                return true;
            }
            if (fbytes[i] == 0xC3) break;
        }
        return false;
    }

    inline bool extract_ssn(const uint8_t* fbytes, uint32_t& ssn_out)
    {
        if (fbytes[0] == 0x4C && fbytes[1] == 0x8B && fbytes[2] == 0xD1
            && fbytes[3] == 0xB8)
        {
            std::memcpy(&ssn_out, fbytes + 4, 4);
            return true;
        }
        for (size_t i = 3; i < 32; ++i)
        {
            if (fbytes[i] == 0xB8 &&
                fbytes[i - 3] == 0x4C && fbytes[i - 2] == 0x8B &&
                fbytes[i - 1] == 0xD1)
            {
                std::memcpy(&ssn_out, fbytes + i + 1, 4);
                return true;
            }
        }
        return false;
    }

    inline bool derive_pipeline_key(uint8_t out[32])
    {
        const char* domain = "aida.syscall.ssn.v1";
        uint8_t salt[24];
        std::memcpy(salt, "syscall.bind.salt.0001", 22);
        salt[22] = 0;
        salt[23] = 1;
        return key_pipeline::derive(domain, salt, sizeof(salt), out, 32);
    }

    inline void mac_for_slot(const uint8_t key[32],
                             uint32_t entry_id,
                             uint8_t out[32])
    {
        uint8_t buf[32];
        std::memset(buf, 0, sizeof(buf));
        std::memcpy(buf, &entry_id, 4);
        bool ok = false;
        key_pipeline::detail_kp::hmac_sha256_internal(
            key, 32, buf, sizeof(buf), out, ok);
        if (!ok)
        {
            for (size_t i = 0; i < 32; ++i)
                out[i] = key[i] ^ buf[i & 31] ^ static_cast<uint8_t>(i);
        }
    }

    inline uint8_t* alloc_rwx_page()
    {
        return static_cast<uint8_t*>(
            VirtualAlloc(nullptr, 4096,
                         MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE));
    }

    inline void emit_random_padding(uint8_t*& p, uint8_t* limit, uint32_t bytes)
    {
        for (uint32_t i = 0; i < bytes && p < limit; ++i)
        {
            uint8_t kind = random_byte() & 0x3;
            switch (kind)
            {
            case 0:
                *p++ = 0x90;
                break;
            case 1:
                if (limit - p < 3) { *p++ = 0x90; break; }
                *p++ = 0x66;
                *p++ = 0x66;
                *p++ = 0x90;
                i += 2;
                break;
            case 2:
                if (limit - p < 4) { *p++ = 0x90; break; }
                *p++ = 0x48;
                *p++ = 0x8D;
                *p++ = 0x40;
                *p++ = 0x00;
                i += 3;
                break;
            default:
                if (limit - p < 3) { *p++ = 0x90; break; }
                *p++ = 0x48;
                *p++ = 0x89;
                *p++ = 0xC0;
                i += 2;
                break;
            }
        }
    }

    inline uint8_t* build_call_stub(uint32_t encrypted_ssn,
                                     uint32_t ssn_mask,
                                     uint64_t syscall_insn_va,
                                     uint8_t* page)
    {
        uint8_t* p = page;
        uint8_t* limit = page + 4096;

        uint32_t pre_pad = (random_byte() & 0xF) + 1;
        emit_random_padding(p, limit, pre_pad);

        *p++ = 0x4C; *p++ = 0x8B; *p++ = 0xD1;

        *p++ = 0xB8;
        std::memcpy(p, &encrypted_ssn, 4);
        p += 4;

        *p++ = 0x35;
        std::memcpy(p, &ssn_mask, 4);
        p += 4;

        uint32_t mid_pad = (random_byte() & 0x7) + 1;
        emit_random_padding(p, limit, mid_pad);

        *p++ = 0x49; *p++ = 0xBB;
        std::memcpy(p, &syscall_insn_va, 8);
        p += 8;

        uint32_t late_pad = (random_byte() & 0x3) + 1;
        emit_random_padding(p, limit, late_pad);

        *p++ = 0x41; *p++ = 0xFF; *p++ = 0xE3;

        uint32_t tail_pad = (random_byte() & 0x7) + 1;
        emit_random_padding(p, limit, tail_pad);

        return page;
    }

    inline uint8_t* commit_executable(uint8_t* page)
    {
        DWORD old = 0;
        if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old))
            return nullptr;
        FlushInstructionCache(GetCurrentProcess(), page, 4096);
        return page;
    }

    inline void free_stub_page(uint8_t* page)
    {
        if (page) VirtualFree(page, 0, MEM_RELEASE);
    }

    inline bool resolve_slot(uint32_t entry_id, const char* func_name)
    {
        auto& t = table();
        if (entry_id >= kSlotCount) return false;

        uint64_t fn_va = 0;
        uint64_t insn_va = 0;
        if (!resolve_ntdll_function(func_name, fn_va, insn_va))
            return false;

        uint32_t ssn = 0xFFFFFFFFu;
        if (!extract_ssn(reinterpret_cast<const uint8_t*>(fn_va), ssn))
            return false;

        slot_t& s = t.slots[entry_id];
        s.function_va = fn_va;
        s.syscall_insn_va = insn_va;
        mac_for_slot(t.pipeline_key, entry_id, s.hmac_anchor);
        std::memcpy(&s.ssn_mask, s.hmac_anchor, 4);
        s.ssn_xor = ssn ^ s.ssn_mask;
        return true;
    }

    inline bool fetch_slot(uint32_t entry_id, slot_t& out)
    {
        auto& t = table();
        if (!t.initialized.load(std::memory_order_acquire)) return false;
        if (entry_id >= kSlotCount) return false;
        out = t.slots[entry_id];
        return out.syscall_insn_va != 0;
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

using NtOpenProcessToken_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);

using NtOpenThreadToken_t = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle);

using NtAdjustPrivilegesToken_t = NTSTATUS(NTAPI*)(
    HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);

using RtlAdjustPrivilege_t = NTSTATUS(NTAPI*)(
    ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);

using NtSuspendProcess_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle);

using NtResumeProcess_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle);

using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect,
    PULONG OldProtect);

using NtGetContextThread_t = NTSTATUS(NTAPI*)(
    HANDLE ThreadHandle, CONTEXT* Context);

using NtReadVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead);

using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten);

using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect);

using NtFreeVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

using NtOpenProcess_t = NTSTATUS(NTAPI*)(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId);

using NtCreateFile_t = NTSTATUS(NTAPI*)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock,
    LARGE_INTEGER* AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

namespace detail {

    template <typename Fn>
    __forceinline NTSTATUS run_call(uint32_t entry_id, Fn&& invoker)
    {
        slot_t s{};
        if (!fetch_slot(entry_id, s))
            return static_cast<NTSTATUS>(0xC0000225L);

        uint8_t* page = alloc_rwx_page();
        if (!page) return static_cast<NTSTATUS>(0xC0000017L);

        uint32_t fresh_mask = random_u32();
        uint32_t real_ssn = s.ssn_xor ^ s.ssn_mask;
        uint32_t reencrypted = real_ssn ^ fresh_mask;

        build_call_stub(reencrypted, fresh_mask, s.syscall_insn_va, page);
        uint8_t* code = commit_executable(page);
        if (!code)
        {
            free_stub_page(page);
            return static_cast<NTSTATUS>(0xC0000022L);
        }

        NTSTATUS rc = invoker(code);

        DWORD old = 0;
        VirtualProtect(page, 4096, PAGE_READWRITE, &old);
        SecureZeroMemory(page, 4096);
        free_stub_page(page);
        return rc;
    }

}

inline bool initialize()
{
    auto& t = detail::table();
    std::lock_guard<std::mutex> lk(t.init_mtx);
    if (t.initialized.load(std::memory_order_acquire)) return true;

    if (!detail::derive_pipeline_key(t.pipeline_key))
        return false;

    HMODULE mod = GetModuleHandleW(L"ntdll.dll");
    if (!mod) return false;
    auto* base = reinterpret_cast<uint8_t*>(mod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    t.ntdll_base = reinterpret_cast<uint64_t>(base);
    t.ntdll_size = nt->OptionalHeader.SizeOfImage;

    bool ok = true;
    ok &= detail::resolve_slot(detail::kEntryNtQueryInformationProcess, "NtQueryInformationProcess");
    ok &= detail::resolve_slot(detail::kEntryNtQuerySystemInformation,  "NtQuerySystemInformation");
    ok &= detail::resolve_slot(detail::kEntryNtQueryVirtualMemory,      "NtQueryVirtualMemory");
    ok &= detail::resolve_slot(detail::kEntryNtSetInformationThread,    "NtSetInformationThread");
    ok &= detail::resolve_slot(detail::kEntryNtQueryInformationThread,  "NtQueryInformationThread");
    ok &= detail::resolve_slot(detail::kEntryNtClose,                   "NtClose");
    ok &= detail::resolve_slot(detail::kEntryNtRaiseHardError,          "NtRaiseHardError");
    ok &= detail::resolve_slot(detail::kEntryNtOpenProcessToken,        "NtOpenProcessToken");
    ok &= detail::resolve_slot(detail::kEntryNtOpenThreadToken,         "NtOpenThreadToken");
    ok &= detail::resolve_slot(detail::kEntryNtAdjustPrivilegesToken,   "NtAdjustPrivilegesToken");
    ok &= detail::resolve_slot(detail::kEntryNtSuspendProcess,          "NtSuspendProcess");
    ok &= detail::resolve_slot(detail::kEntryNtResumeProcess,           "NtResumeProcess");
    ok &= detail::resolve_slot(detail::kEntryNtProtectVirtualMemory,    "NtProtectVirtualMemory");
    ok &= detail::resolve_slot(detail::kEntryNtGetContextThread,        "NtGetContextThread");
    ok &= detail::resolve_slot(detail::kEntryNtReadVirtualMemory,       "NtReadVirtualMemory");
    ok &= detail::resolve_slot(detail::kEntryNtWriteVirtualMemory,      "NtWriteVirtualMemory");
    ok &= detail::resolve_slot(detail::kEntryNtAllocateVirtualMemory,   "NtAllocateVirtualMemory");
    ok &= detail::resolve_slot(detail::kEntryNtFreeVirtualMemory,       "NtFreeVirtualMemory");
    ok &= detail::resolve_slot(detail::kEntryNtOpenProcess,             "NtOpenProcess");
    ok &= detail::resolve_slot(detail::kEntryNtCreateFile,              "NtCreateFile");

    t.initialized.store(ok, std::memory_order_release);
    return ok;
}

inline bool is_initialized()
{
    return detail::table().initialized.load(std::memory_order_acquire);
}

inline NTSTATUS call_NtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    return detail::run_call(detail::kEntryNtQueryInformationProcess,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtQueryInformationProcess_t>(code);
            return fn(ProcessHandle, ProcessInformationClass,
                      ProcessInformation, ProcessInformationLength,
                      ReturnLength);
        });
}

inline NTSTATUS call_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    return detail::run_call(detail::kEntryNtQuerySystemInformation,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtQuerySystemInformation_t>(code);
            return fn(SystemInformationClass, SystemInformation,
                      SystemInformationLength, ReturnLength);
        });
}

inline NTSTATUS call_NtQueryVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, ULONG MemoryInformationClass,
    PVOID MemoryInformation, SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength)
{
    return detail::run_call(detail::kEntryNtQueryVirtualMemory,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtQueryVirtualMemory_t>(code);
            return fn(ProcessHandle, BaseAddress, MemoryInformationClass,
                      MemoryInformation, MemoryInformationLength,
                      ReturnLength);
        });
}

inline NTSTATUS call_NtSetInformationThread(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    return detail::run_call(detail::kEntryNtSetInformationThread,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtSetInformationThread_t>(code);
            return fn(ThreadHandle, ThreadInformationClass,
                      ThreadInformation, ThreadInformationLength);
        });
}

inline NTSTATUS call_NtQueryInformationThread(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength)
{
    return detail::run_call(detail::kEntryNtQueryInformationThread,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtQueryInformationThread_t>(code);
            return fn(ThreadHandle, ThreadInformationClass,
                      ThreadInformation, ThreadInformationLength,
                      ReturnLength);
        });
}

inline NTSTATUS call_NtClose(HANDLE Handle)
{
    return detail::run_call(detail::kEntryNtClose,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtClose_t>(code);
            return fn(Handle);
        });
}

inline NTSTATUS call_NtRaiseHardError(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask, PULONG_PTR Parameters,
    ULONG ValidResponseOption, PULONG Response)
{
    return detail::run_call(detail::kEntryNtRaiseHardError,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtRaiseHardError_t>(code);
            return fn(ErrorStatus, NumberOfParameters,
                      UnicodeStringParameterMask, Parameters,
                      ValidResponseOption, Response);
        });
}

inline NTSTATUS call_NtOpenProcessToken(
    HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle)
{
    return detail::run_call(detail::kEntryNtOpenProcessToken,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtOpenProcessToken_t>(code);
            return fn(ProcessHandle, DesiredAccess, TokenHandle);
        });
}

inline NTSTATUS call_NtOpenThreadToken(
    HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf,
    PHANDLE TokenHandle)
{
    return detail::run_call(detail::kEntryNtOpenThreadToken,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtOpenThreadToken_t>(code);
            return fn(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
        });
}

inline NTSTATUS call_NtAdjustPrivilegesToken(
    HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength)
{
    return detail::run_call(detail::kEntryNtAdjustPrivilegesToken,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtAdjustPrivilegesToken_t>(code);
            return fn(TokenHandle, DisableAllPrivileges, NewState, BufferLength,
                      PreviousState, ReturnLength);
        });
}

inline NTSTATUS call_RtlAdjustPrivilege(
    ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled)
{
    if (WasEnabled)
        *WasEnabled = FALSE;

    HANDLE token = nullptr;
    ACCESS_MASK access = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    NTSTATUS status = Client
        ? call_NtOpenThreadToken(GetCurrentThread(), access, TRUE, &token)
        : call_NtOpenProcessToken(GetCurrentProcess(), access, &token);
    if (status < 0)
        return status;

    TOKEN_PRIVILEGES requested{};
    requested.PrivilegeCount = 1;
    requested.Privileges[0].Luid.LowPart = Privilege;
    requested.Privileges[0].Luid.HighPart = 0;
    requested.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

    TOKEN_PRIVILEGES previous{};
    ULONG previous_len = 0;
    status = call_NtAdjustPrivilegesToken(
        token,
        FALSE,
        &requested,
        sizeof(previous),
        &previous,
        &previous_len);

    if (WasEnabled && status >= 0 && previous.PrivilegeCount != 0)
        *WasEnabled = (previous.Privileges[0].Attributes & SE_PRIVILEGE_ENABLED) ? TRUE : FALSE;

    NTSTATUS close_status = call_NtClose(token);
    if (status >= 0 && close_status < 0)
        return close_status;
    return status;
}

inline NTSTATUS call_NtSuspendProcess(HANDLE ProcessHandle)
{
    return detail::run_call(detail::kEntryNtSuspendProcess,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtSuspendProcess_t>(code);
            return fn(ProcessHandle);
        });
}

inline NTSTATUS call_NtResumeProcess(HANDLE ProcessHandle)
{
    return detail::run_call(detail::kEntryNtResumeProcess,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtResumeProcess_t>(code);
            return fn(ProcessHandle);
        });
}

inline NTSTATUS call_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect,
    PULONG OldProtect)
{
    return detail::run_call(detail::kEntryNtProtectVirtualMemory,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtProtectVirtualMemory_t>(code);
            return fn(ProcessHandle, BaseAddress, RegionSize,
                      NewProtect, OldProtect);
        });
}

inline NTSTATUS call_NtGetContextThread(
    HANDLE ThreadHandle, CONTEXT* Context)
{
    return detail::run_call(detail::kEntryNtGetContextThread,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtGetContextThread_t>(code);
            return fn(ThreadHandle, Context);
        });
}

inline NTSTATUS call_NtReadVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesRead)
{
    return detail::run_call(detail::kEntryNtReadVirtualMemory,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtReadVirtualMemory_t>(code);
            return fn(ProcessHandle, BaseAddress, Buffer, Size, BytesRead);
        });
}

inline NTSTATUS call_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T Size, PSIZE_T BytesWritten)
{
    return detail::run_call(detail::kEntryNtWriteVirtualMemory,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtWriteVirtualMemory_t>(code);
            return fn(ProcessHandle, BaseAddress, Buffer, Size, BytesWritten);
        });
}

inline NTSTATUS call_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize,
    ULONG AllocationType, ULONG Protect)
{
    return detail::run_call(detail::kEntryNtAllocateVirtualMemory,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtAllocateVirtualMemory_t>(code);
            return fn(ProcessHandle, BaseAddress, ZeroBits,
                      RegionSize, AllocationType, Protect);
        });
}

inline NTSTATUS call_NtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType)
{
    return detail::run_call(detail::kEntryNtFreeVirtualMemory,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtFreeVirtualMemory_t>(code);
            return fn(ProcessHandle, BaseAddress, RegionSize, FreeType);
        });
}

inline NTSTATUS call_NtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId)
{
    return detail::run_call(detail::kEntryNtOpenProcess,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtOpenProcess_t>(code);
            return fn(ProcessHandle, DesiredAccess,
                      ObjectAttributes, ClientId);
        });
}

inline NTSTATUS call_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID IoStatusBlock,
    LARGE_INTEGER* AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition,
    ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    return detail::run_call(detail::kEntryNtCreateFile,
        [&](uint8_t* code) -> NTSTATUS {
            auto fn = reinterpret_cast<NtCreateFile_t>(code);
            return fn(FileHandle, DesiredAccess, ObjectAttributes,
                      IoStatusBlock, AllocationSize, FileAttributes,
                      ShareAccess, CreateDisposition,
                      CreateOptions, EaBuffer, EaLength);
        });
}

namespace adapters {

    inline NTSTATUS NTAPI adapter_NtQueryInformationProcess(
        HANDLE h, ULONG c, PVOID i, ULONG l, PULONG r)
    {
        return call_NtQueryInformationProcess(h, c, i, l, r);
    }

    inline NTSTATUS NTAPI adapter_NtQuerySystemInformation(
        ULONG c, PVOID i, ULONG l, PULONG r)
    {
        return call_NtQuerySystemInformation(c, i, l, r);
    }

    inline NTSTATUS NTAPI adapter_NtQueryVirtualMemory(
        HANDLE h, PVOID b, ULONG c, PVOID i, SIZE_T l, PSIZE_T r)
    {
        return call_NtQueryVirtualMemory(h, b, c, i, l, r);
    }

    inline NTSTATUS NTAPI adapter_NtSetInformationThread(
        HANDLE h, ULONG c, PVOID i, ULONG l)
    {
        return call_NtSetInformationThread(h, c, i, l);
    }

    inline NTSTATUS NTAPI adapter_NtQueryInformationThread(
        HANDLE h, ULONG c, PVOID i, ULONG l, PULONG r)
    {
        return call_NtQueryInformationThread(h, c, i, l, r);
    }

    inline NTSTATUS NTAPI adapter_NtClose(HANDLE h)
    {
        return call_NtClose(h);
    }

    inline NTSTATUS NTAPI adapter_NtRaiseHardError(
        NTSTATUS s, ULONG n, ULONG m, PULONG_PTR p, ULONG o, PULONG r)
    {
        return call_NtRaiseHardError(s, n, m, p, o, r);
    }

    inline NTSTATUS NTAPI adapter_RtlAdjustPrivilege(
        ULONG p, BOOLEAN e, BOOLEAN c, PBOOLEAN w)
    {
        return call_RtlAdjustPrivilege(p, e, c, w);
    }

    inline NTSTATUS NTAPI adapter_NtSuspendProcess(HANDLE h)
    {
        return call_NtSuspendProcess(h);
    }

    inline NTSTATUS NTAPI adapter_NtResumeProcess(HANDLE h)
    {
        return call_NtResumeProcess(h);
    }

    inline NTSTATUS NTAPI adapter_NtProtectVirtualMemory(
        HANDLE h, PVOID* ba, PSIZE_T rs, ULONG np, PULONG op)
    {
        return call_NtProtectVirtualMemory(h, ba, rs, np, op);
    }

    inline NTSTATUS NTAPI adapter_NtGetContextThread(
        HANDLE h, CONTEXT* c)
    {
        return call_NtGetContextThread(h, c);
    }

    inline NTSTATUS NTAPI adapter_NtReadVirtualMemory(
        HANDLE h, PVOID ba, PVOID buf, SIZE_T sz, PSIZE_T br)
    {
        return call_NtReadVirtualMemory(h, ba, buf, sz, br);
    }

    inline NTSTATUS NTAPI adapter_NtWriteVirtualMemory(
        HANDLE h, PVOID ba, PVOID buf, SIZE_T sz, PSIZE_T bw)
    {
        return call_NtWriteVirtualMemory(h, ba, buf, sz, bw);
    }

    inline NTSTATUS NTAPI adapter_NtAllocateVirtualMemory(
        HANDLE h, PVOID* ba, ULONG_PTR z, PSIZE_T rs,
        ULONG at, ULONG p)
    {
        return call_NtAllocateVirtualMemory(h, ba, z, rs, at, p);
    }

    inline NTSTATUS NTAPI adapter_NtFreeVirtualMemory(
        HANDLE h, PVOID* ba, PSIZE_T rs, ULONG ft)
    {
        return call_NtFreeVirtualMemory(h, ba, rs, ft);
    }

    inline NTSTATUS NTAPI adapter_NtOpenProcess(
        PHANDLE h, ACCESS_MASK da, PVOID oa, PVOID ci)
    {
        return call_NtOpenProcess(h, da, oa, ci);
    }

    inline NTSTATUS NTAPI adapter_NtCreateFile(
        PHANDLE h, ACCESS_MASK da, PVOID oa, PVOID iosb,
        LARGE_INTEGER* as, ULONG fa, ULONG sa, ULONG cd,
        ULONG co, PVOID ea, ULONG eal)
    {
        return call_NtCreateFile(h, da, oa, iosb, as, fa, sa, cd, co, ea, eal);
    }

}

inline NtQueryInformationProcess_t NtQueryInformationProcess()
{
    return &adapters::adapter_NtQueryInformationProcess;
}

inline NtQuerySystemInformation_t NtQuerySystemInformation()
{
    return &adapters::adapter_NtQuerySystemInformation;
}

inline NtQueryVirtualMemory_t NtQueryVirtualMemory()
{
    return &adapters::adapter_NtQueryVirtualMemory;
}

inline NtSetInformationThread_t NtSetInformationThread()
{
    return &adapters::adapter_NtSetInformationThread;
}

inline NtQueryInformationThread_t NtQueryInformationThread()
{
    return &adapters::adapter_NtQueryInformationThread;
}

inline NtClose_t NtClose()
{
    return &adapters::adapter_NtClose;
}

inline NtRaiseHardError_t NtRaiseHardError()
{
    return &adapters::adapter_NtRaiseHardError;
}

inline RtlAdjustPrivilege_t RtlAdjustPrivilege()
{
    return &adapters::adapter_RtlAdjustPrivilege;
}

inline NtSuspendProcess_t NtSuspendProcess()
{
    return &adapters::adapter_NtSuspendProcess;
}

inline NtResumeProcess_t NtResumeProcess()
{
    return &adapters::adapter_NtResumeProcess;
}

inline NtProtectVirtualMemory_t NtProtectVirtualMemory()
{
    return &adapters::adapter_NtProtectVirtualMemory;
}

inline NtGetContextThread_t NtGetContextThread()
{
    return &adapters::adapter_NtGetContextThread;
}

inline NtReadVirtualMemory_t NtReadVirtualMemory()
{
    return &adapters::adapter_NtReadVirtualMemory;
}

inline NtWriteVirtualMemory_t NtWriteVirtualMemory()
{
    return &adapters::adapter_NtWriteVirtualMemory;
}

inline NtAllocateVirtualMemory_t NtAllocateVirtualMemory()
{
    return &adapters::adapter_NtAllocateVirtualMemory;
}

inline NtFreeVirtualMemory_t NtFreeVirtualMemory()
{
    return &adapters::adapter_NtFreeVirtualMemory;
}

inline NtOpenProcess_t NtOpenProcess()
{
    return &adapters::adapter_NtOpenProcess;
}

inline NtCreateFile_t NtCreateFile()
{
    return &adapters::adapter_NtCreateFile;
}

namespace detail {

    inline bool inline_redirect_bytes(const uint8_t* bytes)
    {
        __try
        {
            if (bytes[0] == 0xE9 || bytes[0] == 0xEB || bytes[0] == 0xCC)
                return true;
            if (bytes[0] == 0xFF && bytes[1] == 0x25)
                return true;
            if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0)
                return true;
            if (bytes[0] == 0x68 && bytes[5] == 0xC3)
                return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return false;
    }

    inline bool standard_x64_syscall_stub_bytes(const uint8_t* bytes)
    {
        __try
        {
            return bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
                   bytes[3] == 0xB8;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    inline bool nt_export_name(const char* name)
    {
        return name && name[0] == 'N' && name[1] == 't';
    }

    inline const char* memory_type_name(DWORD type)
    {
        if (type == MEM_IMAGE) return "image";
        if (type == MEM_MAPPED) return "mapped";
        if (type == MEM_PRIVATE) return "private";
        return "unknown";
    }

    inline bool writable_protection(DWORD protect)
    {
        DWORD p = protect & 0xFFu;
        return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
    }

    inline bool path_prefix_i(const wchar_t* path, const wchar_t* prefix)
    {
        if (!path || !prefix || !*path || !*prefix) return false;
        size_t prefix_len = wcslen(prefix);
        if (prefix_len == 0) return false;
        if (CompareStringOrdinal(path, static_cast<int>(prefix_len),
                                 prefix, static_cast<int>(prefix_len), TRUE) != CSTR_EQUAL)
            return false;
        wchar_t ch = path[prefix_len];
        return ch == L'\0' || ch == L'\\' || ch == L'/';
    }

    inline bool append_child_path(wchar_t* out, size_t out_count, const wchar_t* base, const wchar_t* child)
    {
        if (!out || out_count == 0 || !base || !child) return false;
        out[0] = L'\0';
        return wcscpy_s(out, out_count, base) == 0 &&
               wcscat_s(out, out_count, L"\\") == 0 &&
               wcscat_s(out, out_count, child) == 0;
    }

    inline bool system_image_module_path(const wchar_t* path)
    {
        if (!path || !*path) return false;

        wchar_t system_dir[MAX_PATH]{};
        if (GetSystemDirectoryW(system_dir, MAX_PATH) != 0 &&
            path_prefix_i(path, system_dir))
            return true;

        wchar_t wow64_dir[MAX_PATH]{};
        if (GetSystemWow64DirectoryW(wow64_dir, MAX_PATH) != 0 &&
            path_prefix_i(path, wow64_dir))
            return true;

        wchar_t windows_dir[MAX_PATH]{};
        if (GetWindowsDirectoryW(windows_dir, MAX_PATH) == 0)
            return false;

        wchar_t winsxs_dir[MAX_PATH]{};
        if (append_child_path(winsxs_dir, MAX_PATH, windows_dir, L"WinSxS") &&
            path_prefix_i(path, winsxs_dir))
            return true;

        return false;
    }

    inline void narrow_path(const wchar_t* src, char* out, size_t out_count)
    {
        if (!out || out_count == 0) return;
        out[0] = '\0';
        if (!src || !*src) return;
        int written = WideCharToMultiByte(CP_UTF8, 0, src, -1,
                                          out, static_cast<int>(out_count),
                                          nullptr, nullptr);
        if (written <= 0)
            out[0] = '\0';
        else
            out[out_count - 1] = '\0';
    }

    inline uint32_t image_size_from_base(const uint8_t* base)
    {
        if (!base) return 0;
        __try
        {
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
            return nt->OptionalHeader.SizeOfImage;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    inline void hex16(const uint8_t* bytes, char out[49])
    {
        static constexpr char kHex[] = "0123456789ABCDEF";
        for (size_t i = 0; i < 16; ++i)
        {
            uint8_t v = 0;
            __try
            {
                v = bytes[i];
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                v = 0;
            }
            out[i * 3] = kHex[v >> 4];
            out[i * 3 + 1] = kHex[v & 0x0F];
            out[i * 3 + 2] = (i == 15) ? '\0' : ' ';
        }
        out[48] = '\0';
    }

    inline uint64_t fnv1a_bytes(const void* data, size_t len)
    {
        uint64_t h = 14695981039346656037ULL;
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < len; ++i)
        {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
        return h;
    }

    inline void bytes_to_hex(const uint8_t* bytes, size_t len, char* out, size_t out_count)
    {
        static constexpr char kHex[] = "0123456789ABCDEF";
        if (!out || out_count == 0) return;
        out[0] = '\0';
        if (!bytes || out_count < len * 2 + 1) return;
        for (size_t i = 0; i < len; ++i)
        {
            out[i * 2] = kHex[bytes[i] >> 4];
            out[i * 2 + 1] = kHex[bytes[i] & 0x0F];
        }
        out[len * 2] = '\0';
    }

    inline bool sha256_hex_bytes(const uint8_t* data, size_t len, char out[65], DWORD& gle)
    {
        out[0] = '\0';
        gle = ERROR_SUCCESS;
        if (!data && len != 0) {
            gle = ERROR_INVALID_ADDRESS;
            return false;
        }
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (st != 0) {
            gle = static_cast<DWORD>(st);
            return false;
        }
        DWORD object_len = 0;
        DWORD cb = 0;
        st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_len),
                               sizeof(object_len), &cb, 0);
        if (st != 0 || object_len == 0) {
            gle = st != 0 ? static_cast<DWORD>(st) : ERROR_INVALID_DATA;
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }
        std::vector<UCHAR> object(object_len);
        st = BCryptCreateHash(alg, &hash, object.data(), object_len, nullptr, 0, 0);
        if (st == 0 && data && len != 0)
            st = BCryptHashData(hash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data)), static_cast<ULONG>(len), 0);
        uint8_t digest[32]{};
        if (st == 0)
            st = BCryptFinishHash(hash, digest, sizeof(digest), 0);
        if (hash)
            BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (st != 0) {
            gle = static_cast<DWORD>(st);
            return false;
        }
        bytes_to_hex(digest, sizeof(digest), out, 65);
        return true;
    }

    inline bool sha256_hex_memory16(const uint8_t* data, char out[65], DWORD& gle)
    {
        uint8_t local[16]{};
        __try
        {
            memcpy(local, data, sizeof(local));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out[0] = '\0';
            gle = GetExceptionCode();
            return false;
        }
        return sha256_hex_bytes(local, sizeof(local), out, gle);
    }

    inline bool sha256_hex_file(HANDLE hFile, char out[65], DWORD& gle)
    {
        out[0] = '\0';
        gle = ERROR_SUCCESS;
        if (hFile == INVALID_HANDLE_VALUE || !hFile) {
            gle = ERROR_INVALID_HANDLE;
            return false;
        }
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN)) {
            gle = GetLastError();
            return false;
        }
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (st != 0) {
            gle = static_cast<DWORD>(st);
            return false;
        }
        DWORD object_len = 0;
        DWORD cb = 0;
        st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_len),
                               sizeof(object_len), &cb, 0);
        if (st != 0 || object_len == 0) {
            gle = st != 0 ? static_cast<DWORD>(st) : ERROR_INVALID_DATA;
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }
        std::vector<UCHAR> object(object_len);
        st = BCryptCreateHash(alg, &hash, object.data(), object_len, nullptr, 0, 0);
        std::vector<uint8_t> buf(64 * 1024);
        while (st == 0)
        {
            DWORD read = 0;
            if (!ReadFile(hFile, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr)) {
                gle = GetLastError();
                st = static_cast<NTSTATUS>(0xC0000001L);
                break;
            }
            if (read == 0)
                break;
            st = BCryptHashData(hash, buf.data(), read, 0);
        }
        uint8_t digest[32]{};
        if (st == 0)
            st = BCryptFinishHash(hash, digest, sizeof(digest), 0);
        if (hash)
            BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);
        if (st != 0) {
            if (gle == ERROR_SUCCESS)
                gle = static_cast<DWORD>(st);
            return false;
        }
        bytes_to_hex(digest, sizeof(digest), out, 65);
        return true;
    }

    struct image_identity_t
    {
        bool opened = false;
        bool basic_ok = false;
        bool file_id_ok = false;
        bool hash_ok = false;
        bool trust_checked = false;
        bool trust_ok = false;
        bool signer_checked = false;
        bool signer_ok = false;
        DWORD open_error = ERROR_SUCCESS;
        DWORD basic_error = ERROR_SUCCESS;
        DWORD file_id_error = ERROR_SUCCESS;
        DWORD hash_error = ERROR_SUCCESS;
        DWORD signer_error = ERROR_SUCCESS;
        LONG trust_status = 0;
        DWORD volume_serial = 0;
        DWORD file_index_high = 0;
        DWORD file_index_low = 0;
        ULONGLONG file_size = 0;
        ULONGLONG last_write_ft = 0;
        uint64_t file_id_hash = 0;
        uint64_t signer_subject_hash = 0;
        uint64_t signer_issuer_hash = 0;
        char file_sha256[65]{};
        char signer_subject[192]{};
        char signer_issuer[192]{};
    };

    inline void collect_signer_identity(const wchar_t* path, image_identity_t& id)
    {
        id.signer_checked = true;
        HCERTSTORE store = nullptr;
        HCRYPTMSG msg = nullptr;
        DWORD encoding = 0;
        DWORD content_type = 0;
        DWORD format_type = 0;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                              CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                              &encoding, &content_type, &format_type,
                              &store, &msg, nullptr)) {
            id.signer_error = GetLastError();
            return;
        }
        DWORD signer_size = 0;
        if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_size) || signer_size == 0) {
            id.signer_error = GetLastError();
            if (msg) CryptMsgClose(msg);
            if (store) CertCloseStore(store, 0);
            return;
        }
        std::vector<uint8_t> signer_buf(signer_size);
        if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, signer_buf.data(), &signer_size)) {
            id.signer_error = GetLastError();
            if (msg) CryptMsgClose(msg);
            if (store) CertCloseStore(store, 0);
            return;
        }
        auto* signer_info = reinterpret_cast<PCMSG_SIGNER_INFO>(signer_buf.data());
        CERT_INFO cert_info{};
        cert_info.Issuer = signer_info->Issuer;
        cert_info.SerialNumber = signer_info->SerialNumber;
        PCCERT_CONTEXT cert = CertFindCertificateInStore(store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_CERT, &cert_info, nullptr);
        if (!cert) {
            id.signer_error = GetLastError();
            if (msg) CryptMsgClose(msg);
            if (store) CertCloseStore(store, 0);
            return;
        }
        wchar_t subject_w[256]{};
        wchar_t issuer_w[256]{};
        DWORD subject_len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject_w, 256);
        DWORD issuer_len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issuer_w, 256);
        if (subject_len > 1) {
            narrow_path(subject_w, id.signer_subject, sizeof(id.signer_subject));
            id.signer_subject_hash = fnv1a_bytes(subject_w, (subject_len - 1) * sizeof(wchar_t));
        }
        if (issuer_len > 1) {
            narrow_path(issuer_w, id.signer_issuer, sizeof(id.signer_issuer));
            id.signer_issuer_hash = fnv1a_bytes(issuer_w, (issuer_len - 1) * sizeof(wchar_t));
        }
        id.signer_ok = subject_len > 1;
        id.signer_error = id.signer_ok ? ERROR_SUCCESS : ERROR_NOT_FOUND;
        CertFreeCertificateContext(cert);
        if (msg) CryptMsgClose(msg);
        if (store) CertCloseStore(store, 0);
    }

    inline LONG verify_file_trust_status(const wchar_t* path, bool& checked)
    {
        checked = false;
        if (!path || !*path)
            return static_cast<LONG>(ERROR_PATH_NOT_FOUND);
        WINTRUST_FILE_INFO file_info{};
        file_info.cbStruct = sizeof(file_info);
        file_info.pcwszFilePath = path;
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA data{};
        data.cbStruct = sizeof(data);
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.pFile = &file_info;
        data.dwStateAction = WTD_STATEACTION_VERIFY;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
        checked = true;
        LONG status = WinVerifyTrust(nullptr, &action, &data);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &data);
        return status;
    }

    inline image_identity_t collect_image_identity(const wchar_t* path)
    {
        image_identity_t id{};
        if (!path || !*path) {
            id.open_error = ERROR_PATH_NOT_FOUND;
            return id;
        }
        HANDLE h = CreateFileW(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            id.open_error = GetLastError();
        } else {
            id.opened = true;
            BY_HANDLE_FILE_INFORMATION basic{};
            if (GetFileInformationByHandle(h, &basic)) {
                id.basic_ok = true;
                id.volume_serial = basic.dwVolumeSerialNumber;
                id.file_index_high = basic.nFileIndexHigh;
                id.file_index_low = basic.nFileIndexLow;
                id.file_size = (static_cast<ULONGLONG>(basic.nFileSizeHigh) << 32) | basic.nFileSizeLow;
                id.last_write_ft = (static_cast<ULONGLONG>(basic.ftLastWriteTime.dwHighDateTime) << 32) |
                    basic.ftLastWriteTime.dwLowDateTime;
            } else {
                id.basic_error = GetLastError();
            }
            FILE_ID_INFO file_id{};
            if (GetFileInformationByHandleEx(h, FileIdInfo, &file_id, sizeof(file_id))) {
                id.file_id_ok = true;
                id.file_id_hash = fnv1a_bytes(&file_id, sizeof(file_id));
            } else {
                id.file_id_error = GetLastError();
                if (id.basic_ok) {
                    uint64_t fallback[3] = {
                        id.volume_serial,
                        (static_cast<uint64_t>(id.file_index_high) << 32) | id.file_index_low,
                        id.file_size
                    };
                    id.file_id_hash = fnv1a_bytes(fallback, sizeof(fallback));
                }
            }
            id.hash_ok = sha256_hex_file(h, id.file_sha256, id.hash_error);
            CloseHandle(h);
        }
        id.trust_status = verify_file_trust_status(path, id.trust_checked);
        id.trust_ok = id.trust_checked && id.trust_status == ERROR_SUCCESS;
        collect_signer_identity(path, id);
        return id;
    }

    inline bool basename_equals_i(const wchar_t* path, const wchar_t* expected)
    {
        if (!path || !expected || !*path || !*expected)
            return false;
        const wchar_t* name = wcsrchr(path, L'\\');
        const wchar_t* slash = wcsrchr(path, L'/');
        if (slash && (!name || slash > name))
            name = slash;
        name = name ? name + 1 : path;
        return CompareStringOrdinal(name, -1, expected, -1, TRUE) == CSTR_EQUAL;
    }

    inline void log_nt_export_wrapper_diag(
        const char* tag,
        const char* marker,
        const char* func_name,
        const uint8_t* wrapper_bytes,
        const uint8_t* disk_bytes,
        uint64_t mem_va,
        uint64_t mem_rva,
        uint64_t disk_rva,
        SIZE_T vq,
        const MEMORY_BASIC_INFORMATION& mbi,
        bool mem_writable,
        bool mem_redirect,
        bool disk_redirect,
        bool mem_syscall,
        bool disk_syscall,
        bool is_nt_export,
        BOOL owner_ok,
        uint64_t owner_base,
        uint32_t owner_size,
        uint64_t owner_rva,
        bool owner_system,
        const wchar_t* owner_path_w,
        const char* owner_path,
        bool allow)
    {
        char wrapper_hash[65]{};
        char disk_hash[65]{};
        DWORD wrapper_hash_error = ERROR_SUCCESS;
        DWORD disk_hash_error = ERROR_SUCCESS;
        const bool wrapper_hash_ok = sha256_hex_memory16(wrapper_bytes, wrapper_hash, wrapper_hash_error);
        const bool disk_hash_ok = sha256_hex_memory16(disk_bytes, disk_hash, disk_hash_error);
        image_identity_t image = collect_image_identity(owner_path_w);
        const bool committed = vq != 0 && mbi.State == MEM_COMMIT;
        const bool image_type = vq != 0 && mbi.Type == MEM_IMAGE;
        const bool non_writable = vq != 0 && !mem_writable;
        const bool non_redirecting = !mem_redirect;
        const bool apphelp_exact = owner_system && basename_equals_i(owner_path_w, L"apphelp.dll");
        webhook::write_log_critical_fmt(tag ? tag : "runtime_integrity",
            "%s func=%s allow=%d criteria_nt_export=%d criteria_disk_syscall=%d criteria_committed=%d criteria_mem_image=%d criteria_non_writable=%d criteria_non_redirecting=%d criteria_owner_ok=%d criteria_owner_system=%d apphelp_exact=%d mem_va=0x%llX mem_rva=0x%llX disk_rva=0x%llX owner_base=0x%llX owner_size=0x%lX owner_rva=0x%llX vq=%llu protect=0x%lX state=0x%lX type=0x%lX type_name=%s mem_writable=%d mem_redirect=%d disk_redirect=%d mem_syscall=%d disk_syscall=%d wrapper_hash_ok=%d wrapper_sha256=%s wrapper_hash_error=0x%08lX disk_hash_ok=%d disk_sha256=%s disk_hash_error=0x%08lX image_open=%d image_open_error=%lu image_basic=%d image_basic_error=%lu image_volume=0x%08lX image_index=0x%08lX%08lX image_size=%llu image_last_write=0x%016llX image_file_id_ok=%d image_file_id_error=%lu image_file_id_hash=0x%016llX image_hash_ok=%d image_hash_error=%lu image_sha256=%s signer_checked=%d signer_ok=%d signer_error=%lu signer_subject_hash=0x%016llX signer_issuer_hash=0x%016llX signer_subject='%.120s' signer_issuer='%.120s' trust_checked=%d trust_ok=%d trust_status=0x%08lX owner_path=%s",
            marker ? marker : "nt_export_wrapper_diag",
            func_name ? func_name : "?",
            allow ? 1 : 0,
            is_nt_export ? 1 : 0,
            disk_syscall ? 1 : 0,
            committed ? 1 : 0,
            image_type ? 1 : 0,
            non_writable ? 1 : 0,
            non_redirecting ? 1 : 0,
            owner_ok ? 1 : 0,
            owner_system ? 1 : 0,
            apphelp_exact ? 1 : 0,
            static_cast<unsigned long long>(mem_va),
            static_cast<unsigned long long>(mem_rva),
            static_cast<unsigned long long>(disk_rva),
            static_cast<unsigned long long>(owner_base),
            static_cast<unsigned long>(owner_size),
            static_cast<unsigned long long>(owner_rva),
            static_cast<unsigned long long>(vq),
            vq ? static_cast<unsigned long>(mbi.Protect) : 0ul,
            vq ? static_cast<unsigned long>(mbi.State) : 0ul,
            vq ? static_cast<unsigned long>(mbi.Type) : 0ul,
            vq ? memory_type_name(mbi.Type) : "none",
            mem_writable ? 1 : 0,
            mem_redirect ? 1 : 0,
            disk_redirect ? 1 : 0,
            mem_syscall ? 1 : 0,
            disk_syscall ? 1 : 0,
            wrapper_hash_ok ? 1 : 0,
            wrapper_hash_ok ? wrapper_hash : "<none>",
            static_cast<unsigned long>(wrapper_hash_error),
            disk_hash_ok ? 1 : 0,
            disk_hash_ok ? disk_hash : "<none>",
            static_cast<unsigned long>(disk_hash_error),
            image.opened ? 1 : 0,
            static_cast<unsigned long>(image.open_error),
            image.basic_ok ? 1 : 0,
            static_cast<unsigned long>(image.basic_error),
            static_cast<unsigned long>(image.volume_serial),
            static_cast<unsigned long>(image.file_index_high),
            static_cast<unsigned long>(image.file_index_low),
            static_cast<unsigned long long>(image.file_size),
            static_cast<unsigned long long>(image.last_write_ft),
            image.file_id_ok ? 1 : 0,
            static_cast<unsigned long>(image.file_id_error),
            static_cast<unsigned long long>(image.file_id_hash),
            image.hash_ok ? 1 : 0,
            static_cast<unsigned long>(image.hash_error),
            image.hash_ok ? image.file_sha256 : "<none>",
            image.signer_checked ? 1 : 0,
            image.signer_ok ? 1 : 0,
            static_cast<unsigned long>(image.signer_error),
            static_cast<unsigned long long>(image.signer_subject_hash),
            static_cast<unsigned long long>(image.signer_issuer_hash),
            image.signer_subject[0] ? image.signer_subject : "<none>",
            image.signer_issuer[0] ? image.signer_issuer : "<none>",
            image.trust_checked ? 1 : 0,
            image.trust_ok ? 1 : 0,
            static_cast<unsigned long>(image.trust_status),
            owner_path && owner_path[0] ? owner_path : "<none>");
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
        if (!mapped) { CloseHandle(hMap); CloseHandle(hFile); return false; }

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
                uint32_t names_off = rva_to_offset(exports->AddressOfNames);
                uint32_t funcs_off = rva_to_offset(exports->AddressOfFunctions);
                uint32_t ords_off  = rva_to_offset(exports->AddressOfNameOrdinals);
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
                    if (memcmp(mem_func, disk_bytes, 16) != 0)
                    {
                        const bool mem_redirect = inline_redirect_bytes(mem_func);
                        const bool disk_redirect = inline_redirect_bytes(disk_bytes);
                        const bool mem_syscall = standard_x64_syscall_stub_bytes(mem_func);
                        const bool disk_syscall = standard_x64_syscall_stub_bytes(disk_bytes);
                        const auto* mem_base = reinterpret_cast<const uint8_t*>(mem_ntdll);
                        uint32_t mem_image_size = image_size_from_base(mem_base);
                        uint64_t mem_va = reinterpret_cast<uint64_t>(mem_func);
                        uint64_t ntdll_base = reinterpret_cast<uint64_t>(mem_base);
                        uint64_t mem_rva = mem_va >= ntdll_base ? mem_va - ntdll_base : 0;
                        uint64_t disk_rva = func_rva;
                        bool rva_match = mem_rva == disk_rva;
                        bool in_ntdll_range = mem_image_size != 0 &&
                            mem_va >= ntdll_base &&
                            mem_va < ntdll_base + mem_image_size;
                        MEMORY_BASIC_INFORMATION mbi{};
                        SIZE_T vq = VirtualQuery(mem_func, &mbi, sizeof(mbi));
                        bool mem_writable = vq != 0 && writable_protection(mbi.Protect);
                        HMODULE owner_mod = nullptr;
                        BOOL owner_ok = GetModuleHandleExW(
                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(mem_func),
                            &owner_mod);
                        wchar_t owner_path_w[MAX_PATH]{};
                        DWORD owner_path_len = owner_ok && owner_mod
                            ? GetModuleFileNameW(owner_mod, owner_path_w, MAX_PATH)
                            : 0;
                        const auto* owner_base_ptr = reinterpret_cast<const uint8_t*>(owner_mod);
                        uint32_t owner_size = owner_ok && owner_mod ? image_size_from_base(owner_base_ptr) : 0;
                        uint64_t owner_base = reinterpret_cast<uint64_t>(owner_base_ptr);
                        bool in_owner_range = owner_size != 0 &&
                            mem_va >= owner_base &&
                            mem_va < owner_base + owner_size;
                        uint64_t owner_rva = in_owner_range ? mem_va - owner_base : 0;
                        bool owner_system = owner_path_len != 0 && system_image_module_path(owner_path_w);
                        char owner_path[512]{};
                        narrow_path(owner_path_w, owner_path, sizeof(owner_path));
                        char mem_hex[49]{};
                        char disk_hex[49]{};
                        hex16(mem_func, mem_hex);
                        hex16(disk_bytes, disk_hex);
                        webhook::write_log_critical_fmt("disk_hook",
                            "ntdll_compare_mismatch func=%s mem_va=0x%llX mem_rva=0x%llX disk_rva=0x%llX rva_match=%d in_ntdll=%d vq=%llu protect=0x%lX state=0x%lX type=0x%lX type_name=%s mem_writable=%d owner_ok=%d owner_base=0x%llX owner_size=0x%lX owner_rva=0x%llX owner_system=%d owner_path=%s mem_redirect=%d disk_redirect=%d mem_syscall=%d disk_syscall=%d mem16=%s disk16=%s",
                            func_name ? func_name : "?",
                            static_cast<unsigned long long>(mem_va),
                            static_cast<unsigned long long>(mem_rva),
                            static_cast<unsigned long long>(disk_rva),
                            rva_match ? 1 : 0,
                            in_ntdll_range ? 1 : 0,
                            static_cast<unsigned long long>(vq),
                            vq ? static_cast<unsigned long>(mbi.Protect) : 0ul,
                            vq ? static_cast<unsigned long>(mbi.State) : 0ul,
                            vq ? static_cast<unsigned long>(mbi.Type) : 0ul,
                            vq ? memory_type_name(mbi.Type) : "none",
                            mem_writable ? 1 : 0,
                            owner_ok ? 1 : 0,
                            static_cast<unsigned long long>(owner_base),
                            static_cast<unsigned long>(owner_size),
                            static_cast<unsigned long long>(owner_rva),
                            owner_system ? 1 : 0,
                            owner_path[0] ? owner_path : "<none>",
                            mem_redirect ? 1 : 0,
                            disk_redirect ? 1 : 0,
                            mem_syscall ? 1 : 0,
                            disk_syscall ? 1 : 0,
                            mem_hex,
                            disk_hex);
                        const bool is_nt_export = nt_export_name(func_name);
                        const bool system_owned_wrapper = is_nt_export &&
                            disk_syscall &&
                            vq != 0 &&
                            mbi.State == MEM_COMMIT &&
                            mbi.Type == MEM_IMAGE &&
                            !mem_writable &&
                            !mem_redirect &&
                            owner_ok &&
                            owner_system;
                        const bool suspicious_nt_target = is_nt_export &&
                            !system_owned_wrapper &&
                            (!in_ntdll_range || !mem_syscall);
                        const bool suspicious_non_nt_target = !is_nt_export &&
                            !mem_syscall &&
                            !disk_syscall;
                        is_hooked = mem_redirect ||
                            mem_writable ||
                            suspicious_nt_target ||
                            suspicious_non_nt_target;
                        if (!is_hooked)
                        {
                            log_nt_export_wrapper_diag("disk_hook",
                                "ntdll_compare_mismatch_nonfatal",
                                func_name,
                                mem_func,
                                disk_bytes,
                                mem_va,
                                mem_rva,
                                disk_rva,
                                vq,
                                mbi,
                                mem_writable,
                                mem_redirect,
                                disk_redirect,
                                mem_syscall,
                                disk_syscall,
                                is_nt_export,
                                owner_ok,
                                owner_base,
                                owner_size,
                                owner_rva,
                                owner_system,
                                owner_path_w,
                                owner_path,
                                system_owned_wrapper);
                        }
                    }
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
    std::lock_guard<std::mutex> lk(t.init_mtx);
    SecureZeroMemory(t.slots, sizeof(t.slots));
    SecureZeroMemory(t.pipeline_key, sizeof(t.pipeline_key));
    t.initialized.store(false, std::memory_order_release);
}

}
}
