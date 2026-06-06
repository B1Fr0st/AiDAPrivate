#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "work_queue.hpp"
#include <tlhelp32.h>

#include "standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace page_guard_engine {


struct pg_capture_t {
    uint64_t timestamp;
    uint64_t fault_addr;
    uint64_t rip;
    uint64_t ctx_rax;
    uint64_t ctx_rcx;
    uint64_t ctx_rdx;
    uint32_t exception_code;
    uint32_t access_type;
    uint8_t  pad[8];
};

static_assert(sizeof(pg_capture_t) == 64, "pg_capture_t must be 64 bytes");


struct pg_ring_header_t {
    volatile uint32_t write_idx;
    volatile uint32_t read_idx;
    uint32_t          reserved0;
    uint32_t          reserved1;
};

static_assert(sizeof(pg_ring_header_t) == 16, "pg_ring_header_t must be 16 bytes");

static constexpr uint32_t RING_ENTRIES    = 256;
static constexpr uint32_t RING_TOTAL_SIZE = sizeof(pg_ring_header_t) +
                                             RING_ENTRIES * sizeof(pg_capture_t);
static constexpr uint32_t PAYLOAD_PREVIEW_MAX = 128;


static constexpr size_t SHELLCODE_SIZE          = 265;
static constexpr size_t PATCH_RING_BASE         = 50;
static constexpr size_t PATCH_PAGE_BASE         = 183;
static constexpr size_t PATCH_PAGE_SIZE         = 196;
static constexpr size_t PATCH_ORIG_PROTECT      = 208;
static constexpr size_t PATCH_VIRT_PROTECT      = 227;

struct remote_call_state_t {
    uint64_t function_address;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t result;
};

static_assert(sizeof(remote_call_state_t) == 48, "remote_call_state_t layout mismatch");

static inline void log_remote_region(HANDLE process,
                                     const char* label,
                                     uint32_t pid,
                                     const char* phase,
                                     const void* address)
{
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T got = VirtualQueryEx(process, address, &mbi, sizeof(mbi));
    DWORD err = got == sizeof(mbi) ? 0 : GetLastError();
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_region label=%s pid=%u phase=%s addr=%p query=%llu base=%p alloc_base=%p size=0x%llX state=0x%08lX protect=0x%08lX type=0x%08lX err=%lu",
        label ? label : "",
        pid,
        phase ? phase : "",
        address,
        static_cast<unsigned long long>(got),
        got == sizeof(mbi) ? mbi.BaseAddress : nullptr,
        got == sizeof(mbi) ? mbi.AllocationBase : nullptr,
        got == sizeof(mbi) ? static_cast<unsigned long long>(mbi.RegionSize) : 0ULL,
        got == sizeof(mbi) ? static_cast<unsigned long>(mbi.State) : 0UL,
        got == sizeof(mbi) ? static_cast<unsigned long>(mbi.Protect) : 0UL,
        got == sizeof(mbi) ? static_cast<unsigned long>(mbi.Type) : 0UL,
        static_cast<unsigned long>(err));
}

static inline uint64_t remote_thread_call(uint32_t pid,
                                          uint64_t function_address,
                                          uint64_t arg1,
                                          uint64_t arg2 = 0,
                                          uint64_t arg3 = 0,
                                          uint64_t arg4 = 0,
                                          DWORD timeout_ms = 5000,
                                          const char* label = "remote_call")
{
    const ULONGLONG call_start = GetTickCount64();
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_entry label=%s pid=%u fn=0x%llX arg1=0x%llX arg2=0x%llX arg3=0x%llX arg4=0x%llX timeout_ms=%lu caller_tid=%lu tick=%llu",
        label ? label : "",
        pid,
        static_cast<unsigned long long>(function_address),
        static_cast<unsigned long long>(arg1),
        static_cast<unsigned long long>(arg2),
        static_cast<unsigned long long>(arg3),
        static_cast<unsigned long long>(arg4),
        static_cast<unsigned long>(timeout_ms),
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(call_start));
    if (pid == 0 || function_address == 0) {
        diag::log_tagged_fmt("pg_sniff",
            "remote_thread_call_reject label=%s pid=%u fn=0x%llX",
            label ? label : "",
            pid,
            static_cast<unsigned long long>(function_address));
        return 0;
    }

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION |
                                 PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                                 FALSE, pid);
    if (!process) {
        diag::log_tagged_fmt("pg_sniff", "remote_thread_call_open_failed label=%s pid=%u err=%lu",
            label ? label : "", pid, static_cast<unsigned long>(GetLastError()));
        return 0;
    }
    DWORD process_exit = STILL_ACTIVE;
    BOOL process_exit_ok = GetExitCodeProcess(process, &process_exit);
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_open_ok label=%s pid=%u process=%p exit_ok=%d exit=0x%08lX elapsed_ms=%llu",
        label ? label : "",
        pid,
        process,
        process_exit_ok ? 1 : 0,
        static_cast<unsigned long>(process_exit),
        static_cast<unsigned long long>(GetTickCount64() - call_start));

    static const uint8_t kStub[] = {
        0x53,
        0x48, 0x89, 0xCB,
        0x48, 0x83, 0xEC, 0x20,
        0x48, 0x8B, 0x03,
        0x48, 0x8B, 0x4B, 0x08,
        0x48, 0x8B, 0x53, 0x10,
        0x4C, 0x8B, 0x43, 0x18,
        0x4C, 0x8B, 0x4B, 0x20,
        0xFF, 0xD0,
        0x48, 0x89, 0x43, 0x28,
        0x48, 0x83, 0xC4, 0x20,
        0x5B,
        0xC3
    };

    remote_call_state_t state{};
    state.function_address = function_address;
    state.arg1 = arg1;
    state.arg2 = arg2;
    state.arg3 = arg3;
    state.arg4 = arg4;

    LPVOID remote_state = VirtualAllocEx(process, nullptr, sizeof(state), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    LPVOID remote_code = VirtualAllocEx(process, nullptr, sizeof(kStub), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_alloc_result label=%s pid=%u state=%p state_size=%llu code=%p code_size=%llu elapsed_ms=%llu",
        label ? label : "",
        pid,
        remote_state,
        static_cast<unsigned long long>(sizeof(state)),
        remote_code,
        static_cast<unsigned long long>(sizeof(kStub)),
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    if (!remote_state || !remote_code) {
        diag::log_tagged_fmt("pg_sniff", "remote_thread_call_alloc_failed label=%s pid=%u state=%p code=%p err=%lu",
            label ? label : "", pid, remote_state, remote_code, static_cast<unsigned long>(GetLastError()));
        if (remote_state)
            VirtualFreeEx(process, remote_state, 0, MEM_RELEASE);
        if (remote_code)
            VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }
    log_remote_region(process, label, pid, "state_after_alloc", remote_state);
    log_remote_region(process, label, pid, "code_after_alloc", remote_code);

    SIZE_T wrote_state = 0;
    SIZE_T wrote_code = 0;
    SetLastError(0);
    BOOL wrote_state_ok = WriteProcessMemory(process, remote_state, &state, sizeof(state), &wrote_state);
    DWORD wrote_state_err = wrote_state_ok ? 0 : GetLastError();
    SetLastError(0);
    BOOL wrote_code_ok = WriteProcessMemory(process, remote_code, kStub, sizeof(kStub), &wrote_code);
    DWORD wrote_code_err = wrote_code_ok ? 0 : GetLastError();
    BOOL wrote_ok = wrote_state_ok && wrote_code_ok;
    DWORD old_protect = 0;
    SetLastError(0);
    BOOL protect_ok = wrote_ok && VirtualProtectEx(process, remote_code, sizeof(kStub), PAGE_EXECUTE_READ, &old_protect);
    DWORD protect_err = protect_ok ? 0 : GetLastError();
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_write_protect label=%s pid=%u wrote_state_ok=%d wrote_state=%llu wrote_state_err=%lu wrote_code_ok=%d wrote_code=%llu wrote_code_err=%lu protect_ok=%d old_protect=0x%08lX protect_err=%lu elapsed_ms=%llu",
        label ? label : "",
        pid,
        wrote_state_ok ? 1 : 0,
        static_cast<unsigned long long>(wrote_state),
        static_cast<unsigned long>(wrote_state_err),
        wrote_code_ok ? 1 : 0,
        static_cast<unsigned long long>(wrote_code),
        static_cast<unsigned long>(wrote_code_err),
        protect_ok ? 1 : 0,
        static_cast<unsigned long>(old_protect),
        static_cast<unsigned long>(protect_err),
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    log_remote_region(process, label, pid, "code_after_protect", remote_code);
    if (!wrote_ok || !protect_ok || wrote_state != sizeof(state) || wrote_code != sizeof(kStub)) {
        diag::log_tagged_fmt("pg_sniff", "remote_thread_call_write_failed label=%s pid=%u wrote_state=%llu wrote_code=%llu protect_ok=%d err=%lu",
            label ? label : "", pid,
            static_cast<unsigned long long>(wrote_state),
            static_cast<unsigned long long>(wrote_code),
            protect_ok ? 1 : 0,
            static_cast<unsigned long>(protect_err != 0 ? protect_err : (wrote_state_err != 0 ? wrote_state_err : wrote_code_err)));
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_state, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }

    BOOL flush_ok = FlushInstructionCache(process, remote_code, sizeof(kStub));
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_flush label=%s pid=%u ok=%d elapsed_ms=%llu",
        label ? label : "",
        pid,
        flush_ok ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    DWORD remote_tid = 0;
    HANDLE thread = CreateRemoteThread(process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_code),
        remote_state, 0, &remote_tid);
    if (!thread) {
        diag::log_tagged_fmt("pg_sniff", "remote_thread_call_create_failed label=%s pid=%u err=%lu",
            label ? label : "", pid, static_cast<unsigned long>(GetLastError()));
        VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
        VirtualFreeEx(process, remote_state, 0, MEM_RELEASE);
        CloseHandle(process);
        return 0;
    }
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_thread_created label=%s pid=%u remote_tid=%lu thread=%p elapsed_ms=%llu",
        label ? label : "",
        pid,
        static_cast<unsigned long>(remote_tid),
        thread,
        static_cast<unsigned long long>(GetTickCount64() - call_start));

    const ULONGLONG wait_start = GetTickCount64();
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_wait_begin label=%s pid=%u remote_tid=%lu timeout_ms=%lu elapsed_ms=%llu",
        label ? label : "",
        pid,
        static_cast<unsigned long>(remote_tid),
        static_cast<unsigned long>(timeout_ms),
        static_cast<unsigned long long>(wait_start - call_start));
    DWORD wait = WaitForSingleObject(thread, timeout_ms);
    const ULONGLONG wait_elapsed = GetTickCount64() - wait_start;
    if (wait != WAIT_OBJECT_0) {
        DWORD thread_exit = STILL_ACTIVE;
        GetExitCodeThread(thread, &thread_exit);
        DWORD after_exit = STILL_ACTIVE;
        BOOL after_exit_ok = GetExitCodeProcess(process, &after_exit);
        diag::log_tagged_fmt("pg_sniff", "remote_thread_call_timeout label=%s pid=%u remote_tid=%lu wait=0x%08lX wait_elapsed_ms=%llu thread_exit=0x%08lX process_exit_ok=%d process_exit=0x%08lX total_elapsed_ms=%llu",
            label ? label : "",
            pid,
            static_cast<unsigned long>(remote_tid),
            static_cast<unsigned long>(wait),
            static_cast<unsigned long long>(wait_elapsed),
            static_cast<unsigned long>(thread_exit),
            after_exit_ok ? 1 : 0,
            static_cast<unsigned long>(after_exit),
            static_cast<unsigned long long>(GetTickCount64() - call_start));
        CloseHandle(thread);
        CloseHandle(process);
        return 0;
    }
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_wait_done label=%s pid=%u remote_tid=%lu wait_elapsed_ms=%llu total_elapsed_ms=%llu",
        label ? label : "",
        pid,
        static_cast<unsigned long>(remote_tid),
        static_cast<unsigned long long>(wait_elapsed),
        static_cast<unsigned long long>(GetTickCount64() - call_start));

    SIZE_T read = 0;
    remote_call_state_t out_state{};
    SetLastError(0);
    BOOL read_ok = ReadProcessMemory(process, remote_state, &out_state, sizeof(out_state), &read);
    DWORD read_err = read_ok ? 0 : GetLastError();
    DWORD exit_code = 0;
    BOOL exit_ok = GetExitCodeThread(thread, &exit_code);
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_read_exit label=%s pid=%u remote_tid=%lu read_ok=%d read=%llu read_err=%lu exit_ok=%d exit=0x%08lX result=0x%llX elapsed_ms=%llu",
        label ? label : "",
        pid,
        static_cast<unsigned long>(remote_tid),
        read_ok ? 1 : 0,
        static_cast<unsigned long long>(read),
        static_cast<unsigned long>(read_err),
        exit_ok ? 1 : 0,
        static_cast<unsigned long>(exit_code),
        static_cast<unsigned long long>(out_state.result),
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    CloseHandle(thread);
    SetLastError(0);
    BOOL free_code_ok = VirtualFreeEx(process, remote_code, 0, MEM_RELEASE);
    DWORD free_code_err = free_code_ok ? 0 : GetLastError();
    SetLastError(0);
    BOOL free_state_ok = VirtualFreeEx(process, remote_state, 0, MEM_RELEASE);
    DWORD free_state_err = free_state_ok ? 0 : GetLastError();
    diag::log_tagged_fmt("pg_sniff",
        "remote_thread_call_free label=%s pid=%u code=%p free_code_ok=%d free_code_err=%lu state=%p free_state_ok=%d free_state_err=%lu elapsed_ms=%llu",
        label ? label : "",
        pid,
        remote_code,
        free_code_ok ? 1 : 0,
        static_cast<unsigned long>(free_code_err),
        remote_state,
        free_state_ok ? 1 : 0,
        static_cast<unsigned long>(free_state_err),
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    CloseHandle(process);

    if (!read_ok || read != sizeof(out_state)) {
        diag::log_tagged_fmt("pg_sniff", "remote_thread_call_read_failed label=%s pid=%u read=%llu err=%lu",
            label ? label : "", pid,
            static_cast<unsigned long long>(read),
            static_cast<unsigned long>(read_err));
        return 0;
    }

    diag::log_tagged_fmt("pg_sniff", "remote_thread_call_done label=%s pid=%u fn=0x%llX result=0x%llX exit=0x%08lX total_elapsed_ms=%llu",
        label ? label : "",
        pid,
        static_cast<unsigned long long>(function_address),
        static_cast<unsigned long long>(out_state.result),
        static_cast<unsigned long>(exit_code),
        static_cast<unsigned long long>(GetTickCount64() - call_start));
    return out_state.result;
}


static inline std::vector<uint8_t> generate_veh_shellcode(
        uint64_t ring_base,
        uint64_t page_base,
        uint64_t page_size,
        uint32_t orig_protect,
        uint64_t virt_protect_fn)
{


    static const uint8_t kTemplate[SHELLCODE_SIZE] = {

        0x53,
        0x56,
        0x57,
        0x41, 0x55,
        0x41, 0x56,
        0x48, 0x83, 0xEC, 0x28,
        0x49, 0x89, 0xCD,
        0x48, 0x8B, 0x19,
        0x8B, 0x03,
        0x3D, 0x01, 0x00, 0x00, 0x80,
        0x0F, 0x84, 0x12, 0x00, 0x00, 0x00,
        0x3D, 0x04, 0x00, 0x00, 0x80,
        0x0F, 0x84, 0x8C, 0x00, 0x00, 0x00,
        0x33, 0xC0,
        0xE9, 0xCD, 0x00, 0x00, 0x00,

        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x8B, 0x00,
        0x45, 0x0F, 0xB6, 0xC0,
        0x41, 0xC1, 0xE0, 0x06,
        0x48, 0x8D, 0x48, 0x10,
        0x49, 0x03, 0xC8,
        0x48, 0x89, 0xC6,
        0x0F, 0x31,
        0x48, 0xC1, 0xE2, 0x20,
        0x48, 0x0B, 0xC2,
        0x48, 0x89, 0x01,
        0x48, 0x8B, 0x43, 0x28,
        0x48, 0x89, 0x41, 0x08,
        0x49, 0x8B, 0x55, 0x08,
        0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x10,
        0x48, 0x8B, 0x42, 0x78,
        0x48, 0x89, 0x41, 0x18,
        0x48, 0x8B, 0x82, 0x80, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x20,
        0x48, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x41, 0x28,
        0x8B, 0x03,
        0x89, 0x41, 0x30,
        0x8B, 0x43, 0x20,
        0x89, 0x41, 0x34,
        0x8B, 0x06,
        0xFF, 0xC0,
        0x0F, 0xB6, 0xC0,
        0x89, 0x06,
        0x81, 0x4A, 0x44, 0x00, 0x01, 0x00, 0x00,
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,
        0xE9, 0x48, 0x00, 0x00, 0x00,

        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC1,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC2,
        0xB8,
        0x00, 0x00, 0x00, 0x00,
        0x0D, 0x00, 0x01, 0x00, 0x00,
        0x41, 0x89, 0xC0,
        0x4C, 0x8D, 0x4C, 0x24, 0x20,
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0x49, 0x8B, 0x4D, 0x08,
        0x81, 0x61, 0x44, 0xFF, 0xFE, 0xFF, 0xFF,
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,

        0x48, 0x83, 0xC4, 0x28,
        0x41, 0x5E,
        0x41, 0x5D,
        0x5F,
        0x5E,
        0x5B,
        0xC3,
    };

    static_assert(sizeof(kTemplate) == SHELLCODE_SIZE,
                  "shellcode template size mismatch");

    std::vector<uint8_t> sc(kTemplate, kTemplate + SHELLCODE_SIZE);


    auto patch64 = [&](size_t off, uint64_t v) {
        memcpy(sc.data() + off, &v, 8);
    };
    auto patch32 = [&](size_t off, uint32_t v) {
        memcpy(sc.data() + off, &v, 4);
    };

    patch64(PATCH_RING_BASE,    ring_base);
    patch64(PATCH_PAGE_BASE,    page_base);
    patch64(PATCH_PAGE_SIZE,    page_size);
    patch32(PATCH_ORIG_PROTECT, orig_protect);
    patch64(PATCH_VIRT_PROTECT, virt_protect_fn);

    return sc;
}

struct pg_capture_record_t {
    pg_capture_t metadata{};
    uint64_t payload_addr = 0;
    uint64_t payload_offset = 0;
    uint32_t payload_size = 0;
    bool payload_read = false;
    bool payload_truncated = false;
    std::string payload_source;
    std::vector<uint8_t> payload;
};

static inline bool address_in_range(uint64_t base, uint64_t size, uint64_t address) noexcept {
    return size != 0 && address >= base && (address - base) < size;
}

static inline std::string hex_u64(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

static inline std::string payload_hex_preview(const std::vector<uint8_t>& bytes, size_t max_bytes = PAYLOAD_PREVIEW_MAX) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    const size_t show = std::min(bytes.size(), max_bytes);
    out.reserve(show * 3);
    for (size_t i = 0; i < show; ++i) {
        const uint8_t b = bytes[i];
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
        if (i + 1 != show)
            out.push_back(' ');
    }
    return out;
}

static inline std::string payload_plaintext_preview(const std::vector<uint8_t>& bytes, size_t max_chars = PAYLOAD_PREVIEW_MAX) {
    std::string out;
    const size_t show = std::min(bytes.size(), max_chars);
    out.reserve(show);
    for (size_t i = 0; i < show; ++i) {
        const uint8_t b = bytes[i];
        out.push_back((b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.');
    }
    return out;
}

static inline bool has_payload_preview(const pg_capture_record_t& record) noexcept {
    return record.payload_read && record.payload_size != 0 && !record.payload.empty();
}

template <typename Json>
static inline void serialize_payload_fields(Json& out, const pg_capture_record_t& record) {
    out["payload_addr"] = hex_u64(record.payload_addr);
    out["payload_offset"] = record.payload_offset;
    out["payload_size"] = record.payload_size;
    out["payload_preview_size"] = static_cast<uint32_t>(record.payload.size());
    out["payload_available"] = has_payload_preview(record);
    out["payload_truncated"] = record.payload_truncated;
    out["payload_source"] = record.payload_source;
    out["hex_preview"] = payload_hex_preview(record.payload);
    out["plaintext_preview"] = payload_plaintext_preview(record.payload);
}


struct pg_session_t {
    uint32_t session_id    = 0;
    uint32_t pid           = 0;
    uint64_t target_addr   = 0;
    uint64_t region_size   = 0;
    uint64_t ring_addr     = 0;
    uint64_t sc_addr       = 0;
    uint32_t orig_protect  = 0;
    uint64_t veh_handle    = 0;

    std::mutex                      captures_mutex;
    std::mutex                      drain_mutex;
    std::queue<pg_capture_record_t> captures;

    std::atomic<bool>          polling{false};
    std::atomic<bool>          exited{false};


    uint32_t prev_write_idx     = 0;
    uint32_t prev_raw_write_idx = 0;
    bool     ring_initialized   = false;
    uint64_t total_captured     = 0;
    uint64_t estimated_drops    = 0;
    uint64_t header_read_failures = 0;
    uint64_t entry_read_failures  = 0;
    uint64_t rearm_attempts       = 0;
    uint64_t rearm_failures       = 0;
    std::atomic<size_t> payload_budget{static_cast<size_t>(-1)};
    std::atomic<size_t> payload_reads{0};
    std::atomic<bool> capture_payloads{true};
    std::atomic<uint32_t> max_records_per_drain{0};

    pg_session_t() = default;
    ~pg_session_t() {
        polling.store(false);
        for (int i = 0; i < 2000; ++i) {
            if (exited.load())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    pg_session_t(const pg_session_t&)            = delete;
    pg_session_t& operator=(const pg_session_t&) = delete;
};


class pg_engine_t {
    struct active_pid_scope_t {
        uint32_t previous_pid = 0;
        uint32_t entered_pid = 0;
        bool swapped = false;

        bool enter(uint32_t pid) {
            previous_pid = driver_bridge::attached_pid();
            entered_pid = pid;
            if (previous_pid == pid)
                return true;
            bool already_attached = false;
            const auto pids = driver_bridge::attached_pids();
            for (auto attached : pids) {
                if (attached == pid) {
                    already_attached = true;
                    break;
                }
            }
            if (!already_attached && !driver_bridge::attach_additional(pid))
                return false;
            if (!driver_bridge::set_active_pid(pid))
                return false;
            swapped = previous_pid != pid;
            return driver_bridge::attached_pid() == pid;
        }

        ~active_pid_scope_t() {
            if (!swapped)
                return;
            uint32_t current_pid = driver_bridge::attached_pid();
            if (current_pid != entered_pid) {
                diag::log_tagged_fmt("pg_sniff", "active_pid_scope_skip_restore entered=%u previous=%u current=%u",
                    entered_pid,
                    previous_pid,
                    current_pid);
                return;
            }
            if (previous_pid != 0)
                driver_bridge::set_active_pid(previous_pid);
            else
                driver_bridge::clear_active_pid();
        }
    };

public:
    pg_engine_t() = default;
    ~pg_engine_t() {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_.clear();
        retired_sessions_.clear();
    }

    pg_engine_t(const pg_engine_t&)            = delete;
    pg_engine_t& operator=(const pg_engine_t&) = delete;


    uint32_t install(uint32_t pid, uint64_t target_addr, uint64_t region_size, bool capture_payloads = true, uint32_t max_records_per_drain = 0) {
        diag::log_tagged_fmt("pg_sniff", "install_start pid=%u target=0x%llX size=0x%llX kernel=%d attached=%u payloads=%d max_drain=%u",
            pid,
            static_cast<unsigned long long>(target_addr),
            static_cast<unsigned long long>(region_size),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::attached_pid(),
            capture_payloads ? 1 : 0,
            max_records_per_drain);
        if (!driver_bridge::using_kernel_driver()) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=no_kernel_driver pid=%u", pid);
            return 0;
        }
        if (pid == 0 || target_addr == 0 || region_size == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=invalid_args pid=%u target=0x%llX size=0x%llX",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size));
            return 0;
        }

        active_pid_scope_t active;
        if (!active.enter(pid)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=active_pid_enter pid=%u status=%s last_error=%s",
                pid, driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
            return 0;
        }
        if (driver_bridge::attached_pid() != pid) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=active_pid_mismatch requested=%u attached=%u",
                pid, driver_bridge::attached_pid());
            return 0;
        }


        driver_bridge::memory_region_t mri{};
        if (!driver_bridge::query_memory_for(pid, target_addr, mri)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=query_memory pid=%u target=0x%llX last_error=%s",
                pid, static_cast<unsigned long long>(target_addr), driver_bridge::last_error().c_str());
            return 0;
        }
        uint32_t orig_protect = mri.protect;


        uint64_t k32_base = find_module_base(pid, "kernel32.dll");
        if (k32_base == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=kernel32_missing pid=%u", pid);
            return 0;
        }
        uint64_t virt_protect_fn = driver_bridge::resolve_export(k32_base, "VirtualProtect");
        if (virt_protect_fn == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=virtualprotect_missing pid=%u k32=0x%llX",
                pid, static_cast<unsigned long long>(k32_base));
            return 0;
        }


        uint64_t ring_addr = driver_bridge::allocate_memory(RING_TOTAL_SIZE + 16);
        if (ring_addr == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=ring_alloc pid=%u bytes=%u last_error=%s",
                pid, RING_TOTAL_SIZE + 16, driver_bridge::last_error().c_str());
            return 0;
        }
        if (driver_bridge::attached_pid() != pid) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=post_ring_active_mismatch requested=%u attached=%u ring=0x%llX",
                pid, driver_bridge::attached_pid(), static_cast<unsigned long long>(ring_addr));
            driver_bridge::free_memory(ring_addr);
            return 0;
        }

        uint64_t sc_addr = driver_bridge::allocate_memory(SHELLCODE_SIZE + 16);
        if (sc_addr == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=shellcode_alloc pid=%u bytes=%zu ring=0x%llX last_error=%s",
                pid, SHELLCODE_SIZE + 16, static_cast<unsigned long long>(ring_addr), driver_bridge::last_error().c_str());
            driver_bridge::free_memory(ring_addr);
            return 0;
        }


        std::vector<uint8_t> zeroes(RING_TOTAL_SIZE, 0);
        if (!driver_bridge::write_memory_for(pid, ring_addr, zeroes)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=ring_zero_write pid=%u ring=0x%llX last_error=%s",
                pid, static_cast<unsigned long long>(ring_addr), driver_bridge::last_error().c_str());
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }


        auto sc = generate_veh_shellcode(ring_addr, target_addr,
                                         region_size, orig_protect,
                                         virt_protect_fn);
        if (!driver_bridge::write_memory_for(pid, sc_addr, sc)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=shellcode_write pid=%u sc=0x%llX bytes=%zu last_error=%s",
                pid, static_cast<unsigned long long>(sc_addr), sc.size(), driver_bridge::last_error().c_str());
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }
        uint32_t old_sc_protect = 0;
        if (!driver_bridge::protect_memory_for(pid, sc_addr, SHELLCODE_SIZE,
                                               PAGE_EXECUTE_READ, &old_sc_protect)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=shellcode_protect pid=%u sc=0x%llX last_error=%s",
                pid, static_cast<unsigned long long>(sc_addr), driver_bridge::last_error().c_str());
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }


        uint64_t ntdll_base_install = find_module_base(pid, "ntdll.dll");
        if (ntdll_base_install == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=ntdll_missing pid=%u", pid);
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }
        uint64_t rtl_add_fn = driver_bridge::resolve_export(ntdll_base_install,
                                                      "RtlAddVectoredExceptionHandler");
        if (rtl_add_fn == 0) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=rtladdveh_missing pid=%u ntdll=0x%llX",
                pid, static_cast<unsigned long long>(ntdll_base_install));
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }

        uint64_t veh_handle = remote_thread_call(pid, rtl_add_fn, 1, sc_addr, 0, 0, 5000, "RtlAddVectoredExceptionHandler");
        if (veh_handle == 0) {
            diag::log_tagged_fmt("pg_sniff", "veh_register_failed pid=%u handler=0x%llX",
                pid, static_cast<unsigned long long>(sc_addr));
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }

        uint32_t old_prot = 0;
        if (!driver_bridge::protect_memory_for(pid, target_addr, region_size,
                                               orig_protect | PAGE_GUARD, &old_prot)) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=target_guard_protect pid=%u target=0x%llX size=0x%llX orig=0x%08X last_error=%s",
                pid,
                static_cast<unsigned long long>(target_addr),
                static_cast<unsigned long long>(region_size),
                orig_protect,
                driver_bridge::last_error().c_str());
            uint64_t rtl_rm = driver_bridge::resolve_export(ntdll_base_install,
                                                      "RtlRemoveVectoredExceptionHandler");
            if (rtl_rm) {
                uint64_t removed = remote_thread_call(pid, rtl_rm, veh_handle, 0, 0, 0, 5000, "RtlRemoveVectoredExceptionHandler");
                if (removed == 0)
                    diag::log_tagged_fmt("pg_sniff", "veh_remove_failed pid=%u handle=0x%llX",
                        pid, static_cast<unsigned long long>(veh_handle));
            }
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            return 0;
        }


        auto session         = std::make_shared<pg_session_t>();
        session->pid         = pid;
        session->target_addr = target_addr;
        session->region_size = region_size;
        session->ring_addr   = ring_addr;
        session->sc_addr     = sc_addr;
        session->orig_protect= orig_protect;
        session->veh_handle  = veh_handle;
        session->polling.store(true);
        session->capture_payloads.store(capture_payloads, std::memory_order_release);
        session->max_records_per_drain.store(max_records_per_drain, std::memory_order_release);

        uint32_t sid = next_id_++;
        session->session_id = sid;

        auto* sess_ptr = session.get();
        if (!work_queue::post([this, sess_ptr]() {
            poll_ring(sess_ptr);
        })) {
            diag::log_tagged_fmt("pg_sniff", "install_failed reason=poll_worker_post pid=%u target=0x%llX",
                pid, static_cast<unsigned long long>(target_addr));
            uint64_t rtl_rm = driver_bridge::resolve_export(ntdll_base_install,
                                                      "RtlRemoveVectoredExceptionHandler");
            if (rtl_rm)
                remote_thread_call(pid, rtl_rm, veh_handle, 0, 0, 0, 5000, "RtlRemoveVectoredExceptionHandler");
            driver_bridge::protect_memory_for(pid, target_addr, region_size, orig_protect, nullptr);
            driver_bridge::free_memory(sc_addr);
            driver_bridge::free_memory(ring_addr);
            session->polling.store(false);
            session->exited.store(true);
            return 0;
        }

        std::lock_guard<std::mutex> lk(sessions_mutex_);
        sessions_[sid] = session;
        diag::log_tagged_fmt("pg_sniff", "install_ok sid=%u pid=%u target=0x%llX size=0x%llX ring=0x%llX sc=0x%llX orig=0x%08X old_guard=0x%08X veh=0x%llX payloads=%d max_drain=%u",
            sid,
            pid,
            static_cast<unsigned long long>(target_addr),
            static_cast<unsigned long long>(region_size),
            static_cast<unsigned long long>(ring_addr),
            static_cast<unsigned long long>(sc_addr),
            orig_protect,
            old_prot,
            static_cast<unsigned long long>(veh_handle),
            capture_payloads ? 1 : 0,
            max_records_per_drain);
        return sid;
    }


    std::vector<pg_capture_t> get_captures(uint32_t session_id) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return {};
            sess = it->second;
        }
        if (!sess) return {};
        if (driver_bridge::using_kernel_driver())
            drain_ring(sess.get());
        std::lock_guard<std::mutex> slk(sess->captures_mutex);
        std::vector<pg_capture_t> out;
        while (!sess->captures.empty()) {
            out.push_back(sess->captures.front().metadata);
            sess->captures.pop();
        }
        return out;
    }

    std::vector<pg_capture_record_t> get_capture_records(uint32_t session_id) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return {};
            sess = it->second;
        }
        if (!sess) return {};
        if (driver_bridge::using_kernel_driver())
            drain_ring(sess.get());
        std::lock_guard<std::mutex> slk(sess->captures_mutex);
        std::vector<pg_capture_record_t> out;
        while (!sess->captures.empty()) {
            out.push_back(std::move(sess->captures.front()));
            sess->captures.pop();
        }
        return out;
    }

    bool set_payload_budget(uint32_t session_id, size_t budget) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return false;
            sess = it->second;
        }
        if (!sess) return false;
        sess->payload_budget.store(budget, std::memory_order_release);
        sess->payload_reads.store(0, std::memory_order_release);
        diag::log_tagged_fmt("pg_sniff", "payload_budget sid=%u budget=%zu", session_id, budget);
        return true;
    }


    bool uninstall(uint32_t session_id) {
        std::shared_ptr<pg_session_t> sess;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            auto it = sessions_.find(session_id);
            if (it == sessions_.end()) return false;
            sess = std::move(it->second);
            sessions_.erase(it);
        }


        const ULONGLONG cleanup_start = GetTickCount64();
        diag::log_tagged_fmt("pg_sniff", "uninstall_start sid=%u pid=%u target=0x%llX size=0x%llX exited=%d",
            session_id,
            sess->pid,
            static_cast<unsigned long long>(sess->target_addr),
            static_cast<unsigned long long>(sess->region_size),
            sess->exited.load() ? 1 : 0);

        sess->polling.store(false);
        bool poller_exited = sess->exited.load();
        for (int i = 0; i < 200 && !poller_exited; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            poller_exited = sess->exited.load();
        }
        diag::log_tagged_fmt("pg_sniff", "uninstall_poller_state sid=%u exited=%d elapsed_ms=%llu",
            session_id,
            poller_exited ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

        if (driver_bridge::using_kernel_driver()) {
            active_pid_scope_t active;
            const bool active_ok = active.enter(sess->pid);
            diag::log_tagged_fmt("pg_sniff", "uninstall_active_pid sid=%u active_ok=%d attached=%u elapsed_ms=%llu",
                session_id,
                active_ok ? 1 : 0,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

            if (active_ok && sess->veh_handle) {
                uint64_t ntdll_base = find_module_base(sess->pid, "ntdll.dll");
                if (ntdll_base) {
                    uint64_t rtl_rm = driver_bridge::resolve_export(ntdll_base,
                                                              "RtlRemoveVectoredExceptionHandler");
                    if (rtl_rm) {
                        uint64_t removed = remote_thread_call(sess->pid, rtl_rm, sess->veh_handle, 0, 0, 0, 5000, "RtlRemoveVectoredExceptionHandler");
                        if (removed == 0)
                            diag::log_tagged_fmt("pg_sniff", "veh_remove_failed pid=%u handle=0x%llX",
                                sess->pid, static_cast<unsigned long long>(sess->veh_handle));
                    }
                }
            }

            diag::log_tagged_fmt("pg_sniff", "uninstall_restore_protect_begin sid=%u target=0x%llX size=0x%llX orig=0x%08X elapsed_ms=%llu",
                session_id,
                static_cast<unsigned long long>(sess->target_addr),
                static_cast<unsigned long long>(sess->region_size),
                sess->orig_protect,
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
            driver_bridge::protect_memory_for(sess->pid, sess->target_addr, sess->region_size,
                                              sess->orig_protect, nullptr);
            diag::log_tagged_fmt("pg_sniff", "uninstall_restore_protect_done sid=%u elapsed_ms=%llu",
                session_id,
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start));

            poller_exited = sess->exited.load();
            if (active_ok && poller_exited) {
                diag::log_tagged_fmt("pg_sniff", "uninstall_free_begin sid=%u sc=0x%llX ring=0x%llX elapsed_ms=%llu",
                    session_id,
                    static_cast<unsigned long long>(sess->sc_addr),
                    static_cast<unsigned long long>(sess->ring_addr),
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                if (sess->sc_addr) driver_bridge::free_memory(sess->sc_addr);
                if (sess->ring_addr) driver_bridge::free_memory(sess->ring_addr);
                diag::log_tagged_fmt("pg_sniff", "uninstall_free_done sid=%u elapsed_ms=%llu",
                    session_id,
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
            } else {
                diag::log_tagged_fmt("pg_sniff", "uninstall_retired sid=%u active_ok=%d exited=%d sc=0x%llX ring=0x%llX elapsed_ms=%llu",
                    session_id,
                    active_ok ? 1 : 0,
                    poller_exited ? 1 : 0,
                    static_cast<unsigned long long>(sess->sc_addr),
                    static_cast<unsigned long long>(sess->ring_addr),
                    static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
                std::lock_guard<std::mutex> lk(sessions_mutex_);
                retired_sessions_.push_back(std::move(sess));
            }
        }
        diag::log_tagged_fmt("pg_sniff", "uninstall_done sid=%u elapsed_ms=%llu",
            session_id,
            static_cast<unsigned long long>(GetTickCount64() - cleanup_start));
        return true;
    }

    size_t signal_stop_all() {
        std::vector<std::shared_ptr<pg_session_t>> snapshot;
        {
            std::lock_guard<std::mutex> lk(sessions_mutex_);
            snapshot.reserve(sessions_.size());
            for (auto& [sid, sess] : sessions_) {
                (void)sid;
                if (sess)
                    snapshot.push_back(sess);
            }
        }
        size_t signalled = 0;
        for (auto& sess : snapshot) {
            if (!sess)
                continue;
            sess->polling.store(false);
            ++signalled;
            diag::log_tagged_fmt("pg_sniff", "signal_stop sid=%u pid=%u target=0x%llX",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->target_addr));
        }
        return signalled;
    }


    struct session_info_t {
        uint32_t session_id;
        uint32_t pid;
        uint64_t target_addr;
        uint64_t region_size;
        size_t   pending_captures;
    };

    std::vector<session_info_t> list_sessions() {
        std::lock_guard<std::mutex> lk(sessions_mutex_);
        std::vector<session_info_t> out;
        for (auto& [sid, sess] : sessions_) {
            session_info_t si;
            si.session_id  = sid;
            si.pid         = sess->pid;
            si.target_addr = sess->target_addr;
            si.region_size = sess->region_size;
            {
                std::lock_guard<std::mutex> slk(sess->captures_mutex);
                si.pending_captures = sess->captures.size();
            }
            out.push_back(si);
        }
        return out;
    }


    static uint64_t find_module_base(uint32_t pid, const char* name_lower) noexcept {
        auto modules = driver_bridge::enumerate_modules_for(pid);
        for (const auto& m : modules) {
            std::string lower_name = m.name;
            for (char& c : lower_name)
                c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            if (lower_name == name_lower)
                return m.base;
        }
        return 0;
    }

private:
    std::vector<std::shared_ptr<pg_session_t>> retired_sessions_;

    void poll_ring(pg_session_t* sess) {
        while (sess->polling.load()) {
            if (driver_bridge::using_kernel_driver()) {
                drain_ring(sess);
            }

            if (sess->polling.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        sess->exited.store(true);
    }

    void drain_ring(pg_session_t* sess) {
        std::lock_guard<std::mutex> drain_lk(sess->drain_mutex);

        pg_ring_header_t hdr{};
        std::vector<uint8_t> hdr_buf;
        if (!driver_bridge::read_memory_for(sess->pid, sess->ring_addr, sizeof(hdr), hdr_buf) || hdr_buf.size() < sizeof(hdr)) {
            ++sess->header_read_failures;
            if (sess->header_read_failures <= 4 || (sess->header_read_failures % 20) == 0) {
                std::string err = driver_bridge::last_error();
                if (err.empty())
                    err = std::string("empty_last_error status=") + driver_bridge::status() + " gle=" + std::to_string(GetLastError());
                diag::log_tagged_fmt("pg_sniff", "drain_header_read_failed sid=%u pid=%u ring=0x%llX failures=%llu read=%zu last_error=%s",
                    sess->session_id,
                    sess->pid,
                    static_cast<unsigned long long>(sess->ring_addr),
                    static_cast<unsigned long long>(sess->header_read_failures),
                    hdr_buf.size(),
                    err.c_str());
            }
            return;
        }
        std::memcpy(&hdr, hdr_buf.data(), sizeof(hdr));

        uint32_t raw_w = hdr.write_idx;
        uint32_t raw_r = hdr.read_idx;
        uint32_t w = raw_w & (RING_ENTRIES - 1);
        uint32_t r = raw_r & (RING_ENTRIES - 1);


        if (sess->ring_initialized) {
            uint32_t writes_advanced = raw_w - sess->prev_raw_write_idx;
            if (writes_advanced > RING_ENTRIES) {
                sess->estimated_drops += writes_advanced - RING_ENTRIES;
                diag::log_tagged_fmt("pg_sniff", "drain_drop_estimate sid=%u raw_w=%u prev_raw_w=%u advanced=%u drops=%llu",
                    sess->session_id,
                    raw_w,
                    sess->prev_raw_write_idx,
                    writes_advanced,
                    static_cast<unsigned long long>(sess->estimated_drops));
            }
        }
        sess->prev_raw_write_idx = raw_w;
        sess->ring_initialized = true;
        sess->prev_write_idx = w;

        uint64_t drained = 0;
        uint64_t entry_failures = 0;
        uint32_t initial_r = r;
        const bool capture_payloads = sess->capture_payloads.load(std::memory_order_acquire);
        const uint32_t max_records = sess->max_records_per_drain.load(std::memory_order_acquire);
        while (r != w) {
            pg_capture_t entry{};
            uint64_t entry_addr = sess->ring_addr + sizeof(pg_ring_header_t)
                                  + r * sizeof(pg_capture_t);
            std::vector<uint8_t> entry_buf;
            if (driver_bridge::read_memory_for(sess->pid, entry_addr, sizeof(entry), entry_buf) && entry_buf.size() >= sizeof(entry)) {
                std::memcpy(&entry, entry_buf.data(), sizeof(entry));
                pg_capture_record_t record;
                if (capture_payloads) {
                    const size_t budget = sess->payload_budget.load(std::memory_order_acquire);
                    const bool unlimited = budget == static_cast<size_t>(-1);
                    const bool include_payload = unlimited || sess->payload_reads.load(std::memory_order_acquire) < budget;
                    record = build_capture_record(sess, entry, include_payload);
                    if (!include_payload && sess->payload_reads.load(std::memory_order_relaxed) == budget) {
                        diag::log_tagged_fmt("pg_sniff", "payload_budget_exhausted sid=%u budget=%zu total=%llu",
                            sess->session_id,
                            budget,
                            static_cast<unsigned long long>(sess->total_captured));
                    }
                    if (!unlimited && record.payload_read)
                        sess->payload_reads.fetch_add(1, std::memory_order_acq_rel);
                } else {
                    record.metadata = entry;
                    record.payload_source = "metadata_only";
                }
                std::lock_guard<std::mutex> lk(sess->captures_mutex);
                sess->captures.push(std::move(record));
            } else {
                ++entry_failures;
                ++sess->entry_read_failures;
            }
            r = (r + 1) & (RING_ENTRIES - 1);
            drained++;
            if (max_records != 0 && drained >= max_records)
                break;
        }
        sess->total_captured += drained;
        if (drained > 0 || entry_failures > 0) {
            diag::log_tagged_fmt("pg_sniff", "drain sid=%u pid=%u raw_w=%u raw_r=%u w=%u r0=%u r1=%u drained=%llu entry_failures=%llu total=%llu drops=%llu rearm=%llu/%llu payloads=%d max_drain=%u",
                sess->session_id,
                sess->pid,
                raw_w,
                raw_r,
                w,
                initial_r,
                r,
                static_cast<unsigned long long>(drained),
                static_cast<unsigned long long>(entry_failures),
                static_cast<unsigned long long>(sess->total_captured),
                static_cast<unsigned long long>(sess->estimated_drops),
                static_cast<unsigned long long>(sess->rearm_attempts),
                static_cast<unsigned long long>(sess->rearm_failures),
                capture_payloads ? 1 : 0,
                max_records);
        }

        if (drained > 0 || r != initial_r) {

            uint32_t new_r = r;
            std::vector<uint8_t> r_buf(sizeof(new_r));
            std::memcpy(r_buf.data(), &new_r, sizeof(new_r));
            driver_bridge::write_memory_for(sess->pid, sess->ring_addr + offsetof(pg_ring_header_t, read_idx), r_buf);
        }
    }

    static bool readable_protect(uint32_t protect) noexcept {
        const uint32_t base = protect & 0xFFu;
        return base != PAGE_NOACCESS;
    }

    static uint64_t region_remaining(const pg_session_t* sess, uint64_t address) noexcept {
        if (!address_in_range(sess->target_addr, sess->region_size, address))
            return 0;
        return sess->region_size - (address - sess->target_addr);
    }

    static uint64_t choose_payload_address(const pg_session_t* sess, const pg_capture_t& entry, std::string& source) {
        struct candidate_t {
            uint64_t address;
            const char* source;
        };
        const candidate_t candidates[] = {
            {entry.fault_addr, "fault_addr"},
            {entry.ctx_rdx, "rdx"},
            {entry.ctx_rcx, "rcx"},
            {entry.ctx_rax, "rax"},
            {sess->target_addr, "region_base"}
        };
        for (const auto& c : candidates) {
            if (address_in_range(sess->target_addr, sess->region_size, c.address)) {
                source = c.source;
                return c.address;
            }
        }
        source = "unavailable";
        return 0;
    }

    static void rearm_guard(pg_session_t* sess) {
        if (!sess->polling.load())
            return;
        ++sess->rearm_attempts;
        uint32_t old_protect = 0;
        const bool ok = driver_bridge::protect_memory_for(sess->pid, sess->target_addr, sess->region_size,
                                                          sess->orig_protect | PAGE_GUARD, &old_protect);
        if (!ok) {
            ++sess->rearm_failures;
            diag::log_tagged_fmt("pg_sniff", "rearm_failed sid=%u pid=%u target=0x%llX size=0x%llX orig=0x%08X attempt=%llu failures=%llu last_error=%s",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->target_addr),
                static_cast<unsigned long long>(sess->region_size),
                sess->orig_protect,
                static_cast<unsigned long long>(sess->rearm_attempts),
                static_cast<unsigned long long>(sess->rearm_failures),
                driver_bridge::last_error().c_str());
        } else if (sess->rearm_attempts <= 3 || (sess->rearm_attempts % 16) == 0) {
            diag::log_tagged_fmt("pg_sniff", "rearm_ok sid=%u pid=%u target=0x%llX size=0x%llX old=0x%08X attempt=%llu",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(sess->target_addr),
                static_cast<unsigned long long>(sess->region_size),
                old_protect,
                static_cast<unsigned long long>(sess->rearm_attempts));
        }
    }

    pg_capture_record_t build_capture_record(pg_session_t* sess, const pg_capture_t& entry, bool include_payload = true) {
        pg_capture_record_t record;
        record.metadata = entry;
        record.payload_addr = choose_payload_address(sess, entry, record.payload_source);
        if (record.payload_addr == 0) {
            diag::log_tagged_fmt("pg_sniff", "payload_addr_unavailable sid=%u fault=0x%llX rip=0x%llX access=%u source=%s",
                sess ? sess->session_id : 0,
                static_cast<unsigned long long>(entry.fault_addr),
                static_cast<unsigned long long>(entry.rip),
                entry.access_type,
                record.payload_source.c_str());
            return record;
        }
        record.payload_offset = record.payload_addr - sess->target_addr;
        if (!include_payload) {
            diag::log_tagged_fmt("pg_sniff", "payload_skipped sid=%u addr=0x%llX source=%s reason=budget",
                sess ? sess->session_id : 0,
                static_cast<unsigned long long>(record.payload_addr),
                record.payload_source.c_str());
            return record;
        }

        const uint64_t available = region_remaining(sess, record.payload_addr);
        if (available == 0) {
            diag::log_tagged_fmt("pg_sniff", "payload_region_empty sid=%u addr=0x%llX target=0x%llX size=0x%llX source=%s",
                sess ? sess->session_id : 0,
                static_cast<unsigned long long>(record.payload_addr),
                static_cast<unsigned long long>(sess ? sess->target_addr : 0),
                static_cast<unsigned long long>(sess ? sess->region_size : 0),
                record.payload_source.c_str());
            return record;
        }

        const size_t requested = static_cast<size_t>(std::min<uint64_t>(available, PAYLOAD_PREVIEW_MAX));
        driver_bridge::memory_region_t mri{};
        if (!driver_bridge::query_memory_for(sess->pid, record.payload_addr, mri) || !readable_protect(mri.protect)) {
            diag::log_tagged_fmt("pg_sniff", "payload_query_failed sid=%u pid=%u addr=0x%llX query_base=0x%llX query_size=0x%llX protect=0x%08X state=0x%08X source=%s last_error=%s",
                sess ? sess->session_id : 0,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(record.payload_addr),
                static_cast<unsigned long long>(mri.base),
                static_cast<unsigned long long>(mri.size),
                mri.protect,
                mri.state,
                record.payload_source.c_str(),
                driver_bridge::last_error().c_str());
            return record;
        }

        std::vector<uint8_t> bytes;
        bool ok = driver_bridge::read_memory_for(sess->pid, record.payload_addr, requested, bytes);
        if (!ok || bytes.empty()) {
            diag::log_tagged_fmt("pg_sniff", "payload_read_retry sid=%u pid=%u addr=0x%llX requested=%zu ok=%d bytes=%zu source=%s last_error=%s",
                sess ? sess->session_id : 0,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(record.payload_addr),
                requested,
                ok ? 1 : 0,
                bytes.size(),
                record.payload_source.c_str(),
                driver_bridge::last_error().c_str());
            driver_bridge::protect_memory_for(sess->pid, sess->target_addr, sess->region_size,
                                              sess->orig_protect, nullptr);
            ok = driver_bridge::read_memory_for(sess->pid, record.payload_addr, requested, bytes);
        }
        rearm_guard(sess);

        if (!ok || bytes.empty()) {
            diag::log_tagged_fmt("pg_sniff", "payload_read_failed sid=%u pid=%u addr=0x%llX requested=%zu ok=%d bytes=%zu source=%s last_error=%s",
                sess ? sess->session_id : 0,
                sess ? sess->pid : 0,
                static_cast<unsigned long long>(record.payload_addr),
                requested,
                ok ? 1 : 0,
                bytes.size(),
                record.payload_source.c_str(),
                driver_bridge::last_error().c_str());
            return record;
        }
        if (bytes.size() > requested)
            bytes.resize(requested);

        record.payload = std::move(bytes);
        record.payload_read = true;
        record.payload_size = static_cast<uint32_t>(record.payload.size());
        record.payload_truncated = available > record.payload.size();
        if (sess && sess->payload_reads.load(std::memory_order_relaxed) < 16) {
            diag::log_tagged_fmt("pg_sniff", "payload_read_ok sid=%u pid=%u addr=0x%llX offset=0x%llX bytes=%u truncated=%d source=%s",
                sess->session_id,
                sess->pid,
                static_cast<unsigned long long>(record.payload_addr),
                static_cast<unsigned long long>(record.payload_offset),
                record.payload_size,
                record.payload_truncated ? 1 : 0,
                record.payload_source.c_str());
        }
        return record;
    }

    std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<pg_session_t>> sessions_;
    uint32_t next_id_ = 1;
};

inline pg_engine_t g_pg_engine;

}
