#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <process.h>

#include <cerrno>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <cstdio>
#include <string>
#include <utility>

#include "../../helpers/diag_log.hpp"
#include "../runtime/loader_header_invariant.hpp"
#include "../runtime/manual_map_tls.hpp"

namespace aida::infra::win_thread {

inline constexpr unsigned default_stack_reserve = 512u * 1024u;
inline constexpr unsigned fixture_stack_reserve = 256u * 1024u;

namespace detail {

struct thread_state_t {
    std::function<void()> fn;
};

inline void run_state_fn(thread_state_t* state, void* raw_state)
{
    try {
        if (state && state->fn)
            state->fn();
        diag::log_tagged_fmt("win_thread", "thread_fn_return tid=%lu state=%p", static_cast<unsigned long>(GetCurrentThreadId()), raw_state);
    } catch (const std::exception& ex) {
        diag::log_tagged_fmt("win_thread", "thread_fn_exception tid=%lu state=%p err=%s", static_cast<unsigned long>(GetCurrentThreadId()), raw_state, ex.what());
    } catch (...) {
        diag::log_tagged_fmt("win_thread", "thread_fn_exception tid=%lu state=%p err=unknown", static_cast<unsigned long>(GetCurrentThreadId()), raw_state);
    }
}

inline DWORD run_state_fn_guarded(thread_state_t* state, void* raw_state)
{
    DWORD seh_code = 0;
    __try {
        run_state_fn(state, raw_state);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        seh_code = GetExceptionCode();
    }
    return seh_code;
}

inline DWORD destroy_state_guarded(thread_state_t* state)
{
    DWORD seh_code = 0;
    __try {
        delete state;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        seh_code = GetExceptionCode();
    }
    return seh_code;
}

inline DWORD WINAPI entry(void* arg)
{
    const bool tls_ready = aida::manual_map_tls::ensure_current_thread();
    diag::log_tagged_fmt("win_thread", "thread_entry tls_ready=%d tid=%lu state=%p",
        tls_ready ? 1 : 0,
        static_cast<unsigned long>(GetCurrentThreadId()),
        arg);
    if (!arg) {
        diag::log_tagged_fmt("win_thread", "thread_entry_null_state tid=%lu", static_cast<unsigned long>(GetCurrentThreadId()));
        return 0;
    }
    thread_state_t* state = static_cast<thread_state_t*>(arg);
    const DWORD run_seh = run_state_fn_guarded(state, arg);
    if (run_seh != 0) {
        diag::log_tagged_fmt("win_thread",
            "thread_fn_seh tid=%lu state=%p code=0x%08lX",
            static_cast<unsigned long>(GetCurrentThreadId()),
            arg,
            static_cast<unsigned long>(run_seh));
    }
    diag::log_tagged_fmt("win_thread", "thread_exit_pre tid=%lu state=%p", static_cast<unsigned long>(GetCurrentThreadId()), arg);
    const DWORD destroy_seh = destroy_state_guarded(state);
    if (destroy_seh != 0) {
        diag::log_tagged_fmt("win_thread",
            "thread_state_destroy_seh tid=%lu state=%p code=0x%08lX",
            static_cast<unsigned long>(GetCurrentThreadId()),
            arg,
            static_cast<unsigned long>(destroy_seh));
    }
    diag::log_tagged_fmt("win_thread", "thread_exit_post tid=%lu state=%p run_seh=0x%08lX destroy_seh=0x%08lX",
        static_cast<unsigned long>(GetCurrentThreadId()),
        arg,
        static_cast<unsigned long>(run_seh),
        static_cast<unsigned long>(destroy_seh));
    return 0;
}

inline unsigned __stdcall crt_entry(void* arg)
{
    const unsigned rc = static_cast<unsigned>(entry(arg));
    _endthreadex(rc);
    return rc;
}

inline void describe_address(const void* p, char* out, size_t out_size)
{
    if (!out || out_size == 0)
        return;
    out[0] = '\0';
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T got = VirtualQuery(p, &mbi, sizeof(mbi));
    if (got == sizeof(mbi)) {
        _snprintf_s(out, out_size, _TRUNCATE,
            "addr=%p base=%p alloc=%p size=0x%llX state=0x%lX protect=0x%lX type=0x%lX",
            p,
            mbi.BaseAddress,
            mbi.AllocationBase,
            static_cast<unsigned long long>(mbi.RegionSize),
            static_cast<unsigned long>(mbi.State),
            static_cast<unsigned long>(mbi.Protect),
            static_cast<unsigned long>(mbi.Type));
    } else {
        _snprintf_s(out, out_size, _TRUNCATE,
            "addr=%p virtual_query_failed gle=%lu",
            p,
            static_cast<unsigned long>(GetLastError()));
    }
}

inline void append_attempt_error(std::string& dst,
    const char* api,
    const char* name,
    unsigned stack_bytes,
    DWORD flags,
    DWORD gle,
    int crt_errno,
    DWORD elapsed_ms)
{
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%s%s{name=%s stack_bytes=%u flags=0x%08lX gle=%lu errno=%d elapsed_ms=%lu}",
        dst.empty() ? "" : " ",
        api ? api : "<api>",
        name ? name : "<unnamed>",
        stack_bytes,
        static_cast<unsigned long>(flags),
        static_cast<unsigned long>(gle),
        crt_errno,
        static_cast<unsigned long>(elapsed_ms));
    dst += buf;
}

inline void append_nt_attempt_error(std::string& dst,
    const char* api,
    const char* name,
    unsigned stack_bytes,
    LONG status,
    DWORD gle,
    int crt_errno,
    DWORD elapsed_ms)
{
    char buf[512];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%s%s{name=%s stack_bytes=%u status=0x%08lX gle=%lu errno=%d elapsed_ms=%lu}",
        dst.empty() ? "" : " ",
        api ? api : "<api>",
        name ? name : "<unnamed>",
        stack_bytes,
        static_cast<unsigned long>(status),
        static_cast<unsigned long>(gle),
        crt_errno,
        static_cast<unsigned long>(elapsed_ms));
    dst += buf;
}

inline bool try_create_thread(thread_state_t* state,
    const char* name,
    unsigned stack_bytes,
    DWORD flags,
    HANDLE& out_handle,
    unsigned& out_tid,
    std::string& errors)
{
    DWORD tid = 0;
    errno = 0;
    SetLastError(0);
    DWORD t0 = GetTickCount();
    HANDLE h = CreateThread(nullptr, stack_bytes, &entry, state, flags, &tid);
    DWORD gle = GetLastError();
    int crt = errno;
    DWORD elapsed = GetTickCount() - t0;
    diag::log_tagged_fmt("win_thread",
        "CreateThread result name=%s stack_bytes=%u flags=0x%08lX handle=%p tid=%lu elapsed_ms=%lu gle=%lu errno=%d caller_pid=%lu caller_tid=%lu state=%p entry=%p",
        name ? name : "<unnamed>",
        stack_bytes,
        static_cast<unsigned long>(flags),
        h,
        static_cast<unsigned long>(tid),
        static_cast<unsigned long>(elapsed),
        static_cast<unsigned long>(gle),
        crt,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        state,
        reinterpret_cast<void*>(&entry));
    if (h) {
        out_handle = h;
        out_tid = static_cast<unsigned>(tid);
        return true;
    }
    append_attempt_error(errors, "CreateThread", name, stack_bytes, flags, gle, crt, elapsed);
    return false;
}

inline bool try_nt_create_thread_ex(thread_state_t* state,
    const char* name,
    unsigned stack_bytes,
    HANDLE& out_handle,
    unsigned& out_tid,
    std::string& errors)
{
    using NtCreateThreadEx_t = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto pNtCreateThreadEx = ntdll ? reinterpret_cast<NtCreateThreadEx_t>(
        GetProcAddress(ntdll, "NtCreateThreadEx")) : nullptr;
    if (!pNtCreateThreadEx) {
        DWORD gle = GetLastError();
        diag::log_tagged_fmt("win_thread",
            "NtCreateThreadEx unavailable name=%s ntdll=%p gle=%lu",
            name ? name : "<unnamed>",
            ntdll,
            static_cast<unsigned long>(gle));
        append_nt_attempt_error(errors, "NtCreateThreadEx", name, stack_bytes, static_cast<LONG>(0xC0000139L), gle, errno, 0);
        return false;
    }

    HANDLE h = nullptr;
    errno = 0;
    SetLastError(0);
    DWORD t0 = GetTickCount();
    LONG status = pNtCreateThreadEx(&h,
        THREAD_ALL_ACCESS,
        nullptr,
        GetCurrentProcess(),
        reinterpret_cast<PVOID>(&entry),
        state,
        0,
        0,
        0,
        stack_bytes,
        nullptr);
    DWORD gle = GetLastError();
    int crt = errno;
    DWORD elapsed = GetTickCount() - t0;
    DWORD tid = h ? GetThreadId(h) : 0;
    diag::log_tagged_fmt("win_thread",
        "NtCreateThreadEx result name=%s stack_bytes=%u status=0x%08lX handle=%p tid=%lu elapsed_ms=%lu gle=%lu errno=%d caller_pid=%lu caller_tid=%lu state=%p entry=%p",
        name ? name : "<unnamed>",
        stack_bytes,
        static_cast<unsigned long>(status),
        h,
        static_cast<unsigned long>(tid),
        static_cast<unsigned long>(elapsed),
        static_cast<unsigned long>(gle),
        crt,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        state,
        reinterpret_cast<void*>(&entry));
    if (status >= 0 && h) {
        out_handle = h;
        out_tid = static_cast<unsigned>(tid);
        return true;
    }
    if (h)
        CloseHandle(h);
    append_nt_attempt_error(errors, "NtCreateThreadEx", name, stack_bytes, status, gle, crt, elapsed);
    return false;
}

inline bool try_beginthreadex(thread_state_t* state,
    const char* name,
    unsigned stack_bytes,
    HANDLE& out_handle,
    unsigned& out_tid,
    std::string& errors)
{
    unsigned tid = 0;
    errno = 0;
    SetLastError(0);
    DWORD t0 = GetTickCount();
    uintptr_t raw = _beginthreadex(nullptr, stack_bytes, &crt_entry, state, 0, &tid);
    DWORD gle = GetLastError();
    int crt = errno;
    DWORD elapsed = GetTickCount() - t0;
    HANDLE h = reinterpret_cast<HANDLE>(raw);
    diag::log_tagged_fmt("win_thread",
        "_beginthreadex result name=%s stack_bytes=%u flags=0x00000000 handle=%p tid=%u elapsed_ms=%lu gle=%lu errno=%d caller_pid=%lu caller_tid=%lu state=%p entry=%p",
        name ? name : "<unnamed>",
        stack_bytes,
        h,
        tid,
        static_cast<unsigned long>(elapsed),
        static_cast<unsigned long>(gle),
        crt,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        state,
        reinterpret_cast<void*>(&crt_entry));
    if (raw != 0) {
        out_handle = h;
        out_tid = tid;
        return true;
    }
    append_attempt_error(errors, "_beginthreadex", name, stack_bytes, 0, gle, crt, elapsed);
    return false;
}

template <typename Fn>
bool start_raw(Fn&& fn, unsigned stack_reserve, HANDLE& out_handle, unsigned& out_tid, std::string* err, const char* name)
{
    out_handle = nullptr;
    out_tid = 0;
    thread_state_t* state = nullptr;
    try {
        state = new (std::nothrow) thread_state_t{std::function<void()>(std::forward<Fn>(fn))};
    } catch (const std::exception& ex) {
        if (err) *err = std::string("thread state initialization failed: ") + ex.what();
        return false;
    } catch (...) {
        if (err) *err = "thread state initialization failed";
        return false;
    }
    if (!state) {
        if (err) *err = "thread state allocation failed";
        return false;
    }

    aida::runtime::loader_header_invariant::scoped_restore_t loader_window(name ? name : "thread_start", "win_thread");

    char entry_desc[256];
    describe_address(reinterpret_cast<const void*>(&entry), entry_desc, sizeof(entry_desc));
    diag::log_tagged_fmt("win_thread",
        "thread_start begin name=%s requested_stack_reserve=%u caller_pid=%lu caller_tid=%lu state=%p loader_window=%d entry_region={%s}",
        name ? name : "<unnamed>",
        stack_reserve,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()),
        state,
        loader_window.active() ? 1 : 0,
        entry_desc);

    std::string errors;
    if (stack_reserve != 0 &&
        try_beginthreadex(state, name, stack_reserve, out_handle, out_tid, errors))
        return true;

    if (try_beginthreadex(state, name, 0, out_handle, out_tid, errors))
        return true;

    if (stack_reserve != 0 &&
        try_create_thread(state, name, stack_reserve, STACK_SIZE_PARAM_IS_A_RESERVATION, out_handle, out_tid, errors))
        return true;

    if (try_create_thread(state, name, 0, 0, out_handle, out_tid, errors))
        return true;

    if (try_nt_create_thread_ex(state, name, stack_reserve, out_handle, out_tid, errors))
        return true;

    if (err) {
        *err = errors.empty() ? "thread start failed" : errors;
    }
    diag::log_tagged_fmt("win_thread",
        "thread_start failed name=%s errors=%s",
        name ? name : "<unnamed>",
        errors.empty() ? "<none>" : errors.c_str());
    delete state;
    return false;
}

}

class joinable_thread_t {
public:
    joinable_thread_t() = default;
    joinable_thread_t(const joinable_thread_t&) = delete;
    joinable_thread_t& operator=(const joinable_thread_t&) = delete;

    joinable_thread_t(joinable_thread_t&& other) noexcept
    {
        handle_ = other.handle_;
        tid_ = other.tid_;
        other.handle_ = nullptr;
        other.tid_ = 0;
    }

    joinable_thread_t& operator=(joinable_thread_t&& other) noexcept
    {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            tid_ = other.tid_;
            other.handle_ = nullptr;
            other.tid_ = 0;
        }
        return *this;
    }

    ~joinable_thread_t()
    {
        close();
    }

    template <typename Fn>
    bool start(Fn&& fn, std::string* err = nullptr, unsigned stack_reserve = default_stack_reserve, const char* name = nullptr)
    {
        if (handle_) {
            if (err) *err = "thread already running";
            return false;
        }
        return detail::start_raw(std::forward<Fn>(fn), stack_reserve, handle_, tid_, err, name);
    }

    bool joinable() const
    {
        return handle_ != nullptr;
    }

    void join()
    {
        HANDLE h = handle_;
        if (!h) return;
        WaitForSingleObject(h, INFINITE);
        CloseHandle(h);
        handle_ = nullptr;
        tid_ = 0;
    }

    bool join_for(DWORD timeout_ms)
    {
        HANDLE h = handle_;
        if (!h) return true;
        DWORD rc = WaitForSingleObject(h, timeout_ms);
        if (rc != WAIT_OBJECT_0)
            return false;
        CloseHandle(h);
        handle_ = nullptr;
        tid_ = 0;
        return true;
    }

    void detach()
    {
        close();
    }

    void close()
    {
        if (!handle_) return;
        CloseHandle(handle_);
        handle_ = nullptr;
        tid_ = 0;
    }

    unsigned id() const
    {
        return tid_;
    }

private:
    HANDLE handle_ = nullptr;
    unsigned tid_ = 0;
};

template <typename Fn>
bool start_detached(Fn&& fn, std::string* err = nullptr, unsigned stack_reserve = default_stack_reserve, const char* name = nullptr)
{
    HANDLE h = nullptr;
    unsigned tid = 0;
    if (!detail::start_raw(std::forward<Fn>(fn), stack_reserve, h, tid, err, name))
        return false;
    CloseHandle(h);
    return true;
}

}
