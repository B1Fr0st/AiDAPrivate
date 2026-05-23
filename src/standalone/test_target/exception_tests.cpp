#include "exception_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <malloc.h>

namespace test_target {
namespace exceptions {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[EXC] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

static volatile LONG s_veh_hit_count = 0;
static volatile DWORD s_last_veh_code = 0;

static LONG CALLBACK veh_first_handler(EXCEPTION_POINTERS* ep) {
    InterlockedIncrement(&s_veh_hit_count);
    s_last_veh_code = ep->ExceptionRecord->ExceptionCode;

    switch (ep->ExceptionRecord->ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            log("VEH caught ACCESS_VIOLATION at %p", ep->ExceptionRecord->ExceptionAddress);
#ifdef _M_X64
            ep->ContextRecord->Rip += 2;
#else
            ep->ContextRecord->Eip += 2;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;

        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            log("VEH caught INT_DIVIDE_BY_ZERO at %p", ep->ExceptionRecord->ExceptionAddress);
#ifdef _M_X64
            ep->ContextRecord->Rip += 2;
#else
            ep->ContextRecord->Eip += 2;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;

        case EXCEPTION_BREAKPOINT:
            log("VEH caught BREAKPOINT at %p", ep->ExceptionRecord->ExceptionAddress);
#ifdef _M_X64
            ep->ContextRecord->Rip += 1;
#else
            ep->ContextRecord->Eip += 1;
#endif
            return EXCEPTION_CONTINUE_EXECUTION;

        case EXCEPTION_SINGLE_STEP:
            log("VEH caught SINGLE_STEP at %p", ep->ExceptionRecord->ExceptionAddress);
            return EXCEPTION_CONTINUE_EXECUTION;

        case EXCEPTION_GUARD_PAGE:
            log("VEH caught GUARD_PAGE at %p", ep->ExceptionRecord->ExceptionAddress);
            return EXCEPTION_CONTINUE_EXECUTION;

        default:
            break;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#pragma optimize("", off)

static volatile int s_seh_depth = 0;

static int __declspec(noinline) seh_level_4(int input) {
    int result = 0;
    __try {
        s_seh_depth = 4;
        log("SEH level 4: entering (input=%d)", input);
        if (input == 0) {
            volatile int* p = nullptr;
            result = *p;
        } else {
            result = input * 4;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("SEH level 4: caught exception (code=0x%08X)", GetExceptionCode());
        result = -4;
    }
    return result;
}

static int __declspec(noinline) seh_level_3(int input) {
    int result = 0;
    __try {
        s_seh_depth = 3;
        log("SEH level 3: entering");
        result = seh_level_4(input);
        result += input * 3;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("SEH level 3: caught exception (code=0x%08X)", GetExceptionCode());
        result = -3;
    }
    return result;
}

static int __declspec(noinline) seh_level_2(int input) {
    int result = 0;
    __try {
        s_seh_depth = 2;
        log("SEH level 2: entering");
        result = seh_level_3(input);
        result += input * 2;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("SEH level 2: caught exception (code=0x%08X)", GetExceptionCode());
        result = -2;
    }
    return result;
}

static int __declspec(noinline) seh_level_1(int input) {
    int result = 0;
    __try {
        s_seh_depth = 1;
        log("SEH level 1: entering");
        result = seh_level_2(input);
        result += input;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("SEH level 1: caught exception (code=0x%08X)", GetExceptionCode());
        result = -1;
    }
    return result;
}

void __declspec(noinline) test_access_violation(const config_t& cfg) {
    log("Access violation test starting...");

    __try {
        volatile int* null_ptr = nullptr;
        volatile int val = *null_ptr;
        (void)val;
        log("ACCESS_VIOLATION: NOT triggered (unexpected)");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("ACCESS_VIOLATION: caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    __try {
        volatile int* null_ptr = nullptr;
        *null_ptr = 42;
        log("ACCESS_VIOLATION (write): NOT triggered (unexpected)");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("ACCESS_VIOLATION (write): caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    __try {
        volatile int* bad_ptr = (volatile int*)0xDEADBEEF00000000ULL;
        volatile int val = *bad_ptr;
        (void)val;
        log("ACCESS_VIOLATION (high addr): NOT triggered (unexpected)");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("ACCESS_VIOLATION (high addr): caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    log("Access violation test complete");
}

void __declspec(noinline) test_divide_by_zero(const config_t& cfg) {
    log("Divide-by-zero test starting...");

    __try {
        volatile int numerator = 100;
        volatile int denominator = 0;
        volatile int result = numerator / denominator;
        (void)result;
        log("INT_DIVIDE_BY_ZERO: NOT triggered (unexpected)");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("INT_DIVIDE_BY_ZERO: caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    log("Divide-by-zero test complete");
}

void __declspec(noinline) test_breakpoint(const config_t& cfg) {
    log("Breakpoint (INT3) test starting...");

    __try {
        __debugbreak();
        log("BREAKPOINT: continued past INT3");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("BREAKPOINT: caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    log("Breakpoint test complete");
}

void __declspec(noinline) test_single_step(const config_t& cfg) {
    log("Single-step test starting...");

    CONTEXT ctx_orig = {};
    ctx_orig.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(GetCurrentThread(), &ctx_orig)) {
        log("Single-step: current EFLAGS=0x%08X", (uint32_t)ctx_orig.EFlags);
    }

    __try {
        CONTEXT ctx_mod = {};
        ctx_mod.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(GetCurrentThread(), &ctx_mod);
        ctx_mod.EFlags |= 0x100;
        SetThreadContext(GetCurrentThread(), &ctx_mod);
        volatile int x = 42;
        (void)x;
    }
    __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        log("SINGLE_STEP: caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    log("Single-step test complete");
}

static LONG WINAPI custom_unhandled_filter(EXCEPTION_POINTERS* ep) {
    log("Custom unhandled filter invoked: code=0x%08X at %p",
        ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
    return EXCEPTION_EXECUTE_HANDLER;
}

void __declspec(noinline) test_unhandled_filter(const config_t& cfg) {
    log("Unhandled exception filter test starting...");

    LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(custom_unhandled_filter);
    log("Installed custom unhandled exception filter at %p", (void*)custom_unhandled_filter);
    log("Previous filter was at %p", (void*)prev);

    SetUnhandledExceptionFilter(prev);
    log("Restored previous unhandled exception filter");

    log("Unhandled exception filter test complete");
}

void __declspec(noinline) test_guard_page(const config_t& cfg) {
    log("Guard page test starting...");

    void* guard_mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
    if (!guard_mem) {
        log("Guard page: VirtualAlloc failed: %lu", GetLastError());
        return;
    }
    log("Guard page allocated at %p (PAGE_READWRITE | PAGE_GUARD)", guard_mem);

    __try {
        volatile int* p = (volatile int*)guard_mem;
        *p = 0x12345678;
        log("Guard page: write succeeded (guard consumed)");
    }
    __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        log("GUARD_PAGE_VIOLATION: caught via SEH (code=0x%08X)", GetExceptionCode());
    }

    __try {
        volatile int* p = (volatile int*)guard_mem;
        volatile int val = *p;
        log("Guard page: second access succeeded, value=0x%08X", val);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log("Guard page: second access unexpectedly faulted (code=0x%08X)", GetExceptionCode());
    }

    VirtualFree(guard_mem, 0, MEM_RELEASE);
    log("Guard page test complete");
}

static volatile int s_stack_depth_reached = 0;

#pragma warning(push)
#pragma warning(disable: 4717)
static void __declspec(noinline) stack_recurse(int depth) {
    volatile char buffer[1024];
    buffer[0] = (char)depth;
    s_stack_depth_reached = depth;
    stack_recurse(depth + 1);
}
#pragma warning(pop)

void __declspec(noinline) test_stack_overflow_guard(const config_t& cfg) {
    log("Stack overflow guard test starting...");

    __try {
        stack_recurse(0);
    }
    __except (GetExceptionCode() == EXCEPTION_STACK_OVERFLOW ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        log("STACK_OVERFLOW: caught at recursion depth %d (code=0x%08X)", s_stack_depth_reached, GetExceptionCode());
        if (_resetstkoflw()) {
            log("Stack guard page restored via _resetstkoflw()");
        } else {
            log("WARNING: _resetstkoflw() failed");
        }
    }

    log("Stack overflow guard test complete");
}

void __declspec(noinline) test_hw_breakpoint_surface(const config_t& cfg) {
    log("Hardware breakpoint surface test starting...");

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        log("Debug registers: DR0=0x%016llX DR1=0x%016llX DR2=0x%016llX DR3=0x%016llX",
            (uint64_t)ctx.Dr0, (uint64_t)ctx.Dr1, (uint64_t)ctx.Dr2, (uint64_t)ctx.Dr3);
        log("Debug registers: DR6=0x%016llX DR7=0x%016llX",
            (uint64_t)ctx.Dr6, (uint64_t)ctx.Dr7);
    } else {
        log("GetThreadContext failed for debug registers: %lu", GetLastError());
    }

    volatile int hw_bp_target = 0xBAADF00D;
    log("HW breakpoint target variable at %p (value=0x%08X)", (void*)&hw_bp_target, hw_bp_target);

    CONTEXT ctx_set = {};
    ctx_set.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(hThread, &ctx_set)) {
        ctx_set.Dr0 = (DWORD64)(uintptr_t)&hw_bp_target;
        ctx_set.Dr7 = (ctx_set.Dr7 & ~0x000F0003ULL) | 0x00030001ULL;
        if (SetThreadContext(hThread, &ctx_set)) {
            log("Set DR0 = %p (write watchpoint on hw_bp_target)", (void*)&hw_bp_target);
        } else {
            log("SetThreadContext for DR0 failed: %lu", GetLastError());
        }

        ctx_set.Dr0 = 0;
        ctx_set.Dr7 &= ~0x00000001ULL;
        SetThreadContext(hThread, &ctx_set);
        log("Cleared DR0");
    }

    log("Hardware breakpoint surface test complete");
}

void __declspec(noinline) test_veh_handler(const config_t& cfg) {
    log("VEH handler test starting...");

    PVOID veh_handle = AddVectoredExceptionHandler(1, veh_first_handler);
    if (veh_handle) {
        log("Registered VEH first-chance handler at %p (handle=%p)", (void*)veh_first_handler, veh_handle);
    } else {
        log("Failed to register VEH handler: %lu", GetLastError());
        return;
    }

    s_veh_hit_count = 0;

    __try {
        __debugbreak();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        log("VEH did not handle BREAKPOINT, fell through to SEH");
    }

    log("VEH total hits: %ld, last code: 0x%08X", s_veh_hit_count, s_last_veh_code);

    RemoveVectoredExceptionHandler(veh_handle);
    log("Removed VEH handler");

    log("VEH handler test complete");
}

void __declspec(noinline) test_seh_chain(const config_t& cfg) {
    log("SEH chain test starting (4-deep)...");

    int r1 = seh_level_1(5);
    log("SEH chain result (no exception): %d", r1);

    int r2 = seh_level_1(0);
    log("SEH chain result (exception at level 4): %d", r2);

    log("SEH chain test complete");
}

#pragma optimize("", on)

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Exception tests starting ===");

    test_veh_handler(cfg);
    test_seh_chain(cfg);
    test_access_violation(cfg);
    test_divide_by_zero(cfg);
    test_breakpoint(cfg);
    test_single_step(cfg);
    test_unhandled_filter(cfg);
    test_guard_page(cfg);
    test_stack_overflow_guard(cfg);
    test_hw_breakpoint_surface(cfg);

    log("=== Exception tests complete ===");
}

}
}
