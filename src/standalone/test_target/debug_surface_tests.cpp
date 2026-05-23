#include "debug_surface_tests.h"
#include "test_log.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace test_target {
namespace debug_surface {

static void log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[DBG] ");
    vprintf(fmt, ap);
    printf("\n");
    fflush(stdout);
    va_end(ap);
}

volatile int    g_watch_int    = 0;
volatile double g_watch_double = 0.0;
volatile void*  g_watch_ptr    = nullptr;

static volatile int s_shared_counter = 0;
static volatile int s_sink = 0;

static const char* const kStringTable[] = {
    "AiDA_DebugSurface_String_001", "AiDA_DebugSurface_String_002",
    "AiDA_DebugSurface_String_003", "AiDA_DebugSurface_String_004",
    "AiDA_DebugSurface_String_005", "AiDA_DebugSurface_String_006",
    "AiDA_DebugSurface_String_007", "AiDA_DebugSurface_String_008",
    "AiDA_DebugSurface_String_009", "AiDA_DebugSurface_String_010",
    "AiDA_DebugSurface_Sentinel_Alpha", "AiDA_DebugSurface_Sentinel_Beta",
    "AiDA_DebugSurface_Sentinel_Gamma", "AiDA_DebugSurface_Sentinel_Delta",
    "AiDA_DebugSurface_Sentinel_Epsilon", "AiDA_DebugSurface_Sentinel_Zeta",
    "AiDA_DebugSurface_Sentinel_Eta", "AiDA_DebugSurface_Sentinel_Theta",
    "AiDA_DebugSurface_Sentinel_Iota", "AiDA_DebugSurface_Sentinel_Kappa",
    "AiDA_DebugSurface_Crypto_Key_1", "AiDA_DebugSurface_Crypto_Key_2",
    "AiDA_DebugSurface_Crypto_Key_3", "AiDA_DebugSurface_Crypto_Key_4",
    "AiDA_DebugSurface_Network_Addr_1", "AiDA_DebugSurface_Network_Addr_2",
    "AiDA_DebugSurface_Network_Addr_3", "AiDA_DebugSurface_Network_Addr_4",
    "AiDA_DebugSurface_Config_Path_1", "AiDA_DebugSurface_Config_Path_2",
    "AiDA_DebugSurface_Config_Path_3", "AiDA_DebugSurface_Config_Path_4",
    "AiDA_DebugSurface_License_Token_1", "AiDA_DebugSurface_License_Token_2",
    "AiDA_DebugSurface_License_Token_3", "AiDA_DebugSurface_License_Token_4",
    "AiDA_DebugSurface_Driver_Name_1", "AiDA_DebugSurface_Driver_Name_2",
    "AiDA_DebugSurface_Driver_Name_3", "AiDA_DebugSurface_Driver_Name_4",
    "AiDA_DebugSurface_Module_Hash_1", "AiDA_DebugSurface_Module_Hash_2",
    "AiDA_DebugSurface_Module_Hash_3", "AiDA_DebugSurface_Module_Hash_4",
    "AiDA_DebugSurface_Session_ID_1", "AiDA_DebugSurface_Session_ID_2",
    "AiDA_DebugSurface_Session_ID_3", "AiDA_DebugSurface_Session_ID_4",
    "AiDA_DebugSurface_Watermark_1", "AiDA_DebugSurface_Watermark_2",
    "AiDA_DebugSurface_Watermark_3", "AiDA_DebugSurface_Watermark_4",
};

static const int kStringTableSize = sizeof(kStringTable) / sizeof(kStringTable[0]);

#pragma optimize("", off)

void __declspec(noinline) test_step_through(const config_t& cfg) {
    log("Step-through test starting (20+ operations)...");

    volatile int a = 10;
    volatile int b = 20;
    volatile int c = a + b;
    volatile int d = c - a;
    volatile int e = a * b;
    volatile int f = e / a;
    volatile int g = c % 7;
    volatile int h = a ^ b;
    volatile int i = a & 0xFF;
    volatile int j = b | 0x100;
    volatile int k = a << 3;
    volatile int l = e >> 2;
    volatile int m = ~c;
    volatile int n = -d;
    volatile int o = (a > b) ? a : b;
    volatile int p = a + b + c + d;
    volatile int q = (a * b) ^ (c + d);
    volatile uint32_t r = (uint32_t)e;
    r = (r << 13) | (r >> 19);
    volatile int s = (int)r + g;
    volatile int t = s * 3 - h;
    volatile int u = (t & 0xF0) | (s & 0x0F);
    volatile int v = u + i + j;

    s_sink = a + b + c + d + e + f + g + h + i + j + k + l + m + n + o + p + q + (int)r + s + t + u + v;

    log("Step-through result sink: %d", s_sink);
    log("  a=%d b=%d c=%d d=%d e=%d f=%d", a, b, c, d, e, f);
    log("  g=%d h=%d i=%d j=%d k=%d l=%d", g, h, i, j, k, l);
    log("  m=%d n=%d o=%d p=%d q=%d r=%u", m, n, o, p, q, r);
    log("  s=%d t=%d u=%d v=%d", s, t, u, v);

    log("Step-through test complete");
}

static volatile int s_bp_results[10] = {0};

void __declspec(noinline) breakpoint_target_1() {
    volatile int x = 11;
    s_bp_results[0] = x * x;
}

void __declspec(noinline) breakpoint_target_2() {
    volatile int x = 22;
    s_bp_results[1] = x + 100;
}

void __declspec(noinline) breakpoint_target_3() {
    volatile int x = 33;
    s_bp_results[2] = x ^ 0xFF;
}

void __declspec(noinline) breakpoint_target_4() {
    volatile int x = 44;
    s_bp_results[3] = x << 4;
}

void __declspec(noinline) breakpoint_target_5() {
    volatile int x = 55;
    s_bp_results[4] = x & 0x3F;
}

void __declspec(noinline) breakpoint_target_6() {
    volatile int x = 66;
    s_bp_results[5] = x | 0x700;
}

void __declspec(noinline) breakpoint_target_7() {
    volatile int x = 77;
    s_bp_results[6] = ~x;
}

void __declspec(noinline) breakpoint_target_8() {
    volatile int x = 88;
    s_bp_results[7] = x * 3 + 1;
}

void __declspec(noinline) breakpoint_target_9() {
    volatile int x = 99;
    s_bp_results[8] = x / 3;
}

void __declspec(noinline) breakpoint_target_10() {
    volatile int x = 110;
    s_bp_results[9] = x % 7;
}

typedef void(*bp_target_fn)();

static bp_target_fn s_bp_dispatch_table[10] = {
    breakpoint_target_1, breakpoint_target_2, breakpoint_target_3,
    breakpoint_target_4, breakpoint_target_5, breakpoint_target_6,
    breakpoint_target_7, breakpoint_target_8, breakpoint_target_9,
    breakpoint_target_10,
};

void __declspec(noinline) test_breakpoint_targets(const config_t& cfg) {
    log("Breakpoint targets test starting (10 targets)...");

    for (int i = 0; i < 10; ++i) {
        s_bp_dispatch_table[i]();
        log("breakpoint_target_%d at %p -> result=%d", i + 1, (void*)s_bp_dispatch_table[i], s_bp_results[i]);
    }

    for (int i = 9; i >= 0; --i) {
        s_bp_dispatch_table[i]();
    }

    log("Breakpoint targets test complete");
}

void __declspec(noinline) test_watchpoint_target(const config_t& cfg) {
    log("Watchpoint target test starting...");
    log("Watchpoint variables: g_watch_int=%p g_watch_double=%p g_watch_ptr=%p",
        (void*)&g_watch_int, (void*)&g_watch_double, (void*)&g_watch_ptr);

    for (int i = 0; i < 20; ++i) {
        g_watch_int = i * 7 + 3;
        g_watch_double = (double)i * 3.14159;
        g_watch_ptr = (void*)(uintptr_t)(0x10000 + i * 0x1000);

        if (cfg.verbose && i % 5 == 0) {
            log("Watchpoint iteration %d: int=%d double=%.4f ptr=%p",
                i, g_watch_int, g_watch_double, (void*)g_watch_ptr);
        }
    }

    log("Watchpoint target test complete (final: int=%d, double=%.4f, ptr=%p)",
        g_watch_int, g_watch_double, (void*)g_watch_ptr);
}

static DWORD WINAPI counter_thread_func(LPVOID param) {
    int thread_id = (int)(intptr_t)param;
    for (int i = 0; i < 100; ++i) {
        InterlockedIncrement((volatile LONG*)&s_shared_counter);
        Sleep(1);
    }
    return (DWORD)thread_id;
}

void __declspec(noinline) test_multithread_counter(const config_t& cfg) {
    log("Multi-thread counter test starting (5 threads x 100 increments)...");

    s_shared_counter = 0;
    HANDLE threads[5];
    DWORD tids[5];

    for (int i = 0; i < 5; ++i) {
        threads[i] = CreateThread(nullptr, 0, counter_thread_func, (LPVOID)(intptr_t)i, 0, &tids[i]);
        if (threads[i]) {
            log("Counter thread %d started (tid=%lu)", i, tids[i]);
        }
    }

    WaitForMultipleObjects(5, threads, TRUE, 10000);

    for (int i = 0; i < 5; ++i) {
        if (threads[i]) CloseHandle(threads[i]);
    }

    log("Multi-thread counter final value: %d (expected 500)", s_shared_counter);
    log("Multi-thread counter test complete");
}

static volatile int s_recursion_results[20] = {0};

int __declspec(noinline) deep_recurse(int depth, int a, int b) {
    volatile int local_state = a * depth + b;
    s_recursion_results[depth % 20] = local_state;

    if (depth >= 19) {
        return local_state;
    }

    switch (depth % 5) {
        case 0: return deep_recurse(depth + 1, a + 3, b ^ 0x1F) + local_state;
        case 1: return deep_recurse(depth + 1, a * 2, b - 7) + local_state;
        case 2: return deep_recurse(depth + 1, a ^ b, b + 11) + local_state;
        case 3: return deep_recurse(depth + 1, a - 1, b << 1) + local_state;
        case 4: return deep_recurse(depth + 1, a + b, b >> 1) + local_state;
        default: return local_state;
    }
}

void __declspec(noinline) test_deep_recursion(const config_t& cfg) {
    log("Deep recursion test starting (20 levels)...");

    int result = deep_recurse(0, 42, 17);
    log("Deep recursion result: %d", result);

    for (int i = 0; i < 20; ++i) {
        log("  recursion level %2d state: %d", i, s_recursion_results[i]);
    }

    log("Deep recursion test complete");
}

void __declspec(noinline) test_handle_leak(const config_t& cfg) {
    log("Handle leak test starting...");

    HANDLE events[10];
    for (int i = 0; i < 10; ++i) {
        wchar_t name[64];
        wsprintfW(name, L"AiDA_TestTarget_Event_%d", i);
        events[i] = CreateEventW(nullptr, FALSE, FALSE, name);
        if (events[i]) {
            log("Created event '%S' handle=%p", name, events[i]);
        }
    }

    HANDLE mutexes[5];
    for (int i = 0; i < 5; ++i) {
        wchar_t name[64];
        wsprintfW(name, L"AiDA_TestTarget_Mutex_%d", i);
        mutexes[i] = CreateMutexW(nullptr, FALSE, name);
        if (mutexes[i]) {
            log("Created mutex '%S' handle=%p", name, mutexes[i]);
        }
    }

    HANDLE files[3];
    for (int i = 0; i < 3; ++i) {
        wchar_t path[MAX_PATH];
        wchar_t temp_dir[MAX_PATH];
        GetTempPathW(MAX_PATH, temp_dir);
        wsprintfW(path, L"%saida_handle_test_%d.tmp", temp_dir, i);
        files[i] = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (files[i] != INVALID_HANDLE_VALUE) {
            const char* data = "AiDA handle test data";
            DWORD written = 0;
            WriteFile(files[i], data, (DWORD)strlen(data), &written, nullptr);
            log("Created file '%S' handle=%p (wrote %lu bytes)", path, files[i], written);
        }
    }

    log("Handle leak: %d events, %d mutexes, %d files open", 10, 5, 3);
    log("Handles intentionally kept open for enumeration testing");

    Sleep(500);

    for (int i = 0; i < 10; ++i) { if (events[i]) CloseHandle(events[i]); }
    for (int i = 0; i < 5; ++i) { if (mutexes[i]) CloseHandle(mutexes[i]); }
    for (int i = 0; i < 3; ++i) {
        if (files[i] != INVALID_HANDLE_VALUE) CloseHandle(files[i]);
    }

    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    for (int i = 0; i < 3; ++i) {
        wchar_t path[MAX_PATH];
        wsprintfW(path, L"%saida_handle_test_%d.tmp", temp_dir, i);
        DeleteFileW(path);
    }

    log("Handle leak test complete (all handles closed)");
}

void __declspec(noinline) test_string_table(const config_t& cfg) {
    log("String table test starting (%d strings)...", kStringTableSize);

    volatile int hash = 0;
    for (int i = 0; i < kStringTableSize; ++i) {
        const char* s = kStringTable[i];
        int len = (int)strlen(s);
        for (int j = 0; j < len; ++j)
            hash += s[j];

        if (cfg.verbose || i % 10 == 0) {
            log("String[%2d] at %p: \"%s\" (len=%d)", i, (const void*)s, s, len);
        }
    }

    log("String table hash accumulator: %d", hash);
    log("String table test complete");
}

static int __declspec(noinline) jt_op_add(int a, int b) { return a + b; }
static int __declspec(noinline) jt_op_sub(int a, int b) { return a - b; }
static int __declspec(noinline) jt_op_mul(int a, int b) { return a * b; }
static int __declspec(noinline) jt_op_div(int a, int b) { return b != 0 ? a / b : 0; }
static int __declspec(noinline) jt_op_mod(int a, int b) { return b != 0 ? a % b : 0; }
static int __declspec(noinline) jt_op_xor(int a, int b) { return a ^ b; }
static int __declspec(noinline) jt_op_and(int a, int b) { return a & b; }
static int __declspec(noinline) jt_op_or(int a, int b)  { return a | b; }
static int __declspec(noinline) jt_op_shl(int a, int b) { return a << (b & 31); }
static int __declspec(noinline) jt_op_shr(int a, int b) { return a >> (b & 31); }
static int __declspec(noinline) jt_op_neg(int a, int b) { (void)b; return -a; }
static int __declspec(noinline) jt_op_not(int a, int b) { (void)b; return ~a; }

typedef int(*jt_op_fn)(int, int);

static jt_op_fn s_jump_table[12] = {
    jt_op_add, jt_op_sub, jt_op_mul, jt_op_div,
    jt_op_mod, jt_op_xor, jt_op_and, jt_op_or,
    jt_op_shl, jt_op_shr, jt_op_neg, jt_op_not,
};

static const char* s_jt_names[12] = {
    "add", "sub", "mul", "div", "mod", "xor", "and", "or", "shl", "shr", "neg", "not"
};

void __declspec(noinline) test_jump_table(const config_t& cfg) {
    log("Jump table test starting (12 operations)...");
    log("Jump table at %p (%zu entries)", (void*)s_jump_table, sizeof(s_jump_table)/sizeof(s_jump_table[0]));

    int a = 100, b = 7;
    for (int i = 0; i < 12; ++i) {
        int result = s_jump_table[i](a, b);
        log("  jt[%2d] %s(%d, %d) at %p = %d", i, s_jt_names[i], a, b, (void*)s_jump_table[i], result);
    }

    for (int round = 0; round < 5; ++round) {
        int op = (round * 3 + 1) % 12;
        int val_a = round * 11 + 5;
        int val_b = round * 3 + 2;
        int result = s_jump_table[op](val_a, val_b);
        log("  computed dispatch: op=%d(%s) -> %s(%d,%d) = %d", op, s_jt_names[op], s_jt_names[op], val_a, val_b, result);
    }

    log("Jump table test complete");
}

#pragma optimize("", on)

void run_all(const config_t& cfg, std::atomic<bool>& running) {
    log("=== Debug surface tests starting ===");

    test_step_through(cfg);
    test_breakpoint_targets(cfg);
    test_watchpoint_target(cfg);
    test_multithread_counter(cfg);
    test_deep_recursion(cfg);
    test_handle_leak(cfg);
    test_string_table(cfg);
    test_jump_table(cfg);

    log("=== Debug surface tests complete ===");
}

}
}
