#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>

#include "network_tests.h"
#include "memory_tests.h"
#include "thread_tests.h"
#include "struct_tests.h"
#include "crypto_tests.h"
#include "exception_tests.h"
#include "debug_surface_tests.h"
#include "file_tests.h"
#include "module_tests.h"
#include "http_server_tests.h"
#include "traffic_generator.h"
#include "resident_state.h"
#include "test_log.h"

static std::atomic<bool> g_running{ true };
static std::atomic<bool> g_absorb_external_single_step{ false };
static volatile LONG     g_absorbed_single_step_count = 0;
static PVOID             g_debugger_veh_handle = nullptr;

static LONG CALLBACK debugger_exception_veh(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        g_absorb_external_single_step.load(std::memory_order_acquire)) {
#ifdef _M_X64
        ep->ContextRecord->EFlags &= ~0x100UL;
        const unsigned long long ip = static_cast<unsigned long long>(ep->ContextRecord->Rip);
#else
        ep->ContextRecord->EFlags &= ~0x100UL;
        const unsigned long long ip = static_cast<unsigned long long>(ep->ContextRecord->Eip);
#endif
        const LONG count = InterlockedIncrement(&g_absorbed_single_step_count);
        if (count <= 32 || (count % 256) == 0) {
            aida_target_printf("[target-debugger] absorbed external SINGLE_STEP count=%ld ip=0x%llX pid=%lu tid=%lu\n",
                count,
                ip,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()));
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI target_unhandled_exception_filter(EXCEPTION_POINTERS* ep) {
    DWORD code = 0;
    void* addr = nullptr;
    if (ep && ep->ExceptionRecord) {
        code = ep->ExceptionRecord->ExceptionCode;
        addr = ep->ExceptionRecord->ExceptionAddress;
    }

    aida_target_printf("[target-crash] UNHANDLED_EXCEPTION code=0x%08lX addr=%p pid=%lu tid=%lu\n",
        static_cast<unsigned long>(code),
        addr,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    if (ep && ep->ContextRecord) {
#ifdef _M_X64
        aida_target_printf("[target-crash] RIP=0x%016llX RSP=0x%016llX RBP=0x%016llX RAX=0x%016llX RCX=0x%016llX RDX=0x%016llX RFLAGS=0x%08lX\n",
            static_cast<unsigned long long>(ep->ContextRecord->Rip),
            static_cast<unsigned long long>(ep->ContextRecord->Rsp),
            static_cast<unsigned long long>(ep->ContextRecord->Rbp),
            static_cast<unsigned long long>(ep->ContextRecord->Rax),
            static_cast<unsigned long long>(ep->ContextRecord->Rcx),
            static_cast<unsigned long long>(ep->ContextRecord->Rdx),
            static_cast<unsigned long>(ep->ContextRecord->EFlags));

        const auto* sp = reinterpret_cast<const unsigned long long*>(ep->ContextRecord->Rsp);
        for (int i = 0; i < 8; ++i) {
            unsigned long long value = 0;
            __try {
                value = sp ? sp[i] : 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                aida_target_printf("[target-crash] stack[%02d]=<unreadable>\n", i);
                break;
            }
            aida_target_printf("[target-crash] stack[%02d]=0x%016llX\n", i, value);
        }
#else
        aida_target_printf("[target-crash] EIP=0x%08lX ESP=0x%08lX EBP=0x%08lX EAX=0x%08lX ECX=0x%08lX EDX=0x%08lX EFLAGS=0x%08lX\n",
            static_cast<unsigned long>(ep->ContextRecord->Eip),
            static_cast<unsigned long>(ep->ContextRecord->Esp),
            static_cast<unsigned long>(ep->ContextRecord->Ebp),
            static_cast<unsigned long>(ep->ContextRecord->Eax),
            static_cast<unsigned long>(ep->ContextRecord->Ecx),
            static_cast<unsigned long>(ep->ContextRecord->Edx),
            static_cast<unsigned long>(ep->ContextRecord->EFlags));
#endif
    }

    aida_target_log_close();
    return EXCEPTION_EXECUTE_HANDLER;
}

static void install_target_crash_handlers() {
    SetUnhandledExceptionFilter(target_unhandled_exception_filter);
    g_debugger_veh_handle = AddVectoredExceptionHandler(1, debugger_exception_veh);
    aida_target_printf("[target-log] crash handlers installed veh=%p pid=%lu tid=%lu\n",
        g_debugger_veh_handle,
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));
}

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        printf("[MAIN] Shutdown signal received (ctrl=%lu)\n", ctrl_type);
        fflush(stdout);
        g_running.store(false);
        return TRUE;
    }
    return FALSE;
}

#pragma optimize("", off)

int __declspec(noinline) test_branch_if_else(int x) {
    if (x > 100) {
        return x * 2 + 1;
    } else if (x > 50) {
        return x * 3 - 7;
    } else if (x > 0) {
        return x + 42;
    } else {
        return -x + 99;
    }
}

int __declspec(noinline) test_branch_switch(int opcode) {
    switch (opcode) {
        case 0x00: return 0;
        case 0x01: return 1;
        case 0x02: return opcode * opcode;
        case 0x10: return opcode + 16;
        case 0x20: return opcode - 32;
        case 0x30: return opcode ^ 0xFF;
        case 0x40: return opcode << 2;
        case 0x50: return opcode >> 1;
        case 0xFF: return -1;
        default:   return opcode;
    }
}

int __declspec(noinline) test_loop_sum(int n) {
    int sum = 0;
    for (int i = 1; i <= n; ++i) {
        sum += i;
        if (sum > 10000) break;
    }
    return sum;
}

int __declspec(noinline) test_nested_calls_leaf(int a, int b) {
    return a * b + (a ^ b);
}

int __declspec(noinline) test_nested_calls_mid(int x) {
    int a = test_nested_calls_leaf(x, x + 1);
    int b = test_nested_calls_leaf(x + 2, x + 3);
    return a + b;
}

int __declspec(noinline) test_nested_calls_outer(int start) {
    int result = 0;
    for (int i = 0; i < 5; ++i) {
        result += test_nested_calls_mid(start + i);
    }
    return result;
}

int __declspec(noinline) test_nested_calls_deep(int depth, int value) {
    if (depth <= 0) return value;
    return test_nested_calls_deep(depth - 1, value + depth);
}

int __declspec(noinline) test_bitwise_operations(uint32_t a, uint32_t b) {
    uint32_t r = a;
    r = (r << 13) | (r >> 19);
    r ^= b;
    r = (r >> 7) | (r << 25);
    r += a;
    r ^= (r >> 16);
    r *= 0x85EBCA6B;
    r ^= (r >> 13);
    r *= 0xC2B2AE35;
    r ^= (r >> 16);
    return (int)r;
}

void __declspec(noinline) test_xref_target_a() {
    volatile int x = 42;
    (void)x;
}

void __declspec(noinline) test_xref_target_b() {
    volatile int y = 99;
    (void)y;
}

void __declspec(noinline) test_xref_caller_1() {
    test_xref_target_a();
    test_xref_target_b();
}

void __declspec(noinline) test_xref_caller_2() {
    test_xref_target_a();
    test_xref_target_a();
    test_xref_target_b();
}

void __declspec(noinline) test_xref_caller_3() {
    test_xref_target_b();
}

static volatile int s_sink = 0;

void __declspec(noinline) test_string_references() {
    const char* strings[] = {
        "AiDA_TestTarget_StringRef_Alpha",
        "AiDA_TestTarget_StringRef_Beta",
        "AiDA_TestTarget_StringRef_Gamma",
        "AiDA_TestTarget_StringRef_Delta",
        "AiDA_TestTarget_StringRef_Epsilon",
        "AiDA_TestTarget_StringRef_Zeta",
    };
    for (int i = 0; i < 6; ++i) {
        s_sink += strings[i][0];
    }
}

int __declspec(noinline) test_complex_control_flow(int a, int b, int c) {
    int result = 0;

    for (int i = 0; i < a; ++i) {
        if (i % 3 == 0) {
            result += test_branch_if_else(i + b);
        } else if (i % 3 == 1) {
            result += test_branch_switch(i % 256);
        } else {
            result += test_loop_sum(i % 50);
        }

        if (result > c) {
            result = result % c;
        }
    }

    return result;
}

#pragma optimize("", on)

struct cli_args_t {
    uint16_t port;
    uint16_t http_port;
    uint32_t duration_sec;
    bool     verbose;
    bool     skip_network;
    uint32_t net_rate_ms;
    bool     no_external;
    bool     absorb_external_single_step;
};

static cli_args_t parse_args(int argc, char* argv[]) {
    cli_args_t args{};
    args.port = 9876;
    args.http_port = 18080;
    args.duration_sec = 0;
    args.verbose = false;
    args.skip_network = false;
    args.net_rate_ms = 1000;
    args.no_external = false;
    args.absorb_external_single_step = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            args.port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            args.duration_sec = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            args.http_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            args.verbose = true;
        } else if (strcmp(argv[i], "--skip-network") == 0) {
            args.skip_network = true;
        } else if (strcmp(argv[i], "--net-rate") == 0 && i + 1 < argc) {
            args.net_rate_ms = (uint32_t)atoi(argv[++i]);
            if (args.net_rate_ms < 50) args.net_rate_ms = 50;
        } else if (strcmp(argv[i], "--no-external") == 0) {
            args.no_external = true;
        } else if (strcmp(argv[i], "--absorb-external-single-step") == 0) {
            args.absorb_external_single_step = true;
        } else if (strcmp(argv[i], "--disable-single-step-absorber") == 0) {
            args.absorb_external_single_step = false;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("AiDA Test Target - CLI test surface for AiDAStandalone.exe\n");
            printf("Usage: AiDA_TestTarget.exe [options]\n");
            printf("  --port <n>        Listen port (default: 9876)\n");
            printf("  --http-port <n>   HTTP server port (default: 18080)\n");
            printf("  --duration <sec>  Run for N seconds then exit (0 = run until Ctrl+C)\n");
            printf("  --verbose         Enable verbose logging\n");
            printf("  --skip-network    Skip network tests\n");
            printf("  --net-rate <ms>   Traffic generator base interval in ms (default: 1000, min: 50)\n");
            printf("  --no-external     Disable opportunistic external DNS/HTTP attempts (loopback only)\n");
            printf("  --absorb-external-single-step  Enable hostile external SINGLE_STEP absorption\n");
            printf("  --disable-single-step-absorber Keep external SINGLE_STEP absorption disabled (default)\n");
            printf("  --help, -h        Show this help\n");
            exit(0);
        }
    }

    return args;
}

static cli_args_t s_args{};
static HANDLE     s_listener_thread = nullptr;

static void log_work_boundary(const char* name, const char* state) {
    printf("[work] %s %s tick=%llu pid=%lu tid=%lu\n",
           state ? state : "?",
           name ? name : "?",
           (unsigned long long)GetTickCount64(),
           GetCurrentProcessId(),
           GetCurrentThreadId());
    fflush(stdout);
}

static DWORD WINAPI tcp_listener_thread(LPVOID param) {
    (void)param;
    test_target::network::config_t ncfg{};
    ncfg.listen_port = s_args.port;
    ncfg.verbose = s_args.verbose;
    test_target::network::test_listen_socket(ncfg, g_running);
    return 0;
}

static DWORD WINAPI workload_orchestrator(LPVOID param) {
    (void)param;
    const cli_args_t& args = s_args;

    printf("[work] orchestrator thread started\n");
    fflush(stdout);

    if (g_running.load()) {
        log_work_boundary("structs", "BEGIN");
        test_target::structs::config_t scfg{};
        scfg.verbose = args.verbose;
        test_target::structs::run_all(scfg, g_running);
        log_work_boundary("structs", "END");
    }

    if (g_running.load()) {
        log_work_boundary("memory", "BEGIN");
        test_target::memory::config_t mcfg{};
        mcfg.verbose = args.verbose;
        test_target::memory::run_all(mcfg, g_running);
        log_work_boundary("memory", "END");
    }

    if (g_running.load()) {
        log_work_boundary("threads", "BEGIN");
        test_target::threads::config_t tcfg{};
        tcfg.verbose = args.verbose;
        test_target::threads::run_all(tcfg, g_running);
        log_work_boundary("threads", "END");
    }

    if (g_running.load()) {
        log_work_boundary("crypto", "BEGIN");
        test_target::crypto::config_t ccfg{};
        ccfg.verbose = args.verbose;
        test_target::crypto::run_all(ccfg, g_running);
        log_work_boundary("crypto", "END");
    }

    if (g_running.load()) {
        log_work_boundary("exceptions", "BEGIN");
        test_target::exceptions::config_t ecfg{};
        ecfg.verbose = args.verbose;
        test_target::exceptions::run_all(ecfg, g_running);
        log_work_boundary("exceptions", "END");
        g_absorb_external_single_step.store(args.absorb_external_single_step, std::memory_order_release);
        printf("[target-debugger] external SINGLE_STEP absorber %s after exception tests\n",
            args.absorb_external_single_step ? "enabled" : "disabled");
        fflush(stdout);
    }

    if (g_running.load()) {
        log_work_boundary("debug_surface", "BEGIN");
        test_target::debug_surface::config_t dcfg{};
        dcfg.verbose = args.verbose;
        test_target::debug_surface::run_all(dcfg, g_running);
        log_work_boundary("debug_surface", "END");
    }

    if (g_running.load()) {
        log_work_boundary("file_io", "BEGIN");
        test_target::file_io::config_t fcfg{};
        fcfg.verbose = args.verbose;
        test_target::file_io::run_all(fcfg, g_running);
        log_work_boundary("file_io", "END");
    }

    if (g_running.load()) {
        log_work_boundary("modules", "BEGIN");
        test_target::modules::config_t modcfg{};
        modcfg.verbose = args.verbose;
        test_target::modules::run_all(modcfg, g_running);
        log_work_boundary("modules", "END");
    }

    if (args.skip_network) {
        printf("[work] network tests skipped (--skip-network)\n");
        fflush(stdout);
        printf("[work] orchestrator thread stopped\n");
        fflush(stdout);
        return 0;
    }

    if (g_running.load()) {
        log_work_boundary("http_server", "BEGIN");
        test_target::http_server::config_t hcfg{};
        hcfg.port = args.http_port;
        hcfg.verbose = args.verbose;
        test_target::http_server::run_all(hcfg, g_running);
        log_work_boundary("http_server", "END");

        log_work_boundary("traffic", "BEGIN");
        test_target::traffic::config_t gcfg{};
        gcfg.base_port = args.port;
        gcfg.http_port = args.http_port;
        gcfg.rate_ms = args.net_rate_ms;
        gcfg.verbose = args.verbose;
        gcfg.no_external = args.no_external;
        gcfg.skip_network = args.skip_network;
        test_target::traffic::run_all(gcfg, g_running);
        log_work_boundary("traffic", "END");
    }

    if (g_running.load()) {
        s_listener_thread = CreateThread(nullptr, 0, tcp_listener_thread, nullptr, 0, nullptr);
        if (s_listener_thread) {
            printf("[net] tcp listener thread started on port %u\n", args.port);
        } else {
            printf("[net] tcp listener thread FAILED (err=%lu)\n", GetLastError());
        }
        fflush(stdout);
    }

    if (g_running.load() && !args.no_external) {
        log_work_boundary("network", "BEGIN");
        test_target::network::config_t ncfg{};
        ncfg.listen_port = args.port;
        ncfg.verbose = args.verbose;
        test_target::network::run_all(ncfg, g_running);
        log_work_boundary("network", "END");
    } else if (args.no_external) {
        printf("[work] external network probes skipped (--no-external, loopback only)\n");
        fflush(stdout);
    }

    printf("[work] orchestrator thread stopped\n");
    fflush(stdout);
    return 0;
}

static void log_sync_event_create(const char* name, HANDLE handle, DWORD gle, bool unavailable) {
    if (handle) {
        ResetEvent(handle);
        printf("[sync] created/reset %s ok existed=%d\n", name ? name : "", gle == ERROR_ALREADY_EXISTS ? 1 : 0);
    } else {
        printf("[sync] created %s %s (err=%lu)\n", name ? name : "", unavailable ? "unavailable" : "FAILED", gle);
    }
    fflush(stdout);
}

int main(int argc, char* argv[]) {
    char target_log_path[MAX_PATH * 2] = {};
    DWORD target_log_len = GetEnvironmentVariableA(
        "AIDA_TARGET_LOG_PATH",
        target_log_path,
        static_cast<DWORD>(sizeof(target_log_path)));
    if (target_log_len > 0 && target_log_len < sizeof(target_log_path))
        aida_target_log_set_file(target_log_path);
    else
        aida_target_log_set_file("C:\\Users\\Public\\Desktop\\aida_full_test.log");
    install_target_crash_handlers();
    s_args = parse_args(argc, argv);
    const cli_args_t& args = s_args;

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    HANDLE h_ready_local = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestReady");
    DWORD h_ready_local_gle = GetLastError();
    log_sync_event_create("Local\\WhosWhoTestReady", h_ready_local, h_ready_local_gle, false);

    HANDLE h_done_local = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestDone");
    DWORD h_done_local_gle = GetLastError();
    log_sync_event_create("Local\\WhosWhoTestDone", h_done_local, h_done_local_gle, false);

    HANDLE h_ready_global = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestReady");
    DWORD h_ready_global_gle = GetLastError();
    log_sync_event_create("Global\\WhosWhoTestReady", h_ready_global, h_ready_global_gle, true);

    HANDLE h_done_global = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestDone");
    DWORD h_done_global_gle = GetLastError();
    log_sync_event_create("Global\\WhosWhoTestDone", h_done_global, h_done_global_gle, true);

    printf("[MAIN] AiDA Test Target starting (port=%u, duration=%u, verbose=%s)\n",
           args.port, args.duration_sec, args.verbose ? "true" : "false");
    fflush(stdout);

    printf("[MAIN] PID: %lu\n", GetCurrentProcessId());
    printf("[MAIN] Module base: %p\n", (void*)GetModuleHandleW(nullptr));
    fflush(stdout);

    printf("[MAIN] Running control flow tests...\n");
    fflush(stdout);

    s_sink += test_branch_if_else(200);
    s_sink += test_branch_if_else(75);
    s_sink += test_branch_if_else(25);
    s_sink += test_branch_if_else(-10);

    s_sink += test_branch_switch(0x01);
    s_sink += test_branch_switch(0x30);
    s_sink += test_branch_switch(0xFF);
    s_sink += test_branch_switch(0x99);

    s_sink += test_loop_sum(100);
    s_sink += test_nested_calls_outer(1);
    s_sink += test_nested_calls_deep(10, 0);
    s_sink += test_bitwise_operations(0xDEADBEEF, 0xCAFEBABE);

    test_xref_caller_1();
    test_xref_caller_2();
    test_xref_caller_3();
    test_string_references();

    s_sink += test_complex_control_flow(20, 50, 5000);

    printf("[MAIN] Control flow sink value: %d\n", s_sink);
    fflush(stdout);

    {
        test_target::resident::config_t rcfg{};
        rcfg.verbose = args.verbose;
        test_target::resident::init(rcfg, g_running);
    }

    HANDLE orchestrator_thread = CreateThread(nullptr, 0, workload_orchestrator, nullptr, 0, nullptr);
    if (orchestrator_thread) {
        printf("[MAIN] Workload orchestrator dispatched on background thread handle=%p\n", orchestrator_thread);
    } else {
        printf("[MAIN] Workload orchestrator FAILED to start (err=%lu); READY will still be signaled for attach diagnostics\n", GetLastError());
    }
    fflush(stdout);

    printf("READY\n");
    fflush(stdout);

    if (h_ready_local) {
        SetEvent(h_ready_local);
        printf("[sync] signaled Local\\WhosWhoTestReady\n");
    }
    if (h_ready_global) {
        SetEvent(h_ready_global);
        printf("[sync] signaled Global\\WhosWhoTestReady\n");
    }
    fflush(stdout);

    ULONGLONG start_tick = GetTickCount64();

    printf("[MAIN] Entering main loop (Ctrl+C to stop)\n");
    fflush(stdout);

    bool done_event_shutdown = false;
    uint64_t loop_counter = 0;
    while (g_running.load()) {
        DWORD wait_result;
        if (h_done_local && h_done_global) {
            HANDLE done_handles[2] = { h_done_local, h_done_global };
            wait_result = WaitForMultipleObjects(2, done_handles, FALSE, 1000);
            if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_OBJECT_0 + 1) {
                printf("[sync] WhosWhoTestDone signaled -- exiting\n");
                fflush(stdout);
                done_event_shutdown = true;
                g_running.store(false);
            }
        } else if (h_done_local) {
            wait_result = WaitForSingleObject(h_done_local, 1000);
            if (wait_result == WAIT_OBJECT_0) {
                printf("[sync] WhosWhoTestDone signaled -- exiting\n");
                fflush(stdout);
                done_event_shutdown = true;
                g_running.store(false);
            }
        } else if (h_done_global) {
            wait_result = WaitForSingleObject(h_done_global, 1000);
            if (wait_result == WAIT_OBJECT_0) {
                printf("[sync] WhosWhoTestDone signaled -- exiting\n");
                fflush(stdout);
                done_event_shutdown = true;
                g_running.store(false);
            }
        } else {
            Sleep(1000);
        }
        loop_counter++;

        if ((loop_counter % 5) == 0) {
            ULONGLONG elapsed = (GetTickCount64() - start_tick) / 1000;
            DWORD orch_wait = orchestrator_thread ? WaitForSingleObject(orchestrator_thread, 0) : WAIT_FAILED;
            DWORD listener_wait = s_listener_thread ? WaitForSingleObject(s_listener_thread, 0) : WAIT_FAILED;
            printf("[MAIN] Heartbeat: elapsed=%llu sec loop=%llu running=%d orchestrator_wait=0x%08lX listener_wait=0x%08lX single_steps=%ld\n",
                elapsed,
                static_cast<unsigned long long>(loop_counter),
                g_running.load() ? 1 : 0,
                static_cast<unsigned long>(orch_wait),
                static_cast<unsigned long>(listener_wait),
                static_cast<long>(g_absorbed_single_step_count));
            fflush(stdout);
        }

        if (args.verbose && loop_counter % 10 == 0) {
            ULONGLONG elapsed = (GetTickCount64() - start_tick) / 1000;
            printf("[MAIN] Alive: %llu sec, loop iteration %llu\n", elapsed, loop_counter);
            fflush(stdout);
        }

        if (args.duration_sec > 0) {
            ULONGLONG elapsed_sec = (GetTickCount64() - start_tick) / 1000;
            if (elapsed_sec >= args.duration_sec) {
                printf("[MAIN] Duration expired (%u sec)\n", args.duration_sec);
                fflush(stdout);
                g_running.store(false);
            }
        }
    }

    printf("[MAIN] Shutting down...\n");
    fflush(stdout);

    if (done_event_shutdown) {
        // The full-test harness force-kills after 6s; keep the done-event path bounded.
        printf("[MAIN] Done-event fast shutdown path active\n");
        fflush(stdout);

        if (orchestrator_thread) {
            DWORD wr = WaitForSingleObject(orchestrator_thread, 1500);
            printf("[MAIN] Workload orchestrator fast wait result=0x%08lX err=%lu\n",
                   wr, wr == WAIT_FAILED ? GetLastError() : 0);
            CloseHandle(orchestrator_thread);
            orchestrator_thread = nullptr;
        }

        if (s_listener_thread) {
            DWORD wr = WaitForSingleObject(s_listener_thread, 1000);
            printf("[net] tcp listener fast wait result=0x%08lX err=%lu\n",
                   wr, wr == WAIT_FAILED ? GetLastError() : 0);
            CloseHandle(s_listener_thread);
            s_listener_thread = nullptr;
        }

        if (g_debugger_veh_handle) {
            RemoveVectoredExceptionHandler(g_debugger_veh_handle);
            g_debugger_veh_handle = nullptr;
        }

        if (h_ready_local) CloseHandle(h_ready_local);
        if (h_done_local) CloseHandle(h_done_local);
        if (h_ready_global) CloseHandle(h_ready_global);
        if (h_done_global) CloseHandle(h_done_global);

        printf("[MAIN] AiDA Test Target exited via done-event fast path\n");
        fflush(stdout);
        aida_target_log_close();
        ExitProcess(0);
    }

    if (orchestrator_thread) {
        DWORD wr = WaitForSingleObject(orchestrator_thread, 10000);
        printf("[MAIN] Workload orchestrator wait result=0x%08lX err=%lu\n",
               wr, wr == WAIT_FAILED ? GetLastError() : 0);
        CloseHandle(orchestrator_thread);
        orchestrator_thread = nullptr;
        printf("[MAIN] Workload orchestrator joined\n");
        fflush(stdout);
    }

    if (s_listener_thread) {
        DWORD wr = WaitForSingleObject(s_listener_thread, 5000);
        printf("[net] tcp listener wait result=0x%08lX err=%lu\n",
               wr, wr == WAIT_FAILED ? GetLastError() : 0);
        CloseHandle(s_listener_thread);
        s_listener_thread = nullptr;
        printf("[net] tcp listener thread joined\n");
        fflush(stdout);
    }

    test_target::threads::shutdown_all();
    test_target::traffic::shutdown_all();
    test_target::http_server::shutdown_all();
    test_target::resident::shutdown_all();

    if (h_ready_local) CloseHandle(h_ready_local);
    if (h_done_local) CloseHandle(h_done_local);
    if (h_ready_global) CloseHandle(h_ready_global);
    if (h_done_global) CloseHandle(h_done_global);

    printf("[MAIN] AiDA Test Target exited cleanly\n");
    fflush(stdout);
    aida_target_log_close();

    return 0;
}
