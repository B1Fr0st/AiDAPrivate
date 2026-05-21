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

static std::atomic<bool> g_running{ true };

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
            printf("  --help, -h        Show this help\n");
            exit(0);
        }
    }

    return args;
}

int main(int argc, char* argv[]) {
    cli_args_t args = parse_args(argc, argv);

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    HANDLE h_ready_local = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestReady");
    if (h_ready_local) {
        printf("[sync] created Local\\WhosWhoTestReady ok\n");
    } else {
        printf("[sync] created Local\\WhosWhoTestReady FAILED (err=%lu)\n", GetLastError());
    }
    fflush(stdout);

    HANDLE h_done_local = CreateEventW(nullptr, TRUE, FALSE, L"Local\\WhosWhoTestDone");
    if (h_done_local) {
        printf("[sync] created Local\\WhosWhoTestDone ok\n");
    } else {
        printf("[sync] created Local\\WhosWhoTestDone FAILED (err=%lu)\n", GetLastError());
    }
    fflush(stdout);

    HANDLE h_ready_global = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestReady");
    if (h_ready_global) {
        printf("[sync] created Global\\WhosWhoTestReady ok\n");
    } else {
        printf("[sync] created Global\\WhosWhoTestReady unavailable (err=%lu)\n", GetLastError());
    }
    fflush(stdout);

    HANDLE h_done_global = CreateEventW(nullptr, TRUE, FALSE, L"Global\\WhosWhoTestDone");
    if (h_done_global) {
        printf("[sync] created Global\\WhosWhoTestDone ok\n");
    } else {
        printf("[sync] created Global\\WhosWhoTestDone unavailable (err=%lu)\n", GetLastError());
    }
    fflush(stdout);

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
        test_target::structs::config_t scfg{};
        scfg.verbose = args.verbose;
        test_target::structs::run_all(scfg, g_running);
    }

    {
        test_target::memory::config_t mcfg{};
        mcfg.verbose = args.verbose;
        test_target::memory::run_all(mcfg, g_running);
    }

    {
        test_target::threads::config_t tcfg{};
        tcfg.verbose = args.verbose;
        test_target::threads::run_all(tcfg, g_running);
    }

    {
        test_target::crypto::config_t ccfg{};
        ccfg.verbose = args.verbose;
        test_target::crypto::run_all(ccfg, g_running);
    }

    {
        test_target::exceptions::config_t ecfg{};
        ecfg.verbose = args.verbose;
        test_target::exceptions::run_all(ecfg, g_running);
    }

    {
        test_target::debug_surface::config_t dcfg{};
        dcfg.verbose = args.verbose;
        test_target::debug_surface::run_all(dcfg, g_running);
    }

    {
        test_target::file_io::config_t fcfg{};
        fcfg.verbose = args.verbose;
        test_target::file_io::run_all(fcfg, g_running);
    }

    {
        test_target::modules::config_t modcfg{};
        modcfg.verbose = args.verbose;
        test_target::modules::run_all(modcfg, g_running);
    }

    if (!args.skip_network) {
        test_target::network::config_t ncfg{};
        ncfg.listen_port = args.port;
        ncfg.verbose = args.verbose;
        test_target::network::run_all(ncfg, g_running);
    } else {
        printf("[MAIN] Network tests skipped (--skip-network)\n");
        fflush(stdout);
    }

    if (!args.skip_network) {
        test_target::http_server::config_t hcfg{};
        hcfg.port = args.http_port;
        hcfg.verbose = args.verbose;
        test_target::http_server::run_all(hcfg, g_running);

        test_target::traffic::config_t gcfg{};
        gcfg.base_port = args.port;
        gcfg.http_port = args.http_port;
        gcfg.rate_ms = args.net_rate_ms;
        gcfg.verbose = args.verbose;
        gcfg.no_external = args.no_external;
        gcfg.skip_network = args.skip_network;
        test_target::traffic::run_all(gcfg, g_running);
    }

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

    if (!args.skip_network) {
        HANDLE listen_thread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
            cli_args_t* a = (cli_args_t*)param;
            test_target::network::config_t ncfg{};
            ncfg.listen_port = a->port;
            ncfg.verbose = a->verbose;
            test_target::network::test_listen_socket(ncfg, g_running);
            return 0;
        }, &args, 0, nullptr);

        if (listen_thread) CloseHandle(listen_thread);
    }

    printf("[MAIN] Entering main loop (Ctrl+C to stop)\n");
    fflush(stdout);

    uint64_t loop_counter = 0;
    while (g_running.load()) {
        DWORD wait_result;
        if (h_done_local && h_done_global) {
            HANDLE done_handles[2] = { h_done_local, h_done_global };
            wait_result = WaitForMultipleObjects(2, done_handles, FALSE, 1000);
            if (wait_result == WAIT_OBJECT_0 || wait_result == WAIT_OBJECT_0 + 1) {
                printf("[sync] WhosWhoTestDone signaled -- exiting\n");
                fflush(stdout);
                g_running.store(false);
            }
        } else if (h_done_local) {
            wait_result = WaitForSingleObject(h_done_local, 1000);
            if (wait_result == WAIT_OBJECT_0) {
                printf("[sync] WhosWhoTestDone signaled -- exiting\n");
                fflush(stdout);
                g_running.store(false);
            }
        } else {
            Sleep(1000);
        }
        loop_counter++;

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

    test_target::threads::shutdown_all();
    test_target::traffic::shutdown_all();
    test_target::http_server::shutdown_all();

    if (h_ready_local) CloseHandle(h_ready_local);
    if (h_done_local) CloseHandle(h_done_local);
    if (h_ready_global) CloseHandle(h_ready_global);
    if (h_done_global) CloseHandle(h_done_global);

    printf("[MAIN] AiDA Test Target exited cleanly\n");
    fflush(stdout);

    return 0;
}
