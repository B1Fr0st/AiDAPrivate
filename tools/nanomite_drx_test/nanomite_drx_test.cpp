#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <thread>
#include <vector>
#include <chrono>

#include "nanomites.hpp"

#pragma optimize("", off)

extern "C" __declspec(noinline) int target_func(int x, int y)
{
    int result = 0;
    if (x > 5)
    {
        result += 100;
        if (y < 0)
            result += 11;
        else
            result += 22;
    }
    else if (x == 0)
    {
        result += 200;
    }
    else
    {
        result += 300;
        if (y == 7)
            result += 33;
        else
            result += 44;
    }
    if (result > 250)
        result += 1000;
    else
        result += 2000;
    return result;
}

#pragma optimize("", on)

static int reference_target(int x, int y)
{
    int result = 0;
    if (x > 5)
    {
        result += 100;
        if (y < 0)
            result += 11;
        else
            result += 22;
    }
    else if (x == 0)
    {
        result += 200;
    }
    else
    {
        result += 300;
        if (y == 7)
            result += 33;
        else
            result += 44;
    }
    if (result > 250)
        result += 1000;
    else
        result += 2000;
    return result;
}

static size_t estimate_func_size(uint8_t* func_bytes, size_t cap)
{
    for (size_t i = 0; i + 1 < cap; ++i)
    {
        if (func_bytes[i] == 0xC3 && (i == 0 || func_bytes[i - 1] != 0x40))
        {
            for (size_t j = i + 1; j < (i + 16) && j < cap; ++j)
            {
                if (func_bytes[j] == 0xCC)
                    return i + 1;
            }
            return i + 1;
        }
    }
    return cap;
}

static int g_failures = 0;

static void check_eq(const char* name, int got, int expected)
{
    if (got != expected)
    {
        std::printf("[FAIL] %s: got=%d expected=%d\n", name, got, expected);
        g_failures++;
    }
    else
    {
        std::printf("[PASS] %s: got=%d\n", name, got);
    }
}

static std::atomic<int> g_thread_failures{0};

static void worker(int tid, int iterations)
{
    for (int i = 0; i < iterations; ++i)
    {
        int x = (i * 31 + tid * 7) % 13 - 5;
        int y = ((i * 17) % 19) - 9;
        int got = target_func(x, y);
        int expected = reference_target(x, y);
        if (got != expected)
        {
            g_thread_failures.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    }
}

int main(int /*argc*/, char** /*argv*/)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== nanomite_drx_test starting ===\n");
    std::printf("target_func address: %p\n", reinterpret_cast<void*>(&target_func));

    uint8_t snapshot_before[1024];
    size_t snapshot_size = sizeof(snapshot_before);
    std::memcpy(snapshot_before,
                reinterpret_cast<const void*>(&target_func),
                snapshot_size);

    size_t func_size = estimate_func_size(snapshot_before, snapshot_size);
    if (func_size < 32) func_size = 256;
    std::printf("estimated func_size: %zu\n", func_size);

    int sanity1 = target_func(10, -3);
    int ref1 = reference_target(10, -3);
    check_eq("pre_protect target_func(10,-3)", sanity1, ref1);

    int sanity2 = target_func(0, 0);
    int ref2 = reference_target(0, 0);
    check_eq("pre_protect target_func(0,0)", sanity2, ref2);

    int sanity3 = target_func(3, 7);
    int ref3 = reference_target(3, 7);
    check_eq("pre_protect target_func(3,7)", sanity3, ref3);

    if (!anti_tamper::nanomites::initialize())
    {
        std::printf("[FAIL] nanomites::initialize() returned false\n");
        return 1;
    }
    std::printf("[PASS] nanomites::initialize() ok\n");

    uintptr_t func_addr = reinterpret_cast<uintptr_t>(&target_func);
    uint32_t replaced = anti_tamper::nanomites::protect_function(func_addr, func_size);
    std::printf("protect_function replaced: %u\n", replaced);
    if (replaced == 0)
    {
        std::printf("[FAIL] no Jcc sites found in target_func\n");
        anti_tamper::nanomites::shutdown();
        return 2;
    }

    uint8_t snapshot_after[1024];
    std::memcpy(snapshot_after,
                reinterpret_cast<const void*>(&target_func),
                snapshot_size);

    bool bytes_unchanged = (std::memcmp(snapshot_before, snapshot_after, func_size) == 0);
    if (!bytes_unchanged)
    {
        std::printf("[FAIL] .text bytes were modified by protect_function!\n");
        size_t differences = 0;
        for (size_t i = 0; i < func_size; ++i)
        {
            if (snapshot_before[i] != snapshot_after[i])
            {
                if (differences < 16)
                {
                    std::printf("  diff @ +%zu: %02X -> %02X\n",
                                i, snapshot_before[i], snapshot_after[i]);
                }
                differences++;
            }
        }
        std::printf("  total byte differences: %zu\n", differences);
        g_failures++;
    }
    else
    {
        std::printf("[PASS] .text bytes are bit-identical after protect_function (no 0xCC inserted)\n");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    int post1 = target_func(10, -3);
    check_eq("post_protect target_func(10,-3)", post1, ref1);
    int post2 = target_func(0, 0);
    check_eq("post_protect target_func(0,0)", post2, ref2);
    int post3 = target_func(3, 7);
    check_eq("post_protect target_func(3,7)", post3, ref3);
    int post4 = target_func(7, 1);
    int ref4 = reference_target(7, 1);
    check_eq("post_protect target_func(7,1)", post4, ref4);
    int post5 = target_func(1, 2);
    int ref5 = reference_target(1, 2);
    check_eq("post_protect target_func(1,2)", post5, ref5);

    std::printf("dispatch_count after single-thread tests: %llu\n",
                static_cast<unsigned long long>(anti_tamper::nanomites::dispatch_count()));

    std::printf("--- multi-thread test (3 workers x 10000 iters) ---\n");
    g_thread_failures.store(0);
    std::thread t1(worker, 1, 10000);
    std::thread t2(worker, 2, 10000);
    std::thread t3(worker, 3, 10000);
    t1.join();
    t2.join();
    t3.join();

    int tf = g_thread_failures.load();
    if (tf != 0)
    {
        std::printf("[FAIL] multi-thread mismatches: %d\n", tf);
        g_failures++;
    }
    else
    {
        std::printf("[PASS] multi-thread (3x10000=30000 calls) zero mismatches\n");
    }

    std::printf("dispatch_count after multi-thread tests: %llu\n",
                static_cast<unsigned long long>(anti_tamper::nanomites::dispatch_count()));

    bool integrity_ok = anti_tamper::nanomites::verify_table_integrity();
    if (!integrity_ok)
    {
        std::printf("[FAIL] verify_table_integrity returned false\n");
        g_failures++;
    }
    else
    {
        std::printf("[PASS] verify_table_integrity ok\n");
    }

    anti_tamper::nanomites::rotate_keys();
    std::printf("[PASS] rotate_keys returned\n");

    integrity_ok = anti_tamper::nanomites::verify_table_integrity();
    if (!integrity_ok)
    {
        std::printf("[FAIL] verify_table_integrity after rotate_keys\n");
        g_failures++;
    }
    else
    {
        std::printf("[PASS] verify_table_integrity ok after rotate_keys\n");
    }

    int after_rot = target_func(10, -3);
    check_eq("after_rotate_keys target_func(10,-3)", after_rot, ref1);

    std::printf("--- explicit rotation sweep across all entries ---\n");
    uint64_t baseline_dispatch = anti_tamper::nanomites::dispatch_count();
    int rot_failures = 0;
    for (int rot = 0; rot < 8; ++rot)
    {
        anti_tamper::nanomites::rotate_drx_assignment();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        for (int x = -3; x <= 12; ++x)
        {
            for (int y = -5; y <= 10; ++y)
            {
                int got = target_func(x, y);
                int exp = reference_target(x, y);
                if (got != exp) rot_failures++;
            }
        }
    }
    if (rot_failures > 0)
    {
        std::printf("[FAIL] rotation sweep mismatches=%d\n", rot_failures);
        g_failures++;
    }
    else
    {
        std::printf("[PASS] rotation sweep zero mismatches\n");
    }
    uint64_t after_dispatch = anti_tamper::nanomites::dispatch_count();
    std::printf("dispatch_count delta during rotation sweep: %llu\n",
                static_cast<unsigned long long>(after_dispatch - baseline_dispatch));

    anti_tamper::nanomites::shutdown();
    std::printf("[PASS] nanomites::shutdown() ok\n");

    if (g_failures == 0)
    {
        std::printf("\nNANOMITE_DRX_TEST_PASSED\n");
        return 0;
    }
    std::printf("\nNANOMITE_DRX_TEST_FAILED (failures=%d)\n", g_failures);
    return 3;
}
