#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace debug_surface {

struct config_t {
    bool verbose;
};

extern volatile int    g_watch_int;
extern volatile double g_watch_double;
extern volatile void*  g_watch_ptr;

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_step_through(const config_t& cfg);
void test_breakpoint_targets(const config_t& cfg);
void test_watchpoint_target(const config_t& cfg);
void test_multithread_counter(const config_t& cfg);
void test_deep_recursion(const config_t& cfg);
void test_handle_leak(const config_t& cfg);
void test_string_table(const config_t& cfg);
void test_jump_table(const config_t& cfg);

}
}
