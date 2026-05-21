#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace exceptions {

struct config_t {
    bool verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_veh_handler(const config_t& cfg);
void test_seh_chain(const config_t& cfg);
void test_access_violation(const config_t& cfg);
void test_divide_by_zero(const config_t& cfg);
void test_breakpoint(const config_t& cfg);
void test_single_step(const config_t& cfg);
void test_unhandled_filter(const config_t& cfg);
void test_guard_page(const config_t& cfg);
void test_stack_overflow_guard(const config_t& cfg);
void test_hw_breakpoint_surface(const config_t& cfg);

}
}
