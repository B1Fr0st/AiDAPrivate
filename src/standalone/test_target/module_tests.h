#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace modules {

struct config_t {
    bool verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_load_system_dlls(const config_t& cfg);
void test_resolve_functions(const config_t& cfg);
void test_call_resolved(const config_t& cfg);
void test_enumerate_modules(const config_t& cfg);
void test_enumerate_threads(const config_t& cfg);
void test_get_peb(const config_t& cfg);
void test_dynamic_load_unload(const config_t& cfg);

}
}
