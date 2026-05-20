#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace memory {

struct config_t {
    bool verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_aob_markers(const config_t& cfg);
void test_signature_patterns(const config_t& cfg);
void test_protection_flags(const config_t& cfg);
void test_function_pointers(const config_t& cfg);
void test_crypto_patterns(const config_t& cfg);

}
}
