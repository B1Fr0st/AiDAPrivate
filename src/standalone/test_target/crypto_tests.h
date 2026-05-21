#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <cstdint>
#include <atomic>

namespace test_target {
namespace crypto {

struct config_t {
    bool verbose;
};

void run_all(const config_t& cfg, std::atomic<bool>& running);

void test_aes128_ecb(const config_t& cfg);
void test_sha256(const config_t& cfg);
void test_rc4(const config_t& cfg);
void test_xor_strings(const config_t& cfg);
void test_base64(const config_t& cfg);
void test_crc32(const config_t& cfg);
void test_constant_time_compare(const config_t& cfg);
void test_tea(const config_t& cfg);
void test_crypto_context(const config_t& cfg);

}
}
