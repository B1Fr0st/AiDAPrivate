#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <atomic>
#include <cstdint>

#ifndef AIDA_TEST_TARGET_HWBP_API
#define AIDA_TEST_TARGET_HWBP_API __declspec(dllexport)
#endif

namespace test_target {
namespace hwbp_fixture {

struct config_t {
    bool verbose;
};

struct descriptor_t {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t size;
    std::uint32_t thread_id;
    std::uint32_t ready;
    std::uint32_t state;
    std::uint32_t generation;
    std::uint32_t reserved;
    std::uint64_t descriptor_va;
    std::uint64_t execute_fn_va;
    std::uint64_t data_va;
    std::uint64_t data_size;
    std::uint64_t hit_counter_va;
    std::uint64_t heartbeat_va;
    std::uint64_t thread_entry_va;
};

void init(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}

extern "C" AIDA_TEST_TARGET_HWBP_API test_target::hwbp_fixture::descriptor_t aida_test_hwbp_descriptor;
extern "C" AIDA_TEST_TARGET_HWBP_API __declspec(noinline) const test_target::hwbp_fixture::descriptor_t* aida_test_hwbp_get_descriptor() noexcept;
extern "C" AIDA_TEST_TARGET_HWBP_API __declspec(noinline) std::uint64_t aida_test_hwbp_execute_probe(std::uint64_t seed) noexcept;
