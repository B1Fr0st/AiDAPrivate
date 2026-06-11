#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <atomic>
#include <cstdint>

#ifndef AIDA_TEST_TARGET_FIXTURE_API
#define AIDA_TEST_TARGET_FIXTURE_API
#endif

namespace test_target {
namespace protected_re {

struct config_t {
    bool verbose;
    bool enabled;
};

struct descriptor_t {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t size;
    std::uint64_t module_base_va;
    std::uint64_t descriptor_va;
    std::uint64_t entropy_region_va;
    std::uint32_t entropy_region_size;
    std::uint32_t entropy_region_protection;
    std::uint64_t smc_region_va;
    std::uint32_t smc_region_size;
    std::uint32_t smc_key;
    std::uint64_t entry_fn_va;
    std::uint64_t vm_entry_fn_va;
    std::uint64_t cff_entry_fn_va;
    std::uint64_t mba_entry_fn_va;
    std::uint64_t opaque_entry_fn_va;
    std::uint64_t smc_helper_fn_va;
    std::uint64_t reserved[8];
};

void init(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}

extern "C" AIDA_TEST_TARGET_FIXTURE_API test_target::protected_re::descriptor_t aida_test_protected_re_descriptor;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) const test_target::protected_re::descriptor_t* aida_test_protected_re_get_descriptor() noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_protected_entry(std::uint32_t selector, std::uint32_t value) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_protected_vm_entry(const std::uint8_t* bytecode, std::uint32_t size, std::uint32_t seed) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_protected_cff_entry(std::uint32_t seed) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_protected_mba_entry(std::uint32_t x, std::uint32_t y) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_protected_opaque_entry(std::uint32_t x) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_protected_smc_decrypt(std::uint32_t action) noexcept;
