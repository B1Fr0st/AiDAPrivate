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
namespace re_fixtures {

struct config_t {
    bool verbose;
    bool enable_window;
};

struct descriptor_t {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t size;
    std::uint64_t module_base_va;
    std::uint64_t descriptor_va;
    std::uint64_t matrix_buffer_va;
    std::uint32_t matrix_count;
    std::uint32_t matrix_stride;
    std::uint64_t resource_object_va;
    std::uint64_t resource_backing_va;
    std::uint32_t resource_size;
    std::uint32_t resource_stride;
    std::uint64_t struct_base_va;
    std::uint64_t struct_array_va;
    std::uint32_t struct_count;
    std::uint32_t struct_size;
    std::uint64_t rtti_instance_va;
    std::uint64_t rtti_vtable_va;
    std::uint64_t heap_burst_fn_va;
    std::uint64_t heap_burst_first_va;
    std::uint32_t heap_burst_count;
    std::uint32_t heap_burst_stride;
    std::uint64_t mutate_struct_fn_va;
    std::uint64_t frame_tick_fn_va;
    std::uint64_t window_hwnd;
    std::uint64_t frame_counter_va;
    std::uint64_t d3d11_module_va;
    std::uint64_t dxgi_module_va;
    std::uint64_t reserved[8];
};

void init(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}

extern "C" AIDA_TEST_TARGET_FIXTURE_API test_target::re_fixtures::descriptor_t aida_test_re_descriptor;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) const test_target::re_fixtures::descriptor_t* aida_test_re_get_descriptor() noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint64_t aida_test_re_heap_burst(std::uint32_t count, std::uint32_t payload_size) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint64_t aida_test_re_mutate_struct(std::uint32_t index, std::uint32_t delta) noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint64_t aida_test_re_frame_tick(std::uint32_t frame_index) noexcept;
