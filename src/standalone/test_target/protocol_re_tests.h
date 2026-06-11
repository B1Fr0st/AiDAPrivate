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
namespace protocol_re {

struct config_t {
    bool verbose;
    bool enabled;
    std::uint32_t rate_ms;
};

struct descriptor_t {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t size;
    std::uint64_t descriptor_va;
    std::uint64_t context_va;
    std::uint64_t marker_va;
    std::uint32_t marker_size;
    std::uint32_t listen_port;
    std::uint32_t send_port;
    std::uint32_t worker_thread_id;
    std::uint32_t rate_ms;
    std::uint64_t emit_fn_va;
    std::uint64_t packets_sent;
    std::uint64_t framed_packets_sent;
    std::uint64_t enet_packets_sent;
    std::uint64_t bytes_sent;
    std::uint64_t reserved[8];
};

void init(const config_t& cfg, std::atomic<bool>& running);
void shutdown_all();

}
}

extern "C" AIDA_TEST_TARGET_FIXTURE_API test_target::protocol_re::descriptor_t aida_test_proto_re_descriptor;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) const test_target::protocol_re::descriptor_t* aida_test_proto_re_get_descriptor() noexcept;
extern "C" AIDA_TEST_TARGET_FIXTURE_API __declspec(noinline) std::uint32_t aida_test_proto_emit_capture(void* ctx, std::uint8_t* buffer, std::uint32_t size) noexcept;
