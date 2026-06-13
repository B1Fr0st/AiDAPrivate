#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace net_proto_analysis {

struct sendrecv_scan_options_t {
    std::uint32_t process_id = 0;
    std::uint32_t max_results = 64;
    std::uint32_t max_modules = 32;
    std::uint64_t max_scan_bytes = 67108864;
};

struct serializer_trace_options_t {
    std::uint32_t process_id = 0;
    std::uint64_t serializer_va = 0;
    std::string buffer_reg = "rdx";
    std::string size_reg = "r8";
    std::uint32_t tid = 0;
    std::uint32_t max_captures = 16;
    std::uint32_t sample_ms = 2000;
};

struct udp_reassemble_options_t {
    std::uint32_t pid = 0;
    std::uint32_t capture_ms = 10000;
    std::uint32_t max_packets = 256;
    std::uint32_t max_payload = 1500;
    std::vector<std::vector<std::uint8_t>> fixture_payloads;
};

struct replay_mutate_options_t {
    std::string session_id;
    std::string target_ip;
    std::uint32_t target_port = 0;
    std::uint32_t source_port = 0;
    std::string mutation_strategy = "boundary";
    std::uint32_t max_mutations = 64;
    std::uint32_t payload_cap = 1024;
    std::uint32_t response_wait_ms = 500;
    bool allow_non_loopback = false;
    bool allow_unsafe = false;
    bool confirm_unsafe = false;
};

bool find_sendrecv_handlers(const sendrecv_scan_options_t& options,
                            nlohmann::json& out,
                            std::string& error);
bool trace_serializer(const serializer_trace_options_t& options,
                      nlohmann::json& out,
                      std::string& error);
bool reassemble_udp_sessions(const udp_reassemble_options_t& options,
                             nlohmann::json& out,
                             std::string& error);
bool replay_mutate(const replay_mutate_options_t& options,
                   nlohmann::json& out,
                   std::string& error);

}
