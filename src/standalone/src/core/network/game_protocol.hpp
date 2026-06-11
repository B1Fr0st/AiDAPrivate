#pragma once

#include "standalone_driver.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace game_protocol {

struct capture_options_t {
    std::uint32_t pid = 0;
    std::uint32_t protocol = 0;
    std::uint32_t capture_ms = 5000;
    std::uint32_t max_packets = 64;
    std::uint32_t max_payload = 1500;
};

struct replay_options_t {
    std::string session_id;
    std::string target_ip;
    std::uint32_t target_port = 0;
    std::uint32_t source_port = 0;
    std::string direction = "outbound";
    std::uint32_t max_packets = 32;
    std::uint32_t payload_cap = 1024;
    std::uint32_t replay_delay_ms = 0;
    bool allow_non_loopback = false;
    bool allow_unsafe = false;
    bool confirm_unsafe = false;
};

std::vector<std::uint8_t> hex_to_bytes(const std::string& text,
                                       std::string* error = nullptr,
                                       std::size_t max_bytes = 65536);
std::string bytes_to_hex(const std::uint8_t* data, std::size_t len, std::size_t max_bytes = 256);
std::string bytes_to_hex(const std::vector<std::uint8_t>& data, std::size_t max_bytes = 256);
double shannon_entropy(const std::uint8_t* data, std::size_t len);

bool capture_packets_bounded(const capture_options_t& options,
                             std::vector<driver_bridge::captured_packet_t>& out,
                             std::string& error);

nlohmann::json detect_protocols(const std::vector<driver_bridge::captured_packet_t>& packets,
                                std::size_t max_detected_packets = 32);
nlohmann::json decode_enet_packet(const std::vector<std::uint8_t>& packet,
                                  std::optional<std::uint32_t> channel_filter = std::nullopt);
nlohmann::json decode_payload_heuristic(const std::vector<std::uint8_t>& payload,
                                        const std::string& context_hint = {});

nlohmann::json record_replay_session(const capture_options_t& options,
                                     std::string& error);
nlohmann::json stop_replay_recording(const std::string& requested_session_id,
                                     std::uint32_t max_packets,
                                     std::string& error);
nlohmann::json list_replay_sessions();
bool replay_session(const replay_options_t& options,
                    nlohmann::json& out,
                    std::string& error);

}
