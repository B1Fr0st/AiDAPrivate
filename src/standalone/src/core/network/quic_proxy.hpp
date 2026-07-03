#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "protocol_parser.hpp"

namespace mitm_proxy {
namespace quic_proxy {

struct quic_proxy_config {
    std::string bind_addr = "127.0.0.1";
    uint16_t bind_port = 8443;
    uint16_t expected_origin_port = 443;
    size_t max_datagram_size = 65535;
    size_t max_observations = 512;
    bool fail_closed_without_tls_keys = true;
    bool observation_only = true;
};

struct http3_frame {
    uint64_t type = 0;
    uint64_t length = 0;
    size_t payload_offset = 0;
    bool valid = false;
};

struct quic_observation {
    uint64_t timestamp = 0;
    uint64_t listener_id = 0;
    std::string client_addr;
    uint16_t client_port = 0;
    uint16_t local_port = 0;
    size_t datagram_size = 0;
    bool is_quic = false;
    bool decrypted = false;
    bool tls_client_hello_available = false;
    bool http3_frames_available = false;
    protocol_parser::quic_header header;
    protocol_parser::tls_client_hello client_hello;
    std::vector<http3_frame> http3_frames;
    std::string unsupported_reason;
};

struct quic_proxy_stats {
    bool running = false;
    size_t listener_count = 0;
    uint64_t datagrams = 0;
    uint64_t bytes_in = 0;
    uint64_t quic_packets = 0;
    uint64_t non_quic_packets = 0;
    uint64_t dropped_unsupported = 0;
    uint64_t parse_errors = 0;
    uint64_t http3_frames = 0;
    bool observation_only = true;
    bool mitm_supported = false;
    std::string last_error;
    std::string contract;
    std::string last_packet_type;
    std::string last_version;
    std::string last_sni;
};

bool start(const quic_proxy_config& config, uint64_t* listener_id = nullptr);
bool stop(uint64_t listener_id);
void stop_all();
bool is_running();
quic_proxy_stats get_stats();
std::vector<quic_observation> get_observations(size_t max_count = 0);
quic_observation classify_datagram(const uint8_t* data,
                                   size_t len,
                                   uint16_t dst_port,
                                   const std::string& client_addr = {},
                                   uint16_t client_port = 0,
                                   uint64_t listener_id = 0);
std::vector<http3_frame> parse_http3_frames(const uint8_t* data, size_t len);

}
}
