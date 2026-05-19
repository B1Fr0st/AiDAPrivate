#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace license {
namespace transport {

struct request_t {
    std::wstring host;
    std::wstring path;
    std::string method;
    std::vector<std::pair<std::wstring, std::wstring>> headers;
    std::vector<uint8_t> body;
    uint32_t timeout_ms = 15000u;
};

struct response_t {
    uint32_t http_status = 0u;
    std::vector<uint8_t> body;
    std::vector<uint8_t> tls_exporter;
    std::array<uint8_t, 32> server_spki_hash = {};
    std::string debug_reason;
};

using pubkey_provider_fn = bool(*)(uint8_t kid, uint8_t out_pubkey[32]);

bool initialize();
bool is_initialized();

void set_pubkey_provider(pubkey_provider_fn fn);

bool send(const request_t& req, response_t& resp, std::string& last_error);

bool verify_response_signature(
    const std::vector<uint8_t>& payload_bytes,
    const std::vector<uint8_t>& sig_bytes,
    uint8_t kid,
    std::string& last_error);

}
}
}
