#pragma once

#include "mitm_proxy.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace flow_serializer {

enum class flow_format {
    aida_json,
    har_1_2
};

struct parse_result {
    bool success = false;
    std::vector<mitm_proxy::http_exchange> flows;
    std::string error;
};

nlohmann::json exchange_to_json(const mitm_proxy::http_exchange& exchange);
bool exchange_from_json(const nlohmann::json& value, mitm_proxy::http_exchange& out, std::string& error);

nlohmann::json export_aida_json(const std::vector<mitm_proxy::http_exchange>& flows);
parse_result import_aida_json(const nlohmann::json& document);

nlohmann::json export_har_1_2(const std::vector<mitm_proxy::http_exchange>& flows);
parse_result import_har_1_2(const nlohmann::json& document);

bool save_file(const std::string& path,
               flow_format format,
               const std::vector<mitm_proxy::http_exchange>& flows,
               std::string& error);

parse_result load_file(const std::string& path, flow_format format);
bool parse_format(const std::string& value, flow_format& out);
const char* format_name(flow_format format);

std::string base64_encode(const std::vector<uint8_t>& data);
bool base64_decode(const std::string& value, std::vector<uint8_t>& out);
std::vector<uint8_t> bytes_from_text(const std::string& value);
std::string text_from_bytes(const std::vector<uint8_t>& value);
std::vector<uint8_t> build_raw_request(const mitm_proxy::http_exchange& exchange);
std::vector<uint8_t> build_raw_response(const mitm_proxy::http_exchange& exchange);

}
