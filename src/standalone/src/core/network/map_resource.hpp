#pragma once

#include "mitm_proxy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace map_resource {

enum class local_rule_kind {
    exact_file,
    directory_prefix
};

struct local_rule {
    uint64_t id = 0;
    bool enabled = true;
    std::string label;
    std::string url_prefix;
    std::string local_path;
    local_rule_kind kind = local_rule_kind::exact_file;
    uint16_t status_code = 200;
    std::string reason = "OK";
    std::string content_type;
    uint64_t max_bytes = 32ull * 1024ull * 1024ull;
    std::vector<std::string> tags;
};

struct remote_rule {
    uint64_t id = 0;
    bool enabled = true;
    std::string label;
    std::string url_prefix;
    std::string remote_prefix;
    bool update_host_header = true;
    std::vector<std::string> tags;
};

struct local_result {
    bool matched = false;
    uint64_t rule_id = 0;
    std::string label;
    std::vector<uint8_t> raw_response;
    std::vector<std::string> tags;
    std::string error;
};

struct remote_result {
    bool matched = false;
    uint64_t rule_id = 0;
    std::string label;
    std::string host;
    uint16_t port = 0;
    bool use_tls = false;
    std::vector<uint8_t> raw_request;
    std::vector<std::string> tags;
    std::string error;
};

uint64_t add_local_rule(const local_rule& rule);
uint64_t add_remote_rule(const remote_rule& rule);
bool remove_local_rule(uint64_t id);
bool remove_remote_rule(uint64_t id);
void clear_local_rules();
void clear_remote_rules();
std::vector<local_rule> list_local_rules();
std::vector<remote_rule> list_remote_rules();

local_result try_local(const mitm_proxy::http_exchange& exchange);
remote_result try_remote(const mitm_proxy::http_exchange& exchange, const std::vector<uint8_t>& raw_request);

std::string exchange_url(const mitm_proxy::http_exchange& exchange);
std::string content_type_for_path(const std::string& path);

}
