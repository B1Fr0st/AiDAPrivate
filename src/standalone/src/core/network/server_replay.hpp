#pragma once

#include "mitm_proxy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace server_replay {

enum class body_match_mode {
    ignore,
    exact
};

struct match_rule {
    uint64_t id = 0;
    bool enabled = true;
    std::string label;
    std::string method;
    std::string scheme;
    std::string host;
    uint16_t port = 0;
    std::string path_query;
    body_match_mode body_mode = body_match_mode::ignore;
    std::vector<uint8_t> request_body;
    std::vector<uint8_t> raw_response;
    std::vector<std::string> tags;
};

struct load_options {
    bool replace_existing = false;
    bool exact_body = false;
};

struct match_result {
    bool matched = false;
    uint64_t rule_id = 0;
    std::string label;
    std::vector<uint8_t> raw_response;
    std::vector<std::string> tags;
};

uint64_t add_rule(const match_rule& rule);
size_t load_from_flows(const std::vector<mitm_proxy::http_exchange>& flows, const load_options& options = {});
bool remove_rule(uint64_t id);
void clear_rules();
void set_enabled(bool enabled);
bool is_enabled();
std::vector<match_rule> list_rules();

match_result match(const mitm_proxy::http_exchange& exchange, const std::vector<uint8_t>& raw_request);

}
