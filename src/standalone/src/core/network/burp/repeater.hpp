#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace repeater {

struct repeater_tab_t {
    uint64_t id = 0;
    std::string name;
    std::string host;
    uint16_t port = 443;
    bool use_tls = true;
    std::vector<uint8_t> raw_request;
    std::vector<uint8_t> raw_response;
    int status_code = 0;
    uint64_t latency_ms = 0;
    std::string error;
    uint64_t created_ms = 0;
    uint64_t last_sent_ms = 0;
    bool has_response = false;
};

bool initialize();
void shutdown();

uint64_t create_tab(const std::string& host, uint16_t port, bool use_tls,
                    const std::vector<uint8_t>& raw_request, const std::string& name = "");
bool close_tab(uint64_t tab_id);
std::vector<repeater_tab_t> list_tabs();
bool get_tab(uint64_t tab_id, repeater_tab_t& out);

struct send_result_t {
    bool success = false;
    int status_code = 0;
    std::vector<uint8_t> raw_response;
    std::vector<std::pair<std::string, std::string>> response_headers;
    uint64_t latency_ms = 0;
    std::string error;
};

send_result_t send(uint64_t tab_id);
send_result_t send_raw(const std::string& host, uint16_t port, bool use_tls,
                       const std::vector<uint8_t>& raw_request,
                       int timeout_ms = 15000, bool follow_redirects = false);

bool update_tab_request(uint64_t tab_id, const std::vector<uint8_t>& raw_request);
bool update_tab_target(uint64_t tab_id, const std::string& host, uint16_t port, bool use_tls);

size_t tab_count();
void clear_all();
nlohmann::json export_json();
bool import_json(const nlohmann::json& doc, bool replace_existing);

}
}
}
