#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace audit_trail {

struct event_t
{
    std::string    session_id;
    uint64_t       scan_id = 0;
    uint64_t       timestamp_ms = 0;
    std::string    tool_name;
    nlohmann::json parameters_json = nlohmann::json::object();
    nlohmann::json result_json = nlohmann::json::object();
    uint64_t       duration_ms = 0;
    std::string    caller;
    bool           success = true;
    std::string    error_message;
};

struct record_t
{
    uint64_t       id = 0;
    std::string    session_id;
    uint64_t       scan_id = 0;
    uint64_t       timestamp_ms = 0;
    std::string    tool_name;
    std::string    parameters_hash;
    std::string    result_hash;
    nlohmann::json parameters_preview_json = nlohmann::json::object();
    nlohmann::json result_summary_json = nlohmann::json::object();
    uint64_t       duration_ms = 0;
    std::string    caller;
    bool           success = true;
    std::string    error_message;
};

struct query_filter_t
{
    std::string session_id;
    bool        has_scan_id = false;
    uint64_t    scan_id = 0;
    std::string tool_name_substring;
    uint64_t    since_ms = 0;
    uint64_t    until_ms = 0;
    bool        failures_only = false;
    size_t      limit = 200;
    size_t      offset = 0;
};

bool                  initialize();
void                  shutdown();
bool                  record(const event_t& event, uint64_t* out_id = nullptr);
std::vector<record_t> query(const query_filter_t& filter = query_filter_t{});
nlohmann::json        export_json(const query_filter_t& filter = query_filter_t{});
nlohmann::json        record_to_json(const record_t& record);
std::string           last_error();

}
}
}
