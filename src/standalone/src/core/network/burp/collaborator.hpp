#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace collaborator {

struct collaborator_config_t
{
    std::string bind_ip       = "0.0.0.0";
    uint16_t    http_port     = 8444;
    uint16_t    dns_port      = 5353;
    uint16_t    smtp_port     = 2525;
    uint16_t    smtps_port    = 2465;
    uint16_t    ldap_port     = 1389;
    bool        enable_http   = true;
    bool        enable_dns    = true;
    bool        enable_smtp   = true;
    std::string public_host   = "aidacollab.local";
    std::string public_ip     = "127.0.0.1";
    std::string canned_body;
    std::string canned_content_type = "text/plain";
    size_t      max_interactions   = 4096;
    int         smtp_max_message   = 1024 * 1024;
};

struct interaction_t
{
    uint64_t                              id = 0;
    uint64_t                              timestamp_ms = 0;
    std::string                           kind;
    std::string                           client_ip;
    uint16_t                              client_port = 0;
    std::string                           subdomain;
    std::string                           raw;
    std::map<std::string, std::string>    details;
    std::string                           payload_token;
};

struct token_info_t
{
    std::string token;
    std::string full_domain;
    uint64_t    issued_ms = 0;
    uint64_t    last_seen_ms = 0;
    size_t      interaction_count = 0;
};

struct poll_request_t
{
    std::string token;
    std::string cursor;
    uint64_t    since_ms = 0;
    uint64_t    after_id = 0;
    size_t      max_entries = 256;
    uint32_t    wait_ms = 0;
};

struct poll_result_t
{
    std::vector<interaction_t> interactions;
    std::string cursor;
    uint64_t    next_since_ms = 0;
    uint64_t    next_after_id = 0;
    bool        timed_out = false;
};

struct status_t
{
    bool        running = false;
    bool        http_alive = false;
    bool        dns_alive  = false;
    bool        smtp_alive = false;
    bool        smtps_supported = false;
    bool        ldap_supported = false;
    std::string bind_ip;
    uint16_t    http_port = 0;
    uint16_t    dns_port  = 0;
    uint16_t    smtp_port = 0;
    uint16_t    smtps_port = 0;
    uint16_t    ldap_port = 0;
    std::string public_host;
    std::string public_ip;
    size_t      interaction_count = 0;
    size_t      token_count = 0;
    size_t      poll_cursor_count = 0;
    uint64_t    started_ms = 0;
    std::string durable_state_path;
};

struct webhook_delivery_result_t
{
    bool        delivered = false;
    int         status_code = 0;
    size_t      interaction_count = 0;
    std::string origin;
    std::string path;
    std::string error;
};

bool start(const collaborator_config_t& cfg);
void stop();
bool is_running();

status_t                 status();
collaborator_config_t    current_config();

std::string              generate_token();
std::vector<token_info_t> list_tokens();
bool                     forget_token(const std::string& token);

std::vector<interaction_t> poll_since(uint64_t timestamp_ms_inclusive);
std::vector<interaction_t> poll_by_token(const std::string& token);
poll_result_t              poll_async(const poll_request_t& request);
std::vector<interaction_t> snapshot_all(size_t max_entries = 0);
bool                       get_interaction(uint64_t id, interaction_t& out);
void                       clear();

nlohmann::json             export_json();
bool                       import_json(const nlohmann::json& doc, bool replace_existing);
bool                       save_state_to_file(const std::string& path);
bool                       load_state_from_file(const std::string& path, bool replace_existing);
bool                       save_default_state();
bool                       load_default_state(bool replace_existing);
std::string                default_state_path();
bool                       export_interactions_to_file(const std::string& path,
                                                       const std::string& token,
                                                       uint64_t since_ms,
                                                       uint64_t after_id,
                                                       size_t max_entries);
bool                       post_interactions_webhook(const std::string& url,
                                                     const std::string& token,
                                                     uint64_t since_ms,
                                                     uint64_t after_id,
                                                     size_t max_entries,
                                                     const std::string& signing_secret,
                                                     uint32_t timeout_ms,
                                                     webhook_delivery_result_t& result);
std::string last_error();

}
}
}
