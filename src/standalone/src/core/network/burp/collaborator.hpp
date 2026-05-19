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

namespace aida {
namespace burp {
namespace collaborator {

struct collaborator_config_t
{
    std::string bind_ip       = "0.0.0.0";
    uint16_t    http_port     = 8444;
    uint16_t    dns_port      = 5353;
    uint16_t    smtp_port     = 2525;
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

struct status_t
{
    bool        running = false;
    bool        http_alive = false;
    bool        dns_alive  = false;
    bool        smtp_alive = false;
    std::string bind_ip;
    uint16_t    http_port = 0;
    uint16_t    dns_port  = 0;
    uint16_t    smtp_port = 0;
    std::string public_host;
    std::string public_ip;
    size_t      interaction_count = 0;
    size_t      token_count = 0;
    uint64_t    started_ms = 0;
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
std::vector<interaction_t> snapshot_all(size_t max_entries = 0);
bool                       get_interaction(uint64_t id, interaction_t& out);
void                       clear();

std::string last_error();

}
}
}
