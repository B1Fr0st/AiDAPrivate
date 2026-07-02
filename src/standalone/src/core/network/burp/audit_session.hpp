#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace audit_session {

struct audit_target_t
{
    uint64_t    id = 0;
    std::string session_id;
    std::string url;
    std::string host;
    uint16_t    port = 0;
    std::string scheme;
    uint64_t    added_ms = 0;
    bool        is_primary = false;
};

struct session_t
{
    std::string    session_id;
    std::string    title;
    std::string    description;
    uint64_t       created_ms = 0;
    uint64_t       closed_ms = 0;
    std::string    status = "active";
    nlohmann::json scope_json = nlohmann::json::array();
    nlohmann::json auth_json = nlohmann::json::object();
    nlohmann::json notes_json = nlohmann::json::array();
    uint64_t       target_count = 0;
    uint64_t       finding_count = 0;
    uint64_t       scan_count = 0;
    nlohmann::json metadata_json = nlohmann::json::object();
};

struct create_request_t
{
    std::string              title;
    std::string              description;
    nlohmann::json           scope_json = nlohmann::json::array();
    nlohmann::json           auth_json = nlohmann::json::object();
    nlohmann::json           notes_json = nlohmann::json::array();
    nlohmann::json           metadata_json = nlohmann::json::object();
    std::vector<std::string> targets;
};

struct update_request_t
{
    std::string    session_id;
    bool           has_title = false;
    std::string    title;
    bool           has_description = false;
    std::string    description;
    bool           has_status = false;
    std::string    status;
    bool           has_scope = false;
    nlohmann::json scope_json = nlohmann::json::array();
    bool           has_auth = false;
    nlohmann::json auth_json = nlohmann::json::object();
    bool           has_notes = false;
    nlohmann::json notes_json = nlohmann::json::array();
    bool           has_metadata = false;
    nlohmann::json metadata_json = nlohmann::json::object();
};

struct list_filter_t
{
    bool        include_closed = true;
    std::string status;
    std::string title_substring;
    size_t      limit = 0;
    size_t      offset = 0;
};

bool                  initialize();
void                  shutdown();
bool                  create(const create_request_t& req, session_t& out);
std::vector<session_t> list(const list_filter_t& filter = list_filter_t{});
bool                  get(const std::string& session_id, session_t& out);
bool                  update(const update_request_t& req, session_t& out);
bool                  close(const std::string& session_id, session_t& out);
bool                  remove(const std::string& session_id);
bool                  add_target(const std::string& session_id, const std::string& url, bool is_primary, audit_target_t& out);
std::vector<audit_target_t> list_targets(const std::string& session_id);
bool                  remove_target(const std::string& session_id, uint64_t target_id);
nlohmann::json        session_to_json(const session_t& session, bool include_targets = true);
nlohmann::json        target_to_json(const audit_target_t& target);
std::string           last_error();

}
}
}
