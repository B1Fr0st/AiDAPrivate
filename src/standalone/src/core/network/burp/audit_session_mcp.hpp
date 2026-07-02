#pragma once

#include "../../mcp/mcp_standalone.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace audit_session_mcp_store {

struct target_t
{
    std::string id;
    std::string label;
    std::string url;
    std::string scheme;
    std::string host;
    uint16_t    port = 0;
    std::string path;
    uint64_t    added_ms = 0;
    bool        active = true;
};

struct session_t
{
    std::string              id;
    std::string              title;
    std::string              client;
    std::string              scope_summary;
    std::string              status;
    std::string              owner;
    std::string              notes;
    uint64_t                 created_ms = 0;
    uint64_t                 updated_ms = 0;
    uint64_t                 closed_ms = 0;
    std::vector<target_t>    targets;
    nlohmann::json           metadata = nlohmann::json::object();
};

struct evidence_record_t
{
    uint64_t       id = 0;
    std::string    session_id;
    uint64_t       issue_id = 0;
    uint64_t       exchange_id = 0;
    std::string    source;
    std::string    category;
    std::string    label;
    uint64_t       captured_ms = 0;
    std::string    method;
    std::string    url;
    std::string    host;
    uint16_t       port = 0;
    std::string    path;
    int            status_code = 0;
    uint64_t       request_length = 0;
    uint64_t       response_length = 0;
    std::string    request_sha256;
    std::string    response_sha256;
    std::string    request_preview;
    std::string    response_preview;
    std::string    marker_preview;
    std::string    marker_sha256;
    uint64_t       marker_length = 0;
    nlohmann::json extra = nlohmann::json::object();
};

struct suppression_t
{
    uint64_t    id = 0;
    std::string session_id;
    uint64_t    issue_id = 0;
    std::string scope;
    std::string reason;
    std::string actor;
    std::string issue_type;
    std::string host;
    std::string path;
    uint64_t    created_ms = 0;
    uint64_t    expires_ms = 0;
    bool        active = true;
};

struct audit_entry_t
{
    uint64_t       id = 0;
    std::string    session_id;
    uint64_t       ts_ms = 0;
    std::string    actor;
    std::string    tool;
    std::string    action;
    bool           read_only = true;
    bool           ok = true;
    uint64_t       elapsed_ms = 0;
    std::string    target;
    std::string    summary;
    nlohmann::json params_summary = nlohmann::json::object();
    nlohmann::json result_summary = nlohmann::json::object();
};

struct session_update_t
{
    bool           has_title = false;
    bool           has_client = false;
    bool           has_scope_summary = false;
    bool           has_status = false;
    bool           has_owner = false;
    bool           has_notes = false;
    bool           has_metadata = false;
    std::string    title;
    std::string    client;
    std::string    scope_summary;
    std::string    status;
    std::string    owner;
    std::string    notes;
    nlohmann::json metadata = nlohmann::json::object();
};

struct session_filter_t
{
    std::string status;
    bool        include_closed = true;
    size_t      limit = 0;
};

struct evidence_query_t
{
    std::string session_id;
    uint64_t    issue_id = 0;
    uint64_t    exchange_id = 0;
    size_t      limit = 128;
};

struct audit_query_t
{
    std::string session_id;
    std::string tool;
    uint64_t    since_ms = 0;
    uint64_t    until_ms = 0;
    size_t      limit = 128;
};

bool initialize();
void shutdown();
bool save_to_disk();
bool load_from_disk();
std::string storage_path();
std::string last_error();

std::string create_session(const std::string& title,
                           const std::string& client,
                           const std::string& scope_summary,
                           const std::string& owner,
                           const nlohmann::json& metadata);
bool get_session(const std::string& id, session_t& out);
std::vector<session_t> list_sessions(const session_filter_t& filter);
bool update_session(const std::string& id, const session_update_t& update, session_t& out);
bool close_session(const std::string& id, const std::string& reason, session_t& out);
bool delete_session(const std::string& id);

bool add_target(const std::string& session_id, target_t target, target_t& out);
std::vector<target_t> list_targets(const std::string& session_id);
bool remove_target(const std::string& session_id, const std::string& target_id);

uint64_t store_evidence(evidence_record_t record);
std::vector<evidence_record_t> list_evidence(const evidence_query_t& query);
size_t evidence_count_for_issue(const std::string& session_id, uint64_t issue_id);

uint64_t suppress_finding(suppression_t suppression);
bool is_suppressed(uint64_t issue_id, const std::string& session_id);
std::vector<suppression_t> list_suppressions(const std::string& session_id, bool active_only);

uint64_t append_audit(audit_entry_t entry);
std::vector<audit_entry_t> list_audit(const audit_query_t& query);

nlohmann::json target_to_json(const target_t& target);
nlohmann::json session_to_json(const session_t& session, bool include_targets);
nlohmann::json evidence_to_json(const evidence_record_t& record);
nlohmann::json suppression_to_json(const suppression_t& suppression);
nlohmann::json audit_entry_to_json(const audit_entry_t& entry);
nlohmann::json report_context_json(const std::string& session_id, bool include_audit_trail, size_t audit_limit);
nlohmann::json redact_json_for_output(const nlohmann::json& value);
std::string redact_for_output(const std::string& value);
std::string redact_url_for_output(const std::string& value);
std::string hash_for_output(const std::string& value);

}

namespace audit_session_mcp {

void register_audit_session_tools(mcp_standalone::server_t& srv);

}
}
}
