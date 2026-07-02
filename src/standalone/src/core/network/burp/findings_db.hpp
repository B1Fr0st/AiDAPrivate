#pragma once

#include "issue.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

struct sqlite3;

namespace aida {
namespace burp {
namespace findings_db {

struct finding_filter_t
{
    std::string session_id;
    bool        has_scan_id = false;
    uint64_t    scan_id = 0;
    bool        has_audit_id = false;
    uint64_t    audit_id = 0;
    std::string host_substring;
    std::string type_key_substring;
    std::string path_substring;
    bool        has_severity_min = false;
    severity_t  severity_min = severity_t::info;
    bool        has_confidence_min = false;
    confidence_t confidence_min = confidence_t::tentative;
    bool        include_suppressed = false;
    size_t      limit = 0;
    size_t      offset = 0;
};

struct suppression_t
{
    uint64_t    finding_id = 0;
    std::string reason;
    std::string suppressed_by;
    std::string scope;
    bool        create_rule = true;
};

struct dedupe_result_t
{
    size_t before_count = 0;
    size_t after_count = 0;
    size_t merged = 0;
    size_t duplicates_removed = 0;
};

struct scan_run_t
{
    uint64_t       scan_id = 0;
    std::string    session_id;
    std::string    target_url;
    std::string    profile = "quick";
    std::string    status = "pending";
    uint64_t       total_probes = 0;
    uint64_t       completed_probes = 0;
    uint64_t       issues_found = 0;
    nlohmann::json modules_json = nlohmann::json::array();
    nlohmann::json defensive_json = nlohmann::json::array();
    nlohmann::json config_json = nlohmann::json::object();
    uint64_t       started_ms = 0;
    uint64_t       ended_ms = 0;
    std::string    error_message;
};

struct scan_module_status_t
{
    uint64_t    scan_id = 0;
    std::string module_id;
    std::string status = "pending";
    uint64_t    probes_done = 0;
    uint64_t    probes_total = 0;
    uint64_t    issues_found = 0;
    uint64_t    started_ms = 0;
    uint64_t    ended_ms = 0;
    std::string error_message;
};

struct scan_profile_t
{
    std::string    profile_id;
    std::string    name;
    std::string    description;
    nlohmann::json module_ids_json = nlohmann::json::array();
    nlohmann::json defensive_checks_json = nlohmann::json::array();
    int            crawl_depth = 2;
    int            max_concurrent = 16;
    uint64_t       created_ms = 0;
    bool           is_builtin = false;
};

bool                  initialize();
bool                  shutdown();
bool                  is_initialized();

uint64_t              upsert(issue_t issue);
bool                  remove(uint64_t finding_id);
bool                  get(uint64_t finding_id, issue_t& out);
std::vector<issue_t>  list(const finding_filter_t& filter);
size_t                count(const finding_filter_t& filter = finding_filter_t{});
bool                  suppress(const suppression_t& req);
dedupe_result_t       deduplicate(const finding_filter_t& filter, bool merge_evidence);
nlohmann::json        correlate(const finding_filter_t& filter, bool persist = false);
nlohmann::json        score(const finding_filter_t& filter, uint64_t finding_id = 0, const std::string& cvss_vector_override = std::string(), bool persist = false);
nlohmann::json        export_json(const finding_filter_t& filter, bool include_evidence = true);
bool                  mirror_issue_store(bool replace_existing = false);

bool                  upsert_scan_run(const scan_run_t& scan);
bool                  update_scan_module(const scan_module_status_t& module);
bool                  save_scan_profile(const scan_profile_t& profile);
std::vector<scan_profile_t> list_scan_profiles(bool include_builtin = true);

std::string           last_error();
std::string           storage_path();
uint64_t              now_ms();
std::string           generate_id(const std::string& prefix);
bool                  with_db(const char* operation, const std::function<bool(sqlite3*)>& fn);

}
}
}
