#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {

enum class severity_t : int
{
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4
};

enum class confidence_t : int
{
    tentative = 0,
    firm = 1,
    certain = 2
};

struct evidence_t
{
    std::string  request_raw;
    std::string  response_raw;
    std::string  marker;
    size_t       marker_offset_request = 0;
    size_t       marker_offset_response = 0;
};

struct issue_t
{
    uint64_t                 id = 0;
    std::string              session_id;
    uint64_t                 scan_id = 0;
    std::string              type_key;
    std::string              name;
    std::string              description;
    std::string              remediation;
    std::vector<std::string> cwe;
    double                   cvss_score = 0.0;
    std::string              cvss_vector;
    std::string              cvss_severity;
    std::string              owasp_category;
    severity_t               severity = severity_t::info;
    confidence_t             confidence = confidence_t::tentative;
    std::string              scheme;
    std::string              host;
    uint16_t                 port = 0;
    std::string              path;
    std::string              parameter;
    std::string              insertion_point;
    std::vector<evidence_t>  evidence;
    uint64_t                 seen_ms = 0;
    uint64_t                 src_exchange_id = 0;
    uint64_t                 audit_id = 0;
    bool                     suppressed = false;
    std::string              suppress_reason;
    std::string              suppressed_by;
    uint64_t                 suppressed_ms = 0;
};

struct issue_filter_t
{
    bool        has_severity_min = false;
    severity_t  severity_min = severity_t::info;
    bool        has_confidence_min = false;
    confidence_t confidence_min = confidence_t::tentative;
    std::string host_substring;
    std::string type_key_substring;
    bool        has_audit_id = false;
    uint64_t    audit_id = 0;
    bool        include_suppressed = false;
    size_t      limit = 0;
};

const char* severity_label(severity_t s);
const char* confidence_label(confidence_t c);
bool        parse_severity(const std::string& s, severity_t& out);
bool        parse_confidence(const std::string& s, confidence_t& out);

namespace issue_store {

bool                  initialize();
void                  shutdown();

uint64_t              add(issue_t issue);
bool                  remove(uint64_t id);
void                  clear();

std::vector<issue_t>  list(const issue_filter_t& filter);
size_t                count();
bool                  get(uint64_t id, issue_t& out);

size_t                count_by_severity(severity_t s);

nlohmann::json        export_json(const issue_filter_t& filter);
nlohmann::json        issue_to_json(const issue_t& iss);
bool                  import_json(const nlohmann::json& doc, bool replace_existing);

std::string           last_error();
std::string           storage_path();
bool                  save_to_disk();
bool                  load_from_disk();

}

}
}
