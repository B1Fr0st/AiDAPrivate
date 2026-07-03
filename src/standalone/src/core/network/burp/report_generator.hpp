#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "issue.hpp"

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace report {

enum class report_format_t : int
{
    html      = 0,
    markdown  = 1,
    json      = 2,
    sarif_2_1 = 3,
    csv       = 4
};

struct report_config_t
{
    std::string                  title;
    std::string                  client;
    std::string                  scope_summary;
    std::vector<uint64_t>        include_issue_ids;
    bool                         include_evidence = true;
    bool                         include_remediation = true;
    std::string                  output_path;
    report_format_t              format = report_format_t::html;
    std::string                  session_id;
    bool                         include_session_context = true;
    bool                         include_audit_trail = false;
    size_t                       audit_trail_limit = 128;
    bool                         has_audit_id = false;
    uint64_t                     audit_id = 0;
    bool                         has_severity_min = false;
    severity_t                   severity_min = severity_t::info;
    std::string                  target_domain;
    bool                         include_recon = true;
    std::vector<std::string>     include_offensive_run_ids;
    bool                         include_suppressed = false;
};

struct generated_report_t
{
    uint64_t        id = 0;
    uint64_t        ts_ms = 0;
    std::string     title;
    std::string     output_path;
    report_format_t format = report_format_t::html;
    size_t          issue_count = 0;
    bool            inline_output = false;
};

bool                generate(const report_config_t& cfg, std::string& out_path_or_error);
bool                parse_format(const std::string& s, report_format_t& out);
const char*         format_label(report_format_t f);
const char*         default_extension(report_format_t f);

std::vector<generated_report_t> list_reports();
size_t                           reports_count();
void                             clear_history();

std::string         last_error();

}
}
}
