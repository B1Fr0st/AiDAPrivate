#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "issue.hpp"

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
};

struct generated_report_t
{
    uint64_t        id = 0;
    uint64_t        ts_ms = 0;
    std::string     title;
    std::string     output_path;
    report_format_t format = report_format_t::html;
    size_t          issue_count = 0;
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
