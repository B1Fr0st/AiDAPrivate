#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace csp {

struct csp_directive_t
{
    std::string              name;
    std::vector<std::string> values;
};

struct csp_finding_t
{
    std::string id;
    std::string title;
    std::string severity;
    std::string description;
    std::string evidence;
};

struct csp_result_t
{
    std::vector<csp_directive_t> directives;
    std::vector<csp_finding_t>   findings;
    int                          score = 100;
    bool                         has_csp = false;
    bool                         is_report_only = false;
};

bool initialize();
void shutdown();

csp_result_t analyze(const std::string& csp_header_value, bool is_report_only);
csp_result_t analyze_for_response(const std::vector<std::pair<std::string, std::string>>& response_headers);

std::string last_error();

}
}
}
