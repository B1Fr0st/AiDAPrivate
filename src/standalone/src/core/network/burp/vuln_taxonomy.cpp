#include "vuln_taxonomy.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <sstream>
#include <unordered_map>

namespace aida {
namespace burp {
namespace vuln_taxonomy {
namespace {

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string family_copy(std::string s)
{
    s = lower_copy(s);
    for (char& c : s) {
        if (c == '_') c = '-';
    }
    return s;
}

std::vector<std::string> split(const std::string& s, char delim)
{
    std::vector<std::string> out;
    std::string cur;
    std::istringstream is(s);
    while (std::getline(is, cur, delim)) {
        if (!cur.empty()) out.push_back(cur);
    }
    return out;
}

bool metric_value(const std::map<std::string, std::string>& m, const char* key, std::string& out)
{
    auto it = m.find(key);
    if (it == m.end() || it->second.empty()) return false;
    out = it->second;
    return true;
}

double round_up_1(double v)
{
    if (v <= 0.0) return 0.0;
    return std::ceil((v * 10.0) - 0.000001) / 10.0;
}

bool lookup_weight(const std::unordered_map<std::string, double>& weights, const std::string& key, double& out)
{
    auto it = weights.find(key);
    if (it == weights.end()) return false;
    out = it->second;
    return true;
}

const std::unordered_map<std::string, std::string>& cwe_names()
{
    static const std::unordered_map<std::string, std::string> table = {
        {"CWE-16", "Configuration"},
        {"CWE-20", "Improper Input Validation"},
        {"CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"},
        {"CWE-23", "Relative Path Traversal"},
        {"CWE-35", "Path Traversal"},
        {"CWE-74", "Improper Neutralization of Special Elements in Output Used by a Downstream Component"},
        {"CWE-77", "Improper Neutralization of Special Elements used in a Command"},
        {"CWE-78", "OS Command Injection"},
        {"CWE-79", "Improper Neutralization of Input During Web Page Generation"},
        {"CWE-89", "SQL Injection"},
        {"CWE-90", "LDAP Injection"},
        {"CWE-91", "XML Injection"},
        {"CWE-94", "Code Injection"},
        {"CWE-95", "Eval Injection"},
        {"CWE-98", "PHP Remote File Inclusion"},
        {"CWE-99", "Resource Injection"},
        {"CWE-113", "HTTP Response Splitting"},
        {"CWE-116", "Improper Encoding or Escaping of Output"},
        {"CWE-184", "Incomplete List of Disallowed Inputs"},
        {"CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"},
        {"CWE-201", "Insertion of Sensitive Information Into Sent Data"},
        {"CWE-209", "Generation of Error Message Containing Sensitive Information"},
        {"CWE-213", "Exposure of Sensitive Information Due to Incompatible Policies"},
        {"CWE-285", "Improper Authorization"},
        {"CWE-287", "Improper Authentication"},
        {"CWE-294", "Authentication Bypass by Capture-replay"},
        {"CWE-295", "Improper Certificate Validation"},
        {"CWE-297", "Improper Validation of Certificate with Host Mismatch"},
        {"CWE-302", "Authentication Bypass by Assumed-Immutable Data"},
        {"CWE-306", "Missing Authentication for Critical Function"},
        {"CWE-307", "Improper Restriction of Excessive Authentication Attempts"},
        {"CWE-319", "Cleartext Transmission of Sensitive Information"},
        {"CWE-326", "Inadequate Encryption Strength"},
        {"CWE-327", "Use of a Broken or Risky Cryptographic Algorithm"},
        {"CWE-328", "Use of Weak Hash"},
        {"CWE-345", "Insufficient Verification of Data Authenticity"},
        {"CWE-352", "Cross-Site Request Forgery"},
        {"CWE-359", "Exposure of Private Personal Information to an Unauthorized Actor"},
        {"CWE-384", "Session Fixation"},
        {"CWE-400", "Uncontrolled Resource Consumption"},
        {"CWE-425", "Direct Request"},
        {"CWE-434", "Unrestricted Upload of File with Dangerous Type"},
        {"CWE-441", "Unintended Proxy or Intermediary"},
        {"CWE-444", "Inconsistent Interpretation of HTTP Requests"},
        {"CWE-502", "Deserialization of Untrusted Data"},
        {"CWE-521", "Weak Password Requirements"},
        {"CWE-522", "Insufficiently Protected Credentials"},
        {"CWE-523", "Unprotected Transport of Credentials"},
        {"CWE-525", "Use of Web Browser Cache Containing Sensitive Information"},
        {"CWE-532", "Insertion of Sensitive Information into Log File"},
        {"CWE-539", "Use of Persistent Cookies Containing Sensitive Information"},
        {"CWE-548", "Exposure of Information Through Directory Listing"},
        {"CWE-552", "Files or Directories Accessible to External Parties"},
        {"CWE-601", "Open Redirect"},
        {"CWE-611", "Improper Restriction of XML External Entity Reference"},
        {"CWE-613", "Insufficient Session Expiration"},
        {"CWE-614", "Sensitive Cookie in HTTPS Session Without Secure Attribute"},
        {"CWE-639", "Authorization Bypass Through User-Controlled Key"},
        {"CWE-693", "Protection Mechanism Failure"},
        {"CWE-697", "Incorrect Comparison"},
        {"CWE-770", "Allocation of Resources Without Limits or Throttling"},
        {"CWE-776", "Improper Restriction of Recursive Entity References in DTDs"},
        {"CWE-798", "Use of Hard-coded Credentials"},
        {"CWE-829", "Inclusion of Functionality from Untrusted Control Sphere"},
        {"CWE-918", "Server-Side Request Forgery"},
        {"CWE-922", "Insecure Storage of Sensitive Information"},
        {"CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"},
        {"CWE-943", "Improper Neutralization of Special Elements in Data Query Logic"},
        {"CWE-1004", "Sensitive Cookie Without HttpOnly Flag"},
        {"CWE-1021", "Improper Restriction of Rendered UI Layers or Frames"},
        {"CWE-1104", "Use of Unmaintained Third Party Components"},
        {"CWE-1166", "Improper Encoding or Escaping of Output"}
    };
    return table;
}

struct prefix_mapping_t
{
    const char* prefix;
    const char* owasp;
    const char* vector;
    std::vector<std::string> cwes;
};

const std::vector<prefix_mapping_t>& mappings()
{
    static const std::vector<prefix_mapping_t> table = {
        {"xss", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", {"CWE-79"}},
        {"dom_xss", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", {"CWE-79"}},
        {"sqli", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", {"CWE-89"}},
        {"nosqli", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", {"CWE-943", "CWE-20"}},
        {"cmdi", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", {"CWE-78", "CWE-77"}},
        {"ssti", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", {"CWE-94", "CWE-95"}},
        {"ldap", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", {"CWE-90"}},
        {"xpath", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", {"CWE-91"}},
        {"xxe", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", {"CWE-611", "CWE-776"}},
        {"ssrf", "A10:2021 - Server-Side Request Forgery", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", {"CWE-918"}},
        {"blind-ssrf", "A10:2021 - Server-Side Request Forgery", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L", {"CWE-918"}},
        {"path-traversal", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", {"CWE-22", "CWE-23", "CWE-35"}},
        {"lfi", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", {"CWE-22", "CWE-98"}},
        {"open-redirect", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", {"CWE-601"}},
        {"idor", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", {"CWE-639", "CWE-285"}},
        {"csrf", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", {"CWE-352"}},
        {"cors", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N", {"CWE-942", "CWE-346"}},
        {"csp", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", {"CWE-693", "CWE-1021"}},
        {"host-header", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", {"CWE-20", "CWE-601"}},
        {"smuggling", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", {"CWE-444"}},
        {"race", "A04:2021 - Insecure Design", "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L", {"CWE-362", "CWE-367"}},
        {"deserial", "A08:2021 - Software and Data Integrity Failures", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", {"CWE-502"}},
        {"jwt", "A07:2021 - Identification and Authentication Failures", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", {"CWE-345", "CWE-287"}},
        {"auth", "A07:2021 - Identification and Authentication Failures", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", {"CWE-287", "CWE-306"}},
        {"session", "A07:2021 - Identification and Authentication Failures", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", {"CWE-384", "CWE-613"}},
        {"cookie", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", {"CWE-614", "CWE-1004"}},
        {"tls", "A02:2021 - Cryptographic Failures", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", {"CWE-295", "CWE-326", "CWE-327"}},
        {"crypto", "A02:2021 - Cryptographic Failures", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", {"CWE-326", "CWE-327"}},
        {"info", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", {"CWE-200", "CWE-209"}},
        {"backup", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", {"CWE-552", "CWE-548"}},
        {"source", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", {"CWE-552", "CWE-200"}},
        {"graphql", "A01:2021 - Broken Access Control", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", {"CWE-200", "CWE-285"}},
        {"cache", "A05:2021 - Security Misconfiguration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N", {"CWE-525", "CWE-524"}},
        {"email", "A03:2021 - Injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N", {"CWE-74", "CWE-113"}}
    };
    return table;
}

}

cvss_result_t calculate_cvss31(const std::string& vector)
{
    cvss_result_t result;
    result.vector = vector;
    std::string normalized = vector;
    if (normalized.rfind("CVSS:3.1/", 0) == 0) {
        normalized = normalized.substr(9);
    }
    else if (normalized.rfind("CVSS:3.0/", 0) == 0) {
        normalized = normalized.substr(9);
        result.vector = std::string("CVSS:3.1/") + normalized;
    }

    std::map<std::string, std::string> metrics;
    for (const auto& token : split(normalized, '/')) {
        auto pos = token.find(':');
        if (pos == std::string::npos || pos == 0 || pos + 1 >= token.size()) {
            result.error = "invalid_cvss_token";
            return result;
        }
        metrics[token.substr(0, pos)] = token.substr(pos + 1);
    }

    std::string av;
    std::string ac;
    std::string pr;
    std::string ui;
    std::string scope;
    std::string c;
    std::string i;
    std::string a;
    if (!metric_value(metrics, "AV", av) ||
        !metric_value(metrics, "AC", ac) ||
        !metric_value(metrics, "PR", pr) ||
        !metric_value(metrics, "UI", ui) ||
        !metric_value(metrics, "S", scope) ||
        !metric_value(metrics, "C", c) ||
        !metric_value(metrics, "I", i) ||
        !metric_value(metrics, "A", a)) {
        result.error = "missing_required_metric";
        return result;
    }

    static const std::unordered_map<std::string, double> av_w = {{"N", 0.85}, {"A", 0.62}, {"L", 0.55}, {"P", 0.20}};
    static const std::unordered_map<std::string, double> ac_w = {{"L", 0.77}, {"H", 0.44}};
    static const std::unordered_map<std::string, double> ui_w = {{"N", 0.85}, {"R", 0.62}};
    static const std::unordered_map<std::string, double> cia_w = {{"H", 0.56}, {"L", 0.22}, {"N", 0.0}};

    double avv = 0.0;
    double acv = 0.0;
    double prv = 0.0;
    double uiv = 0.0;
    double cv = 0.0;
    double iv = 0.0;
    double avia = 0.0;
    if (!lookup_weight(av_w, av, avv) ||
        !lookup_weight(ac_w, ac, acv) ||
        !lookup_weight(ui_w, ui, uiv) ||
        !lookup_weight(cia_w, c, cv) ||
        !lookup_weight(cia_w, i, iv) ||
        !lookup_weight(cia_w, a, avia)) {
        result.error = "unknown_metric_value";
        return result;
    }

    if (scope == "U") {
        static const std::unordered_map<std::string, double> pr_u = {{"N", 0.85}, {"L", 0.62}, {"H", 0.27}};
        if (!lookup_weight(pr_u, pr, prv)) {
            result.error = "unknown_privileges_metric";
            return result;
        }
    }
    else if (scope == "C") {
        static const std::unordered_map<std::string, double> pr_c = {{"N", 0.85}, {"L", 0.68}, {"H", 0.50}};
        if (!lookup_weight(pr_c, pr, prv)) {
            result.error = "unknown_privileges_metric";
            return result;
        }
    }
    else {
        result.error = "unknown_scope_metric";
        return result;
    }

    const double impact_sub = 1.0 - ((1.0 - cv) * (1.0 - iv) * (1.0 - avia));
    if (impact_sub <= 0.0) {
        result.valid = true;
        result.score = 0.0;
        result.severity = cvss_severity(0.0);
        return result;
    }

    const double exploitability = 8.22 * avv * acv * prv * uiv;
    double impact = 0.0;
    double base = 0.0;
    if (scope == "U") {
        impact = 6.42 * impact_sub;
        base = round_up_1((std::min)(impact + exploitability, 10.0));
    }
    else {
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * std::pow(impact_sub - 0.02, 15.0);
        base = round_up_1((std::min)(1.08 * (impact + exploitability), 10.0));
    }

    result.valid = true;
    result.score = base;
    result.severity = cvss_severity(base);
    if (result.vector.rfind("CVSS:3.", 0) != 0) {
        result.vector = std::string("CVSS:3.1/") + normalized;
    }
    return result;
}

std::string cvss_severity(double score)
{
    if (score <= 0.0) return "none";
    if (score < 4.0) return "low";
    if (score < 7.0) return "medium";
    if (score < 9.0) return "high";
    return "critical";
}

taxonomy_mapping_t mapping_for_type(const std::string& type_key)
{
    const std::string key = lower_copy(type_key);
    const std::string family_key = family_copy(type_key);
    for (const auto& m : mappings()) {
        const std::string p = lower_copy(m.prefix);
        const std::string family_p = family_copy(m.prefix);
        if (key == p || key.rfind(p + ".", 0) == 0 || key.rfind(p + "-", 0) == 0 || key.find(p) != std::string::npos ||
            family_key == family_p || family_key.rfind(family_p + ".", 0) == 0 || family_key.rfind(family_p + "-", 0) == 0 || family_key.find(family_p) != std::string::npos) {
            taxonomy_mapping_t out;
            out.type_key = type_key;
            out.owasp_category = m.owasp;
            out.cwe_ids = m.cwes;
            out.default_cvss_vector = m.vector;
            for (const auto& cwe : out.cwe_ids) out.cwe_names.push_back(cwe_name(cwe));
            return out;
        }
    }
    taxonomy_mapping_t out;
    out.type_key = type_key;
    out.owasp_category = "A05:2021 - Security Misconfiguration";
    out.cwe_ids = {"CWE-200"};
    out.cwe_names = {cwe_name("CWE-200")};
    out.default_cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N";
    return out;
}

std::string cwe_name(const std::string& cwe_id)
{
    auto it = cwe_names().find(cwe_id);
    if (it != cwe_names().end()) return it->second;
    return "Unmapped CWE";
}

nlohmann::json mapping_to_json(const taxonomy_mapping_t& mapping)
{
    nlohmann::json j = nlohmann::json::object();
    j["type_key"] = mapping.type_key;
    j["owasp_category"] = mapping.owasp_category;
    j["cwe_ids"] = mapping.cwe_ids;
    j["cwe_names"] = mapping.cwe_names;
    j["default_cvss_vector"] = mapping.default_cvss_vector;
    return j;
}

nlohmann::json score_to_json(const std::string& type_key, const std::string& vector_override)
{
    auto mapping = mapping_for_type(type_key);
    const std::string vector = vector_override.empty() ? mapping.default_cvss_vector : vector_override;
    auto score = calculate_cvss31(vector);
    nlohmann::json j = mapping_to_json(mapping);
    j["cvss_vector"] = score.vector;
    j["cvss_score"] = score.score;
    j["cvss_severity"] = score.severity;
    j["valid"] = score.valid;
    if (!score.error.empty()) j["error"] = score.error;
    return j;
}

}
}
}
