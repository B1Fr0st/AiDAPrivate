#include "../scanner_module.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::string lc(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

bool body_contains_nosql_error(const exchange_observed_t& resp)
{
    if (body_contains_ci(resp, "mongoerror")) return true;
    if (body_contains_ci(resp, "bsonexception")) return true;
    if (body_contains_ci(resp, "[object object]")) return true;
    if (body_contains_ci(resp, "couchbaseerror")) return true;
    if (body_contains_ci(resp, "mongoinvalidargument")) return true;
    if (body_contains_ci(resp, "syntaxerror") && body_contains_ci(resp, "unexpected token")) return true;
    return false;
}

std::vector<probe_t> nosqli_probes(const insertion_point_t& ip, const module_context_t&)
{
    std::vector<probe_t> out;
    std::string base = ip.original_value;
    out.push_back({ base + "[$ne]=1",          "_AIDA_NOSQLI", "operator-ne" });
    out.push_back({ base + "[$gt]=",           "_AIDA_NOSQLI", "operator-gt" });
    out.push_back({ base + "[$regex]=.*",      "_AIDA_NOSQLI", "operator-regex" });
    out.push_back({ base + "[$where]=1==1",    "_AIDA_NOSQLI", "operator-where" });
    out.push_back({ std::string("{\"$ne\":\"\"}"),                "_AIDA_NOSQLI", "json-ne-empty" });
    out.push_back({ std::string("{\"$gt\":\"\"}"),                "_AIDA_NOSQLI", "json-gt-empty" });
    out.push_back({ std::string("{\"$regex\":\".*\"}"),           "_AIDA_NOSQLI", "json-regex-dotstar" });
    out.push_back({ std::string("{\"$in\":[\"\",\"admin\",\"user\"]}"), "_AIDA_NOSQLI", "json-in-array" });
    return out;
}

std::optional<issue_t> nosqli_detect(const insertion_point_t& ip, const probe_t& probe,
                                     const exchange_observed_t& resp, const module_context_t& ctx)
{
    if (probe.marker != "_AIDA_NOSQLI") return std::nullopt;
    bool err = body_contains_nosql_error(resp);

    bool differential = false;
    if (resp.status_code != ctx.baseline_status_code) differential = true;
    else
    {
        size_t mx = std::max(resp.resp_body.size(), ctx.baseline_response_body.size());
        size_t mn = std::min(resp.resp_body.size(), ctx.baseline_response_body.size());
        if (mx > 0 && (mx - mn) * 10 > mx) differential = true;
    }

    if (!err && !differential) return std::nullopt;
    confidence_t conf = err ? confidence_t::firm : confidence_t::tentative;
    auto iss = make_issue("nosqli.injection",
                          std::string("Possible NoSQL Injection (") + probe.variant + ")",
                          severity_t::high, conf, ip, probe, resp, ctx,
                          std::string("probe=") + probe.payload +
                          " baseline_status=" + std::to_string(ctx.baseline_status_code) +
                          " probe_status=" + std::to_string(resp.status_code));
    iss.description = std::string("Replacing the parameter with a NoSQL operator payload (variant '") + probe.variant +
        "') produced " + (err ? "a NoSQL error signature in the response" : "a substantively different response than the baseline") +
        ". This indicates that user input flows into a query operator position.";
    iss.remediation = "Parameterize NoSQL queries. Reject operator keys ($ne, $gt, $regex, $where, $in) in user input; coerce input to expected types before querying.";
    iss.cwe.push_back("CWE-943");
    iss.cwe.push_back("CWE-89");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "nosqli";
    m.name = "NoSQL Injection";
    m.category = "Injection";
    m.max_probes_per_point = 8;
    m.probes = nosqli_probes;
    m.detect = nosqli_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
