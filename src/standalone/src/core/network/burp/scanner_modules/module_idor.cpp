#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <regex>
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

bool is_id_param(const std::string& name)
{
    std::string n = lc(name);
    static const char* tokens[] = {
        "id", "userid", "user_id", "accountid", "account_id", "orderid", "order_id",
        "invoiceid", "invoice_id", "pid", "uid", "oid", "aid", "docid", "doc_id",
        "fileid", "file_id", "messageid", "message_id"
    };
    for (const char* t : tokens) if (n == t || n.find(t) != std::string::npos) return true;
    return false;
}

bool is_pure_integer(const std::string& v)
{
    if (v.empty()) return false;
    size_t i = (v[0] == '-' ? 1 : 0);
    if (i >= v.size()) return false;
    for (; i < v.size(); ++i) if (v[i] < '0' || v[i] > '9') return false;
    return true;
}

bool is_uuid_like(const std::string& v)
{
    static const std::regex uuid_re("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    return std::regex_match(v, uuid_re);
}

std::vector<probe_t> idor_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_idor", "idor_probes entry ip=%s:%s orig=%s",
                         ip.kind.c_str(), ip.name.c_str(), ip.original_value.c_str());
    std::vector<probe_t> out;
    if (!is_id_param(ip.name)) {
        diag::log_tagged_fmt("mod_idor", "idor_probes skip not id param name=%s", ip.name.c_str());
        return out;
    }
    if (ip.original_value.empty()) {
        diag::log_tagged_fmt("mod_idor", "idor_probes skip empty value name=%s", ip.name.c_str());
        return out;
    }
    if (is_pure_integer(ip.original_value))
    {
        long long n = atoll(ip.original_value.c_str());
        diag::log_tagged_fmt("mod_idor", "idor_probes integer id n=%lld name=%s", n, ip.name.c_str());
        if (n > 1) out.push_back({ std::to_string(n - 1), "_AIDA_IDOR", "decrement" });
        out.push_back({ std::to_string(n + 1), "_AIDA_IDOR", "increment" });
        out.push_back({ "0",      "_AIDA_IDOR", "zero" });
        out.push_back({ "1",      "_AIDA_IDOR", "one" });
        out.push_back({ "999999", "_AIDA_IDOR", "high" });
        out.push_back({ "-1",     "_AIDA_IDOR", "negative" });
    }
    else if (is_uuid_like(ip.original_value))
    {
        diag::log_tagged_fmt("mod_idor", "idor_probes uuid id name=%s", ip.name.c_str());
        out.push_back({ "00000000-0000-0000-0000-000000000000", "_AIDA_IDOR", "nil-uuid" });
        out.push_back({ "ffffffff-ffff-ffff-ffff-ffffffffffff", "_AIDA_IDOR", "max-uuid" });
        out.push_back({ "11111111-1111-1111-1111-111111111111", "_AIDA_IDOR", "ones-uuid" });
    }
    diag::log_tagged_fmt("mod_idor", "idor_probes built %zu probes ip=%s:%s", out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

std::optional<issue_t> idor_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_idor", "idor_detect entry ip=%s:%s variant=%s status=%d baseline=%d",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                         resp.status_code, ctx.baseline_status_code);
    if (probe.marker != "_AIDA_IDOR") return std::nullopt;
    if (resp.status_code < 200 || resp.status_code >= 400) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip non-2xx status=%d", resp.status_code);
        return std::nullopt;
    }
    if (resp.status_code != ctx.baseline_status_code) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip status mismatch probe=%d baseline=%d", resp.status_code, ctx.baseline_status_code);
        return std::nullopt;
    }
    const auto& base = ctx.baseline_response_body;
    if (base.empty() || resp.resp_body.empty()) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip empty body");
        return std::nullopt;
    }
    if (resp.resp_body.size() == base.size())
    {
        bool identical = (resp.resp_body == base);
        if (identical) {
            diag::log_tagged_fmt("mod_idor", "idor_detect skip identical body size=%zu", base.size());
            return std::nullopt;
        }
    }
    size_t mx = std::max(resp.resp_body.size(), base.size());
    size_t mn = std::min(resp.resp_body.size(), base.size());
    if ((mx - mn) * 20 < mx) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip size delta too small mx=%zu mn=%zu", mx, mn);
        return std::nullopt;
    }

    diag::log_tagged_fmt("mod_idor", "idor_detect FINDING differential-response ip=%s:%s variant=%s probe_size=%zu base_size=%zu",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), resp.resp_body.size(), base.size());
    auto iss = make_issue("idor.differential-response",
                          "Possible Insecure Direct Object Reference (IDOR)",
                          severity_t::high, confidence_t::tentative, ip, probe, resp, ctx,
                          std::string("baseline_bytes=") + std::to_string(base.size())
                          + "; probe_bytes=" + std::to_string(resp.resp_body.size())
                          + "; probe_value=" + probe.payload);
    std::ostringstream desc;
    desc << "Modifying " << ip.name << " from '" << ip.original_value
         << "' to '" << probe.payload << "' returned HTTP " << resp.status_code
         << " with a substantively different response body (" << resp.resp_body.size()
         << " vs " << base.size() << " bytes). Manually confirm the response discloses another resource's data.";
    iss.description = desc.str();
    iss.remediation = "Enforce per-request authorization. Map IDs through indirection or ownership tables; never trust client-supplied identifiers.";
    iss.cwe.push_back("CWE-639");
    iss.cwe.push_back("CWE-285");
    return iss;
}

bool register_self()
{
    module_t m;
    m.id = "idor";
    m.name = "Insecure Direct Object Reference";
    m.category = "Access Control";
    m.max_probes_per_point = 9;
    m.probes = idor_probes;
    m.detect = idor_detect;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
