#include "../scanner_module.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

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
        "fileid", "file_id", "messageid", "message_id", "account", "acct", "acctid",
        "acct_id", "customer", "customerid", "customer_id", "profile", "profileid",
        "profile_id", "resource", "resourceid", "resource_id", "member", "memberid",
        "member_id"
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

bool sensitive_json_path(const std::string& path)
{
    std::string p = lc(path);
    static const char* names[] = {
        "id", "user", "account", "acct", "customer", "profile", "resource",
        "owner", "member", "email", "name", "balance", "amount", "role"
    };
    for (const char* n : names) {
        if (p.find(n) != std::string::npos)
            return true;
    }
    return false;
}

std::string json_scalar_string(const nlohmann::json& v)
{
    if (v.is_string()) return v.get<std::string>();
    std::ostringstream os;
    os << v;
    return os.str();
}

std::string trunc_value(std::string s)
{
    for (char& c : s) {
        if (static_cast<unsigned char>(c) < 0x20)
            c = '.';
    }
    if (s.size() > 80)
        s = s.substr(0, 80) + "...";
    return s;
}

struct json_semantic_diff_t
{
    bool parsed = false;
    bool same_shape = true;
    size_t scalar_changes = 0;
    size_t sensitive_changes = 0;
    std::vector<std::string> evidence;
};

std::string json_kind(const nlohmann::json& v)
{
    if (v.is_object()) return "object";
    if (v.is_array()) return "array";
    if (v.is_string()) return "string";
    if (v.is_number()) return "number";
    if (v.is_boolean()) return "boolean";
    if (v.is_null()) return "null";
    return "unknown";
}

void compare_json_semantics(const nlohmann::json& base, const nlohmann::json& probe,
                            const std::string& path, json_semantic_diff_t& diff)
{
    if (base.is_object() || probe.is_object()) {
        if (!base.is_object() || !probe.is_object()) {
            diff.same_shape = false;
            return;
        }
        std::vector<std::string> base_keys;
        std::vector<std::string> probe_keys;
        for (auto it = base.begin(); it != base.end(); ++it) base_keys.push_back(it.key());
        for (auto it = probe.begin(); it != probe.end(); ++it) probe_keys.push_back(it.key());
        std::sort(base_keys.begin(), base_keys.end());
        std::sort(probe_keys.begin(), probe_keys.end());
        if (base_keys != probe_keys) {
            diff.same_shape = false;
            return;
        }
        for (const auto& key : base_keys)
            compare_json_semantics(base.at(key), probe.at(key), path + "/" + key, diff);
        return;
    }
    if (base.is_array() || probe.is_array()) {
        if (!base.is_array() || !probe.is_array() || base.size() != probe.size()) {
            diff.same_shape = false;
            return;
        }
        for (size_t i = 0; i < base.size(); ++i)
            compare_json_semantics(base[i], probe[i], path + "/" + std::to_string(i), diff);
        return;
    }
    if (json_kind(base) != json_kind(probe)) {
        diff.same_shape = false;
        return;
    }
    if (base != probe) {
        ++diff.scalar_changes;
        if (sensitive_json_path(path)) {
            ++diff.sensitive_changes;
            if (diff.evidence.size() < 8) {
                diff.evidence.push_back(path + ":" + trunc_value(json_scalar_string(base)) + "=>" + trunc_value(json_scalar_string(probe)));
            }
        }
    }
}

json_semantic_diff_t semantic_json_diff(const std::vector<uint8_t>& baseline_body,
                                        const std::vector<uint8_t>& response_body)
{
    json_semantic_diff_t diff;
    try {
        auto base = nlohmann::json::parse(std::string(reinterpret_cast<const char*>(baseline_body.data()), baseline_body.size()));
        auto probe = nlohmann::json::parse(std::string(reinterpret_cast<const char*>(response_body.data()), response_body.size()));
        diff.parsed = true;
        compare_json_semantics(base, probe, "", diff);
    } catch (...) {
        diff.parsed = false;
    }
    return diff;
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
    if (resp.resp_body == base) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip identical body size=%zu", base.size());
        return std::nullopt;
    }
    auto diff = semantic_json_diff(base, resp.resp_body);
    if (!diff.parsed) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip non_json_or_parse_failed");
        return std::nullopt;
    }
    if (!diff.same_shape) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip shape_changed");
        return std::nullopt;
    }
    if (diff.sensitive_changes == 0) {
        diag::log_tagged_fmt("mod_idor", "idor_detect skip no_sensitive_json_changes scalar_changes=%zu", diff.scalar_changes);
        return std::nullopt;
    }

    std::ostringstream ev;
    ev << "same_status=" << resp.status_code
       << "; same_json_shape=1"
       << "; scalar_changes=" << diff.scalar_changes
       << "; sensitive_changes=" << diff.sensitive_changes
       << "; probe_value=" << probe.payload;
    for (const auto& item : diff.evidence)
        ev << "; " << item;

    diag::log_tagged_fmt("mod_idor", "idor_detect FINDING semantic-json ip=%s:%s variant=%s scalar_changes=%zu sensitive_changes=%zu",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(), diff.scalar_changes, diff.sensitive_changes);
    auto iss = make_issue("idor.semantic-json",
                          "Possible Insecure Direct Object Reference (IDOR)",
                          severity_t::high, confidence_t::tentative, ip, probe, resp, ctx,
                          ev.str());
    std::ostringstream desc;
    desc << "Modifying " << ip.name << " from '" << ip.original_value
         << "' to '" << probe.payload << "' returned HTTP " << resp.status_code
         << " with the same JSON shape but changed account/user/resource fields. Manually confirm the response discloses another resource's data.";
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
