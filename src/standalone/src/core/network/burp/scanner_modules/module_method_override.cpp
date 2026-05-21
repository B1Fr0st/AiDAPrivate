#include "../scanner_module.hpp"
#include "../audit_http.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

static std::string ascii_upper(const std::string& v)
{
    std::string r; r.reserve(v.size());
    for (char c : v) r.push_back((c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c);
    return r;
}

static std::string extract_method(const std::string& base_request)
{
    size_t sp = base_request.find(' ');
    if (sp == std::string::npos) return std::string();
    return base_request.substr(0, sp);
}

static bool insertion_point_is_request_line(const insertion_point_t& ip)
{
    return ip.value_offset < 64;
}

static std::vector<uint8_t> add_header_to_request(const std::string& base, const std::string& header_line)
{
    auto body_off = base.find("\r\n\r\n");
    if (body_off == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    std::string out = base.substr(0, body_off + 2);
    out += header_line;
    out += "\r\n";
    out += base.substr(body_off + 2);
    return std::vector<uint8_t>(out.begin(), out.end());
}

static std::vector<uint8_t> change_method(const std::string& base, const std::string& new_method)
{
    size_t sp = base.find(' ');
    if (sp == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    std::string out = new_method + base.substr(sp);
    return std::vector<uint8_t>(out.begin(), out.end());
}

static std::vector<uint8_t> add_query_param(const std::string& base, const std::string& key, const std::string& value)
{
    size_t sp1 = base.find(' ');
    if (sp1 == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    size_t sp2 = base.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return std::vector<uint8_t>(base.begin(), base.end());
    std::string method = base.substr(0, sp1);
    std::string path = base.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string rest = base.substr(sp2);
    std::string sep = path.find('?') == std::string::npos ? "?" : "&";
    std::string new_path = path + sep + key + "=" + value;
    return std::vector<uint8_t>((method + " " + new_path + rest).begin(),
                                (method + " " + new_path + rest).end());
}

void method_override_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_method", "method_override_run entry ip=%s:%s host=%s", ip.kind.c_str(), ip.name.c_str(), ctx.host.c_str());
    if (!insertion_point_is_request_line(ip)) {
        diag::log_tagged_fmt("mod_method", "method_override_run skip not request-line");
        return;
    }
    if (ip.base_request.empty()) {
        diag::log_tagged_fmt("mod_method", "method_override_run skip empty request");
        return;
    }

    std::string orig_method = extract_method(ip.base_request);
    if (orig_method.empty()) {
        diag::log_tagged_fmt("mod_method", "method_override_run skip no method");
        return;
    }
    orig_method = ascii_upper(orig_method);
    if (orig_method != "GET" && orig_method != "POST") {
        diag::log_tagged_fmt("mod_method", "method_override_run skip non-GET/POST method=%s", orig_method.c_str());
        return;
    }
    diag::log_tagged_fmt("mod_method", "method_override_run testing method=%s host=%s", orig_method.c_str(), ctx.host.c_str());

    audit_http::send_options_t opt;
    opt.timeout_ms = ctx.timeout_ms > 0 ? ctx.timeout_ms : 10000;
    opt.follow_redirects = false;

    diag::log_tagged_fmt("mod_method", "method_override_run fetching baseline timeout=%dms", opt.timeout_ms);
    auto baseline = audit_http::send(std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end()),
                                     ctx.host, ctx.port, ctx.tls, opt);
    if (!baseline.has_value()) {
        diag::log_tagged_fmt("mod_method", "method_override_run no baseline response");
        return;
    }
    int baseline_status = baseline->status_code;
    diag::log_tagged_fmt("mod_method", "method_override_run baseline status=%d method=%s", baseline_status, orig_method.c_str());

    struct variant_t { std::string id; std::string description; std::vector<uint8_t> req; };
    std::vector<variant_t> variants;

    variants.push_back({ "x-http-method-override-delete",
                         "X-HTTP-Method-Override: DELETE on " + orig_method,
                         add_header_to_request(ip.base_request, "X-HTTP-Method-Override: DELETE") });
    variants.push_back({ "x-http-method-override-put",
                         "X-HTTP-Method-Override: PUT on " + orig_method,
                         add_header_to_request(ip.base_request, "X-HTTP-Method-Override: PUT") });
    variants.push_back({ "x-method-override-patch",
                         "X-Method-Override: PATCH on " + orig_method,
                         add_header_to_request(ip.base_request, "X-Method-Override: PATCH") });
    variants.push_back({ "_method-query-delete",
                         "_method=DELETE query parameter",
                         add_query_param(ip.base_request, "_method", "DELETE") });
    variants.push_back({ "raw-delete",
                         "Raw DELETE retry of GET/POST",
                         change_method(ip.base_request, "DELETE") });
    variants.push_back({ "raw-put",
                         "Raw PUT retry of GET/POST",
                         change_method(ip.base_request, "PUT") });
    variants.push_back({ "raw-patch",
                         "Raw PATCH retry of GET/POST",
                         change_method(ip.base_request, "PATCH") });
    variants.push_back({ "raw-options",
                         "Raw OPTIONS information disclosure",
                         change_method(ip.base_request, "OPTIONS") });
    variants.push_back({ "raw-trace",
                         "Raw TRACE information disclosure",
                         change_method(ip.base_request, "TRACE") });

    diag::log_tagged_fmt("mod_method", "method_override_run testing %zu variants baseline_status=%d", variants.size(), baseline_status);
    for (auto& v : variants) {
        diag::log_tagged_fmt("mod_method", "method_override_run probe variant=%s", v.id.c_str());
        probe_t p;
        p.variant = v.id;
        p.payload = v.description;
        p.marker = "method-override";
        auto resp = send(v.req, p);
        if (!resp.has_value()) {
            diag::log_tagged_fmt("mod_method", "method_override_run no response for variant=%s", v.id.c_str());
            continue;
        }
        diag::log_tagged_fmt("mod_method", "method_override_run variant=%s status=%d", v.id.c_str(), resp->status_code);

        if (v.id == "raw-options") {
            std::string allow_header;
            for (auto& h : resp->resp_headers) {
                std::string lname; lname.reserve(h.first.size());
                for (char c : h.first) lname.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c);
                if (lname == "allow") { allow_header = h.second; break; }
            }
            if (resp->status_code == 200 && !allow_header.empty()) {
                diag::log_tagged_fmt("mod_method", "method_override_run FINDING options-leak allow=%s", allow_header.c_str());
                std::string evidence = "OPTIONS returned 200 with Allow header: " + allow_header;
                auto iss = make_issue("method-override.options-leak",
                                      "OPTIONS method discloses allowed verbs",
                                      severity_t::info, confidence_t::firm,
                                      ip, p, *resp, ctx, evidence);
                iss.description = "The OPTIONS verb returned an Allow header that enumerates server-supported methods. This is informational but useful for an attacker mapping the API surface.";
                iss.remediation = "Restrict OPTIONS responses on production endpoints, or ensure the Allow list accurately reflects authorization-checked verbs only.";
                iss.cwe.push_back("CWE-200");
                issue_store::add(std::move(iss));
            }
            continue;
        }

        if (v.id == "raw-trace") {
            if (resp->status_code == 200) {
                diag::log_tagged_fmt("mod_method", "method_override_run FINDING trace-enabled status=200");
                std::string evidence = "TRACE returned 200 (TRACE may be enabled)";
                auto iss = make_issue("method-override.trace-enabled",
                                      "TRACE method enabled",
                                      severity_t::low, confidence_t::firm,
                                      ip, p, *resp, ctx, evidence);
                iss.description = "The server responded 200 OK to a TRACE request. TRACE can be abused for Cross-Site Tracing (XST) when combined with another vulnerability.";
                iss.remediation = "Disable TRACE on the web server (TraceEnable Off / equivalent).";
                iss.cwe.push_back("CWE-693");
                issue_store::add(std::move(iss));
            }
            continue;
        }

        bool privileged_verb = v.id == "raw-delete" || v.id == "raw-put" || v.id == "raw-patch"
                            || v.id == "_method-query-delete"
                            || v.id == "x-http-method-override-delete"
                            || v.id == "x-http-method-override-put"
                            || v.id == "x-method-override-patch";

        if (privileged_verb) {
            bool baseline_405 = (baseline_status == 405 || baseline_status == 501);
            bool now_ok = (resp->status_code >= 200 && resp->status_code < 400);
            bool now_authed = (resp->status_code == 401 || resp->status_code == 403);
            diag::log_tagged_fmt("mod_method", "method_override_run privileged variant=%s baseline_405=%d now_ok=%d now_authed=%d",
                                 v.id.c_str(), baseline_405 ? 1 : 0, now_ok ? 1 : 0, now_authed ? 1 : 0);
            if (baseline_405 && now_ok) {
                diag::log_tagged_fmt("mod_method", "method_override_run FINDING privileged-verb-allowed variant=%s baseline=%d probe=%d",
                                     v.id.c_str(), baseline_status, resp->status_code);
                std::string evidence = v.description + ": baseline " + std::to_string(baseline_status)
                                     + " -> " + std::to_string(resp->status_code);
                auto iss = make_issue("method-override.privileged-verb-allowed",
                                      "HTTP method override permits privileged verb",
                                      severity_t::high, confidence_t::firm,
                                      ip, p, *resp, ctx, evidence);
                iss.description = "The endpoint rejected the original verb but accepted the privileged verb after applying " + v.description + ". An attacker can likely bypass server-side method enforcement.";
                iss.remediation = "Strip X-HTTP-Method-Override / X-Method-Override / _method at the gateway; enforce HTTP method authorization independently of any client-supplied override.";
                iss.cwe.push_back("CWE-285");
                iss.cwe.push_back("CWE-650");
                issue_store::add(std::move(iss));
            } else if (now_ok && baseline_status >= 200 && baseline_status < 400
                       && resp->resp_body.size() != baseline->resp_body.size()) {
                size_t diff = resp->resp_body.size() > baseline->resp_body.size()
                              ? resp->resp_body.size() - baseline->resp_body.size()
                              : baseline->resp_body.size() - resp->resp_body.size();
                if (diff > 32) {
                    diag::log_tagged_fmt("mod_method", "method_override_run FINDING behavior-divergence variant=%s size_delta=%zu",
                                         v.id.c_str(), diff);
                    std::string evidence = v.description + ": status=" + std::to_string(resp->status_code)
                                         + " (baseline=" + std::to_string(baseline_status)
                                         + ") size_delta=" + std::to_string(diff);
                    auto iss = make_issue("method-override.behavior-divergence",
                                          "HTTP method override changes response",
                                          severity_t::medium, confidence_t::tentative,
                                          ip, p, *resp, ctx, evidence);
                    iss.description = "The endpoint accepted both the original verb and the override-mutated verb, but the responses diverge significantly. This often indicates a code path silently switched by the override header.";
                    iss.remediation = "Audit the server-side override unwrapper. Avoid mapping client-controlled method overrides to verbs that bypass authorization or trigger different handlers.";
                    iss.cwe.push_back("CWE-650");
                    issue_store::add(std::move(iss));
                }
            } else if (now_authed && baseline_status == 405) {
                diag::log_tagged_fmt("mod_method", "method_override_run FINDING auth-boundary variant=%s baseline=%d probe=%d",
                                     v.id.c_str(), baseline_status, resp->status_code);
                std::string evidence = v.description + ": baseline " + std::to_string(baseline_status)
                                     + " -> " + std::to_string(resp->status_code)
                                     + " (auth boundary reached via override)";
                auto iss = make_issue("method-override.auth-boundary",
                                      "HTTP method override reaches authentication boundary",
                                      severity_t::low, confidence_t::tentative,
                                      ip, p, *resp, ctx, evidence);
                iss.description = "The privileged verb is reachable through the override and the server enforces authentication (rather than 405). The verb is therefore routed; an authenticated bypass should be evaluated.";
                iss.remediation = "Disable client-controlled method overrides at the gateway.";
                iss.cwe.push_back("CWE-650");
                issue_store::add(std::move(iss));
            }
        }
    }
    diag::log_tagged_fmt("mod_method", "method_override_run complete ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
}

bool register_self()
{
    module_t m;
    m.id = "method_override";
    m.name = "HTTP method override";
    m.category = "Access Control";
    m.max_probes_per_point = 9;
    m.probes = [](const insertion_point_t&, const module_context_t&) { return std::vector<probe_t>{}; };
    m.custom_run = method_override_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
