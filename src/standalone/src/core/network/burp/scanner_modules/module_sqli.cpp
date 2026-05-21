#include "../scanner_module.hpp"
#include "../audit_http.hpp"
#include "../insertion_points.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <regex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace scanner {

namespace {

std::vector<probe_t> sqli_probes(const insertion_point_t& ip, const module_context_t&)
{
    diag::log_tagged_fmt("mod_sqli", "sqli_probes entry ip=%s:%s orig_value=%s",
                         ip.kind.c_str(), ip.name.c_str(), ip.original_value.c_str());
    std::vector<probe_t> out;
    auto base = ip.original_value;
    out.push_back({base + "' AND '1'='1",   std::string(), "bool_true_quote"});
    out.push_back({base + "' AND '1'='2",   std::string(), "bool_false_quote"});
    out.push_back({base + " AND 1=1",       std::string(), "bool_true_bare"});
    out.push_back({base + " AND 1=2",       std::string(), "bool_false_bare"});
    out.push_back({base + "'",              std::string(), "error_quote"});
    out.push_back({base + "\"",             std::string(), "error_dquote"});
    out.push_back({base + "'+SLEEP(8)--",   "_AIDA_SLEEP", "time_mysql"});
    out.push_back({base + "';SELECT pg_sleep(8)--", "_AIDA_SLEEP", "time_postgres"});
    out.push_back({base + "';WAITFOR DELAY '0:0:8'--", "_AIDA_SLEEP", "time_mssql"});
    diag::log_tagged_fmt("mod_sqli", "sqli_probes built %zu probes for ip=%s:%s",
                         out.size(), ip.kind.c_str(), ip.name.c_str());
    return out;
}

bool sql_error_text(const exchange_observed_t& resp, std::string& matched)
{
    static const std::regex re(
        R"((SQL syntax|mysql_fetch|MySQLSyntaxError|PostgreSQL.*ERROR|PG::SyntaxError|SQLSTATE\[)"
        R"(|ORA-\d{5}|Oracle\.DataAccess\.|System\.Data\.SqlClient|Unclosed quotation mark|SQLite3?::SQLException|sqlite3\.OperationalError|near \"\?\": syntax error))",
        std::regex::ECMAScript | std::regex::icase);
    std::string text(reinterpret_cast<const char*>(resp.resp_body.data()),
                     std::min<size_t>(resp.resp_body.size(), static_cast<size_t>(8192)));
    std::smatch m;
    if (std::regex_search(text, m, re)) { matched = m[0].str(); return true; }
    return false;
}

std::optional<issue_t> sqli_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_sqli", "sqli_detect entry ip=%s:%s variant=%s status=%d latency=%llums",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                         resp.status_code, static_cast<unsigned long long>(resp.latency_ms));
    if (probe.variant.rfind("error_", 0) == 0) {
        std::string matched;
        if (sql_error_text(resp, matched)) {
            diag::log_tagged_fmt("mod_sqli", "sqli_detect FINDING error-based ip=%s:%s matched=%s",
                                 ip.kind.c_str(), ip.name.c_str(), matched.c_str());
            auto iss = make_issue("sqli.error-based", "SQL Injection (error-based)",
                                  severity_t::high, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("SQL error in response: ") + matched);
            iss.description = "Injecting a SQL meta-character caused the backend to emit a database error, indicating the parameter is interpolated into a SQL query without proper parameterization.";
            iss.remediation = "Use parameterized queries / prepared statements; never interpolate untrusted input into SQL.";
            iss.cwe.push_back("CWE-89");
            return iss;
        }
        diag::log_tagged_fmt("mod_sqli", "sqli_detect error_ variant no match ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        return std::nullopt;
    }

    if (probe.variant.rfind("time_", 0) == 0) {
        if (ctx.baseline_latency_ms == 0) {
            diag::log_tagged_fmt("mod_sqli", "sqli_detect time_ skip no baseline ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
            return std::nullopt;
        }
        if (resp.latency_ms >= ctx.baseline_latency_ms + 7000) {
            diag::log_tagged_fmt("mod_sqli", "sqli_detect FINDING time-based ip=%s:%s baseline=%llums response=%llums",
                                 ip.kind.c_str(), ip.name.c_str(),
                                 static_cast<unsigned long long>(ctx.baseline_latency_ms),
                                 static_cast<unsigned long long>(resp.latency_ms));
            auto iss = make_issue("sqli.time-based", "SQL Injection (time-based blind)",
                                  severity_t::high, confidence_t::firm, ip, probe, resp, ctx,
                                  std::string("Latency increased: baseline=")
                                      + std::to_string(ctx.baseline_latency_ms) + "ms response="
                                      + std::to_string(resp.latency_ms) + "ms");
            iss.description = "A time-based blind SQLi payload caused a measurable server delay matching the injected sleep, indicating the parameter is concatenated into a SQL query.";
            iss.remediation = "Use parameterized queries; ensure stored procedures and ORMs bind parameters server-side.";
            iss.cwe.push_back("CWE-89");
            return iss;
        }
        diag::log_tagged_fmt("mod_sqli", "sqli_detect time_ latency insufficient baseline=%llums response=%llums",
                             static_cast<unsigned long long>(ctx.baseline_latency_ms),
                             static_cast<unsigned long long>(resp.latency_ms));
        return std::nullopt;
    }

    diag::log_tagged_fmt("mod_sqli", "sqli_detect no match variant=%s ip=%s:%s", probe.variant.c_str(), ip.kind.c_str(), ip.name.c_str());
    return std::nullopt;
}

void sqli_custom_run(const insertion_point_t& ip, const module_context_t& ctx, const send_fn_t& send)
{
    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run entry ip=%s:%s has_build=%d",
                         ip.kind.c_str(), ip.name.c_str(), ip.build ? 1 : 0);
    if (!ip.build) {
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run skip no build fn ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
        return;
    }

    auto fetch = [&](const std::string& payload, probe_t& used) -> std::optional<exchange_observed_t> {
        used.payload = ip.original_value + payload;
        used.variant = "boolean";
        auto built = ip.build(used.payload);
        return send(built, used);
    };

    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run sending bool_true probe ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    probe_t pt; pt.payload = ""; pt.variant = "bool_true";
    auto rt = fetch("' AND '1'='1", pt);
    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run sending bool_false probe ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
    probe_t pf; pf.payload = ""; pf.variant = "bool_false";
    auto rf = fetch("' AND '1'='2", pf);
    if (!rt.has_value() || !rf.has_value()) {
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run no response for boolean probes ip=%s:%s rt=%d rf=%d",
                             ip.kind.c_str(), ip.name.c_str(), rt.has_value() ? 1 : 0, rf.has_value() ? 1 : 0);
        return;
    }
    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run boolean responses true_status=%d false_status=%d true_size=%zu false_size=%zu",
                         rt->status_code, rf->status_code, rt->resp_body.size(), rf->resp_body.size());
    if (rt->status_code != rf->status_code && rt->status_code > 0 && rf->status_code > 0) {
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run FINDING boolean status-diff ip=%s:%s true=%d false=%d",
                             ip.kind.c_str(), ip.name.c_str(), rt->status_code, rf->status_code);
        auto iss = make_issue("sqli.boolean", "SQL Injection (boolean-based)",
                              severity_t::high, confidence_t::firm, ip, pt, *rt, ctx,
                              std::string("Status diff: true=") + std::to_string(rt->status_code)
                                  + " false=" + std::to_string(rf->status_code));
        iss.description = "Two semantically opposing SQL boolean payloads produced different responses, indicating the parameter influences SQL evaluation.";
        iss.remediation = "Parameterize all queries; never interpolate inputs into SQL text.";
        iss.cwe.push_back("CWE-89");
        issue_store::add(std::move(iss));
        return;
    }
    double ratio = body_length_ratio(*rt, *rf);
    long long diff = std::llabs(static_cast<long long>(rt->resp_body.size()) - static_cast<long long>(rf->resp_body.size()));
    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run body ratio=%.4f diff=%lld ip=%s:%s",
                         ratio, diff, ip.kind.c_str(), ip.name.c_str());
    if (ratio < 0.85 && diff > 32) {
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run FINDING boolean body-diff ip=%s:%s true_size=%zu false_size=%zu ratio=%.4f",
                             ip.kind.c_str(), ip.name.c_str(), rt->resp_body.size(), rf->resp_body.size(), ratio);
        auto iss = make_issue("sqli.boolean", "SQL Injection (boolean-based)",
                              severity_t::high, confidence_t::firm, ip, pt, *rt, ctx,
                              std::string("Body length diff: true=") + std::to_string(rt->resp_body.size())
                                  + " false=" + std::to_string(rf->resp_body.size())
                                  + " ratio=" + std::to_string(ratio));
        iss.description = "Two semantically opposing SQL boolean payloads produced substantially different response sizes, indicating injection.";
        iss.remediation = "Parameterize all queries; never interpolate inputs into SQL text.";
        iss.cwe.push_back("CWE-89");
        issue_store::add(std::move(iss));
    } else {
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run no boolean finding ip=%s:%s ratio=%.4f diff=%lld",
                             ip.kind.c_str(), ip.name.c_str(), ratio, diff);
    }
    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run complete ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
}

bool register_self()
{
    module_t m;
    m.id = "sqli";
    m.name = "SQL Injection";
    m.category = "Injection";
    m.max_probes_per_point = 9;
    m.probes = sqli_probes;
    m.detect = sqli_detect;
    m.custom_run = sqli_custom_run;
    return register_module(std::move(m));
}

const bool s_registered = register_self();

}

}
}
}
