#include "../scanner_module.hpp"
#include "../audit_http.hpp"
#include "../insertion_points.hpp"

#include "../../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
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
    out.push_back({base + "' OR '1'='1'--", std::string(), "auth_or_quote_comment"});
    out.push_back({base + "' OR 1=1--",     std::string(), "auth_or_bare_comment"});
    out.push_back({base + "\" OR \"1\"=\"1\"--", std::string(), "auth_or_dquote_comment"});
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
        R"(|ORA-\d{5}|Oracle\.DataAccess\.|System\.Data\.SqlClient|Unclosed quotation mark|SQLite3?::SQLException|sqlite3\.OperationalError|near \"\?\": syntax error)"
        R"(|java\.sql\.SQLException|java\.sql\.SQLSyntaxErrorException|SQLSyntaxErrorException|SQLState|SQLSTATE|org\.apache\.derby|ERROR [0-9A-Z]{5}|Syntax error: Encountered)"
        R"(|EmbedSQLException|StandardException|org\.apache\.derby\.iapi\.error|org\.apache\.derby\.impl\.jdbc|Derby SQL error)"
        R"(|SQL grammar|BadSqlGrammarException|org\.hibernate\.exception\.SQLGrammarException|org\.h2\.jdbc|JdbcSQLSyntaxErrorException|JdbcSQLIntegrityConstraintViolationException|H2 database error|JDBC exception|ServletException.*SQL|javax\.servlet\.ServletException))",
        std::regex::ECMAScript | std::regex::icase);
    std::string text(reinterpret_cast<const char*>(resp.resp_body.data()),
                     std::min<size_t>(resp.resp_body.size(), static_cast<size_t>(32768)));
    std::smatch m;
    if (std::regex_search(text, m, re)) { matched = m[0].str(); return true; }
    return false;
}

std::string body_prefix_lower(const std::vector<uint8_t>& body, size_t cap = 16384)
{
    const size_t n = std::min(body.size(), cap);
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(body[i]))));
    return out;
}

bool is_redirect_status(int status)
{
    return status >= 300 && status < 400;
}

bool body_has_auth_failure_text(const std::vector<uint8_t>& body)
{
    const std::string text = body_prefix_lower(body);
    static const char* needles[] = {
        "login failed",
        "invalid password",
        "invalid username",
        "invalid credentials",
        "authentication failed",
        "sign in failed",
        "incorrect password",
        "try again"
    };
    for (const char* needle : needles) {
        if (text.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

std::vector<response_marker_t> auth_failure_markers()
{
    return {
        {"login_failed", "login failed"},
        {"invalid_password", "invalid password"},
        {"invalid_username", "invalid username"},
        {"invalid_credentials", "invalid credentials"},
        {"authentication_failed", "authentication failed"},
        {"signin_failed", "sign in failed"},
        {"incorrect_password", "incorrect password"},
        {"try_again", "try again"},
        {"bad_credentials", "bad credentials"},
        {"not_authorized", "not authorized"}
    };
}

std::vector<response_marker_t> auth_success_markers()
{
    return {
        {"logout", "logout"},
        {"signout", "sign out"},
        {"account_summary", "account summary"},
        {"my_account", "my account"},
        {"transfer_funds", "transfer funds"},
        {"dashboard", "dashboard"},
        {"authenticated", "authenticated"},
        {"welcome", "welcome"}
    };
}

bool authenticated_location(const std::string& location)
{
    std::string lc = location;
    std::transform(lc.begin(), lc.end(), lc.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    static const char* needles[] = {
        "/bank/",
        "/account",
        "/accounts",
        "/dashboard",
        "/home",
        "/main",
        "/profile",
        "/admin",
        "/secure",
        "/authenticated"
    };
    for (const char* n : needles) {
        if (lc.find(n) != std::string::npos)
            return true;
    }
    return false;
}

bool auth_bypass_delta(const exchange_observed_t& resp, const module_context_t& ctx, std::string& evidence)
{
    auto diff = compare_response_to_baseline(resp, ctx, auth_failure_markers(), auth_success_markers());
    if (!diff.baseline_known)
        return false;
    const bool baseline_redirect = is_redirect_status(diff.baseline_status);
    const bool resp_redirect = is_redirect_status(resp.status_code);
    const bool baseline_failed = body_has_auth_failure_text(ctx.baseline_response_body);
    const bool resp_failed = body_has_auth_failure_text(resp.resp_body);
    const bool auth_location = authenticated_location(diff.response_location);
    if (resp_redirect && !baseline_redirect && auth_location) {
        evidence = "Injected SQL auth payload produced redirect to authenticated area; " + diff.evidence;
        return true;
    }
    if (resp_redirect && diff.location_changed && auth_location) {
        evidence = "Injected SQL auth payload changed redirect Location to authenticated area; " + diff.evidence;
        return true;
    }
    if (baseline_failed && !resp_failed && diff.status_changed) {
        evidence = "Injected SQL auth payload removed authentication failure text and changed status; " + diff.evidence;
        return true;
    }
    if (!diff.removed_markers.empty() && (diff.status_changed || diff.location_changed || diff.meaningful_body_delta || !diff.added_markers.empty())) {
        evidence = "Injected SQL auth payload removed login-failure markers; " + diff.evidence;
        return true;
    }
    if (!diff.added_markers.empty() && (diff.status_changed || diff.location_changed || diff.meaningful_body_delta)) {
        evidence = "Injected SQL auth payload added authenticated-area markers; " + diff.evidence;
        return true;
    }
    return false;
}

bool boolean_response_delta(const exchange_observed_t& false_resp, const exchange_observed_t& true_resp, std::string& evidence)
{
    auto diff = compare_responses(false_resp, true_resp, auth_failure_markers(), auth_success_markers());
    if (diff.status_changed && diff.response_status > 0 && diff.baseline_status > 0) {
        evidence = "Boolean SQL payload status delta; " + diff.evidence;
        return true;
    }
    if (diff.location_changed && authenticated_location(diff.response_location)) {
        evidence = "Boolean SQL payload changed Location to authenticated area; " + diff.evidence;
        return true;
    }
    if (diff.meaningful_body_delta && (!diff.removed_markers.empty() || !diff.added_markers.empty())) {
        evidence = "Boolean SQL payload changed authentication markers; " + diff.evidence;
        return true;
    }
    if (diff.meaningful_body_delta && diff.body_length_delta > 32) {
        evidence = "Boolean SQL payload produced meaningful body delta; " + diff.evidence;
        return true;
    }
    return false;
}

std::optional<issue_t> sqli_detect(const insertion_point_t& ip, const probe_t& probe,
                                   const exchange_observed_t& resp, const module_context_t& ctx)
{
    diag::log_tagged_fmt("mod_sqli", "sqli_detect entry ip=%s:%s variant=%s status=%d latency=%llums",
                         ip.kind.c_str(), ip.name.c_str(), probe.variant.c_str(),
                         resp.status_code, static_cast<unsigned long long>(resp.latency_ms));
    if (probe.variant.rfind("auth_", 0) == 0) {
        std::string evidence;
        if (auth_bypass_delta(resp, ctx, evidence)) {
            diag::log_tagged_fmt("mod_sqli", "sqli_detect FINDING auth-bypass ip=%s:%s evidence=%s",
                                 ip.kind.c_str(), ip.name.c_str(), evidence.c_str());
            auto iss = make_issue("sqli.auth-bypass", "SQL Injection (authentication bypass)",
                                  severity_t::critical, confidence_t::firm, ip, probe, resp, ctx, evidence);
            iss.description = "An SQL boolean/auth-bypass payload produced an authenticated-style response delta compared with the baseline request, consistent with credential checks being evaluated inside injectable SQL.";
            iss.remediation = "Use parameterized queries for authentication lookups and enforce authentication state independently of SQL result shape.";
            iss.cwe.push_back("CWE-89");
            return iss;
        }
        diag::log_tagged_fmt("mod_sqli", "sqli_detect auth_ variant no bypass delta ip=%s:%s baseline_status=%d status=%d",
                             ip.kind.c_str(), ip.name.c_str(), ctx.baseline_status_code, resp.status_code);
        return std::nullopt;
    }

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

    auto build_injected = [&](const std::string& payload) {
        if (ip.build_with_options) {
            insertion_point_build_options_t options;
            options.force_json_string = true;
            return ip.build_with_options(payload, options);
        }
        return ip.build ? ip.build(payload) : std::vector<uint8_t>(ip.base_request.begin(), ip.base_request.end());
    };

    auto fetch = [&](const std::string& payload, const std::string& variant, probe_t& used) -> std::optional<exchange_observed_t> {
        used.payload = ip.original_value + payload;
        used.variant = variant;
        auto built = build_injected(used.payload);
        return send(built, used);
    };

    struct pair_t { const char* true_suffix; const char* false_suffix; const char* variant; bool auth; };
    const pair_t pairs[] = {
        {"' AND '1'='1", "' AND '1'='2", "bool_and_quote", false},
        {" AND 1=1", " AND 1=2", "bool_and_bare", false},
        {"' OR '1'='1'--", "' AND '1'='2'--", "auth_or_quote_comment", true},
        {"' OR 1=1--", "' AND 1=2--", "auth_or_bare_comment", true},
        {"\" OR \"1\"=\"1\"--", "\" AND \"1\"=\"2\"--", "auth_or_dquote_comment", true}
    };

    for (const auto& pair : pairs) {
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run sending pair variant=%s ip=%s:%s",
                             pair.variant, ip.kind.c_str(), ip.name.c_str());
        probe_t pt; pt.payload = ""; pt.variant = std::string(pair.variant) + "_true";
        auto rt = fetch(pair.true_suffix, pt.variant, pt);
        probe_t pf; pf.payload = ""; pf.variant = std::string(pair.variant) + "_false";
        auto rf = fetch(pair.false_suffix, pf.variant, pf);
        if (!rt.has_value() || !rf.has_value()) {
            diag::log_tagged_fmt("mod_sqli", "sqli_custom_run no response for pair variant=%s ip=%s:%s rt=%d rf=%d",
                                 pair.variant, ip.kind.c_str(), ip.name.c_str(), rt.has_value() ? 1 : 0, rf.has_value() ? 1 : 0);
            continue;
        }
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run pair responses variant=%s true_status=%d false_status=%d true_size=%zu false_size=%zu baseline_status=%d",
                             pair.variant, rt->status_code, rf->status_code, rt->resp_body.size(), rf->resp_body.size(), ctx.baseline_status_code);
        std::string auth_evidence;
        const bool pair_delta = boolean_response_delta(*rf, *rt, auth_evidence);
        if (pair.auth && auth_bypass_delta(*rt, ctx, auth_evidence) && (rt->status_code != rf->status_code || pair_delta)) {
            diag::log_tagged_fmt("mod_sqli", "sqli_custom_run FINDING auth-bypass variant=%s ip=%s:%s evidence=%s",
                                 pair.variant, ip.kind.c_str(), ip.name.c_str(), auth_evidence.c_str());
            auto iss = make_issue("sqli.auth-bypass", "SQL Injection (authentication bypass)",
                                  severity_t::critical, confidence_t::firm, ip, pt, *rt, ctx, auth_evidence);
            iss.description = "A true SQL auth-bypass payload and a false SQL control payload produced divergent authenticated-style responses, indicating credential checks are injectable.";
            iss.remediation = "Use server-side parameter binding for authentication SQL and treat redirects/session issuance as security-sensitive scanner signals.";
            iss.cwe.push_back("CWE-89");
            issue_store::add(std::move(iss));
            return;
        }
        std::string bool_evidence;
        if (boolean_response_delta(*rf, *rt, bool_evidence)) {
            diag::log_tagged_fmt("mod_sqli", "sqli_custom_run FINDING boolean status-diff variant=%s ip=%s:%s true=%d false=%d",
                                 pair.variant, ip.kind.c_str(), ip.name.c_str(), rt->status_code, rf->status_code);
            auto iss = make_issue("sqli.boolean", "SQL Injection (boolean-based)",
                                  severity_t::high, confidence_t::firm, ip, pt, *rt, ctx,
                                  bool_evidence);
            iss.description = "Two semantically opposing SQL boolean payloads produced different responses, indicating the parameter influences SQL evaluation.";
            iss.remediation = "Parameterize all queries; never interpolate inputs into SQL text.";
            iss.cwe.push_back("CWE-89");
            issue_store::add(std::move(iss));
            return;
        }
        double ratio = body_length_ratio(*rt, *rf);
        long long diff = std::llabs(static_cast<long long>(rt->resp_body.size()) - static_cast<long long>(rf->resp_body.size()));
        diag::log_tagged_fmt("mod_sqli", "sqli_custom_run body ratio=%.4f diff=%lld variant=%s ip=%s:%s",
                             ratio, diff, pair.variant, ip.kind.c_str(), ip.name.c_str());
        if (ratio < 0.85 && diff > 32) {
            diag::log_tagged_fmt("mod_sqli", "sqli_custom_run FINDING boolean body-diff variant=%s ip=%s:%s true_size=%zu false_size=%zu ratio=%.4f",
                                 pair.variant, ip.kind.c_str(), ip.name.c_str(), rt->resp_body.size(), rf->resp_body.size(), ratio);
            auto iss = make_issue("sqli.boolean", "SQL Injection (boolean-based)",
                                  severity_t::high, confidence_t::firm, ip, pt, *rt, ctx,
                                  std::string("Body length diff: true=") + std::to_string(rt->resp_body.size())
                                      + " false=" + std::to_string(rf->resp_body.size())
                                      + " ratio=" + std::to_string(ratio));
            iss.description = "Two semantically opposing SQL boolean payloads produced substantially different response sizes, indicating injection.";
            iss.remediation = "Parameterize all queries; never interpolate inputs into SQL text.";
            iss.cwe.push_back("CWE-89");
            issue_store::add(std::move(iss));
            return;
        }
    }
    diag::log_tagged_fmt("mod_sqli", "sqli_custom_run complete ip=%s:%s", ip.kind.c_str(), ip.name.c_str());
}

bool register_self()
{
    module_t m;
    m.id = "sqli";
    m.name = "SQL Injection";
    m.category = "Injection";
    m.max_probes_per_point = 12;
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
