#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "report_generator.hpp"

#include "audit_session.hpp"
#include "audit_trail.hpp"
#include "evidence_store.hpp"
#include "findings_db.hpp"
#include "../../../helpers/diag_log.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>

namespace aida {
namespace burp {
namespace report {

namespace {

std::mutex& err_mtx()  { static std::mutex m; return m; }
std::string& err_slot() { static std::string s; return s; }

void set_err(const std::string& m)
{
    std::lock_guard<std::mutex> lk(err_mtx());
    err_slot() = m;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

struct history_t
{
    std::mutex                          mtx;
    std::vector<generated_report_t>     items;
    std::atomic<uint64_t>               next_id{1};
};

history_t& history()
{
    static history_t h;
    return h;
}

std::string html_escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string safe_text(const std::string& s, size_t cap = 2048)
{
    return evidence_store::redact_sensitive_text(s, cap);
}

std::string safe_html(const std::string& s, size_t cap = 2048)
{
    return html_escape(safe_text(s, cap));
}

std::string format_ts(uint64_t ms)
{
    time_t t = static_cast<time_t>(ms / 1000);
    std::tm tm_buf{};
    gmtime_s(&tm_buf, &t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return buf;
}

const char* severity_class(severity_t s)
{
    switch (s) {
        case severity_t::info:     return "info";
        case severity_t::low:      return "low";
        case severity_t::medium:   return "medium";
        case severity_t::high:     return "high";
        case severity_t::critical: return "critical";
    }
    return "info";
}

const char* sarif_level(severity_t s)
{
    switch (s) {
        case severity_t::info:     return "note";
        case severity_t::low:      return "note";
        case severity_t::medium:   return "warning";
        case severity_t::high:     return "error";
        case severity_t::critical: return "error";
    }
    return "note";
}

std::string truncate_for_evidence(const std::string& s, size_t cap)
{
    return safe_text(s, cap);
}

std::string lower_copy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool issue_matches_config(const issue_t& issue, const report_config_t& cfg)
{
    if (!cfg.include_suppressed && issue.suppressed)
        return false;
    if (!cfg.session_id.empty() && issue.session_id != cfg.session_id)
        return false;
    if (cfg.has_audit_id && issue.audit_id != cfg.audit_id)
        return false;
    if (cfg.has_severity_min && static_cast<int>(issue.severity) < static_cast<int>(cfg.severity_min))
        return false;
    if (!cfg.target_domain.empty()) {
        const std::string want = lower_copy(cfg.target_domain);
        const std::string host = lower_copy(issue.host);
        if (host.find(want) == std::string::npos)
            return false;
    }
    return true;
}

bool collect_issues(const report_config_t& cfg, std::vector<issue_t>& out)
{
    out.clear();
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false)) {
        set_err(findings_db::last_error().empty() ? "report.generate: findings database unavailable" : findings_db::last_error());
        return false;
    }
    if (!cfg.include_issue_ids.empty()) {
        for (uint64_t id : cfg.include_issue_ids) {
            issue_t issue;
            if (findings_db::get(id, issue) && issue_matches_config(issue, cfg))
                out.push_back(std::move(issue));
        }
    } else {
        findings_db::finding_filter_t filter;
        filter.session_id = cfg.session_id;
        filter.has_audit_id = cfg.has_audit_id;
        filter.audit_id = cfg.audit_id;
        filter.has_severity_min = cfg.has_severity_min;
        filter.severity_min = cfg.severity_min;
        filter.host_substring = cfg.target_domain;
        filter.include_suppressed = cfg.include_suppressed;
        filter.limit = 0;
        out = findings_db::list(filter);
    }
    std::sort(out.begin(), out.end(), [](const issue_t& a, const issue_t& b) {
        if (a.severity != b.severity) return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        if (a.confidence != b.confidence) return static_cast<int>(a.confidence) > static_cast<int>(b.confidence);
        return a.seen_ms > b.seen_ms;
    });
    return true;
}

size_t severity_count(const std::vector<issue_t>& issues, severity_t severity)
{
    size_t count = 0;
    for (const auto& issue : issues)
        if (issue.severity == severity)
            ++count;
    return count;
}

nlohmann::json severity_counts_json(const std::vector<issue_t>& issues)
{
    return nlohmann::json{
        {"critical", severity_count(issues, severity_t::critical)},
        {"high", severity_count(issues, severity_t::high)},
        {"medium", severity_count(issues, severity_t::medium)},
        {"low", severity_count(issues, severity_t::low)},
        {"info", severity_count(issues, severity_t::info)}
    };
}

double risk_score(const std::vector<issue_t>& issues)
{
    double score = 0.0;
    for (const auto& issue : issues) {
        switch (issue.severity) {
            case severity_t::critical: score += 20.0; break;
            case severity_t::high: score += 12.0; break;
            case severity_t::medium: score += 6.0; break;
            case severity_t::low: score += 2.0; break;
            case severity_t::info: score += 0.5; break;
        }
    }
    return (std::min)(100.0, score);
}

std::string risk_posture(double score)
{
    if (score >= 80.0) return "critical";
    if (score >= 50.0) return "high";
    if (score >= 25.0) return "moderate";
    if (score > 0.0) return "low";
    return "clear";
}

nlohmann::json recommendations_json(const std::vector<issue_t>& issues)
{
    std::map<std::string, size_t> counts;
    for (const auto& issue : issues) {
        std::string text = issue.remediation.empty() ? std::string("Review and remediate ") + (issue.name.empty() ? issue.type_key : issue.name) : issue.remediation;
        counts[evidence_store::redact_sensitive_text(text, 320)]++;
    }
    std::vector<std::pair<std::string, size_t>> rows(counts.begin(), counts.end());
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) return a.second > b.second;
        return a.first < b.first;
    });
    nlohmann::json out = nlohmann::json::array();
    for (const auto& row : rows) {
        out.push_back({{"recommendation", row.first}, {"finding_count", row.second}});
        if (out.size() >= 10) break;
    }
    return out;
}

nlohmann::json issue_to_report_json(const issue_t& issue, bool include_evidence)
{
    nlohmann::json j = issue_store::issue_to_json(issue);
    j["finding_id"] = issue.id;
    j["session_id"] = issue.session_id;
    j["scan_id"] = issue.scan_id;
    j["cvss_score"] = issue.cvss_score;
    j["cvss_vector"] = evidence_store::redact_sensitive_text(issue.cvss_vector, 256);
    j["cvss_severity"] = evidence_store::redact_sensitive_text(issue.cvss_severity, 64);
    j["owasp_category"] = evidence_store::redact_sensitive_text(issue.owasp_category, 128);
    j["suppressed"] = issue.suppressed;
    if (!include_evidence)
        j.erase("evidence");
    else
        j["stored_evidence"] = evidence_store::export_json(issue.id)["evidence"];
    return evidence_store::redact_sensitive_json(j, 4096);
}

nlohmann::json audit_entries_json(const report_config_t& cfg, const std::string& tool_filter)
{
    audit_trail::query_filter_t filter;
    filter.session_id = cfg.session_id;
    filter.tool_name_substring = tool_filter;
    filter.limit = cfg.audit_trail_limit == 0 ? 128 : cfg.audit_trail_limit;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& rec : audit_trail::query(filter))
        arr.push_back(audit_trail::record_to_json(rec));
    return evidence_store::redact_sensitive_json(arr, 2048);
}

bool run_id_selected(const nlohmann::json& record, const std::vector<std::string>& ids)
{
    if (ids.empty())
        return true;
    const std::string text = record.dump();
    for (const auto& id : ids)
        if (!id.empty() && text.find(id) != std::string::npos)
            return true;
    return false;
}

bool text_contains_ci(const std::string& text, const std::string& needle)
{
    if (needle.empty())
        return true;
    return lower_copy(text).find(lower_copy(needle)) != std::string::npos;
}

bool json_contains_text_ci(const nlohmann::json& value, const std::string& needle)
{
    if (needle.empty())
        return true;
    if (value.is_string())
        return text_contains_ci(value.get<std::string>(), needle);
    if (value.is_array()) {
        for (const auto& item : value)
            if (json_contains_text_ci(item, needle))
                return true;
        return false;
    }
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it)
            if (json_contains_text_ci(it.value(), needle))
                return true;
        return false;
    }
    return false;
}

bool json_value_matches_u64(const nlohmann::json& value, uint64_t expected)
{
    if (value.is_number_unsigned())
        return value.get<uint64_t>() == expected;
    if (value.is_number_integer()) {
        const auto signed_value = value.get<int64_t>();
        return signed_value >= 0 && static_cast<uint64_t>(signed_value) == expected;
    }
    if (value.is_string()) {
        const std::string s = value.get<std::string>();
        if (s.empty())
            return false;
        try {
            size_t idx = 0;
            const uint64_t parsed = std::stoull(s, &idx, 10);
            return idx == s.size() && parsed == expected;
        } catch (...) {
            return false;
        }
    }
    return false;
}

bool json_contains_u64_key(const nlohmann::json& value, const char* key, uint64_t expected)
{
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (it.key() == key && json_value_matches_u64(it.value(), expected))
                return true;
            if (json_contains_u64_key(it.value(), key, expected))
                return true;
        }
        return false;
    }
    if (value.is_array()) {
        for (const auto& item : value)
            if (json_contains_u64_key(item, key, expected))
                return true;
    }
    return false;
}

bool context_record_selected(const nlohmann::json& record, const report_config_t& cfg)
{
    if (!run_id_selected(record, cfg.include_offensive_run_ids))
        return false;
    if (cfg.has_audit_id && !json_contains_u64_key(record, "audit_id", cfg.audit_id))
        return false;
    if (!cfg.target_domain.empty() && !json_contains_text_ci(record, cfg.target_domain))
        return false;
    return true;
}

nlohmann::json offensive_context_json(const report_config_t& cfg)
{
    nlohmann::json out;
    out["target_domain"] = evidence_store::redact_sensitive_text(cfg.target_domain, 256);
    out["include_recon"] = cfg.include_recon;
    out["requested_run_ids"] = nlohmann::json::array();
    for (const auto& id : cfg.include_offensive_run_ids)
        out["requested_run_ids"].push_back(evidence_store::sha256_hex(id).substr(0, 16));
    out["source"] = "sqlite_audit_trail";
    out["offensive_events"] = nlohmann::json::array();
    out["recon_events"] = nlohmann::json::array();
    auto offensive = audit_entries_json(cfg, "offensive");
    if (offensive.is_array()) {
        for (const auto& rec : offensive)
            if (context_record_selected(rec, cfg))
                out["offensive_events"].push_back(rec);
    }
    if (cfg.include_recon) {
        auto recon = audit_entries_json(cfg, "recon");
        if (recon.is_array()) {
            for (const auto& rec : recon)
                if (context_record_selected(rec, cfg))
                    out["recon_events"].push_back(rec);
        }
    }
    out["available"] = !out["offensive_events"].empty() || !out["recon_events"].empty();
    return out;
}

nlohmann::json session_context_json(const report_config_t& cfg)
{
    if (cfg.session_id.empty() || !cfg.include_session_context)
        return nlohmann::json::object();
    audit_session::session_t session;
    nlohmann::json out = nlohmann::json::object();
    if (audit_session::get(cfg.session_id, session))
        out["session"] = audit_session::session_to_json(session, true);
    evidence_store::evidence_filter_t ev_filter;
    ev_filter.session_id = cfg.session_id;
    ev_filter.limit = 256;
    out["evidence"] = nlohmann::json::array();
    for (const auto& ev : evidence_store::list(ev_filter))
        out["evidence"].push_back(evidence_store::summary_json(ev));
    out["evidence_count"] = out["evidence"].size();
    if (cfg.include_audit_trail) {
        out["audit_trail"] = audit_entries_json(cfg, std::string());
        out["audit_trail_count"] = out["audit_trail"].size();
    }
    return evidence_store::redact_sensitive_json(out, 4096);
}

nlohmann::json report_summary_json(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    const double score = risk_score(issues);
    nlohmann::json out;
    out["issue_count"] = issues.size();
    out["severity_counts"] = severity_counts_json(issues);
    out["risk_score"] = score;
    out["risk_posture"] = risk_posture(score);
    out["recommendations"] = recommendations_json(issues);
    out["session_id"] = cfg.session_id;
    out["target_domain"] = evidence_store::redact_sensitive_text(cfg.target_domain, 256);
    return out;
}

struct report_context_t
{
    nlohmann::json summary = nlohmann::json::object();
    nlohmann::json session = nlohmann::json::object();
    nlohmann::json offensive = nlohmann::json::object();
};

report_context_t build_context(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    report_context_t ctx;
    ctx.summary = report_summary_json(cfg, issues);
    ctx.session = session_context_json(cfg);
    ctx.offensive = offensive_context_json(cfg);
    return ctx;
}

std::string generate_html(const report_config_t& cfg, const std::vector<issue_t>& issues, const report_context_t& ctx)
{
    std::ostringstream os;
    os << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
       << "<title>" << safe_html(cfg.title.empty() ? std::string("AiDA Security Report") : cfg.title, 256) << "</title>"
       << "<style>"
       << "body{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px;}"
       << "h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px;}"
       << "h2{color:#79c0ff;margin-top:32px;}"
       << "h3{color:#d2a8ff;}"
       << ".meta{color:#8b949e;font-size:0.92em;}"
       << ".badge{display:inline-block;padding:2px 10px;border-radius:10px;font-weight:600;font-size:0.85em;margin-right:6px;}"
       << ".badge.critical{background:#7d1f1f;color:#ffd9d9;}"
       << ".badge.high{background:#9a3412;color:#fed7aa;}"
       << ".badge.medium{background:#854d0e;color:#fef3c7;}"
       << ".badge.low{background:#365314;color:#d9f99d;}"
       << ".badge.info{background:#1e3a8a;color:#dbeafe;}"
       << ".issue{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:16px 0;}"
       << ".kv{color:#8b949e;}"
       << "pre{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;overflow:auto;color:#79c0ff;}"
       << "code{font-family:'Consolas',monospace;}"
       << "a{color:#58a6ff;}"
       << "details{margin-top:8px;}"
       << "summary{cursor:pointer;color:#79c0ff;}"
       << ".toc{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin:16px 0;}"
       << ".toc ul{margin:0;padding-left:18px;}"
       << "</style></head><body>";
    os << "<h1>" << safe_html(cfg.title.empty() ? std::string("AiDA Security Report") : cfg.title, 256) << "</h1>";
    os << "<p class=\"meta\">Client: " << safe_html(cfg.client.empty() ? std::string("N/A") : cfg.client, 256)
       << " &middot; Generated: " << html_escape(format_ts(now_ms()))
       << " &middot; Issues: " << issues.size() << "</p>";
    if (!cfg.scope_summary.empty())
        os << "<p>" << safe_html(cfg.scope_summary, 2048) << "</p>";

    os << "<div class=\"toc\"><h2>Table of contents</h2><ul>";
    for (const auto& it : issues) {
        os << "<li><span class=\"badge " << severity_class(it.severity) << "\">"
           << severity_label(it.severity) << "</span> "
           << "<a href=\"#iss-" << it.id << "\">" << safe_html(it.name, 256)
           << "</a> &mdash; " << safe_html(it.host, 256) << safe_html(it.path, 512) << "</li>";
    }
    os << "</ul></div>";

    size_t counts[5] = {};
    for (const auto& it : issues) {
        int idx = static_cast<int>(it.severity);
        if (idx >= 0 && idx < 5) counts[idx]++;
    }
    os << "<h2>Summary</h2><table style=\"border-collapse:collapse;\"><tr>";
    const char* sn[5] = { "Info","Low","Medium","High","Critical" };
    for (int i = 4; i >= 0; --i) {
        os << "<td style=\"padding:6px 14px;\"><span class=\"badge " << severity_class(static_cast<severity_t>(i))
           << "\">" << sn[i] << "</span> " << counts[i] << "</td>";
    }
    os << "</tr></table>";
    os << "<p class=\"meta\">Risk posture: " << html_escape(ctx.summary.value("risk_posture", std::string("clear")))
       << " &middot; Risk score: " << ctx.summary.value("risk_score", 0.0) << "/100</p>";
    if (ctx.offensive.value("available", false)) {
        os << "<details><summary>Recon and offensive context</summary><pre><code>"
           << html_escape(ctx.offensive.dump(2)) << "</code></pre></details>";
    }
    if (!ctx.session.empty()) {
        os << "<details><summary>Audit session context</summary><pre><code>"
           << html_escape(ctx.session.dump(2)) << "</code></pre></details>";
    }

    os << "<h2>Findings</h2>";
    for (const auto& it : issues) {
        os << "<div class=\"issue\" id=\"iss-" << it.id << "\">";
        os << "<h3><span class=\"badge " << severity_class(it.severity) << "\">"
           << severity_label(it.severity) << "</span> " << safe_html(it.name, 256) << "</h3>";
        os << "<p class=\"meta\">Type: <code>" << safe_html(it.type_key, 128) << "</code>"
           << " &middot; Confidence: " << html_escape(confidence_label(it.confidence))
           << " &middot; Host: <code>" << safe_html(it.host, 256) << ":" << it.port << safe_html(it.path, 512) << "</code>";
        if (!it.parameter.empty()) os << " &middot; Parameter: <code>" << safe_html(it.parameter, 256) << "</code>";
        os << "</p>";
        if (!it.description.empty()) os << "<p>" << safe_html(it.description, 4096) << "</p>";
        if (!it.cwe.empty()) {
            os << "<p class=\"kv\">CWE:";
            for (const auto& c : it.cwe) {
                os << " <a href=\"https://cwe.mitre.org/data/definitions/" << html_escape(c) << ".html\">"
                   << html_escape(c) << "</a>";
            }
            os << "</p>";
        }
        if (!it.owasp_category.empty() || it.cvss_score > 0.0) {
            os << "<p class=\"kv\">";
            if (!it.owasp_category.empty())
                os << "OWASP: " << safe_html(it.owasp_category, 128) << " ";
            if (it.cvss_score > 0.0)
                os << "CVSS: " << it.cvss_score << " " << safe_html(it.cvss_severity, 64) << " " << safe_html(it.cvss_vector, 256);
            os << "</p>";
        }
        if (cfg.include_remediation && !it.remediation.empty()) {
            os << "<details><summary>Remediation</summary><p>"
               << safe_html(it.remediation, 4096) << "</p></details>";
        }
        if (cfg.include_evidence && !it.evidence.empty()) {
            os << "<details><summary>Evidence (" << it.evidence.size() << ")</summary>";
            for (size_t ei = 0; ei < it.evidence.size(); ++ei) {
                const auto& e = it.evidence[ei];
                os << "<h4>Evidence " << (ei + 1) << "</h4>";
                if (!e.marker.empty()) os << "<p class=\"kv\">Marker: <code>" << safe_html(e.marker, 512) << "</code></p>";
                if (!e.request_raw.empty()) {
                    os << "<details open><summary>Request</summary><pre class=\"lang-http\"><code>"
                       << html_escape(truncate_for_evidence(e.request_raw, 8192)) << "</code></pre></details>";
                }
                if (!e.response_raw.empty()) {
                    os << "<details><summary>Response</summary><pre class=\"lang-http\"><code>"
                       << html_escape(truncate_for_evidence(e.response_raw, 8192)) << "</code></pre></details>";
                }
            }
            os << "</details>";
        }
        os << "</div>";
    }

    os << "</body></html>";
    return os.str();
}

std::string generate_markdown(const report_config_t& cfg, const std::vector<issue_t>& issues, const report_context_t& ctx)
{
    std::ostringstream os;
    os << "# " << safe_text(cfg.title.empty() ? std::string("AiDA Security Report") : cfg.title, 256) << "\n\n";
    os << "- **Client:** " << safe_text(cfg.client.empty() ? std::string("N/A") : cfg.client, 256) << "\n";
    os << "- **Generated:** " << format_ts(now_ms()) << "\n";
    os << "- **Issues:** " << issues.size() << "\n\n";
    os << "- **Risk posture:** " << ctx.summary.value("risk_posture", std::string("clear")) << "\n";
    os << "- **Risk score:** " << ctx.summary.value("risk_score", 0.0) << "/100\n\n";
    if (!cfg.scope_summary.empty()) os << safe_text(cfg.scope_summary, 2048) << "\n\n";

    if (ctx.offensive.value("available", false)) {
        os << "## Recon and Offensive Context\n\n```json\n" << ctx.offensive.dump(2) << "\n```\n\n";
    }
    if (!ctx.session.empty()) {
        os << "## Audit Session Context\n\n```json\n" << ctx.session.dump(2) << "\n```\n\n";
    }

    os << "## Table of contents\n\n";
    for (const auto& it : issues) {
        os << "- [" << severity_label(it.severity) << "] [" << safe_text(it.name, 256) << "](#issue-" << it.id << ") - `" << safe_text(it.host, 256) << safe_text(it.path, 512) << "`\n";
    }
    os << "\n## Findings\n\n";

    for (const auto& it : issues) {
        os << "### <a name=\"issue-" << it.id << "\"></a>" << safe_text(it.name, 256) << " (`" << severity_label(it.severity) << "`)\n\n";
        os << "- **Type:** `" << safe_text(it.type_key, 128) << "`\n";
        os << "- **Confidence:** " << confidence_label(it.confidence) << "\n";
        os << "- **URL:** `" << safe_text(it.host, 256) << ":" << it.port << safe_text(it.path, 512) << "`\n";
        if (!it.parameter.empty()) os << "- **Parameter:** `" << safe_text(it.parameter, 256) << "`\n";
        if (!it.cwe.empty()) {
            os << "- **CWE:**";
            for (const auto& c : it.cwe) os << " [" << c << "](https://cwe.mitre.org/data/definitions/" << c << ".html)";
            os << "\n";
        }
        if (!it.owasp_category.empty()) os << "- **OWASP:** " << safe_text(it.owasp_category, 128) << "\n";
        if (it.cvss_score > 0.0) os << "- **CVSS:** " << it.cvss_score << " " << safe_text(it.cvss_severity, 64) << " `" << safe_text(it.cvss_vector, 256) << "`\n";
        os << "\n";
        if (!it.description.empty()) os << safe_text(it.description, 4096) << "\n\n";
        if (cfg.include_remediation && !it.remediation.empty()) {
            os << "**Remediation:** " << safe_text(it.remediation, 4096) << "\n\n";
        }
        if (cfg.include_evidence && !it.evidence.empty()) {
            for (size_t ei = 0; ei < it.evidence.size(); ++ei) {
                const auto& e = it.evidence[ei];
                os << "<details><summary>Evidence " << (ei + 1) << "</summary>\n\n";
                if (!e.request_raw.empty()) {
                    os << "**Request**\n\n```http\n" << truncate_for_evidence(e.request_raw, 8192) << "\n```\n\n";
                }
                if (!e.response_raw.empty()) {
                    os << "**Response**\n\n```http\n" << truncate_for_evidence(e.response_raw, 8192) << "\n```\n\n";
                }
                os << "</details>\n\n";
            }
        }
    }
    return os.str();
}

std::string generate_json(const report_config_t& cfg, const std::vector<issue_t>& issues, const report_context_t& ctx)
{
    nlohmann::json doc;
    doc["title"]        = safe_text(cfg.title, 256);
    doc["client"]       = safe_text(cfg.client, 256);
    doc["scope"]        = safe_text(cfg.scope_summary, 2048);
    doc["generated_ms"] = now_ms();
    doc["summary"]      = ctx.summary;
    doc["session_context"] = ctx.session;
    doc["offensive_context"] = ctx.offensive;
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& it : issues) arr.push_back(issue_to_report_json(it, cfg.include_evidence));
    doc["issues"] = std::move(arr);
    return doc.dump(2);
}

std::string generate_csv(const report_config_t& cfg, const std::vector<issue_t>& issues, const report_context_t& ctx)
{
    (void)cfg;
    (void)ctx;
    std::ostringstream os;
    auto quote = [](const std::string& s) {
        bool needs = false;
        for (char c : s) if (c == ',' || c == '"' || c == '\n' || c == '\r') { needs = true; break; }
        if (!needs) return s;
        std::string out = "\"";
        for (char c : s) { if (c == '"') out += "\"\""; else out += c; }
        out += "\"";
        return out;
    };
    os << "id,severity,cvss_score,cvss_severity,owasp_category,host,port,path,type,confidence,parameter,suppressed\r\n";
    for (const auto& it : issues) {
        os << it.id << "," << severity_label(it.severity) << ","
           << it.cvss_score << "," << quote(safe_text(it.cvss_severity, 64)) << ","
           << quote(safe_text(it.owasp_category, 128)) << ","
           << quote(safe_text(it.host, 256)) << "," << it.port << ","
           << quote(safe_text(it.path, 512)) << "," << quote(safe_text(it.type_key, 128)) << ","
           << confidence_label(it.confidence) << ","
           << quote(safe_text(it.parameter, 256)) << ","
           << (it.suppressed ? "true" : "false") << "\r\n";
    }
    return os.str();
}

std::string generate_sarif(const report_config_t& cfg, const std::vector<issue_t>& issues, const report_context_t& ctx)
{
    nlohmann::json doc;
    doc["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
    doc["version"] = "2.1.0";

    std::unordered_set<std::string> rule_ids;
    nlohmann::json rules = nlohmann::json::array();
    for (const auto& it : issues) {
        if (rule_ids.insert(it.type_key).second) {
            nlohmann::json rule;
            rule["id"]   = safe_text(it.type_key, 128);
            rule["name"] = safe_text(it.name, 256);
            rule["shortDescription"]["text"] = safe_text(it.name, 256);
            if (!it.description.empty()) rule["fullDescription"]["text"] = safe_text(it.description, 4096);
            if (!it.remediation.empty()) rule["help"]["text"] = safe_text(it.remediation, 4096);
            if (!it.cwe.empty()) {
                nlohmann::json tags = nlohmann::json::array();
                for (const auto& c : it.cwe) tags.push_back(std::string("CWE-") + c);
                rule["properties"]["tags"] = std::move(tags);
            }
            rule["properties"]["security-severity"] =
                (it.cvss_score > 0.0) ? std::to_string(it.cvss_score)
              : (it.severity == severity_t::critical) ? "9.5"
              : (it.severity == severity_t::high)     ? "8.0"
              : (it.severity == severity_t::medium)   ? "5.5"
              : (it.severity == severity_t::low)      ? "3.0"
                                                         : "1.0";
            rules.push_back(std::move(rule));
        }
    }

    nlohmann::json results = nlohmann::json::array();
    for (const auto& it : issues) {
        nlohmann::json result;
        result["ruleId"]        = safe_text(it.type_key, 128);
        result["level"]         = sarif_level(it.severity);
        result["message"]["text"] = safe_text(it.description.empty() ? it.name : it.description, 4096);
        std::string url = it.scheme.empty() ? std::string("https") : it.scheme;
        url += "://" + safe_text(it.host, 256) + ":" + std::to_string(it.port) + safe_text(it.path, 512);
        nlohmann::json loc;
        loc["physicalLocation"]["artifactLocation"]["uri"] = url;
        result["locations"] = nlohmann::json::array({ loc });
        if (cfg.include_evidence && !it.evidence.empty()) {
            const auto& e = it.evidence.front();
            if (!e.request_raw.empty() || !e.response_raw.empty()) {
                nlohmann::json att;
                att["description"]["text"] = std::string("Evidence (request/response)");
                att["artifactLocation"]["uri"] = url;
                nlohmann::json content;
                content["text"] = truncate_for_evidence(e.request_raw + "\n\n=== RESPONSE ===\n\n" + e.response_raw, 65536);
                att["contents"] = std::move(content);
                result["attachments"] = nlohmann::json::array({ att });
            }
        }
        if (!it.parameter.empty()) {
            result["properties"]["parameter"] = safe_text(it.parameter, 256);
        }
        result["properties"]["confidence"] = confidence_label(it.confidence);
        result["properties"]["seen_ms"]    = it.seen_ms;
        result["properties"]["audit_id"]   = it.audit_id;
        result["properties"]["session_id"] = safe_text(it.session_id, 256);
        result["properties"]["scan_id"] = it.scan_id;
        result["properties"]["cvss_vector"] = evidence_store::redact_sensitive_text(it.cvss_vector, 256);
        result["properties"]["cvss_severity"] = evidence_store::redact_sensitive_text(it.cvss_severity, 64);
        result["properties"]["owasp_category"] = evidence_store::redact_sensitive_text(it.owasp_category, 128);
        results.push_back(std::move(result));
    }

    nlohmann::json run;
    run["tool"]["driver"]["name"]    = "AiDAStandalone";
    run["tool"]["driver"]["version"] = "1.0.0";
    run["tool"]["driver"]["informationUri"] = "https://aidapro.net/";
    run["tool"]["driver"]["rules"]   = std::move(rules);
    run["properties"]["summary"] = ctx.summary;
    run["properties"]["offensive_context"] = ctx.offensive;
    run["results"] = std::move(results);
    doc["runs"] = nlohmann::json::array({ run });
    return doc.dump(2);
}

bool write_file(const std::string& path, const std::string& body)
{
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        set_err(std::string("report.generate: open failed for ") + path);
        return false;
    }
    f.write(body.data(), static_cast<std::streamsize>(body.size()));
    return f.good();
}

bool bind_report_text(sqlite3_stmt* stmt, int idx, const std::string& s)
{
    return sqlite3_bind_text(stmt, idx, s.c_str(), static_cast<int>(s.size()), SQLITE_TRANSIENT) == SQLITE_OK;
}

std::string report_column_text(sqlite3_stmt* stmt, int col)
{
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) return std::string();
    const unsigned char* p = sqlite3_column_text(stmt, col);
    const int n = sqlite3_column_bytes(stmt, col);
    if (!p || n <= 0) return std::string();
    return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
}

const char* stored_format_label(report_format_t f)
{
    switch (f) {
        case report_format_t::html:      return "html";
        case report_format_t::markdown:  return "markdown";
        case report_format_t::json:      return "json";
        case report_format_t::sarif_2_1: return "sarif_2_1_0";
        case report_format_t::csv:       return "csv";
    }
    return "html";
}

report_format_t stored_format_value(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s == "markdown" || s == "md")
        return report_format_t::markdown;
    if (s == "json")
        return report_format_t::json;
    if (s == "sarif" || s == "sarif_2_1" || s == "sarif_2_1_0")
        return report_format_t::sarif_2_1;
    if (s == "csv")
        return report_format_t::csv;
    return report_format_t::html;
}

generated_report_t make_report_record(const report_config_t& cfg, size_t issue_count, bool inline_output)
{
    auto& h = history();
    generated_report_t rec;
    rec.id = h.next_id.fetch_add(1);
    rec.ts_ms = now_ms();
    rec.title = safe_text(cfg.title, 256);
    rec.output_path = inline_output ? std::string() : cfg.output_path;
    rec.format = cfg.format;
    rec.issue_count = issue_count;
    rec.inline_output = inline_output;
    return rec;
}

void remember_report_record(generated_report_t rec)
{
    auto& h = history();
    std::lock_guard<std::mutex> lk(h.mtx);
    h.items.push_back(std::move(rec));
}

std::vector<generated_report_t> memory_report_history()
{
    auto& h = history();
    std::lock_guard<std::mutex> lk(h.mtx);
    return h.items;
}

std::string report_history_key(const generated_report_t& rec)
{
    std::ostringstream os;
    os << rec.id << '|'
       << rec.ts_ms << '|'
       << rec.title << '|'
       << rec.output_path << '|'
       << static_cast<int>(rec.format) << '|'
       << rec.issue_count << '|'
       << (rec.inline_output ? 1 : 0);
    return os.str();
}

std::vector<generated_report_t> merge_report_history(std::vector<generated_report_t> db_items,
                                                     const std::vector<generated_report_t>& memory_items)
{
    std::unordered_set<std::string> seen;
    for (const auto& item : db_items)
        seen.insert(report_history_key(item));
    for (const auto& item : memory_items) {
        const auto key = report_history_key(item);
        if (!seen.insert(key).second)
            continue;
        db_items.push_back(item);
    }
    std::sort(db_items.begin(), db_items.end(), [](const generated_report_t& a, const generated_report_t& b) {
        if (a.ts_ms != b.ts_ms) return a.ts_ms > b.ts_ms;
        return a.id > b.id;
    });
    if (db_items.size() > 512)
        db_items.resize(512);
    return db_items;
}

bool persist_report_record(const report_config_t& cfg, generated_report_t& rec)
{
    if (!findings_db::initialize())
        return false;
    nlohmann::json metadata;
    metadata["client_present"] = !cfg.client.empty();
    metadata["scope_summary_present"] = !cfg.scope_summary.empty();
    metadata["has_audit_id"] = cfg.has_audit_id;
    metadata["include_session_context"] = cfg.include_session_context;
    metadata["include_audit_trail"] = cfg.include_audit_trail;
    metadata["include_recon"] = cfg.include_recon;
    metadata["include_suppressed"] = cfg.include_suppressed;
    metadata["target_domain_present"] = !cfg.target_domain.empty();
    bool ok = findings_db::with_db("report_history_insert", [&](sqlite3* db) {
        const char* sql =
            "INSERT INTO report_history(session_id,audit_id,ts_ms,title,output_path,format,issue_count,inline_output,metadata_json) "
            "VALUES(?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        const bool bound =
            findings_db::bind_optional_session_id(db, stmt, 1, cfg.session_id, "report_history") &&
            sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(cfg.has_audit_id ? cfg.audit_id : 0)) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(rec.ts_ms)) == SQLITE_OK &&
            bind_report_text(stmt, 4, rec.title) &&
            bind_report_text(stmt, 5, rec.output_path) &&
            bind_report_text(stmt, 6, stored_format_label(rec.format)) &&
            sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(rec.issue_count)) == SQLITE_OK &&
            sqlite3_bind_int(stmt, 8, rec.inline_output ? 1 : 0) == SQLITE_OK &&
            bind_report_text(stmt, 9, metadata.dump());
        if (!bound) {
            sqlite3_finalize(stmt);
            return false;
        }
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE)
            rec.id = static_cast<uint64_t>(sqlite3_last_insert_rowid(db));
        sqlite3_finalize(stmt);
        return rc == SQLITE_DONE;
    });
    if (!ok) {
        diag::log_tagged_fmt("report", "report_history_insert_failed err=%s", findings_db::last_error().c_str());
        return false;
    }
    return true;
}

bool load_report_history_from_db(std::vector<generated_report_t>& out)
{
    out.clear();
    if (!findings_db::initialize())
        return false;
    bool ok = findings_db::with_db("report_history_list", [&](sqlite3* db) {
        const char* sql =
            "SELECT report_id,ts_ms,title,output_path,format,issue_count,inline_output "
            "FROM report_history ORDER BY ts_ms DESC,report_id DESC LIMIT 512";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            generated_report_t rec;
            rec.id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
            rec.ts_ms = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
            rec.title = report_column_text(stmt, 2);
            rec.output_path = report_column_text(stmt, 3);
            rec.format = stored_format_value(report_column_text(stmt, 4));
            rec.issue_count = static_cast<size_t>(sqlite3_column_int64(stmt, 5));
            rec.inline_output = sqlite3_column_int(stmt, 6) != 0;
            out.push_back(std::move(rec));
        }
        sqlite3_finalize(stmt);
        return true;
    });
    if (!ok)
        out.clear();
    return ok;
}

bool report_history_count_from_db(size_t& out)
{
    out = 0;
    if (!findings_db::initialize())
        return false;
    return findings_db::with_db("report_history_count", [&](sqlite3* db) {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM report_history", -1, &stmt, nullptr) != SQLITE_OK) return false;
        if (sqlite3_step(stmt) == SQLITE_ROW)
            out = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
        sqlite3_finalize(stmt);
        return true;
    });
}

bool clear_report_history_db(size_t& cleared)
{
    cleared = 0;
    if (!findings_db::initialize())
        return false;
    return findings_db::with_db("report_history_clear", [&](sqlite3* db) {
        sqlite3_stmt* count_stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM report_history", -1, &count_stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(count_stmt) == SQLITE_ROW)
                cleared = static_cast<size_t>(sqlite3_column_int64(count_stmt, 0));
        }
        if (count_stmt)
            sqlite3_finalize(count_stmt);
        char* err = nullptr;
        const int rc = sqlite3_exec(db, "DELETE FROM report_history", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            if (err)
                sqlite3_free(err);
            return false;
        }
        return true;
    });
}

}

bool parse_format(const std::string& s, report_format_t& out)
{
    diag::log_tagged_fmt("report", "parse_format entry s=%s", s.c_str());
    std::string l = s;
    std::transform(l.begin(), l.end(), l.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (l == "html")     { out = report_format_t::html;      return true; }
    if (l == "markdown" || l == "md") { out = report_format_t::markdown; return true; }
    if (l == "json")     { out = report_format_t::json;      return true; }
    if (l == "sarif" || l == "sarif_2_1_0" || l == "sarif_2_1") { out = report_format_t::sarif_2_1; return true; }
    if (l == "csv")      { out = report_format_t::csv;       return true; }
    diag::log_tagged_fmt("report", "parse_format unknown_format s=%s", s.c_str());
    return false;
}

const char* format_label(report_format_t f)
{
    switch (f) {
        case report_format_t::html:      return "html";
        case report_format_t::markdown:  return "markdown";
        case report_format_t::json:      return "json";
        case report_format_t::sarif_2_1: return "sarif_2_1_0";
        case report_format_t::csv:       return "csv";
    }
    return "html";
}

const char* default_extension(report_format_t f)
{
    diag::log_tagged_fmt("report", "default_extension entry format=%s", format_label(f));
    switch (f) {
        case report_format_t::html:      return ".html";
        case report_format_t::markdown:  return ".md";
        case report_format_t::json:      return ".json";
        case report_format_t::sarif_2_1: return ".sarif";
        case report_format_t::csv:       return ".csv";
    }
    return ".html";
}

bool generate(const report_config_t& cfg, std::string& out_path_or_error)
{
    const std::string log_title = safe_text(cfg.title, 256);
    auto history_count = []() {
        return list_reports().size();
    };
    issue_store::initialize();
    issue_filter_t issue_filter;
    issue_filter.include_suppressed = true;
    const size_t issue_store_count = issue_store::list(issue_filter).size();
    const size_t history_before = history_count();
    const size_t findings_before = findings_db::is_initialized() ? findings_db::count() : 0;
    diag::log_tagged_fmt("report", "generate entry path=%s format=%s title=%s",
        cfg.output_path.c_str(), format_label(cfg.format), log_title.c_str());
    diag::log_tagged_fmt("report",
        "report_generate_db_pre issue_store_count=%zu findings_count=%zu history_count=%zu db_initialized=%d",
        issue_store_count,
        findings_before,
        history_before,
        findings_db::is_initialized() ? 1 : 0);
    std::vector<issue_t> issues;
    if (!collect_issues(cfg, issues)) {
        diag::log_tagged_fmt("report",
            "generate collect_failed err=%s issue_store_count=%zu findings_count=%zu history_count=%zu",
            err_slot().c_str(),
            issue_store_count,
            findings_db::is_initialized() ? findings_db::count() : 0,
            history_count());
        out_path_or_error = err_slot();
        return false;
    }
    const report_context_t ctx = build_context(cfg, issues);
    diag::log_tagged_fmt("report", "generate filtered_issues=%zu format=%s", issues.size(), format_label(cfg.format));
    std::string body;
    switch (cfg.format) {
        case report_format_t::html:      body = generate_html(cfg, issues, ctx); break;
        case report_format_t::markdown:  body = generate_markdown(cfg, issues, ctx); break;
        case report_format_t::json:      body = generate_json(cfg, issues, ctx); break;
        case report_format_t::sarif_2_1: body = generate_sarif(cfg, issues, ctx); break;
        case report_format_t::csv:       body = generate_csv(cfg, issues, ctx); break;
    }
    if (cfg.output_path.empty()) {
        generated_report_t rec = make_report_record(cfg, issues.size(), true);
        const bool persisted = persist_report_record(cfg, rec);
        remember_report_record(rec);
        const size_t history_after = history_count();
        out_path_or_error = std::move(body);
        diag::log_tagged_fmt("report", "generate inline_ok format=%s issues=%zu body_len=%zu report_id=%llu persisted=%d",
            format_label(cfg.format), issues.size(), out_path_or_error.size(),
            static_cast<unsigned long long>(rec.id), persisted ? 1 : 0);
        diag::log_tagged_fmt("report",
            "report_generate_db_post issue_store_count=%zu findings_count=%zu selected_issue_count=%zu history_before=%zu history_after=%zu",
            issue_store_count,
            findings_db::count(),
            issues.size(),
            history_before,
            history_after);
        return true;
    }
    if (!write_file(cfg.output_path, body)) {
        diag::log_tagged_fmt("report", "generate write_failed path=%s", cfg.output_path.c_str());
        out_path_or_error = err_slot();
        return false;
    }
    generated_report_t rec = make_report_record(cfg, issues.size(), false);
    const bool persisted = persist_report_record(cfg, rec);
    remember_report_record(rec);
    diag::log_tagged_fmt("report", "generate ok path=%s format=%s issues=%zu body_len=%zu report_id=%llu persisted=%d",
        cfg.output_path.c_str(), format_label(cfg.format), issues.size(), body.size(),
        static_cast<unsigned long long>(rec.id), persisted ? 1 : 0);
    diag::log_tagged_fmt("burp.report", "generated path=%s format=%s issues=%zu",
        cfg.output_path.c_str(), format_label(cfg.format), issues.size());
    diag::log_tagged_fmt("report",
        "report_generate_db_post issue_store_count=%zu findings_count=%zu selected_issue_count=%zu history_before=%zu history_after=%zu",
        issue_store_count,
        findings_db::count(),
        issues.size(),
        history_before,
        history_count());
    out_path_or_error = cfg.output_path;
    return true;
}

std::vector<generated_report_t> list_reports()
{
    std::vector<generated_report_t> from_db;
    const auto from_memory = memory_report_history();
    if (load_report_history_from_db(from_db)) {
        const size_t db_rows = from_db.size();
        auto merged = merge_report_history(std::move(from_db), from_memory);
        diag::log_tagged_fmt("report", "list_reports result=%zu db_rows=%zu memory_rows=%zu source=merged",
            merged.size(), db_rows, from_memory.size());
        return merged;
    }
    diag::log_tagged_fmt("report", "list_reports result=%zu source=memory", from_memory.size());
    return from_memory;
}

size_t reports_count()
{
    size_t db_count = 0;
    if (report_history_count_from_db(db_count)) {
        const auto merged = list_reports();
        diag::log_tagged_fmt("report", "reports_count result=%zu db_count=%zu source=merged", merged.size(), db_count);
        return merged.size();
    }
    const auto from_memory = memory_report_history();
    size_t n = from_memory.size();
    diag::log_tagged_fmt("report", "reports_count result=%zu source=memory", n);
    return n;
}

void clear_history()
{
    diag::log_tagged_fmt("report", "clear_history entry");
    size_t memory_n = 0;
    {
        auto& h = history();
        std::lock_guard<std::mutex> lk(h.mtx);
        memory_n = h.items.size();
        h.items.clear();
    }
    size_t db_n = 0;
    const bool db_cleared = clear_report_history_db(db_n);
    diag::log_tagged_fmt("report", "clear_history done memory_cleared=%zu db_cleared=%zu db_ok=%d",
        memory_n, db_n, db_cleared ? 1 : 0);
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    std::string e = err_slot();
    diag::log_tagged_fmt("report", "last_error queried val=%s", e.c_str());
    return e;
}

}
}
}
