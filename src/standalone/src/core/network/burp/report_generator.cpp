#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "report_generator.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
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

std::vector<issue_t> filter_issues(const report_config_t& cfg)
{
    issue_filter_t f;
    auto all = issue_store::list(f);
    if (cfg.include_issue_ids.empty()) return all;
    std::unordered_set<uint64_t> keep(cfg.include_issue_ids.begin(), cfg.include_issue_ids.end());
    std::vector<issue_t> filtered;
    filtered.reserve(all.size());
    for (auto& it : all) if (keep.count(it.id)) filtered.push_back(std::move(it));
    return filtered;
}

std::string truncate_for_evidence(const std::string& s, size_t cap)
{
    if (s.size() <= cap) return s;
    return s.substr(0, cap) + "\n...[truncated]";
}

std::string generate_html(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    std::ostringstream os;
    os << "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
       << "<title>" << html_escape(cfg.title.empty() ? std::string("AiDA Security Report") : cfg.title) << "</title>"
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
    os << "<h1>" << html_escape(cfg.title.empty() ? std::string("AiDA Security Report") : cfg.title) << "</h1>";
    os << "<p class=\"meta\">Client: " << html_escape(cfg.client.empty() ? std::string("N/A") : cfg.client)
       << " &middot; Generated: " << html_escape(format_ts(now_ms()))
       << " &middot; Issues: " << issues.size() << "</p>";
    if (!cfg.scope_summary.empty())
        os << "<p>" << html_escape(cfg.scope_summary) << "</p>";

    os << "<div class=\"toc\"><h2>Table of contents</h2><ul>";
    for (const auto& it : issues) {
        os << "<li><span class=\"badge " << severity_class(it.severity) << "\">"
           << severity_label(it.severity) << "</span> "
           << "<a href=\"#iss-" << it.id << "\">" << html_escape(it.name)
           << "</a> &mdash; " << html_escape(it.host) << it.path << "</li>";
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

    os << "<h2>Findings</h2>";
    for (const auto& it : issues) {
        os << "<div class=\"issue\" id=\"iss-" << it.id << "\">";
        os << "<h3><span class=\"badge " << severity_class(it.severity) << "\">"
           << severity_label(it.severity) << "</span> " << html_escape(it.name) << "</h3>";
        os << "<p class=\"meta\">Type: <code>" << html_escape(it.type_key) << "</code>"
           << " &middot; Confidence: " << html_escape(confidence_label(it.confidence))
           << " &middot; Host: <code>" << html_escape(it.host) << ":" << it.port << it.path << "</code>";
        if (!it.parameter.empty()) os << " &middot; Parameter: <code>" << html_escape(it.parameter) << "</code>";
        os << "</p>";
        if (!it.description.empty()) os << "<p>" << html_escape(it.description) << "</p>";
        if (!it.cwe.empty()) {
            os << "<p class=\"kv\">CWE:";
            for (const auto& c : it.cwe) {
                os << " <a href=\"https://cwe.mitre.org/data/definitions/" << html_escape(c) << ".html\">"
                   << html_escape(c) << "</a>";
            }
            os << "</p>";
        }
        if (cfg.include_remediation && !it.remediation.empty()) {
            os << "<details><summary>Remediation</summary><p>"
               << html_escape(it.remediation) << "</p></details>";
        }
        if (cfg.include_evidence && !it.evidence.empty()) {
            os << "<details><summary>Evidence (" << it.evidence.size() << ")</summary>";
            for (size_t ei = 0; ei < it.evidence.size(); ++ei) {
                const auto& e = it.evidence[ei];
                os << "<h4>Evidence " << (ei + 1) << "</h4>";
                if (!e.marker.empty()) os << "<p class=\"kv\">Marker: <code>" << html_escape(e.marker) << "</code></p>";
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

std::string generate_markdown(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    std::ostringstream os;
    os << "# " << (cfg.title.empty() ? std::string("AiDA Security Report") : cfg.title) << "\n\n";
    os << "- **Client:** " << (cfg.client.empty() ? std::string("N/A") : cfg.client) << "\n";
    os << "- **Generated:** " << format_ts(now_ms()) << "\n";
    os << "- **Issues:** " << issues.size() << "\n\n";
    if (!cfg.scope_summary.empty()) os << cfg.scope_summary << "\n\n";

    os << "## Table of contents\n\n";
    for (const auto& it : issues) {
        os << "- [" << severity_label(it.severity) << "] [" << it.name << "](#issue-" << it.id << ") - `" << it.host << it.path << "`\n";
    }
    os << "\n## Findings\n\n";

    for (const auto& it : issues) {
        os << "### <a name=\"issue-" << it.id << "\"></a>" << it.name << " (`" << severity_label(it.severity) << "`)\n\n";
        os << "- **Type:** `" << it.type_key << "`\n";
        os << "- **Confidence:** " << confidence_label(it.confidence) << "\n";
        os << "- **URL:** `" << it.host << ":" << it.port << it.path << "`\n";
        if (!it.parameter.empty()) os << "- **Parameter:** `" << it.parameter << "`\n";
        if (!it.cwe.empty()) {
            os << "- **CWE:**";
            for (const auto& c : it.cwe) os << " [" << c << "](https://cwe.mitre.org/data/definitions/" << c << ".html)";
            os << "\n";
        }
        os << "\n";
        if (!it.description.empty()) os << it.description << "\n\n";
        if (cfg.include_remediation && !it.remediation.empty()) {
            os << "**Remediation:** " << it.remediation << "\n\n";
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

std::string generate_json(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    nlohmann::json doc;
    doc["title"]        = cfg.title;
    doc["client"]       = cfg.client;
    doc["scope"]        = cfg.scope_summary;
    doc["generated_ms"] = now_ms();
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& it : issues) arr.push_back(issue_store::issue_to_json(it));
    doc["issues"] = std::move(arr);
    return doc.dump(2);
}

std::string generate_csv(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    (void)cfg;
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
    os << "id,severity,host,port,path,type,confidence,parameter\r\n";
    for (const auto& it : issues) {
        os << it.id << "," << severity_label(it.severity) << ","
           << quote(it.host) << "," << it.port << ","
           << quote(it.path) << "," << quote(it.type_key) << ","
           << confidence_label(it.confidence) << ","
           << quote(it.parameter) << "\r\n";
    }
    return os.str();
}

std::string generate_sarif(const report_config_t& cfg, const std::vector<issue_t>& issues)
{
    nlohmann::json doc;
    doc["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
    doc["version"] = "2.1.0";

    std::unordered_set<std::string> rule_ids;
    nlohmann::json rules = nlohmann::json::array();
    for (const auto& it : issues) {
        if (rule_ids.insert(it.type_key).second) {
            nlohmann::json rule;
            rule["id"]   = it.type_key;
            rule["name"] = it.name;
            rule["shortDescription"]["text"] = it.name;
            if (!it.description.empty()) rule["fullDescription"]["text"] = it.description;
            if (!it.remediation.empty()) rule["help"]["text"] = it.remediation;
            if (!it.cwe.empty()) {
                nlohmann::json tags = nlohmann::json::array();
                for (const auto& c : it.cwe) tags.push_back(std::string("CWE-") + c);
                rule["properties"]["tags"] = std::move(tags);
            }
            rule["properties"]["security-severity"] =
                (it.severity == severity_t::critical) ? "9.5"
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
        result["ruleId"]        = it.type_key;
        result["level"]         = sarif_level(it.severity);
        result["message"]["text"] = it.description.empty() ? it.name : it.description;
        std::string url = it.scheme.empty() ? std::string("https") : it.scheme;
        url += "://" + it.host + ":" + std::to_string(it.port) + it.path;
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
            result["properties"]["parameter"] = it.parameter;
        }
        result["properties"]["confidence"] = confidence_label(it.confidence);
        result["properties"]["seen_ms"]    = it.seen_ms;
        result["properties"]["audit_id"]   = it.audit_id;
        results.push_back(std::move(result));
    }

    nlohmann::json run;
    run["tool"]["driver"]["name"]    = "AiDAStandalone";
    run["tool"]["driver"]["version"] = "1.0.0";
    run["tool"]["driver"]["informationUri"] = "https://aidapro.net/";
    run["tool"]["driver"]["rules"]   = std::move(rules);
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

}

bool parse_format(const std::string& s, report_format_t& out)
{
    std::string l = s;
    std::transform(l.begin(), l.end(), l.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (l == "html")     { out = report_format_t::html;      return true; }
    if (l == "markdown" || l == "md") { out = report_format_t::markdown; return true; }
    if (l == "json")     { out = report_format_t::json;      return true; }
    if (l == "sarif" || l == "sarif_2_1_0" || l == "sarif_2_1") { out = report_format_t::sarif_2_1; return true; }
    if (l == "csv")      { out = report_format_t::csv;       return true; }
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
    if (cfg.output_path.empty()) {
        set_err("report.generate: empty output_path");
        out_path_or_error = err_slot();
        return false;
    }
    auto issues = filter_issues(cfg);
    std::string body;
    switch (cfg.format) {
        case report_format_t::html:      body = generate_html(cfg, issues); break;
        case report_format_t::markdown:  body = generate_markdown(cfg, issues); break;
        case report_format_t::json:      body = generate_json(cfg, issues); break;
        case report_format_t::sarif_2_1: body = generate_sarif(cfg, issues); break;
        case report_format_t::csv:       body = generate_csv(cfg, issues); break;
    }
    if (!write_file(cfg.output_path, body)) {
        out_path_or_error = err_slot();
        return false;
    }
    {
        auto& h = history();
        std::lock_guard<std::mutex> lk(h.mtx);
        generated_report_t rec;
        rec.id          = h.next_id.fetch_add(1);
        rec.ts_ms       = now_ms();
        rec.title       = cfg.title;
        rec.output_path = cfg.output_path;
        rec.format      = cfg.format;
        rec.issue_count = issues.size();
        h.items.push_back(std::move(rec));
    }
    diag::log_tagged_fmt("burp.report", "generated path=%s format=%s issues=%zu",
        cfg.output_path.c_str(), format_label(cfg.format), issues.size());
    out_path_or_error = cfg.output_path;
    return true;
}

std::vector<generated_report_t> list_reports()
{
    auto& h = history();
    std::lock_guard<std::mutex> lk(h.mtx);
    return h.items;
}

size_t reports_count()
{
    auto& h = history();
    std::lock_guard<std::mutex> lk(h.mtx);
    return h.items.size();
}

void clear_history()
{
    auto& h = history();
    std::lock_guard<std::mutex> lk(h.mtx);
    h.items.clear();
}

std::string last_error()
{
    std::lock_guard<std::mutex> lk(err_mtx());
    return err_slot();
}

}
}
}
