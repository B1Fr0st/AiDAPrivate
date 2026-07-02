#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#ifdef small
#undef small
#endif

#include "web_report_mcp.hpp"

#include "audit_session_mcp.hpp"
#include "evidence_store.hpp"
#include "findings_db.hpp"
#include "issue.hpp"
#include "report_generator.hpp"
#include "site_map.hpp"
#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace web_report_mcp {

namespace {

using json = nlohmann::json;
using mcp_standalone::tool_def_t;
using mcp_standalone::tool_param_t;
using mcp_standalone::tool_result_t;

uint64_t now_ms()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

bool json_u64(const json& value, uint64_t& out)
{
    if (value.is_number_unsigned()) {
        out = value.get<uint64_t>();
        return true;
    }
    if (value.is_number_integer()) {
        const int64_t v = value.get<int64_t>();
        if (v >= 0) {
            out = static_cast<uint64_t>(v);
            return true;
        }
    }
    if (value.is_string()) {
        try {
            const std::string text = value.get<std::string>();
            size_t used = 0;
            out = std::stoull(text, &used);
            if (used != text.size())
                return false;
            return true;
        } catch (...) {
        }
    }
    return false;
}

uint64_t param_u64(const json& params, const char* name)
{
    uint64_t out = 0;
    if (params.contains(name))
        json_u64(params[name], out);
    return out;
}

std::string session_id_from_params(const json& params)
{
    if (params.contains("session_id") && params["session_id"].is_string())
        return params["session_id"].get<std::string>();
    return {};
}

std::string truncate_text(const std::string& value, size_t max_len)
{
    if (value.size() <= max_len)
        return value;
    return value.substr(0, max_len) + "...[truncated]";
}

std::string issue_url(const issue_t& issue)
{
    std::string scheme = issue.scheme.empty() ? std::string("https") : issue.scheme;
    std::string url = scheme + "://" + issue.host;
    if (issue.port != 0 && !((scheme == "https" && issue.port == 443) || (scheme == "http" && issue.port == 80)))
        url += ":" + std::to_string(issue.port);
    url += issue.path.empty() ? std::string("/") : issue.path;
    return audit_session_mcp_store::redact_url_for_output(url);
}

std::string bytes_to_string(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty())
        return {};
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string headers_to_raw(const std::vector<std::pair<std::string, std::string>>& headers)
{
    std::ostringstream os;
    for (const auto& h : headers)
        os << h.first << ": " << h.second << "\r\n";
    return os.str();
}

std::string request_raw_from_exchange(const exchange_observed_t& e)
{
    std::ostringstream os;
    os << (e.method.empty() ? "GET" : e.method) << " " << (e.path.empty() ? "/" : e.path);
    if (!e.query.empty())
        os << "?" << e.query;
    os << " HTTP/1.1\r\n";
    os << headers_to_raw(e.req_headers);
    os << "\r\n";
    const std::string body = bytes_to_string(e.req_body);
    os << body;
    return os.str();
}

std::string response_raw_from_exchange(const exchange_observed_t& e)
{
    std::ostringstream os;
    os << "HTTP/1.1 " << e.status_code << " " << e.reason_phrase << "\r\n";
    os << headers_to_raw(e.resp_headers);
    os << "\r\n";
    const std::string body = bytes_to_string(e.resp_body);
    os << body;
    return os.str();
}

audit_session_mcp_store::evidence_record_t evidence_record_from_raw(const std::string& session_id,
                                                          uint64_t issue_id,
                                                          uint64_t exchange_id,
                                                          const std::string& source,
                                                          const std::string& category,
                                                          const std::string& label,
                                                          const std::string& request_raw,
                                                          const std::string& response_raw,
                                                          const std::string& marker)
{
    audit_session_mcp_store::evidence_record_t record;
    record.session_id = session_id;
    record.issue_id = issue_id;
    record.exchange_id = exchange_id;
    record.source = source.empty() ? std::string("mcp") : source;
    record.category = category.empty() ? std::string("manual") : category;
    record.label = label;
    record.request_length = request_raw.size();
    record.response_length = response_raw.size();
    record.request_sha256 = audit_session_mcp_store::hash_for_output(request_raw);
    record.response_sha256 = audit_session_mcp_store::hash_for_output(response_raw);
    record.request_preview = truncate_text(audit_session_mcp_store::redact_for_output(request_raw), 4096);
    record.response_preview = truncate_text(audit_session_mcp_store::redact_for_output(response_raw), 4096);
    record.marker_length = marker.size();
    record.marker_sha256 = marker.empty() ? std::string() : audit_session_mcp_store::hash_for_output(marker);
    record.marker_preview = marker.empty() ? std::string() : truncate_text(audit_session_mcp_store::redact_for_output(marker), 256);
    return record;
}

audit_session_mcp_store::evidence_record_t evidence_record_from_exchange(const std::string& session_id,
                                                               uint64_t issue_id,
                                                               const exchange_observed_t& e,
                                                               const std::string& category,
                                                               const std::string& label)
{
    audit_session_mcp_store::evidence_record_t record = evidence_record_from_raw(
        session_id,
        issue_id,
        e.id,
        e.source.empty() ? std::string("sitemap") : e.source,
        category,
        label,
        request_raw_from_exchange(e),
        response_raw_from_exchange(e),
        std::string());
    record.method = e.method;
    record.host = e.host;
    record.port = e.port;
    record.path = e.path;
    record.status_code = e.status_code;
    std::string url = e.scheme.empty() ? std::string("https") : e.scheme;
    url += "://" + e.host;
    if (e.port != 0 && !((url.rfind("https://", 0) == 0 && e.port == 443) || (url.rfind("http://", 0) == 0 && e.port == 80)))
        url += ":" + std::to_string(e.port);
    url += e.path.empty() ? std::string("/") : e.path;
    if (!e.query.empty())
        url += "?" + e.query;
    record.url = url;
    record.extra = json{{"latency_ms", e.latency_ms}, {"source", e.source}, {"tls_version", e.tls_version}, {"alpn", e.alpn}};
    return record;
}

json evidence_summary_from_issue_evidence(const evidence_t& evidence)
{
    json out;
    out["request"] = json{
        {"length", evidence.request_raw.size()},
        {"sha256", audit_session_mcp_store::hash_for_output(evidence.request_raw)},
        {"preview", truncate_text(audit_session_mcp_store::redact_for_output(evidence.request_raw), 2048)},
        {"redacted", true}
    };
    out["response"] = json{
        {"length", evidence.response_raw.size()},
        {"sha256", audit_session_mcp_store::hash_for_output(evidence.response_raw)},
        {"preview", truncate_text(audit_session_mcp_store::redact_for_output(evidence.response_raw), 2048)},
        {"redacted", true}
    };
    if (!evidence.marker.empty()) {
        out["marker"] = json{
            {"length", evidence.marker.size()},
            {"sha256", audit_session_mcp_store::hash_for_output(evidence.marker)},
            {"preview", truncate_text(audit_session_mcp_store::redact_for_output(evidence.marker), 256)},
            {"redacted", true}
        };
    }
    out["marker_offset_request"] = evidence.marker_offset_request;
    out["marker_offset_response"] = evidence.marker_offset_response;
    return out;
}

json issue_to_redacted_json(const issue_t& issue, const std::string& session_id, bool include_evidence)
{
    json out;
    out["id"] = issue.id;
    out["type_key"] = audit_session_mcp_store::redact_for_output(issue.type_key);
    out["name"] = audit_session_mcp_store::redact_for_output(issue.name);
    out["description"] = audit_session_mcp_store::redact_for_output(issue.description);
    out["remediation"] = audit_session_mcp_store::redact_for_output(issue.remediation);
    out["cwe"] = issue.cwe;
    out["severity"] = severity_label(issue.severity);
    out["confidence"] = confidence_label(issue.confidence);
    out["scheme"] = issue.scheme;
    out["host"] = issue.host;
    out["port"] = issue.port;
    out["path"] = audit_session_mcp_store::redact_url_for_output(issue.path);
    out["url"] = issue_url(issue);
    out["parameter"] = audit_session_mcp_store::redact_for_output(issue.parameter);
    out["insertion_point"] = audit_session_mcp_store::redact_for_output(issue.insertion_point);
    out["seen_ms"] = issue.seen_ms;
    out["src_exchange_id"] = issue.src_exchange_id;
    out["audit_id"] = issue.audit_id;
    out["suppressed"] = issue.suppressed || audit_session_mcp_store::is_suppressed(issue.id, session_id);
    out["stored_evidence_count"] = audit_session_mcp_store::evidence_count_for_issue(session_id, issue.id);
    if (include_evidence) {
        out["issue_evidence"] = json::array();
        for (const auto& evidence : issue.evidence)
            out["issue_evidence"].push_back(evidence_summary_from_issue_evidence(evidence));
        audit_session_mcp_store::evidence_query_t query;
        query.session_id = session_id;
        query.issue_id = issue.id;
        query.limit = 64;
        out["captured_evidence"] = json::array();
        for (const auto& record : audit_session_mcp_store::list_evidence(query))
            out["captured_evidence"].push_back(audit_session_mcp_store::evidence_to_json(record));
    }
    return out;
}

findings_db::finding_filter_t findings_filter_from_params(const json& params, std::string& error)
{
    findings_db::finding_filter_t filter;
    if (params.contains("severity_min") && params["severity_min"].is_string()) {
        severity_t sev = severity_t::info;
        if (!parse_severity(params["severity_min"].get<std::string>(), sev)) {
            error = "invalid severity_min";
            return filter;
        }
        filter.has_severity_min = true;
        filter.severity_min = sev;
    }
    if (params.contains("confidence_min") && params["confidence_min"].is_string()) {
        confidence_t confidence = confidence_t::tentative;
        if (!parse_confidence(params["confidence_min"].get<std::string>(), confidence)) {
            error = "invalid confidence_min";
            return filter;
        }
        filter.has_confidence_min = true;
        filter.confidence_min = confidence;
    }
    filter.session_id = session_id_from_params(params);
    filter.host_substring = params.value("host", params.value("host_substring", std::string()));
    filter.type_key_substring = params.value("type_key", params.value("type_key_substring", std::string()));
    if (params.contains("scan_id")) {
        uint64_t scan_id = 0;
        if (!json_u64(params["scan_id"], scan_id)) {
            error = "invalid scan_id";
            return filter;
        }
        filter.has_scan_id = true;
        filter.scan_id = scan_id;
    }
    if (params.contains("audit_id")) {
        uint64_t audit_id = 0;
        if (!json_u64(params["audit_id"], audit_id)) {
            error = "invalid audit_id";
            return filter;
        }
        filter.has_audit_id = true;
        filter.audit_id = audit_id;
    }
    filter.include_suppressed = params.value("include_suppressed", false);
    filter.limit = static_cast<size_t>(params.value("limit", 256));
    return filter;
}

json severity_counts_json(const std::vector<issue_t>& issues)
{
    json out;
    size_t critical = 0;
    size_t high = 0;
    size_t medium = 0;
    size_t low = 0;
    size_t info = 0;
    for (const auto& issue : issues) {
        switch (issue.severity) {
            case severity_t::critical: ++critical; break;
            case severity_t::high: ++high; break;
            case severity_t::medium: ++medium; break;
            case severity_t::low: ++low; break;
            case severity_t::info: ++info; break;
        }
    }
    out["critical"] = critical;
    out["high"] = high;
    out["medium"] = medium;
    out["low"] = low;
    out["info"] = info;
    return out;
}

std::string category_for_issue(const issue_t& issue)
{
    const std::string key = issue.type_key.empty() ? issue.name : issue.type_key;
    const size_t dot = key.find('.');
    return audit_session_mcp_store::redact_for_output(dot == std::string::npos ? key : key.substr(0, dot));
}

std::vector<issue_t> filtered_issues_for_report_params(const json& params, std::string& error)
{
    findings_db::finding_filter_t filter = findings_filter_from_params(params, error);
    if (!error.empty())
        return {};
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false)) {
        error = findings_db::last_error().empty() ? "findings database unavailable" : findings_db::last_error();
        return {};
    }
    std::vector<issue_t> issues = findings_db::list(filter);
    const std::string session_id = session_id_from_params(params);
    const bool include_suppressed = params.value("include_suppressed", false);
    if (!include_suppressed) {
        issues.erase(std::remove_if(issues.begin(), issues.end(), [&](const issue_t& issue) {
            return audit_session_mcp_store::is_suppressed(issue.id, session_id);
        }), issues.end());
    }
    return issues;
}

tool_result_t tool_findings_query(const json& params)
{
    std::string error;
    const auto issues = filtered_issues_for_report_params(params, error);
    if (!error.empty())
        return tool_result_t::error(error);
    const std::string session_id = session_id_from_params(params);
    const bool include_evidence = params.value("include_evidence", false);
    json out;
    out["count"] = issues.size();
    out["severity_counts"] = severity_counts_json(issues);
    out["findings"] = json::array();
    for (const auto& issue : issues)
        out["findings"].push_back(issue_to_redacted_json(issue, session_id, include_evidence));
    return tool_result_t::ok(out);
}

tool_result_t tool_findings_suppress(const json& params)
{
    const uint64_t issue_id = param_u64(params, "issue_id");
    if (issue_id == 0)
        return tool_result_t::error("issue_id is required");
    const std::string reason = params.value("reason", std::string());
    if (reason.empty())
        return tool_result_t::error("reason is required");
    issue_t issue;
    if (!issue_store::get(issue_id, issue))
        return tool_result_t::error("issue not found");
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false))
        return tool_result_t::error(findings_db::last_error().empty() ? "findings database unavailable" : findings_db::last_error());
    findings_db::suppression_t db_suppression;
    db_suppression.finding_id = issue_id;
    db_suppression.reason = reason;
    db_suppression.suppressed_by = params.value("actor", std::string("mcp"));
    db_suppression.scope = params.value("scope", std::string("finding"));
    db_suppression.create_rule = true;
    if (!findings_db::suppress(db_suppression))
        return tool_result_t::error(findings_db::last_error().empty() ? "finding suppression failed" : findings_db::last_error());
    audit_session_mcp_store::suppression_t suppression;
    suppression.session_id = session_id_from_params(params);
    suppression.issue_id = issue_id;
    suppression.scope = params.value("scope", std::string("finding"));
    suppression.reason = reason;
    suppression.actor = params.value("actor", std::string("mcp"));
    suppression.issue_type = issue.type_key;
    suppression.host = issue.host;
    suppression.path = issue.path;
    suppression.expires_ms = param_u64(params, "expires_ms");
    const uint64_t suppression_id = audit_session_mcp_store::suppress_finding(suppression);
    json out;
    out["suppressed"] = true;
    out["suppression_id"] = suppression_id;
    out["suppression"] = audit_session_mcp_store::suppression_to_json(suppression);
    out["suppression"]["id"] = suppression_id;
    return tool_result_t::ok(out);
}

bool persist_evidence_record(uint64_t issue_id,
                             const std::string& session_id,
                             uint64_t exchange_id,
                             const std::string& request_raw,
                             const std::string& response_raw,
                             const std::string& marker,
                             uint64_t marker_offset_request,
                             uint64_t marker_offset_response,
                             const std::string& description,
                             std::string& error)
{
    if (issue_id == 0)
        return true;
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false)) {
        error = findings_db::last_error().empty() ? "findings database unavailable" : findings_db::last_error();
        return false;
    }
    evidence_store::evidence_capture_t capture;
    capture.finding_id = issue_id;
    capture.session_id = session_id;
    capture.exchange_id = exchange_id;
    capture.kind = evidence_store::evidence_kind_t::request_response;
    capture.request_raw = request_raw;
    capture.response_raw = response_raw;
    capture.marker = marker;
    capture.marker_offset_request = marker_offset_request;
    capture.marker_offset_response = marker_offset_response;
    capture.description = description;
    capture.metadata_json = json{{"source", "aida.web.report.evidence.capture"}};
    evidence_store::evidence_record_t stored;
    if (!evidence_store::capture(capture, stored)) {
        error = evidence_store::last_error().empty() ? "evidence capture failed" : evidence_store::last_error();
        return false;
    }
    return true;
}

tool_result_t capture_from_exchange(const json& params, const std::string& session_id, uint64_t issue_id, uint64_t exchange_id)
{
    exchange_observed_t exchange;
    if (!sitemap::find_exchange(exchange_id, exchange))
        return tool_result_t::error("exchange not found");
    const std::string request_raw = request_raw_from_exchange(exchange);
    const std::string response_raw = response_raw_from_exchange(exchange);
    std::string persist_error;
    if (!persist_evidence_record(issue_id,
                                 session_id,
                                 exchange_id,
                                 request_raw,
                                 response_raw,
                                 std::string(),
                                 0,
                                 0,
                                 params.value("label", std::string("captured exchange")),
                                 persist_error))
        return tool_result_t::error(persist_error);
    audit_session_mcp_store::evidence_record_t record = evidence_record_from_exchange(
        session_id,
        issue_id,
        exchange,
        params.value("category", std::string("exchange")),
        params.value("label", std::string()));
    const uint64_t id = audit_session_mcp_store::store_evidence(record);
    record.id = id;
    json out;
    out["captured"] = 1;
    out["evidence"] = json::array({audit_session_mcp_store::evidence_to_json(record)});
    return tool_result_t::ok(out);
}

tool_result_t capture_from_issue(const json& params, const std::string& session_id, uint64_t issue_id)
{
    issue_t issue;
    if (!issue_store::get(issue_id, issue))
        return tool_result_t::error("issue not found");
    json records = json::array();
    size_t captured = 0;
    for (const auto& evidence : issue.evidence) {
        std::string persist_error;
        if (!persist_evidence_record(issue_id,
                                     session_id,
                                     issue.src_exchange_id,
                                     evidence.request_raw,
                                     evidence.response_raw,
                                     evidence.marker,
                                     evidence.marker_offset_request,
                                     evidence.marker_offset_response,
                                     params.value("label", issue.name),
                                     persist_error))
            return tool_result_t::error(persist_error);
        audit_session_mcp_store::evidence_record_t record = evidence_record_from_raw(
            session_id,
            issue_id,
            issue.src_exchange_id,
            "issue_store",
            params.value("category", std::string("issue")),
            params.value("label", issue.name),
            evidence.request_raw,
            evidence.response_raw,
            evidence.marker);
        record.method.clear();
        record.host = issue.host;
        record.port = issue.port;
        record.path = issue.path;
        record.url = issue_url(issue);
        const uint64_t id = audit_session_mcp_store::store_evidence(record);
        record.id = id;
        records.push_back(audit_session_mcp_store::evidence_to_json(record));
        ++captured;
    }
    json out;
    out["captured"] = captured;
    out["evidence"] = records;
    return tool_result_t::ok(out);
}

tool_result_t capture_from_raw_params(const json& params, const std::string& session_id, uint64_t issue_id)
{
    const std::string request_raw = params.value("request_raw", std::string());
    const std::string response_raw = params.value("response_raw", std::string());
    if (request_raw.empty() && response_raw.empty())
        return tool_result_t::error("request_raw, response_raw, exchange_id, or issue_id evidence is required");
    std::string persist_error;
    if (!persist_evidence_record(issue_id,
                                 session_id,
                                 0,
                                 request_raw,
                                 response_raw,
                                 params.value("marker", std::string()),
                                 0,
                                 0,
                                 params.value("label", std::string("manual evidence")),
                                 persist_error))
        return tool_result_t::error(persist_error);
    audit_session_mcp_store::evidence_record_t record = evidence_record_from_raw(
        session_id,
        issue_id,
        0,
        params.value("source", std::string("manual")),
        params.value("category", std::string("manual")),
        params.value("label", std::string()),
        request_raw,
        response_raw,
        params.value("marker", std::string()));
    record.url = params.value("url", std::string());
    record.host = params.value("host", std::string());
    record.path = params.value("path", std::string());
    record.method = params.value("method", std::string());
    const uint64_t status_code = param_u64(params, "status_code");
    record.status_code = status_code <= 999 ? static_cast<int>(status_code) : 0;
    const uint64_t id = audit_session_mcp_store::store_evidence(record);
    record.id = id;
    json out;
    out["captured"] = 1;
    out["evidence"] = json::array({audit_session_mcp_store::evidence_to_json(record)});
    return tool_result_t::ok(out);
}

tool_result_t tool_evidence_capture(const json& params)
{
    const std::string session_id = session_id_from_params(params);
    if (session_id.empty())
        return tool_result_t::error("session_id is required");
    audit_session_mcp_store::session_t session;
    if (!audit_session_mcp_store::get_session(session_id, session))
        return tool_result_t::error("session not found");
    const uint64_t issue_id = param_u64(params, "issue_id");
    const uint64_t exchange_id = param_u64(params, "exchange_id");
    if (exchange_id != 0)
        return capture_from_exchange(params, session_id, issue_id, exchange_id);
    if (issue_id != 0)
        return capture_from_issue(params, session_id, issue_id);
    return capture_from_raw_params(params, session_id, issue_id);
}

bool apply_issue_ids(report::report_config_t& cfg, const json& params)
{
    if (!params.contains("include_issue_ids"))
        return true;
    if (!params["include_issue_ids"].is_array())
        return false;
    for (const auto& item : params["include_issue_ids"]) {
        uint64_t id = 0;
        if (!json_u64(item, id))
            return false;
        cfg.include_issue_ids.push_back(id);
    }
    return true;
}

tool_result_t tool_report_generate(const json& params)
{
    const std::string fmt_s = params.value("format", std::string("html"));
    report::report_format_t format = report::report_format_t::html;
    if (!report::parse_format(fmt_s, format))
        return tool_result_t::error("unsupported report format; supported formats are markdown, html, json, sarif_2_1_0, and csv");
    if (!params.contains("output_path") || !params["output_path"].is_string())
        return tool_result_t::error("output_path is required");
    report::report_config_t cfg;
    cfg.title = params.value("title", std::string("AiDA Web Security Report"));
    cfg.client = params.value("client", std::string());
    cfg.scope_summary = params.value("scope_summary", std::string());
    cfg.output_path = params["output_path"].get<std::string>();
    cfg.format = format;
    cfg.include_evidence = params.value("include_evidence", true);
    cfg.include_remediation = params.value("include_remediation", true);
    cfg.target_domain = params.value("target_domain", params.value("host", std::string()));
    cfg.include_recon = params.value("include_recon", true);
    cfg.session_id = session_id_from_params(params);
    cfg.include_session_context = params.value("include_session_context", true);
    cfg.include_audit_trail = params.value("include_audit_trail", false);
    cfg.audit_trail_limit = static_cast<size_t>(params.value("audit_trail_limit", 128));
    if (params.contains("audit_id")) {
        uint64_t audit_id = 0;
        if (!json_u64(params["audit_id"], audit_id))
            return tool_result_t::error("invalid audit_id");
        cfg.has_audit_id = true;
        cfg.audit_id = audit_id;
    }
    if (params.contains("severity_min") && params["severity_min"].is_string()) {
        severity_t sev = severity_t::info;
        if (!parse_severity(params["severity_min"].get<std::string>(), sev))
            return tool_result_t::error("invalid severity_min");
        cfg.has_severity_min = true;
        cfg.severity_min = sev;
    }
    if (!apply_issue_ids(cfg, params))
        return tool_result_t::error("invalid include_issue_ids");
    if (params.contains("include_offensive_run_ids") && params["include_offensive_run_ids"].is_array()) {
        for (const auto& item : params["include_offensive_run_ids"]) {
            if (item.is_string())
                cfg.include_offensive_run_ids.push_back(item.get<std::string>());
        }
    }
    std::string out_path;
    if (!report::generate(cfg, out_path))
        return tool_result_t::error(out_path.empty() ? report::last_error() : out_path);
    uint64_t report_id = 0;
    size_t issue_count = 0;
    uint64_t newest_ts = 0;
    for (const auto& r : report::list_reports()) {
        if (r.output_path == out_path && r.ts_ms >= newest_ts) {
            report_id = r.id;
            issue_count = r.issue_count;
            newest_ts = r.ts_ms;
        }
    }
    uint64_t bytes_written = 0;
    std::error_code ec;
    const auto sz = std::filesystem::file_size(out_path, ec);
    if (!ec)
        bytes_written = static_cast<uint64_t>(sz);
    json out;
    out["report_id"] = report_id;
    out["output_path"] = out_path;
    out["format"] = report::format_label(cfg.format);
    out["issue_count"] = issue_count;
    out["bytes_written"] = bytes_written;
    out["session_id"] = cfg.session_id;
    out["include_audit_trail"] = cfg.include_audit_trail;
    return tool_result_t::ok(out);
}

json recommendations_json(const std::vector<issue_t>& issues)
{
    std::map<std::string, size_t> counts;
    for (const auto& issue : issues) {
        std::string rec = issue.remediation.empty() ? std::string("Review and remediate ") + (issue.name.empty() ? issue.type_key : issue.name) : issue.remediation;
        rec = truncate_text(audit_session_mcp_store::redact_for_output(rec), 240);
        counts[rec]++;
    }
    std::vector<std::pair<std::string, size_t>> rows(counts.begin(), counts.end());
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second)
            return a.second > b.second;
        return a.first < b.first;
    });
    json out = json::array();
    for (const auto& row : rows) {
        json item;
        item["recommendation"] = row.first;
        item["finding_count"] = row.second;
        out.push_back(item);
        if (out.size() >= 10)
            break;
    }
    return out;
}

tool_result_t tool_executive_summary(const json& params)
{
    std::string error;
    const auto issues = filtered_issues_for_report_params(params, error);
    if (!error.empty())
        return tool_result_t::error(error);
    std::map<std::string, size_t> categories;
    std::vector<issue_t> top;
    for (const auto& issue : issues) {
        categories[category_for_issue(issue)]++;
        if (issue.severity == severity_t::critical || issue.severity == severity_t::high)
            top.push_back(issue);
    }
    std::sort(top.begin(), top.end(), [](const issue_t& a, const issue_t& b) {
        if (a.severity != b.severity)
            return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        return a.seen_ms > b.seen_ms;
    });
    std::vector<std::pair<std::string, size_t>> category_rows(categories.begin(), categories.end());
    std::sort(category_rows.begin(), category_rows.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second)
            return a.second > b.second;
        return a.first < b.first;
    });
    json category_arr = json::array();
    for (const auto& row : category_rows)
        category_arr.push_back(json{{"category", row.first}, {"count", row.second}});
    json top_arr = json::array();
    for (const auto& issue : top) {
        top_arr.push_back(json{
            {"id", issue.id},
            {"severity", severity_label(issue.severity)},
            {"name", audit_session_mcp_store::redact_for_output(issue.name)},
            {"type_key", audit_session_mcp_store::redact_for_output(issue.type_key)},
            {"url", issue_url(issue)}
        });
        if (top_arr.size() >= 10)
            break;
    }
    json out;
    out["generated_ms"] = now_ms();
    out["deterministic"] = true;
    out["external_ai_used"] = false;
    out["finding_count"] = issues.size();
    out["severity_counts"] = severity_counts_json(issues);
    out["category_counts"] = category_arr;
    out["priority_findings"] = top_arr;
    out["recommendations"] = recommendations_json(issues);
    return tool_result_t::ok(out);
}

tool_result_t tool_audit_trail(const json& params)
{
    audit_session_mcp_store::audit_query_t query;
    query.session_id = session_id_from_params(params);
    query.tool = params.value("tool", std::string());
    query.since_ms = param_u64(params, "since_ms");
    query.until_ms = param_u64(params, "until_ms");
    query.limit = static_cast<size_t>(params.value("limit", 128));
    const auto entries = audit_session_mcp_store::list_audit(query);
    json out;
    out["count"] = entries.size();
    out["entries"] = json::array();
    for (const auto& entry : entries)
        out["entries"].push_back(audit_session_mcp_store::audit_entry_to_json(entry));
    return tool_result_t::ok(out);
}

tool_result_t audited(const std::string& name,
                      bool read_only,
                      const json& params,
                      const std::function<tool_result_t(const json&)>& fn)
{
    const uint64_t start = now_ms();
    tool_result_t result = fn(params);
    audit_session_mcp_store::audit_entry_t entry;
    entry.session_id = session_id_from_params(params);
    entry.ts_ms = start;
    entry.actor = params.value("actor", std::string("mcp"));
    entry.tool = name;
    entry.action = name;
    entry.read_only = read_only;
    entry.ok = result.success;
    const uint64_t end = now_ms();
    entry.elapsed_ms = end >= start ? end - start : 0;
    entry.target = params.value("target_url", params.value("url", params.value("host", std::string())));
    entry.summary = result.success ? std::string("ok") : result.text;
    entry.params_summary = audit_session_mcp_store::redact_json_for_output(params);
    entry.result_summary = result.data.is_null() ? json{{"text", result.text}} : audit_session_mcp_store::redact_json_for_output(result.data);
    audit_session_mcp_store::append_audit(std::move(entry));
    return result;
}

void register_one(mcp_standalone::server_t& srv,
                  std::string name,
                  std::string description,
                  std::vector<tool_param_t> params,
                  bool read_only,
                  std::function<tool_result_t(const json&)> handler)
{
    tool_def_t t;
    t.name = std::move(name);
    t.description = std::move(description);
    t.params = std::move(params);
    t.read_only = read_only;
    const std::string tool_name = t.name;
    t.handler = [tool_name, read_only, handler = std::move(handler)](const json& params) -> tool_result_t {
        return audited(tool_name, read_only, params, handler);
    };
    srv.register_tool(std::move(t));
}

}

void register_web_report_tools(mcp_standalone::server_t& srv)
{
    using p = tool_param_t;
    register_one(srv, "aida.web.report.findings.query", "Query web findings from the current findings database with suppression-aware filtering and redacted evidence summaries.", {
        p{"severity_min", "string", "Minimum severity: info|low|medium|high|critical.", false},
        p{"confidence_min", "string", "Minimum confidence: tentative|firm|certain.", false},
        p{"host", "string", "Host substring filter.", false},
        p{"type_key", "string", "Type-key substring filter.", false},
        p{"audit_id", "number", "Scanner audit id.", false},
        p{"session_id", "string", "Audit session id for suppression/evidence context.", false},
        p{"include_evidence", "boolean", "Include redacted evidence summaries.", false},
        p{"include_suppressed", "boolean", "Include suppressed findings.", false},
        p{"limit", "number", "Maximum findings.", false}
    }, true, tool_findings_query);
    register_one(srv, "aida.web.report.findings.suppress", "Suppress a finding for a session or global review scope with an auditable reason.", {
        p{"issue_id", "number", "Finding issue id.", true},
        p{"session_id", "string", "Audit session id.", false},
        p{"reason", "string", "Suppression reason.", true},
        p{"scope", "string", "finding|session|target.", false},
        p{"actor", "string", "Operator label.", false},
        p{"expires_ms", "number", "Optional expiry epoch milliseconds.", false}
    }, false, tool_findings_suppress);
    register_one(srv, "aida.web.report.evidence.capture", "Capture redacted evidence summaries from a site-map exchange, issue evidence, or supplied raw request/response.", {
        p{"session_id", "string", "Audit session id.", true},
        p{"issue_id", "number", "Optional issue id.", false},
        p{"exchange_id", "number", "Optional site-map exchange id.", false},
        p{"request_raw", "string", "Manual raw request; persisted only after redaction and returned as hash/length/preview.", false},
        p{"response_raw", "string", "Manual raw response; persisted only after redaction and returned as hash/length/preview.", false},
        p{"marker", "string", "Evidence marker.", false},
        p{"category", "string", "Evidence category.", false},
        p{"label", "string", "Evidence label.", false}
    }, false, tool_evidence_capture);
    register_one(srv, "aida.web.report.generate", "Generate a markdown, HTML, JSON, SARIF 2.1.0, or CSV web report using the existing AiDA report generator.", {
        p{"format", "string", "markdown|html|json|sarif_2_1_0|csv.", true},
        p{"output_path", "string", "Destination file path.", true},
        p{"title", "string", "Report title.", false},
        p{"client", "string", "Client name.", false},
        p{"scope_summary", "string", "Scope summary.", false},
        p{"session_id", "string", "Audit session id.", false},
        p{"include_session_context", "boolean", "Include session/evidence context.", false},
        p{"include_audit_trail", "boolean", "Include redacted audit trail section.", false},
        p{"audit_trail_limit", "number", "Maximum audit entries.", false},
        p{"include_evidence", "boolean", "Include issue evidence in the report.", false},
        p{"include_remediation", "boolean", "Include remediation text.", false},
        p{"severity_min", "string", "Minimum severity.", false},
        p{"target_domain", "string", "Target host/domain filter.", false},
        p{"audit_id", "number", "Scanner audit id filter.", false},
        p{"include_issue_ids", "array", "Specific issue ids.", false}
    }, false, tool_report_generate);
    register_one(srv, "aida.web.report.executive_summary", "Create a deterministic local executive summary from finding counts, categories, and remediation text.", {
        p{"session_id", "string", "Audit session id.", false},
        p{"severity_min", "string", "Minimum severity.", false},
        p{"host", "string", "Host filter.", false},
        p{"type_key", "string", "Type-key filter.", false},
        p{"include_suppressed", "boolean", "Include suppressed findings.", false},
        p{"limit", "number", "Maximum findings to summarize.", false}
    }, true, tool_executive_summary);
    register_one(srv, "aida.web.report.audit_trail", "Query the redacted Plan 6 audit trail.", {
        p{"session_id", "string", "Audit session id.", false},
        p{"tool", "string", "Tool-name substring.", false},
        p{"since_ms", "number", "Earliest timestamp.", false},
        p{"until_ms", "number", "Latest timestamp.", false},
        p{"limit", "number", "Maximum entries.", false}
    }, true, tool_audit_trail);
    diag::log_tagged("web_report_mcp", "registered aida.web.report facade tools");
}

}
}
}
