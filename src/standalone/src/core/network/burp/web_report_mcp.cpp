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
    out["cvss_score"] = issue.cvss_score;
    out["cvss_vector"] = audit_session_mcp_store::redact_for_output(issue.cvss_vector);
    out["cvss_severity"] = audit_session_mcp_store::redact_for_output(issue.cvss_severity);
    out["owasp_category"] = audit_session_mcp_store::redact_for_output(issue.owasp_category);
    out["suppressed"] = issue.suppressed;
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
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false))
        return tool_result_t::error(findings_db::last_error().empty() ? "findings database unavailable" : findings_db::last_error());
    issue_t issue;
    if (!findings_db::get(issue_id, issue))
        return tool_result_t::error("issue not found");
    findings_db::suppression_t db_suppression;
    db_suppression.finding_id = issue_id;
    db_suppression.reason = reason;
    db_suppression.suppressed_by = params.value("actor", std::string("mcp"));
    db_suppression.scope = params.value("scope", std::string("finding"));
    db_suppression.create_rule = true;
    if (!findings_db::suppress(db_suppression))
        return tool_result_t::error(findings_db::last_error().empty() ? "finding suppression failed" : findings_db::last_error());
    findings_db::get(issue_id, issue);
    json out;
    out["suppressed"] = true;
    out["suppression_id"] = issue_id;
    out["suppression"] = json{
        {"id", issue_id},
        {"session_id", session_id_from_params(params)},
        {"issue_id", issue_id},
        {"scope", params.value("scope", std::string("finding"))},
        {"reason", audit_session_mcp_store::redact_for_output(reason)},
        {"actor", audit_session_mcp_store::redact_for_output(params.value("actor", std::string("mcp")))},
        {"issue_type", audit_session_mcp_store::redact_for_output(issue.type_key)},
        {"host", issue.host},
        {"path", audit_session_mcp_store::redact_url_for_output(issue.path)},
        {"created_ms", issue.suppressed_ms},
        {"active", issue.suppressed}
    };
    return tool_result_t::ok(out);
}

json merged_metadata(const json& params)
{
    json metadata = json::object();
    if (params.contains("metadata") && params["metadata"].is_object())
        metadata = params["metadata"];
    if (params.contains("request_metadata") && params["request_metadata"].is_object())
        metadata["request"] = params["request_metadata"];
    if (params.contains("response_metadata") && params["response_metadata"].is_object())
        metadata["response"] = params["response_metadata"];
    if (params.contains("exchange_metadata") && params["exchange_metadata"].is_object())
        metadata["exchange"] = params["exchange_metadata"];
    metadata["source"] = "aida.web.report.evidence.capture";
    return metadata;
}

bool capture_evidence_record(const evidence_store::evidence_capture_t& capture,
                             evidence_store::evidence_record_t& stored,
                             std::string& error)
{
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false)) {
        error = findings_db::last_error().empty() ? "findings database unavailable" : findings_db::last_error();
        return false;
    }
    if (!evidence_store::capture(capture, stored)) {
        error = evidence_store::last_error().empty() ? "evidence capture failed" : evidence_store::last_error();
        return false;
    }
    return true;
}

evidence_store::evidence_capture_t request_response_capture(const json& params,
                                                            uint64_t issue_id,
                                                            const std::string& session_id,
                                                            uint64_t exchange_id,
                                                            const std::string& request_raw,
                                                            const std::string& response_raw,
                                                            const std::string& marker,
                                                            uint64_t marker_offset_request,
                                                            uint64_t marker_offset_response,
                                                            const std::string& description)
{
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
    capture.metadata_json = merged_metadata(params);
    return capture;
}

tool_result_t captured_response(const evidence_store::evidence_record_t& stored)
{
    json out;
    out["captured"] = 1;
    out["stored"] = true;
    out["evidence_id"] = stored.id;
    out["finding_id"] = stored.finding_id;
    out["issue_id"] = stored.finding_id;
    out["captured_ms"] = stored.captured_ms;
    out["evidence"] = json::array({evidence_store::summary_json(stored)});
    return tool_result_t::ok(out);
}

tool_result_t capture_from_exchange(const json& params, const std::string& session_id, uint64_t issue_id, uint64_t exchange_id)
{
    exchange_observed_t exchange;
    if (!sitemap::find_exchange(exchange_id, exchange))
        return tool_result_t::error("exchange not found");
    const std::string request_raw = request_raw_from_exchange(exchange);
    const std::string response_raw = response_raw_from_exchange(exchange);
    std::string persist_error;
    evidence_store::evidence_record_t stored;
    auto capture = request_response_capture(params,
                                            issue_id,
                                            session_id,
                                            exchange_id,
                                            request_raw,
                                            response_raw,
                                            std::string(),
                                            0,
                                            0,
                                            params.value("label", std::string("captured exchange")));
    if (!capture_evidence_record(capture, stored, persist_error))
        return tool_result_t::error(persist_error);
    return captured_response(stored);
}

tool_result_t capture_from_issue(const json& params, const std::string& session_id, uint64_t issue_id)
{
    issue_t issue;
    if (!findings_db::initialize() || !findings_db::mirror_issue_store(false))
        return tool_result_t::error(findings_db::last_error().empty() ? "findings database unavailable" : findings_db::last_error());
    if (!findings_db::get(issue_id, issue))
        return tool_result_t::error("issue not found");
    json records = json::array();
    size_t captured = 0;
    for (const auto& evidence : issue.evidence) {
        std::string persist_error;
        evidence_store::evidence_record_t stored;
        auto capture = request_response_capture(params,
                                                issue_id,
                                                session_id,
                                                issue.src_exchange_id,
                                                evidence.request_raw,
                                                evidence.response_raw,
                                                evidence.marker,
                                                evidence.marker_offset_request,
                                                evidence.marker_offset_response,
                                                params.value("label", issue.name));
        if (!capture_evidence_record(capture, stored, persist_error))
            return tool_result_t::error(persist_error);
        records.push_back(evidence_store::summary_json(stored));
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
    evidence_store::evidence_record_t stored;
    auto capture = request_response_capture(params,
                                            issue_id,
                                            session_id,
                                            0,
                                            request_raw,
                                            response_raw,
                                            params.value("marker", std::string()),
                                            0,
                                            0,
                                            params.value("label", std::string("manual evidence")));
    if (params.contains("url") && params["url"].is_string())
        capture.metadata_json["url"] = audit_session_mcp_store::redact_url_for_output(params["url"].get<std::string>());
    if (params.contains("host") && params["host"].is_string())
        capture.metadata_json["host"] = audit_session_mcp_store::redact_for_output(params["host"].get<std::string>());
    if (params.contains("path") && params["path"].is_string())
        capture.metadata_json["path"] = audit_session_mcp_store::redact_url_for_output(params["path"].get<std::string>());
    if (params.contains("method") && params["method"].is_string())
        capture.metadata_json["method"] = audit_session_mcp_store::redact_for_output(params["method"].get<std::string>());
    if (params.contains("status_code"))
        capture.metadata_json["status_code"] = param_u64(params, "status_code");
    if (!capture_evidence_record(capture, stored, persist_error))
        return tool_result_t::error(persist_error);
    return captured_response(stored);
}

tool_result_t capture_file_like(const json& params, const std::string& session_id, uint64_t issue_id, bool screenshot)
{
    evidence_store::evidence_capture_t capture;
    capture.finding_id = issue_id;
    capture.session_id = session_id;
    capture.kind = screenshot ? evidence_store::evidence_kind_t::screenshot : evidence_store::evidence_kind_t::file;
    capture.description = params.value("label", screenshot ? std::string("screenshot evidence") : std::string("file evidence"));
    capture.metadata_json = merged_metadata(params);
    capture.source_path = screenshot
        ? params.value("screenshot_path", std::string())
        : params.value("file_path", params.value("source_path", std::string()));
    capture.file_name = params.value("file_name", std::filesystem::path(capture.source_path).filename().string());
    if (!screenshot && params.contains("file_text") && params["file_text"].is_string()) {
        const std::string text = params["file_text"].get<std::string>();
        capture.bytes.assign(text.begin(), text.end());
        if (capture.file_name.empty())
            capture.file_name = "evidence.txt";
    }
    std::string error;
    evidence_store::evidence_record_t stored;
    if (!capture_evidence_record(capture, stored, error))
        return tool_result_t::error(error);
    return captured_response(stored);
}

tool_result_t capture_timing_data(const json& params, const std::string& session_id, uint64_t issue_id)
{
    if (!params.contains("timing_data") || !params["timing_data"].is_object())
        return tool_result_t::error("timing_data object is required");
    evidence_store::evidence_capture_t capture;
    capture.finding_id = issue_id;
    capture.session_id = session_id;
    capture.kind = evidence_store::evidence_kind_t::timing;
    capture.timing_json = params["timing_data"];
    capture.description = params.value("label", std::string("timing evidence"));
    capture.metadata_json = merged_metadata(params);
    std::string error;
    evidence_store::evidence_record_t stored;
    if (!capture_evidence_record(capture, stored, error))
        return tool_result_t::error(error);
    return captured_response(stored);
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
    if (params.contains("screenshot_path") && params["screenshot_path"].is_string())
        return capture_file_like(params, session_id, issue_id, true);
    if ((params.contains("file_path") && params["file_path"].is_string()) ||
        (params.contains("source_path") && params["source_path"].is_string()) ||
        (params.contains("file_text") && params["file_text"].is_string()))
        return capture_file_like(params, session_id, issue_id, false);
    if (params.contains("timing_data"))
        return capture_timing_data(params, session_id, issue_id);
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
    report::report_config_t cfg;
    cfg.title = params.value("title", std::string("AiDA Web Security Report"));
    cfg.client = params.value("client", std::string());
    cfg.scope_summary = params.value("scope_summary", std::string());
    cfg.output_path = params.value("output_path", std::string());
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
        const bool same_output = cfg.output_path.empty() ? r.inline_output : r.output_path == out_path;
        if (same_output && r.ts_ms >= newest_ts) {
            report_id = r.id;
            issue_count = r.issue_count;
            newest_ts = r.ts_ms;
        }
    }
    uint64_t bytes_written = 0;
    std::error_code ec;
    if (!cfg.output_path.empty()) {
        const auto sz = std::filesystem::file_size(out_path, ec);
        if (!ec)
            bytes_written = static_cast<uint64_t>(sz);
    } else {
        bytes_written = static_cast<uint64_t>(out_path.size());
    }
    json out;
    out["report_id"] = report_id;
    out["output_path"] = cfg.output_path.empty() ? std::string() : out_path;
    out["inline"] = cfg.output_path.empty();
    if (cfg.output_path.empty())
        out["content"] = out_path;
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

double risk_score_from_counts(const json& counts)
{
    const double score =
        counts.value("critical", 0ull) * 20.0 +
        counts.value("high", 0ull) * 12.0 +
        counts.value("medium", 0ull) * 6.0 +
        counts.value("low", 0ull) * 2.0 +
        counts.value("info", 0ull) * 0.5;
    return (std::min)(100.0, score);
}

std::string risk_posture_from_score(double score)
{
    if (score >= 80.0)
        return "critical";
    if (score >= 50.0)
        return "high";
    if (score >= 25.0)
        return "moderate";
    if (score > 0.0)
        return "low";
    return "clear";
}

json compliance_mapping_json(const std::vector<issue_t>& issues)
{
    std::map<std::string, json> rows;
    for (const auto& issue : issues) {
        std::string key = issue.owasp_category.empty() ? category_for_issue(issue) : issue.owasp_category;
        key = audit_session_mcp_store::redact_for_output(key.empty() ? std::string("unmapped") : key);
        auto& row = rows[key];
        if (row.is_null()) {
            row = json{{"control", key}, {"finding_count", 0}, {"highest_severity", "Info"}, {"status", "observed"}};
        }
        row["finding_count"] = row.value("finding_count", 0ull) + 1ull;
        severity_t existing = severity_t::info;
        parse_severity(row.value("highest_severity", std::string("Info")), existing);
        if (static_cast<int>(issue.severity) > static_cast<int>(existing))
            row["highest_severity"] = severity_label(issue.severity);
        if (issue.severity == severity_t::critical || issue.severity == severity_t::high)
            row["status"] = "non_compliant";
        else if (row.value("status", std::string("observed")) != "non_compliant" && issue.severity == severity_t::medium)
            row["status"] = "needs_attention";
    }
    json out = json::array();
    for (auto& row : rows)
        out.push_back(std::move(row.second));
    return out;
}

std::string executive_summary_text(const json& out)
{
    std::ostringstream os;
    os << "Risk posture: " << out.value("risk_posture", std::string("clear"))
       << " (" << out.value("risk_score", 0.0) << "/100). "
       << "Findings: " << out.value("finding_count", 0ull) << ".";
    const auto& counts = out["severity_counts"];
    os << " Critical " << counts.value("critical", 0ull)
       << ", High " << counts.value("high", 0ull)
       << ", Medium " << counts.value("medium", 0ull)
       << ", Low " << counts.value("low", 0ull)
       << ", Info " << counts.value("info", 0ull) << ".";
    return os.str();
}

tool_result_t tool_executive_summary(const json& params)
{
    if (params.value("ai_augment", false)) {
        json data;
        data["ai_augment"] = false;
        data["unsupported"] = true;
        data["reason"] = "AI augmentation is not enabled for this MCP report surface; deterministic local summary generation is available.";
        return tool_result_t::error("ai_augment is unsupported unless an enabled AiDA AI provider path is explicitly wired for report summarization", "ai_augment_unsupported", data);
    }
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
    out["ai_augment"] = false;
    out["finding_count"] = issues.size();
    out["severity_counts"] = severity_counts_json(issues);
    out["risk_score"] = risk_score_from_counts(out["severity_counts"]);
    out["risk_posture"] = risk_posture_from_score(out["risk_score"].get<double>());
    out["category_counts"] = category_arr;
    out["priority_findings"] = top_arr;
    out["recommendations"] = recommendations_json(issues);
    out["compliance_mapping"] = compliance_mapping_json(issues);
    out["summary"] = executive_summary_text(out);
    const std::string format = params.value("format", std::string("json"));
    if (format == "markdown" || format == "md") {
        std::ostringstream md;
        md << "# Executive Summary\n\n" << out["summary"].get<std::string>() << "\n\n"
           << "- Risk posture: " << out["risk_posture"].get<std::string>() << "\n"
           << "- Risk score: " << out["risk_score"].get<double>() << "/100\n"
           << "- Findings: " << issues.size() << "\n";
        out["content"] = md.str();
        out["format"] = "markdown";
    } else if (format == "text") {
        out["content"] = out["summary"];
        out["format"] = "text";
    } else {
        out["format"] = "json";
    }
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
    t.handler = std::move(handler);
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
    register_one(srv, "aida.web.report.evidence.capture", "Capture redacted evidence through the SQLite evidence store from a site-map exchange, issue evidence, screenshot, file, timing data, or supplied raw request/response.", {
        p{"session_id", "string", "Audit session id.", true},
        p{"issue_id", "number", "Optional issue id.", false},
        p{"exchange_id", "number", "Optional site-map exchange id.", false},
        p{"request_raw", "string", "Manual raw request; persisted only after redaction and returned as hash/length/preview.", false},
        p{"response_raw", "string", "Manual raw response; persisted only after redaction and returned as hash/length/preview.", false},
        p{"screenshot_path", "string", "Local screenshot file to copy into the evidence store.", false},
        p{"file_path", "string", "Local evidence file to copy into the evidence store.", false},
        p{"source_path", "string", "Local evidence file path alias.", false},
        p{"file_text", "string", "Inline textual file evidence; persisted after redaction.", false},
        p{"file_name", "string", "Stored evidence filename hint.", false},
        p{"timing_data", "object", "Timing evidence object.", false},
        p{"request_metadata", "object", "Redacted request metadata.", false},
        p{"response_metadata", "object", "Redacted response metadata.", false},
        p{"exchange_metadata", "object", "Redacted exchange metadata.", false},
        p{"metadata", "object", "Additional redacted evidence metadata.", false},
        p{"marker", "string", "Evidence marker.", false},
        p{"category", "string", "Evidence category.", false},
        p{"label", "string", "Evidence label.", false}
    }, false, tool_evidence_capture);
    register_one(srv, "aida.web.report.generate", "Generate a markdown, HTML, JSON, SARIF 2.1.0, or CSV web report using the existing AiDA report generator.", {
        p{"format", "string", "markdown|html|json|sarif_2_1_0|csv.", true},
        p{"output_path", "string", "Destination file path. Omit for inline content.", false},
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
        p{"include_issue_ids", "array", "Specific issue ids.", false},
        p{"include_recon", "boolean", "Include sanitized recon/offensive context from stored audit events.", false},
        p{"include_offensive_run_ids", "array", "Offensive run ids to include when present in stored redacted context.", false}
    }, false, tool_report_generate);
    register_one(srv, "aida.web.report.executive_summary", "Create a deterministic local executive summary with risk posture, compliance mapping, and recommended actions.", {
        p{"session_id", "string", "Audit session id.", false},
        p{"severity_min", "string", "Minimum severity.", false},
        p{"host", "string", "Host filter.", false},
        p{"type_key", "string", "Type-key filter.", false},
        p{"include_suppressed", "boolean", "Include suppressed findings.", false},
        p{"limit", "number", "Maximum findings to summarize.", false},
        p{"format", "string", "json|markdown|text.", false},
        p{"ai_augment", "boolean", "Request AI augmentation; returns explicit unsupported error unless an AI path is wired.", false}
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
