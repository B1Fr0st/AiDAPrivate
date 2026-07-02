#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_report_mcp.hpp"
#include "report_generator.hpp"
#include "issue.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace report_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

json report_to_json(const report::generated_report_t& r)
{
    json out;
    out["id"] = static_cast<uint64_t>(r.id);
    out["ts_ms"] = static_cast<uint64_t>(r.ts_ms);
    out["title"] = r.title;
    out["output_path"] = r.output_path;
    out["format"] = report::format_label(r.format);
    out["issue_count"] = static_cast<uint64_t>(r.issue_count);
    return out;
}

tool_result_t handle_generate(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "report_generate entry");
    if (!p.contains("title") || !p["title"].is_string() || p["title"].get<std::string>().empty())
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate missing_title");
        return tool_result_t::error("title parameter required for generate action");
    }
    if (!p.contains("format") || !p["format"].is_string())
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate missing_format");
        return tool_result_t::error("format parameter required for generate action");
    }
    std::string format_str = p["format"].get<std::string>();
    report::report_format_t fmt;
    if (!report::parse_format(format_str, fmt))
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate invalid_format=%s", format_str.c_str());
        return tool_result_t::error("invalid format: " + format_str + " (expected html, markdown, json, sarif_2_1, or csv)");
    }

    report::report_config_t cfg;
    cfg.title = p["title"].get<std::string>();
    cfg.format = fmt;
    if (p.contains("client") && p["client"].is_string()) cfg.client = p["client"].get<std::string>();
    if (p.contains("scope_summary") && p["scope_summary"].is_string()) cfg.scope_summary = p["scope_summary"].get<std::string>();
    if (p.contains("include_evidence") && p["include_evidence"].is_boolean()) cfg.include_evidence = p["include_evidence"].get<bool>();
    if (p.contains("include_remediation") && p["include_remediation"].is_boolean()) cfg.include_remediation = p["include_remediation"].get<bool>();
    if (p.contains("output_path") && p["output_path"].is_string()) cfg.output_path = p["output_path"].get<std::string>();

    if (p.contains("include_issue_ids") && p["include_issue_ids"].is_array())
    {
        for (const auto& v : p["include_issue_ids"])
        {
            if (v.is_number()) cfg.include_issue_ids.push_back(static_cast<uint64_t>(v.get<int64_t>()));
        }
    }

    if (cfg.include_issue_ids.empty() && p.contains("severity_min") && p["severity_min"].is_string())
    {
        std::string sev_str = p["severity_min"].get<std::string>();
        severity_t sev;
        if (parse_severity(sev_str, sev))
        {
            issue_filter_t filt;
            filt.has_severity_min = true;
            filt.severity_min = sev;
            auto matching = issue_store::list(filt);
            for (const auto& iss : matching) cfg.include_issue_ids.push_back(iss.id);
            diag::log_tagged_fmt("mcp_burp", "report_generate severity_min=%s matched=%zu", sev_str.c_str(), matching.size());
        }
        else
        {
            diag::log_tagged_fmt("mcp_burp", "report_generate invalid_severity_min=%s", sev_str.c_str());
            return tool_result_t::error("invalid severity_min: " + sev_str + " (expected info, low, medium, high, or critical)");
        }
    }

    diag::log_tagged_fmt("mcp_burp", "report_generate title=%s format=%s issue_ids=%zu evidence=%d remediation=%d",
        cfg.title.c_str(), format_str.c_str(), cfg.include_issue_ids.size(), (int)cfg.include_evidence, (int)cfg.include_remediation);

    std::string out_path_or_error;
    bool ok = report::generate(cfg, out_path_or_error);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "report_generate failed err=%s", out_path_or_error.c_str());
        json data;
        data["error"] = out_path_or_error;
        data["status"] = "generate_failed";
        data["title"] = cfg.title;
        data["format"] = format_str;
        return error_with_data("report generation failed: " + out_path_or_error, data);
    }

    diag::log_tagged_fmt("mcp_burp", "report_generate ok path=%s", out_path_or_error.c_str());
    json result;
    result["status"] = "generated";
    result["output_path"] = out_path_or_error;
    result["title"] = cfg.title;
    result["format"] = format_str;
    result["issue_count"] = static_cast<uint64_t>(cfg.include_issue_ids.size());
    return tool_result_t::ok("report generated: " + out_path_or_error, result);
}

tool_result_t handle_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "report_list entry");
    auto reports = report::list_reports();
    json arr = json::array();
    for (const auto& r : reports) arr.push_back(report_to_json(r));
    diag::log_tagged_fmt("mcp_burp", "report_list ok count=%zu", reports.size());
    json result;
    result["reports"] = std::move(arr);
    result["count"] = static_cast<uint64_t>(reports.size());
    return tool_result_t::ok("reports count=" + std::to_string(reports.size()), result);
}

tool_result_t handle_count(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "report_count entry");
    size_t n = report::reports_count();
    diag::log_tagged_fmt("mcp_burp", "report_count ok count=%zu", n);
    json result;
    result["count"] = static_cast<uint64_t>(n);
    return tool_result_t::ok("reports count=" + std::to_string(n), result);
}

tool_result_t handle_clear_history(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "report_clear_history entry");
    size_t before = report::reports_count();
    report::clear_history();
    size_t after = report::reports_count();
    diag::log_tagged_fmt("mcp_burp", "report_clear_history ok before=%zu after=%zu", before, after);
    json result;
    result["before_count"] = static_cast<uint64_t>(before);
    result["after_count"] = static_cast<uint64_t>(after);
    result["cleared"] = static_cast<uint64_t>(before >= after ? before - after : 0);
    return tool_result_t::ok("report history cleared before=" + std::to_string(before) + " after=" + std::to_string(after), result);
}

}

void register_report_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_report_manage", "burp",
        "Manage Burp-style vulnerability reports. Actions: generate, list, count, clear_history.",
        {{"action", "string", "generate|list|count|clear_history", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "generate") return handle_generate(p);
            if (action == "list") return handle_list(p);
            if (action == "count") return handle_count(p);
            if (action == "clear_history") return handle_clear_history(p);
            return compat_unknown_action("burp_report_manage", action);
        },
        false
    });
}

}
}
}
