#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef small
#undef small
#endif

#include "burp_crawl_audit_mcp.hpp"
#include "crawl_audit.hpp"
#include "../../settings/standalone_compat.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace crawl_audit_mcp {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace {

tool_result_t error_with_data(const std::string& text, const json& data)
{
    return tool_result_t{false, text, data};
}

json status_to_json(const crawl_audit::pipeline_status_t& s)
{
    json out;
    out["id"] = static_cast<uint64_t>(s.id);
    out["crawl_id"] = static_cast<uint64_t>(s.crawl_id);
    json aids = json::array();
    for (uint64_t a : s.audit_ids)
        aids.push_back(static_cast<uint64_t>(a));
    out["audit_ids"] = std::move(aids);
    out["pages_discovered"] = s.pages_discovered;
    out["audits_started"] = s.audits_started;
    out["issues_found"] = s.issues_found;
    out["phase"] = s.phase;
    out["started_ms"] = static_cast<uint64_t>(s.started_ms);
    out["finished_ms"] = static_cast<uint64_t>(s.finished_ms);
    out["last_error"] = s.last_error;
    return out;
}

crawl_audit::pipeline_config_t config_from_json(const json& p)
{
    crawl_audit::pipeline_config_t cfg;

    if (p.contains("start_urls") && p["start_urls"].is_array())
    {
        for (const auto& u : p["start_urls"])
            if (u.is_string())
                cfg.start_urls.push_back(u.get<std::string>());
    }

    if (p.contains("max_depth") && p["max_depth"].is_number())
        cfg.max_depth = p["max_depth"].get<int>();

    if (p.contains("max_pages") && p["max_pages"].is_number())
        cfg.max_pages = p["max_pages"].get<int>();

    if (p.contains("same_host_only") && p["same_host_only"].is_boolean())
        cfg.same_host_only = p["same_host_only"].get<bool>();

    if (p.contains("scope_only") && p["scope_only"].is_boolean())
        cfg.scope_only = p["scope_only"].get<bool>();

    if (p.contains("enabled_modules") && p["enabled_modules"].is_array())
    {
        for (const auto& m : p["enabled_modules"])
            if (m.is_string())
                cfg.enabled_modules.push_back(m.get<std::string>());
    }

    if (p.contains("max_concurrent") && p["max_concurrent"].is_number())
        cfg.max_concurrent = p["max_concurrent"].get<int>();

    if (p.contains("throttle_ms") && p["throttle_ms"].is_number())
        cfg.throttle_ms = p["throttle_ms"].get<int>();

    if (p.contains("audit_after_crawl") && p["audit_after_crawl"].is_boolean())
        cfg.audit_after_crawl = p["audit_after_crawl"].get<bool>();

    return cfg;
}

tool_result_t handle_start(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_start entry");

    crawl_audit::pipeline_config_t cfg = config_from_json(p);

    if (cfg.start_urls.empty())
    {
        diag::log_tagged_fmt("mcp_burp", "crawl_audit_start missing_start_urls");
        json data;
        data["error"] = "start_urls is required and must be a non-empty array";
        data["status"] = "missing_start_urls";
        return error_with_data("start_urls is required", data);
    }

    diag::log_tagged_fmt("mcp_burp", "crawl_audit_start urls=%zu depth=%d max_pages=%d same_host=%d scope=%d max_concurrent=%d throttle=%d audit_after=%d",
        cfg.start_urls.size(), cfg.max_depth, cfg.max_pages,
        (int)cfg.same_host_only, (int)cfg.scope_only,
        cfg.max_concurrent, cfg.throttle_ms, (int)cfg.audit_after_crawl);

    uint64_t pipeline_id = crawl_audit::start(cfg);
    if (pipeline_id == 0)
    {
        diag::log_tagged_fmt("mcp_burp", "crawl_audit_start failed");
        json data;
        data["error"] = "failed to start pipeline";
        data["status"] = "start_failed";
        return error_with_data("crawl-audit start failed", data);
    }

    diag::log_tagged_fmt("mcp_burp", "crawl_audit_start ok pipeline_id=%llu",
        static_cast<unsigned long long>(pipeline_id));

    auto s = crawl_audit::status(pipeline_id);
    json data = status_to_json(s);
    return tool_result_t::ok("crawl-audit started pipeline_id=" + std::to_string(pipeline_id), data);
}

tool_result_t handle_status(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_status entry");

    if (!p.contains("pipeline_id") || !p["pipeline_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "crawl_audit_status missing_pipeline_id");
        return tool_result_t::error("pipeline_id parameter required");
    }

    uint64_t pipeline_id = p["pipeline_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_status pipeline_id=%llu",
        static_cast<unsigned long long>(pipeline_id));

    auto s = crawl_audit::status(pipeline_id);
    if (s.id == 0 && s.last_error == "pipeline not found")
    {
        diag::log_tagged_fmt("mcp_burp", "crawl_audit_status not_found pipeline_id=%llu",
            static_cast<unsigned long long>(pipeline_id));
        return tool_result_t::error("pipeline not found");
    }

    diag::log_tagged_fmt("mcp_burp", "crawl_audit_status ok pipeline_id=%llu phase=%s issues=%d",
        static_cast<unsigned long long>(pipeline_id), s.phase.c_str(), s.issues_found);

    return tool_result_t::ok("pipeline status phase=" + s.phase + " issues=" + std::to_string(s.issues_found),
        status_to_json(s));
}

tool_result_t handle_stop(const json& p)
{
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_stop entry");

    if (!p.contains("pipeline_id") || !p["pipeline_id"].is_number())
    {
        diag::log_tagged_fmt("mcp_burp", "crawl_audit_stop missing_pipeline_id");
        return tool_result_t::error("pipeline_id parameter required");
    }

    uint64_t pipeline_id = p["pipeline_id"].get<uint64_t>();
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_stop pipeline_id=%llu",
        static_cast<unsigned long long>(pipeline_id));

    bool ok = crawl_audit::stop(pipeline_id);
    if (!ok)
    {
        diag::log_tagged_fmt("mcp_burp", "crawl_audit_stop not_found pipeline_id=%llu",
            static_cast<unsigned long long>(pipeline_id));
        return tool_result_t::error("pipeline not found");
    }

    auto s = crawl_audit::status(pipeline_id);
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_stop ok pipeline_id=%llu phase=%s",
        static_cast<unsigned long long>(pipeline_id), s.phase.c_str());

    return tool_result_t::ok("pipeline stopped pipeline_id=" + std::to_string(pipeline_id),
        status_to_json(s));
}

tool_result_t handle_list(const json&)
{
    diag::log_tagged_fmt("mcp_burp", "crawl_audit_list entry");

    auto pipelines = crawl_audit::list();
    json arr = json::array();
    for (const auto& s : pipelines)
        arr.push_back(status_to_json(s));

    diag::log_tagged_fmt("mcp_burp", "crawl_audit_list ok count=%zu", pipelines.size());

    json r;
    r["pipelines"] = std::move(arr);
    return tool_result_t::ok("pipelines count=" + std::to_string(pipelines.size()), r);
}

}

void register_crawl_audit_tools(mcp_standalone::server_t& srv)
{
    register_compat(srv, {
        "burp_crawl_audit_manage", "burp",
        "Manage the Crawl-Audit pipeline. Actions: start, status, stop, list.",
        {{"action", "string", "start|status|stop|list", true},
         {"payload", "object", "Action-specific parameters; top-level action-specific fields are also accepted.", false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return handle_start(p);
            if (action == "status") return handle_status(p);
            if (action == "stop") return handle_stop(p);
            if (action == "list") return handle_list(p);
            return compat_unknown_action("burp_crawl_audit_manage", action);
        },
        false
    });
}

}
}
}
