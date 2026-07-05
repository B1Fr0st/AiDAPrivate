#pragma once

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace mcp_standalone
{
namespace capacity_diag
{
    using json = nlohmann::json;

    enum class priority_t : int
    {
        p0 = 0,
        p1 = 1,
        p2 = 2,
        p3 = 3,
        p4 = 4,
        p5 = 5
    };

    struct quota_entry_t
    {
        std::string name;
        std::string scope;
        std::size_t limit = 0;
        bool reserved = false;
    };

    struct quota_set_t
    {
        std::size_t global_external_active_tools = 8;
        std::size_t global_external_queued_tools = 128;
        std::size_t per_principal_active_normal_tools = 4;
        std::size_t per_principal_active_long_running_tools = 1;
        std::size_t per_principal_queued_normal_tools = 32;
        std::size_t per_principal_queued_long_running_tools = 8;
        std::size_t per_session_active_mutations = 1;
        std::size_t per_session_active_read_only_tools = 4;
        std::size_t per_target_driver_debugger_active_tools = 2;
        std::size_t per_domain_mutating_active_tools = 1;
        std::size_t active_batch_children_per_principal = 16;
        std::size_t queued_batch_children_per_principal = 128;
        std::size_t active_background_command_sessions_per_principal = 2;
        std::size_t global_active_background_command_sessions = 8;
        std::size_t p0_reserved_liveness_slots = 2;
        std::size_t p1_reserved_foreground_slots = 1;
        std::size_t global_ingress_active_requests = 8;
        std::size_t global_ingress_queued_requests = 32;
        std::size_t per_principal_ingress_active_requests = 4;
        std::size_t per_principal_ingress_queued_requests = 8;
        std::size_t global_ingress_streams = 16;
        std::size_t per_principal_ingress_streams = 2;
    };

    struct pressure_snapshot_t
    {
        std::size_t tool_workers = 0;
        std::size_t tool_queue_limit = 0;
        std::size_t batch_workers = 0;
        std::size_t batch_queue_limit = 0;
        std::size_t active_http_requests = 0;
        std::size_t active_streams = 0;
        std::size_t global_ingress_active_requests = 0;
        std::size_t global_ingress_queued_requests = 0;
        std::size_t per_principal_ingress_active_requests = 0;
        std::size_t per_principal_ingress_queued_requests = 0;
        std::size_t global_ingress_streams = 0;
        std::size_t per_principal_ingress_streams = 0;
        std::size_t global_external_active_tools = 0;
        std::size_t global_external_queued_tools = 0;
        std::size_t batch_active_children = 0;
        std::size_t batch_queued_children = 0;
        std::size_t per_principal_active_normal_tools = 0;
        std::size_t per_principal_active_long_running_tools = 0;
        std::size_t per_principal_queued_normal_tools = 0;
        std::size_t per_principal_queued_long_running_tools = 0;
        std::size_t per_session_active_mutations = 0;
        std::size_t per_session_active_read_only_tools = 0;
        std::size_t per_target_driver_debugger_active_tools = 0;
        std::size_t per_domain_mutating_active_tools = 0;
        std::size_t active_background_command_sessions_per_principal = 0;
        std::size_t global_active_background_command_sessions = 0;
        std::size_t background_command_sessions_total = 0;
        std::size_t background_command_sessions_running = 0;
        std::size_t background_command_sessions_reader_active = 0;
        std::size_t background_command_sessions_timed_out = 0;
        std::uint64_t background_command_oldest_running_ms = 0;
        std::size_t downstream_general_pending = 0;
        std::size_t downstream_general_active = 0;
        std::size_t downstream_service_pending = 0;
        std::size_t downstream_service_active = 0;
        std::size_t downstream_critical_pending = 0;
        std::size_t downstream_critical_active = 0;
    };

    struct request_context_t
    {
        std::string diagnostic_id;
        std::string request_id;
        std::string transport;
        std::string route;
        std::string method;
        std::string principal_id;
        std::string session_id;
        std::string target_id;
        std::string tool_name;
        std::string domain;
        std::string lane;
        std::string action;
        std::string payload_shape;
        bool external = true;
        bool tool_known = true;
        bool read_only = true;
        bool session_manager = false;
        bool explicit_target = false;
        bool browser_tool = false;
        bool driver_debugger_tool = false;
        bool scanner_tool = false;
        bool decompiler_tool = false;
        bool network_tool = false;
        bool background_command = false;
        bool list_or_schema = false;
        bool batch_child = false;
        bool http_ingress = false;
        bool sse_stream = false;
        bool reserved_lane = false;
        std::uint32_t target_pid = 0;
        std::uint64_t requested_timeout_ms = 0;
        std::uint64_t effective_timeout_ms = 0;
        std::size_t batch_size = 0;
        std::size_t batch_index = 0;
    };

    struct decision_t
    {
        bool would_accept = true;
        std::string reason = "within_diagnostic_quota";
        std::string quota_name;
        std::string quota_scope;
        std::size_t observed = 0;
        std::size_t limit = 0;
    };

    struct prediction_t
    {
        request_context_t context;
        quota_set_t quotas;
        pressure_snapshot_t pressure;
        priority_t priority = priority_t::p4;
        std::string priority_name = "P4";
        std::string lane;
        std::string classification = "read_only";
        std::uint32_t cost_units = 1;
        bool long_running = false;
        bool mutating = false;
        bool read_only = true;
        bool session_manager = false;
        decision_t decision;
        bool diagnostics_only = true;
        bool enforcement_enabled = false;
    };

    struct activity_counters_t
    {
        std::size_t active_total = 0;
        std::size_t active_normal = 0;
        std::size_t active_long_running = 0;
        std::size_t active_batch_children = 0;
        std::size_t active_background_command_sessions = 0;
        std::size_t active_session_mutations = 0;
        std::size_t active_session_read_only = 0;
        std::size_t active_target_driver_debugger = 0;
        std::size_t active_domain_mutating = 0;
        bool registry_lock_busy = false;
    };

    struct record_t
    {
        std::uint64_t id = 0;
        std::string diagnostic_id;
        std::string principal_id;
        std::string session_id;
        std::string target_id;
        std::string domain;
        std::string lane;
        std::string tool_name;
        std::string priority_name;
        std::string classification;
        bool long_running = false;
        bool mutating = false;
        bool read_only = true;
        bool session_manager = false;
        bool driver_debugger_tool = false;
        bool browser_tool = false;
        bool scanner_tool = false;
        bool decompiler_tool = false;
        bool network_tool = false;
        bool background_command = false;
        bool batch_child = false;
        std::uint64_t started_ms = 0;
    };

    inline std::string lower_ascii(std::string text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return text;
    }

    inline std::string clean_label(const std::string& text, std::size_t max_len = 160)
    {
        std::string out;
        out.reserve((std::min)(text.size(), max_len));
        for (char ch : text) {
            const unsigned char c = static_cast<unsigned char>(ch);
            out.push_back((c < 0x20 || c == 0x7f) ? '_' : ch);
            if (out.size() >= max_len)
                break;
        }
        return out;
    }

    inline const char* priority_name(priority_t p)
    {
        switch (p) {
        case priority_t::p0: return "P0";
        case priority_t::p1: return "P1";
        case priority_t::p2: return "P2";
        case priority_t::p3: return "P3";
        case priority_t::p4: return "P4";
        case priority_t::p5: return "P5";
        default: return "P4";
        }
    }

    inline quota_set_t make_quota_set(std::size_t tool_workers,
                                      std::size_t http_workers = 0,
                                      std::size_t http_queue_limit = 0,
                                      std::size_t stream_limit = 0,
                                      std::size_t principal_stream_limit = 0)
    {
        quota_set_t q;
        q.global_external_active_tools = (std::max)(tool_workers, std::size_t{8});
        q.global_external_queued_tools = (std::max)(std::size_t{128}, tool_workers * std::size_t{32});
        if (http_workers != 0) {
            const std::size_t reserved = (std::min)(std::size_t{4}, (std::max)(std::size_t{2}, http_workers / std::size_t{4}));
            q.global_ingress_active_requests = (std::max)(std::size_t{4}, http_workers > reserved ? http_workers - reserved : std::size_t{1});
            q.per_principal_ingress_active_requests = (std::min)(std::size_t{4}, (std::max)(std::size_t{2}, q.global_ingress_active_requests / std::size_t{2}));
            q.global_ingress_queued_requests = (std::max)(std::size_t{8}, (std::min)(http_queue_limit == 0 ? http_workers * std::size_t{4} : http_queue_limit, http_workers * std::size_t{2}));
            q.per_principal_ingress_queued_requests = (std::max)(std::size_t{2}, (std::min)(std::size_t{8}, q.global_ingress_queued_requests / std::size_t{2}));
        }
        if (stream_limit != 0) {
            q.global_ingress_streams = stream_limit;
            q.per_principal_ingress_streams = principal_stream_limit != 0
                ? principal_stream_limit
                : (std::max)(std::size_t{1}, (std::min)(std::size_t{4}, stream_limit / std::size_t{4}));
        }
        return q;
    }

    inline std::vector<quota_entry_t> quota_entries(const quota_set_t& q)
    {
        return {
            {"global_external_active_tools", "global", q.global_external_active_tools, false},
            {"global_external_queued_tools", "global", q.global_external_queued_tools, false},
            {"per_principal_active_normal_tools", "principal", q.per_principal_active_normal_tools, false},
            {"per_principal_active_long_running_tools", "principal", q.per_principal_active_long_running_tools, false},
            {"per_principal_queued_normal_tools", "principal", q.per_principal_queued_normal_tools, false},
            {"per_principal_queued_long_running_tools", "principal", q.per_principal_queued_long_running_tools, false},
            {"per_session_active_mutations", "session", q.per_session_active_mutations, false},
            {"per_session_active_read_only_tools", "session", q.per_session_active_read_only_tools, false},
            {"per_target_driver_debugger_active_tools", "target", q.per_target_driver_debugger_active_tools, false},
            {"per_domain_mutating_active_tools", "domain", q.per_domain_mutating_active_tools, false},
            {"active_batch_children_per_principal", "principal_batch", q.active_batch_children_per_principal, false},
            {"queued_batch_children_per_principal", "principal_batch", q.queued_batch_children_per_principal, false},
            {"active_background_command_sessions_per_principal", "principal_background_command", q.active_background_command_sessions_per_principal, false},
            {"global_active_background_command_sessions", "global_background_command", q.global_active_background_command_sessions, false},
            {"p0_reserved_liveness_slots", "reserved_liveness", q.p0_reserved_liveness_slots, true},
            {"p1_reserved_foreground_slots", "reserved_foreground", q.p1_reserved_foreground_slots, true},
            {"global_ingress_active_requests", "ingress_global", q.global_ingress_active_requests, false},
            {"global_ingress_queued_requests", "ingress_global", q.global_ingress_queued_requests, false},
            {"per_principal_ingress_active_requests", "ingress_principal", q.per_principal_ingress_active_requests, false},
            {"per_principal_ingress_queued_requests", "ingress_principal", q.per_principal_ingress_queued_requests, false},
            {"global_ingress_streams", "ingress_stream_global", q.global_ingress_streams, false},
            {"per_principal_ingress_streams", "ingress_stream_principal", q.per_principal_ingress_streams, false}
        };
    }

    inline json quotas_json(const quota_set_t& q)
    {
        json out = json::array();
        for (const auto& entry : quota_entries(q)) {
            out.push_back({
                {"name", entry.name},
                {"scope", entry.scope},
                {"limit", entry.limit},
                {"reserved", entry.reserved}
            });
        }
        return out;
    }

    inline bool has_prefix(const std::string& text, const char* prefix)
    {
        return prefix && text.rfind(prefix, 0) == 0;
    }

    inline bool contains_any(const std::string& text, const std::vector<const char*>& needles)
    {
        for (const char* needle : needles) {
            if (needle && text.find(needle) != std::string::npos)
                return true;
        }
        return false;
    }

    inline bool classify_long_running(const request_context_t& ctx)
    {
        const std::string tool = lower_ascii(ctx.tool_name);
        const std::string domain = lower_ascii(ctx.domain);
        if (ctx.browser_tool || ctx.driver_debugger_tool || ctx.background_command)
            return true;
        if (ctx.effective_timeout_ms >= 60000)
            return true;
        if (domain == "browser" || domain == "scanner" || domain == "decompile" ||
            domain == "debugger" || domain == "driver" || domain == "network_security")
            return true;
        return contains_any(tool, {
            "scan", "bulk", "enumerate", "find_references", "find_strings",
            "classify", "api_monitor", "decompile", "search", "trace", "sandbox"
        });
    }

    inline priority_t predict_priority(const request_context_t& ctx, bool long_running, bool mutating, bool session_manager)
    {
        const std::string method = lower_ascii(ctx.method);
        const std::string route = lower_ascii(ctx.route);
        const std::string tool = lower_ascii(ctx.tool_name);
        if (route == "/health" || method == "initialize" || method == "notifications/initialized" ||
            method == "ping" || method == "notifications/cancelled" || method == "shutdown" ||
            tool == "cancel_command")
            return priority_t::p0;
        if (ctx.background_command || ctx.batch_size > 16 ||
            contains_any(tool, {"bulk", "full", "sweep", "large_batch"}))
            return priority_t::p5;
        if (ctx.list_or_schema || method == "tools/list" || method == "resources/list" ||
            method == "prompts/list" || tool == "get_tool_descriptions" || tool == "list_processes")
            return priority_t::p4;
        if (session_manager || (mutating && !long_running))
            return priority_t::p1;
        if (long_running)
            return priority_t::p3;
        if (ctx.explicit_target || ctx.target_pid != 0 || !ctx.target_id.empty())
            return priority_t::p2;
        return priority_t::p4;
    }

    inline std::uint32_t predict_cost_units(const request_context_t& ctx, priority_t priority, bool long_running, bool mutating, bool session_manager)
    {
        std::uint32_t cost = 1;
        if (long_running)
            cost += 3;
        if (mutating)
            cost += 2;
        if (session_manager)
            cost += 2;
        if (ctx.browser_tool)
            cost += 3;
        if (ctx.driver_debugger_tool)
            cost += 3;
        if (ctx.background_command)
            cost += 4;
        if (ctx.batch_child)
            cost += 1;
        if (ctx.batch_size > 16)
            cost += static_cast<std::uint32_t>((std::min<std::size_t>)(ctx.batch_size / 16, 8));
        if (priority == priority_t::p0)
            cost = 0;
        return cost;
    }

    inline void mark_would_reject(decision_t& d, const char* reason, const char* quota_name, const char* quota_scope, std::size_t observed, std::size_t limit)
    {
        if (!d.would_accept)
            return;
        d.would_accept = false;
        d.reason = reason ? reason : "would_reject";
        d.quota_name = quota_name ? quota_name : "";
        d.quota_scope = quota_scope ? quota_scope : "";
        d.observed = observed;
        d.limit = limit;
    }

    inline prediction_t predict(const request_context_t& ctx, const quota_set_t& quotas, const pressure_snapshot_t& pressure)
    {
        prediction_t p;
        p.context = ctx;
        p.quotas = quotas;
        p.pressure = pressure;
        p.lane = ctx.lane.empty() ? std::string("unclassified") : ctx.lane;
        p.session_manager = ctx.session_manager;
        p.read_only = ctx.read_only && !ctx.session_manager;
        p.mutating = !ctx.read_only || ctx.session_manager;
        p.long_running = classify_long_running(ctx);
        p.classification = p.session_manager ? std::string("session_manager") : (p.mutating ? std::string("mutating") : std::string("read_only"));
        p.priority = predict_priority(ctx, p.long_running, p.mutating, p.session_manager);
        p.priority_name = priority_name(p.priority);
        p.cost_units = predict_cost_units(ctx, p.priority, p.long_running, p.mutating, p.session_manager);

        if (ctx.http_ingress && !ctx.reserved_lane && p.priority != priority_t::p0) {
            if (pressure.global_ingress_active_requests >= quotas.global_ingress_active_requests)
                mark_would_reject(p.decision, "would_reject_global_ingress_active_requests", "global_ingress_active_requests", "ingress_global", pressure.global_ingress_active_requests, quotas.global_ingress_active_requests);
            if (pressure.global_ingress_queued_requests >= quotas.global_ingress_queued_requests)
                mark_would_reject(p.decision, "would_reject_global_ingress_queued_requests", "global_ingress_queued_requests", "ingress_global", pressure.global_ingress_queued_requests, quotas.global_ingress_queued_requests);
            if (pressure.per_principal_ingress_active_requests >= quotas.per_principal_ingress_active_requests)
                mark_would_reject(p.decision, "would_reject_per_principal_ingress_active_requests", "per_principal_ingress_active_requests", "ingress_principal", pressure.per_principal_ingress_active_requests, quotas.per_principal_ingress_active_requests);
            if (pressure.per_principal_ingress_queued_requests >= quotas.per_principal_ingress_queued_requests)
                mark_would_reject(p.decision, "would_reject_per_principal_ingress_queued_requests", "per_principal_ingress_queued_requests", "ingress_principal", pressure.per_principal_ingress_queued_requests, quotas.per_principal_ingress_queued_requests);
            if (ctx.sse_stream && pressure.global_ingress_streams >= quotas.global_ingress_streams)
                mark_would_reject(p.decision, "would_reject_global_ingress_streams", "global_ingress_streams", "ingress_stream_global", pressure.global_ingress_streams, quotas.global_ingress_streams);
            if (ctx.sse_stream && pressure.per_principal_ingress_streams >= quotas.per_principal_ingress_streams)
                mark_would_reject(p.decision, "would_reject_per_principal_ingress_streams", "per_principal_ingress_streams", "ingress_stream_principal", pressure.per_principal_ingress_streams, quotas.per_principal_ingress_streams);
        }

        if (p.priority != priority_t::p0) {
            if (pressure.global_external_active_tools >= quotas.global_external_active_tools)
                mark_would_reject(p.decision, "would_reject_global_external_active_tools", "global_external_active_tools", "global", pressure.global_external_active_tools, quotas.global_external_active_tools);
            if (pressure.global_external_queued_tools >= quotas.global_external_queued_tools)
                mark_would_reject(p.decision, "would_reject_global_external_queued_tools", "global_external_queued_tools", "global", pressure.global_external_queued_tools, quotas.global_external_queued_tools);
            if (p.long_running) {
                if (pressure.per_principal_active_long_running_tools >= quotas.per_principal_active_long_running_tools)
                    mark_would_reject(p.decision, "would_reject_per_principal_active_long_running_tools", "per_principal_active_long_running_tools", "principal", pressure.per_principal_active_long_running_tools, quotas.per_principal_active_long_running_tools);
                if (pressure.per_principal_queued_long_running_tools >= quotas.per_principal_queued_long_running_tools)
                    mark_would_reject(p.decision, "would_reject_per_principal_queued_long_running_tools", "per_principal_queued_long_running_tools", "principal", pressure.per_principal_queued_long_running_tools, quotas.per_principal_queued_long_running_tools);
            } else {
                if (pressure.per_principal_active_normal_tools >= quotas.per_principal_active_normal_tools)
                    mark_would_reject(p.decision, "would_reject_per_principal_active_normal_tools", "per_principal_active_normal_tools", "principal", pressure.per_principal_active_normal_tools, quotas.per_principal_active_normal_tools);
                if (pressure.per_principal_queued_normal_tools >= quotas.per_principal_queued_normal_tools)
                    mark_would_reject(p.decision, "would_reject_per_principal_queued_normal_tools", "per_principal_queued_normal_tools", "principal", pressure.per_principal_queued_normal_tools, quotas.per_principal_queued_normal_tools);
            }
            if (p.mutating && pressure.per_session_active_mutations >= quotas.per_session_active_mutations)
                mark_would_reject(p.decision, "would_reject_per_session_active_mutations", "per_session_active_mutations", "session", pressure.per_session_active_mutations, quotas.per_session_active_mutations);
            if (p.read_only && !ctx.session_id.empty() && pressure.per_session_active_read_only_tools >= quotas.per_session_active_read_only_tools)
                mark_would_reject(p.decision, "would_reject_per_session_active_read_only_tools", "per_session_active_read_only_tools", "session", pressure.per_session_active_read_only_tools, quotas.per_session_active_read_only_tools);
            if (ctx.driver_debugger_tool && pressure.per_target_driver_debugger_active_tools >= quotas.per_target_driver_debugger_active_tools)
                mark_would_reject(p.decision, "would_reject_per_target_driver_debugger_active_tools", "per_target_driver_debugger_active_tools", "target", pressure.per_target_driver_debugger_active_tools, quotas.per_target_driver_debugger_active_tools);
            if (p.mutating && !ctx.domain.empty() && pressure.per_domain_mutating_active_tools >= quotas.per_domain_mutating_active_tools)
                mark_would_reject(p.decision, "would_reject_per_domain_mutating_active_tools", "per_domain_mutating_active_tools", "domain", pressure.per_domain_mutating_active_tools, quotas.per_domain_mutating_active_tools);
            if (ctx.batch_child || ctx.batch_size != 0) {
                const std::size_t batch_units = ctx.batch_size == 0 ? std::size_t{1} : ctx.batch_size;
                const std::size_t active_batch_observed = pressure.batch_active_children + batch_units;
                const std::size_t queued_batch_observed = pressure.batch_queued_children + batch_units;
                if (active_batch_observed > quotas.active_batch_children_per_principal)
                    mark_would_reject(p.decision, "would_reject_active_batch_children_per_principal", "active_batch_children_per_principal", "principal_batch", active_batch_observed, quotas.active_batch_children_per_principal);
                if (queued_batch_observed > quotas.queued_batch_children_per_principal)
                    mark_would_reject(p.decision, "would_reject_queued_batch_children_per_principal", "queued_batch_children_per_principal", "principal_batch", queued_batch_observed, quotas.queued_batch_children_per_principal);
            }
            if (ctx.background_command) {
                if (pressure.active_background_command_sessions_per_principal >= quotas.active_background_command_sessions_per_principal)
                    mark_would_reject(p.decision, "would_reject_active_background_command_sessions_per_principal", "active_background_command_sessions_per_principal", "principal_background_command", pressure.active_background_command_sessions_per_principal, quotas.active_background_command_sessions_per_principal);
                if (pressure.global_active_background_command_sessions >= quotas.global_active_background_command_sessions)
                    mark_would_reject(p.decision, "would_reject_global_active_background_command_sessions", "global_active_background_command_sessions", "global_background_command", pressure.global_active_background_command_sessions, quotas.global_active_background_command_sessions);
            }
        }
        if (!p.decision.would_accept && p.decision.limit == 0)
            p.decision.limit = 0;
        return p;
    }

    inline json pressure_json(const pressure_snapshot_t& p)
    {
        return {
            {"tool_workers", p.tool_workers},
            {"tool_queue_limit", p.tool_queue_limit},
            {"batch_workers", p.batch_workers},
            {"batch_queue_limit", p.batch_queue_limit},
            {"active_http_requests", p.active_http_requests},
            {"active_streams", p.active_streams},
            {"global_ingress_active_requests", p.global_ingress_active_requests},
            {"global_ingress_queued_requests", p.global_ingress_queued_requests},
            {"per_principal_ingress_active_requests", p.per_principal_ingress_active_requests},
            {"per_principal_ingress_queued_requests", p.per_principal_ingress_queued_requests},
            {"global_ingress_streams", p.global_ingress_streams},
            {"per_principal_ingress_streams", p.per_principal_ingress_streams},
            {"global_external_active_tools", p.global_external_active_tools},
            {"global_external_queued_tools", p.global_external_queued_tools},
            {"batch_active_children", p.batch_active_children},
            {"batch_queued_children", p.batch_queued_children},
            {"per_principal_active_normal_tools", p.per_principal_active_normal_tools},
            {"per_principal_active_long_running_tools", p.per_principal_active_long_running_tools},
            {"per_principal_queued_normal_tools", p.per_principal_queued_normal_tools},
            {"per_principal_queued_long_running_tools", p.per_principal_queued_long_running_tools},
            {"per_session_active_mutations", p.per_session_active_mutations},
            {"per_session_active_read_only_tools", p.per_session_active_read_only_tools},
            {"per_target_driver_debugger_active_tools", p.per_target_driver_debugger_active_tools},
            {"per_domain_mutating_active_tools", p.per_domain_mutating_active_tools},
            {"active_background_command_sessions_per_principal", p.active_background_command_sessions_per_principal},
            {"global_active_background_command_sessions", p.global_active_background_command_sessions},
            {"background_command_sessions_total", p.background_command_sessions_total},
            {"background_command_sessions_running", p.background_command_sessions_running},
            {"background_command_sessions_reader_active", p.background_command_sessions_reader_active},
            {"background_command_sessions_timed_out", p.background_command_sessions_timed_out},
            {"background_command_oldest_running_ms", p.background_command_oldest_running_ms},
            {"downstream_general_pending", p.downstream_general_pending},
            {"downstream_general_active", p.downstream_general_active},
            {"downstream_service_pending", p.downstream_service_pending},
            {"downstream_service_active", p.downstream_service_active},
            {"downstream_critical_pending", p.downstream_critical_pending},
            {"downstream_critical_active", p.downstream_critical_active}
        };
    }

    inline json prediction_json(const prediction_t& p)
    {
        return {
            {"diagnostic_id", p.context.diagnostic_id},
            {"request_id", p.context.request_id},
            {"transport", p.context.transport},
            {"route", p.context.route},
            {"method", p.context.method},
            {"principal_id", p.context.principal_id},
            {"session_id", p.context.session_id},
            {"target_id", p.context.target_id},
            {"tool", p.context.tool_name},
            {"domain", p.context.domain},
            {"lane", p.lane},
            {"action", p.context.action},
            {"priority", p.priority_name},
            {"cost_units", p.cost_units},
            {"long_running", p.long_running},
            {"classification", p.classification},
            {"read_only", p.read_only},
            {"mutating", p.mutating},
            {"session_manager", p.session_manager},
            {"browser_tool", p.context.browser_tool},
            {"driver_debugger_tool", p.context.driver_debugger_tool},
            {"scanner_tool", p.context.scanner_tool},
            {"decompiler_tool", p.context.decompiler_tool},
            {"network_tool", p.context.network_tool},
            {"background_command", p.context.background_command},
            {"batch_child", p.context.batch_child},
            {"http_ingress", p.context.http_ingress},
            {"sse_stream", p.context.sse_stream},
            {"reserved_lane", p.context.reserved_lane},
            {"batch_size", p.context.batch_size},
            {"batch_index", p.context.batch_index},
            {"target_pid", p.context.target_pid},
            {"requested_timeout_ms", p.context.requested_timeout_ms},
            {"effective_timeout_ms", p.context.effective_timeout_ms},
            {"payload_shape", p.context.payload_shape},
            {"would_accept", p.decision.would_accept},
            {"would_reject", !p.decision.would_accept},
            {"decision_reason", p.decision.reason},
            {"decision_quota", p.decision.quota_name},
            {"decision_scope", p.decision.quota_scope},
            {"decision_observed", p.decision.observed},
            {"decision_limit", p.decision.limit},
            {"diagnostics_only", p.diagnostics_only},
            {"enforcement_enabled", p.enforcement_enabled},
            {"pressure", pressure_json(p.pressure)}
        };
    }

    inline std::mutex& registry_mutex()
    {
        static std::mutex m;
        return m;
    }

    inline std::map<std::uint64_t, record_t>& active_records()
    {
        static std::map<std::uint64_t, record_t> records;
        return records;
    }

    inline std::atomic<std::uint64_t>& next_record_id()
    {
        static std::atomic<std::uint64_t> value{0};
        return value;
    }

    inline std::atomic<std::uint64_t>& observed_predictions()
    {
        static std::atomic<std::uint64_t> value{0};
        return value;
    }

    inline std::atomic<std::uint64_t>& would_accept_predictions()
    {
        static std::atomic<std::uint64_t> value{0};
        return value;
    }

    inline std::atomic<std::uint64_t>& would_reject_predictions()
    {
        static std::atomic<std::uint64_t> value{0};
        return value;
    }

    inline std::vector<json>& recent_predictions()
    {
        static std::vector<json> items;
        return items;
    }

    inline record_t record_from_prediction(const prediction_t& p, std::uint64_t started_ms)
    {
        record_t r;
        r.id = next_record_id().fetch_add(1u, std::memory_order_acq_rel) + 1u;
        r.diagnostic_id = clean_label(p.context.diagnostic_id);
        r.principal_id = clean_label(p.context.principal_id);
        r.session_id = clean_label(p.context.session_id);
        r.target_id = clean_label(p.context.target_id);
        r.domain = clean_label(p.context.domain);
        r.lane = clean_label(p.lane);
        r.tool_name = clean_label(p.context.tool_name);
        r.priority_name = p.priority_name;
        r.classification = p.classification;
        r.long_running = p.long_running;
        r.mutating = p.mutating;
        r.read_only = p.read_only;
        r.session_manager = p.session_manager;
        r.driver_debugger_tool = p.context.driver_debugger_tool;
        r.browser_tool = p.context.browser_tool;
        r.scanner_tool = p.context.scanner_tool;
        r.decompiler_tool = p.context.decompiler_tool;
        r.network_tool = p.context.network_tool;
        r.background_command = p.context.background_command;
        r.batch_child = p.context.batch_child;
        r.started_ms = started_ms;
        return r;
    }

    inline void remember_prediction(const prediction_t& p)
    {
        observed_predictions().fetch_add(1u, std::memory_order_acq_rel);
        if (p.decision.would_accept)
            would_accept_predictions().fetch_add(1u, std::memory_order_acq_rel);
        else
            would_reject_predictions().fetch_add(1u, std::memory_order_acq_rel);
        std::unique_lock<std::mutex> lk(registry_mutex(), std::try_to_lock);
        if (!lk.owns_lock())
            return;
        auto item = prediction_json(p);
        item.erase("pressure");
        recent_predictions().push_back(std::move(item));
        if (recent_predictions().size() > 32)
            recent_predictions().erase(recent_predictions().begin(), recent_predictions().begin() + static_cast<std::ptrdiff_t>(recent_predictions().size() - 32));
    }

    class scoped_activity_t
    {
    public:
        scoped_activity_t() = default;
        scoped_activity_t(const prediction_t& prediction, std::uint64_t started_ms)
        {
            record_ = record_from_prediction(prediction, started_ms);
            active_ = true;
            std::lock_guard<std::mutex> lk(registry_mutex());
            active_records()[record_.id] = record_;
        }

        scoped_activity_t(const scoped_activity_t&) = delete;
        scoped_activity_t& operator=(const scoped_activity_t&) = delete;

        scoped_activity_t(scoped_activity_t&& other) noexcept
        {
            move_from(other);
        }

        scoped_activity_t& operator=(scoped_activity_t&& other) noexcept
        {
            if (this != &other) {
                release();
                move_from(other);
            }
            return *this;
        }

        ~scoped_activity_t()
        {
            release();
        }

        void release()
        {
            if (!active_)
                return;
            std::lock_guard<std::mutex> lk(registry_mutex());
            active_records().erase(record_.id);
            active_ = false;
        }

    private:
        void move_from(scoped_activity_t& other) noexcept
        {
            record_ = other.record_;
            active_ = other.active_;
            other.active_ = false;
        }

        record_t record_;
        bool active_ = false;
    };

    inline activity_counters_t counters_for_context(const request_context_t& ctx)
    {
        activity_counters_t counters;
        std::unique_lock<std::mutex> lk(registry_mutex(), std::try_to_lock);
        if (!lk.owns_lock()) {
            counters.registry_lock_busy = true;
            return counters;
        }
        for (const auto& pair : active_records()) {
            const auto& r = pair.second;
            ++counters.active_total;
            if (!ctx.principal_id.empty() && r.principal_id != ctx.principal_id)
                continue;
            if (r.long_running)
                ++counters.active_long_running;
            else
                ++counters.active_normal;
            if (r.batch_child)
                ++counters.active_batch_children;
            if (r.background_command)
                ++counters.active_background_command_sessions;
            if (r.mutating && (ctx.session_id.empty() || r.session_id == ctx.session_id))
                ++counters.active_session_mutations;
            if (r.read_only && !ctx.session_id.empty() && r.session_id == ctx.session_id)
                ++counters.active_session_read_only;
            if (r.driver_debugger_tool && !ctx.target_id.empty() && r.target_id == ctx.target_id)
                ++counters.active_target_driver_debugger;
            if (r.mutating && !ctx.domain.empty() && r.domain == ctx.domain)
                ++counters.active_domain_mutating;
        }
        return counters;
    }

    inline json activity_snapshot_json(std::uint64_t now_ms)
    {
        json active = json::array();
        std::size_t total = 0;
        std::size_t long_running = 0;
        std::size_t mutating = 0;
        std::size_t session_manager = 0;
        std::size_t background = 0;
        std::size_t browser = 0;
        std::size_t scanner = 0;
        std::size_t decompiler = 0;
        std::size_t network = 0;
        std::size_t batch = 0;
        bool registry_lock_busy = false;
        {
            std::unique_lock<std::mutex> lk(registry_mutex(), std::try_to_lock);
            if (!lk.owns_lock()) {
                registry_lock_busy = true;
            } else {
                for (const auto& pair : active_records()) {
                    const auto& r = pair.second;
                    ++total;
                    if (r.long_running)
                        ++long_running;
                    if (r.mutating)
                        ++mutating;
                    if (r.session_manager)
                        ++session_manager;
                    if (r.background_command)
                        ++background;
                    if (r.browser_tool)
                        ++browser;
                    if (r.scanner_tool)
                        ++scanner;
                    if (r.decompiler_tool)
                        ++decompiler;
                    if (r.network_tool)
                        ++network;
                    if (r.batch_child)
                        ++batch;
                    if (active.size() < 16) {
                        active.push_back({
                            {"id", r.id},
                            {"diagnostic_id", r.diagnostic_id},
                            {"principal_id", r.principal_id},
                            {"session_id", r.session_id},
                            {"target_id", r.target_id},
                            {"tool", r.tool_name},
                            {"domain", r.domain},
                            {"lane", r.lane},
                            {"priority", r.priority_name},
                            {"classification", r.classification},
                            {"long_running", r.long_running},
                            {"mutating", r.mutating},
                            {"read_only", r.read_only},
                            {"session_manager", r.session_manager},
                            {"driver_debugger_tool", r.driver_debugger_tool},
                            {"browser_tool", r.browser_tool},
                            {"scanner_tool", r.scanner_tool},
                            {"decompiler_tool", r.decompiler_tool},
                            {"network_tool", r.network_tool},
                            {"background_command", r.background_command},
                            {"batch_child", r.batch_child},
                            {"age_ms", now_ms >= r.started_ms ? now_ms - r.started_ms : 0}
                        });
                    }
                }
            }
        }
        return {
            {"registry_lock_busy", registry_lock_busy},
            {"active_total", total},
            {"active_long_running", long_running},
            {"active_mutating", mutating},
            {"active_session_manager", session_manager},
            {"active_background_command", background},
            {"active_browser", browser},
            {"active_scanner", scanner},
            {"active_decompiler", decompiler},
            {"active_network", network},
            {"active_batch_children", batch},
            {"observed_predictions", observed_predictions().load(std::memory_order_acquire)},
            {"would_accept_predictions", would_accept_predictions().load(std::memory_order_acquire)},
            {"would_reject_predictions", would_reject_predictions().load(std::memory_order_acquire)},
            {"active_records", std::move(active)}
        };
    }

    inline json recent_snapshot_json()
    {
        json out = json::array();
        std::unique_lock<std::mutex> lk(registry_mutex(), std::try_to_lock);
        if (!lk.owns_lock())
            return out;
        for (const auto& item : recent_predictions())
            out.push_back(item);
        return out;
    }
}
}
