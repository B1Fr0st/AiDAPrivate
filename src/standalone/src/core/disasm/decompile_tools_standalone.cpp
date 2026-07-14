#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "standalone_compat.hpp"
#include "../analysis/decompiler/decompiler_ui_integration.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <limits>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace decompile_tools {

class cancellation_bridge_t final {
public:
    cancellation_bridge_t(aida::analysis::cancellation_source_t& source,
                          std::atomic<bool>* external)
        : source_(source), external_(external)
    {
        if (external_)
            worker_ = std::thread([this] { monitor(); });
    }

    cancellation_bridge_t(const cancellation_bridge_t&) = delete;
    cancellation_bridge_t& operator=(const cancellation_bridge_t&) = delete;

    ~cancellation_bridge_t()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        wake_.notify_all();
        if (worker_.joinable())
            worker_.join();
    }

private:
    void monitor()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!stopping_) {
            lock.unlock();
            if (external_->load(std::memory_order_acquire)) {
                source_.request_cancel();
                return;
            }
            lock.lock();
            wake_.wait_for(lock, std::chrono::milliseconds(10), [this] { return stopping_; });
        }
    }

    aida::analysis::cancellation_source_t& source_;
    std::atomic<bool>* external_ = nullptr;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_ = false;
    std::thread worker_;
};

static std::string hex_u64(uint64_t value)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

static bool parse_address_param(const json& params, const char* key, uint64_t& out)
{
    if (!params.contains(key))
        return false;
    const auto& v = params[key];
    if (v.is_string()) {
        auto parsed = sa_parse_address(v.get<std::string>());
        if (!parsed) return false;
        out = *parsed;
        return true;
    }
    if (v.is_number_unsigned()) { out = v.get<uint64_t>(); return true; }
    if (v.is_number_integer()) {
        int64_t s = v.get<int64_t>();
        if (s < 0) return false;
        out = static_cast<uint64_t>(s);
        return true;
    }
    return false;
}

static std::string pipeline_status_code(
    const aida::analysis::decompiler_pipeline_status_t status)
{
    using status_t = aida::analysis::decompiler_pipeline_status_t;
    switch (status) {
    case status_t::invalid_request: return "DECOMPILER_INVALID_REQUEST";
    case status_t::explicit_request_required: return "DECOMPILER_EXPLICIT_REQUEST_REQUIRED";
    case status_t::provider_unavailable: return "DECOMPILER_PROVIDER_UNAVAILABLE";
    case status_t::provider_failed: return "DECOMPILER_PROVIDER_FAILED";
    case status_t::provider_crashed: return "DECOMPILER_PROVIDER_CRASHED";
    case status_t::deadline_exceeded: return "DECOMPILER_DEADLINE_EXCEEDED";
    case status_t::cancelled: return "DECOMPILER_CANCELLED";
    case status_t::resource_limit: return "DECOMPILER_RESOURCE_LIMIT";
    case status_t::stale_generation: return "DECOMPILER_STALE_GENERATION";
    case status_t::normalization_failed: return "DECOMPILER_NORMALIZATION_FAILED";
    case status_t::rendering_failed: return "DECOMPILER_RENDERING_FAILED";
    case status_t::cache_integrity_failure: return "DECOMPILER_CACHE_INTEGRITY_FAILURE";
    case status_t::service_stopped: return "DECOMPILER_SERVICE_STOPPED";
    case status_t::completed: return "DECOMPILER_COMPLETED";
    }
    return "DECOMPILER_FAILED";
}

static json collect_callees(
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace,
    const aida::analysis::decompiler_document_t& document)
{
    json callees = json::array();
    const auto* identity = std::get_if<aida::analysis::native_decompiler_entity_identity_t>(
        &document.entity.identity);
    const auto publication = workspace ? workspace->analysis_publication() : nullptr;
    if (!identity || !publication || !publication->snapshot)
        return callees;
    const auto& snapshot = *publication->snapshot;
    for (const auto& edge : snapshot.call_graph.edges) {
        if (edge.source_function_id != identity->function_id)
            continue;
        std::string name = "callee_" + std::to_string(edge.id);
        if (edge.target_function_id) {
            const auto target = std::find_if(snapshot.functions.begin(), snapshot.functions.end(),
                [&](const auto& function) { return function.id == *edge.target_function_id; });
            if (target != snapshot.functions.end() && target->symbol_id) {
                const auto symbol = std::find_if(snapshot.symbols.begin(), snapshot.symbols.end(),
                    [&](const auto& current) { return current.id == *target->symbol_id; });
                if (symbol != snapshot.symbols.end() && !symbol->name.empty())
                    name = symbol->name;
            }
        }
        auto address = edge.target.value;
        if (edge.target.space == aida::analysis::address_space_id_t::relative_virtual &&
            snapshot.normalized_image &&
            address <= (std::numeric_limits<std::uint64_t>::max)() -
                snapshot.normalized_image->image_base)
            address += snapshot.normalized_image->image_base;
        callees.push_back(json{{"name", std::move(name)}, {"address", hex_u64(address)},
            {"external", edge.external_target},
            {"noreturn", edge.target_noreturn},
            {"confidence", edge.quality.confidence}});
    }
    return callees;
}

static tool_result_t handle_decompile_function(
    const json& params,
    const std::shared_ptr<aida::analysis::analysis_workspace_t>& workspace)
{
    mcp_standalone::downstream::producer_identity_t identity;
    identity.kind = mcp_standalone::downstream::producer_kind_t::decompiler;
    identity.tool_name = "decompile_function";
    auto admission = mcp_standalone::downstream::scoped_admission_t::acquire(identity);
    if (!admission.active()) {
        return tool_result_t::error(
            "Decompiler capacity exhausted; work was not started.",
            "MCP_DOWNSTREAM_CAPACITY_REJECT",
            json{{"producer", "decompiler"}, {"work_started", false}});
    }

    std::uint64_t raw_address = 0;
    if (!parse_address_param(params, "address", raw_address))
        return tool_result_t::error("'address' is required (hex string or integer).");
    int timeout_sec = 30;
    if (params.contains("timeout_sec") && params["timeout_sec"].is_number_integer()) {
        const int requested = params["timeout_sec"].get<int>();
        if (requested >= 1 && requested <= 300)
            timeout_sec = requested;
    }
    if (!workspace)
        return tool_result_t::error("Target workspace is unavailable", "TARGET_NOT_FOUND", json::object());
    auto integration = aida::analysis::decompiler_ui_integration_t::production_for_workspace(
        workspace);
    if (!integration)
        return tool_result_t::error(
            integration.error().message.empty()
                ? "The typed decompiler service is unavailable"
                : integration.error().message,
            "DECOMPILER_UNAVAILABLE",
            json{{"phase", integration.error().phase},
                 {"readiness", static_cast<unsigned>(workspace->progress().readiness)}});

    aida::analysis::cancellation_source_t cancellation(
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec));
    if (mcp_standalone::current_call_cancelled())
        cancellation.request_cancel();
    std::unique_ptr<cancellation_bridge_t> cancellation_bridge;
    try {
        cancellation_bridge = std::make_unique<cancellation_bridge_t>(
            cancellation, mcp_standalone::current_cancel_token());
    } catch (const std::system_error& error) {
        return tool_result_t::error(
            "Unable to establish bounded MCP cancellation monitoring",
            "CANCELLATION_BRIDGE_UNAVAILABLE",
            json{{"native_error", error.code().value()}});
    }
    auto decompiled = integration.value()->decompile_native(
        raw_address,
        aida::analysis::decompiler_ui_invocation_source_t::mcp_request,
        aida::analysis::decompiler_profile_id_t::balanced,
        aida::analysis::decompiler_pipeline_cache_mode_t::read_write,
        cancellation.token());
    if (!decompiled) {
        const auto& error = decompiled.error();
        return tool_result_t::error(
            error.message.empty() ? std::string("Decompilation failed") : error.message,
            error.stable_code(),
            json{{"phase", error.phase},
                 {"cancelled", error.cancellation},
                 {"deadline", error.deadline}});
    }

    const auto& result_value = decompiled.value();
    if (!result_value.succeeded()) {
        json diagnostics = json::array();
        for (const auto& diagnostic : result_value.diagnostics) {
            diagnostics.push_back(json{
                {"code", static_cast<unsigned>(diagnostic.code)},
                {"key", diagnostic.localization_key},
                {"message", diagnostic.message},
                {"confidence", diagnostic.confidence},
                {"retryable", diagnostic.retryable}});
        }
        return tool_result_t::error(
            result_value.diagnostics.empty() || result_value.diagnostics.front().message.empty()
                ? "Typed decompilation failed"
                : result_value.diagnostics.front().message,
            pipeline_status_code(result_value.status),
            json{{"address", hex_u64(raw_address)}, {"diagnostics", std::move(diagnostics)}});
    }
    if (result_value.rendered_text.find_first_not_of(" \t\r\n") == std::string::npos)
        return tool_result_t::error(
            "Decompilation produced no pseudocode",
            "DECOMPILER_EMPTY_RESULT",
            json{{"address", hex_u64(raw_address)}});

    json result;
    result["address"] = hex_u64(raw_address);
    result["function_name"] = result_value.function_symbol;
    result["sleigh_id"] = result_value.language_id;
    result["complete"] = true;
    result["elapsed_ms"] = result_value.elapsed_ms;
    result["pseudocode"] = result_value.rendered_text;
    result["cache_hit"] = result_value.cache_hit_stage.has_value();
    result["cache_stage"] = result_value.cache_hit_stage
        ? static_cast<unsigned>(*result_value.cache_hit_stage) : 0U;
    result["persistent_cache_hit"] = false;
    result["generation"] = result_value.workspace_generation;
    result["analysis_revision"] = result_value.analysis_revision;
    result["overlay_revision"] = result_value.overlay_revision;
    if (result_value.provider) {
        result["provider"] = json{{"id", result_value.provider->registration_id},
            {"name", result_value.provider->identity.provider_name},
            {"version", result_value.provider->identity.provider_version},
            {"isolated", result_value.provider->isolated}};
    }
    result["callees"] = collect_callees(workspace, *result_value.document);
    result["mapped_line_count"] = result_value.source_mappings.size();
    std::size_t line_count = 0;
    for (char ch : result_value.rendered_text)
        line_count += ch == '\n' ? 1U : 0U;
    if (!result_value.rendered_text.empty() && result_value.rendered_text.back() != '\n')
        ++line_count;
    result["pseudocode_line_count"] = line_count;
    result["line_count"] = result_value.source_mappings.empty()
        ? line_count : result_value.source_mappings.size();
    if (result_value.readability) {
        result["readability"] = json{
            {"ast_nodes", result_value.readability->ast_node_count},
            {"source_map_coverage", result_value.readability->source_map_coverage_ratio},
            {"mean_confidence", result_value.readability->mean_confidence},
            {"minimum_confidence", result_value.readability->minimum_confidence},
            {"explicit_unknown_ratio", result_value.readability->explicit_unknown_ratio},
            {"max_expression_depth", result_value.readability->metrics.max_expression_depth},
            {"max_control_nesting", result_value.readability->metrics.max_control_nesting}};
    }
    admission.release("completed");
    return tool_result_t::ok(result);
}

void register_decompile_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "decompile_function",
        "Decompile a function through the isolated typed provider pipeline and return pseudocode, exact source mappings, readability evidence, and recovered callees. Runs with a configurable timeout (default 30s).",
        {{"address", "string", "Function entry address (hex string or integer)", true},
         {"timeout_sec", "number", "Maximum seconds to wait for decompilation (1-300, default 30)", false}},
        true,
        {}},
        handle_decompile_function);
}

}
