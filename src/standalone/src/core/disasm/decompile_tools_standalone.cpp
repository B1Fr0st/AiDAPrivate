#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "standalone_compat.hpp"
#include "../analysis/workspace/decompiler_service.hpp"
#include "../mcp/downstream_producer_governor.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <memory>
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
    auto service = workspace->decompiler();
    if (!service)
        return tool_result_t::error(
            "The workspace decompiler service is unavailable",
            "DECOMPILER_UNAVAILABLE",
            json{{"readiness", static_cast<unsigned>(workspace->progress().readiness)}});

    aida::analysis::address_t address;
    address.space = workspace->target_kind() == aida::analysis::target_kind_t::live_snapshot
        ? aida::analysis::address_space_id_t::live_virtual
        : aida::analysis::address_space_id_t::virtual_address;
    address.value = raw_address;
    address.architecture = workspace->identity().architecture();
    if (const auto image = workspace->image()) {
        address.mode = image->architecture_mode();
        if (workspace->target_kind() == aida::analysis::target_kind_t::static_file &&
            raw_address < image->image_base() && raw_address < image->image_size())
            address.value = image->image_base() + raw_address;
    }

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
    auto decompiled = service->decompile(address, {}, cancellation.token());
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
    if (result_value.pseudocode.find_first_not_of(" \t\r\n") == std::string::npos)
        return tool_result_t::error(
            "Decompilation produced no pseudocode",
            "DECOMPILER_EMPTY_RESULT",
            json{{"address", hex_u64(result_value.function_address.value)}});

    json result;
    result["address"] = hex_u64(result_value.function_address.value);
    result["function_name"] = result_value.function_name;
    result["sleigh_id"] = result_value.sleigh_id;
    result["complete"] = true;
    result["elapsed_ms"] = result_value.elapsed_ms;
    result["pseudocode"] = result_value.pseudocode;
    result["cache_hit"] = result_value.cache_hit;
    result["persistent_cache_hit"] = result_value.persistent_cache_hit;
    result["generation"] = result_value.generation;
    result["analysis_revision"] = result_value.analysis_revision;
    result["overlay_revision"] = result_value.overlay_revision;
    json callees = json::array();
    for (const auto& callee : result_value.callees)
        callees.push_back(json{{"name", callee.first}, {"address", hex_u64(callee.second)}});
    result["callees"] = std::move(callees);
    result["mapped_line_count"] = result_value.line_to_address.size();
    std::size_t line_count = 0;
    for (char ch : result_value.pseudocode)
        line_count += ch == '\n' ? 1U : 0U;
    if (!result_value.pseudocode.empty() && result_value.pseudocode.back() != '\n')
        ++line_count;
    result["pseudocode_line_count"] = line_count;
    result["line_count"] = result_value.line_to_address.empty()
        ? line_count
        : result_value.line_to_address.size();
    admission.release("completed");
    return tool_result_t::ok(result);
}

void register_decompile_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "decompile_function",
        "Decompile a function at the given address using the Ghidra-derived decompiler and return the pseudocode text plus callee list. Runs on a worker thread with a configurable timeout (default 30s).",
        {{"address", "string", "Function entry address (hex string or integer)", true},
         {"timeout_sec", "number", "Maximum seconds to wait for decompilation (1-300, default 30)", false}},
        true,
        {}},
        handle_decompile_function);
}

}
