#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "standalone_compat.hpp"
#include "ghidra_decompiler.hpp"
#include "function_index.hpp"
#include "rename_store.hpp"
#include "work_queue.hpp"
#include "../helpers/diag_log.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace decompile_tools {

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

static tool_result_t handle_decompile_function(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("decomp_tools", "decompile_function_bad_params");
        return tool_result_t::error("'address' is required (hex string or integer).");
    }

    int timeout_sec = 30;
    if (params.contains("timeout_sec") && params["timeout_sec"].is_number_integer()) {
        int v = params["timeout_sec"].get<int>();
        if (v >= 1 && v <= 300) timeout_sec = v;
    }
    diag::log_tagged_fmt("decomp_tools", "decompile_function_enter addr=0x%llX timeout_sec=%d",
        static_cast<unsigned long long>(addr), timeout_sec);

    struct slot_t {
        std::mutex                              mtx;
        bool                                    done = false;
        ghidra_decompiler::ghidra_result_t      result;
        std::atomic<bool>                       cancel{false};
    };
    auto slot = std::make_shared<slot_t>();

    bool posted = work_queue::post([slot, addr]() {
        diag::log_tagged_fmt("decomp_tools", "decompile_function_work_start addr=0x%llX",
            static_cast<unsigned long long>(addr));
        ghidra_decompiler::ghidra_result_t r =
            ghidra_decompiler::decompile_function(addr, &slot->cancel);
        diag::log_tagged_fmt("decomp_tools", "decompile_function_work_done addr=0x%llX is_error=%d elapsed_ms=%lld",
            static_cast<unsigned long long>(addr), r.is_error ? 1 : 0,
            static_cast<long long>(r.elapsed_ms));
        std::lock_guard<std::mutex> lk(slot->mtx);
        slot->result = std::move(r);
        slot->done = true;
    });
    if (!posted) {
        diag::log_tagged_fmt("decomp_tools", "decompile_function_post_failed addr=0x%llX",
            static_cast<unsigned long long>(addr));
        slot->cancel.store(true);
        return tool_result_t::error("Failed to schedule decompilation work item.");
    }
    diag::log_tagged_fmt("decomp_tools", "decompile_function_posted addr=0x%llX waiting_timeout=%d",
        static_cast<unsigned long long>(addr), timeout_sec);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lk(slot->mtx);
            if (slot->done) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    {
        std::lock_guard<std::mutex> lk(slot->mtx);
        if (!slot->done) {
            slot->cancel.store(true);
            diag::log_tagged_fmt("decomp_tools", "decompile_function_timeout addr=0x%llX timeout_sec=%d",
                static_cast<unsigned long long>(addr), timeout_sec);
            return tool_result_t::error("Decompilation timed out after " +
                                       std::to_string(timeout_sec) + " seconds.");
        }
        const auto& r = slot->result;
        if (r.is_error) {
            diag::log_tagged_fmt("decomp_tools", "decompile_function_error addr=0x%llX error=%s",
                static_cast<unsigned long long>(addr), r.error_text.c_str());
            return tool_result_t::error(r.error_text.empty()
                                        ? std::string("Decompilation failed.")
                                        : r.error_text);
        }
        diag::log_tagged_fmt("decomp_tools",
            "decompile_function_success addr=0x%llX func=%s sleigh=%s elapsed_ms=%lld lines=%zu callees=%zu pseudocode_bytes=%zu",
            static_cast<unsigned long long>(r.function_addr),
            r.function_name.c_str(), r.sleigh_id.c_str(),
            static_cast<long long>(r.elapsed_ms),
            r.line_to_address.size(), r.callees.size(), r.pseudocode.size());
        json result;
        result["address"]      = hex_u64(r.function_addr);
        result["function_name"]= r.function_name.empty()
                                 ? function_index::synthetic_name(r.function_addr)
                                 : r.function_name;
        result["sleigh_id"]    = r.sleigh_id;
        result["complete"]     = r.complete;
        result["elapsed_ms"]   = r.elapsed_ms;
        result["pseudocode"]   = r.pseudocode;

        json callees = json::array();
        for (const auto& c : r.callees) {
            json o;
            o["name"]    = c.first;
            o["address"] = hex_u64(c.second);
            callees.push_back(std::move(o));
        }
        result["callees"] = std::move(callees);
        result["line_count"] = r.line_to_address.size();
        return tool_result_t::ok(result);
    }
}

void register_decompile_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "decompile_function",
        "Decompile a function at the given address using the Ghidra-derived decompiler and return the pseudocode text plus callee list. Runs on a worker thread with a configurable timeout (default 30s).",
        {{"address", "string", "Function entry address (hex string or integer)", true},
         {"timeout_sec", "number", "Maximum seconds to wait for decompilation (1-300, default 30)", false}},
        true, handle_decompile_function});
}

}
