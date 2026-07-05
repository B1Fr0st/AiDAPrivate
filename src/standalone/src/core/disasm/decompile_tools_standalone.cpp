#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "standalone_compat.hpp"
#include "ghidra_decompiler.hpp"
#include "function_index.hpp"
#include "rename_store.hpp"
#include "work_queue.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../infra/executor.hpp"
#include "../helpers/diag_log.hpp"
#include "../mcp/downstream_producer_governor.hpp"

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
    mcp_standalone::downstream::producer_identity_t dec_id;
    dec_id.kind = mcp_standalone::downstream::producer_kind_t::decompiler;
    dec_id.tool_name = "decompile_function";
    mcp_standalone::downstream::scoped_admission_t dec_admission =
        mcp_standalone::downstream::scoped_admission_t::acquire(dec_id);
    if (!dec_admission.active()) {
        auto rej = mcp_standalone::downstream::governor_t::instance().try_admit(dec_id);
        diag::log_tagged_fmt("decomp_tools",
            "FEATURE-WORKER-GROUP-REJECT decompile_function reason=%s quota=%s observed=%zu limit=%zu",
            rej.reason.c_str(), rej.quota_name.c_str(), rej.observed, rej.limit);
        return tool_result_t::error(
            "Decompiler capacity exhausted; work was not started.",
            "MCP_DOWNSTREAM_CAPACITY_REJECT",
            mcp_standalone::downstream::rejection_json(rej, dec_id));
    }
    diag::log_tagged_fmt("decomp_tools",
        "FEATURE-WORKER-GROUP-ADMIT decompile_function token=%llu",
        static_cast<unsigned long long>(dec_admission.token()));

    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("decomp_tools", "decompile_function_bad_params");
        if (dec_admission.active()) {
            diag::log_tagged_fmt("decomp_tools",
                "FEATURE-WORKER-GROUP-RELEASE decompile_function token=%llu reason=completed",
                static_cast<unsigned long long>(dec_admission.token()));
            dec_admission.release("completed");
        }
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
        std::atomic<bool>                       claimed{false};
        std::atomic<bool>                       started{false};
    };
    auto slot = std::make_shared<slot_t>();

    auto run_decompile = [slot, addr]() {
        if (slot->claimed.exchange(true, std::memory_order_acq_rel))
            return;
        slot->started.store(true, std::memory_order_release);
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
    };
    bool posted = false;
    {
        aida::executor::submission_t _exec_sub;
        _exec_sub.owner_subsystem = "standalone.decompiler.tools";
        _exec_sub.label = "decompile_tools.post";
        _exec_sub.thread_class = "queued_task";
        _exec_sub.domain = aida::executor::domain_t::general;
        _exec_sub.priority = 3;
        _exec_sub.body = run_decompile;
        _exec_sub.failure_policy = "reject_not_started";
        _exec_sub.ui_access_policy = "none";
        _exec_sub.shutdown_policy = "drain";
        _exec_sub.no_capacity_reason = "no_capacity_needed_general_queue";
        auto _exec_result = aida::executor::submit(std::move(_exec_sub));
        posted = _exec_result.submitted;
        (void)_exec_result;
    }
    if (!posted) {
        diag::log_tagged_fmt("decomp_tools", "decompile_function_post_failed_running_inline addr=0x%llX",
            static_cast<unsigned long long>(addr));
        run_decompile();
    }
    diag::log_tagged_fmt("decomp_tools", "decompile_function_posted addr=0x%llX waiting_timeout=%d",
        static_cast<unsigned long long>(addr), timeout_sec);

    if (posted) {
        auto start_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
        while (!slot->started.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < start_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!slot->started.load(std::memory_order_acquire)) {
            diag::log_tagged_fmt("decomp_tools", "decompile_function_queue_stalled_inline addr=0x%llX",
                static_cast<unsigned long long>(addr));
            run_decompile();
        }
    }

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
            if (dec_admission.active()) {
                diag::log_tagged_fmt("decomp_tools",
                    "FEATURE-WORKER-GROUP-RELEASE decompile_function token=%llu reason=completed",
                    static_cast<unsigned long long>(dec_admission.token()));
                dec_admission.release("completed");
            }
            return tool_result_t::error("Decompilation timed out after " +
                                       std::to_string(timeout_sec) + " seconds.");
        }
        const auto& r = slot->result;
        if (r.is_error) {
            diag::log_tagged_fmt("decomp_tools", "decompile_function_error addr=0x%llX error=%s",
                static_cast<unsigned long long>(addr), r.error_text.c_str());
            if (dec_admission.active()) {
                diag::log_tagged_fmt("decomp_tools",
                    "FEATURE-WORKER-GROUP-RELEASE decompile_function token=%llu reason=completed",
                    static_cast<unsigned long long>(dec_admission.token()));
                dec_admission.release("completed");
            }
            return tool_result_t::error(r.error_text.empty()
                                        ? std::string("Decompilation failed.")
                                        : r.error_text);
        }
        if (r.pseudocode.find_first_not_of(" \t\r\n") == std::string::npos) {
            diag::log_tagged_fmt("decomp_tools", "decompile_function_empty_pseudocode addr=0x%llX func=%s elapsed_ms=%lld",
                static_cast<unsigned long long>(r.function_addr),
                r.function_name.c_str(),
                static_cast<long long>(r.elapsed_ms));
            if (dec_admission.active()) {
                diag::log_tagged_fmt("decomp_tools",
                    "FEATURE-WORKER-GROUP-RELEASE decompile_function token=%llu reason=completed",
                    static_cast<unsigned long long>(dec_admission.token()));
                dec_admission.release("completed");
            }
            return tool_result_t::error("Decompilation produced no pseudocode.");
        }
        const size_t mapped_line_count = r.line_to_address.size();
        size_t pseudocode_line_count = 0;
        for (char ch : r.pseudocode) {
            if (ch == '\n')
                ++pseudocode_line_count;
        }
        if (!r.pseudocode.empty() && r.pseudocode.back() != '\n')
            ++pseudocode_line_count;
        const size_t reported_line_count = mapped_line_count != 0 ? mapped_line_count : pseudocode_line_count;
        diag::log_tagged_fmt("decomp_tools",
            "decompile_function_success addr=0x%llX func=%s sleigh=%s elapsed_ms=%lld lines=%zu mapped_lines=%zu text_lines=%zu callees=%zu pseudocode_bytes=%zu",
            static_cast<unsigned long long>(r.function_addr),
            r.function_name.c_str(), r.sleigh_id.c_str(),
            static_cast<long long>(r.elapsed_ms),
            reported_line_count, mapped_line_count, pseudocode_line_count, r.callees.size(), r.pseudocode.size());
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
        result["line_count"] = reported_line_count;
        result["mapped_line_count"] = mapped_line_count;
        result["pseudocode_line_count"] = pseudocode_line_count;
        if (dec_admission.active()) {
            diag::log_tagged_fmt("decomp_tools",
                "FEATURE-WORKER-GROUP-RELEASE decompile_function token=%llu reason=completed",
                static_cast<unsigned long long>(dec_admission.token()));
            dec_admission.release("completed");
        }
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
