#include <winsock2.h>
#include <ws2tcpip.h>

#include "test_all_mcp.h"
#include "test_all_features.hpp"

#include "../mcp/mcp_standalone.hpp"
#include "../ai/standalone_chat.hpp"
#include "../analysis/decrypt_oracle.hpp"
#include "../analysis/integrity_hunter.hpp"
#include "../analysis/struct_monitor.hpp"
#include "../analysis/xref_engine.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace test_all_features {

namespace {

    std::set<std::string> g_invoked_tools;
    uint32_t g_mcp_target_pid = 0;
    std::atomic<int> g_mcp_tool_sequence{0};
    uint64_t g_mcp_driver_hw_addr = 0;
    uint32_t g_mcp_driver_hw_tid = 0;
    uint64_t g_mcp_dbg_hw_addr = 0;
    uint64_t g_mcp_live_monitor_addr = 0;
    uint64_t g_mcp_live_monitor_cmp_addr = 0;

    enum class mcp_tool_call_status_t {
        passed,
        failed,
        skipped,
        timed_out
    };

    struct mcp_tool_attempt_stats_t {
        int attempted = 0;
        int passed = 0;
        int failed = 0;
        int skipped = 0;
        int timed_out = 0;
    };

    std::map<std::string, mcp_tool_attempt_stats_t> g_tool_attempt_stats;

    std::string lower_copy(std::string v) {
        std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return v;
    }

    std::string hex_u64(uint64_t value) {
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llX",
            static_cast<unsigned long long>(value));
        return std::string(buf);
    }

    bool is_ai_related_mcp_tool(const std::string& name) {
        static const std::set<std::string> exact = {
            "task",
            "switch_agent",
            "list_agents",
            "ask_followup_question",
            "attempt_completion",
            "plan_enter",
            "plan_exit",
            "update_todo_list",
            "apply_diff",
            "apply_patch",
            "codebase_search",
            "search_workspace",
            "skill",
            "run_slash_command",
            "get_context",
            "workflow_status",
            "checkpoint_create",
            "checkpoint_list",
            "checkpoint_restore",
            "checkpoint_diff",
            "save_checkpoint",
            "restore_checkpoint",
            "list_checkpoints",
            "read_command_output",
            "command_run",
            "command_output",
            "create_goal",
            "update_goal",
            "get_goal",
            "request_user_input"
        };
        const std::string lowered = lower_copy(name);
        if (exact.find(lowered) != exact.end())
            return true;
        return lowered.rfind("ai_", 0) == 0 ||
            lowered.rfind("agent_", 0) == 0 ||
            lowered.rfind("agents_", 0) == 0 ||
            lowered.rfind("workflow_", 0) == 0 ||
            lowered.find("openai") != std::string::npos;
    }

    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...);

    bool process_alive_by_pid(uint32_t pid, uint32_t* exit_code_out = nullptr) {
        if (exit_code_out)
            *exit_code_out = 0;
        if (pid == 0)
            return false;
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) {
            if (exit_code_out)
                *exit_code_out = GetLastError();
            return false;
        }
        DWORD exit_code = 0;
        const bool ok = GetExitCodeProcess(h, &exit_code) != FALSE;
        CloseHandle(h);
        if (exit_code_out)
            *exit_code_out = ok ? exit_code : GetLastError();
        return ok && exit_code == STILL_ACTIVE;
    }

    bool restore_mcp_target(HANDLE hf, const char* tag) {
        if (g_mcp_target_pid == 0)
            return false;
        const uint32_t current = driver_bridge::attached_pid();
        bool known = false;
        for (auto p : driver_bridge::attached_pids()) {
            if (p == g_mcp_target_pid) {
                known = true;
                break;
            }
        }
        bool ok = known ? driver_bridge::set_active_pid(g_mcp_target_pid) : driver_bridge::attach(g_mcp_target_pid);
        if (!ok && known)
            ok = driver_bridge::attach(g_mcp_target_pid);
        log_msg(hf, tag, "%s -- restored MCP test target pid=%u from active_pid=%u known=%d now=%u",
            ok ? "INFO" : "WARN", g_mcp_target_pid, current, known ? 1 : 0, driver_bridge::attached_pid());
        return ok;
    }

    bool ensure_mcp_target_live(HANDLE hf, const char* tag) {
        if (g_mcp_target_pid == 0)
            return true;

        if (!restore_mcp_target(hf, tag))
            return false;

        uint32_t exit_code = 0;
        const bool alive = driver_bridge::attached_process_alive(&exit_code);
        if (!alive) {
            log_msg(hf, tag, "SKIP -- MCP target pid=%u is no longer alive (exit_code_or_err=0x%08X)",
                g_mcp_target_pid, exit_code);
        }
        return alive;
    }

    bool tool_may_change_target(const std::string& name) {
        static const std::set<std::string> names = {
            "driver_attach",
            "driver_detach",
            "driver_unattach",
            "debugger_attach_to_process",
            "debugger_detach",
            "sessions_open_file",
            "sessions_attach_pid",
            "sessions_run_binary",
            "sessions_close"
        };
        return names.find(name) != names.end();
    }

    bool tool_uses_live_target(const std::string& name) {
        return name.rfind("driver_", 0) == 0 ||
            name.rfind("dbg_", 0) == 0 ||
            name.rfind("debugger_", 0) == 0 ||
            name.rfind("scanner_", 0) == 0 ||
            name.rfind("memory_", 0) == 0 ||
            name == "reconstruct_source" ||
            name == "decompile_function" ||
            name == "scan_crypto_constants" ||
            name == "crypto_scanner_run" ||
            name == "crypto_scanner_get_results" ||
            name == "generate_aob_signature" ||
            name == "reconstruct_struct" ||
            name == "start_fuzz" ||
            name == "stop_fuzz" ||
            name == "get_fuzz_results" ||
            name == "auto_decrypt_strings" ||
            name == "hunt_integrity_checkers" ||
            name == "neutralize_integrity_node" ||
            name == "start_live_monitor" ||
            name == "stop_live_monitor" ||
            name == "symbolic_deobfuscate" ||
            name == "symbolic_slice_function" ||
            name == "symbolic_solve_path" ||
            name == "taint_trace_register";
    }

    uint32_t first_mcp_target_tid();

    void add_target_pid_if_needed(const std::string& name, mcp_standalone::json& args) {
        if (g_mcp_target_pid == 0 || !tool_uses_live_target(name))
            return;
        if (args.contains("target_pid") || args.contains("process_id") || args.contains("pid"))
            return;
        args["target_pid"] = g_mcp_target_pid;
    }

    void add_target_tid_if_zero(mcp_standalone::json& args) {
        if (!args.is_object() || !args.contains("tid"))
            return;

        bool replace = false;
        auto& tid = args["tid"];
        if (tid.is_string()) {
            std::string s = tid.get<std::string>();
            replace = s.empty() || s == "0" || s == "0x0";
        } else if (tid.is_number_unsigned()) {
            replace = (tid.get<std::uint64_t>() == 0);
        } else if (tid.is_number_integer()) {
            replace = (tid.get<std::int64_t>() == 0);
        }
        if (!replace)
            return;

        uint32_t live_tid = first_mcp_target_tid();
        if (live_tid != 0)
            args["tid"] = std::to_string(live_tid);
    }


    void format_timestamp(char* out, std::size_t cap) {
        SYSTEMTIME st; GetLocalTime(&st);
        std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
            (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    }
    void write_log_file(HANDLE hf, const std::string& line) {
        if (hf == INVALID_HANDLE_VALUE) return;
        DWORD wrote = 0;
        WriteFile(hf, line.data(), (DWORD)line.size(), &wrote, nullptr);
        FlushFileBuffers(hf);
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
        std::string s(line);
        write_log_file(hf, s);
        diag::log_tagged_fmt("test_all", "%s: %s", tag, detail);
        OutputDebugStringA(s.c_str());
    }

    std::string compact_json(const mcp_standalone::json& value) {
        std::string out;
        try {
            out = value.is_null() ? "{}" : value.dump();
        } catch (...) {
            out = "<json-dump-failed>";
        }
        for (auto& c : out) {
            if (c == '\n' || c == '\r') c = ' ';
        }
        if (out.size() > 360)
            out = out.substr(0, 360) + "...(truncated)";
        return out;
    }


    mcp_standalone::server_t* get_server() {
        return &get_local_mcp_server();
    }


    struct invoke_result_t {
        bool   found = false;
        bool   success = false;
        bool   threw = false;
        std::string text;
        std::string exception_msg;
        mcp_standalone::json data;
    };

    void record_tool_status(const std::string& name, mcp_tool_call_status_t status) {
        if (name.empty())
            return;
        auto& stats = g_tool_attempt_stats[name];
        ++stats.attempted;
        switch (status) {
            case mcp_tool_call_status_t::passed: ++stats.passed; break;
            case mcp_tool_call_status_t::failed: ++stats.failed; break;
            case mcp_tool_call_status_t::skipped: ++stats.skipped; break;
            case mcp_tool_call_status_t::timed_out: ++stats.timed_out; break;
        }
    }

    bool inspect_payload_object_failure(const mcp_standalone::json& obj, std::string& reason) {
        if (!obj.is_object())
            return false;

        auto success_it = obj.find("success");
        if (success_it != obj.end() && success_it->is_boolean() && !success_it->get<bool>()) {
            reason = "success=false";
            auto err = obj.find("error");
            if (err != obj.end() && err->is_string() && !err->get<std::string>().empty())
                reason += ": " + err->get<std::string>();
            return true;
        }

        auto status_it = obj.find("status");
        if (status_it != obj.end() && status_it->is_string()) {
            std::string status = lower_copy(status_it->get<std::string>());
            if (status == "failed" || status == "error") {
                reason = status;
                auto err = obj.find("error");
                if (err != obj.end() && err->is_string() && !err->get<std::string>().empty())
                    reason += ": " + err->get<std::string>();
                return true;
            }
        }

        auto value_it = obj.find("value");
        if (value_it != obj.end() && value_it->is_string()) {
            const std::string value = lower_copy(value_it->get<std::string>());
            if (value.find("<read error>") != std::string::npos || value.find("read error") != std::string::npos) {
                reason = "value read error";
                return true;
            }
        }

        return false;
    }

    bool tool_payload_failure_reason(const invoke_result_t& ir, std::string& reason) {
        reason.clear();
        if (inspect_payload_object_failure(ir.data, reason))
            return true;

        if (!ir.text.empty()) {
            try {
                auto parsed = mcp_standalone::json::parse(ir.text);
                if (inspect_payload_object_failure(parsed, reason))
                    return true;
            } catch (...) {
            }
        }

        return false;
    }

    struct timed_invoke_result_t {
        invoke_result_t result;
        bool timed_out = false;
        long long elapsed_ms = 0;
    };

    struct async_invoke_state_t {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        invoke_result_t result;
        long long elapsed_ms = 0;
    };

    bool tool_registered(mcp_standalone::server_t* srv, const char* tool_name) {
        if (!srv || !tool_name)
            return false;
        const auto& tools = srv->get_tools();
        for (const auto& t : tools) {
            if (t.name == tool_name)
                return true;
        }
        return false;
    }

    long long tool_timeout_ms(const std::string& name) {
        if (name == "web_search" || name == "webfetch")
            return 45000;
        if (name == "auto_decrypt_strings")
            return 65000;
        if (name.find("reconstruct_") == 0)
            return 45000;
        if (name.find("decompile") != std::string::npos)
            return 45000;
        if (name.find("scanner_") == 0 || name.find("driver_pointer_scan") == 0)
            return 45000;
        return 30000;
    }

    void cancel_timed_out_tool(HANDLE hf, const char* tag, const std::string& name) {
        if (name == "auto_decrypt_strings") {
            decrypt_oracle::g_state.cancel.store(true, std::memory_order_release);
            xref_engine::cancel_scan();
            log_msg(hf, tag, "CANCEL -- auto_decrypt_strings decrypt/xref state signalled");
        } else if (name == "start_live_monitor" || name == "stop_live_monitor") {
            struct_monitor::stop();
            log_msg(hf, tag, "CANCEL -- live monitor stop signalled");
        } else if (name == "hunt_integrity_checkers") {
            integrity_hunter::stop_hunt();
            log_msg(hf, tag, "CANCEL -- integrity hunter stop signalled");
        }
    }

    invoke_result_t invoke_tool(mcp_standalone::server_t* srv, const char* tool_name,
                                const mcp_standalone::json& args)
    {
        invoke_result_t ir;
        if (!srv) { ir.exception_msg = "null server"; return ir; }

        mcp_standalone::json call_args = args.is_null() ? mcp_standalone::json::object() : args;
        const auto& tools = srv->get_tools();
        for (const auto& t : tools) {
            if (t.name == tool_name) {
                ir.found = true;
                try {
                    auto result = t.handler(call_args);
                    ir.success = result.success;
                    ir.text = result.text;
                    ir.data = result.data;
                } catch (const std::exception& ex) {
                    ir.threw = true;
                    ir.exception_msg = ex.what();
                } catch (...) {
                    ir.threw = true;
                    ir.exception_msg = "unknown exception";
                }
                return ir;
            }
        }
        return ir;
    }

    timed_invoke_result_t invoke_tool_bounded(mcp_standalone::server_t* srv,
                                             const std::string& tool_name,
                                             const mcp_standalone::json& args,
                                             long long timeout_ms)
    {
        timed_invoke_result_t out;
        const auto state = std::make_shared<async_invoke_state_t>();
        std::thread([state, srv, tool_name, args]() {
            auto t0 = std::chrono::steady_clock::now();
            auto ir = invoke_tool(srv, tool_name.c_str(), args);
            auto t1 = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            {
                std::lock_guard<std::mutex> lk(state->mutex);
                state->result = std::move(ir);
                state->elapsed_ms = static_cast<long long>(ms);
                state->done = true;
            }
            state->cv.notify_all();
        }).detach();

        std::unique_lock<std::mutex> lk(state->mutex);
        if (!state->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&]() { return state->done; })) {
            out.timed_out = true;
            out.elapsed_ms = timeout_ms;
            return out;
        }
        out.result = std::move(state->result);
        out.elapsed_ms = state->elapsed_ms;
        return out;
    }


    mcp_tool_call_status_t test_tool_call(HANDLE hf, const char* tag, mcp_standalone::server_t* srv,
                                          const char* tool_name, const mcp_standalone::json& args,
                                          std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped,
                                          bool skip_on_error = true)
    {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        if (is_ai_related_mcp_tool(tool_name_s)) {
            log_msg(hf, tag, "SKIP -- tool \"%s\" is AI/agent-related and excluded from full-run tests",
                tool_name_s.c_str());
            skipped.fetch_add(1);
            return mcp_tool_call_status_t::skipped;
        }

        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: %s", seq, tool_name ? tool_name : "<null>");
        set_progress_step(step);

        mcp_standalone::json call_args = args.is_null() ? mcp_standalone::json::object() : args;
        add_target_pid_if_needed(tool_name_s, call_args);
        add_target_tid_if_zero(call_args);

        const std::string args_preview = compact_json(call_args);
        log_msg(hf, tag, "START -- \"%s\" seq=%d target_pid=%u attached_pid=%u args=%s",
            tool_name ? tool_name : "<null>",
            seq,
            g_mcp_target_pid,
            driver_bridge::attached_pid(),
            args_preview.c_str());
        g_invoked_tools.insert(tool_name_s);

        if (!ensure_mcp_target_live(hf, tag)) {
            record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return mcp_tool_call_status_t::skipped;
        }

        if (!tool_registered(srv, tool_name)) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" not registered", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        const long long timeout_ms = tool_timeout_ms(tool_name_s);
        log_msg(hf, tag, "DISPATCH -- \"%s\" watchdog=%lld ms", tool_name, timeout_ms);
        auto timed = invoke_tool_bounded(srv, tool_name_s, call_args, timeout_ms);
        auto ir = std::move(timed.result);
        auto ms = timed.elapsed_ms;
        auto restore_after_mutation = [&]() {
            if (tool_may_change_target(tool_name_s))
                restore_mcp_target(hf, tag);
        };
        if (timed.timed_out) {
            log_msg(hf, tag, "FAIL -- \"%s\" timed out after %lld ms; detached worker may still be unwinding",
                tool_name, timeout_ms);
            cancel_timed_out_tool(hf, tag, tool_name_s);
            restore_after_mutation();
            record_tool_status(tool_name_s, mcp_tool_call_status_t::timed_out);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::timed_out;
        }
        if (!ir.found) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" disappeared during dispatch", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        if (ir.threw) {
            if (skip_on_error) {
                log_msg(hf, tag, "SKIP -- tool \"%s\" threw: %s (elapsed %lld ms)",
                    tool_name, ir.exception_msg.c_str(), (long long)ms);
                restore_after_mutation();
                record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                return mcp_tool_call_status_t::skipped;
            } else {
                log_msg(hf, tag, "FAIL -- tool \"%s\" threw: %s (elapsed %lld ms)",
                    tool_name, ir.exception_msg.c_str(), (long long)ms);
                restore_after_mutation();
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return mcp_tool_call_status_t::failed;
            }
        }


        std::string preview = ir.text;
        if (preview.size() > 200) preview = preview.substr(0, 200) + "...(truncated)";

        for (auto& c : preview) { if (c == '\n') c = ' '; if (c == '\r') c = ' '; }

        uint32_t post_exit_code = 0;
        if (g_mcp_target_pid != 0 && tool_uses_live_target(tool_name_s) &&
            !process_alive_by_pid(g_mcp_target_pid, &post_exit_code)) {
            log_msg(hf, tag, "FAIL -- \"%s\" ended MCP target pid=%u exit_code_or_err=0x%08X (elapsed %lld ms) -> %s",
                tool_name, g_mcp_target_pid, post_exit_code, (long long)ms, preview.c_str());
            restore_after_mutation();
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }

        std::string payload_failure;
        if (ir.success && tool_payload_failure_reason(ir, payload_failure)) {
            log_msg(hf, tag, "FAIL -- \"%s\" success=true but payload reports failure: %s (elapsed %lld ms) -> %s",
                tool_name, payload_failure.c_str(), (long long)ms, preview.c_str());
            restore_after_mutation();
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }

        if (ir.success) {
            log_msg(hf, tag, "PASS -- \"%s\" success=true (elapsed %lld ms) -> %s",
                tool_name, (long long)ms, preview.c_str());
            record_tool_status(tool_name_s, mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            restore_after_mutation();
            return mcp_tool_call_status_t::passed;
        } else {
            if (skip_on_error) {
                log_msg(hf, tag, "SKIP -- \"%s\" returned error (precondition): %s (elapsed %lld ms)",
                    tool_name, preview.c_str(), (long long)ms);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                restore_after_mutation();
                return mcp_tool_call_status_t::skipped;
            } else {
                log_msg(hf, tag, "FAIL -- \"%s\" success=false: %s (elapsed %lld ms)",
                    tool_name, preview.c_str(), (long long)ms);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                restore_after_mutation();
                return mcp_tool_call_status_t::failed;
            }
        }
    }


    std::string get_self_path_narrow() {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, self, -1, narrow, MAX_PATH, nullptr, nullptr);
        return std::string(narrow);
    }

    bool file_exists_narrow(const std::string& path) {
        if (path.empty()) return false;
        DWORD attr = GetFileAttributesA(path.c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    std::string dirname_narrow(const std::string& path) {
        size_t pos = path.find_last_of("\\/");
        return pos == std::string::npos ? std::string() : path.substr(0, pos);
    }

    std::string join_path_narrow(const std::string& dir, const char* leaf) {
        if (dir.empty()) return leaf ? std::string(leaf) : std::string();
        char sep = '\\';
        if (!dir.empty() && (dir.back() == '\\' || dir.back() == '/')) sep = '\0';
        std::string out = dir;
        if (sep) out.push_back(sep);
        if (leaf) out += leaf;
        return out;
    }

    std::string get_small_pe_fixture_path() {
        const std::string self = get_self_path_narrow();
        const std::string dir = dirname_narrow(self);
        const std::string parent = dirname_narrow(dir);
        std::vector<std::string> candidates;
        candidates.push_back(join_path_narrow(dir, "test_target.exe"));
        candidates.push_back(join_path_narrow(dir, "AiDA_TestTarget.exe"));
        candidates.push_back(join_path_narrow(join_path_narrow(dir, "Release"), "AiDA_TestTarget.exe"));
        candidates.push_back(join_path_narrow(join_path_narrow(parent, "Release"), "AiDA_TestTarget.exe"));
        candidates.push_back(join_path_narrow(parent, "test_target.exe"));

        char sysroot[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableA("SystemRoot", sysroot, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            candidates.push_back(join_path_narrow(join_path_narrow(sysroot, "System32"), "cmd.exe"));
        }

        for (const auto& path : candidates) {
            if (file_exists_narrow(path)) return path;
        }
        return self;
    }

    std::string temp_file_narrow(const char* name) {
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, temp, -1, narrow, MAX_PATH, nullptr, nullptr);
        return std::string(narrow) + (name ? name : "aida_mcp_tmp.bin");
    }

    bool read_file_prefix(const std::string& path, std::vector<unsigned char>& out, DWORD max_bytes) {
        out.clear();
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0) {
            CloseHandle(h);
            return false;
        }
        const LONGLONG cap = static_cast<LONGLONG>(max_bytes);
        DWORD to_read = static_cast<DWORD>((size.QuadPart < cap) ? size.QuadPart : cap);
        out.resize(to_read);
        DWORD got = 0;
        BOOL ok = ReadFile(h, out.data(), to_read, &got, nullptr);
        CloseHandle(h);
        if (!ok || got == 0)
            return false;
        out.resize(got);
        return true;
    }

    std::string get_ntdll_addr_str() {
        if (g_mcp_target_pid != 0 && driver_bridge::attached_pid() != g_mcp_target_pid) {
            (void)driver_bridge::attach(g_mcp_target_pid);
        }
        uint64_t remote_base = 0;
        const uint32_t pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : driver_bridge::attached_pid();
        if (pid != 0) {
            for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
                const std::string name = lower_copy(mod.name);
                if (name == "ntdll.dll") {
                    remote_base = mod.base;
                    break;
                }
            }
        }
        if (remote_base != 0)
            return hex_u64(remote_base);

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? hex_u64(reinterpret_cast<uintptr_t>(ntdll)) : std::string();
    }

    std::string get_ntclose_addr_str() {
        if (g_mcp_target_pid != 0 && driver_bridge::attached_pid() != g_mcp_target_pid) {
            (void)driver_bridge::attach(g_mcp_target_pid);
        }

        uint64_t remote_base = 0;
        const uint32_t pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : driver_bridge::attached_pid();
        if (pid != 0) {
            for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
                const std::string name = lower_copy(mod.name);
                if (name == "ntdll.dll") {
                    remote_base = mod.base;
                    break;
                }
            }
        }

        if (remote_base != 0) {
            const uint64_t resolved = driver_bridge::resolve_export(remote_base, "NtClose");
            if (resolved != 0)
                return hex_u64(resolved);

            HMODULE local_ntdll = GetModuleHandleW(L"ntdll.dll");
            FARPROC local_fn = local_ntdll ? GetProcAddress(local_ntdll, "NtClose") : nullptr;
            if (local_ntdll && local_fn) {
                const uint64_t offset =
                    reinterpret_cast<uintptr_t>(local_fn) - reinterpret_cast<uintptr_t>(local_ntdll);
                return hex_u64(remote_base + offset);
            }
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        FARPROC fn = ntdll ? GetProcAddress(ntdll, "NtClose") : nullptr;
        return fn ? hex_u64(reinterpret_cast<uintptr_t>(fn)) : std::string();
    }

    uint64_t get_remote_module_base(const char* module_name) {
        if (!module_name)
            return 0;
        if (g_mcp_target_pid != 0 && driver_bridge::attached_pid() != g_mcp_target_pid) {
            (void)driver_bridge::attach(g_mcp_target_pid);
        }
        const std::string want = lower_copy(module_name);
        const uint32_t pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : driver_bridge::attached_pid();
        if (pid == 0)
            return 0;
        for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
            if (lower_copy(mod.name) == want)
                return mod.base;
        }
        return 0;
    }

    uint64_t resolve_remote_export(const char* module_name, const char* export_name) {
        const uint64_t base = get_remote_module_base(module_name);
        if (base == 0 || !export_name)
            return 0;
        uint64_t resolved = driver_bridge::resolve_export(base, export_name);
        if (resolved != 0)
            return resolved;

        wchar_t wide_name[MAX_PATH] = {};
        MultiByteToWideChar(CP_UTF8, 0, module_name, -1, wide_name, MAX_PATH);
        HMODULE local_module = GetModuleHandleW(wide_name);
        FARPROC local_fn = local_module ? GetProcAddress(local_module, export_name) : nullptr;
        if (!local_module || !local_fn)
            return 0;
        const uint64_t offset =
            reinterpret_cast<uintptr_t>(local_fn) - reinterpret_cast<uintptr_t>(local_module);
        return base + offset;
    }

    void cleanup_live_monitor_regions(HANDLE hf, const char* tag) {
        if (g_mcp_live_monitor_addr != 0) {
            bool freed = driver_bridge::free_memory(g_mcp_live_monitor_addr);
            log_msg(hf, tag, "live-monitor primary free addr=0x%016llX ok=%d",
                static_cast<unsigned long long>(g_mcp_live_monitor_addr),
                freed ? 1 : 0);
            g_mcp_live_monitor_addr = 0;
        }
        if (g_mcp_live_monitor_cmp_addr != 0) {
            bool freed = driver_bridge::free_memory(g_mcp_live_monitor_cmp_addr);
            log_msg(hf, tag, "live-monitor compare free addr=0x%016llX ok=%d",
                static_cast<unsigned long long>(g_mcp_live_monitor_cmp_addr),
                freed ? 1 : 0);
            g_mcp_live_monitor_cmp_addr = 0;
        }
    }

    bool prepare_live_monitor_regions(HANDLE hf, const char* tag) {
        cleanup_live_monitor_regions(hf, tag);
        uint64_t primary = driver_bridge::allocate_memory(4096);
        uint64_t compare = driver_bridge::allocate_memory(4096);
        if (primary == 0 || compare == 0) {
            log_msg(hf, tag, "SKIP -- allocate_memory failed for live-monitor buffers primary=0x%016llX compare=0x%016llX",
                static_cast<unsigned long long>(primary),
                static_cast<unsigned long long>(compare));
            if (primary != 0)
                driver_bridge::free_memory(primary);
            if (compare != 0)
                driver_bridge::free_memory(compare);
            return false;
        }

        std::vector<uint8_t> bytes(4096);
        for (size_t i = 0; i < bytes.size(); ++i)
            bytes[i] = static_cast<uint8_t>((i * 17u + 0x41u) & 0xFFu);
        if (!driver_bridge::write_memory(primary, bytes) ||
            !driver_bridge::write_memory(compare, bytes)) {
            log_msg(hf, tag, "SKIP -- write_memory failed for live-monitor buffers primary=0x%016llX compare=0x%016llX",
                static_cast<unsigned long long>(primary),
                static_cast<unsigned long long>(compare));
            driver_bridge::free_memory(primary);
            driver_bridge::free_memory(compare);
            return false;
        }

        uint32_t old_primary = 0;
        uint32_t old_compare = 0;
        (void)driver_bridge::protect_memory(primary, 4096, PAGE_READWRITE, &old_primary);
        (void)driver_bridge::protect_memory(compare, 4096, PAGE_READWRITE, &old_compare);
        g_mcp_live_monitor_addr = primary;
        g_mcp_live_monitor_cmp_addr = compare;
        log_msg(hf, tag, "live-monitor buffers primary=0x%016llX compare=0x%016llX",
            static_cast<unsigned long long>(primary),
            static_cast<unsigned long long>(compare));
        return true;
    }

    void trigger_live_monitor_accesses(HANDLE hf, const char* tag) {
        if (g_mcp_live_monitor_addr == 0 || g_mcp_live_monitor_cmp_addr == 0)
            return;

        std::vector<uint8_t> bytes;
        const bool read_ok = driver_bridge::read_memory(g_mcp_live_monitor_addr, 128, bytes);
        bool write_ok = false;
        if (read_ok && !bytes.empty()) {
            bytes[0] ^= 0x5Au;
            write_ok = driver_bridge::write_memory(g_mcp_live_monitor_addr, bytes);
        }
        log_msg(hf, tag, "live-monitor safe access probe read_ok=%d write_ok=%d bytes=%zu addr=0x%016llX",
            read_ok ? 1 : 0,
            write_ok ? 1 : 0,
            bytes.size(),
            static_cast<unsigned long long>(g_mcp_live_monitor_addr));
    }

    uint64_t alloc_private_mcp_bp_region(HANDLE hf, const char* tag) {
        uint64_t addr = driver_bridge::allocate_memory(64);
        if (addr == 0) {
            log_msg(hf, tag, "SKIP -- allocate_memory returned 0 for private HWBP region");
            return 0;
        }

        std::vector<uint8_t> bytes(64, 0x90);
        bytes.back() = 0xC3;
        if (!driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, tag, "SKIP -- write_memory failed for private HWBP region addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            return 0;
        }

        uint32_t old_protect = 0;
        (void)driver_bridge::protect_memory(addr, 64, PAGE_EXECUTE_READWRITE, &old_protect);
        log_msg(hf, tag, "private HWBP region addr=0x%016llX", static_cast<unsigned long long>(addr));
        return addr;
    }

    uint32_t first_mcp_target_tid() {
        const uint32_t pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : driver_bridge::attached_pid();
        if (pid == 0)
            return 0;
        if (driver_bridge::attached_pid() != pid)
            (void)driver_bridge::attach(pid);
        for (const auto& t : driver_bridge::enumerate_threads()) {
            if (t.owner_pid == pid)
                return t.tid;
        }
        return 0;
    }

    std::string get_pid_str() {
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%u", (unsigned)GetCurrentProcessId());
        return std::string(buf);
    }

    BOOL CALLBACK init_mcp_winsock_once(PINIT_ONCE, PVOID parameter, PVOID*) {
        bool* ok = static_cast<bool*>(parameter);
        WSADATA wsa = {};
        *ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        return TRUE;
    }

    bool ensure_mcp_winsock_ready() {
        static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
        static bool ok = false;
        if (!InitOnceExecuteOnce(&once, init_mcp_winsock_once, &ok, nullptr))
            return false;
        return ok;
    }

    struct mcp_loopback_tcp_pair_t {
        SOCKET listener = INVALID_SOCKET;
        SOCKET client = INVALID_SOCKET;
        SOCKET accepted = INVALID_SOCKET;
        bool wsa_started = false;
        uint16_t listen_port = 0;
        uint16_t client_port = 0;

        bool open(HANDLE hf, const char* tag) {
            if (!ensure_mcp_winsock_ready()) {
                log_msg(hf, tag, "SKIP -- WSAStartup failed for loopback TCP tuple");
                return false;
            }
            wsa_started = true;

            listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                log_msg(hf, tag, "SKIP -- listener socket failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
                listen(listener, 1) == SOCKET_ERROR) {
                log_msg(hf, tag, "SKIP -- listener bind/listen failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            int addr_len = sizeof(addr);
            if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len) == SOCKET_ERROR) {
                log_msg(hf, tag, "SKIP -- listener getsockname failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }
            listen_port = ntohs(addr.sin_port);

            client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (client == INVALID_SOCKET) {
                log_msg(hf, tag, "SKIP -- client socket failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            if (connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                log_msg(hf, tag, "SKIP -- loopback connect failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            accepted = accept(listener, nullptr, nullptr);
            if (accepted == INVALID_SOCKET) {
                log_msg(hf, tag, "SKIP -- loopback accept failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            sockaddr_in local = {};
            int local_len = sizeof(local);
            if (getsockname(client, reinterpret_cast<sockaddr*>(&local), &local_len) == SOCKET_ERROR) {
                log_msg(hf, tag, "SKIP -- client getsockname failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }
            client_port = ntohs(local.sin_port);
            log_msg(hf, tag, "loopback TCP tuple src=127.0.0.1:%u dst=127.0.0.1:%u",
                (unsigned)client_port, (unsigned)listen_port);
            return client_port != 0 && listen_port != 0;
        }

        void close_all() {
            if (accepted != INVALID_SOCKET) {
                closesocket(accepted);
                accepted = INVALID_SOCKET;
            }
            if (client != INVALID_SOCKET) {
                closesocket(client);
                client = INVALID_SOCKET;
            }
            if (listener != INVALID_SOCKET) {
                closesocket(listener);
                listener = INVALID_SOCKET;
            }
            if (wsa_started) {
                wsa_started = false;
            }
            listen_port = 0;
            client_port = 0;
        }

        ~mcp_loopback_tcp_pair_t() {
            close_all();
        }
    };

    void cleanup_mcp_network_state(HANDLE hf, const char* reason) {
        log_msg(hf, "mcp.net_cleanup", "BEGIN -- %s", reason ? reason : "unspecified");
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, "mcp.net_cleanup", "SKIP -- kernel driver not connected");
            return;
        }

        const bool stop_cap = driver_bridge::stop_capture();
        const bool clear_filters = driver_bridge::clear_filter_rules();
        const bool intercept = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        const bool clear_mod = driver_bridge::packet_mod_rule_op(3);
        const bool clear_redirect = driver_bridge::traffic_redirect_op(3);
        const bool clear_streams = driver_bridge::stream_reassemble_op(4);
        std::uint8_t zero[16] = {};
        const bool clear_dns = driver_bridge::dns_spoof_op(3, 0, nullptr, zero, 2, 300, nullptr);
        const bool stop_bw = driver_bridge::bw_monitor_op(1, 0, nullptr);
        const bool reset_bw = driver_bridge::bw_monitor_op(3, 0, nullptr);
        log_msg(hf, "mcp.net_cleanup",
            "END -- stop_capture=%d clear_filters=%d intercept_disable=%d packet_mod_clear=%d redirect_clear=%d stream_clear=%d dns_clear=%d bw_stop=%d bw_reset=%d",
            stop_cap ? 1 : 0, clear_filters ? 1 : 0, intercept ? 1 : 0, clear_mod ? 1 : 0,
            clear_redirect ? 1 : 0, clear_streams ? 1 : 0, clear_dns ? 1 : 0, stop_bw ? 1 : 0, reset_bw ? 1 : 0);
    }


    void test_mcp_server_accessible(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.server_accessible";
        auto* srv = get_server();
        if (srv) {
            log_msg(hf, tag, "PASS -- MCP server instance obtained");
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- could not get MCP server instance");
            failed.fetch_add(1);
        }
    }

    void test_mcp_server_running(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.server_running";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }
        bool running = srv->is_running();
        int port = srv->get_port();
        if (running) {
            log_msg(hf, tag, "PASS -- server running=true port=%d", port);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- server running=false port=%d", port);
            failed.fetch_add(1);
        }
    }

    void test_mcp_tool_count(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.tool_count";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }
        const auto& tools = srv->get_tools();
        int non_ai_count = 0;
        int ai_count = 0;
        for (const auto& t : tools) {
            if (is_ai_related_mcp_tool(t.name))
                ++ai_count;
            else
                ++non_ai_count;
        }
        if (non_ai_count > 0) {
            log_msg(hf, tag, "PASS -- %zu tools registered non_ai=%d ai_or_workflow=%d",
                tools.size(), non_ai_count, ai_count);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no non-AI tools registered total=%zu ai_or_workflow=%d",
                tools.size(), ai_count);
            failed.fetch_add(1);
        }
    }

    void test_mcp_enumerate_tools(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.enumerate_tools";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }
        const auto& tools = srv->get_tools();
        int read_only_count = 0;
        int writable_count = 0;
        for (const auto& t : tools) {
            if (t.read_only) ++read_only_count;
            else ++writable_count;
            log_msg(hf, tag, "  tool: %-40s params=%zu ro=%s desc=\"%.80s\"",
                t.name.c_str(), t.params.size(),
                t.read_only ? "Y" : "N",
                t.description.c_str());
        }
        log_msg(hf, tag, "PASS -- enumerated %zu tools (read_only=%d writable=%d)",
            tools.size(), read_only_count, writable_count);
        passed.fetch_add(1);
    }

    void test_mcp_categorize_tools(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.categorize_tools";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }
        const auto& tools = srv->get_tools();
        std::map<std::string, int> categories;


        for (const auto& t : tools) {
            std::string cat = "other";
            auto pos = t.name.find('_');
            if (pos != std::string::npos && pos > 0) {
                cat = t.name.substr(0, pos);
            }
            categories[cat]++;
        }
        for (const auto& kv : categories) {
            log_msg(hf, tag, "  category %-20s : %d tools", kv.first.c_str(), kv.second);
        }
        log_msg(hf, tag, "PASS -- %zu categories identified", categories.size());
        passed.fetch_add(1);
    }

    void test_mcp_tool_schemas(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.tool_schemas";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }
        const auto& tools = srv->get_tools();
        int valid = 0;
        int invalid = 0;
        for (const auto& t : tools) {
            bool ok = !t.name.empty() && !t.description.empty() && t.handler;
            if (ok) ++valid;
            else {
                ++invalid;
                log_msg(hf, tag, "  invalid schema: name=\"%s\" desc_empty=%d handler=%s",
                    t.name.c_str(), (int)t.description.empty(),
                    t.handler ? "present" : "null");
            }
        }
        if (invalid == 0) {
            log_msg(hf, tag, "PASS -- all %d tool schemas valid (name, desc, handler present)", valid);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %d/%d tool schemas invalid", invalid, valid + invalid);
            failed.fetch_add(1);
        }
    }

    void test_mcp_duplicate_tool_names(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.duplicate_tool_names";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }

        std::map<std::string, int> counts;
        for (const auto& t : srv->get_tools()) {
            counts[t.name]++;
        }

        int duplicates = 0;
        for (const auto& kv : counts) {
            if (kv.second > 1) {
                duplicates += kv.second - 1;
                log_msg(hf, tag, "DUPLICATE -- tool \"%s\" registered %d times; direct tests exercise only the first handler",
                    kv.first.c_str(), kv.second);
            }
        }

        if (duplicates == 0) {
            log_msg(hf, tag, "PASS -- %zu registered tool names are unique", counts.size());
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %d duplicate MCP tool registration(s) across %zu unique names",
                duplicates, counts.size());
            failed.fetch_add(1);
        }
    }

    void test_mcp_jsonrpc_smoke(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.jsonrpc_smoke";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }

        try {
            mcp_standalone::json init_req = {
                {"jsonrpc", "2.0"},
                {"id", 1},
                {"method", "initialize"},
                {"params", mcp_standalone::json::object()}
            };
            auto init_resp = mcp_standalone::json::parse(mcp_standalone::handle_body(srv, init_req.dump()));
            if (!init_resp.contains("result") || !init_resp["result"].contains("serverInfo")) {
                log_msg(hf, tag, "FAIL -- initialize response missing result.serverInfo");
                failed.fetch_add(1);
                return;
            }

            mcp_standalone::json list_req = {
                {"jsonrpc", "2.0"},
                {"id", 2},
                {"method", "tools/list"},
                {"params", mcp_standalone::json::object()}
            };
            auto list_resp = mcp_standalone::json::parse(mcp_standalone::handle_body(srv, list_req.dump()));
            if (!list_resp.contains("result") || !list_resp["result"].contains("tools") ||
                !list_resp["result"]["tools"].is_array()) {
                log_msg(hf, tag, "FAIL -- tools/list response missing result.tools array");
                failed.fetch_add(1);
                return;
            }

            mcp_standalone::json call_req = {
                {"jsonrpc", "2.0"},
                {"id", 3},
                {"method", "tools/call"},
                {"params", {
                    {"name", "driver_status"},
                    {"arguments", mcp_standalone::json::object()}
                }}
            };
            auto call_resp = mcp_standalone::json::parse(mcp_standalone::handle_body(srv, call_req.dump()));
            if (!call_resp.contains("result") && !call_resp.contains("error")) {
                log_msg(hf, tag, "FAIL -- tools/call response missing result/error");
                failed.fetch_add(1);
                return;
            }

            mcp_standalone::json resources_req = {
                {"jsonrpc", "2.0"},
                {"id", 4},
                {"method", "resources/list"},
                {"params", mcp_standalone::json::object()}
            };
            auto resources_resp = mcp_standalone::json::parse(mcp_standalone::handle_body(srv, resources_req.dump()));
            if (!resources_resp.contains("result") ||
                !resources_resp["result"].contains("resources") ||
                !resources_resp["result"]["resources"].is_array()) {
                log_msg(hf, tag, "FAIL -- resources/list response missing result.resources array");
                failed.fetch_add(1);
                return;
            }

            std::set<std::string> resources_seen;
            for (const auto& res : resources_resp["result"]["resources"]) {
                if (res.contains("uri") && res["uri"].is_string())
                    resources_seen.insert(res["uri"].get<std::string>());
            }

            const char* required_resources[] = {
                "standalone://driver-status",
                "standalone://loaded-file"
            };
            for (int i = 0; i < 2; ++i) {
                const char* uri = required_resources[i];
                if (resources_seen.find(uri) == resources_seen.end()) {
                    log_msg(hf, tag, "FAIL -- resources/list missing required uri %s", uri);
                    failed.fetch_add(1);
                    return;
                }
                mcp_standalone::json read_req = {
                    {"jsonrpc", "2.0"},
                    {"id", 5 + i},
                    {"method", "resources/read"},
                    {"params", {{"uri", uri}}}
                };
                auto read_resp = mcp_standalone::json::parse(mcp_standalone::handle_body(srv, read_req.dump()));
                if (!read_resp.contains("result") ||
                    !read_resp["result"].contains("contents") ||
                    !read_resp["result"]["contents"].is_array() ||
                    read_resp["result"]["contents"].empty()) {
                    log_msg(hf, tag, "FAIL -- resources/read response for %s missing result.contents", uri);
                    failed.fetch_add(1);
                    return;
                }
            }

            log_msg(hf, tag, "PASS -- initialize/tools-list/tools-call/resources-list/resources-read JSON-RPC path responded; external_tools=%zu resources=%zu",
                list_resp["result"]["tools"].size(),
                resources_resp["result"]["resources"].size());
            passed.fetch_add(1);
        } catch (const std::exception& ex) {
            log_msg(hf, tag, "FAIL -- JSON-RPC smoke threw: %s", ex.what());
            failed.fetch_add(1);
        }
    }

    void test_mcp_coverage_audit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.coverage_audit";
        auto* srv = get_server();
        if (!srv) {
            log_msg(hf, tag, "SKIP -- no server instance");
            skipped.fetch_add(1);
            return;
        }

        std::set<std::string> registered;
        int covered = 0;
        int attempted = 0;
        int passed_tools = 0;
        int failed_tools = 0;
        int skipped_tools = 0;
        int timed_out_tools = 0;
        int no_pass = 0;
        int skipped_ai = 0;
        int missing = 0;
        for (const auto& t : srv->get_tools()) {
            if (is_ai_related_mcp_tool(t.name)) {
                ++skipped_ai;
                continue;
            }
            if (!registered.insert(t.name).second)
                continue;
            auto stats_it = g_tool_attempt_stats.find(t.name);
            if (stats_it != g_tool_attempt_stats.end() && stats_it->second.attempted > 0) {
                ++attempted;
                const auto& st = stats_it->second;
                if (st.passed > 0) {
                    ++covered;
                    ++passed_tools;
                } else {
                    ++no_pass;
                    log_msg(hf, tag, "NO-PASS -- registered tool \"%s\" attempted=%d failed=%d skipped=%d timed_out=%d",
                        t.name.c_str(), st.attempted, st.failed, st.skipped, st.timed_out);
                }
                if (st.failed > 0)
                    ++failed_tools;
                if (st.skipped > 0)
                    ++skipped_tools;
                if (st.timed_out > 0)
                    ++timed_out_tools;
            } else if (g_invoked_tools.find(t.name) != g_invoked_tools.end()) {
                ++attempted;
                ++no_pass;
                log_msg(hf, tag, "NO-PASS -- registered tool \"%s\" was attempted without a recorded terminal status",
                    t.name.c_str());
            } else {
                ++missing;
                log_msg(hf, tag, "MISSING -- registered tool \"%s\" was not attempted by the full MCP harness",
                    t.name.c_str());
            }
        }

        int stale = 0;
        for (const auto& attempted : g_invoked_tools) {
            if (registered.find(attempted) == registered.end() && !is_ai_related_mcp_tool(attempted)) {
                ++stale;
                log_msg(hf, tag, "STALE -- explicit MCP test attempted unregistered tool \"%s\"",
                    attempted.c_str());
            }
        }

        if (missing == 0 && stale == 0 && timed_out_tools == 0 && no_pass == 0 && failed_tools == 0) {
            log_msg(hf, tag, "PASS -- attempted=%d passed_tools=%d no_pass=%d failed_tools=%d skipped_tools=%d timed_out_tools=%d ai_skipped=%d",
                attempted, passed_tools, no_pass, failed_tools, skipped_tools, timed_out_tools, skipped_ai);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- missing=%d stale=%d attempted=%d passed_tools=%d no_pass=%d failed_tools=%d skipped_tools=%d timed_out_tools=%d ai_skipped=%d",
                missing, stale, attempted, covered, no_pass, failed_tools, skipped_tools, timed_out_tools, skipped_ai);
            failed.fetch_add(1);
        }
    }


    void test_tool_driver_load(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_load", get_server(), "driver_load", {}, passed, failed, skipped);
    }

    void test_tool_driver_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_status", get_server(), "driver_status", {}, passed, failed, skipped);
    }

    void test_tool_list_processes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.list_processes", get_server(), "list_processes", {}, passed, failed, skipped);
    }

    void test_tool_list_processes_filter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["filter"] = "explorer";
        test_tool_call(hf, "mcp.list_processes_filter", get_server(), "list_processes", args, passed, failed, skipped);
    }

    void test_tool_enumerate_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.enumerate_modules", get_server(), "enumerate_modules", {}, passed, failed, skipped);
    }

    void test_tool_enumerate_threads(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.enumerate_threads", get_server(), "enumerate_threads", {}, passed, failed, skipped);
    }

    void test_tool_read_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.read_memory", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["size"] = 64;
        test_tool_call(hf, "mcp.read_memory", get_server(), "read_memory", args, passed, failed, skipped);
    }

    void test_tool_read_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.read_string", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.read_string", get_server(), "read_string", args, passed, failed, skipped);
    }

    void test_tool_query_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.query_memory", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.query_memory", get_server(), "query_memory", args, passed, failed, skipped);
    }

    void test_tool_disassemble_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disassemble_address", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disassemble_address", get_server(), "disassemble_address", args, passed, failed, skipped);
    }

    void test_tool_disassemble_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_self_path_narrow();
        args["count"] = 16;
        test_tool_call(hf, "mcp.disassemble_file", get_server(), "disassemble_file", args, passed, failed, skipped);
    }

    void test_tool_driver_detach(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_detach", get_server(), "driver_detach", {}, passed, failed, skipped);
    }

    void test_tool_sandbox_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\Windows\\System32\\cmd.exe";
        args["arguments"] = "/c echo test";
        args["timeout_ms"] = 5000;
        test_tool_call(hf, "mcp.sandbox_execute", get_server(), "sandbox_execute", args, passed, failed, skipped);
    }

    void test_tool_convert_number_decimal(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "255";
        args["from"] = "decimal";
        test_tool_call(hf, "mcp.convert_number_dec", get_server(), "convert_number", args, passed, failed, skipped, false);
    }

    void test_tool_convert_number_hex(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "0xFF";
        args["from"] = "hex";
        test_tool_call(hf, "mcp.convert_number_hex", get_server(), "convert_number", args, passed, failed, skipped, false);
    }

    void test_tool_convert_number_binary(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "0b11111111";
        args["from"] = "binary";
        test_tool_call(hf, "mcp.convert_number_bin", get_server(), "convert_number", args, passed, failed, skipped, false);
    }

    void test_tool_read_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_self_path_narrow();
        args["max_bytes"] = 256;
        test_tool_call(hf, "mcp.read_file", get_server(), "read_file", args, passed, failed, skipped);
    }

    void test_tool_write_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, temp, -1, narrow, MAX_PATH, nullptr, nullptr);
        std::string path = std::string(narrow) + "aida_mcp_test_write.txt";
        args["path"] = path;
        args["content"] = "mcp_test_content";
        test_tool_call(hf, "mcp.write_file", get_server(), "write_file", args, passed, failed, skipped);
    }

    void test_tool_edit_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, temp, -1, narrow, MAX_PATH, nullptr, nullptr);
        std::string path = std::string(narrow) + "aida_mcp_test_write.txt";
        args["path"] = path;
        args["find_text"] = "mcp_test_content";
        args["replace_text"] = "mcp_test_edited";
        test_tool_call(hf, "mcp.edit_file", get_server(), "edit_file", args, passed, failed, skipped);
    }

    void test_tool_delete_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, temp, -1, narrow, MAX_PATH, nullptr, nullptr);
        std::string path = std::string(narrow) + "aida_mcp_test_write.txt";
        args["path"] = path;
        test_tool_call(hf, "mcp.delete_file", get_server(), "delete_file", args, passed, failed, skipped);
    }

    void test_tool_create_directory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        wchar_t temp[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, temp, -1, narrow, MAX_PATH, nullptr, nullptr);
        std::string path = std::string(narrow) + "aida_mcp_test_dir";
        args["path"] = path;
        test_tool_call(hf, "mcp.create_directory", get_server(), "create_directory", args, passed, failed, skipped);
    }

    void test_tool_list_directory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = ".";
        test_tool_call(hf, "mcp.list_directory", get_server(), "list_directory", args, passed, failed, skipped);
    }

    void test_tool_search_files(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["root"] = ".";
        args["pattern"] = "*.exe";
        test_tool_call(hf, "mcp.search_files", get_server(), "search_files", args, passed, failed, skipped);
    }

    void test_tool_grep_in_files(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["root"] = ".";
        args["pattern"] = "main";
        args["limit"] = 5;
        test_tool_call(hf, "mcp.grep_in_files", get_server(), "grep_in_files", args, passed, failed, skipped);
    }

    void test_tool_file_info(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_self_path_narrow();
        test_tool_call(hf, "mcp.file_info", get_server(), "file_info", args, passed, failed, skipped);
    }

    void test_tool_get_working_directory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.get_working_directory", get_server(), "get_working_directory", {}, passed, failed, skipped);
    }

    void test_tool_web_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.web_search";
        mcp_standalone::json args;
        args["query"] = "Microsoft Windows API";
        args["max_results"] = 2;

        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: web_search", seq);
        set_progress_step(step);
        log_msg(hf, tag, "START -- \"web_search\" seq=%d args=%s", seq, compact_json(args).c_str());

        g_invoked_tools.insert("web_search");
        auto timed = invoke_tool_bounded(get_server(), "web_search", args, tool_timeout_ms("web_search"));
        auto ir = std::move(timed.result);
        auto ms = timed.elapsed_ms;

        if (timed.timed_out) {
            log_msg(hf, tag, "FAIL -- tool \"web_search\" timed out after %lld ms", tool_timeout_ms("web_search"));
            record_tool_status("web_search", mcp_tool_call_status_t::timed_out);
            failed.fetch_add(1);
            return;
        }
        if (!ir.found) {
            log_msg(hf, tag, "FAIL -- tool \"web_search\" not registered");
            record_tool_status("web_search", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (ir.threw) {
            log_msg(hf, tag, "FAIL -- tool \"web_search\" threw: %s (elapsed %lld ms)",
                ir.exception_msg.c_str(), (long long)ms);
            record_tool_status("web_search", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (!ir.success) {
            log_msg(hf, tag, "SKIP -- web_search transport/precondition error: %s (elapsed %lld ms)",
                ir.text.c_str(), (long long)ms);
            record_tool_status("web_search", mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return;
        }

        const bool has_results =
            ir.data.is_object() &&
            ir.data.contains("results") &&
            ir.data["results"].is_array() &&
            !ir.data["results"].empty();
        if (!has_results) {
            log_msg(hf, tag,
                "FAIL -- web_search returned success with zero results for a common query; text=%s data=%s (elapsed %lld ms)",
                ir.text.c_str(), compact_json(ir.data).c_str(), (long long)ms);
            record_tool_status("web_search", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }

        log_msg(hf, tag, "PASS -- web_search returned %zu result(s) (elapsed %lld ms) -> %s",
            ir.data["results"].size(), (long long)ms, ir.text.c_str());
        record_tool_status("web_search", mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_webfetch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["url"] = "https://httpbin.org/get";
        args["format"] = "text";
        args["timeout"] = 10;
        test_tool_call(hf, "mcp.webfetch", get_server(), "webfetch", args, passed, failed, skipped);
    }

    void test_tool_reconstruct_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.reconstruct_status", get_server(), "reconstruct_status", {}, passed, failed, skipped);
    }

    void test_tool_reconstruct_cancel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.reconstruct_cancel", get_server(), "reconstruct_cancel", {}, passed, failed, skipped);
    }

    void test_tool_reconstruct_source(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["output_dir"] = "C:\\temp\\aida_test_recon";
        args["module_name"] = "ntdll.dll";
        args["use_ai"] = false;
        args["max_functions"] = 1;
        args["include_imports"] = false;
        args["include_exports"] = false;
        args["generate_cmake"] = false;
        test_tool_call(hf, "mcp.reconstruct_source", get_server(), "reconstruct_source", args, passed, failed, skipped);
        for (int i = 0; i < 80; ++i) {
            auto status = invoke_tool_bounded(get_server(), "reconstruct_status", {}, 1000);
            bool running = false;
            if (!status.timed_out && status.result.success && status.result.data.is_object())
                running = status.result.data.value("running", false);
            log_msg(hf, "mcp.reconstruct_source", "cleanup poll %d running=%d timed_out=%d",
                i, running ? 1 : 0, status.timed_out ? 1 : 0);
            if (!running)
                break;
            if (i == 0)
                (void)invoke_tool_bounded(get_server(), "reconstruct_cancel", {}, 1000);
            Sleep(100);
        }
    }


    void test_tool_driver_connect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_connect", get_server(), "driver_connect", {}, passed, failed, skipped);
    }

    void test_tool_driver_attach(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["process"] = "AiDA_TestTarget.exe";
        test_tool_call(hf, "mcp.driver_attach", get_server(), "driver_attach", args, passed, failed, skipped);
    }

    void test_tool_driver_unattach(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_unattach", get_server(), "driver_unattach", {}, passed, failed, skipped);
    }

    void test_tool_driver_read_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_read_memory", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["size"] = 64;
        test_tool_call(hf, "mcp.driver_read_memory", get_server(), "driver_read_memory", args, passed, failed, skipped);
    }

    void test_tool_driver_write_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(16);
        if (addr == 0) {
            log_msg(hf, "mcp.driver_write_memory", "SKIP -- allocate_memory failed for write fixture");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["bytes"] = "90";
        test_tool_call(hf, "mcp.driver_write_memory", get_server(), "driver_write_memory", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_driver_dump_module(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_name"] = "ntdll.dll";
        test_tool_call(hf, "mcp.driver_dump_module", get_server(), "driver_dump_module", args, passed, failed, skipped);
    }

    void test_tool_driver_scan_pattern(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pattern"] = "48 89 5C 24";
        test_tool_call(hf, "mcp.driver_scan_pattern", get_server(), "driver_scan_pattern", args, passed, failed, skipped);
    }

    void test_tool_driver_read_string(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_read_string", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.driver_read_string", get_server(), "driver_read_string", args, passed, failed, skipped);
    }

    void test_tool_driver_read_pointer_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_read_pointer_chain", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["base_address"] = addr;
        mcp_standalone::json offsets = mcp_standalone::json::array();
        offsets.push_back(0);
        args["offsets"] = offsets;
        test_tool_call(hf, "mcp.driver_read_pointer_chain", get_server(), "driver_read_pointer_chain", args, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_modules", get_server(), "driver_enumerate_modules", {}, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_kernel_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_kernel_modules", get_server(), "driver_enumerate_kernel_modules", {}, passed, failed, skipped);
    }

    void test_tool_driver_dump_kernel_module(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.driver_dump_kernel_module";
        mcp_standalone::json args;
        args["module"] = "ntoskrnl.exe";
        args["from_memory"] = false;
        args["patch_idb"] = false;
        args["analyze"] = false;
        args["output_path"] = temp_file_narrow("aida_mcp_ntoskrnl_disk_dump.bin");

        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: driver_dump_kernel_module disk-smoke", seq);
        set_progress_step(step);

        log_msg(hf, tag,
            "START -- \"driver_dump_kernel_module\" seq=%d bounded disk-smoke args=%s",
            seq, compact_json(args).c_str());
        g_invoked_tools.insert("driver_dump_kernel_module");
        if (!ensure_mcp_target_live(hf, tag)) {
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return;
        }

        auto timed = invoke_tool_bounded(get_server(), "driver_dump_kernel_module", args, 45000);
        auto ir = std::move(timed.result);
        auto ms = timed.elapsed_ms;

        if (timed.timed_out) {
            log_msg(hf, tag, "FAIL -- bounded disk-smoke timed out after %lld ms", (long long)ms);
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::timed_out);
            failed.fetch_add(1);
            return;
        }

        if (!ir.found) {
            log_msg(hf, tag, "FAIL -- tool \"driver_dump_kernel_module\" not registered");
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (ir.threw) {
            log_msg(hf, tag, "FAIL -- bounded disk-smoke threw: %s (elapsed %lld ms)",
                ir.exception_msg.c_str(), (long long)ms);
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (!ir.success) {
            log_msg(hf, tag, "SKIP -- bounded disk-smoke returned precondition error: %s (elapsed %lld ms)",
                ir.text.c_str(), (long long)ms);
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return;
        }

        const std::string output_path = args["output_path"].get<std::string>();
        std::vector<unsigned char> prefix;
        if (!read_file_prefix(output_path, prefix, 64) || prefix.size() < 2) {
            log_msg(hf, tag,
                "FAIL -- bounded disk-smoke reported success but output file is missing/empty path=\"%s\" text=%s (elapsed %lld ms)",
                output_path.c_str(), ir.text.c_str(), (long long)ms);
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (prefix[0] != 'M' || prefix[1] != 'Z') {
            log_msg(hf, tag,
                "FAIL -- bounded disk-smoke output is not a PE image path=\"%s\" first2=%02X %02X text=%s (elapsed %lld ms)",
                output_path.c_str(), prefix[0], prefix[1], ir.text.c_str(), (long long)ms);
            record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }

        log_msg(hf, tag,
            "PASS -- bounded disk-smoke dumped PE header path=\"%s\" first2=MZ bytes_checked=%zu (elapsed %lld ms) -> %s",
            output_path.c_str(), prefix.size(), (long long)ms, ir.text.c_str());
        record_tool_status("driver_dump_kernel_module", mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_driver_read_kernel_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["address"] = "0xFFFFF80000000000";
        args["size"] = 16;
        test_tool_call(hf, "mcp.driver_read_kernel_memory", get_server(), "driver_read_kernel_memory", args, passed, failed, skipped);
    }

    void test_tool_driver_write_kernel_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["address"] = "0x0";
        args["bytes"] = "90";
        test_tool_call(hf, "mcp.driver_write_kernel_memory", get_server(), "driver_write_kernel_memory", args, passed, failed, skipped);
    }

    void test_tool_driver_allocate_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["size"] = 4096;
        test_tool_call(hf, "mcp.driver_allocate_memory", get_server(), "driver_allocate_memory", args, passed, failed, skipped);
    }

    void test_tool_driver_free_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(4096);
        if (addr == 0) {
            log_msg(hf, "mcp.driver_free_memory", "SKIP -- allocate_memory failed for free fixture");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        auto st = test_tool_call(hf, "mcp.driver_free_memory", get_server(), "driver_free_memory", args, passed, failed, skipped);
        if (st != mcp_tool_call_status_t::passed)
            driver_bridge::free_memory(addr);
    }

    void test_tool_driver_call_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_call_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["dry_run"] = true;
        test_tool_call(hf, "mcp.driver_call_function", get_server(), "driver_call_function", args, passed, failed, skipped);
    }

    void test_tool_driver_get_thread_context(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.driver_get_thread_context", get_server(), "driver_get_thread_context", args, passed, failed, skipped);
    }

    void test_tool_driver_set_thread_context(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        args["register"] = "rax";
        args["value"] = "0x0";
        test_tool_call(hf, "mcp.driver_set_thread_context", get_server(), "driver_set_thread_context", args, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_threads(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_threads", get_server(), "driver_enumerate_threads", {}, passed, failed, skipped);
    }

    void test_tool_driver_suspend_thread(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.driver_suspend_thread", get_server(), "driver_suspend_thread", args, passed, failed, skipped);
    }

    void test_tool_driver_resume_thread(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.driver_resume_thread", get_server(), "driver_resume_thread", args, passed, failed, skipped);
    }

    void test_tool_driver_query_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_query_memory", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.driver_query_memory", get_server(), "driver_query_memory", args, passed, failed, skipped);
    }

    void test_tool_driver_protect_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(4096);
        if (addr == 0) {
            log_msg(hf, "mcp.driver_protect_memory", "SKIP -- allocate_memory failed for protect fixture");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["size"] = 4096;
        args["protect"] = 0x04;
        test_tool_call(hf, "mcp.driver_protect_memory", get_server(), "driver_protect_memory", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_driver_enumerate_memory_regions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_memory_regions", get_server(), "driver_enumerate_memory_regions", {}, passed, failed, skipped);
    }

    void test_tool_driver_read_peb(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_read_peb", get_server(), "driver_read_peb", {}, passed, failed, skipped);
    }

    void test_tool_driver_spoof_debug_flags(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_spoof_debug_flags", get_server(), "driver_spoof_debug_flags", {}, passed, failed, skipped);
    }

    void test_tool_driver_set_hw_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr_raw = alloc_private_mcp_bp_region(hf, "mcp.driver_set_hw_breakpoint");
        if (addr_raw == 0) { skipped.fetch_add(1); return; }
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.driver_set_hw_breakpoint", "SKIP -- target thread not found for private HWBP test");
            driver_bridge::free_memory(addr_raw);
            skipped.fetch_add(1);
            return;
        }
        g_mcp_driver_hw_addr = addr_raw;
        g_mcp_driver_hw_tid = tid;
        mcp_standalone::json args;
        args["address"] = hex_u64(addr_raw);
        args["tid"] = std::to_string(tid);
        args["index"] = 0;
        args["type"] = "execute";
        args["size"] = 1;
        test_tool_call(hf, "mcp.driver_set_hw_breakpoint", get_server(), "driver_set_hw_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_driver_clear_hw_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        if (g_mcp_driver_hw_tid == 0) {
            g_mcp_driver_hw_tid = first_mcp_target_tid();
        }
        if (g_mcp_driver_hw_tid == 0) {
            log_msg(hf, "mcp.driver_clear_hw_breakpoint", "SKIP -- target thread not found for clear test");
            skipped.fetch_add(1);
            return;
        }
        args["tid"] = std::to_string(g_mcp_driver_hw_tid);
        args["index"] = 0;
        test_tool_call(hf, "mcp.driver_clear_hw_breakpoint", get_server(), "driver_clear_hw_breakpoint", args, passed, failed, skipped);
        if (g_mcp_driver_hw_addr != 0) {
            driver_bridge::free_memory(g_mcp_driver_hw_addr);
            g_mcp_driver_hw_addr = 0;
        }
        g_mcp_driver_hw_tid = 0;
    }

    void test_tool_driver_resolve_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_name"] = "ntdll.dll";
        args["function_name"] = "NtClose";
        test_tool_call(hf, "mcp.driver_resolve_export", get_server(), "driver_resolve_export", args, passed, failed, skipped);
    }

    void test_tool_driver_virtual_to_physical(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_virtual_to_physical", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.driver_virtual_to_physical", get_server(), "driver_virtual_to_physical", args, passed, failed, skipped);
    }

    void test_tool_driver_defer_action(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["wait_for"] = "process_start";
        args["target"] = "aida_mcp_deferred_never.exe";
        args["timeout"] = 1;
        args["poll_interval"] = 100;
        args["actions"] = mcp_standalone::json::array({
            {{"tool", "driver_status"}, {"params", mcp_standalone::json::object()}}
        });
        test_tool_call(hf, "mcp.driver_defer_action", get_server(), "driver_defer_action", args, passed, failed, skipped);
    }

    void test_tool_driver_list_deferred_actions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_list_deferred_actions", get_server(), "driver_list_deferred_actions", {}, passed, failed, skipped);
    }

    void test_tool_driver_cancel_deferred_action(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["action_id"] = 999999;
        test_tool_call(hf, "mcp.driver_cancel_deferred_action", get_server(), "driver_cancel_deferred_action", args, passed, failed, skipped);
    }

    void test_tool_driver_get_deferred_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["action_id"] = 999999;
        test_tool_call(hf, "mcp.driver_get_deferred_results", get_server(), "driver_get_deferred_results", args, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_wfp_callouts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_wfp_callouts", get_server(), "driver_enumerate_wfp_callouts", {}, passed, failed, skipped);
    }

    void test_tool_driver_get_socket_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_get_socket_handles", get_server(), "driver_get_socket_handles", {}, passed, failed, skipped);
    }

    void test_tool_driver_sniff_network_buffers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_sniff_network_buffers", get_server(), "driver_sniff_network_buffers", {}, passed, failed, skipped);
    }

    void test_tool_driver_dump_tcpip_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_dump_tcpip_connections", get_server(), "driver_dump_tcpip_connections", {}, passed, failed, skipped);
    }

    void test_tool_driver_inject_packet(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["protocol"] = "udp";
        args["src_addr"] = "127.0.0.1";
        args["dst_addr"] = "127.0.0.1";
        args["src_port"] = 65534;
        args["dst_port"] = 65533;
        args["payload"] = "00";
        test_tool_call(hf, "mcp.driver_inject_packet", get_server(), "driver_inject_packet", args, passed, failed, skipped);
    }

    void test_tool_driver_modify_packet_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "add";
        args["direction"] = "both";
        args["protocol"] = "tcp";
        args["port"] = 65534;
        args["pattern"] = "41";
        args["replacement"] = "42";
        test_tool_call(hf, "mcp.driver_modify_packet_rule", get_server(), "driver_modify_packet_rule", args, passed, failed, skipped);
    }

    void test_tool_driver_redirect_traffic(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "add";
        args["protocol"] = "tcp";
        args["match_port"] = 65534;
        args["redirect_port"] = 65533;
        args["match_addr"] = "127.0.0.1";
        args["redirect_addr"] = "127.0.0.1";
        test_tool_call(hf, "mcp.driver_redirect_traffic", get_server(), "driver_redirect_traffic", args, passed, failed, skipped);
    }

    void test_tool_driver_reassemble_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["connection_id"] = 0;
        test_tool_call(hf, "mcp.driver_reassemble_stream", get_server(), "driver_reassemble_stream", args, passed, failed, skipped);
    }

    void test_tool_driver_deep_inspect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["connection_id"] = 0;
        test_tool_call(hf, "mcp.driver_deep_inspect", get_server(), "driver_deep_inspect", args, passed, failed, skipped);
    }

    void test_tool_driver_intercept_hold(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "disable";
        test_tool_call(hf, "mcp.driver_intercept_hold", get_server(), "driver_intercept_hold", args, passed, failed, skipped);
    }

    void test_tool_driver_kill_connection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_loopback_tcp_pair_t pair;
        if (!pair.open(hf, "mcp.driver_kill_connection")) {
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["protocol"] = "tcp";
        args["src_addr"] = "127.0.0.1";
        args["dst_addr"] = "127.0.0.1";
        args["src_port"] = pair.client_port;
        args["dst_port"] = pair.listen_port;
        args["pid"] = GetCurrentProcessId();
        test_tool_call(hf, "mcp.driver_kill_connection", get_server(), "driver_kill_connection", args, passed, failed, skipped);
    }

    void test_tool_driver_spoof_dns(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "add";
        args["domain"] = "aida-mcp-test.invalid";
        args["spoof_addr"] = "127.0.0.1";
        args["ttl"] = 30;
        test_tool_call(hf, "mcp.driver_spoof_dns", get_server(), "driver_spoof_dns", args, passed, failed, skipped);
    }

    void test_tool_driver_bandwidth_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "status";
        test_tool_call(hf, "mcp.driver_bandwidth_monitor", get_server(), "driver_bandwidth_monitor", args, passed, failed, skipped);
    }

    void test_tool_driver_list_interfaces(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_list_interfaces", get_server(), "driver_list_interfaces", {}, passed, failed, skipped);
    }

    void test_tool_driver_export_pcap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\temp\\aida_test.pcap";
        test_tool_call(hf, "mcp.driver_export_pcap", get_server(), "driver_export_pcap", args, passed, failed, skipped);
    }

    void test_tool_driver_network_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_network_fingerprint", get_server(), "driver_network_fingerprint", {}, passed, failed, skipped);
    }

    void test_tool_driver_enum_kernel_callbacks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enum_kernel_callbacks", get_server(), "driver_enum_kernel_callbacks", {}, passed, failed, skipped);
    }

    void test_tool_driver_detect_integrity_checks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_detect_integrity_checks", get_server(), "driver_detect_integrity_checks", {}, passed, failed, skipped);
    }

    void test_tool_driver_detect_ssdt_hooks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_detect_ssdt_hooks", get_server(), "driver_detect_ssdt_hooks", {}, passed, failed, skipped);
    }

    void test_tool_driver_enum_minifilters(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enum_minifilters", get_server(), "driver_enum_minifilters", {}, passed, failed, skipped);
    }

    void test_tool_driver_detect_etw_monitors(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_detect_etw_monitors", get_server(), "driver_detect_etw_monitors", {}, passed, failed, skipped);
    }

    void test_tool_driver_detect_hidden_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_detect_hidden_modules", get_server(), "driver_detect_hidden_modules", {}, passed, failed, skipped);
    }

    void test_tool_driver_walk_heap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_walk_heap", get_server(), "driver_walk_heap", {}, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_handles", get_server(), "driver_enumerate_handles", {}, passed, failed, skipped);
    }

    void test_tool_driver_walk_seh_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_walk_seh_chain", get_server(), "driver_walk_seh_chain", {}, passed, failed, skipped);
    }

    void test_tool_driver_find_code_caves(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_find_code_caves", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["size"] = 0x1000;
        test_tool_call(hf, "mcp.driver_find_code_caves", get_server(), "driver_find_code_caves", args, passed, failed, skipped);
    }

    void test_tool_driver_scan_memory_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "0";
        args["type"] = "int32";
        test_tool_call(hf, "mcp.driver_scan_memory_value", get_server(), "driver_scan_memory_value", args, passed, failed, skipped);
    }

    void test_tool_driver_pointer_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["target_address"] = "0x0";
        test_tool_call(hf, "mcp.driver_pointer_scan", get_server(), "driver_pointer_scan", args, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_windows(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_windows", get_server(), "driver_enumerate_windows", {}, passed, failed, skipped);
    }

    void test_tool_driver_walk_stack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.driver_walk_stack", get_server(), "driver_walk_stack", args, passed, failed, skipped);
    }

    void test_tool_driver_assemble(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["assembly"] = "nop";
        test_tool_call(hf, "mcp.driver_assemble", get_server(), "driver_assemble", args, passed, failed, skipped);
    }

    void test_tool_driver_compare_memory_snapshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_compare_memory_snapshot", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["operation"] = "take";
        args["name"] = "mcp_test";
        args["address"] = addr;
        args["size"] = 32;
        test_tool_call(hf, "mcp.driver_compare_memory_snapshot", get_server(), "driver_compare_memory_snapshot", args, passed, failed, skipped);
    }

    void test_tool_driver_find_references(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_find_references", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["target_address"] = addr;
        args["limit"] = 10;
        test_tool_call(hf, "mcp.driver_find_references", get_server(), "driver_find_references", args, passed, failed, skipped);
    }

    void test_tool_driver_read_teb(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.driver_read_teb", get_server(), "driver_read_teb", args, passed, failed, skipped);
    }

    void test_tool_driver_map_peb_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_map_peb_modules", get_server(), "driver_map_peb_modules", {}, passed, failed, skipped);
    }

    void test_tool_driver_set_page_guard(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_set_page_guard", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["operation"] = "query";
        args["address"] = addr;
        args["size"] = 4096;
        test_tool_call(hf, "mcp.driver_set_page_guard", get_server(), "driver_set_page_guard", args, passed, failed, skipped);
    }


    void test_tool_dbg_set_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_set_breakpoint", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_set_breakpoint", get_server(), "dbg_set_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_dbg_remove_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_remove_breakpoint", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_remove_breakpoint", get_server(), "dbg_remove_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_dbg_list_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_list_breakpoints", get_server(), "dbg_list_breakpoints", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_callstack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.dbg_get_callstack", get_server(), "dbg_get_callstack", args, passed, failed, skipped);
    }

    void test_tool_dbg_snapshot_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        args["name"] = "test_snapshot";
        test_tool_call(hf, "mcp.dbg_snapshot_state", get_server(), "dbg_snapshot_state", args, passed, failed, skipped);
    }

    void test_tool_dbg_compare_snapshots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["snapshot_a"] = "test_a";
        args["snapshot_b"] = "test_b";
        test_tool_call(hf, "mcp.dbg_compare_snapshots", get_server(), "dbg_compare_snapshots", args, passed, failed, skipped);
    }

    void test_tool_dbg_detect_vm_handler(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_detect_vm_handler", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_detect_vm_handler", get_server(), "dbg_detect_vm_handler", args, passed, failed, skipped);
    }

    void test_tool_dbg_map_vm_handlers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_map_vm_handlers", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["table_address"] = addr;
        args["count"] = 4;
        test_tool_call(hf, "mcp.dbg_map_vm_handlers", get_server(), "dbg_map_vm_handlers", args, passed, failed, skipped);
    }

    void test_tool_dbg_run(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_run", get_server(), "dbg_run", {}, passed, failed, skipped);
    }

    void test_tool_dbg_pause(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_pause", get_server(), "dbg_pause", {}, passed, failed, skipped);
    }

    void test_tool_dbg_step_into(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.dbg_step_into", get_server(), "dbg_step_into", args, passed, failed, skipped);
    }

    void test_tool_dbg_step_over(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.dbg_step_over", get_server(), "dbg_step_over", args, passed, failed, skipped);
    }

    void test_tool_dbg_step_out(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.dbg_step_out", get_server(), "dbg_step_out", args, passed, failed, skipped);
    }

    void test_tool_dbg_run_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["address"] = "0x0";
        args["wait_for_completion"] = true;
        args["timeout_ms"] = 100;
        test_tool_call(hf, "mcp.dbg_run_to_address", get_server(), "dbg_run_to_address", args, passed, failed, skipped);
    }

    void test_tool_debugger_get_attached(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_attached", get_server(), "debugger_get_attached", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_registers", get_server(), "debugger_get_registers", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_breakpoints", get_server(), "debugger_get_breakpoints", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_memory_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_memory_map", get_server(), "debugger_get_memory_map", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_callstack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_callstack", get_server(), "debugger_get_callstack", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_threads(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_threads", get_server(), "debugger_get_threads", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_handles", get_server(), "debugger_get_handles", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_modules", get_server(), "debugger_get_modules", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_seh_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_seh_chain", get_server(), "debugger_get_seh_chain", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_patches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_patches", get_server(), "debugger_get_patches", {}, passed, failed, skipped);
    }

    void test_tool_debugger_set_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.debugger_set_breakpoint", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.debugger_set_breakpoint", get_server(), "debugger_set_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_debugger_remove_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.debugger_remove_breakpoint", get_server(), "debugger_remove_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_debugger_step_over(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.debugger_step_over", get_server(), "debugger_step_over", args, passed, failed, skipped);
    }

    void test_tool_debugger_step_into(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.debugger_step_into", get_server(), "debugger_step_into", args, passed, failed, skipped);
    }

    void test_tool_debugger_step_out(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["tid"] = "0";
        test_tool_call(hf, "mcp.debugger_step_out", get_server(), "debugger_step_out", args, passed, failed, skipped);
    }

    void test_tool_debugger_continue(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_continue", get_server(), "debugger_continue", {}, passed, failed, skipped);
    }

    void test_tool_debugger_pause(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_pause", get_server(), "debugger_pause", {}, passed, failed, skipped);
    }

    void test_tool_debugger_read_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.debugger_read_memory", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["size"] = 32;
        test_tool_call(hf, "mcp.debugger_read_memory", get_server(), "debugger_read_memory", args, passed, failed, skipped);
    }

    void test_tool_debugger_write_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(16);
        if (addr == 0) {
            log_msg(hf, "mcp.debugger_write_memory", "SKIP -- allocate_memory failed for debugger write fixture");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["hex_bytes"] = "90";
        test_tool_call(hf, "mcp.debugger_write_memory", get_server(), "debugger_write_memory", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_debugger_protect_memory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(4096);
        if (addr == 0) {
            log_msg(hf, "mcp.debugger_protect_memory", "SKIP -- allocate_memory failed for debugger protect fixture");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["size"] = 4096;
        args["new_protect"] = 0x04;
        test_tool_call(hf, "mcp.debugger_protect_memory", get_server(), "debugger_protect_memory", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_debugger_attach_to_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "explorer.exe";
        test_tool_call(hf, "mcp.debugger_attach_to_process", get_server(), "debugger_attach_to_process", args, passed, failed, skipped);
    }

    void test_tool_debugger_detach(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_detach", get_server(), "debugger_detach", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_registers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_registers", get_server(), "dbg_get_registers", {}, passed, failed, skipped);
    }

    void test_tool_dbg_set_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.dbg_set_register", "SKIP -- target thread not found");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(tid);
        args["register"] = "rax";
        args["value"] = "0x0";
        test_tool_call(hf, "mcp.dbg_set_register", get_server(), "dbg_set_register", args, passed, failed, skipped);
    }

    void test_tool_dbg_get_memory_map(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_memory_map", get_server(), "dbg_get_memory_map", {}, passed, failed, skipped);
    }

    void test_tool_dbg_add_watch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["expression"] = "rax";
        test_tool_call(hf, "mcp.dbg_add_watch", get_server(), "dbg_add_watch", args, passed, failed, skipped);
    }

    void test_tool_dbg_remove_watch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.dbg_remove_watch", get_server(), "dbg_remove_watch", args, passed, failed, skipped);
    }

    void test_tool_dbg_get_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_watches", get_server(), "dbg_get_watches", {}, passed, failed, skipped);
    }

    void test_tool_dbg_start_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_start_trace", get_server(), "dbg_start_trace", {}, passed, failed, skipped);
    }

    void test_tool_dbg_stop_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_stop_trace", get_server(), "dbg_stop_trace", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_trace", get_server(), "dbg_get_trace", {}, passed, failed, skipped);
    }

    void test_tool_dbg_set_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_set_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["text"] = "test_comment";
        test_tool_call(hf, "mcp.dbg_set_comment", get_server(), "dbg_set_comment", args, passed, failed, skipped);
    }

    void test_tool_dbg_set_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_set_label", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["text"] = "test_label";
        test_tool_call(hf, "mcp.dbg_set_label", get_server(), "dbg_set_label", args, passed, failed, skipped);
    }

    void test_tool_dbg_toggle_bookmark(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_toggle_bookmark", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_toggle_bookmark", get_server(), "dbg_toggle_bookmark", args, passed, failed, skipped);
    }

    void test_tool_dbg_find_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_find_strings", get_server(), "dbg_find_strings", {}, passed, failed, skipped);
    }

    void test_tool_dbg_enumerate_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_enumerate_handles", get_server(), "dbg_enumerate_handles", {}, passed, failed, skipped);
    }

    void test_tool_dbg_add_hw_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr_raw = alloc_private_mcp_bp_region(hf, "mcp.dbg_add_hw_breakpoint");
        if (addr_raw == 0) { skipped.fetch_add(1); return; }
        g_mcp_dbg_hw_addr = addr_raw;
        mcp_standalone::json args;
        args["address"] = hex_u64(addr_raw);
        args["type"] = "execute";
        args["size"] = 1;
        test_tool_call(hf, "mcp.dbg_add_hw_breakpoint", get_server(), "dbg_add_hw_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_dbg_toggle_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.dbg_toggle_breakpoint", get_server(), "dbg_toggle_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_dbg_clear_all_breakpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_clear_all_breakpoints", get_server(), "dbg_clear_all_breakpoints", {}, passed, failed, skipped);
        if (g_mcp_dbg_hw_addr != 0) {
            driver_bridge::free_memory(g_mcp_dbg_hw_addr);
            g_mcp_dbg_hw_addr = 0;
        }
    }

    void test_tool_dbg_get_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_get_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_get_comment", get_server(), "dbg_get_comment", args, passed, failed, skipped);
    }

    void test_tool_dbg_get_label(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_get_label", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_get_label", get_server(), "dbg_get_label", args, passed, failed, skipped);
    }

    void test_tool_dbg_get_bookmarks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_bookmarks", get_server(), "dbg_get_bookmarks", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_xrefs_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_get_xrefs_to", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_get_xrefs_to", get_server(), "dbg_get_xrefs_to", args, passed, failed, skipped);
    }

    void test_tool_dbg_get_xrefs_from(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_get_xrefs_from", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_get_xrefs_from", get_server(), "dbg_get_xrefs_from", args, passed, failed, skipped);
    }

    void test_tool_dbg_scan_xrefs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        auto base = get_ntdll_addr_str();
        if (addr.empty() || base.empty()) { log_msg(hf, "mcp.dbg_scan_xrefs", "SKIP -- ntdll not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["target_address"] = addr;
        args["start_address"] = base;
        args["size"] = 0x1000;
        test_tool_call(hf, "mcp.dbg_scan_xrefs", get_server(), "dbg_scan_xrefs", args, passed, failed, skipped);
    }

    void test_tool_dbg_build_cfg(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_build_cfg", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_build_cfg", get_server(), "dbg_build_cfg", args, passed, failed, skipped);
    }

    void test_tool_dbg_get_cfg(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_cfg", get_server(), "dbg_get_cfg", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_seh_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_seh_chain", get_server(), "dbg_get_seh_chain", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_modules_detail(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_name"] = "ntdll.dll";
        args["max_modules"] = 1;
        args["max_exports"] = 32;
        args["max_imports"] = 32;
        args["timeout_ms"] = 8000;
        test_tool_call(hf, "mcp.dbg_get_modules_detail", get_server(), "dbg_get_modules_detail", args, passed, failed, skipped);
    }

    void test_tool_dbg_add_patch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_add_patch", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["bytes"] = "90";
        test_tool_call(hf, "mcp.dbg_add_patch", get_server(), "dbg_add_patch", args, passed, failed, skipped);
    }

    void test_tool_dbg_remove_patch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.dbg_remove_patch", get_server(), "dbg_remove_patch", args, passed, failed, skipped);
    }

    void test_tool_dbg_list_patches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_list_patches", get_server(), "dbg_list_patches", {}, passed, failed, skipped);
    }

    void test_tool_dbg_nop_fill(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_nop_fill", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["size"] = 1;
        test_tool_call(hf, "mcp.dbg_nop_fill", get_server(), "dbg_nop_fill", args, passed, failed, skipped);
    }

    void test_tool_dbg_find_code_caves(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_find_code_caves", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.dbg_find_code_caves", get_server(), "dbg_find_code_caves", args, passed, failed, skipped);
    }

    void test_tool_dbg_conditional_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.dbg_conditional_breakpoint", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["condition"] = "rax == 0";
        test_tool_call(hf, "mcp.dbg_conditional_breakpoint", get_server(), "dbg_conditional_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_enable_stealth(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.enable_stealth", get_server(), "enable_stealth", {}, passed, failed, skipped);
    }

    void test_tool_disable_stealth(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.disable_stealth", get_server(), "disable_stealth", {}, passed, failed, skipped);
    }

    void test_tool_stealth_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.stealth_status", get_server(), "stealth_status", {}, passed, failed, skipped);
    }

    void test_tool_dbg_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_status", get_server(), "dbg_status", {}, passed, failed, skipped);
    }

    void test_tool_dbg_list_watches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_list_watches", get_server(), "dbg_list_watches", {}, passed, failed, skipped);
    }


    void test_tool_scanner_first_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "0";
        args["type"] = "int32";
        args["scan_type"] = "exact";
        test_tool_call(hf, "mcp.scanner_first_scan", get_server(), "scanner_first_scan", args, passed, failed, skipped);
    }

    void test_tool_scanner_next_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "0";
        args["scan_type"] = "exact";
        test_tool_call(hf, "mcp.scanner_next_scan", get_server(), "scanner_next_scan", args, passed, failed, skipped);
    }

    void test_tool_scanner_get_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_get_results", get_server(), "scanner_get_results", {}, passed, failed, skipped);
    }

    void test_tool_scanner_reset(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_reset", get_server(), "scanner_reset", {}, passed, failed, skipped);
    }

    void test_tool_scanner_undo(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_undo", get_server(), "scanner_undo", {}, passed, failed, skipped);
    }

    void test_tool_scanner_add_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["address"] = "0x0";
        args["type"] = "int32";
        test_tool_call(hf, "mcp.scanner_add_address", get_server(), "scanner_add_address", args, passed, failed, skipped);
    }

    void test_tool_scanner_remove_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.scanner_remove_address", get_server(), "scanner_remove_address", args, passed, failed, skipped);
    }

    void test_tool_scanner_freeze_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        args["freeze"] = true;
        test_tool_call(hf, "mcp.scanner_freeze_address", get_server(), "scanner_freeze_address", args, passed, failed, skipped);
    }

    void test_tool_scanner_read_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(16);
        if (addr == 0) {
            log_msg(hf, "mcp.scanner_read_value", "SKIP -- allocate_memory failed for scanner read fixture");
            skipped.fetch_add(1);
            return;
        }
        std::vector<uint8_t> bytes = {0x39, 0x30, 0x00, 0x00};
        if (!driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, "mcp.scanner_read_value", "SKIP -- write_memory failed for scanner read fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["value_type"] = "int32";
        test_tool_call(hf, "mcp.scanner_read_value", get_server(), "scanner_read_value", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_scanner_write_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(16);
        if (addr == 0) {
            log_msg(hf, "mcp.scanner_write_value", "SKIP -- allocate_memory failed for scanner write fixture");
            skipped.fetch_add(1);
            return;
        }
        std::vector<uint8_t> bytes(4, 0);
        if (!driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, "mcp.scanner_write_value", "SKIP -- write_memory failed for scanner write fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["value"] = "12345";
        args["value_type"] = "int32";
        auto status = test_tool_call(hf, "mcp.scanner_write_value", get_server(), "scanner_write_value", args, passed, failed, skipped);
        std::vector<uint8_t> check;
        const bool read_ok = driver_bridge::read_memory(addr, 4, check);
        const bool value_ok = read_ok && check.size() >= 4 &&
            check[0] == 0x39 && check[1] == 0x30 && check[2] == 0x00 && check[3] == 0x00;
        if (status == mcp_tool_call_status_t::passed && !value_ok) {
            log_msg(hf, "mcp.scanner_write_value", "FAIL -- scanner_write_value reported success but readback mismatched read_ok=%d size=%zu",
                read_ok ? 1 : 0, check.size());
            failed.fetch_add(1);
        }
        driver_bridge::free_memory(addr);
    }

    void test_tool_scanner_get_address_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_get_address_list", get_server(), "scanner_get_address_list", {}, passed, failed, skipped);
    }

    void test_tool_scanner_pointer_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["target_address"] = "0x0";
        test_tool_call(hf, "mcp.scanner_pointer_scan", get_server(), "scanner_pointer_scan", args, passed, failed, skipped);
    }

    void test_tool_scanner_cancel_pointer_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_cancel_pointer_scan", get_server(), "scanner_cancel_pointer_scan", {}, passed, failed, skipped);
    }

    void test_tool_scanner_define_struct(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "test_struct";
        args["base_address"] = "0x0";
        test_tool_call(hf, "mcp.scanner_define_struct", get_server(), "scanner_define_struct", args, passed, failed, skipped);
    }

    void test_tool_scanner_add_struct_field(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_name"] = "test_struct";
        args["field_name"] = "field1";
        args["type"] = "int32";
        args["offset"] = 0;
        test_tool_call(hf, "mcp.scanner_add_struct_field", get_server(), "scanner_add_struct_field", args, passed, failed, skipped);
    }

    void test_tool_scanner_get_struct(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "test_struct";
        test_tool_call(hf, "mcp.scanner_get_struct", get_server(), "scanner_get_struct", args, passed, failed, skipped);
    }

    void test_tool_scanner_export_struct_c(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "test_struct";
        test_tool_call(hf, "mcp.scanner_export_struct_c", get_server(), "scanner_export_struct_c", args, passed, failed, skipped);
    }

    void test_tool_memory_get_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.memory_get_results", get_server(), "memory_get_results", {}, passed, failed, skipped);
    }

    void test_tool_memory_get_address_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.memory_get_address_list", get_server(), "memory_get_address_list", {}, passed, failed, skipped);
    }

    void test_tool_memory_reset_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.memory_reset_scan", get_server(), "memory_reset_scan", {}, passed, failed, skipped);
    }

    void test_tool_scan_crypto_constants(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_filter"] = "AiDA_TestTarget.exe";
        args["max_regions"] = 64;
        args["max_bytes"] = 0x400000;
        args["max_hits"] = 64;
        args["timeout_ms"] = 20000;
        test_tool_call(hf, "mcp.scan_crypto_constants", get_server(), "scan_crypto_constants", args, passed, failed, skipped);
    }

    void test_tool_generate_aob_signature(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.generate_aob_sig", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.generate_aob_sig", get_server(), "generate_aob_signature", args, passed, failed, skipped);
    }


    void test_tool_reconstruct_struct(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.reconstruct_struct", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.reconstruct_struct", get_server(), "reconstruct_struct", args, passed, failed, skipped);
    }

    void test_tool_start_fuzz(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.start_fuzz", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["target_address"] = addr;
        args["max_iterations"] = 16;
        test_tool_call(hf, "mcp.start_fuzz", get_server(), "start_fuzz", args, passed, failed, skipped);
    }

    void test_tool_stop_fuzz(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.stop_fuzz", get_server(), "stop_fuzz", {}, passed, failed, skipped);
    }

    void test_tool_get_fuzz_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.get_fuzz_results", get_server(), "get_fuzz_results", {}, passed, failed, skipped);
    }

    void test_tool_auto_decrypt_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.auto_decrypt_strings", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["region_address"] = addr;
        args["region_size"] = 128;
        args["timeout_ms"] = 5000;
        test_tool_call(hf, "mcp.auto_decrypt_strings", get_server(), "auto_decrypt_strings", args, passed, failed, skipped);
    }

    void test_tool_hunt_integrity_checkers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!prepare_live_monitor_regions(hf, "mcp.hunt_integrity_checkers")) { skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["target_address"] = hex_u64(g_mcp_live_monitor_addr);
        args["target_size"] = 128;
        args["duration_ms"] = 1000;
        test_tool_call(hf, "mcp.hunt_integrity_checkers", get_server(), "hunt_integrity_checkers", args, passed, failed, skipped);
    }

    void test_tool_neutralize_integrity_node(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["node_index"] = 0;
        test_tool_call(hf, "mcp.neutralize_integrity_node", get_server(), "neutralize_integrity_node", args, passed, failed, skipped);
    }

    void test_tool_start_live_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_live_monitor_addr == 0 && !prepare_live_monitor_regions(hf, "mcp.start_live_monitor")) { skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_live_monitor_addr);
        args["size"] = 128;
        args["name"] = "mcp_live_monitor_fixture";
        auto status = test_tool_call(hf, "mcp.start_live_monitor", get_server(), "start_live_monitor", args, passed, failed, skipped);
        if (status != mcp_tool_call_status_t::passed) {
            log_msg(hf, "mcp.start_live_monitor", "INFO -- monitor did not start; skipping access trigger and cleaning fixture buffers");
            cleanup_live_monitor_regions(hf, "mcp.start_live_monitor");
            return;
        }
        trigger_live_monitor_accesses(hf, "mcp.start_live_monitor");
        if (!ensure_mcp_target_live(hf, "mcp.start_live_monitor")) {
            failed.fetch_add(1);
            cleanup_live_monitor_regions(hf, "mcp.start_live_monitor");
        }
    }

    void test_tool_stop_live_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["require_captures"] = true;
        test_tool_call(hf, "mcp.stop_live_monitor", get_server(), "stop_live_monitor", args, passed, failed, skipped);
        cleanup_live_monitor_regions(hf, "mcp.stop_live_monitor");
    }

    void test_tool_symbolic_deobfuscate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.symbolic_deobfuscate", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["entry_address"] = addr;
        args["max_instructions"] = 128;
        test_tool_call(hf, "mcp.symbolic_deobfuscate", get_server(), "symbolic_deobfuscate", args, passed, failed, skipped);
    }

    void test_tool_symbolic_slice_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.symbolic_slice_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["start_address"] = addr;
        args["end_address"] = hex_u64(std::strtoull(addr.c_str(), nullptr, 16) + 64);
        args["target_register"] = "rax";
        args["max_instructions"] = 128;
        test_tool_call(hf, "mcp.symbolic_slice_function", get_server(), "symbolic_slice_function", args, passed, failed, skipped);
    }

    void test_tool_symbolic_solve_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.symbolic_solve_path", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["start_address"] = addr;
        args["target_address"] = hex_u64(std::strtoull(addr.c_str(), nullptr, 16) + 16);
        args["symbolic_registers"] = "rax";
        args["max_instructions"] = 64;
        test_tool_call(hf, "mcp.symbolic_solve_path", get_server(), "symbolic_solve_path", args, passed, failed, skipped);
    }

    void test_tool_taint_trace_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.taint_trace_register", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["start_address"] = addr;
        args["end_address"] = hex_u64(std::strtoull(addr.c_str(), nullptr, 16) + 64);
        args["taint_registers"] = "rcx";
        args["max_instructions"] = 128;
        test_tool_call(hf, "mcp.taint_trace_register", get_server(), "taint_trace_register", args, passed, failed, skipped);
    }

    void test_tool_decompile_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.decompile_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.decompile_function", get_server(), "decompile_function", args, passed, failed, skipped);
    }

    void test_tool_enable_stealth_context(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.enable_stealth_context", get_server(), "enable_stealth_context", {}, passed, failed, skipped);
    }

    void test_tool_disable_stealth_context(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.disable_stealth_context", get_server(), "disable_stealth_context", {}, passed, failed, skipped);
    }

    void test_tool_analysis_get_imports(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.analysis_get_imports", get_server(), "analysis_get_imports", {}, passed, failed, skipped);
    }

    void test_tool_analysis_get_exports(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.analysis_get_exports", get_server(), "analysis_get_exports", {}, passed, failed, skipped);
    }

    void test_tool_analysis_get_types(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.analysis_get_types", get_server(), "analysis_get_types", {}, passed, failed, skipped);
    }

    void test_tool_analysis_get_type_definition(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "HANDLE";
        test_tool_call(hf, "mcp.analysis_get_type_definition", get_server(), "analysis_get_type_definition", args, passed, failed, skipped);
    }

    void test_tool_analysis_get_pdb_symbols(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.analysis_get_pdb_symbols", get_server(), "analysis_get_pdb_symbols", {}, passed, failed, skipped);
    }

    void test_tool_analysis_get_binary_map_overview(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.analysis_get_binary_map_overview", get_server(), "analysis_get_binary_map_overview", {}, passed, failed, skipped);
    }

    void test_tool_analysis_get_xref_db_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.analysis_get_xref_db_stats", get_server(), "analysis_get_xref_db_stats", {}, passed, failed, skipped);
    }

    void test_tool_crypto_scanner_run(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_filter"] = "AiDA_TestTarget.exe";
        args["max_regions"] = 64;
        args["max_bytes"] = 0x400000;
        args["max_hits"] = 64;
        args["timeout_ms"] = 20000;
        test_tool_call(hf, "mcp.crypto_scanner_run", get_server(), "crypto_scanner_run", args, passed, failed, skipped);
    }

    void test_tool_crypto_scanner_get_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.crypto_scanner_get_results", get_server(), "crypto_scanner_get_results", {}, passed, failed, skipped);
    }


    void test_tool_disasm_jump_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_jump_to_address", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_jump_to_address", get_server(), "disasm_jump_to_address", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_instruction(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_instruction", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_instruction", get_server(), "disasm_get_instruction", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_function_bounds(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_function_bounds", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_function_bounds", get_server(), "disasm_get_function_bounds", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_function_disassembly(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_function_disassembly", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_function_disassembly", get_server(), "disasm_get_function_disassembly", args, passed, failed, skipped);
    }

    void test_tool_disasm_list_functions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.disasm_list_functions", get_server(), "disasm_list_functions", {}, passed, failed, skipped);
    }

    void test_tool_disasm_get_xrefs_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_xrefs_to", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_xrefs_to", get_server(), "disasm_get_xrefs_to", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_xrefs_from(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_xrefs_from", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_xrefs_from", get_server(), "disasm_get_xrefs_from", args, passed, failed, skipped);
    }

    void test_tool_disasm_set_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_set_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["text"] = "test";
        test_tool_call(hf, "mcp.disasm_set_comment", get_server(), "disasm_set_comment", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_comment", get_server(), "disasm_get_comment", args, passed, failed, skipped);
    }

    void test_tool_disasm_rename_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_rename_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["name"] = "test_func";
        test_tool_call(hf, "mcp.disasm_rename_function", get_server(), "disasm_rename_function", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_section_info(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.disasm_get_section_info", get_server(), "disasm_get_section_info", {}, passed, failed, skipped);
    }

    void test_tool_disasm_search_bytes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pattern"] = "48 89 5C";
        test_tool_call(hf, "mcp.disasm_search_bytes", get_server(), "disasm_search_bytes", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.disasm_get_strings", get_server(), "disasm_get_strings", {}, passed, failed, skipped);
    }

    void test_tool_ui_set_active_view(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["view"] = "disasm";
        test_tool_call(hf, "mcp.ui_set_active_view", get_server(), "ui_set_active_view", args, passed, failed, skipped);
    }

    void test_tool_bookmarks_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.bookmarks_add", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.bookmarks_add", get_server(), "bookmarks_add", args, passed, failed, skipped);
    }

    void test_tool_bookmarks_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.bookmarks_remove", get_server(), "bookmarks_remove", args, passed, failed, skipped);
    }

    void test_tool_bookmarks_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.bookmarks_list", get_server(), "bookmarks_list", {}, passed, failed, skipped);
    }

    void test_tool_hex_view_open(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntdll_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.hex_view_open", "SKIP -- ntdll not loaded"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.hex_view_open", get_server(), "hex_view_open", args, passed, failed, skipped);
    }


    void test_tool_sessions_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.sessions_list", get_server(), "sessions_list", {}, passed, failed, skipped);
    }

    void test_tool_sessions_get_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.sessions_get_active", get_server(), "sessions_get_active", {}, passed, failed, skipped);
    }

    void test_tool_sessions_switch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["binary_id"] = "nonexistent";
        test_tool_call(hf, "mcp.sessions_switch", get_server(), "sessions_switch", args, passed, failed, skipped);
    }

    void test_tool_sessions_open_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_small_pe_fixture_path();
        test_tool_call(hf, "mcp.sessions_open_file", get_server(), "sessions_open_file", args, passed, failed, skipped);
    }

    void test_tool_sessions_attach_pid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pid"] = 0;
        test_tool_call(hf, "mcp.sessions_attach_pid", get_server(), "sessions_attach_pid", args, passed, failed, skipped);
    }

    void test_tool_sessions_close(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["binary_id"] = "nonexistent";
        test_tool_call(hf, "mcp.sessions_close", get_server(), "sessions_close", args, passed, failed, skipped);
    }

    void test_tool_sessions_run_binary(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\Windows\\System32\\cmd.exe";
        args["args"] = "/c echo test";
        test_tool_call(hf, "mcp.sessions_run_binary", get_server(), "sessions_run_binary", args, passed, failed, skipped);
    }

    void test_tool_sessions_create(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "__test_session_mcp_test__";
        test_tool_call(hf, "mcp.sessions_create", get_server(), "sessions_create", args, passed, failed, skipped);
    }

    void test_tool_sessions_export(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.sessions_export", get_server(), "sessions_export", {}, passed, failed, skipped);
    }

    void test_tool_sessions_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.sessions_stats", get_server(), "sessions_stats", {}, passed, failed, skipped);
    }


    void test_tool_switch_agent(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["agent"] = "build";
        test_tool_call(hf, "mcp.switch_agent", get_server(), "switch_agent", args, passed, failed, skipped);
    }

    void test_tool_plan_enter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.plan_enter", get_server(), "plan_enter", {}, passed, failed, skipped);
    }

    void test_tool_plan_exit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.plan_exit", get_server(), "plan_exit", {}, passed, failed, skipped);
    }

    void test_tool_list_agents(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.list_agents", get_server(), "list_agents", {}, passed, failed, skipped);
    }

    void test_tool_ask_followup_question(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["question"] = "test question";
        test_tool_call(hf, "mcp.ask_followup_question", get_server(), "ask_followup_question", args, passed, failed, skipped);
    }

    void test_tool_attempt_completion(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["result"] = "test result";
        test_tool_call(hf, "mcp.attempt_completion", get_server(), "attempt_completion", args, passed, failed, skipped);
    }

    void test_tool_update_todo_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["content"] = "- [ ] test item";
        test_tool_call(hf, "mcp.update_todo_list", get_server(), "update_todo_list", args, passed, failed, skipped);
    }

    void test_tool_apply_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "nonexistent.txt";
        args["diff"] = "--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new";
        test_tool_call(hf, "mcp.apply_diff", get_server(), "apply_diff", args, passed, failed, skipped);
    }

    void test_tool_apply_patch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["patch"] = "*** Begin Patch\n*** End Patch";
        test_tool_call(hf, "mcp.apply_patch", get_server(), "apply_patch", args, passed, failed, skipped);
    }

    void test_tool_codebase_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["query"] = "main";
        test_tool_call(hf, "mcp.codebase_search", get_server(), "codebase_search", args, passed, failed, skipped);
    }

    void test_tool_read_command_output(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["session_id"] = "nonexistent";
        test_tool_call(hf, "mcp.read_command_output", get_server(), "read_command_output", args, passed, failed, skipped);
    }

    void test_tool_save_checkpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["message"] = "test_checkpoint";
        test_tool_call(hf, "mcp.save_checkpoint", get_server(), "save_checkpoint", args, passed, failed, skipped);
    }

    void test_tool_restore_checkpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["checkpoint_id"] = "nonexistent";
        test_tool_call(hf, "mcp.restore_checkpoint", get_server(), "restore_checkpoint", args, passed, failed, skipped);
    }

    void test_tool_list_checkpoints(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.list_checkpoints", get_server(), "list_checkpoints", {}, passed, failed, skipped);
    }

    void test_tool_checkpoint_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.checkpoint_list", get_server(), "checkpoint_list", {}, passed, failed, skipped);
    }

    void test_tool_skill(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "nonexistent";
        test_tool_call(hf, "mcp.skill", get_server(), "skill", args, passed, failed, skipped);
    }

    void test_tool_run_slash_command(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["command"] = "help";
        test_tool_call(hf, "mcp.run_slash_command", get_server(), "run_slash_command", args, passed, failed, skipped);
    }

    void test_tool_get_context(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.get_context", get_server(), "get_context", {}, passed, failed, skipped);
    }

    void test_tool_workflow_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.workflow_status", get_server(), "workflow_status", {}, passed, failed, skipped);
    }

    void test_tool_task(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["agent"] = "general";
        args["prompt"] = "test";
        test_tool_call(hf, "mcp.task", get_server(), "task", args, passed, failed, skipped);
    }


    void test_tool_search_workspace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["query"] = "main";
        test_tool_call(hf, "mcp.search_workspace", get_server(), "search_workspace", args, passed, failed, skipped);
    }

    void test_tool_run_command(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["command"] = "echo test";
        test_tool_call(hf, "mcp.run_command", get_server(), "run_command", args, passed, failed, skipped);
    }

    void test_tool_cancel_command(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["session_id"] = "nonexistent";
        test_tool_call(hf, "mcp.cancel_command", get_server(), "cancel_command", args, passed, failed, skipped);
    }

    void test_tool_list_commands(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.list_commands", get_server(), "list_commands", {}, passed, failed, skipped);
    }


    void test_tool_disassemble_zydis(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disassemble_zydis", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disassemble_zydis", get_server(), "disassemble_zydis", args, passed, failed, skipped);
    }

    void test_tool_driver_snapshot_and_emulate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.driver_snapshot_and_emulate", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.driver_snapshot_and_emulate", get_server(), "driver_snapshot_and_emulate", args, passed, failed, skipped);
    }

    void test_tool_trace_execution_unicorn(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.trace_execution_unicorn", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.trace_execution_unicorn", get_server(), "trace_execution_unicorn", args, passed, failed, skipped);
    }

    void test_tool_analyze_vm_handler(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.analyze_vm_handler", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.analyze_vm_handler", get_server(), "analyze_vm_handler", args, passed, failed, skipped);
    }

    void test_tool_emulate_multi_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.emulate_multi_trace", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.emulate_multi_trace", get_server(), "emulate_multi_trace", args, passed, failed, skipped);
    }

    void test_tool_emulate_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.emulate_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.emulate_function", get_server(), "emulate_function", args, passed, failed, skipped);
    }


    void test_tool_network_enumerate_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_enumerate_conns", get_server(), "network_enumerate_connections", {}, passed, failed, skipped);
    }

    void test_tool_network_start_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        if (g_mcp_target_pid != 0)
            args["pid"] = g_mcp_target_pid;
        args["protocol"] = "tcp";
        args["max_payload"] = 256;
        test_tool_call(hf, "mcp.network_start_capture", get_server(), "network_start_capture", args, passed, failed, skipped);
    }

    void test_tool_network_stop_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_stop_capture", get_server(), "network_stop_capture", {}, passed, failed, skipped);
    }

    void test_tool_network_get_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_get_packets", get_server(), "network_get_packets", {}, passed, failed, skipped);
    }

    void test_tool_network_analyze_packet(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_analyze_packet", get_server(), "network_analyze_packet", args, passed, failed, skipped);
    }

    void test_tool_network_dns_log(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_dns_log", get_server(), "network_dns_log", {}, passed, failed, skipped);
    }

    void test_tool_network_add_filter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["action"] = "log";
        args["direction"] = "both";
        args["protocol"] = "tcp";
        args["port"] = 65534;
        test_tool_call(hf, "mcp.network_add_filter", get_server(), "network_add_filter", args, passed, failed, skipped);
    }

    void test_tool_network_remove_filter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, "mcp.network_remove_filter", "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        std::uint32_t rule_id = 0;
        if (!driver_bridge::add_filter_rule(2, 2, 6, 0, 65533, nullptr, nullptr, &rule_id) || rule_id == 0) {
            log_msg(hf, "mcp.network_remove_filter", "SKIP -- setup add_filter_rule failed");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["rule_id"] = rule_id;
        test_tool_call(hf, "mcp.network_remove_filter", get_server(), "network_remove_filter", args, passed, failed, skipped);
    }

    void test_tool_network_clear_filters(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_clear_filters", get_server(), "network_clear_filters", {}, passed, failed, skipped);
    }

    void test_tool_network_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_stats", get_server(), "network_stats", {}, passed, failed, skipped);
    }

    void test_tool_network_capture_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_capture_status", get_server(), "network_capture_status", {}, passed, failed, skipped);
    }

    void test_tool_network_block_ip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["ip"] = "203.0.113.254";
        args["direction"] = "both";
        test_tool_call(hf, "mcp.network_block_ip", get_server(), "network_block_ip", args, passed, failed, skipped);
    }

    void test_tool_network_block_port(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["port"] = 65534;
        test_tool_call(hf, "mcp.network_block_port", get_server(), "network_block_port", args, passed, failed, skipped);
    }

    void test_tool_network_block_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pid"] = 999999;
        test_tool_call(hf, "mcp.network_block_process", get_server(), "network_block_process", args, passed, failed, skipped);
    }

    void test_tool_network_deep_inspect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_deep_inspect", get_server(), "network_deep_inspect", args, passed, failed, skipped);
    }

    void test_tool_network_follow_tcp_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_follow_tcp_stream", get_server(), "network_follow_tcp_stream", args, passed, failed, skipped);
    }

    void test_tool_network_parse_http(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_parse_http", get_server(), "network_parse_http", args, passed, failed, skipped);
    }

    void test_tool_network_parse_tls(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_parse_tls", get_server(), "network_parse_tls", args, passed, failed, skipped);
    }

    void test_tool_network_enumerate_wfp_callouts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_enumerate_wfp_callouts", get_server(), "network_enumerate_wfp_callouts", {}, passed, failed, skipped);
    }

    void test_tool_network_get_socket_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_get_socket_handles", get_server(), "network_get_socket_handles", {}, passed, failed, skipped);
    }

    void test_tool_network_dump_tcpip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_dump_tcpip", get_server(), "network_dump_tcpip", {}, passed, failed, skipped);
    }

    void test_tool_network_enumerate_interfaces(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_enumerate_interfaces", get_server(), "network_enumerate_interfaces", {}, passed, failed, skipped);
    }

    void test_tool_network_list_interfaces(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_list_interfaces", get_server(), "network_enumerate_interfaces", {}, passed, failed, skipped);
    }

    void test_tool_network_inject_packet(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["protocol"] = "udp";
        args["src_ip"] = "127.0.0.1";
        args["dst_ip"] = "127.0.0.1";
        args["src_port"] = 65534;
        args["dst_port"] = 65533;
        args["payload_hex"] = "00";
        test_tool_call(hf, "mcp.network_inject_packet", get_server(), "network_inject_packet", args, passed, failed, skipped);
    }

    void test_tool_network_modify_packet_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "add";
        args["direction"] = "both";
        args["protocol"] = "tcp";
        args["port"] = 65534;
        args["pattern_hex"] = "41";
        args["replacement_hex"] = "42";
        test_tool_call(hf, "mcp.network_modify_packet_rule", get_server(), "network_modify_packet_rule", args, passed, failed, skipped);
    }

    void test_tool_network_list_mod_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_list_mod_rules", get_server(), "network_list_mod_rules", {}, passed, failed, skipped);
    }

    void test_tool_network_redirect_traffic(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "add";
        args["protocol"] = "tcp";
        args["match_port"] = 65534;
        args["redirect_port"] = 65533;
        args["match_ip"] = "127.0.0.1";
        args["redirect_ip"] = "127.0.0.1";
        test_tool_call(hf, "mcp.network_redirect_traffic", get_server(), "network_redirect_traffic", args, passed, failed, skipped);
    }

    void test_tool_network_list_redirect_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_list_redirect_rules", get_server(), "network_list_redirect_rules", {}, passed, failed, skipped);
    }

    void test_tool_network_intercept(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "disable";
        test_tool_call(hf, "mcp.network_intercept", get_server(), "network_intercept", args, passed, failed, skipped);
    }

    void test_tool_network_get_held_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_get_held_packets", get_server(), "network_get_held_packets", {}, passed, failed, skipped);
    }

    void test_tool_network_release_packet(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_release_packet", get_server(), "network_release_packet", args, passed, failed, skipped);
    }

    void test_tool_network_kill_connection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_loopback_tcp_pair_t pair;
        if (!pair.open(hf, "mcp.network_kill_connection")) {
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["protocol"] = "tcp";
        args["src_ip"] = "127.0.0.1";
        args["dst_ip"] = "127.0.0.1";
        args["src_port"] = pair.client_port;
        args["dst_port"] = pair.listen_port;
        args["pid"] = GetCurrentProcessId();
        test_tool_call(hf, "mcp.network_kill_connection", get_server(), "network_kill_connection", args, passed, failed, skipped);
    }

    void test_tool_network_spoof_dns(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "add";
        args["domain"] = "aida-mcp-test.invalid";
        args["spoof_ip"] = "127.0.0.1";
        args["ttl"] = 30;
        test_tool_call(hf, "mcp.network_spoof_dns", get_server(), "network_spoof_dns", args, passed, failed, skipped);
    }

    void test_tool_network_list_dns_spoof_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_list_dns_spoof_rules", get_server(), "network_list_dns_spoof_rules", {}, passed, failed, skipped);
    }

    void test_tool_network_bandwidth_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "get";
        test_tool_call(hf, "mcp.network_bandwidth_monitor", get_server(), "network_bandwidth_monitor", args, passed, failed, skipped);
    }

    void test_tool_network_bandwidth_per_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_bandwidth_per_process", get_server(), "network_bandwidth_per_process", {}, passed, failed, skipped);
    }

    void test_tool_network_os_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "get";
        test_tool_call(hf, "mcp.network_os_fingerprint", get_server(), "network_os_fingerprint", args, passed, failed, skipped);
    }

    void test_tool_network_export_pcap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\temp\\aida_test_net.pcap";
        test_tool_call(hf, "mcp.network_export_pcap", get_server(), "network_export_pcap", args, passed, failed, skipped);
    }

    void test_tool_network_decode_data(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["input"] = "dGVzdA==";
        args["pipeline"] = mcp_standalone::json::array({ {{"name", "base64_decode"}} });
        test_tool_call(hf, "mcp.network_decode_data", get_server(), "network_decode_data", args, passed, failed, skipped);
    }

    void test_tool_network_list_transforms(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_list_transforms", get_server(), "network_list_transforms", {}, passed, failed, skipped);
    }

    void test_tool_network_script_load(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "nonexistent.lua";
        test_tool_call(hf, "mcp.network_script_load", get_server(), "network_script_load", args, passed, failed, skipped);
    }

    void test_tool_network_script_unload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "nonexistent";
        test_tool_call(hf, "mcp.network_script_unload", get_server(), "network_script_unload", args, passed, failed, skipped);
    }

    void test_tool_network_script_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["code"] = "return 1";
        test_tool_call(hf, "mcp.network_script_execute", get_server(), "network_script_execute", args, passed, failed, skipped);
    }

    void test_tool_network_script_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_script_list", get_server(), "network_script_list", {}, passed, failed, skipped);
    }

    void test_tool_network_script_api(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_script_api", get_server(), "network_script_api", {}, passed, failed, skipped);
    }

    void test_tool_network_stream_track(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "get_all";
        test_tool_call(hf, "mcp.network_stream_track", get_server(), "network_stream_track", args, passed, failed, skipped);
    }

    void test_tool_network_pg_sniff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "list_sessions";
        test_tool_call(hf, "mcp.network_pg_sniff", get_server(), "network_pg_sniff", args, passed, failed, skipped);
    }

    void test_tool_network_packet_callstack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "recent";
        args["max_count"] = 8;
        test_tool_call(hf, "mcp.network_packet_callstack", get_server(), "network_packet_callstack", args, passed, failed, skipped);
    }

    void test_tool_network_pre_encrypt_hook(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "status";
        test_tool_call(hf, "mcp.network_pre_encrypt_hook", get_server(), "network_pre_encrypt_hook", args, passed, failed, skipped);
    }

    void test_tool_network_display_filter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "validate";
        args["expression"] = "tcp";
        test_tool_call(hf, "mcp.network_display_filter", get_server(), "network_display_filter", args, passed, failed, skipped);
    }

    void test_tool_network_protobuf_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "decode";
        args["hex_data"] = "0801";
        test_tool_call(hf, "mcp.network_protobuf_decode", get_server(), "network_protobuf_decode", args, passed, failed, skipped);
    }

    void test_tool_network_fuzzer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "status";
        test_tool_call(hf, "mcp.network_fuzzer", get_server(), "network_fuzzer", args, passed, failed, skipped);
    }

    void test_tool_network_websocket(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "list_frames";
        test_tool_call(hf, "mcp.network_websocket", get_server(), "network_websocket", args, passed, failed, skipped);
    }

    void test_tool_network_proxy(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["action"] = "status";
        test_tool_call(hf, "mcp.network_proxy", get_server(), "network_proxy", args, passed, failed, skipped);
    }

    void test_tool_network_repeater(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "list";
        test_tool_call(hf, "mcp.network_repeater", get_server(), "network_repeater", args, passed, failed, skipped);
    }

    void test_tool_mitm_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "status";
        test_tool_call(hf, "mcp.mitm_status", get_server(), "network_proxy", args, passed, failed, skipped);
    }


    void test_tool_tls_extract_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.tls_extract_keys", get_server(), "tls_extract_keys", {}, passed, failed, skipped);
    }

    void test_tool_tls_start_keylog(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.tls_start_keylog", get_server(), "tls_start_keylog", {}, passed, failed, skipped);
    }

    void test_tool_tls_stop_keylog(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.tls_stop_keylog", get_server(), "tls_stop_keylog", {}, passed, failed, skipped);
    }

    void test_tool_tls_get_extracted_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.tls_get_extracted_keys", get_server(), "tls_get_extracted_keys", {}, passed, failed, skipped);
    }

    void test_tool_cert_inject(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "nonexistent.pem";
        test_tool_call(hf, "mcp.cert_inject", get_server(), "cert_inject", args, passed, failed, skipped);
    }

    void test_tool_cert_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["thumbprint"] = "0000";
        test_tool_call(hf, "mcp.cert_remove", get_server(), "cert_remove", args, passed, failed, skipped);
    }

    void test_tool_cert_generate_ca(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.cert_generate_ca", get_server(), "cert_generate_ca", {}, passed, failed, skipped);
    }

    void test_tool_cert_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.cert_list", get_server(), "cert_list", {}, passed, failed, skipped);
    }

    void test_tool_pin_bypass(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.pin_bypass", get_server(), "pin_bypass", {}, passed, failed, skipped);
    }

    void test_tool_pin_bypass_revert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.pin_bypass_revert", get_server(), "pin_bypass_revert", {}, passed, failed, skipped);
    }

    void test_tool_pin_bypass_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.pin_bypass_status", get_server(), "pin_bypass_status", {}, passed, failed, skipped);
    }

    void test_tool_quic_detect_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.quic_detect_connections", get_server(), "quic_detect_connections", {}, passed, failed, skipped);
    }

    void test_tool_quic_decrypt_initial(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.quic_decrypt_initial", get_server(), "quic_decrypt_initial", args, passed, failed, skipped);
    }

    void test_tool_quic_extract_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.quic_extract_keys", get_server(), "quic_extract_keys", {}, passed, failed, skipped);
    }

    void test_tool_dtls_detect_sessions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dtls_detect_sessions", get_server(), "dtls_detect_sessions", {}, passed, failed, skipped);
    }

    void test_tool_dtls_extract_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dtls_extract_keys", get_server(), "dtls_extract_keys", {}, passed, failed, skipped);
    }

    void test_tool_autoresponder_add_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["match_url"] = "test.local";
        args["response_body"] = "test";
        test_tool_call(hf, "mcp.autoresponder_add_rule", get_server(), "autoresponder_add_rule", args, passed, failed, skipped);
    }

    void test_tool_autoresponder_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.autoresponder_remove_rule", get_server(), "autoresponder_remove_rule", args, passed, failed, skipped);
    }

    void test_tool_autoresponder_list_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.autoresponder_list_rules", get_server(), "autoresponder_list_rules", {}, passed, failed, skipped);
    }

    void test_tool_autoresponder_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.autoresponder_start", get_server(), "autoresponder_start", {}, passed, failed, skipped);
    }

    void test_tool_autoresponder_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.autoresponder_stop", get_server(), "autoresponder_stop", {}, passed, failed, skipped);
    }

    void test_tool_autoresponder_import_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "nonexistent.json";
        test_tool_call(hf, "mcp.autoresponder_import_rules", get_server(), "autoresponder_import_rules", args, passed, failed, skipped);
    }

    void test_tool_autoresponder_export_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\temp\\aida_test_rules.json";
        test_tool_call(hf, "mcp.autoresponder_export_rules", get_server(), "autoresponder_export_rules", args, passed, failed, skipped);
    }

    void test_tool_network_decrypt_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pcap_path"] = temp_file_narrow("aida_missing_capture.pcap");
        args["keylog_path"] = "nonexistent.log";
        test_tool_call(hf, "mcp.network_decrypt_capture", get_server(), "network_decrypt_capture", args, passed, failed, skipped);
    }

    void test_tool_tls_ensure_keylogfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.tls_ensure_keylogfile", get_server(), "tls_ensure_keylogfile", {}, passed, failed, skipped);
    }

    void test_tool_burp_scanner_start_audit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_scanner_start_audit", get_server(), "burp_scanner_start_audit", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_audit_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["audit_id"] = 0;
        test_tool_call(hf, "mcp.burp_scanner_audit_status", get_server(), "burp_scanner_audit_status", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_list_audits(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scanner_list_audits", get_server(), "burp_scanner_list_audits", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_cancel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["audit_id"] = 0;
        test_tool_call(hf, "mcp.burp_scanner_cancel", get_server(), "burp_scanner_cancel", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_list_issues(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scanner_list_issues", get_server(), "burp_scanner_list_issues", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_get_issue(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["issue_id"] = 0;
        test_tool_call(hf, "mcp.burp_scanner_get_issue", get_server(), "burp_scanner_get_issue", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_passive_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scanner_passive_status", get_server(), "burp_scanner_passive_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_list_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scanner_list_modules", get_server(), "burp_scanner_list_modules", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_clear_issues(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scanner_clear_issues", get_server(), "burp_scanner_clear_issues", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_passive_enable(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["enabled"] = false;
        test_tool_call(hf, "mcp.burp_scanner_passive_enable", get_server(), "burp_scanner_passive_enable", args, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_list_hosts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_sitemap_list_hosts", get_server(), "burp_sitemap_list_hosts", {}, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_list_paths(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_sitemap_list_paths", get_server(), "burp_sitemap_list_paths", {}, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_get_exchange(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["exchange_id"] = 0;
        test_tool_call(hf, "mcp.burp_sitemap_get_exchange", get_server(), "burp_sitemap_get_exchange", args, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_send_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["exchange_id"] = 0; args["destination"] = "repeater";
        test_tool_call(hf, "mcp.burp_sitemap_send_to", get_server(), "burp_sitemap_send_to", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_scope_add", get_server(), "burp_scope_add", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_scope_remove", get_server(), "burp_scope_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scope_list", get_server(), "burp_scope_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_scope_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_scope_check", get_server(), "burp_scope_check", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_cookie_list", get_server(), "burp_cookie_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_cookie_set(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_cookie"; args["value"] = "test_val"; args["domain"] = "127.0.0.1";
        test_tool_call(hf, "mcp.burp_cookie_set", get_server(), "burp_cookie_set", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_cookie"; args["domain"] = "127.0.0.1";
        test_tool_call(hf, "mcp.burp_cookie_delete", get_server(), "burp_cookie_delete", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_export_netscape(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_cookie_export_netscape", get_server(), "burp_cookie_export_netscape", {}, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_dom_xss_status", get_server(), "burp_dom_xss_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_test_payload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["payload"] = "<script>test</script>";
        test_tool_call(hf, "mcp.burp_dom_xss_test_payload", get_server(), "burp_dom_xss_test_payload", args, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_dom_xss_scan", get_server(), "burp_dom_xss_scan", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_crawler_start", get_server(), "burp_crawler_start", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crawler_id"] = 0;
        test_tool_call(hf, "mcp.burp_crawler_status", get_server(), "burp_crawler_status", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crawler_id"] = 0;
        test_tool_call(hf, "mcp.burp_crawler_stop", get_server(), "burp_crawler_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_crawler_list", get_server(), "burp_crawler_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_content_discovery_start", get_server(), "burp_content_discovery_start", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_content_discovery_status", get_server(), "burp_content_discovery_status", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_content_discovery_results", get_server(), "burp_content_discovery_results", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_content_discovery_stop", get_server(), "burp_content_discovery_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["domain"] = "test.local";
        test_tool_call(hf, "mcp.burp_subdomain_enum_start", get_server(), "burp_subdomain_enum_start", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_subdomain_enum_status", get_server(), "burp_subdomain_enum_status", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_subdomain_enum_results", get_server(), "burp_subdomain_enum_results", args, passed, failed, skipped);
    }
    void test_tool_burp_payloads_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_payloads_list", get_server(), "burp_payloads_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_payloads_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "xss";
        test_tool_call(hf, "mcp.burp_payloads_get", get_server(), "burp_payloads_get", args, passed, failed, skipped);
    }
    void test_tool_burp_payloads_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["query"] = "xss";
        test_tool_call(hf, "mcp.burp_payloads_search", get_server(), "burp_payloads_search", args, passed, failed, skipped);
    }
    void test_tool_burp_payloads_add_custom(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_payload"; args["content"] = "test";
        test_tool_call(hf, "mcp.burp_payloads_add_custom", get_server(), "burp_payloads_add_custom", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/"; args["raw_request"] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        test_tool_call(hf, "mcp.burp_intruder_start", get_server(), "burp_intruder_start", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_intruder_status", get_server(), "burp_intruder_status", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_intruder_results", get_server(), "burp_intruder_results", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_intruder_stop", get_server(), "burp_intruder_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_intruder_list_jobs", get_server(), "burp_intruder_list_jobs", {}, passed, failed, skipped);
    }
    void test_tool_burp_intruder_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_intruder_clear", get_server(), "burp_intruder_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_param_miner_start", get_server(), "burp_param_miner_start", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_param_miner_status", get_server(), "burp_param_miner_status", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_param_miner_results", get_server(), "burp_param_miner_results", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_param_miner_stop", get_server(), "burp_param_miner_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_h2_send(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_h2_send", get_server(), "burp_h2_send", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_call(hf, "mcp.burp_jwt_decode", get_server(), "burp_jwt_decode", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_forge(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["header"] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"; args["payload"] = "{\"sub\":\"test\"}";
        test_tool_call(hf, "mcp.burp_jwt_forge", get_server(), "burp_jwt_forge", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_verify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_call(hf, "mcp.burp_jwt_verify", get_server(), "burp_jwt_verify", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_crack_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_call(hf, "mcp.burp_jwt_crack_start", get_server(), "burp_jwt_crack_start", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_crack_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_jwt_crack_status", get_server(), "burp_jwt_crack_status", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_crack_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = 0;
        test_tool_call(hf, "mcp.burp_jwt_crack_stop", get_server(), "burp_jwt_crack_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_attack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_call(hf, "mcp.burp_jwt_attack", get_server(), "burp_jwt_attack", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_basic_encode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["username"] = "test"; args["password"] = "test";
        test_tool_call(hf, "mcp.burp_auth_basic_encode", get_server(), "burp_auth_basic_encode", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_basic_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["encoded"] = "dGVzdDp0ZXN0";
        test_tool_call(hf, "mcp.burp_auth_basic_decode", get_server(), "burp_auth_basic_decode", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_digest_solve(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["username"] = "test"; args["password"] = "test";
        args["realm"] = "test"; args["nonce"] = "test"; args["uri"] = "/";
        test_tool_call(hf, "mcp.burp_auth_digest_solve", get_server(), "burp_auth_digest_solve", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_ntlm_type1(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_auth_ntlm_type1", get_server(), "burp_auth_ntlm_type1", {}, passed, failed, skipped);
    }
    void test_tool_burp_auth_ntlm_type3(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["username"] = "test"; args["password"] = "test"; args["challenge"] = "0000000000000000";
        test_tool_call(hf, "mcp.burp_auth_ntlm_type3", get_server(), "burp_auth_ntlm_type3", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_bearer(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "test_token";
        test_tool_call(hf, "mcp.burp_auth_bearer", get_server(), "burp_auth_bearer", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_oauth2_pkce(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_auth_oauth2_pkce", get_server(), "burp_auth_oauth2_pkce", {}, passed, failed, skipped);
    }
    void test_tool_burp_auth_oauth2_build_auth_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["client_id"] = "test"; args["auth_endpoint"] = "http://127.0.0.1/auth"; args["redirect_uri"] = "http://127.0.0.1/cb";
        test_tool_call(hf, "mcp.burp_auth_oauth2_build_auth_url", get_server(), "burp_auth_oauth2_build_auth_url", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_oauth2_exchange_code(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["code"] = "test_code"; args["token_endpoint"] = "http://127.0.0.1/token"; args["client_id"] = "test"; args["redirect_uri"] = "http://127.0.0.1/cb";
        test_tool_call(hf, "mcp.burp_auth_oauth2_exchange_code", get_server(), "burp_auth_oauth2_exchange_code", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_oauth2_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["refresh_token"] = "test_refresh"; args["token_endpoint"] = "http://127.0.0.1/token"; args["client_id"] = "test";
        test_tool_call(hf, "mcp.burp_auth_oauth2_refresh", get_server(), "burp_auth_oauth2_refresh", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_saml_decode_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["saml_request"] = "dGVzdA==";
        test_tool_call(hf, "mcp.burp_auth_saml_decode_request", get_server(), "burp_auth_saml_decode_request", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_saml_decode_response(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["saml_response"] = "dGVzdA==";
        test_tool_call(hf, "mcp.burp_auth_saml_decode_response", get_server(), "burp_auth_saml_decode_response", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["match"] = "test_match"; args["replace"] = "test_replace";
        test_tool_call(hf, "mcp.burp_match_replace_add", get_server(), "burp_match_replace_add", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_update(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0; args["match"] = "test_match2"; args["replace"] = "test_replace2";
        test_tool_call(hf, "mcp.burp_match_replace_update", get_server(), "burp_match_replace_update", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0;
        test_tool_call(hf, "mcp.burp_match_replace_remove", get_server(), "burp_match_replace_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_match_replace_list", get_server(), "burp_match_replace_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_match_replace_clear", get_server(), "burp_match_replace_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_test(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["match"] = "test"; args["data"] = "test data";
        test_tool_call(hf, "mcp.burp_match_replace_test", get_server(), "burp_match_replace_test", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_macro"; args["request"] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        test_tool_call(hf, "mcp.burp_macro_add", get_server(), "burp_macro_add", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_run(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_macro";
        test_tool_call(hf, "mcp.burp_macro_run", get_server(), "burp_macro_run", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_macro_list", get_server(), "burp_macro_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_macro_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_macro";
        test_tool_call(hf, "mcp.burp_macro_remove", get_server(), "burp_macro_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_update(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_macro";
        test_tool_call(hf, "mcp.burp_macro_update", get_server(), "burp_macro_update", args, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "test_rule"; args["condition"] = "always";
        test_tool_call(hf, "mcp.burp_session_rule_add", get_server(), "burp_session_rule_add", args, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_session_rule_list", get_server(), "burp_session_rule_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0;
        test_tool_call(hf, "mcp.burp_session_rule_remove", get_server(), "burp_session_rule_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_api_import(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["path"] = "nonexistent.json";
        test_tool_call(hf, "mcp.burp_api_import", get_server(), "burp_api_import", args, passed, failed, skipped);
    }
    void test_tool_burp_api_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_api_list_collections", get_server(), "burp_api_list_collections", {}, passed, failed, skipped);
    }
    void test_tool_burp_api_get_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "nonexistent";
        test_tool_call(hf, "mcp.burp_api_get_collection", get_server(), "burp_api_get_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_api_remove_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "nonexistent";
        test_tool_call(hf, "mcp.burp_api_remove_collection", get_server(), "burp_api_remove_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_api_send_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection"] = "nonexistent"; args["request_name"] = "test";
        test_tool_call(hf, "mcp.burp_api_send_request", get_server(), "burp_api_send_request", args, passed, failed, skipped);
    }
    void test_tool_burp_api_audit_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "nonexistent";
        test_tool_call(hf, "mcp.burp_api_audit_collection", get_server(), "burp_api_audit_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_introspect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/graphql";
        test_tool_call(hf, "mcp.burp_graphql_introspect", get_server(), "burp_graphql_introspect", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_example(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/graphql"; args["query"] = "{ __typename }";
        test_tool_call(hf, "mcp.burp_graphql_example", get_server(), "burp_graphql_example", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_send(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/graphql"; args["query"] = "{ __typename }";
        test_tool_call(hf, "mcp.burp_graphql_send", get_server(), "burp_graphql_send", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_connect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "ws://127.0.0.1/ws";
        test_tool_call(hf, "mcp.burp_ws_connect", get_server(), "burp_ws_connect", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_disconnect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = 0;
        test_tool_call(hf, "mcp.burp_ws_disconnect", get_server(), "burp_ws_disconnect", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_send_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = 0; args["message"] = "test";
        test_tool_call(hf, "mcp.burp_ws_send_text", get_server(), "burp_ws_send_text", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_send_binary(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = 0; args["data_hex"] = "00";
        test_tool_call(hf, "mcp.burp_ws_send_binary", get_server(), "burp_ws_send_binary", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_send_raw(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = 0; args["data"] = "test";
        test_tool_call(hf, "mcp.burp_ws_send_raw", get_server(), "burp_ws_send_raw", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_list_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_ws_list_connections", get_server(), "burp_ws_list_connections", {}, passed, failed, skipped);
    }
    void test_tool_burp_ws_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = 0;
        test_tool_call(hf, "mcp.burp_ws_frames", get_server(), "burp_ws_frames", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_clear_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = 0;
        test_tool_call(hf, "mcp.burp_ws_clear_frames", get_server(), "burp_ws_clear_frames", args, passed, failed, skipped);
    }
    void test_tool_burp_logger_query(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_logger_query", get_server(), "burp_logger_query", {}, passed, failed, skipped);
    }
    void test_tool_burp_logger_total(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_logger_total", get_server(), "burp_logger_total", {}, passed, failed, skipped);
    }
    void test_tool_burp_logger_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_logger_clear", get_server(), "burp_logger_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_logger_export_csv(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["path"] = "C:\\temp\\aida_logger_test.csv";
        test_tool_call(hf, "mcp.burp_logger_export_csv", get_server(), "burp_logger_export_csv", args, passed, failed, skipped);
    }
    void test_tool_burp_report_generate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["path"] = "C:\\temp\\aida_burp_report.html";
        test_tool_call(hf, "mcp.burp_report_generate", get_server(), "burp_report_generate", args, passed, failed, skipped);
    }
    void test_tool_burp_bambda_compile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["code"] = "return true;";
        test_tool_call(hf, "mcp.burp_bambda_compile", get_server(), "burp_bambda_compile", args, passed, failed, skipped);
    }
    void test_tool_burp_bambda_test(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["code"] = "return true;";
        test_tool_call(hf, "mcp.burp_bambda_test", get_server(), "burp_bambda_test", args, passed, failed, skipped);
    }
    void test_tool_burp_bambda_help(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_bambda_help", get_server(), "burp_bambda_help", {}, passed, failed, skipped);
    }
    void test_tool_burp_csp_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["policy"] = "default-src 'self'";
        test_tool_call(hf, "mcp.burp_csp_analyze", get_server(), "burp_csp_analyze", args, passed, failed, skipped);
    }
    void test_tool_burp_csp_analyze_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_csp_analyze_url", get_server(), "burp_csp_analyze_url", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_add_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["port"] = 8888; args["protocol"] = "http";
        test_tool_call(hf, "mcp.burp_upstream_add_chain", get_server(), "burp_upstream_add_chain", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_remove_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0;
        test_tool_call(hf, "mcp.burp_upstream_remove_chain", get_server(), "burp_upstream_remove_chain", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_list_chains(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_upstream_list_chains", get_server(), "burp_upstream_list_chains", {}, passed, failed, skipped);
    }
    void test_tool_burp_upstream_set_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0;
        test_tool_call(hf, "mcp.burp_upstream_set_active", get_server(), "burp_upstream_set_active", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_get_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_upstream_get_active", get_server(), "burp_upstream_get_active", {}, passed, failed, skipped);
    }
    void test_tool_burp_upstream_test_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0;
        test_tool_call(hf, "mcp.burp_upstream_test_chain", get_server(), "burp_upstream_test_chain", args, passed, failed, skipped);
    }
    void test_tool_burp_tech_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_tech_fingerprint", get_server(), "burp_tech_fingerprint", args, passed, failed, skipped);
    }
    void test_tool_burp_tech_inventory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_tech_inventory", get_server(), "burp_tech_inventory", {}, passed, failed, skipped);
    }
    void test_tool_burp_tech_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_tech_clear", get_server(), "burp_tech_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_browser_launch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_browser_launch", get_server(), "burp_browser_launch", {}, passed, failed, skipped);
    }
    void test_tool_burp_browser_kill(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["pid"] = 0;
        test_tool_call(hf, "mcp.burp_browser_kill", get_server(), "burp_browser_kill", args, passed, failed, skipped);
    }
    void test_tool_burp_browser_kill_all(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_browser_kill_all", get_server(), "burp_browser_kill_all", {}, passed, failed, skipped);
    }
    void test_tool_burp_browser_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_browser_list", get_server(), "burp_browser_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_browser_detect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_browser_detect", get_server(), "burp_browser_detect", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_start", get_server(), "burp_headless_start", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_stop", get_server(), "burp_headless_stop", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_status", get_server(), "burp_headless_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_navigate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_headless_navigate", get_server(), "burp_headless_navigate", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_reload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_reload", get_server(), "burp_headless_reload", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_evaluate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["code"] = "document.title";
        test_tool_call(hf, "mcp.burp_headless_evaluate", get_server(), "burp_headless_evaluate", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_screenshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_screenshot", get_server(), "burp_headless_screenshot", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_snapshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_snapshot", get_server(), "burp_headless_snapshot", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_click(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["selector"] = "body";
        test_tool_call(hf, "mcp.burp_headless_click", get_server(), "burp_headless_click", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_type(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["selector"] = "input"; args["text"] = "test";
        test_tool_call(hf, "mcp.burp_headless_type", get_server(), "burp_headless_type", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_wait_for(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["selector"] = "body";
        test_tool_call(hf, "mcp.burp_headless_wait_for", get_server(), "burp_headless_wait_for", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_console_logs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_console_logs", get_server(), "burp_headless_console_logs", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_network_requests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_network_requests", get_server(), "burp_headless_network_requests", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_inject_hook(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["code"] = "console.log('test');";
        test_tool_call(hf, "mcp.burp_headless_inject_hook", get_server(), "burp_headless_inject_hook", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_hook_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["function_name"] = "XMLHttpRequest.prototype.send"; args["code"] = "console.log('intercepted');";
        test_tool_call(hf, "mcp.burp_headless_hook_function", get_server(), "burp_headless_hook_function", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_remove_hooks(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_remove_hooks", get_server(), "burp_headless_remove_hooks", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_reset_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_reset_state", get_server(), "burp_headless_reset_state", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_view_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_view_status", get_server(), "burp_headless_view_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_view_quick_navigate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_headless_view_quick_navigate", get_server(), "burp_headless_view_quick_navigate", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_view_install(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_view_install", get_server(), "burp_headless_view_install", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_status", get_server(), "burp_collaborator_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_start", get_server(), "burp_collaborator_start", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_stop", get_server(), "burp_collaborator_stop", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_generate_token(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_generate_token", get_server(), "burp_collaborator_generate_token", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_poll(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_poll", get_server(), "burp_collaborator_poll", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_get_interaction(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = 0;
        test_tool_call(hf, "mcp.burp_collaborator_get_interaction", get_server(), "burp_collaborator_get_interaction", args, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_clear", get_server(), "burp_collaborator_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_list_tokens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_list_tokens", get_server(), "burp_collaborator_list_tokens", {}, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_start_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_call(hf, "mcp.burp_sequencer_start_collection", get_server(), "burp_sequencer_start_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = 0;
        test_tool_call(hf, "mcp.burp_sequencer_status", get_server(), "burp_sequencer_status", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = 0;
        test_tool_call(hf, "mcp.burp_sequencer_stop", get_server(), "burp_sequencer_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_samples(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = 0;
        test_tool_call(hf, "mcp.burp_sequencer_samples", get_server(), "burp_sequencer_samples", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = 0;
        test_tool_call(hf, "mcp.burp_sequencer_analyze", get_server(), "burp_sequencer_analyze", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_sequencer_list_collections", get_server(), "burp_sequencer_list_collections", {}, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = 0;
        test_tool_call(hf, "mcp.burp_sequencer_delete", get_server(), "burp_sequencer_delete", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_add_slot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["data"] = "test data";
        test_tool_call(hf, "mcp.burp_comparer_add_slot", get_server(), "burp_comparer_add_slot", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_list_slots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_comparer_list_slots", get_server(), "burp_comparer_list_slots", {}, passed, failed, skipped);
    }
    void test_tool_burp_comparer_remove_slot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["slot_id"] = 0;
        test_tool_call(hf, "mcp.burp_comparer_remove_slot", get_server(), "burp_comparer_remove_slot", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_comparer_clear", get_server(), "burp_comparer_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_comparer_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["slot_a"] = 0; args["slot_b"] = 1;
        test_tool_call(hf, "mcp.burp_comparer_diff", get_server(), "burp_comparer_diff", args, passed, failed, skipped);
    }

}

void phase_mcp_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "mcp_phase", "=== MCP TOOL TESTS START (525 tests) ===");
    auto t0 = std::chrono::steady_clock::now();

    g_invoked_tools.clear();
    g_tool_attempt_stats.clear();
    g_mcp_tool_sequence.store(0, std::memory_order_release);
    g_mcp_target_pid = driver_bridge::attached_pid();
    log_msg(hf, "mcp_phase", "target snapshot active_pid=%u", g_mcp_target_pid);

    if (!cancelled()) test_mcp_server_accessible(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_server_running(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_tool_count(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_enumerate_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_categorize_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_tool_schemas(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_duplicate_tool_names(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_jsonrpc_smoke(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_driver_load(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_processes(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_processes_filter(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_enumerate_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_enumerate_threads(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_string(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_query_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disassemble_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disassemble_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detach(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sandbox_execute(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_convert_number_decimal(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_convert_number_hex(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_convert_number_binary(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_write_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_edit_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_delete_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_create_directory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_directory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_search_files(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_grep_in_files(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_web_search(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_webfetch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_reconstruct_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_reconstruct_cancel(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_reconstruct_source(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_driver_connect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_attach(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_unattach(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_write_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_dump_module(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_scan_pattern(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_string(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_pointer_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_kernel_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_dump_kernel_module(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_kernel_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_write_kernel_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_allocate_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_free_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_call_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_get_thread_context(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_set_thread_context(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_threads(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_suspend_thread(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_resume_thread(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_query_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_protect_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_memory_regions(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_peb(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_spoof_debug_flags(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_set_hw_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_clear_hw_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_resolve_export(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_virtual_to_physical(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_defer_action(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_list_deferred_actions(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_cancel_deferred_action(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_get_deferred_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_wfp_callouts(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_get_socket_handles(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_network_state(hf, "before MCP driver network tools");
    if (!cancelled()) test_tool_driver_sniff_network_buffers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_dump_tcpip_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_inject_packet(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_modify_packet_rule(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_redirect_traffic(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_reassemble_stream(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_deep_inspect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_intercept_hold(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_kill_connection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_spoof_dns(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_bandwidth_monitor(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_list_interfaces(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_export_pcap(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_network_fingerprint(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_network_state(hf, "after MCP driver network tools");
    if (!cancelled()) test_tool_driver_enum_kernel_callbacks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_integrity_checks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_ssdt_hooks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enum_minifilters(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_etw_monitors(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_hidden_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_walk_heap(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_handles(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_walk_seh_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_find_code_caves(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_scan_memory_value(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_pointer_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_windows(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_walk_stack(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_assemble(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_compare_memory_snapshot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_find_references(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_teb(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_map_peb_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_set_page_guard(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_dbg_set_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_remove_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_list_breakpoints(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_callstack(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_snapshot_state(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_compare_snapshots(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_detect_vm_handler(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_map_vm_handlers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_run(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_pause(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_step_into(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_step_over(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_step_out(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_run_to_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_attached(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_registers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_breakpoints(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_memory_map(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_callstack(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_threads(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_handles(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_seh_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_patches(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_set_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_remove_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_step_over(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_step_into(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_step_out(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_continue(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_pause(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_read_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_write_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_protect_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_attach_to_process(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_detach(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_registers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_set_register(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_memory_map(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_add_watch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_remove_watch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_watches(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_start_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_stop_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_set_comment(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_set_label(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_toggle_bookmark(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_find_strings(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_enumerate_handles(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_add_hw_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_toggle_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_clear_all_breakpoints(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_comment(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_label(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_bookmarks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_xrefs_to(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_xrefs_from(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_scan_xrefs(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_build_cfg(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_cfg(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_seh_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_modules_detail(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_add_patch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_remove_patch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_list_patches(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_nop_fill(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_find_code_caves(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_conditional_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_enable_stealth(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disable_stealth(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_stealth_status(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_scanner_first_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_next_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_get_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_reset(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_undo(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_add_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_remove_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_freeze_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_read_value(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_write_value(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_get_address_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_pointer_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_cancel_pointer_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_define_struct(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_add_struct_field(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_get_struct(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_export_struct_c(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scan_crypto_constants(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_generate_aob_signature(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_reconstruct_struct(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_start_fuzz(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_stop_fuzz(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_get_fuzz_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_auto_decrypt_strings(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_hunt_integrity_checkers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_neutralize_integrity_node(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_start_live_monitor(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_stop_live_monitor(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_symbolic_deobfuscate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_symbolic_slice_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_symbolic_solve_path(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_taint_trace_register(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_decompile_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_enable_stealth_context(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disable_stealth_context(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_imports(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_exports(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_types(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_type_definition(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_pdb_symbols(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_binary_map_overview(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_get_xref_db_stats(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_crypto_scanner_run(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_crypto_scanner_get_results(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_disasm_jump_to_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_instruction(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_function_bounds(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_function_disassembly(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_list_functions(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_xrefs_to(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_xrefs_from(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_set_comment(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_comment(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_rename_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_section_info(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_search_bytes(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disasm_get_strings(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_ui_set_active_view(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_bookmarks_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_bookmarks_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_bookmarks_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_hex_view_open(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_sessions_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_get_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_switch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_open_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_attach_pid(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_close(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_run_binary(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_switch_agent(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_plan_enter(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_plan_exit(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_agents(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_ask_followup_question(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_attempt_completion(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_update_todo_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_apply_diff(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_apply_patch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_codebase_search(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_command_output(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_save_checkpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_restore_checkpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_checkpoints(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_checkpoint_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_skill(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_run_slash_command(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_get_context(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_workflow_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_task(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_search_workspace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_run_command(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cancel_command(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_commands(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_disassemble_zydis(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_snapshot_and_emulate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_trace_execution_unicorn(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analyze_vm_handler(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_emulate_multi_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_emulate_function(hf, passed, failed, skipped);

    if (!cancelled()) cleanup_mcp_network_state(hf, "before MCP network tools");
    if (!cancelled()) test_tool_network_enumerate_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_start_capture(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_stop_capture(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_get_packets(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_analyze_packet(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_dns_log(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_add_filter(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_remove_filter(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_clear_filters(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_stats(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_capture_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_block_ip(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_block_port(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_block_process(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_deep_inspect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_follow_tcp_stream(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_parse_http(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_parse_tls(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_enumerate_wfp_callouts(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_get_socket_handles(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_dump_tcpip(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_enumerate_interfaces(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_inject_packet(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_modify_packet_rule(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_list_mod_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_redirect_traffic(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_list_redirect_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_intercept(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_get_held_packets(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_release_packet(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_kill_connection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_spoof_dns(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_list_dns_spoof_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_bandwidth_monitor(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_bandwidth_per_process(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_os_fingerprint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_export_pcap(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_decode_data(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_list_transforms(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_script_load(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_script_unload(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_script_execute(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_script_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_script_api(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_stream_track(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_pg_sniff(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_packet_callstack(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_pre_encrypt_hook(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_display_filter(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_protobuf_decode(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_fuzzer(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_websocket(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_proxy(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_repeater(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_mitm_status(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_network_state(hf, "after MCP network tools");

    if (!cancelled()) test_tool_tls_extract_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_start_keylog(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_stop_keylog(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_get_extracted_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_inject(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_generate_ca(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_pin_bypass(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_pin_bypass_revert(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_pin_bypass_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_quic_detect_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_quic_decrypt_initial(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_quic_extract_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dtls_detect_sessions(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dtls_extract_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_add_rule(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_remove_rule(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_list_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_import_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_export_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_decrypt_capture(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_ensure_keylogfile(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_burp_scanner_start_audit(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_audit_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_list_audits(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_cancel(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_list_issues(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_get_issue(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_passive_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_list_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_clear_issues(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_passive_enable(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_list_hosts(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_list_paths(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_get_exchange(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_send_to(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_check(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_set(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_delete(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_export_netscape(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_dom_xss_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_dom_xss_test_payload(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_dom_xss_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_subdomain_enum_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_subdomain_enum_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_subdomain_enum_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_get(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_search(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_add_custom(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_list_jobs(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_h2_send(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_decode(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_forge(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_verify(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_crack_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_crack_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_crack_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_attack(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_basic_encode(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_basic_decode(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_digest_solve(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_ntlm_type1(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_ntlm_type3(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_bearer(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_oauth2_pkce(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_oauth2_build_auth_url(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_oauth2_exchange_code(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_oauth2_refresh(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_saml_decode_request(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_auth_saml_decode_response(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_update(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_test(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_run(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_update(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_import(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_list_collections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_get_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_remove_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_send_request(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_audit_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_introspect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_example(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_send(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_connect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_disconnect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_send_text(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_send_binary(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_send_raw(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_list_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_frames(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_clear_frames(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_query(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_total(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_export_csv(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_report_generate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_bambda_compile(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_bambda_test(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_bambda_help(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_csp_analyze(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_csp_analyze_url(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_add_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_remove_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_list_chains(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_set_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_get_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_test_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_fingerprint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_inventory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_launch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_kill(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_kill_all(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_detect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_navigate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_reload(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_evaluate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_screenshot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_snapshot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_click(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_type(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_wait_for(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_console_logs(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_network_requests(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_inject_hook(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_hook_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_remove_hooks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_reset_state(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_view_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_view_quick_navigate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_view_install(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_generate_token(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_poll(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_get_interaction(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_list_tokens(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_start_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_samples(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_analyze(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_list_collections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_delete(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_add_slot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_list_slots(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_remove_slot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_diff(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_network_state(hf, "before MCP coverage audit");
    if (!cancelled()) test_mcp_coverage_audit(hf, passed, failed, skipped);

    if (g_mcp_driver_hw_tid != 0) {
        (void)driver_bridge::clear_hardware_breakpoint(g_mcp_driver_hw_tid, 0);
        g_mcp_driver_hw_tid = 0;
    }
    if (g_mcp_driver_hw_addr != 0) {
        driver_bridge::free_memory(g_mcp_driver_hw_addr);
        g_mcp_driver_hw_addr = 0;
    }
    if (g_mcp_dbg_hw_addr != 0) {
        debugger_engine::clear_all_breakpoints();
        driver_bridge::free_memory(g_mcp_dbg_hw_addr);
        g_mcp_dbg_hw_addr = 0;
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    log_msg(hf, "mcp_phase", "=== MCP TOOL TESTS DONE (elapsed %lld ms) ===", (long long)ms);
}

}
