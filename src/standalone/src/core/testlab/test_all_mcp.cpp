#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#include "test_all_mcp.h"
#include "test_all_features.hpp"

#include "../mcp/mcp_standalone.hpp"
#include "../ai/standalone_chat.hpp"
#include "../analysis/decrypt_oracle.hpp"
#include "../analysis/integrity_hunter.hpp"
#include "../analysis/struct_monitor.hpp"
#include "../analysis/xref_db.hpp"
#include "../analysis/xref_engine.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../debugger/page_guard_engine.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../network/burp/issue.hpp"
#include "../network/burp/site_map.hpp"
#include "../tools/pre_encrypt_hook.hpp"
#include "../infra/work_queue.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <iomanip>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

extern DisasmState g_disasm;

namespace test_all_features {

namespace {

    std::set<std::string> g_invoked_tools;
    uint32_t g_mcp_target_pid = 0;
    bool g_mcp_target_unavailable = false;
    std::atomic<int> g_mcp_tool_sequence{0};
    uint64_t g_mcp_driver_hw_addr = 0;
    uint32_t g_mcp_driver_hw_tid = 0;
    uint64_t g_mcp_dbg_hw_addr = 0;
    uint64_t g_mcp_dbg_sw_addr = 0;
    uint64_t g_mcp_integrity_addr = 0;
    uint64_t g_mcp_emulation_addr = 0;
    uint64_t g_mcp_emulate_function_addr = 0;
    int g_mcp_debugger_bp_index = -1;
    uint64_t g_mcp_deferred_action_id = 0;
    uint64_t g_mcp_live_monitor_addr = 0;
    uint64_t g_mcp_live_monitor_cmp_addr = 0;
    uint64_t g_mcp_scanner_addr = 0;
    uint64_t g_mcp_scanner_pointer_addr = 0;
    uint64_t g_mcp_symbolic_deobf_addr = 0;
    uint64_t g_autoresponder_rule_id = 0;
    uint64_t g_burp_scanner_audit_id = 0;
    uint64_t g_burp_scanner_issue_id = 0;
    uint64_t g_burp_sitemap_exchange_id = 0;
    uint64_t g_burp_crawler_id = 0;
    uint64_t g_burp_content_discovery_id = 0;
    uint64_t g_burp_subdomain_id = 0;
    uint64_t g_burp_intruder_job_id = 0;
    uint64_t g_burp_param_miner_job_id = 0;
    uint64_t g_burp_jwt_crack_id = 0;
    uint64_t g_burp_match_replace_rule_id = 0;
    uint64_t g_burp_macro_id = 0;
    uint64_t g_burp_session_rule_id = 0;
    uint64_t g_burp_api_collection_id = 0;
    uint64_t g_burp_ws_conn_id = 0;
    uint64_t g_burp_upstream_chain_id = 0;
    uint64_t g_burp_sequencer_collection_id = 0;
    uint64_t g_burp_comparer_slot_a = 0;
    uint64_t g_burp_comparer_slot_b = 0;
    uint64_t g_burp_collaborator_interaction_id = 0;
    uint64_t g_burp_browser_pid = 0;
    std::string g_burp_collaborator_token;
    std::string g_burp_fixture_base_url;
    std::string g_burp_fixture_wordlist_path;
    std::string g_mcp_session_binary_id;

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

    std::string hex_preview(const std::vector<uint8_t>& bytes, size_t max_len = 16) {
        char cell[4];
        std::string out;
        const size_t n = std::min(bytes.size(), max_len);
        out.reserve(n * 3);
        for (size_t i = 0; i < n; ++i) {
            _snprintf_s(cell, sizeof(cell), _TRUNCATE, "%02X", static_cast<unsigned>(bytes[i]));
            if (!out.empty())
                out.push_back(' ');
            out += cell;
        }
        if (bytes.size() > n)
            out += " ...";
        return out;
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
            "run_command",
            "cancel_command",
            "list_commands",
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

    bool is_destructive_mcp_tool(const std::string& name) {
        static const std::set<std::string> exact = {
            "driver_write_kernel_memory",
            "cert_inject",
            "cert_remove"
        };
        return exact.find(lower_copy(name)) != exact.end();
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
        if (g_mcp_target_pid == 0) {
            g_mcp_target_unavailable = true;
            log_msg(hf, tag, "SKIP -- no MCP target pid is available");
            return false;
        }

        if (!restore_mcp_target(hf, tag)) {
            g_mcp_target_unavailable = true;
            return false;
        }

        uint32_t exit_code = 0;
        const bool alive = driver_bridge::attached_process_alive(&exit_code);
        if (!alive) {
            g_mcp_target_unavailable = true;
            log_msg(hf, tag, "SKIP -- MCP target pid=%u is no longer alive (exit_code_or_err=0x%08X)",
                g_mcp_target_pid, exit_code);
        } else {
            g_mcp_target_unavailable = false;
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
        static const std::set<std::string> no_target_required = {
            "driver_load",
            "driver_status",
            "driver_connect",
            "driver_detach",
            "driver_unattach",
            "driver_enumerate_kernel_modules",
            "driver_dump_kernel_module",
            "driver_read_kernel_memory",
            "driver_write_kernel_memory"
        };
        if (no_target_required.find(name) != no_target_required.end())
            return false;
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

    bool tool_allows_host_dependency_skip(const std::string& name) {
        static const std::set<std::string> names = {
            "sandbox_execute",
            "network_decrypt_capture",
            "firefox_profile_prepare",
            "firefox_profile_launch"
        };
        return names.find(name) != names.end();
    }

    bool json_u64_field(const mcp_standalone::json& j, const char* key, uint64_t& out) {
        if (!key || !j.is_object() || !j.contains(key))
            return false;
        const auto& v = j[key];
        if (v.is_number_unsigned()) {
            out = v.get<uint64_t>();
            return true;
        }
        if (v.is_number_integer()) {
            auto raw = v.get<int64_t>();
            if (raw > 0) {
                out = static_cast<uint64_t>(raw);
                return true;
            }
        }
        if (v.is_string()) {
            std::string s = v.get<std::string>();
            char* end = nullptr;
            unsigned long long parsed = std::strtoull(s.c_str(), &end, 0);
            if (end && end != s.c_str()) {
                out = static_cast<uint64_t>(parsed);
                return true;
            }
        }
        return false;
    }

    bool json_u64_any_field(const mcp_standalone::json& j, uint64_t& out, std::initializer_list<const char*> keys) {
        if (!j.is_object())
            return false;
        for (const char* key : keys) {
            if (json_u64_field(j, key, out) && out != 0)
                return true;
        }
        return false;
    }

    bool json_u64_array_first_field(const mcp_standalone::json& j, const char* array_key, uint64_t& out, std::initializer_list<const char*> keys) {
        if (!array_key || !j.is_object() || !j.contains(array_key) || !j[array_key].is_array())
            return false;
        for (const auto& it : j[array_key]) {
            if (json_u64_any_field(it, out, keys))
                return true;
        }
        return false;
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

    bool sensitive_json_key(const std::string& key) {
        const std::string k = lower_copy(key);
        if (k.find("endpoint") != std::string::npos || k.find("url") != std::string::npos)
            return false;
        if (k == "authorization" || k == "cookie" || k == "set-cookie" || k == "password" ||
            k == "passwd" || k == "pass" || k == "secret" || k == "client_secret" ||
            k == "api_key" || k == "apikey" || k == "key" || k == "license" ||
            k == "license_key" || k == "access_token" || k == "refresh_token" ||
            k == "token" || k == "session" || k == "session_id" || k == "bearer")
            return true;
        return k.find("_token") != std::string::npos ||
               k.find("token_") != std::string::npos ||
               k.find("_secret") != std::string::npos ||
               k.find("secret_") != std::string::npos ||
               k.find("_password") != std::string::npos ||
               k.find("password_") != std::string::npos ||
               k.find("_cookie") != std::string::npos ||
               k.find("cookie_") != std::string::npos ||
               k.find("authorization") != std::string::npos ||
               k.find("private_key") != std::string::npos;
    }

    mcp_standalone::json redacted_json_value(const mcp_standalone::json& value) {
        if (value.is_string()) {
            const auto s = value.get<std::string>();
            return "<redacted string len=" + std::to_string(s.size()) + ">";
        }
        if (value.is_object())
            return "<redacted object size=" + std::to_string(value.size()) + ">";
        if (value.is_array())
            return "<redacted array size=" + std::to_string(value.size()) + ">";
        if (value.is_boolean())
            return "<redacted bool>";
        if (value.is_number())
            return "<redacted number>";
        return "<redacted>";
    }

    mcp_standalone::json redact_json_for_log(const mcp_standalone::json& value, const std::string& key = {}) {
        if (!key.empty() && sensitive_json_key(key))
            return redacted_json_value(value);
        if (value.is_object()) {
            auto out = mcp_standalone::json::object();
            for (auto it = value.begin(); it != value.end(); ++it)
                out[it.key()] = redact_json_for_log(*it, it.key());
            return out;
        }
        if (value.is_array()) {
            auto out = mcp_standalone::json::array();
            for (const auto& item : value)
                out.push_back(redact_json_for_log(item));
            return out;
        }
        return value;
    }

    std::string compact_json(const mcp_standalone::json& value, std::size_t cap = 360) {
        std::string out;
        try {
            const auto safe = redact_json_for_log(value.is_null() ? mcp_standalone::json::object() : value);
            out = safe.dump();
        } catch (...) {
            out = "<json-dump-failed>";
        }
        for (auto& c : out) {
            if (c == '\n' || c == '\r') c = ' ';
        }
        if (out.size() > cap)
            out = out.substr(0, cap) + "...(truncated)";
        return out;
    }

    bool sensitive_log_tool(const std::string& tool_name) {
        const std::string t = lower_copy(tool_name);
        static const char* markers[] = {
            "auth", "token", "collaborator", "cookie", "license", "session",
            "oauth", "saml", "jwt", "bearer", "secret", "api_key", "apikey"
        };
        for (const char* marker : markers) {
            if (t.find(marker) != std::string::npos)
                return true;
        }
        return false;
    }

    std::string redact_labeled_text(std::string out) {
        static const char* labels[] = {
            "token", "access_token", "refresh_token", "password", "passwd", "pass",
            "secret", "client_secret", "api_key", "apikey", "authorization",
            "cookie", "set-cookie", "license", "session"
        };
        for (const char* label : labels) {
            std::string lowered = lower_copy(out);
            std::size_t pos = 0;
            const std::string needle(label);
            while ((pos = lowered.find(needle, pos)) != std::string::npos) {
                std::size_t value_start = pos + needle.size();
                while (value_start < out.size() && (out[value_start] == ' ' || out[value_start] == '\t' ||
                       out[value_start] == ':' || out[value_start] == '=' || out[value_start] == '"' ||
                       out[value_start] == '\'')) {
                    ++value_start;
                }
                if (value_start >= out.size()) {
                    pos += needle.size();
                    continue;
                }
                std::size_t value_end = value_start;
                while (value_end < out.size()) {
                    const char c = out[value_end];
                    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' ||
                        c == '\'' || c == ',' || c == ';' || c == '&' || c == '}')
                        break;
                    ++value_end;
                }
                if (value_end > value_start) {
                    out.replace(value_start, value_end - value_start, "<redacted>");
                    lowered = lower_copy(out);
                    pos = value_start + 10;
                } else {
                    pos += needle.size();
                }
            }
        }
        return out;
    }

    std::string compact_text(std::string out, std::size_t cap) {
        out = redact_labeled_text(std::move(out));
        for (auto& c : out) {
            if (c == '\n' || c == '\r') c = ' ';
        }
        if (out.size() > cap)
            out = out.substr(0, cap) + "...(truncated)";
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

    void log_mcp_result_detail(const char* phase,
                               int seq,
                               const std::string& tool_name,
                               const mcp_standalone::json& args,
                               const invoke_result_t& ir,
                               long long elapsed_ms,
                               const std::string& reason) {
        const bool sensitive_tool = sensitive_log_tool(tool_name);
        const std::string args_preview = compact_json(args, 1200);
        const std::string data_preview = compact_json(ir.data, 2200);
        const std::string reason_preview = sensitive_tool ? "<redacted reason len=" + std::to_string(reason.size()) + ">" : compact_text(reason, 900);
        const std::string text_preview = sensitive_tool ? "<redacted text len=" + std::to_string(ir.text.size()) + ">" : compact_text(ir.text, 1400);
        const std::string ex_preview = compact_text(ir.exception_msg, 900);
        diag::log_tagged_fmt("mcp_result_detail",
            "phase=%s seq=%d tool=%s elapsed_ms=%lld found=%d success=%d threw=%d reason=%s text_len=%zu data_type=%s args=%s text=%s exception=%s data=%s",
            phase ? phase : "",
            seq,
            tool_name.c_str(),
            elapsed_ms,
            ir.found ? 1 : 0,
            ir.success ? 1 : 0,
            ir.threw ? 1 : 0,
            reason_preview.c_str(),
            ir.text.size(),
            ir.data.type_name(),
            args_preview.c_str(),
            text_preview.c_str(),
            ex_preview.c_str(),
            data_preview.c_str());
    }

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

    void record_precondition_skipped_tool(const char* tool_name, std::atomic<int>& skipped) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        if (!tool_name_s.empty()) {
            g_invoked_tools.insert(tool_name_s);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
        }
        skipped.fetch_add(1);
    }

    void record_fixture_failed_tool(const char* tool_name, std::atomic<int>& failed) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        if (!tool_name_s.empty()) {
            g_invoked_tools.insert(tool_name_s);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
        }
        failed.fetch_add(1);
    }

    bool ensure_mcp_private_bytes(HANDLE hf, const char* tag, uint64_t& addr, size_t size, const std::vector<uint8_t>& bytes) {
        if (!ensure_mcp_target_live(hf, tag))
            return false;
        if (addr == 0) {
            addr = driver_bridge::allocate_memory(size);
            if (addr == 0) {
                log_msg(hf, tag, "SKIP -- allocate_memory failed for MCP fixture");
                return false;
            }
        }
        uint32_t old_protect = 0;
        driver_bridge::protect_memory(addr, size, PAGE_EXECUTE_READWRITE, &old_protect);
        if (!bytes.empty() && !driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, tag, "SKIP -- write_memory failed for MCP fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            addr = 0;
            return false;
        }
        if (!bytes.empty()) {
            std::vector<uint8_t> verify;
            const bool read_ok = driver_bridge::read_memory(addr, bytes.size(), verify);
            const bool match = read_ok &&
                verify.size() >= bytes.size() &&
                std::equal(bytes.begin(), bytes.end(), verify.begin());
            if (!match) {
                log_msg(hf, tag, "SKIP -- MCP fixture readback mismatch addr=0x%016llX wrote=%zu read_ok=%d read=%zu active_pid=%u expected=[%s] actual=[%s]",
                    static_cast<unsigned long long>(addr),
                    bytes.size(),
                    read_ok ? 1 : 0,
                    verify.size(),
                    driver_bridge::attached_pid(),
                    hex_preview(bytes).c_str(),
                    hex_preview(verify).c_str());
                driver_bridge::free_memory(addr);
                addr = 0;
                return false;
            }
        }
        return true;
    }

    bool ensure_mcp_scanner_pointer_fixture(HANDLE hf, const char* tag) {
        if (!ensure_mcp_private_bytes(hf, tag, g_mcp_scanner_addr, 4096, {0x1A, 0x2B, 0x3C, 0x4D}))
            return false;

        if (g_mcp_scanner_pointer_addr == 0) {
            g_mcp_scanner_pointer_addr = driver_bridge::allocate_memory(4096);
            if (g_mcp_scanner_pointer_addr == 0) {
                log_msg(hf, tag, "SKIP -- allocate_memory failed for scanner pointer slots target=0x%016llX",
                    static_cast<unsigned long long>(g_mcp_scanner_addr));
                return false;
            }
        }

        std::vector<uint8_t> bytes(4096, 0);
        const uint64_t target = g_mcp_scanner_addr;
        for (size_t off = 0; off + sizeof(target) <= bytes.size(); off += 16)
            std::memcpy(bytes.data() + off, &target, sizeof(target));

        if (!driver_bridge::write_memory(g_mcp_scanner_pointer_addr, bytes)) {
            log_msg(hf, tag, "SKIP -- write_memory failed for scanner pointer slots addr=0x%016llX target=0x%016llX",
                static_cast<unsigned long long>(g_mcp_scanner_pointer_addr),
                static_cast<unsigned long long>(g_mcp_scanner_addr));
            driver_bridge::free_memory(g_mcp_scanner_pointer_addr);
            g_mcp_scanner_pointer_addr = 0;
            return false;
        }

        uint32_t old_protect = 0;
        driver_bridge::protect_memory(g_mcp_scanner_pointer_addr, 4096, PAGE_READWRITE, &old_protect);

        std::vector<uint8_t> check;
        const bool read_ok = driver_bridge::read_memory(g_mcp_scanner_pointer_addr, sizeof(target), check);
        uint64_t read_value = 0;
        if (read_ok && check.size() >= sizeof(read_value))
            std::memcpy(&read_value, check.data(), sizeof(read_value));
        const bool ok = read_ok && read_value == target;
        log_msg(hf, tag, "scanner pointer fixture target=0x%016llX slot=0x%016llX read_ok=%d read_value=0x%016llX",
            static_cast<unsigned long long>(target),
            static_cast<unsigned long long>(g_mcp_scanner_pointer_addr),
            read_ok ? 1 : 0,
            static_cast<unsigned long long>(read_value));
        if (!ok) {
            driver_bridge::free_memory(g_mcp_scanner_pointer_addr);
            g_mcp_scanner_pointer_addr = 0;
        }
        return ok;
    }

    bool inspect_payload_object_failure(const mcp_standalone::json& obj, std::string& reason) {
        if (!obj.is_object())
            return false;

        auto degraded_string = [&](const char* key) -> bool {
            auto it = obj.find(key);
            if (it != obj.end() && it->is_string() && !it->get<std::string>().empty()) {
                reason = std::string(key) + "=" + it->get<std::string>();
                return true;
            }
            return false;
        };

        auto degraded_true = [&](const char* key) -> bool {
            auto it = obj.find(key);
            if (it != obj.end() && it->is_boolean() && it->get<bool>()) {
                reason = std::string(key) + "=true";
                return true;
            }
            return false;
        };

        if (degraded_string("transport_error") ||
            degraded_true("fixture_transport_fallback") ||
            degraded_true("offline_validated") ||
            degraded_true("fixture_noop") ||
            degraded_true("setup_pending") ||
            degraded_true("noop")) {
            return true;
        }

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
            if (status == "backend_unavailable" || status == "unavailable" ||
                status == "not_applicable" || status == "no_captures" ||
                status == "no-data" || status == "no_data") {
                reason = "status=" + status;
                return true;
            }
        }

        auto ok_it = obj.find("ok");
        if (ok_it != obj.end() && ok_it->is_boolean() && !ok_it->get<bool>()) {
            reason = "ok=false";
            auto err = obj.find("error");
            if (err != obj.end() && err->is_string() && !err->get<std::string>().empty())
                reason += ": " + err->get<std::string>();
            return true;
        }

        auto removed_it = obj.find("removed");
        if (removed_it != obj.end() && removed_it->is_boolean() && !removed_it->get<bool>()) {
            reason = "removed=false";
            return true;
        }

        auto neutralized_it = obj.find("neutralized");
        if (neutralized_it != obj.end() && neutralized_it->is_boolean() && !neutralized_it->get<bool>()) {
            reason = "neutralized=false";
            return true;
        }

        auto xml_it = obj.find("xml");
        if (xml_it != obj.end() && xml_it->is_string() && xml_it->get<std::string>().empty()) {
            reason = "xml is empty";
            return true;
        }

        auto timed_out_it = obj.find("timed_out");
        if (timed_out_it != obj.end() && timed_out_it->is_boolean() && timed_out_it->get<bool>()) {
            reason = "timed_out=true";
            return true;
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

    const mcp_standalone::json* find_payload_key_recursive(const mcp_standalone::json& value,
                                                           const char* key) {
        if (!key)
            return nullptr;
        if (value.is_object()) {
            auto it = value.find(key);
            if (it != value.end())
                return &(*it);
            for (auto it2 = value.begin(); it2 != value.end(); ++it2) {
                if (const auto* found = find_payload_key_recursive(*it2, key))
                    return found;
            }
        } else if (value.is_array()) {
            for (const auto& item : value) {
                if (const auto* found = find_payload_key_recursive(item, key))
                    return found;
            }
        }
        return nullptr;
    }

    bool payload_bool_field(const mcp_standalone::json& value, const char* key, bool& out) {
        const auto* found = find_payload_key_recursive(value, key);
        if (!found || !found->is_boolean())
            return false;
        out = found->get<bool>();
        return true;
    }

    bool payload_u64_field(const mcp_standalone::json& value, const char* key, uint64_t& out) {
        const auto* found = find_payload_key_recursive(value, key);
        if (!found)
            return false;
        if (found->is_number_unsigned()) {
            out = found->get<uint64_t>();
            return true;
        }
        if (found->is_number_integer()) {
            const auto v = found->get<int64_t>();
            if (v >= 0) {
                out = static_cast<uint64_t>(v);
                return true;
            }
        }
        return false;
    }

    bool payload_string_field(const mcp_standalone::json& value, const char* key, std::string& out) {
        const auto* found = find_payload_key_recursive(value, key);
        if (!found || !found->is_string())
            return false;
        out = found->get<std::string>();
        return true;
    }

    bool payload_array_count(const mcp_standalone::json& value, const char* key, size_t& out) {
        const auto* found = find_payload_key_recursive(value, key);
        if (!found || !found->is_array())
            return false;
        out = found->size();
        return true;
    }

    bool payload_text_contains(const invoke_result_t& ir, const std::string& needle_lc) {
        std::string text = lower_copy(ir.text);
        try {
            text += " ";
            text += lower_copy(ir.data.dump());
        } catch (...) {
        }
        return text.find(needle_lc) != std::string::npos;
    }

    bool tool_semantic_failure_reason(const std::string& tool_name,
                                      const invoke_result_t& ir,
                                      std::string& reason) {
        reason.clear();

        const std::string tool_lc = lower_copy(tool_name);
        if (tool_lc == "disasm_get_strings") {
            return false;
        }

        static const char* text_markers[] = {
            "transport_error",
            "fixture_transport_fallback",
            "offline_validated",
            "fixture_noop",
            "backend_unavailable",
            "unavailable",
            "no-data",
            "no data",
            "no_captures",
            "not_applicable",
            "not importable",
            "unresolved",
            "snapshot unavailable",
            "seh chain unavailable",
            "teb unavailable",
            "ssdt export unresolved",
            "did not return",
            "no http messages found",
            "no tls records found"
        };
        for (const char* marker : text_markers) {
            if (payload_text_contains(ir, marker)) {
                reason = marker;
                return true;
            }
        }

        if (tool_lc == "neutralize_integrity_node") {
            std::string status;
            if (payload_string_field(ir.data, "status", status) && lower_copy(status) == "not_applicable") {
                reason = "status=not_applicable";
                return true;
            }
            bool neutralized = false;
            if (payload_bool_field(ir.data, "neutralized", neutralized) && !neutralized) {
                reason = "neutralized=false";
                return true;
            }
        }

        if (tool_lc == "cert_generate_ca") {
            if (find_payload_key_recursive(ir.data, "key_der_hex") ||
                find_payload_key_recursive(ir.data, "private_key_der") ||
                find_payload_key_recursive(ir.data, "private_key_pem")) {
                reason = "private_key_material_returned";
                return true;
            }
        }

        if (tool_lc == "burp_api_audit_collection") {
            uint64_t requests_sent = 0;
            uint64_t requests_failed = 0;
            if (payload_u64_field(ir.data, "requests_sent", requests_sent) && requests_sent == 0) {
                reason = "requests_sent=0";
                return true;
            }
            if (payload_u64_field(ir.data, "requests_failed", requests_failed) && requests_failed > 0) {
                reason = "requests_failed=" + std::to_string(requests_failed);
                return true;
            }
        }

        if (tool_lc == "burp_tech_fingerprint") {
            uint64_t status_code = 0;
            if (payload_u64_field(ir.data, "status_code", status_code) && status_code == 0) {
                reason = "status_code=0";
                return true;
            }
        }

        if (tool_lc == "scanner_pointer_scan") {
            uint64_t total = 1;
            if (payload_u64_field(ir.data, "total", total) && total == 0) {
                reason = "total=0";
                return true;
            }
        }

        if (tool_lc == "scanner_first_scan" ||
            tool_lc == "scanner_next_scan" ||
            tool_lc == "scanner_get_results") {
            uint64_t total = 1;
            if (payload_u64_field(ir.data, "total_found", total) && total == 0) {
                reason = "total_found=0";
                return true;
            }
        }

        if (tool_lc == "disasm_list_functions") {
            uint64_t total = 1;
            if (payload_u64_field(ir.data, "total", total) && total == 0) {
                reason = "total=0";
                return true;
            }
        }

        if (tool_lc == "analysis_get_binary_map_overview") {
            size_t functions = 1;
            size_t sections = 0;
            if (payload_array_count(ir.data, "sections", sections) &&
                payload_array_count(ir.data, "functions", functions) &&
                sections > 0 && functions == 0) {
                reason = "functions=0";
                return true;
            }
        }

        if (tool_lc == "driver_walk_heap") {
            uint64_t heaps = 0;
            uint64_t entries = 1;
            if (payload_u64_field(ir.data, "heap_count", heaps) &&
                payload_u64_field(ir.data, "entries_returned", entries) &&
                heaps > 0 && entries == 0) {
                reason = "entries_returned=0";
                return true;
            }
        }

        if (tool_lc == "burp_headless_start" ||
            tool_lc == "burp_headless_status" ||
            tool_lc == "burp_headless_navigate" ||
            tool_lc == "burp_headless_reload" ||
            tool_lc == "burp_headless_evaluate" ||
            tool_lc == "burp_headless_screenshot" ||
            tool_lc == "burp_headless_snapshot" ||
            tool_lc == "burp_headless_click" ||
            tool_lc == "burp_headless_type" ||
            tool_lc == "burp_headless_wait_for" ||
            tool_lc == "burp_headless_console_logs" ||
            tool_lc == "burp_headless_network_requests" ||
            tool_lc == "burp_headless_inject_hook" ||
            tool_lc == "burp_headless_hook_function" ||
            tool_lc == "burp_headless_remove_hooks" ||
            tool_lc == "burp_headless_reset_state" ||
            tool_lc == "burp_headless_view_status" ||
            tool_lc == "burp_headless_view_quick_navigate" ||
            tool_lc == "burp_headless_view_install") {
            bool browser_open = true;
            if (payload_bool_field(ir.data, "browser_open", browser_open) && !browser_open) {
                reason = "browser_open=false";
                return true;
            }
            bool ready = true;
            if (payload_bool_field(ir.data, "ready", ready) && !ready) {
                reason = "ready=false";
                return true;
            }
            std::string state;
            if (payload_string_field(ir.data, "state", state) && lower_copy(state) == "stopped") {
                reason = "state=stopped";
                return true;
            }
        }

        if (tool_lc == "disasm_get_xrefs_to" ||
            tool_lc == "disasm_get_xrefs_from") {
            uint64_t count = 1;
            if (payload_u64_field(ir.data, "count", count) && count == 0) {
                reason = "count=0";
                return true;
            }
            if (payload_text_contains(ir, "no cached xrefs")) {
                reason = "no cached xrefs";
                return true;
            }
        }

        return false;
    }

    bool tool_payload_failure_reason(const std::string& tool_name, const invoke_result_t& ir, std::string& reason) {
        reason.clear();
        if (inspect_payload_object_failure(ir.data, reason))
            return true;

        if (!ir.text.empty()) {
            try {
                auto parsed = mcp_standalone::json::parse(ir.text);
                if (inspect_payload_object_failure(parsed, reason))
                    return true;
                invoke_result_t parsed_ir = ir;
                parsed_ir.data = std::move(parsed);
                if (tool_semantic_failure_reason(tool_name, parsed_ir, reason))
                    return true;
            } catch (...) {
            }
        }

        if (tool_semantic_failure_reason(tool_name, ir, reason))
            return true;

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

    const mcp_standalone::tool_def_t* find_registered_tool(mcp_standalone::server_t* srv, const char* tool_name) {
        if (!srv || !tool_name)
            return nullptr;
        const auto& tools = srv->get_tools();
        for (const auto& t : tools) {
            if (t.name == tool_name)
                return &t;
        }
        return nullptr;
    }

    bool tool_has_param(const mcp_standalone::tool_def_t& tool, const char* param_name) {
        if (!param_name)
            return false;
        for (const auto& p : tool.params) {
            if (p.name == param_name)
                return true;
        }
        return false;
    }

    void test_tool_schema_only(HANDLE hf, const char* tag, mcp_standalone::server_t* srv,
                               const char* tool_name, std::initializer_list<const char*> required_params,
                               std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)passed;
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        g_invoked_tools.insert(tool_name_s);
        const auto* tool = find_registered_tool(srv, tool_name);
        if (!tool) {
            log_msg(hf, tag, "FAIL -- destructive tool \"%s\" is not registered for schema coverage", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (!tool->handler) {
            log_msg(hf, tag, "FAIL -- destructive tool \"%s\" has no handler for schema coverage", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (tool->read_only) {
            log_msg(hf, tag, "FAIL -- destructive tool \"%s\" is incorrectly marked read_only=true", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        for (const char* param : required_params) {
            if (!tool_has_param(*tool, param)) {
                log_msg(hf, tag, "FAIL -- destructive tool \"%s\" schema missing parameter \"%s\"", tool_name, param ? param : "<null>");
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return;
            }
        }
        const int before = skipped.load(std::memory_order_acquire);
        const int after = skipped.fetch_add(1, std::memory_order_acq_rel) + 1;
        log_msg(hf, tag, "SCHEMA-SKIP -- destructive tool \"%s\" schema-only read_only=false params=%zu functional_run=0 skip_before=%d skip_after=%d",
            tool_name, tool->params.size(), before, after);
        record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
    }

    void test_tool_contract_only(HANDLE hf, const char* tag, mcp_standalone::server_t* srv,
                                 const char* tool_name, bool expected_read_only,
                                 std::initializer_list<const char*> required_params,
                                 std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        g_invoked_tools.insert(tool_name_s);
        const auto* tool = find_registered_tool(srv, tool_name);
        if (!tool) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" is not registered for contract coverage", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (!tool->handler) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" has no handler for contract coverage", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (tool->read_only != expected_read_only) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" read_only=%d expected=%d", tool_name, tool->read_only ? 1 : 0, expected_read_only ? 1 : 0);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        for (const char* param : required_params) {
            if (!tool_has_param(*tool, param)) {
                log_msg(hf, tag, "FAIL -- tool \"%s\" schema missing parameter \"%s\"", tool_name, param ? param : "<null>");
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return;
            }
        }
        log_msg(hf, tag, "CONTRACT-PASS -- tool \"%s\" contract read_only=%d params=%zu functional_run=0", tool_name, tool->read_only ? 1 : 0, tool->params.size());
        record_tool_status(tool_name_s, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    long long tool_timeout_ms(const std::string& name) {
        if (name == "web_search" || name == "webfetch")
            return 45000;
        if (name == "burp_headless_view_install")
            return 600000;
        if (name == "burp_headless_start" ||
            name == "burp_dom_xss_test_payload" ||
            name == "burp_dom_xss_scan")
            return 300000;
        if (name == "burp_headless_view_quick_navigate")
            return 120000;
        if (name.find("burp_headless") == 0)
            return 60000;
        if (name == "scanner_pointer_scan")
            return 35000;
        if (name == "auto_decrypt_strings" ||
            name == "reconstruct_struct" ||
            name == "hunt_integrity_checkers" ||
            name == "start_live_monitor" ||
            name == "stop_live_monitor" ||
            name == "scan_crypto_constants" ||
            name == "crypto_scanner_run")
            return 7000;
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
        } else if (name == "scanner_pointer_scan") {
            memory_scanner::cancel_pointer_scan();
            log_msg(hf, tag, "CANCEL -- scanner pointer scan stop signalled");
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
        auto fail_dispatch = [&](std::string message) {
            timed_invoke_result_t failed;
            failed.result.found = tool_registered(srv, tool_name.c_str());
            failed.result.threw = true;
            failed.result.exception_msg = std::move(message);
            return failed;
        };

        try {
            if (!work_queue::post([state, srv, tool_name, args]() {
                auto t0 = std::chrono::steady_clock::now();
                invoke_result_t ir;
                try {
                    ir = invoke_tool(srv, tool_name.c_str(), args);
                } catch (const std::exception& ex) {
                    ir.found = tool_registered(srv, tool_name.c_str());
                    ir.threw = true;
                    ir.exception_msg = std::string("dispatch worker escaped: ") + ex.what();
                } catch (...) {
                    ir.found = tool_registered(srv, tool_name.c_str());
                    ir.threw = true;
                    ir.exception_msg = "dispatch worker escaped: unknown exception";
                }
                auto t1 = std::chrono::steady_clock::now();
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    state->result = std::move(ir);
                    state->elapsed_ms = static_cast<long long>(ms);
                    state->done = true;
                }
                state->cv.notify_all();
            })) {
                return fail_dispatch("dispatch queue rejected task");
            }
        } catch (const std::exception& ex) {
            return fail_dispatch(std::string("dispatch queue post failed: ") + ex.what());
        } catch (...) {
            return fail_dispatch("dispatch queue post failed: unknown exception");
        }

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
                                          bool skip_on_error = false,
                                          mcp_standalone::tool_result_t* out_result = nullptr)
    {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        if (is_ai_related_mcp_tool(tool_name_s)) {
            log_msg(hf, tag, "EXCLUDED -- tool \"%s\" is AI/agent-related and excluded from full-run tests counted=0",
                tool_name_s.c_str());
            return mcp_tool_call_status_t::skipped;
        }
        if (is_destructive_mcp_tool(tool_name_s)) {
            log_msg(hf, tag, "EXCLUDED -- tool \"%s\" is destructive and requires schema-only coverage",
                tool_name_s.c_str());
            return mcp_tool_call_status_t::skipped;
        }

        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: %s", seq, tool_name ? tool_name : "<null>");
        set_progress_step(step);

        mcp_standalone::json call_args = args.is_null() ? mcp_standalone::json::object() : args;
        add_target_pid_if_needed(tool_name_s, call_args);
        add_target_tid_if_zero(call_args);
        const bool live_target_required = tool_uses_live_target(tool_name_s);
        const bool target_context_may_change = tool_may_change_target(tool_name_s);

        const std::string args_preview = compact_json(call_args);
        log_msg(hf, tag, "START -- \"%s\" seq=%d target_pid=%u attached_pid=%u args=%s",
            tool_name ? tool_name : "<null>",
            seq,
            g_mcp_target_pid,
            driver_bridge::attached_pid(),
            args_preview.c_str());
        g_invoked_tools.insert(tool_name_s);

        if (live_target_required) {
            if (!ensure_mcp_target_live(hf, tag)) {
                log_msg(hf, tag, "SKIP -- \"%s\" requires live MCP target pid=%u but restore/liveness check failed",
                    tool_name, g_mcp_target_pid);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                return mcp_tool_call_status_t::skipped;
            }
        } else if (g_mcp_target_pid != 0 && driver_bridge::attached_pid() == 0) {
            log_msg(hf, tag, "INFO -- \"%s\" does not require the live MCP target; continuing with active_pid=0",
                tool_name);
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
        if (out_result)
            *out_result = { ir.success, ir.text, ir.data };
        auto ms = timed.elapsed_ms;
        auto restore_after_mutation = [&]() {
            if (live_target_required || target_context_may_change)
                restore_mcp_target(hf, tag);
        };
        if (timed.timed_out) {
            log_msg(hf, tag, "FAIL -- \"%s\" timed out after %lld ms; detached worker may still be unwinding",
                tool_name, timeout_ms);
            invoke_result_t timeout_ir;
            log_mcp_result_detail("timeout", seq, tool_name_s, call_args, timeout_ir, timeout_ms, "watchdog_timeout");
            cancel_timed_out_tool(hf, tag, tool_name_s);
            restore_after_mutation();
            record_tool_status(tool_name_s, mcp_tool_call_status_t::timed_out);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::timed_out;
        }
        log_mcp_result_detail("completed", seq, tool_name_s, call_args, ir, ms, "");
        if (!ir.found) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" disappeared during dispatch", tool_name);
            log_mcp_result_detail("failed", seq, tool_name_s, call_args, ir, ms, "tool_not_found_after_dispatch");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        if (ir.threw) {
            if (skip_on_error) {
                log_msg(hf, tag, "SKIP -- tool \"%s\" threw: %s (elapsed %lld ms)",
                    tool_name, ir.exception_msg.c_str(), (long long)ms);
                log_mcp_result_detail("skipped_exception", seq, tool_name_s, call_args, ir, ms, ir.exception_msg);
                restore_after_mutation();
                record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                return mcp_tool_call_status_t::skipped;
            } else {
                log_msg(hf, tag, "FAIL -- tool \"%s\" threw: %s (elapsed %lld ms)",
                    tool_name, ir.exception_msg.c_str(), (long long)ms);
                log_mcp_result_detail("failed_exception", seq, tool_name_s, call_args, ir, ms, ir.exception_msg);
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
            g_mcp_target_unavailable = true;
            log_msg(hf, tag, "FAIL -- \"%s\" ended MCP target pid=%u exit_code_or_err=0x%08X (elapsed %lld ms) -> %s",
                tool_name, g_mcp_target_pid, post_exit_code, (long long)ms, preview.c_str());
            log_mcp_result_detail("failed_target_exit", seq, tool_name_s, call_args, ir, ms,
                "target_exit=0x" + std::to_string(post_exit_code));
            restore_after_mutation();
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }

        std::string payload_failure;
        if (ir.success && tool_payload_failure_reason(tool_name_s, ir, payload_failure)) {
            log_msg(hf, tag, "FAIL -- \"%s\" success=true but payload reports failure: %s (elapsed %lld ms) -> %s",
                tool_name, payload_failure.c_str(), (long long)ms, preview.c_str());
            log_mcp_result_detail("failed_payload", seq, tool_name_s, call_args, ir, ms, payload_failure);
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
                log_mcp_result_detail("skipped_error", seq, tool_name_s, call_args, ir, ms, preview);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                restore_after_mutation();
                return mcp_tool_call_status_t::skipped;
            } else {
                log_msg(hf, tag, "FAIL -- \"%s\" success=false: %s (elapsed %lld ms)",
                    tool_name, preview.c_str(), (long long)ms);
                log_mcp_result_detail("failed_error", seq, tool_name_s, call_args, ir, ms, preview);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                restore_after_mutation();
                return mcp_tool_call_status_t::failed;
            }
        }
    }


    uint64_t g_mcp_xref_from_addr = 0x0000000141DA3000ULL;
    uint64_t g_mcp_xref_to_addr = 0x0000000141DA3010ULL;

    void seed_mcp_xref_db_fixture() {
        xref_db::module_index_t mod;
        mod.name = "aida_mcp_xref_fixture";
        mod.base = g_mcp_xref_from_addr & ~0xFFFULL;
        mod.size = 0x1000;
        mod.timestamp = static_cast<uint64_t>(
            std::chrono::system_clock::now().time_since_epoch().count());
        mod.total_xrefs = 1;
        mod.built = true;

        xref_db::xref_entry_t entry;
        entry.from_addr = g_mcp_xref_from_addr;
        entry.to_addr = g_mcp_xref_to_addr;
        entry.type = xref_engine::xref_type_t::call;
        entry.disasm_text = "call aida_mcp_xref_target";
        mod.to_index[g_mcp_xref_to_addr].push_back(entry);
        mod.from_index[g_mcp_xref_from_addr].push_back(entry);

        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        xref_db::g_state.modules[mod.name] = std::move(mod);
    }

    std::string get_indexed_disasm_function_addr(HANDLE hf, const char* tag) {
        mcp_standalone::json args;
        args["offset"] = 0;
        args["limit"] = 1;
        auto timed = invoke_tool_bounded(get_server(), "disasm_list_functions", args, 2500);
        diag::log_tagged_fmt("mcp_disasm_fixture",
            "list_functions_for_fixture timed_out=%d success=%d threw=%d found=%d elapsed_ms=%lld text=%s data=%s",
            timed.timed_out ? 1 : 0,
            timed.result.success ? 1 : 0,
            timed.result.threw ? 1 : 0,
            timed.result.found ? 1 : 0,
            timed.elapsed_ms,
            compact_text(timed.result.text, 800).c_str(),
            compact_json(timed.result.data, 1400).c_str());
        if (timed.timed_out || !timed.result.success || !timed.result.data.is_object()) {
            log_msg(hf, tag, "FAIL -- disasm_list_functions did not provide an indexed function fixture");
            return {};
        }
        const auto& data = timed.result.data;
        if (!data.contains("functions") || !data["functions"].is_array() || data["functions"].empty()) {
            diag::log_tagged_fmt("mcp_disasm_fixture",
                "list_functions_empty total_present=%d returned_present=%d data=%s",
                data.contains("total") ? 1 : 0,
                data.contains("returned") ? 1 : 0,
                compact_json(data, 1800).c_str());
            log_msg(hf, tag, "FAIL -- disasm function index is empty; no valid function fixture available");
            return {};
        }
        const auto& first = data["functions"].front();
        if (!first.is_object() || !first.contains("address") || !first["address"].is_string()) {
            log_msg(hf, tag, "FAIL -- disasm_list_functions returned malformed function entry");
            return {};
        }
        return first["address"].get<std::string>();
    }

    std::string get_static_disasm_instruction_addr(HANDLE hf, const char* tag) {
        for (int i = 0; i < 50; ++i) {
            if (g_disasm.file.loaded && !g_disasm.file.instrs.empty()) {
                for (const auto& ins : g_disasm.file.instrs) {
                    if (ins.addr != 0) {
                        log_msg(hf, tag, "static disasm instruction fixture addr=0x%016llX instrs=%zu image_base=0x%016llX filename=%s",
                            static_cast<unsigned long long>(ins.addr),
                            g_disasm.file.instrs.size(),
                            static_cast<unsigned long long>(g_disasm.file.image_base),
                            g_disasm.file.filename.c_str());
                        return hex_u64(ins.addr);
                    }
                }
            }
            Sleep(50);
        }
        log_msg(hf, tag, "FAIL -- static disasm fixture unavailable loaded=%d instrs=%zu sections=%zu image_base=0x%016llX file=%s",
            g_disasm.file.loaded ? 1 : 0,
            g_disasm.file.instrs.size(),
            g_disasm.file.sections.size(),
            static_cast<unsigned long long>(g_disasm.file.image_base),
            g_disasm.file.filename.c_str());
        return {};
    }

    std::string get_self_path_narrow() {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, self, MAX_PATH);
        char narrow[MAX_PATH] = {};
        WideCharToMultiByte(CP_UTF8, 0, self, -1, narrow, MAX_PATH, nullptr, nullptr);
        return std::string(narrow);
    }

    std::wstring utf8_to_wide(const std::string& text) {
        if (text.empty())
            return {};
        int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
        if (needed <= 0)
            return {};
        std::wstring out(static_cast<size_t>(needed), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, out.data(), needed);
        out.resize(static_cast<size_t>(needed - 1));
        return out;
    }

    std::string wide_to_utf8(const std::wstring& text) {
        if (text.empty())
            return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 0)
            return {};
        std::string out(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, out.data(), needed, nullptr, nullptr);
        out.resize(static_cast<size_t>(needed - 1));
        return out;
    }

    bool file_exists_narrow(const std::string& path) {
        if (path.empty()) return false;
        const std::wstring wide = utf8_to_wide(path);
        DWORD attr = wide.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(wide.c_str());
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

    bool write_text_file_narrow(const std::string& path, const std::string& content) {
        HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        DWORD wrote = 0;
        BOOL ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()), &wrote, nullptr);
        CloseHandle(h);
        return ok && static_cast<size_t>(wrote) == content.size();
    }

    bool write_binary_file_narrow(const std::string& path, const std::vector<uint8_t>& content) {
        HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        DWORD wrote = 0;
        BOOL ok = WriteFile(h, content.data(), static_cast<DWORD>(content.size()), &wrote, nullptr);
        CloseHandle(h);
        return ok && static_cast<size_t>(wrote) == content.size();
    }

    std::string quote_arg_narrow(const std::string& arg) {
        std::string out;
        out.reserve(arg.size() + 2);
        out.push_back('"');
        for (char c : arg) {
            if (c == '"')
                out.push_back('\\');
            out.push_back(c);
        }
        out.push_back('"');
        return out;
    }

    std::wstring quote_arg_wide(const std::wstring& arg) {
        std::wstring out;
        out.reserve(arg.size() + 2);
        out.push_back(L'"');
        size_t slashes = 0;
        for (wchar_t c : arg) {
            if (c == L'\\') {
                ++slashes;
                continue;
            }
            if (c == L'"') {
                out.append(slashes * 2 + 1, L'\\');
                out.push_back(c);
                slashes = 0;
                continue;
            }
            if (slashes != 0) {
                out.append(slashes, L'\\');
                slashes = 0;
            }
            out.push_back(c);
        }
        if (slashes != 0)
            out.append(slashes * 2, L'\\');
        out.push_back(L'"');
        return out;
    }

    std::wstring extended_path_wide(const std::wstring& path) {
        if (path.empty())
            return {};
        if (path.rfind(L"\\\\?\\", 0) == 0 || path.rfind(L"\\\\.\\", 0) == 0)
            return path;
        if (path.rfind(L"\\\\", 0) == 0)
            return L"\\\\?\\UNC\\" + path.substr(2);
        if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'))
            return L"\\\\?\\" + path;
        return path;
    }

    std::wstring full_path_wide(const std::wstring& path) {
        if (path.empty())
            return {};
        DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (needed == 0)
            return path;
        std::wstring out(static_cast<size_t>(needed), L'\0');
        DWORD wrote = GetFullPathNameW(path.c_str(), needed, out.data(), nullptr);
        if (wrote == 0 || wrote >= needed)
            return path;
        out.resize(wrote);
        return out;
    }

    std::string format_win32_error(DWORD err) {
        char* buf = nullptr;
        DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&buf), 0, nullptr);
        std::string text;
        if (n != 0 && buf)
            text.assign(buf, n);
        if (buf)
            LocalFree(buf);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '\t'))
            text.pop_back();
        if (text.empty())
            text = "unknown error";
        return text;
    }

    DWORD current_parent_pid() {
        DWORD pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        DWORD parent = 0;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    parent = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return parent;
    }

    const char* integrity_name_from_rid(DWORD rid) {
        if (rid >= SECURITY_MANDATORY_SYSTEM_RID)
            return "system";
        if (rid >= SECURITY_MANDATORY_HIGH_RID)
            return "high";
        if (rid >= SECURITY_MANDATORY_MEDIUM_RID)
            return "medium";
        if (rid >= SECURITY_MANDATORY_LOW_RID)
            return "low";
        return "untrusted";
    }

    std::string describe_current_token() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            DWORD err = GetLastError();
            return "OpenProcessToken err=" + std::to_string(static_cast<unsigned long>(err)) + " text=" + format_win32_error(err);
        }
        TOKEN_ELEVATION elevation{};
        DWORD ret = 0;
        std::ostringstream out;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &ret)) {
            out << "elevated=" << (elevation.TokenIsElevated ? 1 : 0);
        } else {
            DWORD err = GetLastError();
            out << "elevation_err=" << static_cast<unsigned long>(err) << " text=" << format_win32_error(err);
        }
        TOKEN_ELEVATION_TYPE elevation_type = TokenElevationTypeDefault;
        ret = 0;
        if (GetTokenInformation(token, TokenElevationType, &elevation_type, sizeof(elevation_type), &ret))
            out << " elevation_type=" << static_cast<unsigned long>(elevation_type);
        ret = 0;
        GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &ret);
        if (ret != 0) {
            std::vector<unsigned char> buf(ret);
            if (GetTokenInformation(token, TokenIntegrityLevel, buf.data(), ret, &ret)) {
                auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buf.data());
                DWORD rid = 0;
                if (til->Label.Sid && IsValidSid(til->Label.Sid)) {
                    DWORD count = *GetSidSubAuthorityCount(til->Label.Sid);
                    if (count != 0)
                        rid = *GetSidSubAuthority(til->Label.Sid, count - 1);
                }
                out << " integrity=" << integrity_name_from_rid(rid) << "(0x" << std::hex << std::uppercase << rid << std::dec << ")";
            } else {
                DWORD err = GetLastError();
                out << " integrity_err=" << static_cast<unsigned long>(err) << " text=" << format_win32_error(err);
            }
        }
        CloseHandle(token);
        return out.str();
    }

    void log_file_open_probe(HANDLE hf, const char* tag, const wchar_t* label, const std::wstring& path, DWORD desired_access) {
        SetLastError(0);
        HANDLE h = CreateFileW(path.c_str(), desired_access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD err = h == INVALID_HANDLE_VALUE ? GetLastError() : 0;
        log_msg(hf, tag, "sidecar exe open probe %ls desired=0x%08lX ok=%d err=%lu text=%s",
            label,
            static_cast<unsigned long>(desired_access),
            h != INVALID_HANDLE_VALUE ? 1 : 0,
            static_cast<unsigned long>(err),
            h == INVALID_HANDLE_VALUE ? format_win32_error(err).c_str() : "success");
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }

    void close_handle_safe(HANDLE& h) {
        if (h && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            h = nullptr;
        }
    }

    struct network_hook_sidecar_proc_t {
        std::string mode;
        std::string exe_path;
        std::string event_prefix;
        std::string output;
        std::string pending_line;
        HANDLE process = nullptr;
        HANDLE thread = nullptr;
        HANDLE stdout_read = nullptr;
        HANDLE stdout_write = nullptr;
        HANDLE ready_event = nullptr;
        HANDLE go_event = nullptr;
        HANDLE done_event = nullptr;
        DWORD pid = 0;
        uint64_t pg_buffer = 0;
        uint64_t pg_size = 0;
        uint64_t send_addr = 0;
        uint64_t wsasend_addr = 0;
    };

    void log_network_hook_sidecar_launch_context(HANDLE hf, const char* tag, const network_hook_sidecar_proc_t& proc, const std::wstring& exe_full, const std::wstring& exe_extended, const std::wstring& workdir_full, const std::wstring& workdir_extended) {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        SetLastError(0);
        BOOL attr_ok = GetFileAttributesExW(exe_extended.c_str(), GetFileExInfoStandard, &fad);
        DWORD attr_err = attr_ok ? 0 : GetLastError();
        ULARGE_INTEGER size{};
        if (attr_ok) {
            size.HighPart = fad.nFileSizeHigh;
            size.LowPart = fad.nFileSizeLow;
        }
        log_msg(hf, tag, "sidecar launch context mode=%s exe=%s exe_full=%s exe_extended=%s workdir=%s workdir_extended=%s host_pid=%lu host_parent_pid=%lu token=%s",
            proc.mode.c_str(),
            proc.exe_path.c_str(),
            wide_to_utf8(exe_full).c_str(),
            wide_to_utf8(exe_extended).c_str(),
            wide_to_utf8(workdir_full).c_str(),
            wide_to_utf8(workdir_extended).c_str(),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(current_parent_pid()),
            describe_current_token().c_str());
        log_msg(hf, tag, "sidecar exe attributes ok=%d err=%lu text=%s attrs=0x%08lX size=%llu",
            attr_ok ? 1 : 0,
            static_cast<unsigned long>(attr_err),
            attr_ok ? "success" : format_win32_error(attr_err).c_str(),
            attr_ok ? static_cast<unsigned long>(fad.dwFileAttributes) : 0UL,
            static_cast<unsigned long long>(size.QuadPart));
        log_file_open_probe(hf, tag, L"metadata", exe_extended, 0);
        log_file_open_probe(hf, tag, L"read", exe_extended, GENERIC_READ);
        log_file_open_probe(hf, tag, L"execute", exe_extended, FILE_EXECUTE);
    }

    bool parse_number_after_marker(const std::string& text, const char* marker, int base, uint64_t& out) {
        if (!marker)
            return false;
        std::size_t pos = text.find(marker);
        if (pos == std::string::npos)
            return false;
        pos += std::strlen(marker);
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        if (pos >= text.size())
            return false;
        const char* begin = text.c_str() + pos;
        char* end = nullptr;
        errno = 0;
        unsigned long long value = std::strtoull(begin, &end, base);
        if (errno != 0 || end == begin)
            return false;
        out = static_cast<uint64_t>(value);
        return true;
    }

    void parse_network_hook_sidecar_metadata(network_hook_sidecar_proc_t& proc) {
        uint64_t value = 0;
        if (proc.pg_buffer == 0 && parse_number_after_marker(proc.output, "pg_buffer=", 0, value))
            proc.pg_buffer = value;
        if (proc.pg_size == 0 && parse_number_after_marker(proc.output, "pg_size=", 0, value))
            proc.pg_size = value;
        if (proc.send_addr == 0 && parse_number_after_marker(proc.output, "send=", 16, value))
            proc.send_addr = value;
        if (proc.wsasend_addr == 0 && parse_number_after_marker(proc.output, "WSASend=", 16, value))
            proc.wsasend_addr = value;
    }

    void consume_network_hook_sidecar_output(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc) {
        if (!proc.stdout_read)
            return;
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(proc.stdout_read, nullptr, 0, nullptr, &available, nullptr))
                break;
            if (available == 0)
                break;
            char buf[512];
            DWORD to_read = available < static_cast<DWORD>(sizeof(buf)) ? available : static_cast<DWORD>(sizeof(buf));
            DWORD read = 0;
            if (!ReadFile(proc.stdout_read, buf, to_read, &read, nullptr) || read == 0)
                break;
            proc.output.append(buf, buf + read);
            proc.pending_line.append(buf, buf + read);
            for (;;) {
                std::size_t eol = proc.pending_line.find('\n');
                if (eol == std::string::npos)
                    break;
                std::string line = proc.pending_line.substr(0, eol);
                proc.pending_line.erase(0, eol + 1);
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (!line.empty())
                    log_msg(hf, tag, "OUT -- %s", compact_text(line, 900).c_str());
            }
        }
        parse_network_hook_sidecar_metadata(proc);
    }

    void flush_network_hook_sidecar_partial(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc) {
        consume_network_hook_sidecar_output(hf, tag, proc);
        if (!proc.pending_line.empty()) {
            std::string line = proc.pending_line;
            proc.pending_line.clear();
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();
            if (!line.empty())
                log_msg(hf, tag, "OUT -- %s", compact_text(line, 900).c_str());
        }
    }

    std::string find_network_hook_sidecar_path(bool protected_mode) {
        const char* exe = protected_mode ? "AiDA_NetworkHookSidecar_Protected.exe" : "AiDA_NetworkHookSidecar.exe";
        const std::string self = get_self_path_narrow();
        const std::string dir = dirname_narrow(self);
        const std::string parent = dirname_narrow(dir);
        char cwd_buf[MAX_PATH] = {};
        DWORD cwd_len = GetCurrentDirectoryA(MAX_PATH, cwd_buf);
        std::string cwd;
        if (cwd_len > 0 && cwd_len < MAX_PATH)
            cwd.assign(cwd_buf);

        std::vector<std::string> candidates;
        candidates.push_back(join_path_narrow(dir, exe));
        candidates.push_back(join_path_narrow(join_path_narrow(dir, "Release"), exe));
        candidates.push_back(join_path_narrow(parent, exe));
        candidates.push_back(join_path_narrow(join_path_narrow(parent, "Release"), exe));
        if (!cwd.empty()) {
            candidates.push_back(join_path_narrow(cwd, exe));
            candidates.push_back(join_path_narrow(join_path_narrow(cwd, "Release"), exe));
            candidates.push_back(join_path_narrow(join_path_narrow(join_path_narrow(cwd, "build-ninja"), "Release"), exe));
        }
        candidates.push_back(std::string("C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\Release\\") + exe);

        for (const auto& path : candidates) {
            if (file_exists_narrow(path))
                return path;
        }
        return {};
    }

    bool create_network_hook_sidecar_events(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc) {
        proc.ready_event = CreateEventA(nullptr, TRUE, FALSE, (proc.event_prefix + "Ready").c_str());
        proc.go_event = CreateEventA(nullptr, TRUE, FALSE, (proc.event_prefix + "Go").c_str());
        proc.done_event = CreateEventA(nullptr, TRUE, FALSE, (proc.event_prefix + "Done").c_str());
        if (!proc.ready_event || !proc.go_event || !proc.done_event) {
            log_msg(hf, tag, "FAIL -- CreateEvent failed prefix=%s err=%lu",
                proc.event_prefix.c_str(), static_cast<unsigned long>(GetLastError()));
            return false;
        }
        ResetEvent(proc.ready_event);
        ResetEvent(proc.go_event);
        ResetEvent(proc.done_event);
        log_msg(hf, tag, "events prefix=%s", proc.event_prefix.c_str());
        return true;
    }

    bool launch_network_hook_sidecar(HANDLE hf, const char* tag, bool protected_mode, network_hook_sidecar_proc_t& proc) {
        proc.mode = protected_mode ? "protected" : "plain";
        proc.exe_path = find_network_hook_sidecar_path(protected_mode);
        if (proc.exe_path.empty()) {
            log_msg(hf, tag, "SKIP -- %s sidecar executable not found", proc.mode.c_str());
            return false;
        }

        char prefix[160];
        _snprintf_s(prefix, sizeof(prefix), _TRUNCATE, "Local\\AiDANetHook_%lu_%llu_%s_",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(GetTickCount64()),
            proc.mode.c_str());
        proc.event_prefix = prefix;
        if (!create_network_hook_sidecar_events(hf, tag, proc))
            return false;

        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&proc.stdout_read, &proc.stdout_write, &sa, 0)) {
            log_msg(hf, tag, "FAIL -- CreatePipe failed err=%lu", static_cast<unsigned long>(GetLastError()));
            return false;
        }
        SetHandleInformation(proc.stdout_read, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = proc.stdout_write;
        si.hStdError = proc.stdout_write;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi{};
        std::string command = quote_arg_narrow(proc.exe_path) +
            " --event-prefix " + quote_arg_narrow(proc.event_prefix) +
            " --iterations 12 --interval-ms 75 --wait-ms 45000 --mode " + proc.mode +
            " --verbose";
        std::string workdir = dirname_narrow(proc.exe_path);
        std::wstring exe_w = utf8_to_wide(proc.exe_path);
        std::wstring exe_full = full_path_wide(exe_w);
        std::wstring exe_extended = extended_path_wide(exe_full);
        std::wstring workdir_w = utf8_to_wide(workdir);
        std::wstring workdir_full = full_path_wide(workdir_w);
        std::wstring workdir_extended = extended_path_wide(workdir_full);
        std::wstring workdir_create = workdir_full.size() >= MAX_PATH ? workdir_extended : workdir_full;
        std::wstring args_w = L" --event-prefix " + quote_arg_wide(utf8_to_wide(proc.event_prefix)) +
            L" --iterations 12 --interval-ms 75 --wait-ms 45000 --mode " + utf8_to_wide(proc.mode) +
            L" --verbose";
        std::wstring command_w = quote_arg_wide(exe_extended) + args_w;
        std::wstring command_extended_w = quote_arg_wide(exe_extended) + args_w;
        log_network_hook_sidecar_launch_context(hf, tag, proc, exe_full, exe_extended, workdir_full, workdir_extended);

        log_msg(hf, tag, "START -- launching mode=%s exe=%s", proc.mode.c_str(), proc.exe_path.c_str());
        log_msg(hf, tag, "CreateProcess attempt=applicationName app=%s cmd=%s cwd=%s inherit=1 flags=0x%08lX env=null stdin=%p stdout=%p stderr=%p",
            wide_to_utf8(exe_extended).c_str(),
            compact_text(wide_to_utf8(command_w), 900).c_str(),
            wide_to_utf8(workdir_create).c_str(),
            static_cast<unsigned long>(CREATE_NO_WINDOW),
            si.hStdInput,
            si.hStdOutput,
            si.hStdError);
        std::vector<wchar_t> command_mutable(command_w.begin(), command_w.end());
        command_mutable.push_back(L'\0');
        BOOL ok = CreateProcessW(exe_extended.c_str(),
            command_mutable.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            workdir_create.empty() ? nullptr : workdir_create.c_str(),
            &si,
            &pi);
        DWORD first_err = ok ? 0 : GetLastError();
        if (!ok) {
            log_msg(hf, tag, "CreateProcess attempt=applicationName failed err=%lu text=%s command=%s",
                static_cast<unsigned long>(first_err),
                format_win32_error(first_err).c_str(),
                compact_text(wide_to_utf8(command_w), 900).c_str());
            log_msg(hf, tag, "CreateProcess attempt=commandLineOnly app=null cmd=%s cwd=%s inherit=1 flags=0x%08lX env=null stdin=%p stdout=%p stderr=%p",
                compact_text(wide_to_utf8(command_extended_w), 900).c_str(),
                wide_to_utf8(workdir_create).c_str(),
                static_cast<unsigned long>(CREATE_NO_WINDOW),
                si.hStdInput,
                si.hStdOutput,
                si.hStdError);
            std::vector<wchar_t> command_extended_mutable(command_extended_w.begin(), command_extended_w.end());
            command_extended_mutable.push_back(L'\0');
            ok = CreateProcessW(nullptr,
                command_extended_mutable.data(),
                nullptr,
                nullptr,
                TRUE,
                CREATE_NO_WINDOW,
                nullptr,
                workdir_create.empty() ? nullptr : workdir_create.c_str(),
                &si,
                &pi);
            DWORD second_err = ok ? 0 : GetLastError();
            if (!ok) {
                log_msg(hf, tag, "CreateProcess attempt=commandLineOnly failed err=%lu text=%s command=%s",
                    static_cast<unsigned long>(second_err),
                    format_win32_error(second_err).c_str(),
                    compact_text(wide_to_utf8(command_extended_w), 900).c_str());
            } else {
                log_msg(hf, tag, "CreateProcess attempt=commandLineOnly succeeded after applicationName err=%lu text=%s",
                    static_cast<unsigned long>(first_err),
                    format_win32_error(first_err).c_str());
            }
        } else {
            log_msg(hf, tag, "CreateProcess attempt=applicationName succeeded");
        }
        close_handle_safe(proc.stdout_write);
        if (!ok) {
            log_msg(hf, tag, "FAIL -- CreateProcess failed first_err=%lu first_text=%s command=%s",
                static_cast<unsigned long>(first_err), format_win32_error(first_err).c_str(), compact_text(command, 900).c_str());
            return false;
        }
        proc.process = pi.hProcess;
        proc.thread = pi.hThread;
        proc.pid = pi.dwProcessId;
        log_msg(hf, tag, "launched pid=%lu command=%s",
            static_cast<unsigned long>(proc.pid), compact_text(command, 900).c_str());
        return true;
    }

    bool network_hook_sidecar_exited(network_hook_sidecar_proc_t& proc, DWORD& exit_code) {
        exit_code = 0;
        if (!proc.process)
            return true;
        if (!GetExitCodeProcess(proc.process, &exit_code))
            return true;
        return exit_code != STILL_ACTIVE;
    }

    bool wait_network_hook_sidecar_ready(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc, DWORD timeout_ms) {
        const DWORD start = GetTickCount();
        for (;;) {
            consume_network_hook_sidecar_output(hf, tag, proc);
            DWORD wr = WaitForSingleObject(proc.ready_event, 50);
            if (wr == WAIT_OBJECT_0) {
                consume_network_hook_sidecar_output(hf, tag, proc);
                log_msg(hf, tag, "READY -- pid=%lu pg_buffer=0x%016llX pg_size=%llu send=0x%016llX WSASend=0x%016llX",
                    static_cast<unsigned long>(proc.pid),
                    static_cast<unsigned long long>(proc.pg_buffer),
                    static_cast<unsigned long long>(proc.pg_size),
                    static_cast<unsigned long long>(proc.send_addr),
                    static_cast<unsigned long long>(proc.wsasend_addr));
                return true;
            }
            DWORD exit_code = 0;
            if (network_hook_sidecar_exited(proc, exit_code)) {
                flush_network_hook_sidecar_partial(hf, tag, proc);
                log_msg(hf, tag, "FAIL -- sidecar exited before ready exit=0x%08lX",
                    static_cast<unsigned long>(exit_code));
                return false;
            }
            if (GetTickCount() - start >= timeout_ms) {
                flush_network_hook_sidecar_partial(hf, tag, proc);
                log_msg(hf, tag, "FAIL -- sidecar ready timeout after %lu ms", static_cast<unsigned long>(timeout_ms));
                return false;
            }
        }
    }

    DWORD wait_network_hook_sidecar_done(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc, DWORD timeout_ms) {
        const DWORD start = GetTickCount();
        DWORD exit_code = STILL_ACTIVE;
        for (;;) {
            consume_network_hook_sidecar_output(hf, tag, proc);
            if (WaitForSingleObject(proc.done_event, 50) == WAIT_OBJECT_0) {
                WaitForSingleObject(proc.process, 5000);
                consume_network_hook_sidecar_output(hf, tag, proc);
                flush_network_hook_sidecar_partial(hf, tag, proc);
                GetExitCodeProcess(proc.process, &exit_code);
                log_msg(hf, tag, "DONE -- sidecar signaled done exit=0x%08lX output_len=%zu",
                    static_cast<unsigned long>(exit_code), proc.output.size());
                return exit_code;
            }
            if (network_hook_sidecar_exited(proc, exit_code)) {
                flush_network_hook_sidecar_partial(hf, tag, proc);
                log_msg(hf, tag, "DONE -- sidecar process exited exit=0x%08lX output_len=%zu",
                    static_cast<unsigned long>(exit_code), proc.output.size());
                return exit_code;
            }
            if (GetTickCount() - start >= timeout_ms) {
                flush_network_hook_sidecar_partial(hf, tag, proc);
                log_msg(hf, tag, "FAIL -- sidecar done timeout after %lu ms",
                    static_cast<unsigned long>(timeout_ms));
                return STILL_ACTIVE;
            }
        }
    }

    void close_network_hook_sidecar(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc, bool force) {
        if (proc.process) {
            DWORD exit_code = 0;
            if (GetExitCodeProcess(proc.process, &exit_code) && exit_code == STILL_ACTIVE && force) {
                log_msg(hf, tag, "CLEANUP -- terminating sidecar pid=%lu",
                    static_cast<unsigned long>(proc.pid));
                TerminateProcess(proc.process, 0xA1DA);
                WaitForSingleObject(proc.process, 5000);
            }
            flush_network_hook_sidecar_partial(hf, tag, proc);
        }
        close_handle_safe(proc.thread);
        close_handle_safe(proc.process);
        close_handle_safe(proc.stdout_read);
        close_handle_safe(proc.stdout_write);
        close_handle_safe(proc.ready_event);
        close_handle_safe(proc.go_event);
        close_handle_safe(proc.done_event);
    }

    uint32_t json_session_id(const mcp_standalone::json& data) {
        if (!data.is_object() || !data.contains("session_id"))
            return 0;
        const auto& sid = data["session_id"];
        if (sid.is_number_unsigned())
            return sid.get<uint32_t>();
        if (sid.is_number_integer()) {
            auto v = sid.get<int64_t>();
            return v > 0 ? static_cast<uint32_t>(v) : 0;
        }
        return 0;
    }

    bool json_contains_marker(const mcp_standalone::json& data, const std::string& marker) {
        if (marker.empty())
            return false;
        if (data.is_string())
            return data.get<std::string>().find(marker) != std::string::npos;
        if (data.is_array()) {
            for (const auto& item : data) {
                if (json_contains_marker(item, marker))
                    return true;
            }
            return false;
        }
        if (data.is_object()) {
            for (auto it = data.begin(); it != data.end(); ++it) {
                if (it.key().find(marker) != std::string::npos || json_contains_marker(it.value(), marker))
                    return true;
            }
            return false;
        }
        return false;
    }

    struct sidecar_capture_coverage_t {
        size_t captures = 0;
        std::set<std::string> iterations;
    };

    bool is_iteration_tag(const std::string& text, size_t pos) {
        if (!(pos + 3 <= text.size() &&
            std::isdigit(static_cast<unsigned char>(text[pos])) &&
            std::isdigit(static_cast<unsigned char>(text[pos + 1])) &&
            std::isdigit(static_cast<unsigned char>(text[pos + 2]))))
            return false;
        const int value = (text[pos] - '0') * 100 + (text[pos + 1] - '0') * 10 + (text[pos + 2] - '0');
        return value >= 0 && value <= 11;
    }

    void collect_iteration_tags_near_marker(const std::string& text,
                                            const std::string& marker,
                                            std::set<std::string>& iterations) {
        if (marker.empty() || text.empty())
            return;
        size_t pos = 0;
        while ((pos = text.find(marker, pos)) != std::string::npos) {
            const size_t scan_end = std::min(text.size(), pos + marker.size() + 160);
            size_t iter_pos = text.find("iteration=", pos);
            if (iter_pos != std::string::npos && iter_pos + 13 <= scan_end) {
                iter_pos += 10;
                if (is_iteration_tag(text, iter_pos))
                    iterations.insert(text.substr(iter_pos, 3));
            }
            pos += marker.size();
        }
    }

    void collect_iteration_tags_anywhere(const std::string& text,
                                         std::set<std::string>& iterations) {
        if (text.empty())
            return;
        size_t pos = 0;
        while ((pos = text.find("iteration=", pos)) != std::string::npos) {
            const size_t tag_pos = pos + 10;
            if (is_iteration_tag(text, tag_pos))
                iterations.insert(text.substr(tag_pos, 3));
            pos = tag_pos;
        }
    }

    bool is_page_guard_capture_fragment(const std::string& text) {
        return text.find("iteration=") != std::string::npos &&
            (text.find("fault_addr") != std::string::npos ||
                text.find("payload_offset") != std::string::npos ||
                text.find("access_type") != std::string::npos ||
                text.find("exception_code") != std::string::npos);
    }

    void collect_marker_coverage_from_capture_array(const mcp_standalone::json& arr,
                                                    const std::string& marker,
                                                    sidecar_capture_coverage_t& stats) {
        if (!arr.is_array())
            return;
        for (const auto& item : arr) {
            const std::string compact = compact_json(item, 3600);
            const bool full_marker = json_contains_marker(item, marker);
            const bool page_guard_fragment = marker.rfind("AIDA_PG_SNIFF", 0) == 0 && is_page_guard_capture_fragment(compact);
            if (!full_marker && !page_guard_fragment)
                continue;
            ++stats.captures;
            if (full_marker)
                collect_iteration_tags_near_marker(compact, marker, stats.iterations);
            if (page_guard_fragment)
                collect_iteration_tags_anywhere(compact, stats.iterations);
        }
    }

    void collect_marker_coverage_from_text(const std::string& text,
                                           const std::string& marker,
                                           sidecar_capture_coverage_t& stats) {
        if (marker.empty())
            return;
        size_t pos = 0;
        while ((pos = text.find(marker, pos)) != std::string::npos) {
            ++stats.captures;
            pos += marker.size();
        }
        collect_iteration_tags_near_marker(text, marker, stats.iterations);
    }

    sidecar_capture_coverage_t marker_coverage_from_result(const invoke_result_t& ir,
                                                           const std::string& marker) {
        sidecar_capture_coverage_t stats;
        if (ir.data.is_array()) {
            collect_marker_coverage_from_capture_array(ir.data, marker, stats);
        } else {
            const auto* captures = find_payload_key_recursive(ir.data, "captures");
            if (captures && captures->is_array())
                collect_marker_coverage_from_capture_array(*captures, marker, stats);
        }
        if (stats.captures == 0)
            collect_marker_coverage_from_text(ir.text + compact_json(ir.data, 4000), marker, stats);
        return stats;
    }

    std::string iteration_coverage_summary(const std::set<std::string>& iterations) {
        std::string out;
        for (const auto& tag : iterations) {
            if (!out.empty())
                out.push_back(',');
            out += tag;
        }
        return out.empty() ? std::string("-") : out;
    }

    struct sidecar_tool_call_result_t {
        bool ok = false;
        bool timed_out = false;
        invoke_result_t result;
        long long elapsed_ms = 0;
    };

    sidecar_tool_call_result_t invoke_sidecar_tool(HANDLE hf,
                                                   const char* tag,
                                                   const std::string& tool,
                                                   const mcp_standalone::json& args,
                                                   long long timeout_ms,
                                                   bool required) {
        sidecar_tool_call_result_t out;
        g_invoked_tools.insert(tool);
        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        log_msg(hf, tag, "TOOL START -- #%d %s args=%s",
            seq, tool.c_str(), compact_json(args, 1000).c_str());
        auto timed = invoke_tool_bounded(get_server(), tool, args, timeout_ms);
        out.timed_out = timed.timed_out;
        out.result = std::move(timed.result);
        out.elapsed_ms = timed.elapsed_ms;
        if (out.timed_out) {
            log_msg(hf, tag, "%s -- #%d %s timed out after %lld ms",
                required ? "FAIL" : "WARN", seq, tool.c_str(), timeout_ms);
            log_mcp_result_detail("sidecar_timeout", seq, tool, args, out.result, timeout_ms, "watchdog_timeout");
            cancel_timed_out_tool(hf, tag, tool);
            record_tool_status(tool, required ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::skipped);
            return out;
        }
        const std::string reason = out.result.threw ? out.result.exception_msg : out.result.text;
        log_mcp_result_detail("sidecar_completed", seq, tool, args, out.result, out.elapsed_ms, reason);
        out.ok = out.result.found && !out.result.threw && out.result.success;
        log_msg(hf, tag, "TOOL %s -- #%d %s elapsed=%lld found=%d success=%d threw=%d text=%s data=%s",
            out.ok ? "PASS" : (required ? "FAIL" : "WARN"),
            seq,
            tool.c_str(),
            out.elapsed_ms,
            out.result.found ? 1 : 0,
            out.result.success ? 1 : 0,
            out.result.threw ? 1 : 0,
            compact_text(out.result.text, 900).c_str(),
            compact_json(out.result.data, 1200).c_str());
        record_tool_status(tool, out.ok ? mcp_tool_call_status_t::passed :
            (required ? mcp_tool_call_status_t::failed : mcp_tool_call_status_t::skipped));
        return out;
    }

    uint64_t find_remote_module_base_ci(uint32_t pid, const char* module_fragment) {
        if (pid == 0 || !module_fragment)
            return 0;
        const std::string needle = lower_copy(module_fragment);
        for (const auto& mod : driver_bridge::enumerate_modules_for(pid)) {
            std::string name = lower_copy(mod.name);
            std::string path = lower_copy(mod.path);
            if (name.find(needle) != std::string::npos || path.find(needle) != std::string::npos)
                return mod.base;
        }
        return 0;
    }

    bool select_sidecar_driver_pid(HANDLE hf, const char* tag, uint32_t pid) {
        if (pid == 0)
            return false;
        bool known = false;
        for (uint32_t attached_pid : driver_bridge::attached_pids()) {
            if (attached_pid == pid) {
                known = true;
                break;
            }
        }
        bool attached = known ? true : driver_bridge::attach_additional(pid);
        if (!attached)
            attached = driver_bridge::attach(pid);
        if (!attached) {
            log_msg(hf, tag, "FAIL -- driver attach failed pid=%u status=%s error=%s",
                pid, driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
            return false;
        }
        if (!driver_bridge::set_active_pid(pid)) {
            log_msg(hf, tag, "FAIL -- set_active_pid failed pid=%u status=%s error=%s",
                pid, driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
            return false;
        }
        return true;
    }

    bool wait_pre_encrypt_marker_coverage(HANDLE hf,
                                          const char* tag,
                                          const std::string& marker,
                                          size_t required_captures,
                                          DWORD timeout_ms,
                                          std::string& aggregate,
                                          sidecar_capture_coverage_t& coverage) {
        const DWORD start = GetTickCount();
        for (;;) {
            mcp_standalone::json args;
            args["operation"] = "get_captures";
            args["max_count"] = 256;
            auto call = invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 10000, false);
            if (call.ok) {
                aggregate += call.result.text;
                aggregate += compact_json(call.result.data, 2400);
                coverage = marker_coverage_from_result(call.result, marker);
                if (coverage.captures >= required_captures) {
                    log_msg(hf, tag, "CAPTURE -- pre_encrypt marker=%s captures=%zu required=%zu iterations=%zu[%s]",
                        marker.c_str(),
                        coverage.captures,
                        required_captures,
                        coverage.iterations.size(),
                        iteration_coverage_summary(coverage.iterations).c_str());
                    return true;
                }
            }
            if (GetTickCount() - start >= timeout_ms)
                break;
            Sleep(125);
        }
        log_msg(hf, tag, "MISS -- pre_encrypt marker=%s captures=%zu required=%zu iterations=%zu[%s] aggregate=%s",
            marker.c_str(),
            coverage.captures,
            required_captures,
            coverage.iterations.size(),
            iteration_coverage_summary(coverage.iterations).c_str(),
            compact_text(aggregate, 1200).c_str());
        return false;
    }

    bool wait_page_guard_marker_coverage(HANDLE hf,
                                         const char* tag,
                                         uint32_t session_id,
                                         const std::string& marker,
                                         size_t required_distinct_iterations,
                                         DWORD timeout_ms,
                                         std::string& aggregate,
                                         sidecar_capture_coverage_t& coverage) {
        const DWORD start = GetTickCount();
        for (;;) {
            mcp_standalone::json args;
            args["operation"] = "get_captures";
            args["session_id"] = session_id;
            auto call = invoke_sidecar_tool(hf, tag, "network_pg_sniff", args, 10000, false);
            if (call.ok) {
                aggregate += call.result.text;
                aggregate += compact_json(call.result.data, 3000);
                sidecar_capture_coverage_t delta = marker_coverage_from_result(call.result, marker);
                coverage.captures += delta.captures;
                coverage.iterations.insert(delta.iterations.begin(), delta.iterations.end());
                if (coverage.iterations.size() >= required_distinct_iterations) {
                    log_msg(hf, tag, "CAPTURE -- page_guard marker=%s captures=%zu distinct_iterations=%zu required=%zu iterations=%s",
                        marker.c_str(),
                        coverage.captures,
                        coverage.iterations.size(),
                        required_distinct_iterations,
                        iteration_coverage_summary(coverage.iterations).c_str());
                    return true;
                }
            }
            if (GetTickCount() - start >= timeout_ms)
                break;
            Sleep(125);
        }
        log_msg(hf, tag, "MISS -- page_guard marker=%s captures=%zu distinct_iterations=%zu required=%zu iterations=%s aggregate=%s",
            marker.c_str(),
            coverage.captures,
            coverage.iterations.size(),
            required_distinct_iterations,
            iteration_coverage_summary(coverage.iterations).c_str(),
            compact_text(aggregate, 1200).c_str());
        return false;
    }

    enum class sidecar_case_result_t {
        passed,
        failed,
        skipped
    };

    sidecar_case_result_t run_network_hook_sidecar_e2e(HANDLE hf, bool protected_mode) {
        const char* tag = protected_mode ? "mcp.network_hooks.sidecar.protected" : "mcp.network_hooks.sidecar.plain";
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "SKIP -- kernel driver is required for remote page-guard and hardware-breakpoint capture");
            return sidecar_case_result_t::skipped;
        }
        if (!tool_registered(get_server(), "network_pg_sniff") || !tool_registered(get_server(), "network_pre_encrypt_hook")) {
            log_msg(hf, tag, "FAIL -- required MCP tools are not registered");
            return sidecar_case_result_t::failed;
        }

        network_hook_sidecar_proc_t proc;
        uint32_t page_guard_session = 0;
        uint32_t previous_pid = driver_bridge::attached_pid();
        bool launched = false;
        bool signaled_go = false;

        auto cleanup = [&](bool force_sidecar) {
            if (page_guard_session != 0) {
                mcp_standalone::json args;
                args["operation"] = "uninstall";
                args["session_id"] = page_guard_session;
                invoke_sidecar_tool(hf, tag, "network_pg_sniff", args, 15000, false);
                page_guard_session = 0;
            }
            {
                mcp_standalone::json args;
                args["operation"] = "unhook_all";
                invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 15000, false);
            }
            {
                mcp_standalone::json args;
                args["operation"] = "clear";
                invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 10000, false);
            }
            if (previous_pid != 0)
                driver_bridge::set_active_pid(previous_pid);
            else
                driver_bridge::clear_active_pid();
            if (launched)
                close_network_hook_sidecar(hf, tag, proc, force_sidecar);
        };

        auto fail_case = [&](const std::string& reason) {
            log_msg(hf, tag, "FAIL -- %s", reason.c_str());
            cleanup(true);
            return sidecar_case_result_t::failed;
        };

        if (!launch_network_hook_sidecar(hf, tag, protected_mode, proc)) {
            close_network_hook_sidecar(hf, tag, proc, true);
            return protected_mode ? sidecar_case_result_t::skipped : sidecar_case_result_t::failed;
        }
        launched = true;
        if (!wait_network_hook_sidecar_ready(hf, tag, proc, 20000))
            return fail_case("sidecar never reached the ready gate");
        if (proc.pg_buffer == 0 || proc.pg_size == 0)
            return fail_case("sidecar did not publish a valid page-guard buffer");
        if (!select_sidecar_driver_pid(hf, tag, proc.pid))
            return fail_case("driver could not attach to sidecar PID");

        uint64_t ws2_base = find_remote_module_base_ci(proc.pid, "ws2_32");
        uint64_t send_addr = ws2_base ? driver_bridge::resolve_export(ws2_base, "send") : 0;
        uint64_t wsasend_addr = ws2_base ? driver_bridge::resolve_export(ws2_base, "WSASend") : 0;
        if (send_addr == 0)
            send_addr = proc.send_addr;
        if (wsasend_addr == 0)
            wsasend_addr = proc.wsasend_addr;
        log_msg(hf, tag, "resolved ws2_32=0x%016llX send=0x%016llX WSASend=0x%016llX sidecar_send=0x%016llX sidecar_WSASend=0x%016llX",
            static_cast<unsigned long long>(ws2_base),
            static_cast<unsigned long long>(send_addr),
            static_cast<unsigned long long>(wsasend_addr),
            static_cast<unsigned long long>(proc.send_addr),
            static_cast<unsigned long long>(proc.wsasend_addr));
        if (send_addr == 0 || wsasend_addr == 0)
            return fail_case("could not resolve send and WSASend in sidecar");

        {
            mcp_standalone::json args;
            args["operation"] = "unhook_all";
            invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 15000, false);
        }
        {
            mcp_standalone::json args;
            args["operation"] = "clear";
            invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 10000, false);
        }

        {
            mcp_standalone::json args;
            args["operation"] = "install";
            args["pid"] = proc.pid;
            args["address"] = hex_u64(proc.pg_buffer);
            args["size"] = proc.pg_size;
            auto call = invoke_sidecar_tool(hf, tag, "network_pg_sniff", args, 30000, true);
            if (!call.ok)
                return fail_case("network_pg_sniff install failed");
            page_guard_session = json_session_id(call.result.data);
            if (page_guard_session == 0)
                return fail_case("network_pg_sniff did not return a session_id");
        }

        {
            mcp_standalone::json args;
            args["operation"] = "hook_address";
            args["pid"] = proc.pid;
            args["address"] = hex_u64(send_addr);
            args["name"] = "ws2_32.dll!send";
            args["buffer_reg"] = 1;
            args["size_reg"] = 2;
            auto call = invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 30000, true);
            if (!call.ok)
                return fail_case("network_pre_encrypt_hook failed to hook send");
        }

        {
            mcp_standalone::json args;
            args["operation"] = "hook_address";
            args["pid"] = proc.pid;
            args["address"] = hex_u64(wsasend_addr);
            args["name"] = "ws2_32.dll!WSASend";
            args["buffer_reg"] = 1;
            args["size_reg"] = 2;
            auto call = invoke_sidecar_tool(hf, tag, "network_pre_encrypt_hook", args, 30000, true);
            if (!call.ok)
                return fail_case("network_pre_encrypt_hook failed to hook WSASend");
        }

        if (!SetEvent(proc.go_event))
            return fail_case("failed to signal sidecar Go event");
        signaled_go = true;
        log_msg(hf, tag, "GO -- sidecar released mode=%s pid=%lu",
            proc.mode.c_str(), static_cast<unsigned long>(proc.pid));

        const DWORD sidecar_done_timeout_ms = protected_mode ? 60000UL : 90000UL;
        DWORD sidecar_exit = wait_network_hook_sidecar_done(hf, tag, proc, sidecar_done_timeout_ms);
        if (sidecar_exit == STILL_ACTIVE)
            return fail_case("sidecar did not complete after Go event");

        std::string pre_send_aggregate;
        std::string pre_wsasend_aggregate;
        std::string pg_aggregate;
        sidecar_capture_coverage_t pre_send_coverage;
        sidecar_capture_coverage_t pre_wsasend_coverage;
        sidecar_capture_coverage_t pg_coverage;
        const bool pre_send = wait_pre_encrypt_marker_coverage(hf, tag, "AIDA_PRE_ENCRYPT_SEND", 12, 10000, pre_send_aggregate, pre_send_coverage);
        const bool pre_wsasend = wait_pre_encrypt_marker_coverage(hf, tag, "AIDA_PRE_ENCRYPT_WSASEND_A", 12, 10000, pre_wsasend_aggregate, pre_wsasend_coverage);
        const size_t required_pg_iterations = protected_mode ? 2 : 3;
        const bool pg_seen = wait_page_guard_marker_coverage(hf, tag, page_guard_session, "AIDA_PG_SNIFF_DETERMINISTIC_BUFFER", required_pg_iterations, 10000, pg_aggregate, pg_coverage);
        const bool sidecar_completed_payload = proc.output.find("[sidecar] complete") != std::string::npos &&
            proc.output.find("AIDA_PRE_ENCRYPT_SEND") != std::string::npos &&
            proc.output.find("AIDA_PRE_ENCRYPT_WSASEND_A") != std::string::npos &&
            proc.output.find("AIDA_PG_SNIFF_DETERMINISTIC_BUFFER") != std::string::npos;

        log_msg(hf, tag, "ASSERT -- mode=%s go=%d exit=0x%08lX pre_send=%d captures=%zu iter=%zu[%s] pre_wsasend=%d captures=%zu iter=%zu[%s] page_guard=%d captures=%zu iter=%zu[%s] sidecar_payload=%d output_len=%zu",
            proc.mode.c_str(),
            signaled_go ? 1 : 0,
            static_cast<unsigned long>(sidecar_exit),
            pre_send ? 1 : 0,
            pre_send_coverage.captures,
            pre_send_coverage.iterations.size(),
            iteration_coverage_summary(pre_send_coverage.iterations).c_str(),
            pre_wsasend ? 1 : 0,
            pre_wsasend_coverage.captures,
            pre_wsasend_coverage.iterations.size(),
            iteration_coverage_summary(pre_wsasend_coverage.iterations).c_str(),
            pg_seen ? 1 : 0,
            pg_coverage.captures,
            pg_coverage.iterations.size(),
            iteration_coverage_summary(pg_coverage.iterations).c_str(),
            sidecar_completed_payload ? 1 : 0,
            proc.output.size());

        if (sidecar_exit != 0)
            return fail_case("sidecar reported a non-zero exit status");
        if (!sidecar_completed_payload)
            return fail_case("sidecar did not emit the expected deterministic payload markers");
        if (!pre_send || !pre_wsasend)
            return fail_case("pre-encryption MCP captures did not cover all 12 sidecar send and WSASend iterations");
        if (!pg_seen)
            return fail_case("page-guard MCP captures did not cover the required distinct deterministic buffer iterations; captures=" +
                std::to_string(pg_coverage.captures) +
                " distinct=" +
                std::to_string(pg_coverage.iterations.size()) +
                " required=" +
                std::to_string(required_pg_iterations) +
                " iterations=" +
                iteration_coverage_summary(pg_coverage.iterations));

        cleanup(false);
        log_msg(hf, tag, "PASS -- mode=%s pre_send=%zu/12 pre_wsasend=%zu/12 page_guard_captures=%zu page_guard_iter=%zu/%zu iterations=%s",
            proc.mode.c_str(),
            pre_send_coverage.captures,
            pre_wsasend_coverage.captures,
            pg_coverage.captures,
            pg_coverage.iterations.size(),
            required_pg_iterations,
            iteration_coverage_summary(pg_coverage.iterations).c_str());
        return sidecar_case_result_t::passed;
    }

    std::string base64_encode_bytes(const uint8_t* data, size_t len) {
        static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((len + 2) / 3) * 4);
        for (size_t i = 0; i < len; i += 3) {
            uint32_t v = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < len)
                v |= static_cast<uint32_t>(data[i + 1]) << 8;
            if (i + 2 < len)
                v |= static_cast<uint32_t>(data[i + 2]);
            out.push_back(table[(v >> 18) & 0x3F]);
            out.push_back(table[(v >> 12) & 0x3F]);
            out.push_back(i + 1 < len ? table[(v >> 6) & 0x3F] : '=');
            out.push_back(i + 2 < len ? table[v & 0x3F] : '=');
        }
        return out;
    }

    bool sha1_bytes(const std::string& input, uint8_t out_hash[20]) {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD object_len = 0;
        DWORD cb = 0;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0)))
            return false;
        bool ok = false;
        if (BCRYPT_SUCCESS(BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_len), sizeof(object_len), &cb, 0))) {
            std::vector<uint8_t> object_buf(object_len);
            if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, object_buf.data(), object_len, nullptr, 0, 0)) &&
                BCRYPT_SUCCESS(BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0)) &&
                BCRYPT_SUCCESS(BCryptFinishHash(hash, out_hash, 20, 0))) {
                ok = true;
            }
        }
        if (hash)
            BCryptDestroyHash(hash);
        if (alg)
            BCryptCloseAlgorithmProvider(alg, 0);
        return ok;
    }

    std::string trim_http_value(std::string v) {
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
            v.erase(v.begin());
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r' || v.back() == '\n'))
            v.pop_back();
        return v;
    }

    std::string http_header_value(const std::string& req, const char* name) {
        if (!name)
            return {};
        const std::string target = lower_copy(name);
        size_t pos = 0;
        while (pos < req.size()) {
            size_t end = req.find("\r\n", pos);
            if (end == std::string::npos)
                end = req.size();
            std::string line = req.substr(pos, end - pos);
            size_t colon = line.find(':');
            if (colon != std::string::npos && lower_copy(line.substr(0, colon)) == target)
                return trim_http_value(line.substr(colon + 1));
            pos = end + 2;
        }
        return {};
    }

    std::string websocket_accept_value(const std::string& client_key) {
        uint8_t hash[20] = {};
        if (!sha1_bytes(client_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", hash))
            return {};
        return base64_encode_bytes(hash, sizeof(hash));
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

    std::string get_remote_ntclose_addr_str() {
        const uint64_t addr = resolve_remote_export("ntdll.dll", "NtClose");
        return addr != 0 ? hex_u64(addr) : get_ntclose_addr_str();
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

        auto threads = driver_bridge::enumerate_threads();
        std::vector<uint32_t> tids;
        if (debugger_engine::g_state.active_tid != 0) {
            for (const auto& t : threads) {
                if (t.owner_pid == pid && t.tid == debugger_engine::g_state.active_tid) {
                    tids.push_back(t.tid);
                    break;
                }
            }
        }
        for (const auto& t : threads) {
            if (t.owner_pid != pid)
                continue;
            if (std::find(tids.begin(), tids.end(), t.tid) == tids.end())
                tids.push_back(t.tid);
        }

        for (uint32_t candidate : tids) {
            uint32_t suspend_count = 0;
            if (!driver_bridge::suspend_thread(candidate, &suspend_count))
                continue;

            driver_bridge::thread_context_t probe{};
            const bool context_ok = driver_bridge::get_thread_context(candidate, probe) && probe.rip != 0 && probe.rsp != 0;
            uint32_t resume_previous = 0;
            (void)driver_bridge::resume_thread(candidate, &resume_previous);
            if (context_ok) {
                debugger_engine::g_state.active_tid = candidate;
                return candidate;
            }
        }
        if (!tids.empty())
            return tids.front();
        return 0;
    }

    bool acquire_contextable_mcp_thread(HANDLE hf,
                                        const char* tag,
                                        const char* purpose,
                                        uint32_t& tid,
                                        uint32_t& original_suspend_count,
                                        driver_bridge::thread_context_t& ctx) {
        const uint32_t pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : driver_bridge::attached_pid();
        if (pid == 0) {
            log_msg(hf, tag, "FAIL -- no attached target for %s", purpose);
            return false;
        }
        if (driver_bridge::attached_pid() != pid)
            (void)driver_bridge::attach(pid);

        std::vector<uint32_t> tids;
        auto threads = driver_bridge::enumerate_threads();
        if (debugger_engine::g_state.active_tid != 0) {
            for (const auto& t : threads) {
                if (t.owner_pid == pid && t.tid == debugger_engine::g_state.active_tid) {
                    tids.push_back(t.tid);
                    break;
                }
            }
        }
        for (const auto& t : threads) {
            if (t.owner_pid != pid)
                continue;
            if (std::find(tids.begin(), tids.end(), t.tid) == tids.end())
                tids.push_back(t.tid);
        }

        for (uint32_t candidate : tids) {
            uint32_t suspend_count = 0;
            if (!driver_bridge::suspend_thread(candidate, &suspend_count)) {
                log_msg(hf, tag, "INFO -- %s candidate tid=%u suspend rejected", purpose, candidate);
                continue;
            }
            driver_bridge::thread_context_t probe{};
            if (driver_bridge::get_thread_context(candidate, probe) && probe.rip != 0 && probe.rsp != 0) {
                tid = candidate;
                original_suspend_count = suspend_count;
                ctx = probe;
                debugger_engine::g_state.active_tid = candidate;
                log_msg(hf, tag, "INFO -- %s selected contextable tid=%u rip=0x%llX rsp=0x%llX original_suspend=%u",
                    purpose,
                    candidate,
                    static_cast<unsigned long long>(probe.rip),
                    static_cast<unsigned long long>(probe.rsp),
                    suspend_count);
                return true;
            }
            uint32_t resume_prev = 0;
            (void)driver_bridge::resume_thread(candidate, &resume_prev);
            log_msg(hf, tag, "INFO -- %s candidate tid=%u context rejected rip=0x%llX rsp=0x%llX",
                purpose,
                candidate,
                static_cast<unsigned long long>(probe.rip),
                static_cast<unsigned long long>(probe.rsp));
        }

        log_msg(hf, tag, "FAIL -- no contextable target thread available for %s pid=%u candidates=%zu",
            purpose, pid, tids.size());
        return false;
    }

    bool restore_mcp_thread_context(uint32_t tid,
                                    const driver_bridge::thread_context_t& ctx,
                                    uint32_t desired_suspend_count) {
        if (tid == 0)
            return false;
        uint32_t previous_suspend_count = 0;
        if (!driver_bridge::suspend_thread(tid, &previous_suspend_count))
            return false;
        bool ctx_ok = driver_bridge::set_thread_context(tid, ctx, ~0ULL);
        uint32_t current = previous_suspend_count < 0xFFFFFFFFu ? previous_suspend_count + 1 : previous_suspend_count;
        bool depth_ok = true;
        for (int guard = 0; current > desired_suspend_count && guard < 64; ++guard) {
            uint32_t resume_previous = 0;
            if (!driver_bridge::resume_thread(tid, &resume_previous)) {
                depth_ok = false;
                break;
            }
            current = resume_previous > 0 ? resume_previous - 1 : 0;
        }
        return ctx_ok && depth_ok && current == desired_suspend_count;
    }

    struct mcp_step_fixture_t {
        uint32_t tid = 0;
        uint32_t original_suspend_count = 0;
        uint64_t code = 0;
        uint64_t expected_rip = 0;
        driver_bridge::thread_context_t before{};
        bool prepared = false;
    };

    bool prepare_mcp_step_fixture(HANDLE hf, const char* tag, mcp_step_fixture_t& fx) {
        if (!ensure_mcp_target_live(hf, tag))
            return false;
        if (!acquire_contextable_mcp_thread(hf, tag, "controlled step fixture", fx.tid, fx.original_suspend_count, fx.before))
            return false;

        fx.code = driver_bridge::allocate_memory(64);
        bool ok = fx.code != 0;
        if (ok) {
            std::vector<uint8_t> code_bytes(64, 0x90);
            code_bytes[3] = 0xC3;
            ok = driver_bridge::write_memory(fx.code, code_bytes);
        }
        if (ok) {
            uint32_t old_protect = 0;
            ok = driver_bridge::protect_memory(fx.code, 64, PAGE_EXECUTE_READWRITE, &old_protect);
        }
        if (ok) {
            auto ctx = fx.before;
            ctx.rip = fx.code;
            ctx.rflags &= ~0x100ULL;
            ok = driver_bridge::set_thread_context(fx.tid, ctx, ~0ULL);
            fx.expected_rip = fx.code + 1;
        }
        if (!ok) {
            (void)restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
            if (fx.code) driver_bridge::free_memory(fx.code);
            log_msg(hf, tag, "FAIL -- could not build controlled step fixture tid=%u code=0x%llX",
                fx.tid, static_cast<unsigned long long>(fx.code));
            return false;
        }
        fx.prepared = true;
        log_msg(hf, tag, "INFO -- controlled step fixture tid=%u entry=0x%llX expected=0x%llX",
            fx.tid,
            static_cast<unsigned long long>(fx.code),
            static_cast<unsigned long long>(fx.expected_rip));
        return true;
    }

    void cleanup_mcp_step_fixture(const mcp_step_fixture_t& fx) {
        if (fx.tid != 0)
            (void)restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
        if (fx.code)
            driver_bridge::free_memory(fx.code);
    }

    struct mcp_step_out_fixture_t {
        uint32_t tid = 0;
        uint32_t original_suspend_count = 0;
        uint64_t code = 0;
        uint64_t stack = 0;
        uint64_t ret_addr = 0;
        uint64_t rsp = 0;
        driver_bridge::thread_context_t before{};
        bool prepared = false;
    };

    bool prepare_mcp_step_out_fixture(HANDLE hf, const char* tag, mcp_step_out_fixture_t& fx) {
        if (!ensure_mcp_target_live(hf, tag))
            return false;
        if (!acquire_contextable_mcp_thread(hf, tag, "controlled step_out fixture", fx.tid, fx.original_suspend_count, fx.before))
            return false;
        fx.code = driver_bridge::allocate_memory(64);
        fx.stack = driver_bridge::allocate_memory(0x1000);
        fx.ret_addr = fx.code ? fx.code + 0x10 : 0;
        fx.rsp = fx.stack ? fx.stack + 0x800 : 0;
        bool ok = fx.code != 0 && fx.stack != 0;
        if (ok) {
            std::vector<uint8_t> code_bytes(64, 0x90);
            code_bytes[0] = 0xC3;
            ok = driver_bridge::write_memory(fx.code, code_bytes);
        }
        if (ok) {
            std::vector<uint8_t> stack_bytes(8, 0);
            std::memcpy(stack_bytes.data(), &fx.ret_addr, sizeof(fx.ret_addr));
            ok = driver_bridge::write_memory(fx.rsp, stack_bytes);
        }
        if (ok) {
            uint32_t old_protect = 0;
            ok = driver_bridge::protect_memory(fx.code, 64, PAGE_EXECUTE_READWRITE, &old_protect);
        }
        if (ok) {
            auto ctx = fx.before;
            ctx.rip = fx.code;
            ctx.rsp = fx.rsp;
            ctx.rflags &= ~0x100ULL;
            ok = driver_bridge::set_thread_context(fx.tid, ctx, ~0ULL);
        }
        if (!ok) {
            (void)restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
            if (fx.code) driver_bridge::free_memory(fx.code);
            if (fx.stack) driver_bridge::free_memory(fx.stack);
            log_msg(hf, tag, "FAIL -- could not build controlled step_out fixture tid=%u code=0x%llX stack=0x%llX",
                fx.tid,
                static_cast<unsigned long long>(fx.code),
                static_cast<unsigned long long>(fx.stack));
            return false;
        }
        fx.prepared = true;
        log_msg(hf, tag, "INFO -- controlled step_out fixture tid=%u entry=0x%llX ret=0x%llX rsp=0x%llX",
            fx.tid,
            static_cast<unsigned long long>(fx.code),
            static_cast<unsigned long long>(fx.ret_addr),
            static_cast<unsigned long long>(fx.rsp));
        return true;
    }

    void cleanup_mcp_step_out_fixture(const mcp_step_out_fixture_t& fx) {
        if (fx.tid != 0)
            (void)restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
        if (fx.code) driver_bridge::free_memory(fx.code);
        if (fx.stack) driver_bridge::free_memory(fx.stack);
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

    struct mcp_burp_http_fixture_t {
        SOCKET listener = INVALID_SOCKET;
        std::thread worker;
        std::atomic<bool> stop{false};
        uint16_t port = 0;

        bool start(HANDLE hf, const char* tag) {
            if (!ensure_mcp_winsock_ready()) {
                log_msg(hf, tag, "SKIP -- WSAStartup failed for Burp HTTP fixture");
                return false;
            }
            listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                log_msg(hf, tag, "SKIP -- fixture listener socket failed err=%d", WSAGetLastError());
                return false;
            }
            u_long nonblocking = 1;
            ioctlsocket(listener, FIONBIO, &nonblocking);
            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
                listen(listener, SOMAXCONN) == SOCKET_ERROR) {
                log_msg(hf, tag, "SKIP -- fixture bind/listen failed err=%d", WSAGetLastError());
                close();
                return false;
            }
            int addr_len = sizeof(addr);
            if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len) == SOCKET_ERROR) {
                log_msg(hf, tag, "SKIP -- fixture getsockname failed err=%d", WSAGetLastError());
                close();
                return false;
            }
            port = ntohs(addr.sin_port);
            stop.store(false, std::memory_order_release);
            worker = std::thread([this]() { run(); });
            log_msg(hf, tag, "Burp HTTP fixture listening on 127.0.0.1:%u", static_cast<unsigned>(port));
            return port != 0;
        }

        void run() {
            while (!stop.load(std::memory_order_acquire)) {
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(listener, &rfds);
                timeval tv = {};
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                int sel = select(0, &rfds, nullptr, nullptr, &tv);
                if (sel <= 0)
                    continue;
                SOCKET s = accept(listener, nullptr, nullptr);
                if (s == INVALID_SOCKET)
                    continue;
                u_long blocking = 0;
                ioctlsocket(s, FIONBIO, &blocking);
                handle_client(s);
                closesocket(s);
            }
        }

        void handle_client(SOCKET s) {
            DWORD timeout = 1500;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            char buf[4096] = {};
            int got = recv(s, buf, sizeof(buf) - 1, 0);
            if (got <= 0)
                return;
            std::string req(buf, buf + got);
            std::string content_length = http_header_value(req, "Content-Length");
            size_t expected_body = 0;
            if (!content_length.empty()) {
                try { expected_body = static_cast<size_t>(std::stoull(content_length)); } catch (...) { expected_body = 0; }
            }
            size_t header_end = req.find("\r\n\r\n");
            while (header_end != std::string::npos &&
                   expected_body > 0 &&
                   req.size() < header_end + 4 + expected_body &&
                   req.size() < 1024 * 1024) {
                char more[4096] = {};
                int n = recv(s, more, sizeof(more), 0);
                if (n <= 0)
                    break;
                req.append(more, more + n);
            }
            std::string req_lc = lower_copy(req);
            if (req.rfind("GET ", 0) == 0 && req_lc.find("upgrade: websocket") != std::string::npos) {
                const std::string key = http_header_value(req, "Sec-WebSocket-Key");
                const std::string accept = websocket_accept_value(key);
                if (accept.empty())
                    return;
                std::string resp = "HTTP/1.1 101 Switching Protocols\r\n";
                resp += "Upgrade: websocket\r\n";
                resp += "Connection: Upgrade\r\n";
                resp += "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
                send(s, resp.data(), static_cast<int>(resp.size()), 0);
                for (int i = 0; i < 20 && !stop.load(std::memory_order_acquire); ++i) {
                    char frame[512] = {};
                    int n = recv(s, frame, sizeof(frame), 0);
                    if (n <= 0)
                        break;
                    if ((frame[0] & 0x0F) == 0x8) {
                        const char close_frame[2] = { static_cast<char>(0x88), 0 };
                        send(s, close_frame, sizeof(close_frame), 0);
                        break;
                    }
                    if ((frame[0] & 0x0F) == 0x9) {
                        const char pong_frame[2] = { static_cast<char>(0x8A), 0 };
                        send(s, pong_frame, sizeof(pong_frame), 0);
                    }
                }
                return;
            }
            if (req.rfind("CONNECT ", 0) == 0) {
                const std::string established = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: AiDA-Fixture\r\n\r\n";
                send(s, established.data(), static_cast<int>(established.size()), 0);
                return;
            }
            std::string body;
            std::string content_type = "text/html; charset=utf-8";
            if (req.rfind("POST /token ", 0) == 0) {
                content_type = "application/json";
                body = "{\"access_token\":\"aida_mcp_access\",\"refresh_token\":\"aida_mcp_refresh\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";
            } else if (req.rfind("POST /graphql ", 0) == 0) {
                content_type = "application/json";
                body = "{\"data\":{\"__typename\":\"Query\",\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"types\":[]}}}";
            } else if (req.find(" /aida-mcp-test") != std::string::npos || req.find(" /FUZZ") != std::string::npos) {
                body = "aida-mcp-test";
            } else {
                body = "<!doctype html><html><head><title>AiDA MCP Fixture</title></head><body><a href=\"/aida-mcp-test\">fixture</a><input id=\"aida-input\" value=\"\"><script>window.aidaFixture=1;</script></body></html>";
            }
            std::string resp = "HTTP/1.1 200 OK\r\n";
            resp += "Content-Type: " + content_type + "\r\n";
            resp += "Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval' data:\r\n";
            resp += "X-Powered-By: AiDA-Fixture\r\n";
            resp += "Connection: close\r\n";
            resp += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
            resp += body;
            send(s, resp.data(), static_cast<int>(resp.size()), 0);
        }

        void close() {
            stop.store(true, std::memory_order_release);
            if (listener != INVALID_SOCKET) {
                closesocket(listener);
                listener = INVALID_SOCKET;
            }
            if (worker.joinable())
                worker.join();
            port = 0;
        }

        ~mcp_burp_http_fixture_t() {
            close();
        }
    };

    std::unique_ptr<mcp_burp_http_fixture_t> g_burp_http_fixture;

    bool ensure_burp_http_fixture(HANDLE hf, const char* tag) {
        if (g_burp_http_fixture && g_burp_http_fixture->port != 0)
            return true;
        g_burp_http_fixture = std::make_unique<mcp_burp_http_fixture_t>();
        if (!g_burp_http_fixture->start(hf, tag)) {
            g_burp_http_fixture.reset();
            return false;
        }
        g_burp_fixture_base_url = "http://127.0.0.1:" + std::to_string(g_burp_http_fixture->port);
        g_burp_fixture_wordlist_path = temp_file_narrow("aida_mcp_burp_words.txt");
        write_text_file_narrow(g_burp_fixture_wordlist_path, "aida-mcp-test\n");
        return true;
    }

    std::string burp_fixture_url(HANDLE hf, const char* tag, const char* path = "/") {
        std::string suffix = path ? path : "/";
        if (suffix.empty() || suffix[0] != '/')
            suffix.insert(suffix.begin(), '/');
        if (!ensure_burp_http_fixture(hf, tag))
            return "http://127.0.0.1:1" + suffix;
        return g_burp_fixture_base_url + suffix;
    }

    bool send_burp_fixture_tcp_payload(HANDLE hf, const char* tag, const std::vector<uint8_t>& payload) {
        if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture || g_burp_http_fixture->port == 0)
            return false;
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed for capture payload fixture");
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- payload socket failed err=%d", WSAGetLastError());
            return false;
        }
        DWORD timeout = 1500;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        sockaddr_in dst = {};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(g_burp_http_fixture->port);
        if (connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) == SOCKET_ERROR) {
            log_msg(hf, tag, "FAIL -- payload connect failed err=%d", WSAGetLastError());
            closesocket(s);
            return false;
        }
        int sent = send(s, reinterpret_cast<const char*>(payload.data()), static_cast<int>(payload.size()), 0);
        char tmp[256];
        recv(s, tmp, sizeof(tmp), 0);
        closesocket(s);
        if (sent <= 0) {
            log_msg(hf, tag, "FAIL -- payload send failed err=%d", WSAGetLastError());
            return false;
        }
        Sleep(250);
        return true;
    }

    bool seed_network_parse_capture(HANDLE hf, const char* tag, const std::vector<uint8_t>& payload) {
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded for network parser fixture capture");
            return false;
        }
        if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture || g_burp_http_fixture->port == 0)
            return false;
        driver_bridge::stop_capture();
        const bool started = driver_bridge::start_capture(GetCurrentProcessId(), g_burp_http_fixture->port, 6, nullptr, 1500);
        if (!started) {
            log_msg(hf, tag, "FAIL -- start_capture failed for current-process parser fixture port=%u",
                static_cast<unsigned>(g_burp_http_fixture->port));
            return false;
        }
        if (!send_burp_fixture_tcp_payload(hf, tag, payload)) {
            driver_bridge::stop_capture();
            return false;
        }
        return true;
    }

    void seed_burp_scanner_issue_fixture(HANDLE hf, const char* tag) {
        if (g_burp_scanner_issue_id != 0)
            return;
        if (!ensure_burp_http_fixture(hf, tag))
            return;
        aida::burp::issue_store::initialize();
        aida::burp::issue_t issue;
        issue.type_key = "csp.unsafe_inline";
        issue.name = "Content-Security-Policy allows unsafe inline script";
        issue.description = "The local MCP fixture intentionally exposes a weak Content-Security-Policy header for scanner issue retrieval tests.";
        issue.remediation = "Remove unsafe-inline and unsafe-eval from script-src/default-src and constrain script sources.";
        issue.cwe.push_back("CWE-1021");
        issue.severity = aida::burp::severity_t::medium;
        issue.confidence = aida::burp::confidence_t::firm;
        issue.scheme = "http";
        issue.host = "127.0.0.1";
        issue.port = g_burp_http_fixture ? g_burp_http_fixture->port : 0;
        issue.path = "/";
        issue.audit_id = g_burp_scanner_audit_id;
        aida::burp::evidence_t ev;
        ev.marker = "unsafe-inline";
        ev.response_raw = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval' data:\r\n\r\n";
        issue.evidence.push_back(std::move(ev));
        g_burp_scanner_issue_id = aida::burp::issue_store::add(std::move(issue));
        log_msg(hf, tag, "seeded scanner issue fixture id=%llu audit_id=%llu",
            static_cast<unsigned long long>(g_burp_scanner_issue_id),
            static_cast<unsigned long long>(g_burp_scanner_audit_id));
    }

    void seed_burp_sitemap_fixture(HANDLE hf, const char* tag) {
        if (g_burp_sitemap_exchange_id != 0)
            return;
        if (!ensure_burp_http_fixture(hf, tag))
            return;
        aida::burp::sitemap::initialize();
        aida::burp::exchange_observed_t e;
        e.id = 0xA1DA0001ULL;
        e.method = "GET";
        e.scheme = "http";
        e.host = "127.0.0.1";
        e.port = g_burp_http_fixture->port;
        e.path = "/";
        e.req_headers.push_back({"Host", "127.0.0.1"});
        e.status_code = 200;
        e.reason_phrase = "OK";
        e.resp_headers.push_back({"Content-Type", "text/html"});
        const char body[] = "AiDA MCP sitemap fixture";
        e.resp_body.assign(body, body + sizeof(body) - 1);
        aida::burp::sitemap::ingest_exchange(e);
        Sleep(100);
        g_burp_sitemap_exchange_id = e.id;
    }

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

    void test_tool_get_tool_descriptions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "mcp.get_tool_descriptions";
        mcp_standalone::json args;
        args["names"] = mcp_standalone::json::array({"get_tool_descriptions", "driver_status"});
        args["include_schema"] = true;
        g_invoked_tools.insert("get_tool_descriptions");
        auto timed = invoke_tool_bounded(get_server(), "get_tool_descriptions", args, tool_timeout_ms("get_tool_descriptions"));
        auto& ir = timed.result;
        if (timed.timed_out || !ir.found || ir.threw || !ir.success) {
            log_msg(hf, tag, "FAIL -- get_tool_descriptions dispatch failed found=%s threw=%s success=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                ir.success ? "true" : "false",
                timed.timed_out ? "true" : "false",
                ir.exception_msg.c_str());
            record_tool_status("get_tool_descriptions", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const std::string text_lc = lower_copy(ir.text);
        const bool has_self = text_lc.find("### get_tool_descriptions") != std::string::npos;
        const bool has_driver_status = text_lc.find("### driver_status") != std::string::npos;
        const bool has_schema = text_lc.find("`names`") != std::string::npos &&
            text_lc.find("include_schema") != std::string::npos;
        if (has_self && has_driver_status && has_schema) {
            log_msg(hf, tag, "PASS -- returned detailed schemas for selected tools");
            record_tool_status("get_tool_descriptions", mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "FAIL -- response missing expected detail self=%s driver_status=%s schema=%s text=%s",
            has_self ? "true" : "false",
            has_driver_status ? "true" : "false",
            has_schema ? "true" : "false",
            compact_text(ir.text, 900).c_str());
        record_tool_status("get_tool_descriptions", mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
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
                    if (st.failed > 0 || st.timed_out > 0) {
                        log_msg(hf, tag, "INFO -- registered tool \"%s\" had pass evidence after attempted=%d failed=%d skipped=%d timed_out=%d",
                            t.name.c_str(), st.attempted, st.failed, st.skipped, st.timed_out);
                    }
                } else if (is_destructive_mcp_tool(t.name) && st.skipped > 0 && st.failed == 0 && st.timed_out == 0) {
                    ++covered;
                    log_msg(hf, tag, "INFO -- registered destructive tool \"%s\" covered by schema-only destructive skip after attempted=%d skipped=%d",
                        t.name.c_str(), st.attempted, st.skipped);
                } else if (g_mcp_target_unavailable && tool_uses_live_target(t.name) && st.skipped > 0 && st.failed == 0 && st.timed_out == 0) {
                    ++covered;
                    log_msg(hf, tag, "INFO -- registered tool \"%s\" covered by live-target precondition skip after attempted=%d skipped=%d",
                        t.name.c_str(), st.attempted, st.skipped);
                } else if (tool_allows_host_dependency_skip(t.name) && st.skipped > 0 && st.failed == 0 && st.timed_out == 0) {
                    ++covered;
                    log_msg(hf, tag, "INFO -- registered tool \"%s\" covered by explicit host-dependency skip after attempted=%d skipped=%d",
                        t.name.c_str(), st.attempted, st.skipped);
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

        if (missing == 0 && stale == 0 && no_pass == 0) {
            log_msg(hf, tag, "PASS -- attempted=%d passed_tools=%d no_pass=%d failed_tools=%d skipped_tools=%d timed_out_tools=%d ai_excluded=%d",
                attempted, passed_tools, no_pass, failed_tools, skipped_tools, timed_out_tools, skipped_ai);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- missing=%d stale=%d attempted=%d passed_tools=%d no_pass=%d failed_tools=%d skipped_tools=%d timed_out_tools=%d ai_excluded=%d",
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
        const char* tool_name = "sandbox_execute";
        mcp_standalone::json args;
        args["path"] = "C:\\Windows\\System32\\cmd.exe";
        args["arguments"] = "/c echo AIDA_SANDBOX_OK";
        args["timeout_ms"] = 15000;
        args["capture_stdout"] = true;
        args["capture_stderr"] = true;
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        if (timed.timed_out || !ir.found || ir.threw) {
            log_msg(hf, "mcp.sandbox_execute.guard", "FAIL -- sandbox_execute dispatch failed found=%s threw=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                timed.timed_out ? "true" : "false",
                compact_text(ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const std::string text_lc = lower_copy(ir.text + " " + ir.exception_msg);
        if (!ir.success &&
            (text_lc.find("sandbox execution is disabled") != std::string::npos ||
             text_lc.find("windows sandbox") != std::string::npos ||
             text_lc.find("not available") != std::string::npos ||
             text_lc.find("not installed") != std::string::npos)) {
            log_msg(hf, "mcp.sandbox_execute.guard", "SKIP -- Windows Sandbox host dependency unavailable: %s",
                compact_text(ir.text, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return;
        }
        std::string stdout_text;
        uint64_t exit_code = 1;
        payload_string_field(ir.data, "stdout", stdout_text);
        payload_u64_field(ir.data, "exit_code", exit_code);
        if (ir.success && exit_code == 0 && lower_copy(stdout_text).find("aida_sandbox_ok") != std::string::npos) {
            log_msg(hf, "mcp.sandbox_execute.guard", "PASS -- sandbox_execute ran deterministic cmd fixture and captured stdout");
            record_tool_status(tool_name, mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, "mcp.sandbox_execute.guard", "FAIL -- sandbox_execute unexpected result success=%s exit=%llu text=%s stdout=%s",
            ir.success ? "true" : "false",
            static_cast<unsigned long long>(exit_code),
            compact_text(ir.text, 700).c_str(),
            compact_text(stdout_text, 300).c_str());
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
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
        (void)skipped;
        test_tool_schema_only(hf, "mcp.driver_write_kernel_memory", get_server(), "driver_write_kernel_memory", {"address", "bytes"}, passed, failed, skipped);
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
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.driver_set_thread_context", "SKIP -- target thread not found");
            record_precondition_skipped_tool("driver_set_thread_context", skipped);
            return;
        }
        if (!driver_bridge::suspend_thread(tid, nullptr)) {
            log_msg(hf, "mcp.driver_set_thread_context", "SKIP -- could not suspend target thread tid=%u", tid);
            record_precondition_skipped_tool("driver_set_thread_context", skipped);
            return;
        }
        driver_bridge::thread_context_t ctx{};
        if (!driver_bridge::get_thread_context(tid, ctx)) {
            driver_bridge::resume_thread(tid);
            log_msg(hf, "mcp.driver_set_thread_context", "SKIP -- could not read target thread context tid=%u", tid);
            record_precondition_skipped_tool("driver_set_thread_context", skipped);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(tid);
        args["rax"] = hex_u64(ctx.rax);
        test_tool_call(hf, "mcp.driver_set_thread_context", get_server(), "driver_set_thread_context", args, passed, failed, skipped);
        driver_bridge::resume_thread(tid);
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
        args["name"] = "NtClose";
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
        args["timeout"] = 30;
        args["poll_interval"] = 100;
        args["actions"] = mcp_standalone::json::array({
            {{"tool", "driver_status"}, {"params", mcp_standalone::json::object()}}
        });
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.driver_defer_action", get_server(), "driver_defer_action", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "action_id", g_mcp_deferred_action_id);
    }

    void test_tool_driver_list_deferred_actions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_list_deferred_actions", get_server(), "driver_list_deferred_actions", {}, passed, failed, skipped);
    }

    void test_tool_driver_cancel_deferred_action(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_deferred_action_id == 0) {
            log_msg(hf, "mcp.driver_cancel_deferred_action", "SKIP -- no deferred action id captured");
            record_precondition_skipped_tool("driver_cancel_deferred_action", skipped);
            return;
        }
        mcp_standalone::json args;
        args["action_id"] = g_mcp_deferred_action_id;
        test_tool_call(hf, "mcp.driver_cancel_deferred_action", get_server(), "driver_cancel_deferred_action", args, passed, failed, skipped);
    }

    void test_tool_driver_get_deferred_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_deferred_action_id == 0) {
            log_msg(hf, "mcp.driver_get_deferred_results", "SKIP -- no deferred action id captured");
            record_precondition_skipped_tool("driver_get_deferred_results", skipped);
            return;
        }
        mcp_standalone::json args;
        args["action_id"] = g_mcp_deferred_action_id;
        test_tool_call(hf, "mcp.driver_get_deferred_results", get_server(), "driver_get_deferred_results", args, passed, failed, skipped);
    }

    void test_tool_driver_enumerate_wfp_callouts(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_wfp_callouts", get_server(), "driver_enumerate_wfp_callouts", {}, passed, failed, skipped);
    }

    void test_tool_driver_get_socket_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_get_socket_handles", get_server(), "driver_get_socket_handles", {}, passed, failed, skipped);
    }

    void test_tool_driver_sniff_network_buffers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "get";
        test_tool_call(hf, "mcp.driver_sniff_network_buffers", get_server(), "driver_sniff_network_buffers", args, passed, failed, skipped);
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
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.driver_walk_seh_chain", "FAIL -- target thread fixture not found");
            record_fixture_failed_tool("driver_walk_seh_chain", failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(tid);
        test_tool_call(hf, "mcp.driver_walk_seh_chain", get_server(), "driver_walk_seh_chain", args, passed, failed, skipped);
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
        uint64_t addr = driver_bridge::allocate_memory(4096);
        if (addr == 0) {
            log_msg(hf, "mcp.driver_scan_memory_value", "SKIP -- allocate_memory failed for scan fixture");
            record_precondition_skipped_tool("driver_scan_memory_value", skipped);
            return;
        }
        const std::vector<uint8_t> fixture = { 0x78, 0x56, 0x34, 0x12 };
        if (!driver_bridge::write_memory(addr, fixture)) {
            log_msg(hf, "mcp.driver_scan_memory_value", "SKIP -- write_memory failed for scan fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            record_precondition_skipped_tool("driver_scan_memory_value", skipped);
            return;
        }
        mcp_standalone::json args;
        args["value"] = 0x12345678;
        args["value_type"] = "int32";
        args["start"] = hex_u64(addr);
        args["end"] = hex_u64(addr + 4096);
        args["limit"] = 8;
        test_tool_call(hf, "mcp.driver_scan_memory_value", get_server(), "driver_scan_memory_value", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_driver_pointer_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t target = driver_bridge::allocate_memory(4096);
        uint64_t pointer_slot = driver_bridge::allocate_memory(4096);
        if (target == 0 || pointer_slot == 0) {
            if (target) driver_bridge::free_memory(target);
            if (pointer_slot) driver_bridge::free_memory(pointer_slot);
            log_msg(hf, "mcp.driver_pointer_scan", "SKIP -- allocate_memory failed for pointer fixture");
            record_precondition_skipped_tool("driver_pointer_scan", skipped);
            return;
        }
        std::vector<uint8_t> ptr_bytes(sizeof(target), 0);
        std::memcpy(ptr_bytes.data(), &target, sizeof(target));
        if (!driver_bridge::write_memory(pointer_slot, ptr_bytes)) {
            driver_bridge::free_memory(target);
            driver_bridge::free_memory(pointer_slot);
            log_msg(hf, "mcp.driver_pointer_scan", "SKIP -- write_memory failed for pointer fixture");
            record_precondition_skipped_tool("driver_pointer_scan", skipped);
            return;
        }
        mcp_standalone::json args;
        args["target_address"] = hex_u64(target);
        args["max_depth"] = 1;
        args["max_offset"] = 0;
        args["limit"] = 4;
        test_tool_call(hf, "mcp.driver_pointer_scan", get_server(), "driver_pointer_scan", args, passed, failed, skipped);
        driver_bridge::free_memory(target);
        driver_bridge::free_memory(pointer_slot);
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
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.driver_read_teb", "FAIL -- target thread fixture not found");
            record_fixture_failed_tool("driver_read_teb", failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(tid);
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
        if (!ensure_mcp_private_bytes(hf, "mcp.dbg_set_breakpoint", g_mcp_dbg_sw_addr, 64, {0x90, 0x90, 0xC3})) {
            record_precondition_skipped_tool("dbg_set_breakpoint", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_dbg_sw_addr);
        test_tool_call(hf, "mcp.dbg_set_breakpoint", get_server(), "dbg_set_breakpoint", args, passed, failed, skipped);
    }

    void test_tool_dbg_remove_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_dbg_sw_addr == 0) {
            log_msg(hf, "mcp.dbg_remove_breakpoint", "SKIP -- no software breakpoint fixture address");
            record_precondition_skipped_tool("dbg_remove_breakpoint", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_dbg_sw_addr);
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
        args["snapshot_a"] = "test_snapshot";
        args["snapshot_b"] = "test_snapshot";
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
        mcp_step_fixture_t fixture;
        if (!prepare_mcp_step_fixture(hf, "mcp.dbg_step_into", fixture)) {
            failed.fetch_add(1);
            record_tool_status("dbg_step_into", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        test_tool_call(hf, "mcp.dbg_step_into", get_server(), "dbg_step_into", args, passed, failed, skipped);
        cleanup_mcp_step_fixture(fixture);
    }

    void test_tool_dbg_step_over(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_step_fixture_t fixture;
        if (!prepare_mcp_step_fixture(hf, "mcp.dbg_step_over", fixture)) {
            failed.fetch_add(1);
            record_tool_status("dbg_step_over", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        test_tool_call(hf, "mcp.dbg_step_over", get_server(), "dbg_step_over", args, passed, failed, skipped);
        cleanup_mcp_step_fixture(fixture);
    }

    void test_tool_dbg_step_out(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_step_out_fixture_t fixture;
        if (!prepare_mcp_step_out_fixture(hf, "mcp.dbg_step_out", fixture)) {
            failed.fetch_add(1);
            record_tool_status("dbg_step_out", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        test_tool_call(hf, "mcp.dbg_step_out", get_server(), "dbg_step_out", args, passed, failed, skipped);
        cleanup_mcp_step_out_fixture(fixture);
    }

    void test_tool_dbg_run_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_step_out_fixture_t fixture;
        if (!prepare_mcp_step_out_fixture(hf, "mcp.dbg_run_to_address", fixture)) {
            failed.fetch_add(1);
            record_tool_status("dbg_run_to_address", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(fixture.code);
        args["wait_for_completion"] = true;
        args["timeout_ms"] = 1000;
        test_tool_call(hf, "mcp.dbg_run_to_address", get_server(), "dbg_run_to_address", args, passed, failed, skipped);
        cleanup_mcp_step_out_fixture(fixture);
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
        mcp_standalone::json args;
        args["tid"] = "0";
        args["max_depth"] = 16;
        test_tool_call(hf, "mcp.debugger_get_callstack", get_server(), "debugger_get_callstack", args, passed, failed, skipped);
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
        if (!ensure_mcp_private_bytes(hf, "mcp.debugger_set_breakpoint", g_mcp_dbg_sw_addr, 64, {0x90, 0x90, 0xC3})) {
            record_precondition_skipped_tool("debugger_set_breakpoint", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_dbg_sw_addr);
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.debugger_set_breakpoint", get_server(), "debugger_set_breakpoint", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed && result.data.is_object() && result.data.contains("index") && result.data["index"].is_number_integer())
            g_mcp_debugger_bp_index = result.data["index"].get<int>();
    }

    void test_tool_debugger_remove_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        if (g_mcp_debugger_bp_index >= 0)
            args["index"] = g_mcp_debugger_bp_index;
        else if (g_mcp_dbg_sw_addr != 0)
            args["address"] = hex_u64(g_mcp_dbg_sw_addr);
        else {
            log_msg(hf, "mcp.debugger_remove_breakpoint", "SKIP -- no debugger breakpoint fixture address");
            record_precondition_skipped_tool("debugger_remove_breakpoint", skipped);
            return;
        }
        test_tool_call(hf, "mcp.debugger_remove_breakpoint", get_server(), "debugger_remove_breakpoint", args, passed, failed, skipped);
        g_mcp_debugger_bp_index = -1;
    }

    void test_tool_debugger_step_over(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_step_fixture_t fixture;
        if (!prepare_mcp_step_fixture(hf, "mcp.debugger_step_over", fixture)) {
            failed.fetch_add(1);
            record_tool_status("debugger_step_over", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        test_tool_call(hf, "mcp.debugger_step_over", get_server(), "debugger_step_over", args, passed, failed, skipped);
        cleanup_mcp_step_fixture(fixture);
    }

    void test_tool_debugger_step_into(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_step_fixture_t fixture;
        if (!prepare_mcp_step_fixture(hf, "mcp.debugger_step_into", fixture)) {
            failed.fetch_add(1);
            record_tool_status("debugger_step_into", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        test_tool_call(hf, "mcp.debugger_step_into", get_server(), "debugger_step_into", args, passed, failed, skipped);
        cleanup_mcp_step_fixture(fixture);
    }

    void test_tool_debugger_step_out(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_step_out_fixture_t fixture;
        if (!prepare_mcp_step_out_fixture(hf, "mcp.debugger_step_out", fixture)) {
            failed.fetch_add(1);
            record_tool_status("debugger_step_out", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        test_tool_call(hf, "mcp.debugger_step_out", get_server(), "debugger_step_out", args, passed, failed, skipped);
        cleanup_mcp_step_out_fixture(fixture);
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
            record_precondition_skipped_tool("debugger_write_memory", skipped);
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
            record_precondition_skipped_tool("debugger_protect_memory", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["size"] = static_cast<std::uint64_t>(4096);
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
            record_precondition_skipped_tool("dbg_set_register", skipped);
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
        if (addr_raw == 0) { record_precondition_skipped_tool("dbg_add_hw_breakpoint", skipped); return; }
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
        args["max_exports"] = 0;
        args["max_imports"] = 0;
        args["timeout_ms"] = 2500;
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
        const char* tool_name = "dbg_find_code_caves";
        const char* tag = "mcp.dbg_find_code_caves";
        uint64_t addr = 0;
        std::vector<uint8_t> bytes(256, 0x00);
        if (!ensure_mcp_private_bytes(hf, tag, addr, bytes.size(), bytes)) {
            record_precondition_skipped_tool(tool_name, skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["size"] = static_cast<uint32_t>(bytes.size());
        args["min_cave_size"] = 64;
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        if (!timed.timed_out)
            driver_bridge::free_memory(addr);
        if (timed.timed_out || !ir.found || ir.threw || !ir.success) {
            log_msg(hf, tag, "FAIL -- dbg_find_code_caves dispatch failed found=%s threw=%s success=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                ir.success ? "true" : "false",
                timed.timed_out ? "true" : "false",
                compact_text(ir.exception_msg.empty() ? ir.text : ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        uint64_t count = 0;
        payload_u64_field(ir.data, "count", count);
        if (count > 0) {
            log_msg(hf, tag, "PASS -- dbg_find_code_caves found %llu deterministic private code cave(s)",
                static_cast<unsigned long long>(count));
            record_tool_status(tool_name, mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "FAIL -- dbg_find_code_caves returned success without finding the deterministic private zero-filled cave: %s",
            compact_text(ir.text, 700).c_str());
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_dbg_conditional_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_mcp_private_bytes(hf, "mcp.dbg_conditional_breakpoint", g_mcp_dbg_sw_addr, 64, {0x90, 0x90, 0xC3})) {
            record_precondition_skipped_tool("dbg_conditional_breakpoint", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_dbg_sw_addr);
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
        const uint32_t value = 0x4D3C2B1A;
        std::vector<uint8_t> bytes(sizeof(value), 0);
        std::memcpy(bytes.data(), &value, sizeof(value));
        if (!ensure_mcp_private_bytes(hf, "mcp.scanner_first_scan", g_mcp_scanner_addr, 4096, bytes)) {
            record_precondition_skipped_tool("scanner_first_scan", skipped);
            return;
        }
        uint32_t old_protect = 0;
        bool protect_ok = driver_bridge::protect_memory(g_mcp_scanner_addr, 4096, PAGE_READWRITE, &old_protect);
        log_msg(hf, "mcp.scanner_first_scan", "fixture protect_readwrite ok=%d old=0x%08X addr=0x%016llX",
            protect_ok ? 1 : 0,
            old_protect,
            static_cast<unsigned long long>(g_mcp_scanner_addr));
        mcp_standalone::json args;
        args["value"] = "1295788826";
        args["value_type"] = "int32";
        args["scan_mode"] = "exact";
        args["writable_only"] = true;
        args["executable_exclude"] = false;
        args["alignment"] = 4;
        args["range_base"] = hex_u64(g_mcp_scanner_addr & ~0xFFFULL);
        args["range_size"] = 4096;
        auto status = test_tool_call(hf, "mcp.scanner_first_scan", get_server(), "scanner_first_scan", args, passed, failed, skipped);
        if (status == mcp_tool_call_status_t::passed) {
            log_msg(hf, "mcp.scanner_first_scan", "INFO -- expected fixture value at 0x%llX range=0x%llX+0x1000",
                static_cast<unsigned long long>(g_mcp_scanner_addr),
                static_cast<unsigned long long>(g_mcp_scanner_addr & ~0xFFFULL));
        }
    }

    void test_tool_scanner_next_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["value"] = "1295788826";
        args["scan_mode"] = "exact";
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
        const uint32_t value = 0x4D3C2B1A;
        std::vector<uint8_t> bytes(sizeof(value), 0);
        std::memcpy(bytes.data(), &value, sizeof(value));
        if (!ensure_mcp_private_bytes(hf, "mcp.scanner_add_address", g_mcp_scanner_addr, 4096, bytes)) {
            record_precondition_skipped_tool("scanner_add_address", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_scanner_addr);
        args["description"] = "mcp_test_value";
        args["value_type"] = "int32";
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
        args["enable"] = true;
        test_tool_call(hf, "mcp.scanner_freeze_address", get_server(), "scanner_freeze_address", args, passed, failed, skipped);
    }

    void test_tool_scanner_read_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(16);
        if (addr == 0) {
            log_msg(hf, "mcp.scanner_read_value", "SKIP -- allocate_memory failed for scanner read fixture");
            record_precondition_skipped_tool("scanner_read_value", skipped);
            return;
        }
        std::vector<uint8_t> bytes = {0x39, 0x30, 0x00, 0x00};
        if (!driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, "mcp.scanner_read_value", "SKIP -- write_memory failed for scanner read fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            record_precondition_skipped_tool("scanner_read_value", skipped);
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
            record_precondition_skipped_tool("scanner_write_value", skipped);
            return;
        }
        std::vector<uint8_t> bytes(4, 0);
        if (!driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, "mcp.scanner_write_value", "SKIP -- write_memory failed for scanner write fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            record_precondition_skipped_tool("scanner_write_value", skipped);
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
        if (!ensure_mcp_scanner_pointer_fixture(hf, "mcp.scanner_pointer_scan")) {
            record_precondition_skipped_tool("scanner_pointer_scan", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_scanner_addr);
        args["max_depth"] = 1;
        args["max_offset"] = 0x100;
        args["timeout_ms"] = 30000;
        test_tool_call(hf, "mcp.scanner_pointer_scan", get_server(), "scanner_pointer_scan", args, passed, failed, skipped);
    }

    void test_tool_scanner_cancel_pointer_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_cancel_pointer_scan", get_server(), "scanner_cancel_pointer_scan", {}, passed, failed, skipped);
    }

    void test_tool_scanner_define_struct(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_scanner_addr == 0 && !ensure_mcp_private_bytes(hf, "mcp.scanner_define_struct", g_mcp_scanner_addr, 4096, {0x1A, 0x2B, 0x3C, 0x4D})) {
            record_precondition_skipped_tool("scanner_define_struct", skipped);
            return;
        }
        mcp_standalone::json args;
        args["name"] = "test_struct";
        args["base_address"] = hex_u64(g_mcp_scanner_addr);
        test_tool_call(hf, "mcp.scanner_define_struct", get_server(), "scanner_define_struct", args, passed, failed, skipped);
    }

    void test_tool_scanner_add_struct_field(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_index"] = 0;
        args["name"] = "field1";
        args["field_type"] = "int32";
        args["offset"] = 0;
        test_tool_call(hf, "mcp.scanner_add_struct_field", get_server(), "scanner_add_struct_field", args, passed, failed, skipped);
    }

    void test_tool_scanner_get_struct(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_index"] = 0;
        test_tool_call(hf, "mcp.scanner_get_struct", get_server(), "scanner_get_struct", args, passed, failed, skipped);
    }

    void test_tool_scanner_export_struct_c(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_index"] = 0;
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
        args["timeout_ms"] = 4500;
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
        uint64_t addr = 0;
        std::vector<uint8_t> bytes(128, 0);
        for (size_t i = 0; i < bytes.size(); ++i)
            bytes[i] = static_cast<uint8_t>((i * 17U + 3U) & 0xFFU);
        if (!ensure_mcp_private_bytes(hf, "mcp.reconstruct_struct", addr, 128, bytes)) {
            record_precondition_skipped_tool("reconstruct_struct", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["size"] = 128;
        args["name"] = "mcp_reconstruct_fixture";
        args["timeout_ms"] = 2500;
        test_tool_call(hf, "mcp.reconstruct_struct", get_server(), "reconstruct_struct", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
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
        uint64_t addr = 0;
        std::vector<uint8_t> bytes(128, 0);
        const char marker[] = "AIDA_MCP_DECRYPT_FIXTURE";
        std::memcpy(bytes.data(), marker, sizeof(marker));
        if (!ensure_mcp_private_bytes(hf, "mcp.auto_decrypt_strings", addr, 128, bytes)) {
            record_precondition_skipped_tool("auto_decrypt_strings", skipped);
            return;
        }
        mcp_standalone::json args;
        args["region_address"] = hex_u64(addr);
        args["region_size"] = 128;
        args["search_start"] = hex_u64(addr);
        args["search_size"] = 128;
        args["timeout_ms"] = 2500;
        test_tool_call(hf, "mcp.auto_decrypt_strings", get_server(), "auto_decrypt_strings", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_hunt_integrity_checkers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!prepare_live_monitor_regions(hf, "mcp.hunt_integrity_checkers")) { record_precondition_skipped_tool("hunt_integrity_checkers", skipped); return; }
        mcp_standalone::json args;
        args["target_address"] = hex_u64(g_mcp_live_monitor_addr);
        args["target_size"] = 128;
        args["duration_ms"] = 1000;
        test_tool_call(hf, "mcp.hunt_integrity_checkers", get_server(), "hunt_integrity_checkers", args, passed, failed, skipped);
    }

    void test_tool_neutralize_integrity_node(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_mcp_private_bytes(hf, "mcp.neutralize_integrity_node", g_mcp_integrity_addr, 64,
            {0x83, 0xF8, 0x01, 0x75, 0x02, 0x90, 0x90, 0xC3})) {
            log_msg(hf, "mcp.neutralize_integrity_node", "FAIL -- integrity fixture memory setup failed");
            record_fixture_failed_tool("neutralize_integrity_node", failed);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(integrity_hunter::g_state.mutex);
            integrity_hunter::g_state.nodes.clear();
            integrity_hunter::integrity_node_t node;
            node.reader_rip = g_mcp_integrity_addr;
            node.hash_compare_addr = g_mcp_integrity_addr;
            node.read_count = 4;
            node.reads_per_second = 4.0f;
            node.module_name = "mcp_integrity_fixture";
            node.disasm_text = "cmp eax, 1";
            integrity_hunter::g_state.nodes.push_back(std::move(node));
        }
        mcp_standalone::json args;
        args["node_index"] = 0;
        test_tool_call(hf, "mcp.neutralize_integrity_node", get_server(), "neutralize_integrity_node", args, passed, failed, skipped);
    }

    void test_tool_start_live_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_live_monitor_addr == 0 && !prepare_live_monitor_regions(hf, "mcp.start_live_monitor")) {
            log_msg(hf, "mcp.start_live_monitor", "FAIL -- live monitor fixture memory setup failed");
            record_fixture_failed_tool("start_live_monitor", failed);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_live_monitor_addr);
        args["size"] = 128;
        args["name"] = "mcp_live_monitor_fixture";
        args["backend"] = "polling";
        args["timeout_ms"] = 1500;
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
        std::vector<uint8_t> code(4096, 0x90);
        const uint8_t fixture[] = {
            0x48, 0x89, 0xC8,
            0x48, 0x83, 0xC0, 0x05,
            0x48, 0x31, 0xD0,
            0x48, 0x85, 0xC0,
            0x75, 0x03,
            0x48, 0xFF, 0xC0,
            0xC3
        };
        std::copy(std::begin(fixture), std::end(fixture), code.begin());
        if (!ensure_mcp_private_bytes(hf, "mcp.symbolic_deobfuscate", g_mcp_symbolic_deobf_addr, code.size(), code)) {
            log_msg(hf, "mcp.symbolic_deobfuscate", "FAIL -- symbolic deobfuscation fixture setup failed");
            record_fixture_failed_tool("symbolic_deobfuscate", failed);
            return;
        }
        mcp_standalone::json args;
        args["entry_address"] = hex_u64(g_mcp_symbolic_deobf_addr);
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
        mcp_standalone::json args;
        args["max_functions"] = 8;
        args["max_globals"] = 4;
        args["include_imports"] = false;
        args["include_exports"] = false;
        args["include_xrefs"] = false;
        args["fast_summary"] = true;
        test_tool_call(hf, "mcp.analysis_get_binary_map_overview", get_server(), "analysis_get_binary_map_overview", args, passed, failed, skipped);
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
        args["timeout_ms"] = 4500;
        test_tool_call(hf, "mcp.crypto_scanner_run", get_server(), "crypto_scanner_run", args, passed, failed, skipped);
    }

    void test_tool_crypto_scanner_get_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.crypto_scanner_get_results", get_server(), "crypto_scanner_get_results", {}, passed, failed, skipped);
    }


    void test_tool_disasm_jump_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_static_disasm_instruction_addr(hf, "mcp.disasm_jump_to_address");
        if (addr.empty()) {
            addr = get_ntclose_addr_str();
            if (!addr.empty())
                log_msg(hf, "mcp.disasm_jump_to_address", "INFO -- using live NtClose fallback fixture address=%s", addr.c_str());
        }
        if (addr.empty()) { record_precondition_skipped_tool("disasm_jump_to_address", skipped); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_jump_to_address", get_server(), "disasm_jump_to_address", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_instruction(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_remote_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_instruction", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_instruction", get_server(), "disasm_get_instruction", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_function_bounds(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_remote_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_function_bounds", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_function_bounds", get_server(), "disasm_get_function_bounds", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_function_disassembly(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_remote_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_get_function_disassembly", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disasm_get_function_disassembly", get_server(), "disasm_get_function_disassembly", args, passed, failed, skipped);
    }

    void test_tool_disasm_list_functions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.disasm_list_functions", get_server(), "disasm_list_functions", {}, passed, failed, skipped);
    }

    void test_tool_disasm_get_xrefs_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_mcp_xref_db_fixture();
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_xref_to_addr);
        test_tool_call(hf, "mcp.disasm_get_xrefs_to", get_server(), "disasm_get_xrefs_to", args, passed, failed, skipped);
    }

    void test_tool_disasm_get_xrefs_from(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_mcp_xref_db_fixture();
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_xref_from_addr);
        test_tool_call(hf, "mcp.disasm_get_xrefs_from", get_server(), "disasm_get_xrefs_from", args, passed, failed, skipped);
    }

    void test_tool_disasm_set_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_set_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["comment"] = "test";
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
        args["new_name"] = "test_func";
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
        args["view"] = "disassembly";
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
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.bookmarks_remove", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
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
        if (g_mcp_session_binary_id.empty()) {
            log_msg(hf, "mcp.sessions_switch", "FAIL -- no session fixture id from sessions_open_file");
            record_tool_status("sessions_switch", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["binary_id"] = g_mcp_session_binary_id;
        test_tool_call(hf, "mcp.sessions_switch", get_server(), "sessions_switch", args, passed, failed, skipped);
    }

    void test_tool_sessions_open_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_small_pe_fixture_path();
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.sessions_open_file", get_server(), "sessions_open_file", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed && result.data.is_object() &&
            result.data.contains("opened") && result.data["opened"].is_object() &&
            result.data["opened"].contains("id") && result.data["opened"]["id"].is_string()) {
            g_mcp_session_binary_id = result.data["opened"]["id"].get<std::string>();
        }
    }

    void test_tool_sessions_attach_pid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pid"] = g_mcp_target_pid != 0 ? g_mcp_target_pid : GetCurrentProcessId();
        test_tool_call(hf, "mcp.sessions_attach_pid", get_server(), "sessions_attach_pid", args, passed, failed, skipped);
    }

    void test_tool_sessions_close(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_session_binary_id.empty()) {
            log_msg(hf, "mcp.sessions_close", "FAIL -- no session fixture id from sessions_open_file");
            record_tool_status("sessions_close", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["binary_id"] = g_mcp_session_binary_id;
        test_tool_call(hf, "mcp.sessions_close", get_server(), "sessions_close", args, passed, failed, skipped);
        g_mcp_session_binary_id.clear();
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
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.driver_snapshot_and_emulate", "FAIL -- target thread fixture not found for snapshot emulation");
            record_fixture_failed_tool("driver_snapshot_and_emulate", failed);
            return;
        }
        if (!ensure_mcp_private_bytes(hf, "mcp.driver_snapshot_and_emulate", g_mcp_emulation_addr, 4096,
            {0xB8, 0x2A, 0x00, 0x00, 0x00, 0x90, 0x90})) {
            log_msg(hf, "mcp.driver_snapshot_and_emulate", "FAIL -- emulation fixture memory setup failed");
            record_fixture_failed_tool("driver_snapshot_and_emulate", failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = tid;
        args["address"] = hex_u64(g_mcp_emulation_addr);
        args["snapshot_base"] = hex_u64(g_mcp_emulation_addr & ~0xFFFULL);
        args["snapshot_size"] = 4096;
        args["stop_address"] = hex_u64(g_mcp_emulation_addr + 5);
        args["max_instructions"] = 8;
        args["max_trace_entries"] = 8;
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
        args["inputs"] = mcp_standalone::json::array({
            {{"rax", "0x0"}, {"rbx", "0x0"}, {"rcx", "0x0"}, {"rdx", "0x0"}}
        });
        args["max_instructions"] = 32;
        test_tool_call(hf, "mcp.emulate_multi_trace", get_server(), "emulate_multi_trace", args, passed, failed, skipped);
    }

    void test_tool_emulate_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_mcp_private_bytes(hf, "mcp.emulate_function", g_mcp_emulate_function_addr, 4096,
            {0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC})) {
            log_msg(hf, "mcp.emulate_function", "FAIL -- emulation fixture memory setup failed");
            record_fixture_failed_tool("emulate_function", failed);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_emulate_function_addr);
        args["size"] = 6;
        args["max_instructions"] = 8;
        args["max_trace_entries"] = 8;
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
        (void)skipped;
        const char* tool_name = "network_block_process";
        const char* tag = "mcp.network_block_process";
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        if (timed.timed_out || !ir.found || ir.threw || !ir.success) {
            log_msg(hf, tag, "FAIL -- current PID block fixture failed found=%d threw=%d success=%d timeout=%d text=%s err=%s",
                ir.found ? 1 : 0,
                ir.threw ? 1 : 0,
                ir.success ? 1 : 0,
                timed.timed_out ? 1 : 0,
                compact_text(ir.text, 700).c_str(),
                compact_text(ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        uint64_t rule_id = 0;
        uint64_t blocked_pid = 0;
        if (!payload_u64_field(ir.data, "rule_id", rule_id) || rule_id == 0 ||
            !payload_u64_field(ir.data, "blocked_pid", blocked_pid) || blocked_pid != GetCurrentProcessId()) {
            if (rule_id != 0)
                driver_bridge::remove_filter_rule(static_cast<uint32_t>(rule_id));
            log_msg(hf, tag, "FAIL -- current PID block did not return a valid rule_id/blocked_pid data=%s",
                compact_json(ir.data, 900).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const bool removed = driver_bridge::remove_filter_rule(static_cast<uint32_t>(rule_id));
        if (!removed) {
            log_msg(hf, tag, "FAIL -- current PID block rule was created but cleanup remove_filter_rule failed rule_id=%llu",
                static_cast<unsigned long long>(rule_id));
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- current PID block rule exercised pid=%lu rule_id=%llu cleanup=removed",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long long>(rule_id));
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_network_deep_inspect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_deep_inspect", get_server(), "network_deep_inspect", args, passed, failed, skipped);
    }

    void test_tool_network_follow_tcp_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "get";
        args["src_port"] = 0;
        args["dst_port"] = 0;
        test_tool_call(hf, "mcp.network_follow_tcp_stream", get_server(), "network_follow_tcp_stream", args, passed, failed, skipped);
    }

    void test_tool_network_parse_http(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string req = "GET /aida-mcp-test HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: AiDA-MCP-Fixture\r\nConnection: close\r\n\r\n";
        std::vector<uint8_t> payload(req.begin(), req.end());
        if (!seed_network_parse_capture(hf, "mcp.network_parse_http", payload)) {
            record_fixture_failed_tool("network_parse_http", failed);
            return;
        }
        mcp_standalone::json args;
        args["count"] = 32;
        test_tool_call(hf, "mcp.network_parse_http", get_server(), "network_parse_http", args, passed, failed, skipped);
        driver_bridge::stop_capture();
    }

    void test_tool_network_parse_tls(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        std::vector<uint8_t> payload = {
            0x16, 0x03, 0x03, 0x00, 0x2F,
            0x01, 0x00, 0x00, 0x2B,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x02, 0x13, 0x01,
            0x01, 0x00,
            0x00, 0x00
        };
        if (!seed_network_parse_capture(hf, "mcp.network_parse_tls", payload)) {
            record_fixture_failed_tool("network_parse_tls", failed);
            return;
        }
        mcp_standalone::json args;
        args["count"] = 32;
        test_tool_call(hf, "mcp.network_parse_tls", get_server(), "network_parse_tls", args, passed, failed, skipped);
        driver_bridge::stop_capture();
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
        (void)skipped;
        const char* tool_name = "network_release_packet";
        const char* tag = "mcp.network_release_packet";
        g_invoked_tools.insert(tool_name);
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- cannot create held packet fixture because kernel driver is not connected");
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        mcp_standalone::json enable_args;
        enable_args["operation"] = "enable";
        enable_args["pid"] = GetCurrentProcessId();
        enable_args["protocol"] = "udp";
        auto enable_timed = invoke_tool_bounded(get_server(), "network_intercept", enable_args, tool_timeout_ms("network_intercept"));
        const auto& enable_ir = enable_timed.result;
        log_mcp_result_detail("held_packet_setup", 0, "network_intercept", enable_args, enable_ir, enable_timed.elapsed_ms, "");
        if (enable_timed.timed_out || !enable_ir.found || enable_ir.threw || !enable_ir.success) {
            log_msg(hf, tag, "FAIL -- held packet fixture could not enable interception found=%d threw=%d success=%d timeout=%d text=%s err=%s",
                enable_ir.found ? 1 : 0,
                enable_ir.threw ? 1 : 0,
                enable_ir.success ? 1 : 0,
                enable_timed.timed_out ? 1 : 0,
                compact_text(enable_ir.text, 700).c_str(),
                compact_text(enable_ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        WSADATA wsa{};
        int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wsa_err != 0) {
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            log_msg(hf, tag, "FAIL -- held packet fixture WSAStartup failed err=%d", wsa_err);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            DWORD err = WSAGetLastError();
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            WSACleanup();
            log_msg(hf, tag, "FAIL -- held packet fixture socket creation failed err=%lu", static_cast<unsigned long>(err));
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(65432);
        const char payload[] = "AiDA network_release_packet held fixture";
        int sent = sendto(s, payload, static_cast<int>(sizeof(payload) - 1), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        int send_err = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
        closesocket(s);
        WSACleanup();
        if (sent == SOCKET_ERROR) {
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            log_msg(hf, tag, "FAIL -- held packet fixture UDP send failed err=%d", send_err);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        uint64_t hold_id = 0;
        size_t held_count = 0;
        for (int i = 0; i < 40 && hold_id == 0; ++i) {
            auto held = driver_bridge::get_held_packets();
            held_count = held.size();
            for (const auto& h : held) {
                if (h.pid == GetCurrentProcessId() && h.protocol == 17) {
                    hold_id = h.hold_id;
                    break;
                }
            }
            if (hold_id == 0)
                Sleep(50);
        }
        if (hold_id == 0) {
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            log_msg(hf, tag, "FAIL -- held packet fixture produced no held UDP packet pid=%lu held_count=%zu sent=%d",
                static_cast<unsigned long>(GetCurrentProcessId()),
                held_count,
                sent);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["hold_id"] = hold_id;
        args["action"] = "release";
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        const bool disabled = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        if (timed.timed_out || !ir.found || ir.threw || !ir.success || !disabled) {
            log_msg(hf, tag, "FAIL -- release held packet failed hold_id=%llu found=%d threw=%d success=%d timeout=%d cleanup_disabled=%d text=%s err=%s",
                static_cast<unsigned long long>(hold_id),
                ir.found ? 1 : 0,
                ir.threw ? 1 : 0,
                ir.success ? 1 : 0,
                timed.timed_out ? 1 : 0,
                disabled ? 1 : 0,
                compact_text(ir.text, 700).c_str(),
                compact_text(ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- released real held UDP packet hold_id=%llu sent=%d",
            static_cast<unsigned long long>(hold_id),
            sent);
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
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
        args["name"] = "aida_mcp_inline_test";
        args["source"] = "function on_request(ctx) return ctx end";
        test_tool_call(hf, "mcp.network_script_load", get_server(), "network_script_load", args, passed, failed, skipped);
    }

    void test_tool_network_script_unload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "network_script_unload";
        const char* tag = "mcp.network_script_unload";
        const std::string script_name = "aida_mcp_unload_fixture";
        g_invoked_tools.insert(tool_name);
        mcp_standalone::json load_args;
        load_args["name"] = script_name;
        load_args["source"] = "function on_request(ctx) return ctx end";
        auto load_timed = invoke_tool_bounded(get_server(), "network_script_load", load_args, tool_timeout_ms("network_script_load"));
        const auto& load_ir = load_timed.result;
        log_mcp_result_detail("script_unload_setup", 0, "network_script_load", load_args, load_ir, load_timed.elapsed_ms, "");
        if (load_timed.timed_out || !load_ir.found || load_ir.threw || !load_ir.success) {
            log_msg(hf, tag, "FAIL -- unload fixture could not load script found=%d threw=%d success=%d timeout=%d text=%s err=%s",
                load_ir.found ? 1 : 0,
                load_ir.threw ? 1 : 0,
                load_ir.success ? 1 : 0,
                load_timed.timed_out ? 1 : 0,
                compact_text(load_ir.text, 700).c_str(),
                compact_text(load_ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["name"] = script_name;
        test_tool_call(hf, tag, get_server(), tool_name, args, passed, failed, skipped);
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

    void test_network_pg_sniff_payload_serialization(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tag = "mcp.network_pg_sniff.payload_serialization";

        page_guard_engine::pg_capture_record_t rec;
        rec.metadata.timestamp = 1234;
        rec.metadata.fault_addr = 0x1004;
        rec.metadata.rip = 0x2000;
        rec.metadata.ctx_rdx = 0x1004;
        rec.metadata.exception_code = STATUS_GUARD_PAGE_VIOLATION;
        rec.metadata.access_type = 0;
        rec.payload_addr = 0x1004;
        rec.payload_offset = 4;
        rec.payload_read = true;
        rec.payload_source = "rdx";
        rec.payload = {'P', 'O', 'S', 'T', ' ', '/', 'l', 'a', 'b'};
        rec.payload_size = static_cast<uint32_t>(rec.payload.size());
        rec.payload_truncated = false;

        mcp_standalone::json out;
        page_guard_engine::serialize_payload_fields(out, rec);

        const bool ok = out.value("payload_available", false)
            && out.value("payload_size", 0u) == rec.payload_size
            && out.value("payload_preview_size", 0u) == rec.payload_size
            && out.value("payload_addr", std::string()) == "0x1004"
            && out.value("payload_offset", 0ull) == 4ull
            && out.value("payload_source", std::string()) == "rdx"
            && out.value("hex_preview", std::string()).find("50 4F 53 54") != std::string::npos
            && out.value("plaintext_preview", std::string()).find("POST /lab") != std::string::npos;

        if (!ok) {
            log_msg(hf, tag, "FAIL -- page guard capture serialized without payload preview: %s",
                compact_json(out, 800).c_str());
            failed.fetch_add(1);
            return;
        }

        log_msg(hf, tag, "PASS");
        passed.fetch_add(1);
    }

    void test_network_hook_sidecar_plain_e2e(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const sidecar_case_result_t result = run_network_hook_sidecar_e2e(hf, false);
        if (result == sidecar_case_result_t::passed)
            passed.fetch_add(1);
        else if (result == sidecar_case_result_t::skipped)
            skipped.fetch_add(1);
        else
            failed.fetch_add(1);
    }

    void test_network_hook_sidecar_protected_e2e(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const sidecar_case_result_t result = run_network_hook_sidecar_e2e(hf, true);
        if (result == sidecar_case_result_t::passed)
            passed.fetch_add(1);
        else if (result == sidecar_case_result_t::skipped)
            skipped.fetch_add(1);
        else
            failed.fetch_add(1);
    }

    void test_tool_network_packet_callstack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "recent";
        args["max_count"] = 8;
        test_tool_call(hf, "mcp.network_packet_callstack", get_server(), "network_packet_callstack", args, passed, failed, skipped);
    }

    void test_tool_network_pre_encrypt_hook(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        CONTEXT ctx{};
        ctx.Rcx = 0x1111111111111111ULL;
        ctx.Rdx = 0x2222222222222222ULL;
        ctx.R8 = 0x3333333333333333ULL;
        ctx.R9 = 0x4444444444444444ULL;
        bool deterministic_ok =
            pre_encrypt_hook::register_value(ctx, 0) == ctx.Rcx &&
            pre_encrypt_hook::register_value(ctx, 1) == ctx.Rdx &&
            pre_encrypt_hook::register_value(ctx, 2) == ctx.R8 &&
            pre_encrypt_hook::register_value(ctx, 3) == ctx.R9 &&
            pre_encrypt_hook::bounded_capture_size(0) == 0 &&
            pre_encrypt_hook::bounded_capture_size(32) == 32 &&
            pre_encrypt_hook::bounded_capture_size(4096) == 2048;
        if (!deterministic_ok) {
            log_msg(hf, "mcp.network_pre_encrypt_hook", "FAIL -- deterministic register/size guard failed");
            failed.fetch_add(1);
            return;
        }

        pre_encrypt_hook::clear_captures();
        std::vector<uint8_t> sample = {'l', 'a', 'b', '-', 'p', 'l', 'a', 'i', 'n'};
        pre_encrypt_hook::record_capture(1234, "lab!fixture", std::move(sample), 0x140001000ULL);
        auto caps = pre_encrypt_hook::get_captures(1);
        if (caps.size() != 1 || caps[0].tid != 1234 || caps[0].function_name != "lab!fixture" ||
            caps[0].buffer.size() != 9 || caps[0].buffer[0] != 'l') {
            log_msg(hf, "mcp.network_pre_encrypt_hook", "FAIL -- deterministic capture queue guard failed");
            pre_encrypt_hook::clear_captures();
            failed.fetch_add(1);
            return;
        }
        pre_encrypt_hook::clear_captures();

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
        args["operation"] = "status";
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
        (void)skipped;
        test_tool_schema_only(hf, "mcp.cert_inject", get_server(), "cert_inject", {"cert_pem", "cert_der_hex"}, passed, failed, skipped);
    }

    void test_tool_cert_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        test_tool_schema_only(hf, "mcp.cert_remove", get_server(), "cert_remove", {"thumbprint"}, passed, failed, skipped);
    }

    void test_tool_cert_generate_ca(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.cert_generate_ca", get_server(), "cert_generate_ca", {}, passed, failed, skipped, false, &result);
        if (status != mcp_tool_call_status_t::passed)
            return;
        bool private_exported = true;
        bool has_private_material =
            find_payload_key_recursive(result.data, "key_der_hex") ||
            find_payload_key_recursive(result.data, "private_key_der") ||
            find_payload_key_recursive(result.data, "private_key_pem");
        if (payload_bool_field(result.data, "private_key_exported", private_exported) &&
            !private_exported && !has_private_material) {
            log_msg(hf, "mcp.cert_generate_ca.guard", "PASS -- cert_generate_ca returned public certificate only");
            return;
        }
        log_msg(hf, "mcp.cert_generate_ca.guard", "FAIL -- cert_generate_ca exposed private key material or omitted private_key_exported=false");
        failed.fetch_add(1);
    }

    void test_tool_cert_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.cert_list", get_server(), "cert_list", {}, passed, failed, skipped);
    }

    void test_tool_pin_bypass(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        mcp_standalone::json args;
        args["pid"] = 0;
        args["method"] = "all";
        g_invoked_tools.insert("pin_bypass");
        auto timed = invoke_tool_bounded(get_server(), "pin_bypass", args, tool_timeout_ms("pin_bypass"));
        auto& ir = timed.result;
        if (timed.timed_out || !ir.found || ir.threw || !ir.success) {
            log_msg(hf, "mcp.pin_bypass.guard", "FAIL -- pin_bypass dispatch failed found=%s threw=%s success=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                ir.success ? "true" : "false",
                timed.timed_out ? "true" : "false",
                ir.exception_msg.c_str());
            record_tool_status("pin_bypass", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        bool success = true;
        bool read_only = false;
        bool modified = true;
        bool legacy_disabled = false;
        bool has_diagnostics = ir.data.contains("diagnostics") && ir.data["diagnostics"].is_object();
        if (payload_bool_field(ir.data, "success", success) &&
            payload_bool_field(ir.data, "read_only", read_only) &&
            payload_bool_field(ir.data, "target_process_modified", modified) &&
            payload_bool_field(ir.data, "legacy_patching_disabled", legacy_disabled) &&
            !success && read_only && !modified && legacy_disabled && has_diagnostics) {
            log_msg(hf, "mcp.pin_bypass.guard", "PASS -- pin_bypass is diagnostic-only and non-mutating");
            record_tool_status("pin_bypass", mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, "mcp.pin_bypass.guard", "FAIL -- pin_bypass returned operational or mutating state success=%s read_only=%s modified=%s legacy_disabled=%s diagnostics=%s",
            success ? "true" : "false",
            read_only ? "true" : "false",
            modified ? "true" : "false",
            legacy_disabled ? "true" : "false",
            has_diagnostics ? "true" : "false");
        record_tool_status("pin_bypass", mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_pin_bypass_revert(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pid"] = 0xFFFFFFFEu;
        test_tool_call(hf, "mcp.pin_bypass_revert", get_server(), "pin_bypass_revert", args, passed, failed, skipped);
    }

    void test_tool_pin_bypass_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.pin_bypass_status", get_server(), "pin_bypass_status", {}, passed, failed, skipped);
    }

    void test_tool_firefox_profile_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        g_invoked_tools.insert("firefox_profile_status");
        auto timed = invoke_tool_bounded(get_server(), "firefox_profile_status", {}, tool_timeout_ms("firefox_profile_status"));
        auto& ir = timed.result;
        if (timed.timed_out || !ir.found || ir.threw || !ir.success) {
            log_msg(hf, "mcp.firefox_profile_status.guard", "FAIL -- firefox_profile_status dispatch failed found=%s threw=%s success=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                ir.success ? "true" : "false",
                timed.timed_out ? "true" : "false",
                ir.exception_msg.c_str());
            record_tool_status("firefox_profile_status", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        bool profile_files_valid = false;
        bool trust_verified = true;
        bool runtime_checked = true;
        bool runtime_valid = true;
        bool prepared = true;
        payload_bool_field(ir.data, "profile_files_valid", profile_files_valid);
        payload_bool_field(ir.data, "trust_readiness_verified", trust_verified);
        payload_bool_field(ir.data, "runtime_validation_performed", runtime_checked);
        payload_bool_field(ir.data, "runtime_validation_valid", runtime_valid);
        payload_bool_field(ir.data, "prepared", prepared);
        if (!runtime_checked && !runtime_valid && (!profile_files_valid || prepared == trust_verified)) {
            log_msg(hf, "mcp.firefox_profile_status.guard", "PASS -- Firefox status separates file validity from trust/runtime validation");
            record_tool_status("firefox_profile_status", mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, "mcp.firefox_profile_status.guard", "FAIL -- Firefox status regressed to schema/file-only readiness files=%s trust=%s runtime_checked=%s runtime_valid=%s prepared=%s",
            profile_files_valid ? "true" : "false",
            trust_verified ? "true" : "false",
            runtime_checked ? "true" : "false",
            runtime_valid ? "true" : "false",
            prepared ? "true" : "false");
        record_tool_status("firefox_profile_status", mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_firefox_profile_prepare(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["proxy_host"] = "127.0.0.1";
        args["proxy_port"] = 18443;
        const char* tool_name = "firefox_profile_prepare";
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        if (timed.timed_out || !ir.found || ir.threw) {
            log_msg(hf, "mcp.firefox_profile_prepare.guard", "FAIL -- firefox_profile_prepare dispatch failed found=%s threw=%s success=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                ir.success ? "true" : "false",
                timed.timed_out ? "true" : "false",
                compact_text(ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (ir.success) {
            bool firefox_detected = false;
            payload_bool_field(ir.data, "firefox_detected", firefox_detected);
            if (!firefox_detected) {
                log_msg(hf, "mcp.firefox_profile_prepare.guard", "SKIP -- Firefox host dependency unavailable after profile prepare diagnostic: %s",
                    compact_text(ir.text, 700).c_str());
                record_tool_status(tool_name, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                return;
            }
            log_msg(hf, "mcp.firefox_profile_prepare.guard", "PASS -- Firefox profile prepare completed success=%s",
                compact_text(ir.text, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        if (payload_text_contains(ir, "current_user_ca_not_trusted")) {
            auto status_timed = invoke_tool_bounded(get_server(), "firefox_profile_status", {}, tool_timeout_ms("firefox_profile_status"));
            auto& status_ir = status_timed.result;
            bool profile_files_valid = false;
            bool trust_verified = true;
            bool runtime_checked = true;
            bool runtime_valid = true;
            bool prepared = true;
            bool firefox_detected = false;
            payload_bool_field(status_ir.data, "profile_files_valid", profile_files_valid);
            payload_bool_field(status_ir.data, "trust_readiness_verified", trust_verified);
            payload_bool_field(status_ir.data, "runtime_validation_performed", runtime_checked);
            payload_bool_field(status_ir.data, "runtime_validation_valid", runtime_valid);
            payload_bool_field(status_ir.data, "prepared", prepared);
            payload_bool_field(status_ir.data, "firefox_detected", firefox_detected);
            if (!status_timed.timed_out && status_ir.found && !status_ir.threw && status_ir.success && !firefox_detected) {
                log_msg(hf, "mcp.firefox_profile_prepare.guard", "SKIP -- Firefox host dependency unavailable; profile file diagnostics were recorded without counting as runtime success");
                record_tool_status(tool_name, mcp_tool_call_status_t::skipped);
                skipped.fetch_add(1);
                return;
            }
            if (!status_timed.timed_out && status_ir.found && !status_ir.threw && status_ir.success &&
                profile_files_valid && !trust_verified && !runtime_checked && !runtime_valid && !prepared) {
                log_msg(hf, "mcp.firefox_profile_prepare.guard", "PASS -- Firefox profile files prepared; current-user CA trust is explicitly reported as unavailable without mutating trust stores");
                record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
            log_msg(hf, "mcp.firefox_profile_prepare.guard", "FAIL -- current-user trust diagnostic was returned but status did not confirm prepared profile files files=%s trust=%s runtime_checked=%s runtime_valid=%s prepared=%s status_success=%s",
                profile_files_valid ? "true" : "false",
                trust_verified ? "true" : "false",
                runtime_checked ? "true" : "false",
                runtime_valid ? "true" : "false",
                prepared ? "true" : "false",
                status_ir.success ? "true" : "false");
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, "mcp.firefox_profile_prepare.guard", "FAIL -- firefox_profile_prepare returned unexpected failure text=%s",
            compact_text(ir.text, 900).c_str());
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_firefox_profile_launch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["proxy_host"] = "127.0.0.1";
        args["proxy_port"] = 18443;
        args["validate_only"] = true;
        g_invoked_tools.insert("firefox_profile_launch");
        auto timed = invoke_tool_bounded(get_server(), "firefox_profile_launch", args, tool_timeout_ms("firefox_profile_launch"));
        auto& ir = timed.result;
        if (timed.timed_out || !ir.found || ir.threw || !ir.success) {
            log_msg(hf, "mcp.firefox_profile_launch.guard", "FAIL -- firefox_profile_launch validate_only dispatch failed found=%s threw=%s success=%s timeout=%s err=%s",
                ir.found ? "true" : "false",
                ir.threw ? "true" : "false",
                ir.success ? "true" : "false",
                timed.timed_out ? "true" : "false",
                ir.exception_msg.c_str());
            record_tool_status("firefox_profile_launch", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        bool launched = true;
        bool runtime_checked = true;
        bool runtime_valid = true;
        bool firefox_detected = false;
        bool has_validate_note = payload_text_contains(ir, "launch validation only");
        payload_bool_field(ir.data, "launched", launched);
        payload_bool_field(ir.data, "runtime_validation_performed", runtime_checked);
        payload_bool_field(ir.data, "runtime_validation_valid", runtime_valid);
        payload_bool_field(ir.data, "firefox_detected", firefox_detected);
        if (!firefox_detected) {
            log_msg(hf, "mcp.firefox_profile_launch.guard", "SKIP -- Firefox host dependency unavailable for launch validation");
            record_tool_status("firefox_profile_launch", mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return;
        }
        if (!launched && !runtime_checked && !runtime_valid && has_validate_note) {
            log_msg(hf, "mcp.firefox_profile_launch.guard", "PASS -- Firefox launch readiness is behaviorally validated without starting a browser");
            record_tool_status("firefox_profile_launch", mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, "mcp.firefox_profile_launch.guard", "FAIL -- Firefox launch validate_only regressed launched=%s runtime_checked=%s runtime_valid=%s note=%s",
            launched ? "true" : "false",
            runtime_checked ? "true" : "false",
            runtime_valid ? "true" : "false",
            has_validate_note ? "true" : "false");
        record_tool_status("firefox_profile_launch", mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_quic_detect_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.quic_detect_connections", get_server(), "quic_detect_connections", {}, passed, failed, skipped);
    }

    void test_tool_quic_decrypt_initial(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["packet_hex"] = "C000000001080011223344556677088899AABBCCDDEEFF00100000000000";
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
        args["match_type"] = "prefix_url";
        args["match_pattern"] = "http://test.local/";
        args["response_body"] = "test";
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.autoresponder_add_rule", get_server(), "autoresponder_add_rule", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "rule_id", g_autoresponder_rule_id);
    }

    void test_tool_autoresponder_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["rule_id"] = g_autoresponder_rule_id;
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
        args["rules_json"] = "[]";
        test_tool_call(hf, "mcp.autoresponder_import_rules", get_server(), "autoresponder_import_rules", args, passed, failed, skipped);
    }

    void test_tool_autoresponder_export_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\temp\\aida_test_rules.json";
        test_tool_call(hf, "mcp.autoresponder_export_rules", get_server(), "autoresponder_export_rules", args, passed, failed, skipped);
    }

    void test_tool_network_decrypt_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tool_name = "network_decrypt_capture";
        const char* tag = "mcp.network_decrypt_capture";
        const std::string pcap_path = temp_file_narrow("aida_mcp_empty_tls_fixture.pcap");
        const std::string keylog_path = temp_file_narrow("aida_mcp_empty_tls_fixture.keys");
        const std::vector<uint8_t> pcap = {
            0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
        };
        if (!write_binary_file_narrow(pcap_path, pcap) || !write_text_file_narrow(keylog_path, "CLIENT_RANDOM 0000000000000000000000000000000000000000000000000000000000000000 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n")) {
            log_msg(hf, tag, "FAIL -- could not create deterministic pcap/keylog fixtures pcap=%s keylog=%s",
                pcap_path.c_str(), keylog_path.c_str());
            record_fixture_failed_tool(tool_name, failed);
            return;
        }
        mcp_standalone::json args;
        args["pcap_path"] = pcap_path;
        args["keylog_path"] = keylog_path;
        args["display_filter"] = "http2";
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        const std::string text_lc = lower_copy(ir.text + " " + ir.exception_msg);
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        if (timed.timed_out || !ir.found || ir.threw) {
            log_msg(hf, tag, "FAIL -- dispatch failed found=%d threw=%d timeout=%d err=%s",
                ir.found ? 1 : 0,
                ir.threw ? 1 : 0,
                timed.timed_out ? 1 : 0,
                compact_text(ir.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (text_lc.find("pcap file not found") != std::string::npos ||
            text_lc.find("keylog file not found") != std::string::npos) {
            log_msg(hf, tag, "FAIL -- network_decrypt_capture dependency/path failure: %s",
                compact_text(ir.text, 900).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (text_lc.find("tshark not found") != std::string::npos ||
            text_lc.find("failed to launch tshark") != std::string::npos) {
            log_msg(hf, tag, "SKIP -- tshark host dependency unavailable for deterministic pcap/keylog fixture: %s",
                compact_text(ir.text, 900).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::skipped);
            skipped.fetch_add(1);
            return;
        }
        uint64_t decrypted_packets = 0;
        uint64_t total_packets = 0;
        payload_u64_field(ir.data, "decrypted_packets", decrypted_packets);
        payload_u64_field(ir.data, "total_packets", total_packets);
        if (ir.success && decrypted_packets > 0) {
            log_msg(hf, tag, "PASS -- network_decrypt_capture decrypted deterministic pcap/keylog fixture packets=%llu total=%llu text=%s",
                static_cast<unsigned long long>(decrypted_packets),
                static_cast<unsigned long long>(total_packets),
                compact_text(ir.text, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "FAIL -- unexpected network_decrypt_capture result success=%d text=%s",
            ir.success ? 1 : 0,
            compact_text(ir.text, 900).c_str());
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_tls_ensure_keylogfile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.tls_ensure_keylogfile", get_server(), "tls_ensure_keylogfile", {}, passed, failed, skipped);
    }

    void test_tool_burp_scanner_start_audit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string url = burp_fixture_url(hf, "mcp.burp_scanner_start_audit");
        mcp_standalone::json args; args["url"] = url; args["raw_request"] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"; args["modules"] = mcp_standalone::json::array({"csp"}); args["per_module_cap"] = 1; args["timeout_ms"] = 2000; args["max_concurrent"] = 1;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_scanner_start_audit", get_server(), "burp_scanner_start_audit", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            json_u64_field(result.data, "audit_id", g_burp_scanner_audit_id);
            Sleep(250);
        }
    }
    void test_tool_burp_scanner_audit_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["audit_id"] = g_burp_scanner_audit_id;
        test_tool_call(hf, "mcp.burp_scanner_audit_status", get_server(), "burp_scanner_audit_status", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_list_audits(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_scanner_list_audits", get_server(), "burp_scanner_list_audits", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_cancel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["audit_id"] = g_burp_scanner_audit_id;
        test_tool_call(hf, "mcp.burp_scanner_cancel", get_server(), "burp_scanner_cancel", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_list_issues(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_scanner_list_issues", get_server(), "burp_scanner_list_issues", {}, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_array_first_field(result.data, "issues", g_burp_scanner_issue_id, {"id", "issue_id"});
    }
    void test_tool_burp_scanner_get_issue(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_burp_scanner_issue_id == 0)
            seed_burp_scanner_issue_fixture(hf, "mcp.burp_scanner_get_issue");
        if (g_burp_scanner_issue_id == 0) {
            record_precondition_skipped_tool("burp_scanner_get_issue", skipped);
            return;
        }
        mcp_standalone::json args; args["issue_id"] = g_burp_scanner_issue_id;
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
        seed_burp_sitemap_fixture(hf, "mcp.burp_sitemap_list_hosts");
        test_tool_call(hf, "mcp.burp_sitemap_list_hosts", get_server(), "burp_sitemap_list_hosts", {}, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_list_paths(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_burp_sitemap_fixture(hf, "mcp.burp_sitemap_list_paths");
        mcp_standalone::json args; args["host"] = "127.0.0.1"; if (g_burp_http_fixture) args["port"] = g_burp_http_fixture->port;
        test_tool_call(hf, "mcp.burp_sitemap_list_paths", get_server(), "burp_sitemap_list_paths", args, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_get_exchange(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_burp_sitemap_fixture(hf, "mcp.burp_sitemap_get_exchange");
        mcp_standalone::json args; args["exchange_id"] = g_burp_sitemap_exchange_id;
        test_tool_call(hf, "mcp.burp_sitemap_get_exchange", get_server(), "burp_sitemap_get_exchange", args, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_send_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_burp_sitemap_fixture(hf, "mcp.burp_sitemap_send_to");
        mcp_standalone::json args; args["exchange_id"] = g_burp_sitemap_exchange_id; args["target"] = "repeater";
        test_tool_call(hf, "mcp.burp_sitemap_send_to", get_server(), "burp_sitemap_send_to", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = static_cast<std::uint64_t>(424242); args["kind"] = "include"; args["protocol"] = "http"; args["host_pattern"] = "127.0.0.1"; args["port"] = 0; args["path_prefix"] = "/"; args["enabled"] = true;
        test_tool_call(hf, "mcp.burp_scope_add", get_server(), "burp_scope_add", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = static_cast<std::uint64_t>(424242);
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
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["name"] = "test_cookie"; args["value"] = "test_val"; args["domain"] = "127.0.0.1";
        test_tool_call(hf, "mcp.burp_cookie_set", get_server(), "burp_cookie_set", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["name"] = "test_cookie";
        test_tool_call(hf, "mcp.burp_cookie_delete", get_server(), "burp_cookie_delete", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_export_netscape(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["file_path"] = temp_file_narrow("aida_mcp_cookies.txt");
        test_tool_call(hf, "mcp.burp_cookie_export_netscape", get_server(), "burp_cookie_export_netscape", args, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_dom_xss_status", get_server(), "burp_dom_xss_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_test_payload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["target_url"] = burp_fixture_url(hf, "mcp.burp_dom_xss_test_payload", "/?q=test"); args["payload"] = "<script>test</script>";
        test_tool_call(hf, "mcp.burp_dom_xss_test_payload", get_server(), "burp_dom_xss_test_payload", args, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["target_url"] = burp_fixture_url(hf, "mcp.burp_dom_xss_scan", "/?q=test");
        test_tool_call(hf, "mcp.burp_dom_xss_scan", get_server(), "burp_dom_xss_scan", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["start_urls"] = mcp_standalone::json::array({burp_fixture_url(hf, "mcp.burp_crawler_start")}); args["max_depth"] = 1; args["max_pages"] = 2; args["concurrency"] = 1; args["respect_robots"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_crawler_start", get_server(), "burp_crawler_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "crawl_id", g_burp_crawler_id);
    }
    void test_tool_burp_crawler_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crawl_id"] = g_burp_crawler_id;
        test_tool_call(hf, "mcp.burp_crawler_status", get_server(), "burp_crawler_status", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crawl_id"] = g_burp_crawler_id;
        test_tool_call(hf, "mcp.burp_crawler_stop", get_server(), "burp_crawler_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_crawler_list", get_server(), "burp_crawler_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string target = burp_fixture_url(hf, "mcp.burp_content_discovery_start", "/FUZZ");
        mcp_standalone::json args; args["target_url"] = target; args["wordlist_file"] = g_burp_fixture_wordlist_path; args["concurrency"] = 1; args["request_timeout_ms"] = 1500; args["auto_calibrate"] = false; args["match_status"] = mcp_standalone::json::array({200});
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_content_discovery_start", get_server(), "burp_content_discovery_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "disc_id", g_burp_content_discovery_id);
    }
    void test_tool_burp_content_discovery_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["disc_id"] = g_burp_content_discovery_id;
        test_tool_call(hf, "mcp.burp_content_discovery_status", get_server(), "burp_content_discovery_status", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["disc_id"] = g_burp_content_discovery_id;
        test_tool_call(hf, "mcp.burp_content_discovery_results", get_server(), "burp_content_discovery_results", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["disc_id"] = g_burp_content_discovery_id;
        test_tool_call(hf, "mcp.burp_content_discovery_stop", get_server(), "burp_content_discovery_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["domain"] = "test.local"; args["run_passive"] = false; args["run_brute"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_subdomain_enum_start", get_server(), "burp_subdomain_enum_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "sub_id", g_burp_subdomain_id);
    }
    void test_tool_burp_subdomain_enum_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["sub_id"] = g_burp_subdomain_id;
        test_tool_call(hf, "mcp.burp_subdomain_enum_status", get_server(), "burp_subdomain_enum_status", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["sub_id"] = g_burp_subdomain_id;
        test_tool_call(hf, "mcp.burp_subdomain_enum_results", get_server(), "burp_subdomain_enum_results", args, passed, failed, skipped);
    }
    void test_tool_burp_payloads_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_payloads_list", get_server(), "burp_payloads_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_payloads_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["set_id"] = "xss/polyglot"; args["max"] = 8;
        test_tool_call(hf, "mcp.burp_payloads_get", get_server(), "burp_payloads_get", args, passed, failed, skipped);
    }
    void test_tool_burp_payloads_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["query"] = "xss";
        test_tool_call(hf, "mcp.burp_payloads_search", get_server(), "burp_payloads_search", args, passed, failed, skipped);
    }
    void test_tool_burp_payloads_add_custom(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["set_id"] = "custom/aida_mcp_test"; args["label"] = "AiDA MCP Test"; args["entries"] = mcp_standalone::json::array({"test"});
        test_tool_call(hf, "mcp.burp_payloads_add_custom", get_server(), "burp_payloads_add_custom", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        ensure_burp_http_fixture(hf, "mcp.burp_intruder_start");
        const uint16_t port = g_burp_http_fixture ? g_burp_http_fixture->port : 1;
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["port"] = port; args["scheme"] = "http"; args["base_request"] = "GET /?q=test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"; args["positions"] = mcp_standalone::json::array({mcp_standalone::json::array({8, 4})}); args["payload_sets"] = mcp_standalone::json::array({mcp_standalone::json::array({"aida"})}); args["total_cap"] = 1; args["concurrency"] = 1; args["timeout_ms"] = 1500;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_intruder_start", get_server(), "burp_intruder_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "job_id", g_burp_intruder_job_id);
    }
    void test_tool_burp_intruder_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_call(hf, "mcp.burp_intruder_status", get_server(), "burp_intruder_status", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_call(hf, "mcp.burp_intruder_results", get_server(), "burp_intruder_results", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_call(hf, "mcp.burp_intruder_stop", get_server(), "burp_intruder_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_intruder_list_jobs", get_server(), "burp_intruder_list_jobs", {}, passed, failed, skipped);
    }
    void test_tool_burp_intruder_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_call(hf, "mcp.burp_intruder_clear", get_server(), "burp_intruder_clear", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["target_url"] = burp_fixture_url(hf, "mcp.burp_param_miner_start"); args["custom_words"] = mcp_standalone::json::array({"aida_mcp_param"}); args["baseline_count"] = 1; args["concurrency"] = 1; args["timeout_ms"] = 1500;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_param_miner_start", get_server(), "burp_param_miner_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "job_id", g_burp_param_miner_job_id);
    }
    void test_tool_burp_param_miner_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_param_miner_job_id;
        test_tool_call(hf, "mcp.burp_param_miner_status", get_server(), "burp_param_miner_status", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_param_miner_job_id;
        test_tool_call(hf, "mcp.burp_param_miner_results", get_server(), "burp_param_miner_results", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_param_miner_job_id;
        test_tool_call(hf, "mcp.burp_param_miner_stop", get_server(), "burp_param_miner_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_h2_send(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["host"] = "nghttp2.org"; args["port"] = 443; args["timeout_ms"] = 15000;
        args["pseudo_headers"] = mcp_standalone::json::object({{"method", "GET"}, {"scheme", "https"}, {"path", "/httpbin/get"}, {"authority", "nghttp2.org"}});
        test_tool_call(hf, "mcp.burp_h2_send", get_server(), "burp_h2_send", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_call(hf, "mcp.burp_jwt_decode", get_server(), "burp_jwt_decode", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_forge(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["header"] = mcp_standalone::json::object({{"typ", "JWT"}}); args["payload"] = mcp_standalone::json::object({{"sub", "test"}}); args["alg"] = "HS256"; args["hmac_secret"] = "test";
        test_tool_call(hf, "mcp.burp_jwt_forge", get_server(), "burp_jwt_forge", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_verify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.Gmlw_dPyBS-autswceWkocF9ELiEHKeS86-MHgG8MhY"; args["key"] = "test"; args["mode"] = "hmac";
        test_tool_call(hf, "mcp.burp_jwt_verify", get_server(), "burp_jwt_verify", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_crack_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.Gmlw_dPyBS-autswceWkocF9ELiEHKeS86-MHgG8MhY";
        args["custom_words"] = mcp_standalone::json::array({"test", "secret"}); args["concurrency"] = 1; args["max_attempts"] = 2;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_jwt_crack_start", get_server(), "burp_jwt_crack_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "crack_id", g_burp_jwt_crack_id);
    }
    void test_tool_burp_jwt_crack_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crack_id"] = g_burp_jwt_crack_id;
        test_tool_call(hf, "mcp.burp_jwt_crack_status", get_server(), "burp_jwt_crack_status", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_crack_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crack_id"] = g_burp_jwt_crack_id;
        test_tool_call(hf, "mcp.burp_jwt_crack_stop", get_server(), "burp_jwt_crack_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_attack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_call(hf, "mcp.burp_jwt_attack", get_server(), "burp_jwt_attack", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_basic_encode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["user"] = "test"; args["pass"] = "test";
        test_tool_call(hf, "mcp.burp_auth_basic_encode", get_server(), "burp_auth_basic_encode", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_basic_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["header"] = "Basic dGVzdDp0ZXN0";
        test_tool_call(hf, "mcp.burp_auth_basic_decode", get_server(), "burp_auth_basic_decode", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_digest_solve(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["user"] = "test"; args["pass"] = "test"; args["method"] = "GET";
        args["www_auth_header"] = "Digest realm=\"test\", nonce=\"abcdef\", algorithm=MD5, qop=\"auth\""; args["uri"] = "/";
        test_tool_call(hf, "mcp.burp_auth_digest_solve", get_server(), "burp_auth_digest_solve", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_ntlm_type1(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_auth_ntlm_type1", get_server(), "burp_auth_ntlm_type1", {}, passed, failed, skipped);
    }
    void test_tool_burp_auth_ntlm_type3(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["user"] = "test"; args["pass"] = "test"; args["type2_b64"] = "TlRMTVNTUAACAAAAAAAAAAAAAAABAgMEBQYHCAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
        mcp_standalone::json args; args["client_id"] = "test"; args["authorize_endpoint"] = "http://127.0.0.1/auth"; args["redirect_uri"] = "http://127.0.0.1/cb";
        test_tool_call(hf, "mcp.burp_auth_oauth2_build_auth_url", get_server(), "burp_auth_oauth2_build_auth_url", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_oauth2_exchange_code(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["code"] = "test_code"; args["token_endpoint"] = burp_fixture_url(hf, "mcp.burp_auth_oauth2_exchange_code", "/token"); args["client_id"] = "test"; args["redirect_uri"] = "http://127.0.0.1/cb";
        test_tool_call(hf, "mcp.burp_auth_oauth2_exchange_code", get_server(), "burp_auth_oauth2_exchange_code", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_oauth2_refresh(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["refresh_token"] = "test_refresh"; args["token_endpoint"] = burp_fixture_url(hf, "mcp.burp_auth_oauth2_refresh", "/token"); args["client_id"] = "test";
        test_tool_call(hf, "mcp.burp_auth_oauth2_refresh", get_server(), "burp_auth_oauth2_refresh", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_saml_decode_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["saml_b64"] = "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBJRD0iX2FpZGEiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDI2LTA1LTI0VDAwOjAwOjAwWiI+PC9zYW1scDpBdXRoblJlcXVlc3Q%2B";
        test_tool_call(hf, "mcp.burp_auth_saml_decode_request", get_server(), "burp_auth_saml_decode_request", args, passed, failed, skipped);
    }
    void test_tool_burp_auth_saml_decode_response(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["saml_b64"] = "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJfYWlkYV9yZXNwIiBWZXJzaW9uPSIyLjAiIElzc3VlSW5zdGFudD0iMjAyNi0wNS0yNFQwMDowMDowMFoiPjwvc2FtbHA6UmVzcG9uc2U+";
        test_tool_call(hf, "mcp.burp_auth_saml_decode_response", get_server(), "burp_auth_saml_decode_response", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["label"] = "aida_mcp_match_replace"; args["target"] = "request_body"; args["match_regex"] = "test"; args["replacement"] = "test_replace"; args["regex"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_match_replace_add", get_server(), "burp_match_replace_add", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "rule_id", g_burp_match_replace_rule_id);
    }
    void test_tool_burp_match_replace_update(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_match_replace_rule_id; args["fields"] = mcp_standalone::json::object({{"replacement", "test_replace2"}});
        test_tool_call(hf, "mcp.burp_match_replace_update", get_server(), "burp_match_replace_update", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_match_replace_rule_id;
        test_tool_call(hf, "mcp.burp_match_replace_remove", get_server(), "burp_match_replace_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_match_replace_list", get_server(), "burp_match_replace_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_match_replace_clear", get_server(), "burp_match_replace_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_test(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_match_replace_rule_id; args["target"] = "request_body"; args["sample_b64"] = "dGVzdCBkYXRh";
        test_tool_call(hf, "mcp.burp_match_replace_test", get_server(), "burp_match_replace_test", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        ensure_burp_http_fixture(hf, "mcp.burp_macro_add");
        const uint16_t port = g_burp_http_fixture ? g_burp_http_fixture->port : 1;
        mcp_standalone::json step = mcp_standalone::json::object();
        step["label"] = "fixture";
        step["scheme"] = "http";
        step["host"] = "127.0.0.1";
        step["port"] = port;
        step["raw_request"] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        step["timeout_ms"] = 1500;
        step["extracts"] = mcp_standalone::json::array({mcp_standalone::json::object({{"name", "title"}, {"from", "resp_body"}, {"regex", "AiDA MCP Fixture"}, {"group", 0}})});
        mcp_standalone::json args; args["name"] = "aida_mcp_macro"; args["steps"] = mcp_standalone::json::array({step});
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_macro_add", get_server(), "burp_macro_add", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "macro_id", g_burp_macro_id);
    }
    void test_tool_burp_macro_run(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["macro_id"] = g_burp_macro_id;
        test_tool_call(hf, "mcp.burp_macro_run", get_server(), "burp_macro_run", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_macro_list", get_server(), "burp_macro_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_macro_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["macro_id"] = g_burp_macro_id;
        test_tool_call(hf, "mcp.burp_macro_remove", get_server(), "burp_macro_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_update(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["macro_id"] = g_burp_macro_id; args["fields"] = mcp_standalone::json::object({{"name", "aida_mcp_macro_updated"}});
        test_tool_call(hf, "mcp.burp_macro_update", get_server(), "burp_macro_update", args, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "aida_mcp_session_rule"; args["match"] = "url_regex"; args["pattern"] = ".*"; args["macro_id"] = g_burp_macro_id;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_session_rule_add", get_server(), "burp_session_rule_add", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "rule_id", g_burp_session_rule_id);
    }
    void test_tool_burp_session_rule_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_session_rule_list", get_server(), "burp_session_rule_list", {}, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_session_rule_id;
        test_tool_call(hf, "mcp.burp_session_rule_remove", get_server(), "burp_session_rule_remove", args, passed, failed, skipped);
    }
    void test_tool_burp_api_import(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string source = "text:{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"AiDA MCP Test\",\"version\":\"1.0.0\"},\"servers\":[{\"url\":\"" + burp_fixture_url(hf, "mcp.burp_api_import") + "\"}],\"paths\":{\"/ping\":{\"get\":{\"operationId\":\"ping\",\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}";
        mcp_standalone::json args; args["format"] = "openapi_json"; args["source"] = source;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_api_import", get_server(), "burp_api_import", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_any_field(result.data, g_burp_api_collection_id, {"id", "collection_id"});
    }
    void test_tool_burp_api_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_api_list_collections", get_server(), "burp_api_list_collections", {}, passed, failed, skipped);
    }
    void test_tool_burp_api_get_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id;
        test_tool_call(hf, "mcp.burp_api_get_collection", get_server(), "burp_api_get_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_api_remove_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id;
        test_tool_call(hf, "mcp.burp_api_remove_collection", get_server(), "burp_api_remove_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_api_send_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id; args["request_id"] = "ping";
        test_tool_call(hf, "mcp.burp_api_send_request", get_server(), "burp_api_send_request", args, passed, failed, skipped);
    }
    void test_tool_burp_api_audit_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id;
        test_tool_call(hf, "mcp.burp_api_audit_collection", get_server(), "burp_api_audit_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_introspect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["endpoint"] = burp_fixture_url(hf, "mcp.burp_graphql_introspect", "/graphql");
        test_tool_call(hf, "mcp.burp_graphql_introspect", get_server(), "burp_graphql_introspect", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_example(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["endpoint"] = burp_fixture_url(hf, "mcp.burp_graphql_example", "/graphql"); args["field_name"] = "__typename"; args["depth"] = 1;
        test_tool_call(hf, "mcp.burp_graphql_example", get_server(), "burp_graphql_example", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_send(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["endpoint"] = burp_fixture_url(hf, "mcp.burp_graphql_send", "/graphql"); args["query"] = "{ __typename }";
        test_tool_call(hf, "mcp.burp_graphql_send", get_server(), "burp_graphql_send", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_connect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_burp_http_fixture(hf, "mcp.burp_ws_connect") || !g_burp_http_fixture || g_burp_http_fixture->port == 0) {
            log_msg(hf, "mcp.burp_ws_connect", "FAIL -- websocket fixture listener setup failed");
            record_fixture_failed_tool("burp_ws_connect", failed);
            return;
        }
        mcp_standalone::json args; args["scheme"] = "ws"; args["host"] = "127.0.0.1"; args["port"] = g_burp_http_fixture->port; args["path"] = "/ws";
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_ws_connect", get_server(), "burp_ws_connect", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_any_field(result.data, g_burp_ws_conn_id, {"conn_id", "id"});
    }
    void test_tool_burp_ws_disconnect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id;
        test_tool_call(hf, "mcp.burp_ws_disconnect", get_server(), "burp_ws_disconnect", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_send_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id; args["msg"] = "test";
        test_tool_call(hf, "mcp.burp_ws_send_text", get_server(), "burp_ws_send_text", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_send_binary(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id; args["data_b64"] = "AA==";
        test_tool_call(hf, "mcp.burp_ws_send_binary", get_server(), "burp_ws_send_binary", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_send_raw(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id; args["opcode"] = 1; args["fin"] = true; args["masked"] = true; args["payload_b64"] = "dGVzdA==";
        test_tool_call(hf, "mcp.burp_ws_send_raw", get_server(), "burp_ws_send_raw", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_list_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_ws_list_connections", get_server(), "burp_ws_list_connections", {}, passed, failed, skipped);
    }
    void test_tool_burp_ws_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id;
        test_tool_call(hf, "mcp.burp_ws_frames", get_server(), "burp_ws_frames", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_clear_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id;
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
        mcp_standalone::json args; args["format"] = "html"; args["output_path"] = temp_file_narrow("aida_burp_report.html"); args["title"] = "AiDA MCP Test";
        test_tool_call(hf, "mcp.burp_report_generate", get_server(), "burp_report_generate", args, passed, failed, skipped);
    }
    void test_tool_burp_bambda_compile(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["source"] = "request.method == \"GET\"";
        test_tool_call(hf, "mcp.burp_bambda_compile", get_server(), "burp_bambda_compile", args, passed, failed, skipped);
    }
    void test_tool_burp_bambda_test(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["source"] = "request.method == \"GET\""; args["row"] = mcp_standalone::json::object({{"request", mcp_standalone::json::object({{"method", "GET"}, {"host", "127.0.0.1"}})}, {"response", mcp_standalone::json::object({{"status", 200}})}});
        test_tool_call(hf, "mcp.burp_bambda_test", get_server(), "burp_bambda_test", args, passed, failed, skipped);
    }
    void test_tool_burp_bambda_help(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_bambda_help", get_server(), "burp_bambda_help", {}, passed, failed, skipped);
    }
    void test_tool_burp_csp_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["csp_header_value"] = "default-src 'self'";
        test_tool_call(hf, "mcp.burp_csp_analyze", get_server(), "burp_csp_analyze", args, passed, failed, skipped);
    }
    void test_tool_burp_csp_analyze_url(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = burp_fixture_url(hf, "mcp.burp_csp_analyze_url");
        test_tool_call(hf, "mcp.burp_csp_analyze_url", get_server(), "burp_csp_analyze_url", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_add_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        ensure_burp_http_fixture(hf, "mcp.burp_upstream_add_chain");
        mcp_standalone::json hop = mcp_standalone::json::object({{"type", "http_connect"}, {"host", "127.0.0.1"}, {"port", g_burp_http_fixture ? g_burp_http_fixture->port : 1}});
        mcp_standalone::json args; args["label"] = "aida_mcp_upstream"; args["hops"] = mcp_standalone::json::array({hop});
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_upstream_add_chain", get_server(), "burp_upstream_add_chain", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "id", g_burp_upstream_chain_id);
    }
    void test_tool_burp_upstream_remove_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_upstream_chain_id;
        test_tool_call(hf, "mcp.burp_upstream_remove_chain", get_server(), "burp_upstream_remove_chain", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_list_chains(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_upstream_list_chains", get_server(), "burp_upstream_list_chains", {}, passed, failed, skipped);
    }
    void test_tool_burp_upstream_set_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_upstream_chain_id;
        test_tool_call(hf, "mcp.burp_upstream_set_active", get_server(), "burp_upstream_set_active", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_get_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_upstream_get_active", get_server(), "burp_upstream_get_active", {}, passed, failed, skipped);
    }
    void test_tool_burp_upstream_test_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_upstream_chain_id; args["target_host"] = "127.0.0.1"; args["target_port"] = g_burp_http_fixture ? g_burp_http_fixture->port : 1;
        test_tool_call(hf, "mcp.burp_upstream_test_chain", get_server(), "burp_upstream_test_chain", args, passed, failed, skipped);
    }
    void test_tool_burp_tech_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = burp_fixture_url(hf, "mcp.burp_tech_fingerprint");
        test_tool_call(hf, "mcp.burp_tech_fingerprint", get_server(), "burp_tech_fingerprint", args, passed, failed, skipped);
    }
    void test_tool_burp_tech_inventory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_tech_inventory", get_server(), "burp_tech_inventory", {}, passed, failed, skipped);
    }
    void test_tool_burp_tech_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_tech_clear", get_server(), "burp_tech_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_browser_launch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_browser_launch", get_server(), "burp_browser_launch", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            json_u64_field(result.data, "pid", g_burp_browser_pid);
            log_msg(hf, "mcp.burp_browser_launch", "INFO -- captured browser pid=%llu",
                static_cast<unsigned long long>(g_burp_browser_pid));
        }
    }
    void test_tool_burp_browser_kill(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        if (g_burp_browser_pid == 0) {
            log_msg(hf, "mcp.burp_browser_kill", "FAIL -- burp_browser_launch did not provide a pid for kill validation");
            record_fixture_failed_tool("burp_browser_kill", failed);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = g_burp_browser_pid;
        auto status = test_tool_call(hf, "mcp.burp_browser_kill", get_server(), "burp_browser_kill", args, passed, failed, skipped);
        if (status == mcp_tool_call_status_t::passed)
            g_burp_browser_pid = 0;
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
        mcp_standalone::json args; args["headless"] = false;
        test_tool_call(hf, "mcp.burp_headless_start", get_server(), "burp_headless_start", args, passed, failed, skipped, false);
    }
    void test_tool_burp_headless_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_stop", get_server(), "burp_headless_stop", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_status", get_server(), "burp_headless_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_navigate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = burp_fixture_url(hf, "mcp.burp_headless_navigate");
        test_tool_call(hf, "mcp.burp_headless_navigate", get_server(), "burp_headless_navigate", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_reload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_reload", get_server(), "burp_headless_reload", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_evaluate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["expression"] = "document.title";
        test_tool_call(hf, "mcp.burp_headless_evaluate", get_server(), "burp_headless_evaluate", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_screenshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["output_path"] = temp_file_narrow("aida_mcp_headless.png");
        test_tool_call(hf, "mcp.burp_headless_screenshot", get_server(), "burp_headless_screenshot", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_snapshot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_headless_snapshot", get_server(), "burp_headless_snapshot", {}, passed, failed, skipped);
    }
    void test_tool_burp_headless_click(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["selector"] = "body";
        test_tool_call(hf, "mcp.burp_headless_click", get_server(), "burp_headless_click", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_type(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["selector"] = "#aida-input"; args["text"] = "test";
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
        mcp_standalone::json args; args["preset_name"] = "xhr";
        test_tool_call(hf, "mcp.burp_headless_inject_hook", get_server(), "burp_headless_inject_hook", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_hook_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["target"] = "XMLHttpRequest.prototype.send"; args["mode"] = "trace";
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
        mcp_standalone::json args; args["url"] = burp_fixture_url(hf, "mcp.burp_headless_view_quick_navigate");
        test_tool_call(hf, "mcp.burp_headless_view_quick_navigate", get_server(), "burp_headless_view_quick_navigate", args, passed, failed, skipped);
    }
    void test_tool_burp_headless_view_install(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["action"] = "ensure";
        test_tool_call(hf, "mcp.burp_headless_view_install", get_server(), "burp_headless_view_install", args, passed, failed, skipped, false);
    }
    bool collaborator_http_probe(HANDLE hf, const std::string& token) {
        if (token.empty())
            return false;
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, "mcp.burp_collaborator_probe", "WARN -- WSAStartup failed");
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET)
            return false;
        DWORD timeout = 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(8444);
        bool ok = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR;
        if (ok) {
            std::string req = "GET /" + token + " HTTP/1.1\r\nHost: " + token + ".aidacollab.local\r\nConnection: close\r\n\r\n";
            ok = send(s, req.data(), static_cast<int>(req.size()), 0) != SOCKET_ERROR;
            char buf[256];
            (void)recv(s, buf, sizeof(buf), 0);
        }
        closesocket(s);
        if (ok)
            Sleep(100);
        log_msg(hf, "mcp.burp_collaborator_probe", "%s -- token_len=%zu", ok ? "PASS" : "WARN", token.size());
        return ok;
    }
    void capture_collaborator_interaction_id(const mcp_standalone::tool_result_t& result) {
        if (!result.data.is_object() || !result.data.contains("interactions") || !result.data["interactions"].is_array())
            return;
        for (const auto& it : result.data["interactions"]) {
            uint64_t id = 0;
            if (json_u64_field(it, "id", id) && id != 0) {
                g_burp_collaborator_interaction_id = id;
                return;
            }
        }
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
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_collaborator_generate_token", get_server(), "burp_collaborator_generate_token", {}, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed && result.data.is_object() && result.data.contains("token") && result.data["token"].is_string()) {
            g_burp_collaborator_token = result.data["token"].get<std::string>();
            collaborator_http_probe(hf, g_burp_collaborator_token);
        }
    }
    void test_tool_burp_collaborator_poll(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        if (!g_burp_collaborator_token.empty())
            args["token"] = g_burp_collaborator_token;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_collaborator_poll", get_server(), "burp_collaborator_poll", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            capture_collaborator_interaction_id(result);
    }
    void test_tool_burp_collaborator_get_interaction(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_burp_collaborator_interaction_id == 0 && !g_burp_collaborator_token.empty()) {
            collaborator_http_probe(hf, g_burp_collaborator_token);
            mcp_standalone::json poll_args;
            poll_args["token"] = g_burp_collaborator_token;
            mcp_standalone::tool_result_t poll_result;
            auto poll_status = test_tool_call(hf, "mcp.burp_collaborator_poll_for_get", get_server(), "burp_collaborator_poll", poll_args, passed, failed, skipped, true, &poll_result);
            if (poll_status == mcp_tool_call_status_t::passed)
                capture_collaborator_interaction_id(poll_result);
        }
        mcp_standalone::json args; args["id"] = g_burp_collaborator_interaction_id;
        test_tool_call(hf, "mcp.burp_collaborator_get_interaction", get_server(), "burp_collaborator_get_interaction", args, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_clear", get_server(), "burp_collaborator_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_list_tokens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_collaborator_list_tokens", get_server(), "burp_collaborator_list_tokens", {}, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_start_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/"; args["extract_regex"] = "([A-Za-z0-9]{4,})"; args["target_count"] = 4; args["concurrency"] = 1;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_sequencer_start_collection", get_server(), "burp_sequencer_start_collection", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "collection_id", g_burp_sequencer_collection_id);
    }
    void test_tool_burp_sequencer_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_call(hf, "mcp.burp_sequencer_status", get_server(), "burp_sequencer_status", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_call(hf, "mcp.burp_sequencer_stop", get_server(), "burp_sequencer_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_samples(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_call(hf, "mcp.burp_sequencer_samples", get_server(), "burp_sequencer_samples", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_call(hf, "mcp.burp_sequencer_analyze", get_server(), "burp_sequencer_analyze", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_sequencer_list_collections", get_server(), "burp_sequencer_list_collections", {}, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_call(hf, "mcp.burp_sequencer_delete", get_server(), "burp_sequencer_delete", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_add_slot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["label"] = "aida_mcp_test_a"; args["data_text"] = "test data\nalpha\n";
        mcp_standalone::tool_result_t result_a;
        auto status_a = test_tool_call(hf, "mcp.burp_comparer_add_slot_a", get_server(), "burp_comparer_add_slot", args, passed, failed, skipped, true, &result_a);
        if (status_a == mcp_tool_call_status_t::passed) {
            if (!json_u64_field(result_a.data, "slot_id", g_burp_comparer_slot_a))
                json_u64_field(result_a.data, "id", g_burp_comparer_slot_a);
        }
        args["label"] = "aida_mcp_test_b"; args["data_text"] = "test data\nbeta\n";
        mcp_standalone::tool_result_t result_b;
        auto status_b = test_tool_call(hf, "mcp.burp_comparer_add_slot_b", get_server(), "burp_comparer_add_slot", args, passed, failed, skipped, true, &result_b);
        if (status_b == mcp_tool_call_status_t::passed) {
            if (!json_u64_field(result_b.data, "slot_id", g_burp_comparer_slot_b))
                json_u64_field(result_b.data, "id", g_burp_comparer_slot_b);
        }
    }
    void test_tool_burp_comparer_list_slots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_comparer_list_slots", get_server(), "burp_comparer_list_slots", {}, passed, failed, skipped);
    }
    void test_tool_burp_comparer_remove_slot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["slot_id"] = g_burp_comparer_slot_a;
        test_tool_call(hf, "mcp.burp_comparer_remove_slot", get_server(), "burp_comparer_remove_slot", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.burp_comparer_clear", get_server(), "burp_comparer_clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_comparer_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["slot_a"] = g_burp_comparer_slot_a; args["slot_b"] = g_burp_comparer_slot_b;
        test_tool_call(hf, "mcp.burp_comparer_diff", get_server(), "burp_comparer_diff", args, passed, failed, skipped);
    }

}

void phase_mcp_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    log_msg(hf, "mcp_phase", "=== MCP TOOL TESTS START (509 counted tests, AI/agent tools excluded from counters) ===");
    auto t0 = std::chrono::steady_clock::now();
    const int start_passed = passed.load(std::memory_order_acquire);
    const int start_failed = failed.load(std::memory_order_acquire);
    const int start_skipped = skipped.load(std::memory_order_acquire);

    g_invoked_tools.clear();
    g_tool_attempt_stats.clear();
    g_mcp_tool_sequence.store(0, std::memory_order_release);
    g_mcp_target_pid = driver_bridge::attached_pid();
    g_mcp_target_unavailable = (g_mcp_target_pid == 0);
    g_mcp_dbg_sw_addr = 0;
    g_mcp_debugger_bp_index = -1;
    g_mcp_deferred_action_id = 0;
    g_mcp_emulation_addr = 0;
    g_mcp_emulate_function_addr = 0;
    g_mcp_scanner_addr = 0;
    g_mcp_scanner_pointer_addr = 0;
    g_mcp_symbolic_deobf_addr = 0;
    g_autoresponder_rule_id = 0;
    g_burp_scanner_audit_id = 0;
    g_burp_scanner_issue_id = 0;
    g_burp_sitemap_exchange_id = 0;
    g_burp_crawler_id = 0;
    g_burp_content_discovery_id = 0;
    g_burp_subdomain_id = 0;
    g_burp_intruder_job_id = 0;
    g_burp_param_miner_job_id = 0;
    g_burp_jwt_crack_id = 0;
    g_burp_match_replace_rule_id = 0;
    g_burp_macro_id = 0;
    g_burp_session_rule_id = 0;
    g_burp_api_collection_id = 0;
    g_burp_ws_conn_id = 0;
    g_burp_upstream_chain_id = 0;
    g_burp_sequencer_collection_id = 0;
    g_burp_comparer_slot_a = 0;
    g_burp_comparer_slot_b = 0;
    g_burp_collaborator_interaction_id = 0;
    g_burp_browser_pid = 0;
    g_burp_collaborator_token.clear();
    g_burp_fixture_base_url.clear();
    g_burp_fixture_wordlist_path.clear();
    g_burp_http_fixture.reset();
    log_msg(hf, "mcp_phase", "target snapshot active_pid=%u", g_mcp_target_pid);

    if (!cancelled()) test_mcp_server_accessible(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_server_running(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_tool_count(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_enumerate_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_categorize_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_tool_schemas(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_duplicate_tool_names(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_jsonrpc_smoke(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_get_tool_descriptions(hf, passed, failed, skipped);

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
    if (!cancelled()) test_tool_scanner_undo(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_reset(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_add_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_freeze_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_get_address_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_remove_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_read_value(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_write_value(hf, passed, failed, skipped);
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

    if (!cancelled()) test_tool_sessions_open_file(hf, passed, failed, skipped);
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
    if (!cancelled()) test_network_pg_sniff_payload_serialization(hf, passed, failed, skipped);
    if (!cancelled()) test_network_hook_sidecar_plain_e2e(hf, passed, failed, skipped);
    if (!cancelled()) test_network_hook_sidecar_protected_e2e(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_firefox_profile_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_firefox_profile_prepare(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_firefox_profile_launch(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_burp_match_replace_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_test(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_run(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_update(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_import(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_list_collections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_get_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_send_request(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_audit_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_remove_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_introspect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_example(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_send(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_connect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_send_text(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_send_binary(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_send_raw(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_list_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_frames(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_clear_frames(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_disconnect(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_burp_upstream_list_chains(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_set_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_get_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_test_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_remove_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_fingerprint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_inventory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_launch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_kill(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_kill_all(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_browser_detect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_view_install(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_headless_start(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_burp_headless_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_generate_token(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_poll(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_get_interaction(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_list_tokens(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_start_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_samples(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_analyze(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_list_collections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_delete(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_add_slot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_list_slots(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_diff(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_remove_slot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_clear(hf, passed, failed, skipped);
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
    if (g_mcp_dbg_sw_addr != 0) {
        debugger_engine::clear_all_breakpoints();
        driver_bridge::free_memory(g_mcp_dbg_sw_addr);
        g_mcp_dbg_sw_addr = 0;
        g_mcp_debugger_bp_index = -1;
    }
    if (g_mcp_integrity_addr != 0) {
        driver_bridge::free_memory(g_mcp_integrity_addr);
        g_mcp_integrity_addr = 0;
    }
    if (g_mcp_emulation_addr != 0) {
        driver_bridge::free_memory(g_mcp_emulation_addr);
        g_mcp_emulation_addr = 0;
    }
    if (g_mcp_emulate_function_addr != 0) {
        driver_bridge::free_memory(g_mcp_emulate_function_addr);
        g_mcp_emulate_function_addr = 0;
    }
    if (g_mcp_scanner_pointer_addr != 0) {
        driver_bridge::free_memory(g_mcp_scanner_pointer_addr);
        g_mcp_scanner_pointer_addr = 0;
    }
    if (g_mcp_scanner_addr != 0) {
        driver_bridge::free_memory(g_mcp_scanner_addr);
        g_mcp_scanner_addr = 0;
    }
    g_burp_http_fixture.reset();
    g_burp_fixture_base_url.clear();
    g_burp_fixture_wordlist_path.clear();

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    const int delta_passed = passed.load(std::memory_order_acquire) - start_passed;
    const int delta_failed = failed.load(std::memory_order_acquire) - start_failed;
    const int delta_skipped = skipped.load(std::memory_order_acquire) - start_skipped;
    log_msg(hf, "mcp.phase_accounting", "registered_tool_records=%zu explicit_invocations=%zu pass_delta=%d fail_delta=%d skip_delta=%d",
        g_tool_attempt_stats.size(), g_invoked_tools.size(), delta_passed, delta_failed, delta_skipped);
    log_msg(hf, "mcp_phase", "=== MCP TOOL TESTS DONE (elapsed %lld ms) ===", (long long)ms);
}

}
