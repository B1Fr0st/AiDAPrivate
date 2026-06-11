#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#include "test_all_mcp.h"
#include "test_all_features.hpp"

#include "../mcp/mcp_standalone.hpp"
#include "../ai/standalone_chat.hpp"
#include "../analysis/decrypt_oracle.hpp"
#include "../analysis/fuzzer_engine.hpp"
#include "../analysis/integrity_hunter.hpp"
#include "../analysis/code_patcher.hpp"
#include "../analysis/struct_monitor.hpp"
#include "../analysis/symbol_store.hpp"
#include "../analysis/stealth_engine.hpp"
#include "../analysis/xref_db.hpp"
#include "../analysis/xref_engine.hpp"
#include "../debugger/debugger_engine.hpp"
#include "../debugger/page_guard_engine.hpp"
#include "../disasm/disasm_view.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../network/burp/issue.hpp"
#include "../network/burp/burp_events.hpp"
#include "../network/burp/camoufox_bridge.hpp"
#include "../network/burp/camoufox_install.hpp"
#include "../network/burp/passive_scanner.hpp"
#include "../network/burp/site_map.hpp"
#include "../network/burp/collaborator.hpp"
#include "../network/burp/crawler.hpp"
#include "../network/burp/subdomain_enum.hpp"
#include "../network/burp/content_discovery.hpp"
#include "../network/burp/intruder_engine.hpp"
#include "../network/burp/param_miner.hpp"
#include "../network/network_view.hpp"
#include "../network/packet_callstack.hpp"
#include "../network/tcp_stream_tracker.hpp"
#include "../tools/pre_encrypt_hook.hpp"
#include "../tools/standalone_tools_fwd.hpp"
#include "../infra/critical_work_queue.hpp"
#include "../infra/work_queue.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../scanner/crypto_scanner.hpp"
#include "../scanner/memory_scanner.hpp"
#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"
#include "test_lab_bounded_runner.hpp"

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
#include <exception>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <new>
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
    uint64_t g_mcp_fuzz_addr = 0;
    uint64_t g_mcp_fuzz_input_addr = 0;
    int g_mcp_debugger_bp_index = -1;
    uint64_t g_mcp_deferred_action_id = 0;
    bool g_mcp_deferred_action_resource_guarded = false;
    uint64_t g_mcp_live_monitor_addr = 0;
    uint64_t g_mcp_live_monitor_cmp_addr = 0;
    uint64_t g_mcp_scanner_addr = 0;
    uint64_t g_mcp_scanner_pointer_addr = 0;
    uint64_t g_mcp_symbolic_deobf_addr = 0;
    std::string g_mcp_debugger_trace_id;
    uint64_t g_mcp_patch_addr = 0;
    int g_mcp_patch_index = -1;
    int g_mcp_get_patches_fixture_index = -1;
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
    uint64_t g_burp_sequencer_target_count = 0;
    uint64_t g_burp_comparer_slot_a = 0;
    uint64_t g_burp_comparer_slot_b = 0;
    uint64_t g_burp_collaborator_interaction_id = 0;
    bool g_burp_dom_xss_browser_infra_failed = false;
    std::string g_burp_dom_xss_dependency_reason;
    std::string g_burp_collaborator_token;
    std::string g_burp_fixture_base_url;
    std::string g_burp_fixture_wordlist_path;
    std::string g_mcp_cert_thumbprint;
    bool g_mcp_cert_inject_validate_only = false;
    std::string g_mcp_session_binary_id;
    bool g_mcp_camoufox_bridge_ready_proven = false;
    uint64_t g_mcp_camoufox_bridge_generation = 0;
    std::string g_mcp_camoufox_bridge_block_reason;
    constexpr DWORD k_camoufox_testlab_launch_timeout_ms = 70000;
    constexpr long long k_camoufox_testlab_launch_watchdog_ms = 90000;
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

    std::string compact_text(std::string out, std::size_t cap);
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...);
    void record_fixture_failed_tool(const char* tool_name, std::atomic<int>& failed);
    mcp_standalone::server_t* get_server();
    void record_tool_status(const std::string& name, mcp_tool_call_status_t status);

    struct scoped_env_var_t {
        std::string name;
        std::string previous;
        bool had_previous = false;

        scoped_env_var_t(const char* key, const char* value) : name(key ? key : "") {
            if (name.empty())
                return;
            DWORD need = GetEnvironmentVariableA(name.c_str(), nullptr, 0);
            if (need > 0 && need < 32768) {
                previous.resize(need);
                DWORD got = GetEnvironmentVariableA(name.c_str(), previous.data(), need);
                if (got > 0 && got < need) {
                    previous.resize(got);
                    had_previous = true;
                } else {
                    previous.clear();
                }
            }
            SetEnvironmentVariableA(name.c_str(), value);
        }

        ~scoped_env_var_t() {
            if (name.empty())
                return;
            SetEnvironmentVariableA(name.c_str(), had_previous ? previous.c_str() : nullptr);
        }

        scoped_env_var_t(const scoped_env_var_t&) = delete;
        scoped_env_var_t& operator=(const scoped_env_var_t&) = delete;
    };

    struct scoped_camoufox_testlab_launch_t {
        scoped_env_var_t fast_probe;
        scoped_env_var_t timeout_ms;

        scoped_camoufox_testlab_launch_t()
            : fast_probe("AIDA_CAMOUFOX_TESTLAB_FAST_PROBE", "1"),
              timeout_ms("AIDA_CAMOUFOX_TESTLAB_LAUNCH_MS", "70000") {
        }
    };
    const mcp_standalone::tool_def_t* find_registered_tool(mcp_standalone::server_t* srv, const char* tool_name);

    bool browser_infrastructure_text(const std::string& text) {
        std::string s = lower_copy(text);
        return s.find("connection closed") != std::string::npos ||
               s.find("camoufox") != std::string::npos ||
               s.find("browser has been closed") != std::string::npos ||
               s.find("page has been closed") != std::string::npos ||
               s.find("target page, context or browser has been closed") != std::string::npos ||
               s.find("page crashed") != std::string::npos ||
               s.find("navigate failed") != std::string::npos ||
               s.find("add_init_script") != std::string::npos ||
               s.find("evaluate_js failed") != std::string::npos;
    }

    const char* camoufox_install_state_name(aida::burp::camoufox::install::install_state_t state) {
        using state_t = aida::burp::camoufox::install::install_state_t;
        switch (state) {
            case state_t::unknown: return "unknown";
            case state_t::checking: return "checking";
            case state_t::available: return "available";
            case state_t::missing_python: return "missing_python";
            case state_t::missing_module: return "missing_module";
            case state_t::missing_browser: return "missing_browser";
            case state_t::installing: return "installing";
            case state_t::install_failed: return "install_failed";
            case state_t::ok: return "ok";
        }
        return "unknown";
    }

    const char* camoufox_bridge_state_name(aida::burp::camoufox::bridge_state_t state) {
        using state_t = aida::burp::camoufox::bridge_state_t;
        switch (state) {
            case state_t::stopped: return "stopped";
            case state_t::starting: return "starting";
            case state_t::ready: return "ready";
            case state_t::error: return "error";
        }
        return "unknown";
    }

    aida::burp::camoufox::install::status_t bounded_camoufox_probe(HANDLE hf, const char* tag, DWORD timeout_ms, bool& completed) {
        static test_lab::bounded_runner_t runner(1);
        auto state = std::make_shared<aida::burp::camoufox::install::status_t>();
        const uint64_t t0 = GetTickCount64();
        log_msg(hf, tag, "CAMOUFOX-PROBE -- begin timeout_ms=%lu setup_disabled=1", static_cast<unsigned long>(timeout_ms));
        const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [state]() {
            *state = aida::burp::camoufox::install::probe();
        });
        const uint64_t elapsed = GetTickCount64() - t0;
        completed = result.status == test_lab::bounded_run_status_t::completed;
        if (completed) {
            log_msg(hf, tag, "CAMOUFOX-PROBE -- completed elapsed_ms=%llu state=%s message=%s python=%s module=%s browser=%s",
                static_cast<unsigned long long>(elapsed),
                camoufox_install_state_name(state->state),
                compact_text(state->last_message, 500).c_str(),
                state->python_path.empty() ? "<empty>" : state->python_path.c_str(),
                state->module_version.empty() ? "<empty>" : state->module_version.c_str(),
                state->browser_path.empty() ? "<empty>" : state->browser_path.c_str());
            return *state;
        }
        log_msg(hf, tag, "CAMOUFOX-PROBE -- failed elapsed_ms=%llu status=%d error=%s",
            static_cast<unsigned long long>(elapsed),
            static_cast<int>(result.status),
            result.error.empty() ? "<empty>" : result.error.c_str());
        return aida::burp::camoufox::install::get_status();
    }

    bool camoufox_install_status_ready(const aida::burp::camoufox::install::status_t& install_status) {
        using install_state_t = aida::burp::camoufox::install::install_state_t;
        return install_status.state == install_state_t::ok &&
               !install_status.python_path.empty() &&
               !install_status.module_version.empty() &&
               !install_status.browser_path.empty();
    }

    bool camoufox_dependencies_ready_for_test(HANDLE hf, const char* tag, std::string& reason) {
        bool probe_completed = false;
        constexpr DWORD probe_timeout_ms = 9000;
        auto install_status = bounded_camoufox_probe(hf, tag, probe_timeout_ms, probe_completed);
        auto bridge_status = aida::burp::camoufox::get_status();
        log_msg(hf, tag, "CAMOUFOX-SNAPSHOT -- probe_completed=%d install_state=%s install_msg=%s python=%s module=%s browser=%s bridge_state=%s child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d bridge_error=%s",
            probe_completed ? 1 : 0,
            camoufox_install_state_name(install_status.state),
            compact_text(install_status.last_message, 500).c_str(),
            install_status.python_path.empty() ? "<empty>" : install_status.python_path.c_str(),
            install_status.module_version.empty() ? "<empty>" : install_status.module_version.c_str(),
            install_status.browser_path.empty() ? "<empty>" : install_status.browser_path.c_str(),
            camoufox_bridge_state_name(bridge_status.state),
            bridge_status.child_pid,
            bridge_status.child_alive ? 1 : 0,
            bridge_status.browser_open ? 1 : 0,
            bridge_status.page_verified ? 1 : 0,
            bridge_status.cleanup_pending ? 1 : 0,
            compact_text(bridge_status.last_error, 500).c_str());
        if (!probe_completed || !camoufox_install_status_ready(install_status)) {
            reason = probe_completed
                ? std::string("Camoufox bundled runtime is not ready; Test Lab setup/download is disabled state=") + camoufox_install_state_name(install_status.state) +
                    " message=" + (install_status.last_message.empty() ? "<empty>" : install_status.last_message)
            : std::string("Camoufox dependency probe exceeded ") + std::to_string(probe_timeout_ms) + "ms; Test Lab setup/download is disabled";
            log_msg(hf, tag, "CAMOUFOX-FAST-FAIL -- setup_disabled=1 reason=%s", compact_text(reason, 900).c_str());
            return false;
        }
        reason.clear();
        return true;
    }

    bool record_camoufox_dependency_guard_pass(HANDLE hf, const char* tag, const char* tool_name, const std::string& reason, std::atomic<int>& passed, std::atomic<int>& failed) {
        (void)passed;
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        g_invoked_tools.insert(tool_name_s);
        const auto* tool = find_registered_tool(get_server(), tool_name);
        if (!tool) {
            log_msg(hf, tag, "FAIL -- Camoufox dependency guard tool \"%s\" is not registered", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        if (!tool->handler) {
            log_msg(hf, tag, "FAIL -- Camoufox dependency guard tool \"%s\" has no handler", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        log_msg(hf, tag, "FAIL -- \"%s\" could not be exercised because Camoufox dependencies are not ready: %s read_only=%d params=%zu",
            tool_name ? tool_name : "<null>",
            reason.empty() ? "<empty>" : compact_text(reason, 700).c_str(),
            tool->read_only ? 1 : 0,
            tool->params.size());
        record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
        return false;
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
            lowered.find("openai") != std::string::npos;
    }

    bool is_destructive_mcp_tool(const std::string& name) {
        static const std::set<std::string> exact = {
            "driver_call_function"
        };
        return exact.find(lower_copy(name)) != exact.end();
    }

    constexpr const char* k_test_lab_safe_fixture_flag = "__aida_test_safe_fixture";

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

        const uint32_t target_pid = g_mcp_target_pid;
        const DWORD started = GetTickCount();
        for (int attempt = 1; attempt <= 3; ++attempt) {
            const uint32_t current = driver_bridge::attached_pid();
            bool known = false;
            const auto attached = driver_bridge::attached_pids();
            for (auto p : attached) {
                if (p == target_pid) {
                    known = true;
                    break;
                }
            }

            uint32_t win32_code = 0;
            const bool win32_alive = process_alive_by_pid(target_pid, &win32_code);
            bool ok = current == target_pid;
            const char* method = ok ? "already_active" : "none";
            if (!ok && known) {
                method = "set_active";
                ok = driver_bridge::set_active_pid(target_pid);
            }
            if (!ok) {
                method = "attach_additional";
                ok = driver_bridge::attach_additional(target_pid);
                if (ok) {
                    method = "attach_additional_set_active";
                    ok = driver_bridge::set_active_pid(target_pid);
                }
            }
            if (!ok) {
                method = "attach";
                ok = driver_bridge::attach(target_pid);
            }

            const uint32_t now = driver_bridge::attached_pid();
            uint32_t bridge_code = 0;
            const bool bridge_alive = now == target_pid && driver_bridge::attached_process_alive(&bridge_code);
            log_msg(hf, tag, "%s -- restore MCP target attempt=%d pid=%u from_active=%u known=%d attached_count=%zu method=%s ok=%d now=%u win32_alive=%d win32_code=0x%08X bridge_alive=%d bridge_code=0x%08X status=\"%s\" last_error=\"%s\" elapsed_ms=%lu",
                (ok && bridge_alive) ? "INFO" : "WARN",
                attempt,
                target_pid,
                current,
                known ? 1 : 0,
                attached.size(),
                method,
                ok ? 1 : 0,
                now,
                win32_alive ? 1 : 0,
                win32_code,
                bridge_alive ? 1 : 0,
                bridge_code,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long>(GetTickCount() - started));
            if (ok && bridge_alive) {
                g_mcp_target_unavailable = false;
                return true;
            }
            Sleep(50);
        }
        return false;
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
            log_msg(hf, tag, "FAIL -- MCP target pid=%u is no longer alive (exit_code_or_err=0x%08X)",
                g_mcp_target_pid, exit_code);
        } else {
            g_mcp_target_unavailable = false;
        }
        return alive;
    }

    bool tool_may_change_target(const std::string& name) {
        static const std::set<std::string> names = {
            "sessions_manage"
        };
        return names.find(name) != names.end();
    }

    bool tool_uses_live_target(const std::string& name) {
        static const std::set<std::string> no_target_required = {
            "debugger_get_attached",
            "driver_enumerate_kernel_modules",
        };
        if (no_target_required.find(name) != no_target_required.end())
            return false;
        return name.rfind("driver_", 0) == 0 ||
            name.rfind("dbg_", 0) == 0 ||
            name.rfind("debugger_", 0) == 0 ||
            name.rfind("scanner_", 0) == 0 ||
            name.rfind("memory_", 0) == 0 ||
            name == "decompile_function" ||
            name == "scan_crypto_constants" ||
                        name == "generate_aob_signature" ||
            name == "reconstruct_struct" ||
            name == "fuzzer_manage" ||
            name == "auto_decrypt_strings" ||
            name == "hunt_integrity_checkers" ||
            name == "neutralize_integrity_node" ||
            name == "live_monitor_manage" ||
            name == "trace_execution_unicorn" ||
            name == "analyze_vm_handler" ||
            name == "emulate_multi_trace" ||
            name == "symbolic_execution" ||
            name == "taint_trace_register";
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

    bool json_u64_field_allow_zero(const mcp_standalone::json& j, const char* key, uint64_t& out) {
        if (!key || !j.is_object() || !j.contains(key))
            return false;
        const auto& v = j[key];
        if (v.is_number_unsigned()) {
            out = v.get<uint64_t>();
            return true;
        }
        if (v.is_number_integer()) {
            auto raw = v.get<int64_t>();
            if (raw >= 0) {
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

    bool json_u64_any_field_allow_zero(const mcp_standalone::json& j, uint64_t& out, std::initializer_list<const char*> keys) {
        if (!j.is_object())
            return false;
        for (const char* key : keys) {
            if (json_u64_field_allow_zero(j, key, out))
                return true;
        }
        return false;
    }

    bool json_string_field(const mcp_standalone::json& j, const char* key, std::string& out) {
        if (!key || !j.is_object() || !j.contains(key) || !j[key].is_string())
            return false;
        out = j[key].get<std::string>();
        return !out.empty();
    }

    bool json_string_any_field(const mcp_standalone::json& j, std::string& out, std::initializer_list<const char*> keys) {
        if (!j.is_object())
            return false;
        for (const char* key : keys) {
            if (json_string_field(j, key, out))
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
        test_all_features::write_full_test_log_line(hf, line.data(), line.size());
    }
    void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
        char ts[40]; format_timestamp(ts, sizeof(ts));
        char detail[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap); va_end(ap);
        std::string detail_s(detail);
        if (detail_s.rfind("SKIP --", 0) == 0)
            detail_s.replace(0, 7, "FAIL-PREREQ --");
        char line[1200];
        _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail_s.c_str());
        std::string s(line);
        write_log_file(hf, s);
        test_all_features::mirror_full_test_log_line(tag, detail_s.c_str(), s.c_str());
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

    mcp_standalone::json redact_json_for_log(const mcp_standalone::json& value, const std::string& key = {}, std::size_t depth = 0) {
        if (!key.empty() && sensitive_json_key(key))
            return redacted_json_value(value);
        if (depth >= 5) {
            if (value.is_array()) {
                mcp_standalone::json out = mcp_standalone::json::object();
                out["truncated"] = true;
                out["type"] = "array";
                out["items"] = static_cast<uint64_t>(value.size());
                return out;
            }
            if (value.is_object()) {
                mcp_standalone::json out = mcp_standalone::json::object();
                out["truncated"] = true;
                out["type"] = "object";
                out["keys"] = static_cast<uint64_t>(value.size());
                return out;
            }
        }
        if (value.is_object()) {
            auto out = mcp_standalone::json::object();
            std::size_t shown = 0;
            for (auto it = value.begin(); it != value.end(); ++it) {
                if (shown >= 24) {
                    out["__truncated_keys"] = static_cast<uint64_t>(value.size() - shown);
                    break;
                }
                out[it.key()] = redact_json_for_log(*it, it.key(), depth + 1);
                ++shown;
            }
            return out;
        }
        if (value.is_array()) {
            auto out = mcp_standalone::json::array();
            std::size_t shown = 0;
            for (const auto& item : value) {
                if (shown >= 16) {
                    mcp_standalone::json truncated = mcp_standalone::json::object();
                    truncated["__truncated_items"] = static_cast<uint64_t>(value.size() - shown);
                    out.push_back(std::move(truncated));
                    break;
                }
                out.push_back(redact_json_for_log(item, {}, depth + 1));
                ++shown;
            }
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

    bool mcp_tool_requires_live_camoufox_bridge(const std::string& name) {
        const std::string n = lower_copy(name);
        static const char* tools[] = {
            "web_search", "webfetch", "burp_dom_xss_manage",
            "browser_lifecycle", "browser_navigation", "browser_interaction",
            "browser_inspect", "browser_state", "browser_network", "browser_hooks",
            "browser_instrumentation", "get_console_logs", "scripts", "search_code",
            "compare_env", "verify_signer_offline", "analyze_cookie_sources"
        };
        for (const char* tool : tools) {
            if (n == tool)
                return true;
        }
        return false;
    }

    bool camoufox_live_bridge_status(const aida::burp::camoufox::bridge_status_t& st) {
        return st.state == aida::burp::camoufox::bridge_state_t::ready &&
               st.child_pid != 0 &&
               st.child_alive &&
               st.browser_open &&
               st.page_verified &&
               !st.cleanup_pending;
    }

    std::string camoufox_status_compact(const aida::burp::camoufox::bridge_status_t& st) {
        char buf[960];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            "state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d page_count=%u active_page_id=%s active_url_len=%zu calls=%llu errors=%llu last_launch_ms=%llu last_call_ms=%llu last_nav_ms=%llu last_cleanup_ms=%llu last_verified_ms=%llu err=%s",
            camoufox_bridge_state_name(st.state),
            static_cast<unsigned long long>(st.generation),
            st.child_pid,
            st.child_alive ? 1 : 0,
            st.browser_open ? 1 : 0,
            st.page_verified ? 1 : 0,
            st.cleanup_pending ? 1 : 0,
            st.page_count,
            st.active_page_id.empty() ? "<empty>" : st.active_page_id.c_str(),
            st.active_page_url.size(),
            static_cast<unsigned long long>(st.total_calls),
            static_cast<unsigned long long>(st.total_errors),
            static_cast<unsigned long long>(st.last_launch_ms),
            static_cast<unsigned long long>(st.last_call_ms),
            static_cast<unsigned long long>(st.last_nav_ms),
            static_cast<unsigned long long>(st.last_cleanup_ms),
            static_cast<unsigned long long>(st.last_verified_ms),
            compact_text(st.last_error, 420).c_str());
        return std::string(buf);
    }

    void log_camoufox_live_bridge_status(HANDLE hf, const char* tag, const char* phase, const aida::burp::camoufox::bridge_status_t& st) {
        log_msg(hf, tag, "CAMOUFOX-LIVE -- phase=%s live=%d %s",
            phase ? phase : "<null>",
            camoufox_live_bridge_status(st) ? 1 : 0,
            camoufox_status_compact(st).c_str());
    }

    struct camoufox_launch_attempt_result_t {
        bool completed = false;
        bool ok = false;
        aida::burp::camoufox::bridge_status_t status;
        std::string runner_error;
    };

    camoufox_launch_attempt_result_t bounded_camoufox_start_bridge(HANDLE hf, const char* tag, const aida::burp::camoufox::launch_config_t& cfg, DWORD timeout_ms) {
        static test_lab::bounded_runner_t runner(1);
        auto state = std::make_shared<camoufox_launch_attempt_result_t>();
        const uint64_t t0 = GetTickCount64();
        log_msg(hf, tag, "CAMOUFOX-LAUNCH -- begin session=%s headless=%d timeout_ms=%lu requested_launch_timeout_ms=%d trace=%d",
            cfg.session_id.empty() ? "default" : cfg.session_id.c_str(),
            cfg.headless ? 1 : 0,
            static_cast<unsigned long>(timeout_ms),
            cfg.launch_timeout_ms,
            cfg.enable_trace ? 1 : 0);
        const auto result = runner.run(static_cast<std::uint32_t>(timeout_ms), [state, cfg]() {
            state->ok = aida::burp::camoufox::start_bridge(cfg);
            state->status = aida::burp::camoufox::get_status();
        });
        const uint64_t elapsed = GetTickCount64() - t0;
        camoufox_launch_attempt_result_t out;
        if (result.status == test_lab::bounded_run_status_t::completed) {
            out = *state;
            out.completed = true;
        } else {
            out.completed = false;
            out.ok = false;
            out.status = aida::burp::camoufox::get_status();
            out.runner_error = result.error;
        }
        log_msg(hf, tag, "CAMOUFOX-LAUNCH -- end completed=%d runner_status=%d ok=%d elapsed_ms=%llu runner_error=%s %s",
            out.completed ? 1 : 0,
            static_cast<int>(result.status),
            out.ok ? 1 : 0,
            static_cast<unsigned long long>(elapsed),
            out.runner_error.empty() ? "<empty>" : compact_text(out.runner_error, 500).c_str(),
            camoufox_status_compact(out.status).c_str());
        return out;
    }

    bool wait_for_camoufox_live_status(HANDLE hf, const char* tag, DWORD timeout_ms, aida::burp::camoufox::bridge_status_t& out_status) {
        const uint64_t t0 = GetTickCount64();
        uint64_t last_log = 0;
        for (;;) {
            out_status = aida::burp::camoufox::get_status();
            if (camoufox_live_bridge_status(out_status)) {
                log_msg(hf, tag, "CAMOUFOX-WAIT -- ready elapsed_ms=%llu %s",
                    static_cast<unsigned long long>(GetTickCount64() - t0),
                    camoufox_status_compact(out_status).c_str());
                return true;
            }
            const uint64_t elapsed = GetTickCount64() - t0;
            if (elapsed >= timeout_ms)
                break;
            if (elapsed - last_log >= 1000) {
                last_log = elapsed;
                log_msg(hf, tag, "CAMOUFOX-WAIT -- pending elapsed_ms=%llu timeout_ms=%lu %s",
                    static_cast<unsigned long long>(elapsed),
                    static_cast<unsigned long>(timeout_ms),
                    camoufox_status_compact(out_status).c_str());
            }
            Sleep(100);
        }
        log_msg(hf, tag, "CAMOUFOX-WAIT -- timeout timeout_ms=%lu %s",
            static_cast<unsigned long>(timeout_ms),
            camoufox_status_compact(out_status).c_str());
        return false;
    }

    bool prove_camoufox_live_bridge(HANDLE hf, const char* tag, const char* owner, std::string& reason) {
        reason.clear();
        aida::burp::camoufox::bridge_status_t st;
        if (!wait_for_camoufox_live_status(hf, tag, 12000, st)) {
            reason = std::string("Camoufox bridge did not reach live ready status for ") + (owner ? owner : "<unknown>") + ": " + camoufox_status_compact(st);
            return false;
        }
        log_camoufox_live_bridge_status(hf, tag, "proof_status_ready", st);

        const auto list_result = aida::burp::camoufox::call_tool("list_pages", mcp_standalone::json::object(), 15000);
        log_msg(hf, tag, "CAMOUFOX-PROOF -- owner=%s step=list_pages ok=%d text_len=%zu data_type=%s error=%s data=%s",
            owner ? owner : "<unknown>",
            list_result.ok ? 1 : 0,
            list_result.text.size(),
            list_result.data.type_name(),
            list_result.error.empty() ? "<empty>" : compact_text(list_result.error, 500).c_str(),
            compact_json(list_result.data, 900).c_str());
        if (!list_result.ok) {
            reason = std::string("Camoufox list_pages proof failed for ") + (owner ? owner : "<unknown>") + ": " +
                (list_result.error.empty() ? compact_text(list_result.text, 500) : compact_text(list_result.error, 500));
            return false;
        }

        mcp_standalone::json eval_args;
        eval_args["expression"] = "(()=>({aida_probe:'ready',href:location.href,title:document.title,readyState:document.readyState}))()";
        eval_args["await_promise"] = true;
        const auto eval_result = aida::burp::camoufox::call_tool("evaluate_js", eval_args, 15000);
        log_msg(hf, tag, "CAMOUFOX-PROOF -- owner=%s step=evaluate_js ok=%d text_len=%zu data_type=%s error=%s data=%s",
            owner ? owner : "<unknown>",
            eval_result.ok ? 1 : 0,
            eval_result.text.size(),
            eval_result.data.type_name(),
            eval_result.error.empty() ? "<empty>" : compact_text(eval_result.error, 500).c_str(),
            compact_json(eval_result.data, 900).c_str());
        if (!eval_result.ok) {
            reason = std::string("Camoufox evaluate_js proof failed for ") + (owner ? owner : "<unknown>") + ": " +
                (eval_result.error.empty() ? compact_text(eval_result.text, 500) : compact_text(eval_result.error, 500));
            return false;
        }

        st = aida::burp::camoufox::get_status();
        if (!camoufox_live_bridge_status(st)) {
            reason = std::string("Camoufox bridge lost live ready status after proof for ") + (owner ? owner : "<unknown>") + ": " + camoufox_status_compact(st);
            log_camoufox_live_bridge_status(hf, tag, "proof_status_lost", st);
            return false;
        }
        g_mcp_camoufox_bridge_ready_proven = true;
        g_mcp_camoufox_bridge_generation = st.generation;
        g_mcp_camoufox_bridge_block_reason.clear();
        log_msg(hf, tag, "CAMOUFOX-PROOF -- owner=%s complete generation=%llu child_pid=%u page_count=%u active_url_len=%zu",
            owner ? owner : "<unknown>",
            static_cast<unsigned long long>(st.generation),
            st.child_pid,
            st.page_count,
            st.active_page_url.size());
        return true;
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

    std::size_t json_array_size_field(const mcp_standalone::json& j, const char* key) {
        if (!key || !j.is_object() || !j.contains(key) || !j[key].is_array())
            return 0;
        return j[key].size();
    }

    bool json_array_contains_u64_field(const mcp_standalone::json& j, const char* array_key, uint64_t needle,
                                       std::initializer_list<const char*> keys) {
        if (!array_key || !j.is_object() || !j.contains(array_key) || !j[array_key].is_array())
            return false;
        for (const auto& item : j[array_key]) {
            uint64_t value = 0;
            if (json_u64_any_field_allow_zero(item, value, keys) && value == needle)
                return true;
        }
        return false;
    }

    bool json_array_contains_string_field(const mcp_standalone::json& j, const char* array_key, const std::string& needle,
                                          std::initializer_list<const char*> keys) {
        if (needle.empty() || !array_key || !j.is_object() || !j.contains(array_key) || !j[array_key].is_array())
            return false;
        for (const auto& item : j[array_key]) {
            std::string value;
            if (json_string_any_field(item, value, keys) && value == needle)
                return true;
        }
        return false;
    }

    uint64_t json_count_or_array_size(const mcp_standalone::json& j, const char* count_key, const char* array_key) {
        uint64_t count = 0;
        if (json_u64_field_allow_zero(j, count_key, count))
            return count;
        return static_cast<uint64_t>(json_array_size_field(j, array_key));
    }

    void log_tool_result_payload(HANDLE hf, const char* tag, const char* phase, const mcp_standalone::tool_result_t& result) {
        log_msg(hf, tag, "%s -- success=%d text_len=%zu data_type=%s text=%s data=%s",
            phase,
            result.success ? 1 : 0,
            result.text.size(),
            result.data.type_name(),
            compact_text(result.text, 700).c_str(),
            compact_json(result.data, 900).c_str());
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

    const char* tool_visibility_name(mcp_standalone::tool_visibility_t visibility) {
        switch (visibility) {
            case mcp_standalone::tool_visibility_t::external_visible: return "external";
            case mcp_standalone::tool_visibility_t::internal_only: return "internal";
            case mcp_standalone::tool_visibility_t::ide_chat_only: return "ide_chat_only";
            default: return "unknown";
        }
    }

    bool json_payload_empty(const mcp_standalone::json& data) {
        return data.is_null() ||
            (data.is_object() && data.empty()) ||
            (data.is_array() && data.empty());
    }

    std::string mcp_tool_domain(const std::string& tool_name) {
        const std::string name = lower_copy(tool_name);
        static const std::set<std::string> camoufox_tools = {
            "browser_lifecycle", "browser_navigation", "browser_interaction", "browser_inspect",
            "browser_state", "browser_network", "browser_hooks", "browser_instrumentation",
            "get_console_logs", "scripts", "search_code", "compare_env",
            "verify_signer_offline", "analyze_cookie_sources",
        };
        if (name.rfind("burp_", 0) == 0)
            return "burp";
        if (camoufox_tools.find(name) != camoufox_tools.end() || name.rfind("camoufox_", 0) == 0)
            return "camoufox";
        if (name.rfind("driver_", 0) == 0)
            return "driver";
        if (name.rfind("debugger_", 0) == 0 || name.rfind("dbg_", 0) == 0)
            return "debugger";
        if (name.rfind("network_", 0) == 0 || name == "mitm_status")
            return "network";
        if (name.rfind("scanner_", 0) == 0 || name.rfind("memory_", 0) == 0)
            return "scanner";
        if (name.rfind("analysis_", 0) == 0 || name.rfind("disasm_", 0) == 0 ||
            name.find("decompile") != std::string::npos)
            return "analysis";
        if (name.rfind("tls_", 0) == 0 || name.rfind("cert_", 0) == 0 ||
            name.rfind("quic_", 0) == 0 || name.rfind("dtls_", 0) == 0 ||
            name.rfind("pin_", 0) == 0 || name.rfind("firefox_", 0) == 0)
            return "crypto-network";
        if (name.rfind("sandbox_", 0) == 0 ||
            name.rfind("sessions_", 0) == 0)
            return "runtime";
        if (name.find("file") != std::string::npos || name.find("directory") != std::string::npos ||
            name == "web_search" || name == "webfetch" || name == "get_working_directory")
            return "internal-io";
        return "standalone";
    }

    std::string mcp_payload_summary(const mcp_standalone::json& data) {
        std::ostringstream oss;
        if (data.is_null()) {
            oss << "null";
        } else if (data.is_array()) {
            oss << "array size=" << data.size();
            if (!data.empty())
                oss << " first_type=" << data.front().type_name();
        } else if (data.is_object()) {
            oss << "object keys=" << data.size() << " {";
            std::size_t shown = 0;
            for (auto it = data.begin(); it != data.end() && shown < 14; ++it, ++shown) {
                if (shown)
                    oss << ',';
                oss << it.key() << '=';
                const auto& v = *it;
                if (v.is_array())
                    oss << "array[" << v.size() << "]";
                else if (v.is_object())
                    oss << "object[" << v.size() << "]";
                else if (v.is_string())
                    oss << "string(len=" << v.get<std::string>().size() << ")";
                else if (v.is_boolean())
                    oss << "bool(" << (v.get<bool>() ? "true" : "false") << ")";
                else if (v.is_number_unsigned())
                    oss << "u64(" << v.get<uint64_t>() << ")";
                else if (v.is_number_integer())
                    oss << "i64(" << v.get<int64_t>() << ")";
                else if (v.is_number_float())
                    oss << "number";
                else if (v.is_null())
                    oss << "null";
                else
                    oss << v.type_name();
            }
            if (data.size() > shown)
                oss << ",...";
            oss << '}';
        } else {
            oss << data.type_name();
        }
        return compact_text(oss.str(), 520);
    }

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
        const std::string domain = mcp_tool_domain(tool_name);
        const std::string payload_summary = sensitive_tool ?
            "<redacted payload summary type=" + std::string(ir.data.type_name()) + ">" :
            mcp_payload_summary(ir.data);
        diag::log_tagged_fmt("mcp_result_detail",
            "phase=%s seq=%d domain=%s tool=%s elapsed_ms=%lld found=%d success=%d threw=%d reason=%s text_len=%zu data_type=%s data_empty=%d payload_summary=%s args=%s text=%s exception=%s data=%s",
            phase ? phase : "",
            seq,
            domain.c_str(),
            tool_name.c_str(),
            elapsed_ms,
            ir.found ? 1 : 0,
            ir.success ? 1 : 0,
            ir.threw ? 1 : 0,
            reason_preview.c_str(),
            ir.text.size(),
            ir.data.type_name(),
            json_payload_empty(ir.data) ? 1 : 0,
            payload_summary.c_str(),
            args_preview.c_str(),
            text_preview.c_str(),
            ex_preview.c_str(),
            data_preview.c_str());
    }

    void log_mcp_timeout_detail(int seq,
                                const std::string& tool_name,
                                const mcp_standalone::json& args,
                                long long elapsed_ms,
                                bool worker_started,
                                long long queue_delay_ms) {
        const std::string args_preview = compact_json(args, 900);
        const std::string domain = mcp_tool_domain(tool_name);
        diag::log_tagged_fmt("mcp_result_detail",
            "phase=timeout seq=%d domain=%s tool=%s elapsed_ms=%lld worker_started=%d queue_delay_ms=%lld args=%s",
            seq,
            domain.c_str(),
            tool_name.c_str(),
            elapsed_ms,
            worker_started ? 1 : 0,
            queue_delay_ms,
            args_preview.c_str());
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

    void convert_tool_pass_to_fail(const std::string& name) {
        if (name.empty())
            return;
        auto& stats = g_tool_attempt_stats[name];
        if (stats.passed > 0)
            --stats.passed;
        ++stats.failed;
    }

    void convert_tool_fail_to_pass(const std::string& name) {
        if (name.empty())
            return;
        auto& stats = g_tool_attempt_stats[name];
        if (stats.failed > 0)
            --stats.failed;
        ++stats.passed;
    }

    void record_precondition_skipped_tool(const char* tool_name, std::atomic<int>& skipped) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        if (!tool_name_s.empty()) {
            g_invoked_tools.insert(tool_name_s);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
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

    void record_camoufox_bridge_blocked_tool(HANDLE hf, const char* tag, const char* tool_name, const std::string& reason, std::atomic<int>& failed) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        if (tool_name_s.empty()) {
            failed.fetch_add(1);
            return;
        }
        g_invoked_tools.insert(tool_name_s);
        const auto* tool = find_registered_tool(get_server(), tool_name);
        const auto st = aida::burp::camoufox::get_status();
        if (!tool) {
            log_msg(hf, tag, "FAIL -- Camoufox browser tool \"%s\" is not registered while bridge was blocked reason=%s %s",
                tool_name_s.c_str(),
                reason.empty() ? "<empty>" : compact_text(reason, 900).c_str(),
                camoufox_status_compact(st).c_str());
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        if (!tool->handler) {
            log_msg(hf, tag, "FAIL -- Camoufox browser tool \"%s\" has no handler while bridge was blocked reason=%s %s",
                tool_name_s.c_str(),
                reason.empty() ? "<empty>" : compact_text(reason, 900).c_str(),
                camoufox_status_compact(st).c_str());
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "BLOCKED-FAIL -- \"%s\" not dispatched because Camoufox live bridge was not proven reason=%s read_only=%d visibility=%s params=%zu %s",
            tool_name_s.c_str(),
            reason.empty() ? "<empty>" : compact_text(reason, 900).c_str(),
            tool->read_only ? 1 : 0,
            tool_visibility_name(tool->visibility),
            tool->params.size(),
            camoufox_status_compact(st).c_str());
        record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    bool ensure_mcp_camoufox_bridge_ready_for_tool(HANDLE hf, const char* tag, const char* tool_name, std::atomic<int>& failed, std::string* out_reason = nullptr) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        std::string reason;
        auto st = aida::burp::camoufox::get_status();
        log_camoufox_live_bridge_status(hf, tag, "preflight_entry", st);

        if (!g_mcp_camoufox_bridge_ready_proven &&
            !g_mcp_camoufox_bridge_block_reason.empty() &&
            !camoufox_live_bridge_status(st)) {
            reason = std::string("previous Camoufox live bridge proof failed: ") + g_mcp_camoufox_bridge_block_reason +
                "; current " + camoufox_status_compact(st);
            if (out_reason)
                *out_reason = reason;
            record_camoufox_bridge_blocked_tool(hf, tag, tool_name, reason, failed);
            return false;
        }

        if (g_mcp_camoufox_bridge_ready_proven && camoufox_live_bridge_status(st) &&
            (g_mcp_camoufox_bridge_generation == 0 || g_mcp_camoufox_bridge_generation == st.generation)) {
            log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- cached live bridge accepted tool=%s generation=%llu child_pid=%u",
                tool_name_s.empty() ? "<empty>" : tool_name_s.c_str(),
                static_cast<unsigned long long>(st.generation),
                st.child_pid);
            if (out_reason)
                out_reason->clear();
            return true;
        }

        std::string dependency_reason;
        if (!camoufox_dependencies_ready_for_test(hf, tag, dependency_reason)) {
            reason = dependency_reason.empty() ? std::string("Camoufox dependencies are not ready") : dependency_reason;
            g_mcp_camoufox_bridge_ready_proven = false;
            g_mcp_camoufox_bridge_block_reason = reason;
            if (out_reason)
                *out_reason = reason;
            record_camoufox_bridge_blocked_tool(hf, tag, tool_name, reason, failed);
            return false;
        }

        st = aida::burp::camoufox::get_status();
        if (!camoufox_live_bridge_status(st)) {
            if (st.cleanup_pending) {
                const bool idle = aida::burp::camoufox::wait_until_idle(7000, "testlab.camoufox.preflight_cleanup_wait");
                auto after_idle = aida::burp::camoufox::get_status();
                log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- cleanup wait idle=%d before=%s after=%s",
                    idle ? 1 : 0,
                    camoufox_status_compact(st).c_str(),
                    camoufox_status_compact(after_idle).c_str());
                st = after_idle;
            }
        }

        if (!camoufox_live_bridge_status(st)) {
            for (int attempt = 1; attempt <= 1; ++attempt) {
                aida::burp::camoufox::launch_config_t cfg;
                cfg.headless = false;
                cfg.launch_timeout_ms = static_cast<int>(k_camoufox_testlab_launch_timeout_ms);
                cfg.window_width = 1280;
                cfg.window_height = 900;
                cfg.enable_trace = false;
                cfg.testlab_fast_probe = true;
                const DWORD runner_timeout = static_cast<DWORD>(cfg.launch_timeout_ms + 8000);
                auto launch = bounded_camoufox_start_bridge(hf, tag, cfg, runner_timeout);
                st = launch.status;
                if (launch.completed && launch.ok && camoufox_live_bridge_status(st))
                    break;
                reason = launch.completed
                    ? std::string("Camoufox bridge launch did not produce live ready state for ") + tool_name_s + ": " + camoufox_status_compact(st)
                    : std::string("Camoufox bridge launch runner did not complete for ") + tool_name_s + " status=" + camoufox_status_compact(st);
                if (attempt == 1) {
                    const bool stopped = aida::burp::camoufox::stop_bridge("testlab.camoufox.preflight_retry");
                    auto stopped_status = aida::burp::camoufox::get_status();
                    log_msg(hf, tag, "CAMOUFOX-PREFLIGHT -- retry cleanup stopped=%d %s",
                        stopped ? 1 : 0,
                        camoufox_status_compact(stopped_status).c_str());
                    Sleep(500);
                }
            }
        }

        if (!prove_camoufox_live_bridge(hf, tag, tool_name, reason)) {
            g_mcp_camoufox_bridge_ready_proven = false;
            g_mcp_camoufox_bridge_block_reason = reason;
            if (out_reason)
                *out_reason = reason;
            record_camoufox_bridge_blocked_tool(hf, tag, tool_name, reason, failed);
            return false;
        }

        if (out_reason)
            out_reason->clear();
        return true;
    }

    std::filesystem::path mcp_scratch_workspace_root() {
        char tmp[MAX_PATH] = {};
        DWORD n = GetTempPathA(static_cast<DWORD>(sizeof(tmp)), tmp);
        std::filesystem::path base = (n > 0 && n < sizeof(tmp)) ? std::filesystem::path(tmp) : std::filesystem::temp_directory_path();
        return base / ("aida_mcp_testlab_workspace_" + std::to_string(GetCurrentProcessId()));
    }

    bool write_text_fixture(const std::filesystem::path& path, const std::string& text) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec)
            return false;
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs)
            return false;
        ofs << text;
        return ofs.good();
    }

    struct scoped_mcp_workspace_t {
        std::string old_current_dir;
        std::string old_workspace_root;
        std::filesystem::path root;
        bool active = false;

        scoped_mcp_workspace_t(HANDLE hf, const char* tag) {
            old_current_dir = file_browser::current_dir;
            old_workspace_root = g_sa_settings.workspace.root_path;
            root = mcp_scratch_workspace_root();
            std::error_code ec;
            std::filesystem::create_directories(root, ec);
            if (ec) {
                log_msg(hf, tag, "FAIL -- scratch workspace create failed path=%s err=%lu",
                    root.string().c_str(), static_cast<unsigned long>(ec.value()));
                return;
            }
            file_browser::current_dir = root.string();
            g_sa_settings.workspace.root_path = root.string();
            active = true;
            log_msg(hf, tag, "INFO -- scratch workspace active path=%s", file_browser::current_dir.c_str());
        }

        ~scoped_mcp_workspace_t() {
            if (active) {
                file_browser::current_dir = old_current_dir;
                g_sa_settings.workspace.root_path = old_workspace_root;
            }
        }
    };

    bool ensure_mcp_private_bytes(HANDLE hf, const char* tag, uint64_t& addr, size_t size, const std::vector<uint8_t>& bytes) {
        if (!ensure_mcp_target_live(hf, tag))
            return false;
        const uint32_t active_before_alloc = driver_bridge::attached_pid();
        const uint32_t fixture_pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : active_before_alloc;
        const DWORD fixture_start = GetTickCount();
        if (fixture_pid == 0) {
            log_msg(hf, tag, "SKIP -- MCP fixture target pid unavailable size=%zu requested_bytes=%zu active_pid=%u target_pid=%u",
                size,
                bytes.size(),
                active_before_alloc,
                g_mcp_target_pid);
            return false;
        }
        if (addr == 0) {
            addr = driver_bridge::allocate_memory(size);
            if (addr == 0) {
                log_msg(hf, tag, "SKIP -- allocate_memory failed for MCP fixture pid=%u size=%zu active_pid=%u target_pid=%u status=\"%s\" last_error=\"%s\" elapsed_ms=%lu",
                    fixture_pid,
                    size,
                    driver_bridge::attached_pid(),
                    g_mcp_target_pid,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str(),
                    static_cast<unsigned long>(GetTickCount() - fixture_start));
                return false;
            }
            log_msg(hf, tag, "FIXTURE -- allocated addr=0x%016llX size=%zu active_before=%u active_after=%u target_pid=%u fixture_pid=%u elapsed_ms=%lu",
                static_cast<unsigned long long>(addr),
                size,
                active_before_alloc,
                driver_bridge::attached_pid(),
                g_mcp_target_pid,
                fixture_pid,
                static_cast<unsigned long>(GetTickCount() - fixture_start));
        }
        if (driver_bridge::attached_pid() != g_mcp_target_pid && !restore_mcp_target(hf, tag)) {
            log_msg(hf, tag, "SKIP -- unable to restore MCP target before fixture write active_pid=%u target_pid=%u",
                driver_bridge::attached_pid(), g_mcp_target_pid);
            return false;
        }
        uint32_t old_protect = 0;
        const bool protect_ok = driver_bridge::protect_memory_for(fixture_pid, addr, size, PAGE_EXECUTE_READWRITE, &old_protect);
        log_msg(hf, tag, "FIXTURE -- protect addr=0x%016llX size=%zu ok=%d old=0x%08X active_pid=%u target_pid=%u fixture_pid=%u status=\"%s\" last_error=\"%s\" elapsed_ms=%lu",
            static_cast<unsigned long long>(addr),
            size,
            protect_ok ? 1 : 0,
            old_protect,
            driver_bridge::attached_pid(),
            g_mcp_target_pid,
            fixture_pid,
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            static_cast<unsigned long>(GetTickCount() - fixture_start));
        if (driver_bridge::attached_pid() != g_mcp_target_pid && !restore_mcp_target(hf, tag)) {
            log_msg(hf, tag, "SKIP -- unable to restore MCP target after fixture protect active_pid=%u target_pid=%u",
                driver_bridge::attached_pid(), g_mcp_target_pid);
            driver_bridge::free_memory(addr);
            addr = 0;
            return false;
        }
        if (!bytes.empty() && !driver_bridge::write_memory_for(fixture_pid, addr, bytes)) {
            log_msg(hf, tag, "SKIP -- write_memory failed for MCP fixture addr=0x%016llX bytes=%zu active_pid=%u target_pid=%u fixture_pid=%u status=\"%s\" last_error=\"%s\" elapsed_ms=%lu",
                static_cast<unsigned long long>(addr),
                bytes.size(),
                driver_bridge::attached_pid(),
                g_mcp_target_pid,
                fixture_pid,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str(),
                static_cast<unsigned long>(GetTickCount() - fixture_start));
            driver_bridge::free_memory(addr);
            addr = 0;
            return false;
        }
        if (driver_bridge::attached_pid() != g_mcp_target_pid && !restore_mcp_target(hf, tag)) {
            log_msg(hf, tag, "SKIP -- unable to restore MCP target before fixture readback active_pid=%u target_pid=%u",
                driver_bridge::attached_pid(), g_mcp_target_pid);
            driver_bridge::free_memory(addr);
            addr = 0;
            return false;
        }
        if (!bytes.empty()) {
            std::vector<uint8_t> verify;
            const bool read_ok = driver_bridge::read_memory_for(fixture_pid, addr, bytes.size(), verify);
            const bool match = read_ok &&
                verify.size() >= bytes.size() &&
                std::equal(bytes.begin(), bytes.end(), verify.begin());
            if (!match) {
                log_msg(hf, tag, "SKIP -- MCP fixture readback mismatch addr=0x%016llX wrote=%zu read_ok=%d read=%zu active_pid=%u target_pid=%u fixture_pid=%u status=\"%s\" last_error=\"%s\" elapsed_ms=%lu expected=[%s] actual=[%s]",
                    static_cast<unsigned long long>(addr),
                    bytes.size(),
                    read_ok ? 1 : 0,
                    verify.size(),
                    driver_bridge::attached_pid(),
                    g_mcp_target_pid,
                    fixture_pid,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str(),
                    static_cast<unsigned long>(GetTickCount() - fixture_start),
                    hex_preview(bytes).c_str(),
                    hex_preview(verify).c_str());
                driver_bridge::free_memory(addr);
                addr = 0;
                return false;
            }
        }
        return true;
    }

    bool ensure_mcp_private_patch_fixture(HANDLE hf, const char* tag) {
        std::vector<uint8_t> bytes(64, 0x90);
        bytes[0] = 0x48;
        bytes[1] = 0x31;
        bytes[2] = 0xC0;
        bytes[3] = 0xC3;
        return ensure_mcp_private_bytes(hf, tag, g_mcp_patch_addr, bytes.size(), bytes);
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
            auto validate_only_it = obj.find("validate_only");
            if (validate_only_it != obj.end() && validate_only_it->is_boolean() && validate_only_it->get<bool>())
                return false;
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

    bool bounded_text_contains_lc(const std::string& text, const std::string& needle_lc, std::size_t& chars_left) {
        if (needle_lc.empty())
            return true;
        if (chars_left == 0 || text.empty())
            return false;
        const std::size_t scan_len = (std::min)(text.size(), chars_left);
        chars_left -= scan_len;
        if (scan_len < needle_lc.size())
            return false;
        for (std::size_t i = 0; i + needle_lc.size() <= scan_len; ++i) {
            bool match = true;
            for (std::size_t j = 0; j < needle_lc.size(); ++j) {
                const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(text[i + j])));
                if (c != needle_lc[j]) {
                    match = false;
                    break;
                }
            }
            if (match)
                return true;
        }
        return false;
    }

    bool json_text_contains_lc_bounded(const mcp_standalone::json& value,
                                       const std::string& needle_lc,
                                       std::size_t& nodes_left,
                                       std::size_t& chars_left) {
        if (nodes_left == 0 || chars_left == 0)
            return false;
        --nodes_left;
        try {
            if (value.is_string()) {
                return bounded_text_contains_lc(value.get<std::string>(), needle_lc, chars_left);
            }
            if (value.is_object()) {
                for (auto it = value.begin(); it != value.end(); ++it) {
                    if (bounded_text_contains_lc(it.key(), needle_lc, chars_left))
                        return true;
                    if (json_text_contains_lc_bounded(*it, needle_lc, nodes_left, chars_left))
                        return true;
                    if (nodes_left == 0 || chars_left == 0)
                        return false;
                }
            } else if (value.is_array()) {
                for (const auto& item : value) {
                    if (json_text_contains_lc_bounded(item, needle_lc, nodes_left, chars_left))
                        return true;
                    if (nodes_left == 0 || chars_left == 0)
                        return false;
                }
            }
        } catch (...) {
        }
        return false;
    }

    bool payload_text_contains(const invoke_result_t& ir, const std::string& needle_lc) {
        std::size_t text_budget = 262144;
        if (bounded_text_contains_lc(ir.text, needle_lc, text_budget))
            return true;
        std::size_t nodes_left = 8192;
        return json_text_contains_lc_bounded(ir.data, needle_lc, nodes_left, text_budget);
    }

    bool payload_data_empty(const mcp_standalone::json& data) {
        return json_payload_empty(data);
    }

    bool find_what_accesses_payload_evidence_ok(const invoke_result_t& ir, std::string& reason) {
        uint64_t returned = 0;
        uint64_t total_captures = 0;
        size_t accesses = 0;
        const bool has_returned = payload_u64_field(ir.data, "returned", returned);
        const bool has_total = payload_u64_field(ir.data, "total_captures", total_captures);
        const bool has_accesses = payload_array_count(ir.data, "accesses", accesses);
        if (!has_accesses || accesses == 0) {
            reason = "accesses=0";
            return false;
        }
        if ((has_returned && returned == 0) || (has_total && total_captures == 0)) {
            reason = has_returned && returned == 0 ? "returned=0" : "total_captures=0";
            return false;
        }
        const auto it = ir.data.find("accesses");
        if (it == ir.data.end() || !it->is_array()) {
            reason = "accesses_missing";
            return false;
        }
        size_t payload_records = 0;
        size_t unavailable_records = 0;
        size_t metadata_only_records = 0;
        for (const auto& item : *it) {
            bool payload_available = false;
            uint64_t preview_size = 0;
            std::string source;
            std::string hex;
            (void)payload_bool_field(item, "payload_available", payload_available);
            (void)payload_u64_field(item, "payload_preview_size", preview_size);
            (void)payload_string_field(item, "payload_source", source);
            (void)payload_string_field(item, "hex_preview", hex);
            const std::string source_lc = lower_copy(source);
            if (source_lc == "metadata_only")
                ++metadata_only_records;
            if (source_lc == "unavailable" || !payload_available)
                ++unavailable_records;
            if (payload_available && preview_size > 0 && !hex.empty() &&
                source_lc != "metadata_only" && source_lc != "unavailable")
                ++payload_records;
        }
        if (payload_records == 0) {
            reason = "payload_evidence_missing records=" + std::to_string(accesses) +
                " unavailable=" + std::to_string(unavailable_records) +
                " metadata_only=" + std::to_string(metadata_only_records);
            return false;
        }
        return true;
    }

    bool generic_success_text_only(const invoke_result_t& ir) {
        std::string text = lower_copy(ir.text);
        while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(text.begin());
        while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
        if (text.empty() || !payload_data_empty(ir.data)) return false;
        static const std::set<std::string> generic = {
            "ok",
            "success",
            "status",
            "list",
            "results",
            "payload sets",
            "entries",
            "search results",
            "tokens",
            "collections",
            "samples",
            "analysis",
            "slots",
            "diff computed",
            "collaborator status",
            "collaborator interactions",
            "collection status"
        };
        return generic.find(text) != generic.end();
    }

    bool json_string_contains_fragment(const mcp_standalone::json& value, const std::string& fragment_lc) {
        if (value.is_string())
            return lower_copy(value.get<std::string>()).find(fragment_lc) != std::string::npos;
        if (value.is_object()) {
            for (auto it = value.begin(); it != value.end(); ++it) {
                if (json_string_contains_fragment(*it, fragment_lc))
                    return true;
            }
        } else if (value.is_array()) {
            for (const auto& item : value) {
                if (json_string_contains_fragment(item, fragment_lc))
                    return true;
            }
        }
        return false;
    }

    bool positive_u64_arg(const mcp_standalone::json& args, const char* key, uint64_t& value) {
        value = 0;
        return payload_u64_field(args, key, value) && value != 0;
    }

    bool missing_required_u64_arg(const mcp_standalone::json& args, const char* key, std::string& reason) {
        uint64_t value = 0;
        if (!positive_u64_arg(args, key, value)) {
            reason = std::string(key ? key : "<null>") + "=0";
            return true;
        }
        return false;
    }

    bool mcp_call_has_invalid_prerequisite_args(const std::string& tool_lc,
                                                const mcp_standalone::json& args,
                                                std::string& reason) {
        reason.clear();
        if (json_string_contains_fragment(args, "http://127.0.0.1:1") ||
            json_string_contains_fragment(args, "https://127.0.0.1:1") ||
            json_string_contains_fragment(args, "ws://127.0.0.1:1")) {
            reason = "closed_loopback_fixture_url";
            return true;
        }

        auto require = [&](const char* key) -> bool {
            return missing_required_u64_arg(args, key, reason);
        };

        if (tool_lc == "burp_crawler_manage" ||
            tool_lc == "burp_crawler_manage")
            return require("crawl_id");
        if (tool_lc == "burp_content_discovery_manage" ||
            tool_lc == "burp_content_discovery_manage" ||
            tool_lc == "burp_content_discovery_manage")
            return require("disc_id");
        if (tool_lc == "burp_subdomain_enum_manage" ||
            tool_lc == "burp_subdomain_enum_manage")
            return require("sub_id");
        if (tool_lc == "burp_intruder_manage" ||
            tool_lc == "burp_intruder_manage" ||
            tool_lc == "burp_intruder_manage" ||
            tool_lc == "burp_intruder_manage")
            return require("job_id");
        if (tool_lc == "burp_param_miner_manage" ||
            tool_lc == "burp_param_miner_manage" ||
            tool_lc == "burp_param_miner_manage")
            return require("id");
        if (tool_lc == "burp_sequencer_manage" ||
            tool_lc == "burp_sequencer_manage" ||
            tool_lc == "burp_sequencer_manage" ||
            tool_lc == "burp_sequencer_manage" ||
            tool_lc == "burp_sequencer_manage")
            return require("collection_id");
        if (tool_lc == "burp_ws_manage" ||
            tool_lc == "burp_ws_manage" ||
            tool_lc == "burp_ws_manage" ||
            tool_lc == "burp_ws_manage" ||
            tool_lc == "burp_ws_manage" ||
            tool_lc == "burp_ws_manage")
            return require("conn_id");
        if (tool_lc == "burp_collaborator_manage")
            return require("id");
        if (tool_lc == "burp_comparer_manage")
            return require("slot_id");
        if (tool_lc == "burp_comparer_manage") {
            uint64_t slot_a = 0;
            uint64_t slot_b = 0;
            if (!positive_u64_arg(args, "slot_a", slot_a)) {
                reason = "slot_a=0";
                return true;
            }
            if (!positive_u64_arg(args, "slot_b", slot_b)) {
                reason = "slot_b=0";
                return true;
            }
            if (slot_a == slot_b) {
                reason = "slot_ids_not_distinct";
                return true;
            }
        }
        return false;
    }

    void log_mcp_validation_detail(HANDLE hf,
                                   const char* tag,
                                   const char* phase,
                                   int seq,
                                   const std::string& tool_name,
                                   const mcp_standalone::json& args,
                                   const invoke_result_t& ir,
                                   long long elapsed_ms,
                                   const std::string& reason) {
        const bool sensitive_tool = sensitive_log_tool(tool_name);
        const std::string args_preview = sensitive_tool ? "<redacted sensitive args>" : compact_json(args, 420);
        const std::string text_preview = sensitive_tool ? "<redacted sensitive text len=" + std::to_string(ir.text.size()) + ">" : compact_text(ir.text, 420);
        const std::string data_preview = sensitive_tool ? "<redacted sensitive data type=" + std::string(ir.data.type_name()) + ">" : compact_json(ir.data, 520);
        const std::string payload_summary = sensitive_tool ?
            "<redacted payload summary type=" + std::string(ir.data.type_name()) + ">" :
            mcp_payload_summary(ir.data);
        const std::string domain = mcp_tool_domain(tool_name);
        log_msg(hf, tag, "DIAG -- mcp_result phase=%s seq=%d domain=%s tool=%s elapsed_ms=%lld found=%d success=%d threw=%d text_len=%zu data_type=%s data_empty=%d payload_summary=%s reason=%s args=%s text=%s data=%s",
            phase ? phase : "",
            seq,
            domain.c_str(),
            tool_name.c_str(),
            elapsed_ms,
            ir.found ? 1 : 0,
            ir.success ? 1 : 0,
            ir.threw ? 1 : 0,
            ir.text.size(),
            ir.data.type_name(),
            payload_data_empty(ir.data) ? 1 : 0,
            payload_summary.c_str(),
            compact_text(reason, 300).c_str(),
            args_preview.c_str(),
            text_preview.c_str(),
            data_preview.c_str());
    }

    bool tool_semantic_failure_reason(const std::string& tool_name,
                                      const invoke_result_t& ir,
                                      std::string& reason) {
        reason.clear();

        const std::string tool_lc = lower_copy(tool_name);
        if (tool_lc == "disasm_get_strings") {
            return false;
        }
        if (tool_lc == "web_search" || tool_lc == "webfetch") {
            std::string transport;
            std::string browser;
            if (!payload_string_field(ir.data, "transport", transport) || lower_copy(transport) != "camoufox" ||
                !payload_string_field(ir.data, "browser", browser) || lower_copy(browser) != "camoufox") {
                reason = tool_lc + "_not_camoufox_backed";
                return true;
            }
            if (tool_lc == "web_search") {
                if (!ir.data.is_object() ||
                    !ir.data.contains("results") ||
                    !ir.data["results"].is_array() ||
                    ir.data["results"].empty()) {
                    reason = "web_search_no_camoufox_results";
                    return true;
                }
            } else {
                uint64_t bytes = 0;
                if (!payload_u64_field(ir.data, "bytes", bytes) || bytes == 0) {
                    reason = "webfetch_empty_camoufox_payload";
                    return true;
                }
            }
        }
        if (tool_lc == "find_what_accesses") {
            if (find_what_accesses_payload_evidence_ok(ir, reason))
                return false;
            return true;
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
            "snapshot unavailable",
            "seh chain unavailable",
            "teb unavailable",
            "ssdt export unresolved",
            "did not return",
            "no http messages found",
            "no tls records found",
            "filter invalid",
            "tcp_connect_failed"
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

        if (tool_lc == "cert_manage") {
            if (find_payload_key_recursive(ir.data, "key_der_hex") ||
                find_payload_key_recursive(ir.data, "private_key_der") ||
                find_payload_key_recursive(ir.data, "private_key_pem")) {
                reason = "private_key_material_returned";
                return true;
            }
        }

        if (tool_lc == "autoresponder_manage") {
            std::string path;
            bool wrote_file = false;
            uint64_t file_size = 0;
            if (payload_string_field(ir.data, "path", path) && !path.empty()) {
                if (!payload_bool_field(ir.data, "wrote_file", wrote_file) || !wrote_file ||
                    !payload_u64_field(ir.data, "file_size", file_size) || file_size == 0) {
                    reason = "autoresponder_export_file_missing";
                    return true;
                }
            }
        }

        if (tool_lc == "driver_call_function") {
            bool validate_only = false;
            (void)payload_bool_field(ir.data, "validate_only", validate_only);
            const bool dry_run = payload_text_contains(ir, "dry-run") ||
                payload_text_contains(ir, "dry run") ||
                payload_text_contains(ir, "no remote execution performed") ||
                payload_text_contains(ir, "without executing") ||
                payload_text_contains(ir, "without writing memory");
            if (tool_lc == "driver_call_function") {
                std::string function_addr;
                uint64_t pid = 0;
                if (dry_run) {
                    if (!payload_string_field(ir.data, "function", function_addr) || function_addr.empty() ||
                        !payload_u64_field(ir.data, "process_id", pid) || pid == 0) {
                        reason = "driver_call_dry_run_payload_invalid";
                        return true;
                    }
                    reason = "driver_call_dry_run_no_execution";
                    return true;
                }
            }
        }

        if (tool_lc == "cert_manage") {
            bool validate_only = false;
            bool success = false;
            std::string thumbprint;
            (void)payload_bool_field(ir.data, "validate_only", validate_only);
            if (validate_only) {
                reason = "cert_inject_validate_only_no_store_mutation";
                return true;
            }
            if (!payload_bool_field(ir.data, "success", success) ||
                !success ||
                (!validate_only && (!payload_string_field(ir.data, "thumbprint", thumbprint) || thumbprint.empty()))) {
                reason = validate_only ? "cert_inject_validate_failed" : "cert_inject_no_thumbprint";
                return true;
            }
        }

        if (tool_lc == "cert_manage") {
            bool validate_only = false;
            bool removed = false;
            if ((payload_bool_field(ir.data, "validate_only", validate_only) && validate_only) ||
                !payload_bool_field(ir.data, "removed", removed) ||
                !removed) {
                reason = validate_only ? "cert_remove_validate_only" : "cert_removed=false";
                return true;
            }
        }

        if (tool_lc == "burp_api_manage") {
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

        if (tool_lc == "burp_intruder_manage") {
            uint64_t count = 0;
            uint64_t error_count = 0;
            uint64_t successful_count = 0;
            if (!payload_u64_field(ir.data, "count", count) || count == 0) {
                reason = "intruder_results_empty";
                return true;
            }
            if (payload_u64_field(ir.data, "error_count", error_count) && error_count > 0) {
                reason = "intruder_error_count=" + std::to_string(error_count);
                return true;
            }
            if (payload_u64_field(ir.data, "successful_count", successful_count) && successful_count == 0) {
                reason = "intruder_successful_count=0";
                return true;
            }
        }

        if (tool_lc == "autoresponder_manage") {
            uint64_t rule_count = 0;
            uint64_t file_size = 0;
            bool wrote_file = false;
            std::string path;
            if (!payload_u64_field(ir.data, "rule_count", rule_count) || rule_count == 0) {
                reason = "autoresponder_export_rules_empty";
                return true;
            }
            if (payload_string_field(ir.data, "path", path) && !path.empty()) {
                if (!payload_bool_field(ir.data, "wrote_file", wrote_file) || !wrote_file ||
                    !payload_u64_field(ir.data, "file_size", file_size) || file_size == 0) {
                    reason = "autoresponder_export_file_missing";
                    return true;
                }
            }
        }

        if (tool_lc == "network_filter_manage") {
            uint64_t before_count = 0;
            uint64_t after_count = 0;
            uint64_t cleared_count = 0;
            bool before_ok = false;
            bool after_ok = false;
            if (!payload_bool_field(ir.data, "stats_before_ok", before_ok) || !before_ok ||
                !payload_bool_field(ir.data, "stats_after_ok", after_ok) || !after_ok ||
                !payload_u64_field(ir.data, "before_count", before_count) || before_count == 0 ||
                !payload_u64_field(ir.data, "after_count", after_count) || after_count != 0 ||
                !payload_u64_field(ir.data, "cleared_count", cleared_count) || cleared_count == 0) {
                reason = "network_clear_filters_unproven";
                return true;
            }
        }

        if (tool_lc == "burp_collaborator_manage") {
            uint64_t before_count = 0;
            uint64_t after_count = 1;
            uint64_t cleared_count = 0;
            if (!payload_u64_field(ir.data, "before_interaction_count", before_count) || before_count == 0 ||
                !payload_u64_field(ir.data, "after_interaction_count", after_count) || after_count != 0 ||
                !payload_u64_field(ir.data, "cleared_interactions", cleared_count) || cleared_count == 0) {
                reason = "collaborator_clear_unproven";
                return true;
            }
        }

        if (tool_lc == "burp_comparer_manage") {
            uint64_t before_count = 0;
            uint64_t after_count = 1;
            uint64_t cleared_count = 0;
            if (!payload_u64_field(ir.data, "before_count", before_count) || before_count == 0 ||
                !payload_u64_field(ir.data, "after_count", after_count) || after_count != 0 ||
                !payload_u64_field(ir.data, "cleared_count", cleared_count) || cleared_count == 0) {
                reason = "comparer_clear_unproven";
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

        if (tool_lc == "network_capture_manage") {
            if (ir.data.is_array() && !ir.data.empty())
                return false;
            size_t packets = 1;
            uint64_t count = 1;
            if ((payload_array_count(ir.data, "packets", packets) && packets > 0) ||
                (payload_u64_field(ir.data, "packet_count", count) && count > 0) ||
                (payload_u64_field(ir.data, "count", count) && count > 0))
                return false;
            if ((payload_array_count(ir.data, "packets", packets) && packets == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                payload_text_contains(ir, "0 packets retrieved")) {
                reason = "packets=0";
                return true;
            }
        }

        if (tool_lc == "network_analyze_packet") {
            if (payload_text_contains(ir, "no packets available")) {
                reason = "no_packets_available";
                return true;
            }
        }

        if (tool_lc == "network_follow_tcp_stream" ||
            tool_lc == "network_stream_track") {
            uint64_t bytes = 1;
            if ((payload_u64_field(ir.data, "bytes", bytes) && bytes == 0) ||
                (payload_u64_field(ir.data, "stream_size", bytes) && bytes == 0) ||
                (payload_u64_field(ir.data, "data_size", bytes) && bytes == 0) ||
                payload_text_contains(ir, "0 bytes reassembled") ||
                payload_text_contains(ir, "0 stream(s) tracked")) {
                reason = "stream_bytes=0";
                return true;
            }
        }

        if (tool_lc == "network_bandwidth_manage") {
            uint64_t count = 1;
            size_t processes = 1;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "processes", processes) && processes == 0) ||
                payload_text_contains(ir, "0 processes with bandwidth data")) {
                reason = "bandwidth_processes=0";
                return true;
            }
        }

        if (tool_lc == "network_os_fingerprint") {
            uint64_t count = 1;
            size_t fingerprints = 1;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "fingerprints", fingerprints) && fingerprints == 0) ||
                (payload_array_count(ir.data, "results", fingerprints) && fingerprints == 0) ||
                payload_text_contains(ir, "0 os fingerprints collected")) {
                reason = "os_fingerprints=0";
                return true;
            }
        }

        if (tool_lc == "network_pg_sniff") {
            uint64_t count = 1;
            size_t sessions = 1;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "sessions", sessions) && sessions == 0) ||
                payload_text_contains(ir, "0 session(s) active")) {
                reason = "pg_sessions=0";
                return true;
            }
        }

        if (tool_lc == "network_get_held_packets") {
            bool expected_empty = false;
            if (payload_bool_field(ir.data, "expected_empty", expected_empty) && expected_empty)
                return false;
            uint64_t count = 1;
            size_t packets = 1;
            if ((ir.data.is_array() && !ir.data.empty()) ||
                (payload_array_count(ir.data, "packets", packets) && packets > 0) ||
                (payload_array_count(ir.data, "held_packets", packets) && packets > 0) ||
                (payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_u64_field(ir.data, "held_count", count) && count > 0))
                return false;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "packets", packets) && packets == 0) ||
                (payload_array_count(ir.data, "held_packets", packets) && packets == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "held_count", count) && count == 0) ||
                payload_text_contains(ir, "0 packets held") ||
                payload_text_contains(ir, "0 held packet")) {
                reason = "held_packets=0";
                return true;
            }
        }

        if (tool_lc == "network_packet_callstack") {
            bool expected_empty = false;
            if (payload_bool_field(ir.data, "expected_empty", expected_empty) && expected_empty)
                return false;
            uint64_t count = 1;
            size_t entries = 1;
            if ((ir.data.is_array() && !ir.data.empty()) ||
                (payload_array_count(ir.data, "entries", entries) && entries > 0) ||
                (payload_array_count(ir.data, "callstacks", entries) && entries > 0) ||
                (payload_array_count(ir.data, "callstack", entries) && entries > 0) ||
                (payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_u64_field(ir.data, "entry_count", count) && count > 0))
                return false;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "entries", entries) && entries == 0) ||
                (payload_array_count(ir.data, "callstacks", entries) && entries == 0) ||
                (payload_array_count(ir.data, "callstack", entries) && entries == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "entry_count", count) && count == 0) ||
                payload_text_contains(ir, "0 callstack entries") ||
                payload_text_contains(ir, "0 packet callstack")) {
                reason = "packet_callstack_entries=0";
                return true;
            }
        }

        if (tool_lc == "quic_manage" ||
            tool_lc == "dtls_manage") {
            uint64_t count = 1;
            size_t items = 1;
            if ((payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_array_count(ir.data, "connections", items) && items > 0) ||
                (payload_array_count(ir.data, "sessions", items) && items > 0))
                return false;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "connections", items) && items == 0) ||
                (payload_array_count(ir.data, "sessions", items) && items == 0) ||
                payload_text_contains(ir, "detected 0 quic connections") ||
                payload_text_contains(ir, "detected 0 dtls sessions")) {
                reason = "transport_sessions=0";
                return true;
            }
        }

        if (tool_lc == "driver_sniff_network_buffers") {
            size_t captures = 1;
            uint64_t count = 1;
            if ((payload_array_count(ir.data, "captures", captures) && captures == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                payload_text_contains(ir, "0 captures")) {
                reason = "captures=0";
                return true;
            }
        }

        if (tool_lc == "burp_crawler_manage" ||
            tool_lc == "burp_intruder_manage" ||
            tool_lc == "burp_scanner_manage" ||
            tool_lc == "burp_ws_manage" ||
            tool_lc == "burp_logger_manage" ||
            tool_lc == "burp_tech_inventory" ||
            tool_lc == "burp_content_discovery_manage" ||
            tool_lc == "burp_subdomain_enum_manage" ||
            tool_lc == "burp_param_miner_manage" ||
            tool_lc == "burp_sequencer_manage" ||
            tool_lc == "burp_report_list" ||
            tool_lc == "burp_scanner_manage") {
            size_t items = 1;
            uint64_t count = 1;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "items", items) && items == 0) ||
                (payload_array_count(ir.data, "jobs", items) && items == 0) ||
                (payload_array_count(ir.data, "audits", items) && items == 0) ||
                (payload_array_count(ir.data, "issues", items) && items == 0) ||
                (payload_array_count(ir.data, "rows", items) && items == 0) ||
                (payload_array_count(ir.data, "hosts", items) && items == 0) ||
                (payload_array_count(ir.data, "collections", items) && items == 0) ||
                (payload_array_count(ir.data, "reports", items) && items == 0) ||
                (payload_array_count(ir.data, "results", items) && items == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "total", count) && count == 0)) {
                reason = "burp_result_set_empty";
                return true;
            }
        }

        if (tool_lc == "burp_payloads_list" ||
            tool_lc == "burp_payloads_get" ||
            tool_lc == "burp_payloads_search" ||
            tool_lc == "burp_collaborator_manage") {
            size_t items = 1;
            uint64_t count = 1;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "sets", items) && items == 0) ||
                (payload_array_count(ir.data, "entries", items) && items == 0) ||
                (payload_array_count(ir.data, "results", items) && items == 0) ||
                (payload_array_count(ir.data, "tokens", items) && items == 0) ||
                (payload_array_count(ir.data, "items", items) && items == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "total", count) && count == 0)) {
                reason = "required_result_set_empty";
                return true;
            }
        }

        if (tool_lc == "burp_crawler_manage") {
            bool had_count = false;
            bool had_positive = false;
            auto probe_count = [&](const char* key) {
                uint64_t value = 0;
                if (payload_u64_field(ir.data, key, value)) {
                    had_count = true;
                    if (value > 0)
                        had_positive = true;
                }
            };
            probe_count("urls");
            probe_count("url_count");
            probe_count("pages");
            probe_count("visited");
            probe_count("count");
            if ((had_count && !had_positive) || payload_text_contains(ir, "urls=0")) {
                reason = "crawler_urls=0";
                return true;
            }
            if (!had_count && generic_success_text_only(ir)) {
                reason = "crawler_status_missing_evidence";
                return true;
            }
        }

        if (tool_lc == "burp_content_discovery_manage") {
            uint64_t attempts = 1;
            uint64_t hits = 1;
            uint64_t total = 1;
            if ((payload_u64_field(ir.data, "attempts", attempts) && attempts == 0) &&
                (payload_u64_field(ir.data, "hits", hits) && hits == 0) &&
                (payload_u64_field(ir.data, "total", total) && total == 0)) {
                reason = "content_discovery_no_work";
                return true;
            }
        }

        if (tool_lc == "burp_subdomain_enum_manage") {
            uint64_t attempts = 1;
            uint64_t resolved = 1;
            uint64_t results = 1;
            if ((payload_u64_field(ir.data, "attempts", attempts) && attempts == 0) &&
                (payload_u64_field(ir.data, "resolved", resolved) && resolved == 0) &&
                (payload_u64_field(ir.data, "results", results) && results == 0)) {
                reason = "subdomain_enum_no_work";
                return true;
            }
        }

        if (tool_lc == "burp_collaborator_manage") {
            size_t interactions = 1;
            uint64_t count = 1;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "interactions", interactions) && interactions == 0) ||
                (payload_array_count(ir.data, "items", interactions) && interactions == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                payload_text_contains(ir, "interactions count=0")) {
                reason = "collaborator_interactions=0";
                return true;
            }
        }

        if (tool_lc == "burp_collaborator_manage") {
            bool running = false;
            bool http_alive = false;
            if (payload_data_empty(ir.data) ||
                (payload_bool_field(ir.data, "running", running) && !running) ||
                (payload_bool_field(ir.data, "http_alive", http_alive) && !http_alive) ||
                payload_text_contains(ir, "http_thread_not_ready") ||
                payload_text_contains(ir, "http_listener_not_ready") ||
                payload_text_contains(ir, "http_thread_exited_before_ready")) {
                reason = "collaborator_not_ready";
                return true;
            }
        }

        if (tool_lc == "burp_collaborator_manage") {
            std::string token;
            if (payload_data_empty(ir.data) || !payload_string_field(ir.data, "token", token) || token.empty()) {
                reason = "collaborator_token_empty";
                return true;
            }
        }

        if (tool_lc == "burp_comparer_manage") {
            size_t slots = 2;
            uint64_t count = 2;
            if ((ir.data.is_array() && ir.data.size() < 2) ||
                (payload_array_count(ir.data, "slots", slots) && slots < 2) ||
                (payload_u64_field(ir.data, "count", count) && count < 2)) {
                reason = "comparer_slots<2";
                return true;
            }
        }

        if (tool_lc == "burp_comparer_manage") {
            size_t blocks = 1;
            uint64_t count = 1;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "blocks", blocks) && blocks == 0) ||
                (payload_array_count(ir.data, "diffs", blocks) && blocks == 0) ||
                (payload_u64_field(ir.data, "blocks", count) && count == 0) ||
                (payload_u64_field(ir.data, "block_count", count) && count == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0)) {
                reason = "comparer_diff_empty";
                return true;
            }
        }

        if (tool_lc == "scanner_pointer_scan") {
            uint64_t total = 1;
            size_t results = 1;
            if (payload_data_empty(ir.data) ||
                (payload_u64_field(ir.data, "total", total) && total == 0) ||
                (payload_array_count(ir.data, "results", results) && results == 0) ||
                (payload_array_count(ir.data, "pointers", results) && results == 0)) {
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

        if (tool_lc == "find_what_accesses") {
            uint64_t total_captures = 1;
            uint64_t returned = 1;
            size_t accesses = 1;
            if (payload_u64_field(ir.data, "total_captures", total_captures) && total_captures == 0) {
                reason = "total_captures=0";
                return true;
            }
            if (payload_u64_field(ir.data, "returned", returned) && returned == 0) {
                reason = "returned=0";
                return true;
            }
            if (payload_array_count(ir.data, "accesses", accesses) && accesses == 0) {
                reason = "accesses=0";
                return true;
            }
        }

        if (tool_lc == "auto_decrypt_strings") {
            uint64_t count = 1;
            if (payload_u64_field(ir.data, "count", count) && count == 0) {
                reason = "count=0";
                return true;
            }
        }

        if (tool_lc == "analysis_query") {
            uint64_t total = 1;
            uint64_t returned = 1;
            if (payload_u64_field(ir.data, "total", total) && total == 0) {
                reason = "total=0";
                return true;
            }
            if (payload_u64_field(ir.data, "returned", returned) && returned == 0) {
                reason = "returned=0";
                return true;
            }
        }

        if (tool_lc == "analysis_query") {
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

        if (tool_lc == "fuzzer_manage") {
            std::string setup_error;
            if (payload_string_field(ir.data, "setup_error", setup_error) && !setup_error.empty()) {
                reason = "setup_error=" + setup_error;
                return true;
            }
            if (payload_text_contains(ir, "snapshot has no memory regions")) {
                reason = "snapshot_has_no_memory_regions";
                return true;
            }
            uint64_t executions = 1;
            if (payload_u64_field(ir.data, "total_executions", executions) && executions == 0) {
                reason = "total_executions=0";
                return true;
            }
            uint64_t corpus = 1;
            if (payload_u64_field(ir.data, "corpus_size", corpus) && corpus == 0) {
                reason = "corpus_size=0";
                return true;
            }
        }

        if (tool_lc == "burp_auth_saml_decode_request" ||
            tool_lc == "burp_auth_saml_decode_response") {
            std::string xml;
            if (!payload_string_field(ir.data, "xml", xml) || xml.find("<samlp:") == std::string::npos) {
                reason = "xml_missing_samlp";
                return true;
            }
            for (unsigned char ch : xml) {
                if (ch < 0x20 && ch != '\r' && ch != '\n' && ch != '\t') {
                    reason = "xml_contains_control_bytes";
                    return true;
                }
            }
            bool sanitized = false;
            if (payload_bool_field(ir.data, "xml_sanitized", sanitized) && sanitized) {
                reason = "xml_sanitized=true";
                return true;
            }
        }

        if (tool_lc == "burp_h2_send") {
            bool offline = false;
            if (payload_bool_field(ir.data, "offline_validate", offline) && offline) {
                bool ok = false;
                uint64_t frames = 0;
                if (!payload_bool_field(ir.data, "ok", ok) || !ok) {
                    reason = "h2_offline_ok=false";
                    return true;
                }
                if (!payload_u64_field(ir.data, "frames", frames) || frames == 0) {
                    reason = "h2_offline_frames=0";
                    return true;
                }
            }
        }

        if (tool_lc == "burp_dom_xss_manage") {
            bool canary = false;
            if (payload_bool_field(ir.data, "canary_fired", canary) && !canary) {
                reason = "canary_fired=false";
                return true;
            }
            uint64_t issues = 1;
            if (payload_u64_field(ir.data, "issues_emitted", issues) && issues == 0) {
                reason = "issues_emitted=0";
                return true;
            }
            bool ready = true;
            if (payload_bool_field(ir.data, "camoufox_ready", ready) && !ready) {
                reason = "camoufox_ready=false";
                return true;
            }
            bool browser_open = true;
            if (payload_bool_field(ir.data, "browser_open", browser_open) && !browser_open) {
                reason = "browser_open=false";
                return true;
            }
        }

        if (tool_lc == "burp_sequencer_manage") {
            uint64_t collected = 1;
            if (payload_u64_field(ir.data, "collected", collected) && collected == 0) {
                reason = "sequencer_collected=0";
                return true;
            }
        }

        if (tool_lc == "burp_sequencer_manage") {
            uint64_t count = 1;
            if (payload_u64_field(ir.data, "count", count) && count == 0) {
                reason = "sequencer_samples=0";
                return true;
            }
        }

        if (tool_lc == "burp_sequencer_manage") {
            uint64_t samples = 1;
            if (payload_u64_field(ir.data, "samples_count", samples) && samples == 0) {
                reason = "sequencer_samples_count=0";
                return true;
            }
            std::string verdict;
            if (payload_string_field(ir.data, "verdict", verdict) && lower_copy(verdict) == "no_samples") {
                reason = "sequencer_verdict=no_samples";
                return true;
            }
        }

        if (tool_lc == "burp_scanner_manage") {
            bool running = true;
            uint64_t probes = 1;
            if (payload_bool_field(ir.data, "running", running) &&
                payload_u64_field(ir.data, "completed_probes", probes) &&
                !running && probes == 0) {
                reason = "completed_probes=0";
                return true;
            }
        }

        if (tool_lc == "burp_scanner_manage") {
            uint64_t scanned = 1;
            if (payload_u64_field(ir.data, "exchanges_scanned", scanned) && scanned == 0) {
                reason = "exchanges_scanned=0";
                return true;
            }
        }

        if (tool_lc == "network_capture_manage") {
            if (ir.data.is_array() && !ir.data.empty())
                return false;
            if (ir.data.is_array() && ir.data.empty()) {
                reason = "packets=0";
                return true;
            }
            size_t packets = 1;
            uint64_t count = 1;
            if ((payload_array_count(ir.data, "packets", packets) && packets > 0) ||
                (payload_u64_field(ir.data, "packet_count", count) && count > 0) ||
                (payload_u64_field(ir.data, "count", count) && count > 0))
                return false;
            if ((payload_array_count(ir.data, "packets", packets) && packets == 0) ||
                (payload_u64_field(ir.data, "packet_count", count) && count == 0) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                payload_text_contains(ir, "0 packets retrieved")) {
                reason = "packets=0";
                return true;
            }
        }

        if (tool_lc == "network_analyze_packet") {
            bool capture_empty = false;
            uint64_t packet_count = 1;
            if ((payload_bool_field(ir.data, "capture_empty", capture_empty) && capture_empty) ||
                (payload_u64_field(ir.data, "packet_count", packet_count) && packet_count == 0) ||
                payload_text_contains(ir, "no packets available")) {
                reason = "capture_empty";
                return true;
            }
        }

        if (tool_lc == "network_follow_tcp_stream") {
            bool stream_empty = false;
            uint64_t total_bytes = 1;
            uint64_t total_packets = 1;
            if ((payload_bool_field(ir.data, "stream_empty", stream_empty) && stream_empty) ||
                (payload_u64_field(ir.data, "total_bytes", total_bytes) && total_bytes == 0) ||
                (payload_u64_field(ir.data, "total_packets", total_packets) && total_packets == 0) ||
                payload_text_contains(ir, "0 bytes reassembled")) {
                reason = "stream_empty";
                return true;
            }
        }

        if (tool_lc == "driver_sniff_network_buffers") {
            uint64_t capture_count = 1;
            size_t captures = 1;
            if ((payload_u64_field(ir.data, "capture_count", capture_count) && capture_count == 0) ||
                (payload_array_count(ir.data, "captures", captures) && captures == 0) ||
                payload_text_contains(ir, "0 capture(s) retrieved")) {
                reason = "capture_count=0";
                return true;
            }
        }

        if (tool_lc == "driver_reassemble_stream") {
            uint64_t total_bytes = 1;
            uint64_t total_packets = 1;
            if ((payload_u64_field(ir.data, "total_bytes", total_bytes) && total_bytes == 0) ||
                (payload_u64_field(ir.data, "total_packets", total_packets) && total_packets == 0) ||
                payload_text_contains(ir, "0 bytes reassembled")) {
                reason = "stream_bytes=0";
                return true;
            }
        }

        if (tool_lc == "api_monitor_results") {
            uint64_t count = 1;
            size_t events = 1;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "events", events) && events == 0) ||
                payload_text_contains(ir, "0 api monitor event")) {
                reason = "api_monitor_events=0";
                return true;
            }
        }

        if (tool_lc == "dbg_get_trace" ||
            tool_lc == "debugger_get_trace") {
            uint64_t count = 1;
            size_t entries = 1;
            if ((payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_u64_field(ir.data, "returned", count) && count > 0) ||
                (payload_array_count(ir.data, "entries", entries) && entries > 0) ||
                (payload_array_count(ir.data, "trace", entries) && entries > 0))
                return false;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "returned", count) && count == 0) ||
                (payload_array_count(ir.data, "entries", entries) && entries == 0) ||
                (payload_array_count(ir.data, "trace", entries) && entries == 0) ||
                payload_text_contains(ir, "0 trace entries") ||
                payload_text_contains(ir, "trace is empty") ||
                payload_text_contains(ir, "no traced step")) {
                reason = "trace_entries=0";
                return true;
            }
        }

        if (tool_lc == "debugger_start_trace") {
            bool completed = true;
            bool condition_met = false;
            uint64_t entries = 1;
            uint64_t executed = 1;
            std::string stop_reason;
            payload_bool_field(ir.data, "condition_met", condition_met);
            if (payload_bool_field(ir.data, "completed", completed) && !completed) {
                reason = "trace_completed=false";
                return true;
            }
            if (payload_u64_field(ir.data, "entries", entries) && entries == 0 && !condition_met) {
                reason = "trace_entries=0";
                return true;
            }
            if (payload_u64_field(ir.data, "executed_instructions", executed) && executed == 0 && !condition_met) {
                reason = "trace_executed_instructions=0";
                return true;
            }
            if (payload_string_field(ir.data, "stop_reason", stop_reason)) {
                const std::string stop_lc = lower_copy(stop_reason);
                if (stop_lc != "max_instructions" && stop_lc != "condition") {
                    reason = "trace_stop_reason=" + stop_reason;
                    return true;
                }
            }
        }

        if (tool_lc == "debugger_get_patches") {
            uint64_t count = 1;
            size_t patches = 1;
            if ((payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_array_count(ir.data, "patches", patches) && patches > 0))
                return false;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "patches", patches) && patches == 0) ||
                payload_text_contains(ir, "0 patch(es)")) {
                reason = "patches=0";
                return true;
            }
        }

        if (tool_lc == "dbg_scan_xrefs") {
            uint64_t count = 1;
            size_t xrefs = 1;
            if ((payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_array_count(ir.data, "xrefs", xrefs) && xrefs > 0) ||
                (payload_array_count(ir.data, "references", xrefs) && xrefs > 0))
                return false;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "xrefs", xrefs) && xrefs == 0) ||
                (payload_array_count(ir.data, "references", xrefs) && xrefs == 0) ||
                payload_text_contains(ir, "0 xref(s) found")) {
                reason = "xrefs=0";
                return true;
            }
        }

        if (tool_lc == "driver_walk_seh_chain") {
            uint64_t count = 1;
            size_t handlers = 1;
            if ((payload_u64_field(ir.data, "count", count) && count > 0) ||
                (payload_array_count(ir.data, "entries", handlers) && handlers > 0) ||
                (payload_array_count(ir.data, "handlers", handlers) && handlers > 0) ||
                (payload_array_count(ir.data, "seh", handlers) && handlers > 0))
                return false;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "entries", handlers) && handlers == 0) ||
                (payload_array_count(ir.data, "handlers", handlers) && handlers == 0) ||
                (payload_array_count(ir.data, "seh", handlers) && handlers == 0) ||
                payload_text_contains(ir, "0 seh handler(s)")) {
                reason = "seh_handlers=0";
                return true;
            }
        }

        if (tool_lc == "search_workspace") {
            uint64_t count = 1;
            uint64_t total = 1;
            size_t matches = 1;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "total", total) && total == 0) ||
                (payload_array_count(ir.data, "matches", matches) && matches == 0) ||
                payload_text_contains(ir, "0 matches")) {
                reason = "matches=0";
                return true;
            }
        }

        if (tool_lc == "list_commands") {
            uint64_t count = 1;
            size_t commands = 1;
            if ((payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_array_count(ir.data, "commands", commands) && commands == 0)) {
                reason = "commands=0";
                return true;
            }
        }

        if (tool_lc == "network_deep_inspect") {
            size_t count = 1;
            if ((ir.data.is_array() && ir.data.empty()) ||
                (payload_array_count(ir.data, "packets", count) && count == 0) ||
                payload_text_contains(ir, "no dpi results")) {
                reason = "dpi_results=0";
                return true;
            }
        }

        if (tool_lc == "quic_manage" ||
            tool_lc == "dtls_manage" ||
            tool_lc == "tls_manage" ||
            tool_lc == "tls_manage") {
            uint64_t count = 1;
            size_t keys = 1;
            if (payload_data_empty(ir.data) ||
                (ir.data.is_array() && ir.data.empty()) ||
                (payload_u64_field(ir.data, "count", count) && count == 0) ||
                (payload_u64_field(ir.data, "key_count", count) && count == 0) ||
                (payload_array_count(ir.data, "keys", keys) && keys == 0) ||
                (payload_array_count(ir.data, "secrets", keys) && keys == 0) ||
                payload_text_contains(ir, "extracted 0 keys") ||
                payload_text_contains(ir, "0 key")) {
                reason = "extracted_keys=0";
                return true;
            }
        }


        if (tool_lc == "get_xrefs") {
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
        if (generic_success_text_only(ir)) {
            reason = "generic_success_text_without_data";
            return true;
        }

        bool parsed_text_payload_valid = false;
        if (!ir.text.empty()) {
            try {
                auto parsed = mcp_standalone::json::parse(ir.text);
                if (inspect_payload_object_failure(parsed, reason))
                    return true;
                invoke_result_t parsed_ir = ir;
                parsed_ir.data = std::move(parsed);
                if (tool_semantic_failure_reason(tool_name, parsed_ir, reason))
                    return true;
                parsed_text_payload_valid = parsed_ir.data.is_object() || parsed_ir.data.is_array();
            } catch (...) {
            }
        }

        if (parsed_text_payload_valid && payload_data_empty(ir.data))
            return false;

        if (tool_semantic_failure_reason(tool_name, ir, reason))
            return true;

        return false;
    }

    struct timed_invoke_result_t {
        invoke_result_t result;
        bool timed_out = false;
        bool worker_started = false;
        bool handler_entered = false;
        bool handler_exited = false;
        bool done = false;
        DWORD worker_pid = 0;
        DWORD worker_tid = 0;
        long long elapsed_ms = 0;
        long long queue_delay_ms = 0;
        std::string worker_phase;
    };

    struct async_invoke_state_t {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        bool worker_started = false;
        bool handler_entered = false;
        bool handler_exited = false;
        DWORD worker_pid = 0;
        DWORD worker_tid = 0;
        invoke_result_t result;
        long long elapsed_ms = 0;
        long long queue_delay_ms = 0;
        std::string worker_phase;
    };

    struct timed_out_invoke_record_t {
        int seq = 0;
        std::string tool_name;
        std::string domain;
        long long timeout_ms = 0;
        uint64_t queued_tick = 0;
        uint64_t timed_out_tick = 0;
        std::shared_ptr<async_invoke_state_t> state;
    };

    std::mutex g_timed_out_invocations_mtx;
    std::vector<timed_out_invoke_record_t> g_timed_out_invocations;

    bool mcp_tool_uses_camoufox_runtime(const std::string& name) {
        const std::string n = lower_copy(name);
        return mcp_tool_requires_live_camoufox_bridge(n) ||
            n == "browser_lifecycle" ||
            n == "browser_navigation" ||
            n == "browser_interaction" ||
            n == "browser_inspect" ||
            n == "browser_state" ||
            n == "browser_network" ||
            n == "browser_hooks" ||
            n == "browser_instrumentation";
    }

    void log_mcp_camoufox_snapshot(HANDLE hf, const char* tag, const char* phase, int seq, const std::string& tool_name) {
        if (!mcp_tool_uses_camoufox_runtime(tool_name))
            return;
        const auto st = aida::burp::camoufox::get_status();
        log_msg(hf, tag, "CAMOUFOX-RUNNER -- phase=%s seq=%d tool=\"%s\" state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d calls=%llu errors=%llu last_call_ms=%llu last_launch_ms=%llu last_nav_ms=%llu last_cleanup_ms=%llu err=%s",
            phase ? phase : "<null>",
            seq,
            tool_name.c_str(),
            camoufox_bridge_state_name(st.state),
            static_cast<unsigned long long>(st.generation),
            st.child_pid,
            st.child_alive ? 1 : 0,
            st.browser_open ? 1 : 0,
            st.page_verified ? 1 : 0,
            st.cleanup_pending ? 1 : 0,
            static_cast<unsigned long long>(st.total_calls),
            static_cast<unsigned long long>(st.total_errors),
            static_cast<unsigned long long>(st.last_call_ms),
            static_cast<unsigned long long>(st.last_launch_ms),
            static_cast<unsigned long long>(st.last_nav_ms),
            static_cast<unsigned long long>(st.last_cleanup_ms),
            compact_text(st.last_error, 700).c_str());
    }

    void log_mcp_invoke_snapshot(HANDLE hf,
                                 const char* tag,
                                 const char* phase,
                                 int seq,
                                 const std::string& tool_name,
                                 long long timeout_ms,
                                 long long waited_ms,
                                 bool worker_started,
                                 bool handler_entered,
                                 bool handler_exited,
                                 bool done,
                                 DWORD worker_pid,
                                 DWORD worker_tid,
                                 long long queue_delay_ms,
                                 long long worker_elapsed_ms,
                                 const std::string& worker_phase) {
        const auto cq = critical_work_queue::stats();
        const std::string domain = mcp_tool_domain(tool_name);
        log_msg(hf, tag, "INVOKE-%s -- \"%s\" seq=%d domain=%s timeout_ms=%lld waited_ms=%lld host_pid=%lu host_tid=%lu worker_started=%d handler_entered=%d handler_exited=%d done=%d worker_pid=%lu worker_tid=%lu queue_delay_ms=%lld worker_elapsed_ms=%lld worker_phase=%s cq_alive=%d cq_shutdown=%d cq_workers=%zu cq_pending=%zu cq_active=%u cq_posted=%llu cq_started=%llu cq_finished=%llu target_pid=%u attached_pid=%u full_test_running=%d",
            phase ? phase : "<null>",
            tool_name.c_str(),
            seq,
            domain.c_str(),
            timeout_ms,
            waited_ms,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            worker_started ? 1 : 0,
            handler_entered ? 1 : 0,
            handler_exited ? 1 : 0,
            done ? 1 : 0,
            static_cast<unsigned long>(worker_pid),
            static_cast<unsigned long>(worker_tid),
            queue_delay_ms,
            worker_elapsed_ms,
            worker_phase.empty() ? "<empty>" : worker_phase.c_str(),
            cq.alive ? 1 : 0,
            cq.shutting_down ? 1 : 0,
            cq.workers,
            cq.pending,
            static_cast<unsigned>(cq.active),
            static_cast<unsigned long long>(cq.posted),
            static_cast<unsigned long long>(cq.started),
            static_cast<unsigned long long>(cq.finished),
            g_mcp_target_pid,
            driver_bridge::attached_pid(),
            test_all_features::is_running() ? 1 : 0);
        log_mcp_camoufox_snapshot(hf, tag, phase, seq, tool_name);
    }

    void snapshot_async_state_locked(const std::shared_ptr<async_invoke_state_t>& state,
                                     bool& worker_started,
                                     bool& handler_entered,
                                     bool& handler_exited,
                                     bool& done,
                                     DWORD& worker_pid,
                                     DWORD& worker_tid,
                                     long long& queue_delay_ms,
                                     long long& worker_elapsed_ms,
                                     std::string& worker_phase) {
        worker_started = state->worker_started;
        handler_entered = state->handler_entered;
        handler_exited = state->handler_exited;
        done = state->done;
        worker_pid = state->worker_pid;
        worker_tid = state->worker_tid;
        queue_delay_ms = state->queue_delay_ms;
        worker_elapsed_ms = state->elapsed_ms;
        worker_phase = state->worker_phase;
    }

    void register_timed_out_invocation(int seq,
                                       const std::string& tool_name,
                                       long long timeout_ms,
                                       uint64_t queued_tick,
                                       const std::shared_ptr<async_invoke_state_t>& state) {
        if (!state)
            return;
        timed_out_invoke_record_t rec;
        rec.seq = seq;
        rec.tool_name = tool_name;
        rec.domain = mcp_tool_domain(tool_name);
        rec.timeout_ms = timeout_ms;
        rec.queued_tick = queued_tick;
        rec.timed_out_tick = GetTickCount64();
        rec.state = state;
        std::lock_guard<std::mutex> lk(g_timed_out_invocations_mtx);
        for (const auto& existing : g_timed_out_invocations) {
            if (existing.seq == seq)
                return;
        }
        g_timed_out_invocations.push_back(std::move(rec));
    }

    size_t prune_completed_timed_out_invocations() {
        std::lock_guard<std::mutex> lk(g_timed_out_invocations_mtx);
        g_timed_out_invocations.erase(
            std::remove_if(g_timed_out_invocations.begin(), g_timed_out_invocations.end(),
                [](const timed_out_invoke_record_t& rec) {
                    if (!rec.state)
                        return true;
                    std::lock_guard<std::mutex> state_lk(rec.state->mutex);
                    return rec.state->done;
                }),
            g_timed_out_invocations.end());
        return g_timed_out_invocations.size();
    }

    std::vector<timed_out_invoke_record_t> copy_timed_out_invocations() {
        std::lock_guard<std::mutex> lk(g_timed_out_invocations_mtx);
        return g_timed_out_invocations;
    }

    void log_timed_out_invocations(HANDLE hf, const char* tag, const char* phase) {
        const auto records = copy_timed_out_invocations();
        const uint64_t now = GetTickCount64();
        log_msg(hf, tag, "OUTSTANDING-DIAG -- phase=%s count=%zu",
            phase ? phase : "unspecified",
            records.size());
        for (const auto& rec : records) {
            bool worker_started = false;
            bool handler_entered = false;
            bool handler_exited = false;
            bool done = false;
            DWORD worker_pid = 0;
            DWORD worker_tid = 0;
            long long queue_delay_ms = 0;
            long long worker_elapsed_ms = 0;
            std::string worker_phase;
            if (rec.state) {
                std::lock_guard<std::mutex> lk(rec.state->mutex);
                snapshot_async_state_locked(rec.state, worker_started, handler_entered, handler_exited, done,
                    worker_pid, worker_tid, queue_delay_ms, worker_elapsed_ms, worker_phase);
            }
            const uint64_t queued_age = rec.queued_tick != 0 && now >= rec.queued_tick ? now - rec.queued_tick : 0;
            const uint64_t timeout_age = rec.timed_out_tick != 0 && now >= rec.timed_out_tick ? now - rec.timed_out_tick : 0;
            log_msg(hf, tag, "OUTSTANDING -- phase=%s seq=%d tool=\"%s\" domain=%s timeout_ms=%lld queued_age_ms=%llu timed_out_age_ms=%llu worker_started=%d handler_entered=%d handler_exited=%d done=%d worker_pid=%lu worker_tid=%lu queue_delay_ms=%lld worker_elapsed_ms=%lld worker_phase=%s",
                phase ? phase : "unspecified",
                rec.seq,
                rec.tool_name.c_str(),
                rec.domain.c_str(),
                rec.timeout_ms,
                static_cast<unsigned long long>(queued_age),
                static_cast<unsigned long long>(timeout_age),
                worker_started ? 1 : 0,
                handler_entered ? 1 : 0,
                handler_exited ? 1 : 0,
                done ? 1 : 0,
                static_cast<unsigned long>(worker_pid),
                static_cast<unsigned long>(worker_tid),
                queue_delay_ms,
                worker_elapsed_ms,
                worker_phase.empty() ? "<empty>" : worker_phase.c_str());
        }
    }

    bool wait_timed_out_invocation_drain(HANDLE hf, const char* reason, DWORD timeout_ms) {
        const uint64_t start = GetTickCount64();
        const uint64_t deadline = start + timeout_ms;
        size_t remaining = prune_completed_timed_out_invocations();
        auto cq = critical_work_queue::stats();
        log_msg(hf, "mcp.finalize_drain", "BEGIN -- reason=%s timeout_ms=%lu outstanding=%zu cq_alive=%d cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
            reason ? reason : "unspecified",
            static_cast<unsigned long>(timeout_ms),
            remaining,
            cq.alive ? 1 : 0,
            cq.pending,
            static_cast<unsigned>(cq.active),
            static_cast<unsigned long long>(cq.started),
            static_cast<unsigned long long>(cq.finished));
        log_timed_out_invocations(hf, "mcp.finalize_drain", "begin");
        while (remaining != 0 && GetTickCount64() < deadline) {
            Sleep(100);
            remaining = prune_completed_timed_out_invocations();
        }
        cq = critical_work_queue::stats();
        const uint64_t elapsed = GetTickCount64() - start;
        if (remaining == 0) {
            log_msg(hf, "mcp.finalize_drain", "END -- drained=1 elapsed_ms=%llu cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
                static_cast<unsigned long long>(elapsed),
                cq.pending,
                static_cast<unsigned>(cq.active),
                static_cast<unsigned long long>(cq.started),
                static_cast<unsigned long long>(cq.finished));
            return true;
        }
        log_msg(hf, "mcp.finalize_drain", "WARN -- drained=0 elapsed_ms=%llu remaining=%zu cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu; continuing to phase summary",
            static_cast<unsigned long long>(elapsed),
            remaining,
            cq.pending,
            static_cast<unsigned>(cq.active),
            static_cast<unsigned long long>(cq.started),
            static_cast<unsigned long long>(cq.finished));
        log_timed_out_invocations(hf, "mcp.finalize_drain", "timeout");
        return false;
    }

    struct finalizer_bool_state_t {
        std::mutex mutex;
        std::condition_variable cv;
        bool entered = false;
        bool done = false;
        bool value = false;
        DWORD worker_pid = 0;
        DWORD worker_tid = 0;
        uint64_t elapsed_ms = 0;
        std::string error;
    };

    bool run_finalizer_bool_bounded(HANDLE hf,
                                    const char* label,
                                    DWORD timeout_ms,
                                    const std::function<bool()>& fn,
                                    bool& completed,
                                    bool& value) {
        completed = false;
        value = false;
        const char* safe_label = label ? label : "unnamed";
        auto state = std::make_shared<finalizer_bool_state_t>();
        const uint64_t t0 = GetTickCount64();
        log_msg(hf, "mcp.finalize_task", "BEGIN -- label=%s timeout_ms=%lu caller_pid=%lu caller_tid=%lu queue=work_queue",
            safe_label,
            static_cast<unsigned long>(timeout_ms),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        bool started = false;
        DWORD post_gle = ERROR_SUCCESS;
        try {
            started = work_queue::post([state, fn]() {
                const uint64_t worker_t0 = GetTickCount64();
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    state->entered = true;
                    state->worker_pid = GetCurrentProcessId();
                    state->worker_tid = GetCurrentThreadId();
                }
                state->cv.notify_all();
                bool local_value = false;
                std::string local_error;
                try {
                    local_value = fn ? fn() : false;
                } catch (const std::exception& ex) {
                    local_error = ex.what();
                } catch (...) {
                    local_error = "unknown exception";
                }
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    state->value = local_value;
                    state->error = std::move(local_error);
                    state->elapsed_ms = GetTickCount64() - worker_t0;
                    state->done = true;
                }
                state->cv.notify_all();
            });
            post_gle = GetLastError();
        } catch (const std::exception& ex) {
            post_gle = GetLastError();
            if (post_gle == ERROR_SUCCESS)
                post_gle = ERROR_NOT_ENOUGH_MEMORY;
            log_msg(hf, "mcp.finalize_task", "WARN -- label=%s post_exception elapsed_ms=%llu gle=%lu err=%s",
                safe_label,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                static_cast<unsigned long>(post_gle),
                compact_text(ex.what(), 700).c_str());
        } catch (...) {
            post_gle = GetLastError();
            if (post_gle == ERROR_SUCCESS)
                post_gle = ERROR_NOT_ENOUGH_MEMORY;
            log_msg(hf, "mcp.finalize_task", "WARN -- label=%s post_exception elapsed_ms=%llu gle=%lu err=unknown",
                safe_label,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                static_cast<unsigned long>(post_gle));
        }
        if (!started) {
            if (post_gle == ERROR_SUCCESS)
                post_gle = ERROR_NOT_READY;
            log_msg(hf, "mcp.finalize_task", "WARN -- label=%s post_failed elapsed_ms=%llu gle=%lu",
                safe_label,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                static_cast<unsigned long>(post_gle));
            return false;
        }
        std::unique_lock<std::mutex> wait_lock(state->mutex);
        const bool done = state->cv.wait_for(wait_lock, std::chrono::milliseconds(timeout_ms), [state]() {
            return state->done;
        });
        wait_lock.unlock();
        if (!done) {
            DWORD worker_pid = 0;
            DWORD worker_tid = 0;
            bool entered = false;
            {
                std::lock_guard<std::mutex> lk(state->mutex);
                worker_pid = state->worker_pid;
                worker_tid = state->worker_tid;
                entered = state->entered;
            }
            log_msg(hf, "mcp.finalize_task", "WARN -- label=%s timeout elapsed_ms=%llu entered=%d worker_pid=%lu worker_tid=%lu; queued cleanup may finish later",
                safe_label,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                entered ? 1 : 0,
                static_cast<unsigned long>(worker_pid),
                static_cast<unsigned long>(worker_tid));
            return false;
        }
        std::string error;
        uint64_t worker_elapsed = 0;
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            completed = state->done && state->error.empty();
            value = state->value;
            error = state->error;
            worker_elapsed = state->elapsed_ms;
        }
        if (!error.empty()) {
            log_msg(hf, "mcp.finalize_task", "WARN -- label=%s exception elapsed_ms=%llu worker_elapsed_ms=%llu err=%s",
                safe_label,
                static_cast<unsigned long long>(GetTickCount64() - t0),
                static_cast<unsigned long long>(worker_elapsed),
                compact_text(error, 700).c_str());
            return false;
        }
        log_msg(hf, "mcp.finalize_task", "END -- label=%s completed=%d result=%d elapsed_ms=%llu worker_elapsed_ms=%llu",
            safe_label,
            completed ? 1 : 0,
            value ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - t0),
            static_cast<unsigned long long>(worker_elapsed));
        return completed;
    }

    bool bounded_finalizer_call(HANDLE hf,
                                const char* label,
                                DWORD timeout_ms,
                                const std::function<bool()>& fn) {
        bool completed = false;
        bool value = false;
        run_finalizer_bool_bounded(hf, label, timeout_ms, fn, completed, value);
        return completed && value;
    }

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

    bool require_tool_read_only_metadata(HANDLE hf, const char* tag, const char* tool_name, bool expected_read_only, std::atomic<int>& failed) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        const auto* tool = find_registered_tool(get_server(), tool_name);
        if (!tool) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" is not registered for metadata validation", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        if (tool->read_only != expected_read_only) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" read_only=%d expected=%d before functional invocation",
                tool_name ? tool_name : "<null>",
                tool->read_only ? 1 : 0,
                expected_read_only ? 1 : 0);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        log_msg(hf, tag, "METADATA -- tool \"%s\" read_only=%d as expected",
            tool_name ? tool_name : "<null>",
            tool->read_only ? 1 : 0);
        return true;
    }

    long long tool_timeout_ms(const std::string& name) {
        if (name == "web_search")
            return 90000;
        if (name == "webfetch")
            return 90000;
        if (name == "burp_collaborator_manage" || name == "burp_collaborator_manage")
            return 10000;
        if (name == "burp_dom_xss_manage")
            return 60000;
        if (name == "sandbox_execute")
            return 180000;
        if (name == "sessions_manage")
            return 300000;
        if (name == "browser_lifecycle")
            return k_camoufox_testlab_launch_watchdog_ms;
        if (name == "api_monitor_start")
            return 60000;
        if (name == "cert_manage")
            return 60000;
        if (name == "browser_instrumentation")
            return 60000;
        if (name == "compare_env")
            return 45000;
        if (name == "instrumentation" || name == "verify_signer_offline")
            return 60000;
        if (name.find("burp_headless") == 0)
            return 45000;
        if (name == "scanner_pointer_scan")
            return 35000;
        if (name == "find_what_accesses")
            return 12000;
        if (name == "hunt_integrity_checkers")
            return 20000;
        if (name == "auto_decrypt_strings" ||
            name == "reconstruct_struct" ||
            name == "live_monitor_manage" ||
            name == "scan_crypto_constants" ||
            name == "scan_crypto_constants")
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
        } else if (name == "live_monitor_manage") {
            struct_monitor::stop();
            log_msg(hf, tag, "CANCEL -- live monitor stop signalled");
        } else if (name == "scanner_pointer_scan") {
            memory_scanner::cancel_pointer_scan();
            log_msg(hf, tag, "CANCEL -- scanner pointer scan stop signalled");
        } else if (name == "find_what_accesses") {
            const size_t signalled = page_guard_engine::g_pg_engine.signal_stop_all();
            log_msg(hf, tag, "CANCEL -- find_what_accesses page-guard sessions signalled count=%zu", signalled);
        } else if (name == "network_pg_sniff") {
            const size_t signalled = page_guard_engine::g_pg_engine.signal_stop_all();
            log_msg(hf, tag, "CANCEL -- network_pg_sniff page-guard sessions signalled count=%zu", signalled);
        } else if (name == "hunt_integrity_checkers") {
            integrity_hunter::stop_hunt();
            const bool idle = integrity_hunter::wait_until_idle(12000);
            log_msg(hf, tag, "CANCEL -- integrity hunter stop signalled idle=%d", idle ? 1 : 0);
        } else if (mcp_tool_uses_camoufox_runtime(name)) {
            const auto st = aida::burp::camoufox::get_status();
            log_msg(hf, tag, "CANCEL -- camoufox timeout signal begin tool=%s state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu err=%s",
                name.c_str(),
                camoufox_bridge_state_name(st.state),
                static_cast<unsigned long long>(st.generation),
                st.child_pid,
                st.child_alive ? 1 : 0,
                st.browser_open ? 1 : 0,
                st.page_verified ? 1 : 0,
                st.cleanup_pending ? 1 : 0,
                static_cast<unsigned long long>(st.total_errors),
                compact_text(st.last_error, 700).c_str());
            const uint64_t cleanup_start = GetTickCount64();
            const bool cleanup_ok = aida::burp::camoufox::force_cleanup("testlab.camoufox_timeout");
            const bool idle_ok = aida::burp::camoufox::wait_until_idle(30000, "testlab.camoufox_timeout");
            const auto after = aida::burp::camoufox::get_status();
            log_msg(hf, tag, "CANCEL -- camoufox timeout cleanup done cleanup_ok=%d idle_ok=%d elapsed_ms=%llu state=%s generation=%llu child_pid=%u child_alive=%d browser_open=%d page_verified=%d cleanup_pending=%d errors=%llu err=%s",
                cleanup_ok ? 1 : 0,
                idle_ok ? 1 : 0,
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start),
                camoufox_bridge_state_name(after.state),
                static_cast<unsigned long long>(after.generation),
                after.child_pid,
                after.child_alive ? 1 : 0,
                after.browser_open ? 1 : 0,
                after.page_verified ? 1 : 0,
                after.cleanup_pending ? 1 : 0,
                static_cast<unsigned long long>(after.total_errors),
                compact_text(after.last_error, 700).c_str());
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
                                             long long timeout_ms,
                                             HANDLE hf = INVALID_HANDLE_VALUE,
                                             const char* tag = nullptr,
                                             int seq = 0)
    {
        timed_invoke_result_t out;
        const auto state = std::make_shared<async_invoke_state_t>();
        const bool full_log = hf != INVALID_HANDLE_VALUE && tag != nullptr && *tag != '\0';
        auto fail_dispatch = [&](std::string message) {
            timed_invoke_result_t failed;
            failed.result.found = tool_registered(srv, tool_name.c_str());
            failed.result.threw = true;
            failed.result.exception_msg = std::move(message);
            return failed;
        };

        const auto queued_at = std::chrono::steady_clock::now();
        const uint64_t queued_tick = GetTickCount64();
        try {
            if (full_log) {
                log_mcp_invoke_snapshot(hf, tag, "QUEUE", seq, tool_name, timeout_ms, 0,
                    false, false, false, false, 0, 0, 0, 0, "queued");
            }
            diag::log_tagged_fmt("test_all_mcp", "invoke queue seq=%d tool=%s timeout_ms=%lld pid=%lu tid=%lu tick_ms=%llu",
                seq,
                tool_name.c_str(),
                timeout_ms,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(queued_tick));
            if (!critical_work_queue::post([state, srv, tool_name, args, queued_at, queued_tick, seq, timeout_ms]() {
                auto t0 = std::chrono::steady_clock::now();
                const DWORD worker_pid = GetCurrentProcessId();
                const DWORD worker_tid = GetCurrentThreadId();
                const uint64_t enter_tick = GetTickCount64();
                long long queue_delay_ms = static_cast<long long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(t0 - queued_at).count());
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    state->worker_started = true;
                    state->handler_entered = true;
                    state->worker_pid = worker_pid;
                    state->worker_tid = worker_tid;
                    state->queue_delay_ms = queue_delay_ms;
                    state->worker_phase = "handler_enter";
                }
                diag::log_tagged_fmt("test_all_mcp", "invoke worker entry seq=%d tool=%s pid=%lu tid=%lu timeout_ms=%lld queue_delay_ms=%lld queued_tick_ms=%llu enter_tick_ms=%llu",
                    seq,
                    tool_name.c_str(),
                    static_cast<unsigned long>(worker_pid),
                    static_cast<unsigned long>(worker_tid),
                    timeout_ms,
                    queue_delay_ms,
                    static_cast<unsigned long long>(queued_tick),
                    static_cast<unsigned long long>(enter_tick));
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
                const bool log_found = ir.found;
                const bool log_success = ir.success;
                const bool log_threw = ir.threw;
                const std::size_t log_text_len = ir.text.size();
                const std::string log_data_type = ir.data.type_name();
                const std::size_t log_exception_len = ir.exception_msg.size();
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    state->result = std::move(ir);
                    state->elapsed_ms = static_cast<long long>(ms);
                    state->handler_exited = true;
                    state->worker_phase = "handler_exit";
                    state->done = true;
                }
                state->cv.notify_all();
                diag::log_tagged_fmt("test_all_mcp", "invoke worker exit seq=%d tool=%s pid=%lu tid=%lu elapsed_ms=%lld found=%d success=%d threw=%d text_len=%zu data_type=%s exception_len=%zu",
                    seq,
                    tool_name.c_str(),
                    static_cast<unsigned long>(worker_pid),
                    static_cast<unsigned long>(worker_tid),
                    static_cast<long long>(ms),
                    log_found ? 1 : 0,
                    log_success ? 1 : 0,
                    log_threw ? 1 : 0,
                    log_text_len,
                    log_data_type.c_str(),
                    log_exception_len);
            })) {
                if (full_log) {
                    log_mcp_invoke_snapshot(hf, tag, "QUEUE-REJECTED", seq, tool_name, timeout_ms, 0,
                        false, false, false, false, 0, 0, 0, 0, "post_failed");
                }
                return fail_dispatch("dispatch queue rejected task");
            }
        } catch (const std::exception& ex) {
            if (full_log) {
                log_mcp_invoke_snapshot(hf, tag, "QUEUE-EXCEPTION", seq, tool_name, timeout_ms, 0,
                    false, false, false, false, 0, 0, 0, 0, "post_exception");
            }
            return fail_dispatch(std::string("dispatch queue post failed: ") + ex.what());
        } catch (...) {
            if (full_log) {
                log_mcp_invoke_snapshot(hf, tag, "QUEUE-EXCEPTION", seq, tool_name, timeout_ms, 0,
                    false, false, false, false, 0, 0, 0, 0, "post_unknown_exception");
            }
            return fail_dispatch("dispatch queue post failed: unknown exception");
        }

        const auto wait_start = std::chrono::steady_clock::now();
        const auto timeout_duration = std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 0);
        const auto deadline = wait_start + timeout_duration;
        long long last_wait_log_ms = 0;
        std::unique_lock<std::mutex> lk(state->mutex);
        for (;;) {
            if (state->done)
                break;

            const auto now = std::chrono::steady_clock::now();
            const long long waited_ms = static_cast<long long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(now - wait_start).count());
            if (now >= deadline) {
                bool worker_started = false;
                bool handler_entered = false;
                bool handler_exited = false;
                bool done = false;
                DWORD worker_pid = 0;
                DWORD worker_tid = 0;
                long long queue_delay_ms = 0;
                long long worker_elapsed_ms = 0;
                std::string worker_phase;
                snapshot_async_state_locked(state, worker_started, handler_entered, handler_exited, done,
                    worker_pid, worker_tid, queue_delay_ms, worker_elapsed_ms, worker_phase);
                out.timed_out = true;
                out.worker_started = worker_started;
                out.handler_entered = handler_entered;
                out.handler_exited = handler_exited;
                out.done = done;
                out.worker_pid = worker_pid;
                out.worker_tid = worker_tid;
                out.elapsed_ms = timeout_ms;
                out.queue_delay_ms = worker_started ? queue_delay_ms : timeout_ms;
                out.worker_phase = worker_phase;
                register_timed_out_invocation(seq, tool_name, timeout_ms, queued_tick, state);
                lk.unlock();
                if (full_log) {
                    log_mcp_invoke_snapshot(hf, tag, "TIMEOUT", seq, tool_name, timeout_ms, waited_ms,
                        worker_started, handler_entered, handler_exited, done, worker_pid, worker_tid,
                        out.queue_delay_ms, worker_elapsed_ms, worker_phase);
                }
                diag::log_tagged_fmt("test_all_mcp", "invoke timeout seq=%d tool=%s timeout_ms=%lld waited_ms=%lld worker_started=%d handler_entered=%d handler_exited=%d done=%d worker_pid=%lu worker_tid=%lu queue_delay_ms=%lld worker_phase=%s",
                    seq,
                    tool_name.c_str(),
                    timeout_ms,
                    waited_ms,
                    worker_started ? 1 : 0,
                    handler_entered ? 1 : 0,
                    handler_exited ? 1 : 0,
                    done ? 1 : 0,
                    static_cast<unsigned long>(worker_pid),
                    static_cast<unsigned long>(worker_tid),
                    out.queue_delay_ms,
                    worker_phase.empty() ? "<empty>" : worker_phase.c_str());
                return out;
            }

            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            const auto slice = remaining > std::chrono::milliseconds(5000)
                ? std::chrono::milliseconds(5000)
                : remaining;
            if (state->cv.wait_for(lk, slice, [&]() { return state->done; }))
                break;

            const auto after_wait = std::chrono::steady_clock::now();
            const long long after_wait_ms = static_cast<long long>(
                std::chrono::duration_cast<std::chrono::milliseconds>(after_wait - wait_start).count());
            if (full_log && (after_wait_ms - last_wait_log_ms >= 5000 || timeout_ms - after_wait_ms <= 1000)) {
                bool worker_started = false;
                bool handler_entered = false;
                bool handler_exited = false;
                bool done = false;
                DWORD worker_pid = 0;
                DWORD worker_tid = 0;
                long long queue_delay_ms = 0;
                long long worker_elapsed_ms = 0;
                std::string worker_phase;
                snapshot_async_state_locked(state, worker_started, handler_entered, handler_exited, done,
                    worker_pid, worker_tid, queue_delay_ms, worker_elapsed_ms, worker_phase);
                lk.unlock();
                log_mcp_invoke_snapshot(hf, tag, "WAIT", seq, tool_name, timeout_ms, after_wait_ms,
                    worker_started, handler_entered, handler_exited, done, worker_pid, worker_tid,
                    queue_delay_ms, worker_elapsed_ms, worker_phase);
                lk.lock();
                last_wait_log_ms = after_wait_ms;
            }
        }
        out.result = std::move(state->result);
        out.worker_started = state->worker_started;
        out.handler_entered = state->handler_entered;
        out.handler_exited = state->handler_exited;
        out.done = state->done;
        out.worker_pid = state->worker_pid;
        out.worker_tid = state->worker_tid;
        out.elapsed_ms = state->elapsed_ms;
        out.queue_delay_ms = state->queue_delay_ms;
        out.worker_phase = state->worker_phase;
        lk.unlock();
        if (full_log) {
            log_mcp_invoke_snapshot(hf, tag, "COMPLETE", seq, tool_name, timeout_ms, out.elapsed_ms,
                out.worker_started, out.handler_entered, out.handler_exited, out.done, out.worker_pid,
                out.worker_tid, out.queue_delay_ms, out.elapsed_ms, out.worker_phase);
        }
        return out;
    }

    timed_invoke_result_t invoke_tool_action_bounded(mcp_standalone::server_t* srv,
                                                     const std::string& tool_name,
                                                     const std::string& action,
                                                     mcp_standalone::json args,
                                                     long long timeout_ms,
                                                     HANDLE hf = INVALID_HANDLE_VALUE,
                                                     const char* tag = nullptr,
                                                     int seq = 0)
    {
        if (!args.is_object())
            args = mcp_standalone::json::object();
        args["action"] = action;
        return invoke_tool_bounded(srv, tool_name, args, timeout_ms, hf, tag, seq);
    }


    mcp_tool_call_status_t test_tool_call(HANDLE hf, const char* tag, mcp_standalone::server_t* srv,
                                          const char* tool_name, const mcp_standalone::json& args,
                                          std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped,
                                          bool skip_on_error = false,
                                          mcp_standalone::tool_result_t* out_result = nullptr)
    {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        (void)skipped;
        mcp_standalone::json call_args = args.is_null() ? mcp_standalone::json::object() : args;
        bool test_lab_safe_fixture = false;
        if (call_args.is_object() &&
            call_args.contains(k_test_lab_safe_fixture_flag) &&
            call_args[k_test_lab_safe_fixture_flag].is_boolean()) {
            test_lab_safe_fixture = call_args[k_test_lab_safe_fixture_flag].get<bool>();
            call_args.erase(k_test_lab_safe_fixture_flag);
        }
        const bool validate_only_call = call_args.is_object() &&
            call_args.contains("validate_only") &&
            call_args["validate_only"].is_boolean() &&
            call_args["validate_only"].get<bool>();
        const bool dry_run_call = call_args.is_object() &&
            call_args.contains("dry_run") &&
            call_args["dry_run"].is_boolean() &&
            call_args["dry_run"].get<bool>();
        const bool safe_contract_call = validate_only_call || dry_run_call || test_lab_safe_fixture;
        if (is_ai_related_mcp_tool(tool_name_s)) {
            log_msg(hf, tag, "EXCLUDED -- tool \"%s\" is AI/agent-related and excluded from full-run tests counted=0",
                tool_name_s.c_str());
            return mcp_tool_call_status_t::skipped;
        }
        if (is_destructive_mcp_tool(tool_name_s) && !safe_contract_call) {
            log_msg(hf, tag, "EXCLUDED -- tool \"%s\" is destructive and requires schema-only coverage",
                tool_name_s.c_str());
            return mcp_tool_call_status_t::skipped;
        }

        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: %s", seq, tool_name ? tool_name : "<null>");
        set_progress_step(step);

        add_target_pid_if_needed(tool_name_s, call_args);
        add_target_tid_if_zero(call_args);
        const bool live_target_required = tool_uses_live_target(tool_name_s);
        const bool target_context_may_change = tool_may_change_target(tool_name_s);
        const auto* registered_tool = find_registered_tool(srv, tool_name);
        const std::string domain = mcp_tool_domain(tool_name_s);

        const std::string args_preview = compact_json(call_args);
        log_msg(hf, tag, "START -- \"%s\" seq=%d domain=%s target_pid=%u attached_pid=%u live_target_required=%d target_context_may_change=%d validate_only=%d dry_run=%d test_safe_fixture=%d registered=%d read_only=%d visibility=%s args=%s",
            tool_name ? tool_name : "<null>",
            seq,
            domain.c_str(),
            g_mcp_target_pid,
            driver_bridge::attached_pid(),
            live_target_required ? 1 : 0,
            target_context_may_change ? 1 : 0,
            validate_only_call ? 1 : 0,
            dry_run_call ? 1 : 0,
            test_lab_safe_fixture ? 1 : 0,
            registered_tool ? 1 : 0,
            registered_tool && registered_tool->read_only ? 1 : 0,
            registered_tool ? tool_visibility_name(registered_tool->visibility) : "unregistered",
            args_preview.c_str());
        g_invoked_tools.insert(tool_name_s);

        if (live_target_required) {
            if (!ensure_mcp_target_live(hf, tag)) {
                log_msg(hf, tag, "FAIL -- \"%s\" requires live MCP target pid=%u but restore/liveness check failed",
                    tool_name, g_mcp_target_pid);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return mcp_tool_call_status_t::failed;
            }
        } else if (g_mcp_target_pid != 0 && driver_bridge::attached_pid() == 0) {
            log_msg(hf, tag, "INFO -- \"%s\" does not require the live MCP target; continuing with active_pid=0",
                tool_name);
        }

        if (!registered_tool) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" not registered", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        if (is_destructive_mcp_tool(tool_name_s) && safe_contract_call && registered_tool && registered_tool->read_only) {
            log_msg(hf, tag, "FAIL -- destructive safe-contract tool \"%s\" is incorrectly marked read_only=true", tool_name);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        std::string prerequisite_failure;
        if (mcp_call_has_invalid_prerequisite_args(lower_copy(tool_name_s), call_args, prerequisite_failure)) {
            invoke_result_t blocked_ir;
            blocked_ir.found = true;
            blocked_ir.success = false;
            blocked_ir.text = "blocked before dispatch by Test Lab prerequisite validation";
            log_msg(hf, tag, "FAIL -- \"%s\" prerequisite validation failed before dispatch: %s args=%s",
                tool_name,
                prerequisite_failure.c_str(),
                compact_json(call_args, 700).c_str());
            log_mcp_validation_detail(hf, tag, "blocked_prerequisite", seq, tool_name_s, call_args, blocked_ir, 0, prerequisite_failure);
            log_mcp_result_detail("blocked_prerequisite", seq, tool_name_s, call_args, blocked_ir, 0, prerequisite_failure);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        if (mcp_tool_requires_live_camoufox_bridge(tool_name_s)) {
            std::string bridge_reason;
            if (!ensure_mcp_camoufox_bridge_ready_for_tool(hf, tag, tool_name, failed, &bridge_reason)) {
                if (out_result) {
                    mcp_standalone::json data;
                    data["camoufox_bridge_blocked"] = true;
                    data["reason"] = bridge_reason;
                    data["status"] = camoufox_status_compact(aida::burp::camoufox::get_status());
                    *out_result = { false, bridge_reason, data };
                }
                log_msg(hf, tag, "FAIL -- \"%s\" blocked before dispatch because Camoufox bridge proof failed: %s",
                    tool_name ? tool_name : "<null>",
                    bridge_reason.empty() ? "<empty>" : compact_text(bridge_reason, 900).c_str());
                return mcp_tool_call_status_t::failed;
            }
        }
        std::unique_ptr<scoped_camoufox_testlab_launch_t> camoufox_launch_scope;
        if (tool_name_s == "browser_lifecycle" && call_args.is_object() && call_args.value("action", std::string()) == "launch") {
            camoufox_launch_scope = std::make_unique<scoped_camoufox_testlab_launch_t>();
            if (call_args.is_object()) {
                int requested_launch_timeout = static_cast<int>(k_camoufox_testlab_launch_timeout_ms);
                auto timeout_it = call_args.find("launch_timeout_ms");
                if (timeout_it != call_args.end()) {
                    if (timeout_it->is_number_integer() || timeout_it->is_number_unsigned())
                        requested_launch_timeout = timeout_it->get<int>();
                    else if (timeout_it->is_number_float())
                        requested_launch_timeout = static_cast<int>(timeout_it->get<double>());
                }
                if (requested_launch_timeout <= 0 || requested_launch_timeout > static_cast<int>(k_camoufox_testlab_launch_timeout_ms))
                    requested_launch_timeout = static_cast<int>(k_camoufox_testlab_launch_timeout_ms);
                call_args["launch_timeout_ms"] = requested_launch_timeout;
                call_args["aida_testlab_fast_probe"] = true;
            }
            log_msg(hf, tag, "CAMOUFOX-FAST-LAUNCH -- \"%s\" fail_fast=1 cap_ms=%lu watchdog_ms=%lld",
                tool_name ? tool_name : "<null>",
                static_cast<unsigned long>(k_camoufox_testlab_launch_timeout_ms),
                k_camoufox_testlab_launch_watchdog_ms);
        }
        const long long timeout_ms = tool_timeout_ms(tool_name_s);
        log_msg(hf, tag, "DISPATCH -- \"%s\" watchdog=%lld ms", tool_name, timeout_ms);
        auto timed = invoke_tool_bounded(srv, tool_name_s, call_args, timeout_ms, hf, tag, seq);
        auto ir = std::move(timed.result);
        if (out_result)
            *out_result = { ir.success, ir.text, ir.data };
        auto ms = timed.elapsed_ms;
        auto restore_after_mutation = [&]() {
            if (live_target_required || target_context_may_change)
                restore_mcp_target(hf, tag);
        };
        if (timed.timed_out) {
            if (out_result) {
                mcp_standalone::json timeout_data;
                timeout_data["tool"] = tool_name_s;
                timeout_data["timeout_ms"] = timeout_ms;
                timeout_data["worker_started"] = timed.worker_started;
                timeout_data["handler_entered"] = timed.handler_entered;
                timeout_data["handler_exited"] = timed.handler_exited;
                timeout_data["worker_pid"] = timed.worker_pid;
                timeout_data["worker_tid"] = timed.worker_tid;
                timeout_data["queue_delay_ms"] = timed.queue_delay_ms;
                timeout_data["worker_phase"] = timed.worker_phase;
                *out_result = { false, std::string("watchdog timeout in Test Lab runner for ") + tool_name_s, timeout_data };
            }
            log_msg(hf, tag, "FAIL -- \"%s\" timed out after %lld ms; worker_started=%d queue_delay_ms=%lld",
                tool_name, timeout_ms, timed.worker_started ? 1 : 0, timed.queue_delay_ms);
            log_mcp_timeout_detail(seq, tool_name_s, call_args, timeout_ms, timed.worker_started, timed.queue_delay_ms);
            log_msg(hf, tag, "TIMEOUT-CLEANUP -- \"%s\" cancel begin", tool_name);
            cancel_timed_out_tool(hf, tag, tool_name_s);
            log_msg(hf, tag, "TIMEOUT-CLEANUP -- \"%s\" restore begin", tool_name);
            restore_after_mutation();
            log_msg(hf, tag, "TIMEOUT-CLEANUP -- \"%s\" complete", tool_name);
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
                log_msg(hf, tag, "FAIL -- tool \"%s\" threw during required precondition fixture: %s (elapsed %lld ms)",
                    tool_name, ir.exception_msg.c_str(), (long long)ms);
                log_mcp_result_detail("failed_precondition_exception", seq, tool_name_s, call_args, ir, ms, ir.exception_msg);
                restore_after_mutation();
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return mcp_tool_call_status_t::failed;
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

        if (g_mcp_target_pid != 0 && tool_uses_live_target(tool_name_s)) {
            uint32_t post_exit_code = 0;
            const bool win32_alive = process_alive_by_pid(g_mcp_target_pid, &post_exit_code);
            const uint32_t active_before_restore = driver_bridge::attached_pid();
            bool restore_ok = active_before_restore == g_mcp_target_pid;
            if (!win32_alive || !restore_ok)
                restore_ok = restore_mcp_target(hf, tag);
            uint32_t driver_exit_code = 0;
            const bool bridge_alive = driver_bridge::attached_pid() == g_mcp_target_pid &&
                driver_bridge::attached_process_alive(&driver_exit_code);
            log_msg(hf, tag, "LIVENESS -- \"%s\" post-call pid=%u win32_alive=%d win32_code=0x%08X active_before=%u restore_ok=%d active_after=%u bridge_alive=%d bridge_code=0x%08X",
                tool_name,
                g_mcp_target_pid,
                win32_alive ? 1 : 0,
                post_exit_code,
                active_before_restore,
                restore_ok ? 1 : 0,
                driver_bridge::attached_pid(),
                bridge_alive ? 1 : 0,
                driver_exit_code);
            if (!win32_alive && bridge_alive) {
                g_mcp_target_unavailable = false;
                log_msg(hf, tag, "INFO -- \"%s\" post-tool Win32 liveness probe was inconclusive pid=%u exit_code_or_err=0x%08X; driver bridge confirms target alive exit_code=0x%08X",
                    tool_name, g_mcp_target_pid, post_exit_code, driver_exit_code);
            } else if (!win32_alive || !restore_ok || !bridge_alive) {
                g_mcp_target_unavailable = true;
                log_msg(hf, tag, "FAIL -- \"%s\" ended or detached MCP target pid=%u win32_alive=%d exit_code_or_err=0x%08X restore_ok=%d bridge_alive=%d bridge_code=0x%08X (elapsed %lld ms) -> %s",
                    tool_name,
                    g_mcp_target_pid,
                    win32_alive ? 1 : 0,
                    post_exit_code,
                    restore_ok ? 1 : 0,
                    bridge_alive ? 1 : 0,
                    driver_exit_code,
                    (long long)ms,
                    preview.c_str());
                log_mcp_result_detail("failed_target_exit", seq, tool_name_s, call_args, ir, ms,
                    "target_exit=0x" + std::to_string(post_exit_code));
                restore_after_mutation();
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return mcp_tool_call_status_t::failed;
            }
        }

        std::string payload_failure;
        bool payload_failed = false;
        long long payload_validation_ms = 0;
        if (ir.success) {
            const auto payload_validation_start = std::chrono::steady_clock::now();
            log_msg(hf, tag, "VALIDATE-PAYLOAD -- \"%s\" begin data_type=%s text_len=%zu",
                tool_name,
                ir.data.type_name(),
                ir.text.size());
            payload_failed = tool_payload_failure_reason(tool_name_s, ir, payload_failure);
            payload_validation_ms = static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - payload_validation_start).count());
            std::string payload_failure_preview = payload_failure;
            if (sensitive_log_tool(tool_name_s))
                payload_failure_preview = "<redacted reason len=" + std::to_string(payload_failure.size()) + ">";
            else
                payload_failure_preview = compact_text(std::move(payload_failure_preview), 260);
            log_msg(hf, tag, "VALIDATE-PAYLOAD -- \"%s\" complete elapsed_ms=%lld failed=%d reason=%s",
                tool_name,
                payload_validation_ms,
                payload_failed ? 1 : 0,
                payload_failure_preview.c_str());
            diag::log_tagged_fmt("test_all_mcp",
                "payload validation seq=%d tool=%s elapsed_ms=%lld failed=%d data_type=%s text_len=%zu reason_len=%zu",
                seq,
                tool_name_s.c_str(),
                payload_validation_ms,
                payload_failed ? 1 : 0,
                ir.data.type_name(),
                ir.text.size(),
                payload_failure.size());
        }
        if (ir.success && payload_failed) {
            log_msg(hf, tag, "FAIL -- \"%s\" success=true but payload reports failure: %s (elapsed %lld ms) -> %s",
                tool_name, payload_failure.c_str(), (long long)ms, preview.c_str());
            log_mcp_validation_detail(hf, tag, "failed_payload", seq, tool_name_s, call_args, ir, ms, payload_failure);
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
                log_msg(hf, tag, "FAIL -- \"%s\" returned error during required precondition fixture: %s (elapsed %lld ms)",
                    tool_name, preview.c_str(), (long long)ms);
                log_mcp_result_detail("failed_precondition_error", seq, tool_name_s, call_args, ir, ms, preview);
                record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                restore_after_mutation();
                return mcp_tool_call_status_t::failed;
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


    mcp_tool_call_status_t test_tool_action_call(HANDLE hf, const char* tag, const char* tool_name, const char* action,
                                                 mcp_standalone::json args,
                                                 std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped,
                                                 bool skip_on_error = false,
                                                 mcp_standalone::tool_result_t* out_result = nullptr)
    {
        if (!args.is_object())
            args = mcp_standalone::json::object();
        args["action"] = action ? action : "";
        return test_tool_call(hf, tag, get_server(), tool_name, args, passed, failed, skipped, skip_on_error, out_result);
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

    void seed_mcp_xref_to_region_fixture(uint64_t target_addr, uint64_t from_addr, const char* module_name, const char* text) {
        if (target_addr == 0 || from_addr == 0)
            return;
        xref_db::module_index_t mod;
        mod.name = module_name && *module_name ? module_name : "aida_mcp_region_xref_fixture";
        mod.base = from_addr & ~0xFFFULL;
        mod.size = 0x2000;
        mod.timestamp = static_cast<uint64_t>(
            std::chrono::system_clock::now().time_since_epoch().count());
        mod.total_xrefs = 1;
        mod.built = true;

        xref_db::xref_entry_t entry;
        entry.from_addr = from_addr;
        entry.to_addr = target_addr;
        entry.type = xref_engine::xref_type_t::data_ref;
        entry.disasm_text = text && *text ? text : "lea rcx, [aida_mcp_fixture_string]";
        mod.to_index[target_addr].push_back(entry);
        mod.from_index[from_addr].push_back(entry);

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

    std::string mcp_workspace_file_fixture() {
        return "aida_mcp_test_write.txt";
    }

    std::string mcp_workspace_dir_fixture() {
        return "aida_mcp_test_dir";
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

    std::string path_to_utf8(const std::filesystem::path& path) {
        return wide_to_utf8(path.wstring());
    }

    void add_test_target_candidates(std::vector<std::filesystem::path>& candidates, const std::filesystem::path& root) {
        if (root.empty())
            return;
        candidates.push_back(root / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"Release" / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"Debug" / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"RelWithDebInfo" / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"build-ninja" / L"Release" / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"build" / L"Release" / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"test_target" / L"AiDA_TestTarget.exe");
        candidates.push_back(root / L"src" / L"standalone" / L"test_target" / L"AiDA_TestTarget.exe");
    }

    std::string find_sessions_manage_run_binary_target(HANDLE hf) {
        const char* tag = "mcp.sessions_manage.run_binary.target";
        std::vector<std::filesystem::path> candidates;

        wchar_t env_buf[32768] = {};
        const DWORD env_cap = static_cast<DWORD>(sizeof(env_buf) / sizeof(env_buf[0]));
        DWORD env_len = GetEnvironmentVariableW(L"AIDA_TEST_TARGET", env_buf, env_cap);
        if (env_len > 0 && env_len < env_cap)
            candidates.emplace_back(env_buf);
        else
            log_msg(hf, tag, "probe[AIDA_TEST_TARGET] env var not set");

        wchar_t self_w[MAX_PATH] = {};
        DWORD self_len = GetModuleFileNameW(nullptr, self_w, MAX_PATH);
        if (self_len > 0 && self_len < MAX_PATH) {
            std::filesystem::path module_dir = std::filesystem::path(self_w).parent_path();
            add_test_target_candidates(candidates, module_dir);
            add_test_target_candidates(candidates, module_dir.parent_path());
        } else {
            log_msg(hf, tag, "probe[module_dir] GetModuleFileNameW failed gle=0x%08lX", static_cast<unsigned long>(GetLastError()));
        }

        std::error_code ec;
        std::filesystem::path cwd = std::filesystem::current_path(ec);
        if (!ec) {
            add_test_target_candidates(candidates, cwd);
            add_test_target_candidates(candidates, cwd.parent_path());
        } else {
            log_msg(hf, tag, "probe[cwd] current_path failed ec=%d msg=%s", ec.value(), ec.message().c_str());
        }

        const std::filesystem::path legacy = L"C:\\Users\\ruar1337\\AiDAPrivate\\build-ninja\\Release\\AiDA_TestTarget.exe";
        candidates.push_back(legacy);

        std::set<std::wstring> seen;
        for (const auto& candidate : candidates) {
            if (candidate.empty())
                continue;
            std::filesystem::path normalized = candidate.lexically_normal();
            std::wstring key = normalized.wstring();
            std::transform(key.begin(), key.end(), key.begin(), [](wchar_t c) {
                return static_cast<wchar_t>(std::towlower(c));
            });
            if (!seen.insert(key).second)
                continue;

            ec.clear();
            bool exists = std::filesystem::exists(normalized, ec) && !ec;
            bool regular = exists && std::filesystem::is_regular_file(normalized, ec) && !ec;
            const std::string path = path_to_utf8(normalized);
            log_msg(hf, tag, "probe %s -> %s", path.c_str(), regular ? "EXISTS" : (exists ? "not-file" : "missing"));
            diag::log_tagged_fmt("test_all", "sessions_manage run_binary target probe %s -> %s",
                path.c_str(), regular ? "EXISTS" : (exists ? "not-file" : "missing"));
            if (regular)
                return path;
        }

        log_msg(hf, tag, "FAIL -- AiDA_TestTarget.exe not found in session-run candidate paths");
        return {};
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

    std::set<DWORD> process_ids_by_image_name(const wchar_t* image_name) {
        std::set<DWORD> out;
        if (!image_name || !*image_name)
            return out;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return out;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, image_name) == 0)
                    out.insert(pe.th32ProcessID);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return out;
    }

    void terminate_fixture_process_pid(HANDLE hf, const char* tag, DWORD pid, const char* reason) {
        if (pid == 0)
            return;
        HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) {
            DWORD err = GetLastError();
            log_msg(hf, tag, "CLEANUP -- unable to open fixture process pid=%lu reason=%s err=%lu text=%s",
                static_cast<unsigned long>(pid),
                reason ? reason : "<empty>",
                static_cast<unsigned long>(err),
                format_win32_error(err).c_str());
            return;
        }
        DWORD exit_code = 0;
        if (GetExitCodeProcess(h, &exit_code) && exit_code == STILL_ACTIVE) {
            log_msg(hf, tag, "CLEANUP -- terminating fixture process pid=%lu reason=%s",
                static_cast<unsigned long>(pid),
                reason ? reason : "<empty>");
            TerminateProcess(h, 0xA1DA);
            WaitForSingleObject(h, 5000);
        }
        CloseHandle(h);
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
                DWORD probe_exit = 0;
                const BOOL probe_ok = proc.process ? GetExitCodeProcess(proc.process, &probe_exit) : FALSE;
                const DWORD probe_err = probe_ok ? 0 : GetLastError();
                log_msg(hf, tag, "FAIL -- sidecar done timeout after %lu ms",
                    static_cast<unsigned long>(timeout_ms));
                log_msg(hf, tag, "DONE-TIMEOUT-DIAG -- pid=%lu process=%p probe_ok=%d probe_err=%lu probe_text=%s probe_exit=0x%08lX output_len=%zu pending_len=%zu ready_event=%p go_event=%p done_event=%p",
                    static_cast<unsigned long>(proc.pid),
                    proc.process,
                    probe_ok ? 1 : 0,
                    static_cast<unsigned long>(probe_err),
                    probe_ok ? "success" : format_win32_error(probe_err).c_str(),
                    probe_ok ? static_cast<unsigned long>(probe_exit) : 0UL,
                    proc.output.size(),
                    proc.pending_line.size(),
                    proc.ready_event,
                    proc.go_event,
                    proc.done_event);
                return STILL_ACTIVE;
            }
        }
    }

    void close_network_hook_sidecar(HANDLE hf, const char* tag, network_hook_sidecar_proc_t& proc, bool force) {
        const uint64_t start = GetTickCount64();
        log_msg(hf, tag, "CLEANUP -- sidecar close begin pid=%lu force=%d process=%p thread=%p stdout_read=%p stdout_write=%p ready_event=%p go_event=%p done_event=%p output_len=%zu pending_len=%zu",
            static_cast<unsigned long>(proc.pid),
            force ? 1 : 0,
            proc.process,
            proc.thread,
            proc.stdout_read,
            proc.stdout_write,
            proc.ready_event,
            proc.go_event,
            proc.done_event,
            proc.output.size(),
            proc.pending_line.size());
        if (proc.process) {
            DWORD exit_code = 0;
            BOOL exit_ok = GetExitCodeProcess(proc.process, &exit_code);
            DWORD exit_err = exit_ok ? 0 : GetLastError();
            log_msg(hf, tag, "CLEANUP -- sidecar exit probe before pid=%lu ok=%d err=%lu text=%s exit=0x%08lX",
                static_cast<unsigned long>(proc.pid),
                exit_ok ? 1 : 0,
                static_cast<unsigned long>(exit_err),
                exit_ok ? "success" : format_win32_error(exit_err).c_str(),
                exit_ok ? static_cast<unsigned long>(exit_code) : 0UL);
            if (exit_ok && exit_code == STILL_ACTIVE && force) {
                SetLastError(0);
                const BOOL term_ok = TerminateProcess(proc.process, 0xA1DA);
                const DWORD term_err = term_ok ? 0 : GetLastError();
                log_msg(hf, tag, "CLEANUP -- sidecar terminate pid=%lu ok=%d err=%lu text=%s",
                    static_cast<unsigned long>(proc.pid),
                    term_ok ? 1 : 0,
                    static_cast<unsigned long>(term_err),
                    term_ok ? "success" : format_win32_error(term_err).c_str());
                const uint64_t wait_start = GetTickCount64();
                const DWORD wait_ms = term_ok ? 1500UL : 0UL;
                const DWORD wait_result = WaitForSingleObject(proc.process, wait_ms);
                const DWORD wait_err = wait_result == WAIT_FAILED ? GetLastError() : 0;
                DWORD exit_after = 0;
                const BOOL exit_after_ok = GetExitCodeProcess(proc.process, &exit_after);
                const DWORD exit_after_err = exit_after_ok ? 0 : GetLastError();
                log_msg(hf, tag, "CLEANUP -- sidecar terminate wait pid=%lu wait_ms=%lu result=0x%08lX err=%lu text=%s elapsed_ms=%llu exit_ok=%d exit_err=%lu exit_text=%s exit=0x%08lX",
                    static_cast<unsigned long>(proc.pid),
                    static_cast<unsigned long>(wait_ms),
                    static_cast<unsigned long>(wait_result),
                    static_cast<unsigned long>(wait_err),
                    wait_result == WAIT_FAILED ? format_win32_error(wait_err).c_str() : "success",
                    static_cast<unsigned long long>(GetTickCount64() - wait_start),
                    exit_after_ok ? 1 : 0,
                    static_cast<unsigned long>(exit_after_err),
                    exit_after_ok ? "success" : format_win32_error(exit_after_err).c_str(),
                    exit_after_ok ? static_cast<unsigned long>(exit_after) : 0UL);
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
        log_msg(hf, tag, "CLEANUP -- sidecar close end pid=%lu force=%d elapsed_ms=%llu output_len=%zu pending_len=%zu",
            static_cast<unsigned long>(proc.pid),
            force ? 1 : 0,
            static_cast<unsigned long long>(GetTickCount64() - start),
            proc.output.size(),
            proc.pending_line.size());
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
        auto timed = invoke_tool_bounded(get_server(), tool, args, timeout_ms, hf, tag, seq);
        out.timed_out = timed.timed_out;
        out.result = std::move(timed.result);
        out.elapsed_ms = timed.elapsed_ms;
        if (out.timed_out) {
            log_msg(hf, tag, "%s -- #%d %s timed out after %lld ms",
                required ? "FAIL" : "WARN", seq, tool.c_str(), timeout_ms);
            log_mcp_result_detail("sidecar_timeout", seq, tool, args, out.result, timeout_ms, "watchdog_timeout");
            cancel_timed_out_tool(hf, tag, tool);
            record_tool_status(tool, required ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
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
            mcp_tool_call_status_t::failed);
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

        auto cleanup_tool = [&](const char* phase,
                                const std::string& tool,
                                const mcp_standalone::json& args,
                                long long timeout_ms) {
            log_msg(hf, tag, "CLEANUP-TOOL-BEGIN -- phase=%s tool=%s timeout_ms=%lld args=%s",
                phase ? phase : "unspecified",
                tool.c_str(),
                timeout_ms,
                compact_json(args, 1000).c_str());
            auto call = invoke_sidecar_tool(hf, tag, tool, args, timeout_ms, false);
            log_msg(hf, tag, "CLEANUP-TOOL-END -- phase=%s tool=%s ok=%d timeout=%d elapsed=%lld found=%d success=%d threw=%d text=%s data=%s",
                phase ? phase : "unspecified",
                tool.c_str(),
                call.ok ? 1 : 0,
                call.timed_out ? 1 : 0,
                call.elapsed_ms,
                call.result.found ? 1 : 0,
                call.result.success ? 1 : 0,
                call.result.threw ? 1 : 0,
                compact_text(call.result.threw ? call.result.exception_msg : call.result.text, 900).c_str(),
                compact_json(call.result.data, 1200).c_str());
            return call;
        };

        auto cleanup = [&](bool force_sidecar, const char* reason) {
            const uint64_t cleanup_start = GetTickCount64();
            const auto cq_begin = critical_work_queue::stats();
            log_msg(hf, tag, "CLEANUP-BEGIN -- reason=%s force_sidecar=%d launched=%d signaled_go=%d page_guard_session=%u pid=%lu previous_pid=%u active_pid=%u cq_alive=%d cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
                reason ? reason : "unspecified",
                force_sidecar ? 1 : 0,
                launched ? 1 : 0,
                signaled_go ? 1 : 0,
                page_guard_session,
                static_cast<unsigned long>(proc.pid),
                previous_pid,
                driver_bridge::attached_pid(),
                cq_begin.alive ? 1 : 0,
                cq_begin.pending,
                static_cast<unsigned>(cq_begin.active),
                static_cast<unsigned long long>(cq_begin.started),
                static_cast<unsigned long long>(cq_begin.finished));
            log_timed_out_invocations(hf, tag, "sidecar_cleanup_begin");
            if (force_sidecar && launched) {
                close_network_hook_sidecar(hf, tag, proc, true);
                launched = false;
            }
            const long long cleanup_timeout = force_sidecar ? 5000LL : 15000LL;
            const long long clear_timeout = force_sidecar ? 5000LL : 10000LL;
            if (page_guard_session != 0) {
                mcp_standalone::json args;
                args["operation"] = "uninstall";
                args["session_id"] = page_guard_session;
                cleanup_tool("page_guard_uninstall", "network_pg_sniff", args, cleanup_timeout);
                page_guard_session = 0;
            }
            {
                mcp_standalone::json args;
                args["operation"] = "unhook_all";
                cleanup_tool("pre_encrypt_unhook_all", "network_pre_encrypt_hook", args, cleanup_timeout);
            }
            {
                mcp_standalone::json args;
                args["operation"] = "clear";
                cleanup_tool("pre_encrypt_clear", "network_pre_encrypt_hook", args, clear_timeout);
            }
            if (previous_pid != 0) {
                const bool restored = driver_bridge::set_active_pid(previous_pid);
                log_msg(hf, tag, "CLEANUP -- restore active pid previous=%u ok=%d current=%u status=%s error=%s",
                    previous_pid,
                    restored ? 1 : 0,
                    driver_bridge::attached_pid(),
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
            } else {
                driver_bridge::clear_active_pid();
                log_msg(hf, tag, "CLEANUP -- cleared active pid current=%u status=%s error=%s",
                    driver_bridge::attached_pid(),
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
            }
            if (launched) {
                close_network_hook_sidecar(hf, tag, proc, force_sidecar);
                launched = false;
            }
            const auto cq_end = critical_work_queue::stats();
            log_timed_out_invocations(hf, tag, "sidecar_cleanup_end");
            log_msg(hf, tag, "CLEANUP-END -- reason=%s elapsed_ms=%llu cq_alive=%d cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
                reason ? reason : "unspecified",
                static_cast<unsigned long long>(GetTickCount64() - cleanup_start),
                cq_end.alive ? 1 : 0,
                cq_end.pending,
                static_cast<unsigned>(cq_end.active),
                static_cast<unsigned long long>(cq_end.started),
                static_cast<unsigned long long>(cq_end.finished));
        };

        auto fail_case = [&](const std::string& reason) {
            log_msg(hf, tag, "FAIL-CASE-BEGIN -- reason=%s launched=%d signaled_go=%d page_guard_session=%u pid=%lu",
                reason.c_str(),
                launched ? 1 : 0,
                signaled_go ? 1 : 0,
                page_guard_session,
                static_cast<unsigned long>(proc.pid));
            log_msg(hf, tag, "FAIL -- %s", reason.c_str());
            cleanup(true, reason.c_str());
            log_msg(hf, tag, "FAIL-CASE-END -- reason=%s", reason.c_str());
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

        std::string pg_aggregate;
        sidecar_capture_coverage_t pg_coverage;
        const size_t required_pg_iterations = protected_mode ? 2 : 3;
        const bool pg_seen = wait_page_guard_marker_coverage(hf, tag, page_guard_session, "AIDA_PG_SNIFF_DETERMINISTIC_BUFFER", required_pg_iterations, 20000, pg_aggregate, pg_coverage);

        const DWORD sidecar_done_timeout_ms = protected_mode ? (pg_seen ? 30000UL : 8000UL) : 90000UL;
        log_msg(hf, tag, "DONE-WAIT-BEGIN -- timeout_ms=%lu protected=%d pg_seen=%d captures=%zu iterations=%zu output_len=%zu",
            static_cast<unsigned long>(sidecar_done_timeout_ms),
            protected_mode ? 1 : 0,
            pg_seen ? 1 : 0,
            pg_coverage.captures,
            pg_coverage.iterations.size(),
            proc.output.size());
        DWORD sidecar_exit = wait_network_hook_sidecar_done(hf, tag, proc, sidecar_done_timeout_ms);
        log_msg(hf, tag, "DONE-WAIT-END -- exit=0x%08lX still_active=%d output_len=%zu pending_len=%zu",
            static_cast<unsigned long>(sidecar_exit),
            sidecar_exit == STILL_ACTIVE ? 1 : 0,
            proc.output.size(),
            proc.pending_line.size());
        if (sidecar_exit == STILL_ACTIVE) {
            log_msg(hf, tag, "DONE-WAIT-TIMEOUT-RETURN -- entering failure path");
            return fail_case("sidecar did not complete after Go event");
        }

        std::string pre_send_aggregate;
        std::string pre_wsasend_aggregate;
        sidecar_capture_coverage_t pre_send_coverage;
        sidecar_capture_coverage_t pre_wsasend_coverage;
        const bool pre_send = wait_pre_encrypt_marker_coverage(hf, tag, "AIDA_PRE_ENCRYPT_SEND", 12, 10000, pre_send_aggregate, pre_send_coverage);
        const bool pre_wsasend = wait_pre_encrypt_marker_coverage(hf, tag, "AIDA_PRE_ENCRYPT_WSASEND_A", 12, 10000, pre_wsasend_aggregate, pre_wsasend_coverage);
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

        cleanup(false, "pass");
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

    int hex_digit_value(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    }

    std::string fixture_url_decode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (c == '+') {
                out.push_back(' ');
            } else if (c == '%' && i + 2 < s.size()) {
                int hi = hex_digit_value(s[i + 1]);
                int lo = hex_digit_value(s[i + 2]);
                if (hi >= 0 && lo >= 0) {
                    out.push_back(static_cast<char>((hi << 4) | lo));
                    i += 2;
                } else {
                    out.push_back(c);
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    std::string fixture_html_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c); break;
            }
        }
        return out;
    }

    std::string fixture_query_value(const std::string& req, const char* key) {
        if (!key)
            return {};
        size_t line_end = req.find("\r\n");
        if (line_end == std::string::npos)
            return {};
        size_t sp1 = req.find(' ');
        if (sp1 == std::string::npos || sp1 >= line_end)
            return {};
        size_t sp2 = req.find(' ', sp1 + 1);
        if (sp2 == std::string::npos || sp2 >= line_end)
            return {};
        std::string uri = req.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t q = uri.find('?');
        if (q == std::string::npos)
            return {};
        std::string target = key;
        size_t pos = q + 1;
        while (pos <= uri.size()) {
            size_t amp = uri.find('&', pos);
            size_t end = amp == std::string::npos ? uri.size() : amp;
            size_t eq = uri.find('=', pos);
            if (eq != std::string::npos && eq < end) {
                std::string name = fixture_url_decode(uri.substr(pos, eq - pos));
                if (name == target)
                    return fixture_url_decode(uri.substr(eq + 1, end - eq - 1));
            }
            if (amp == std::string::npos)
                break;
            pos = amp + 1;
        }
        return {};
    }

    std::string fixture_request_query(const std::string& req) {
        size_t line_end = req.find("\r\n");
        if (line_end == std::string::npos)
            return {};
        size_t sp1 = req.find(' ');
        if (sp1 == std::string::npos || sp1 >= line_end)
            return {};
        size_t sp2 = req.find(' ', sp1 + 1);
        if (sp2 == std::string::npos || sp2 >= line_end)
            return {};
        std::string uri = req.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t q = uri.find('?');
        if (q == std::string::npos)
            return {};
        return uri.substr(q + 1);
    }

    std::string fixture_header_safe(std::string s) {
        for (char& c : s) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc < 0x20 || uc == 0x7F)
                c = '_';
        }
        if (s.size() > 512)
            s.resize(512);
        return s;
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
        if (integrity_hunter::g_state.hunting.load() || integrity_hunter::g_state.worker_active.load()) {
            log_msg(hf, tag, "live-monitor cleanup waiting for integrity hunter hunting=%d worker=%d install_complete=%d install_success=%d",
                integrity_hunter::g_state.hunting.load() ? 1 : 0,
                integrity_hunter::g_state.worker_active.load() ? 1 : 0,
                integrity_hunter::g_state.install_complete.load() ? 1 : 0,
                integrity_hunter::g_state.install_success.load() ? 1 : 0);
            integrity_hunter::stop_hunt();
            const bool idle = integrity_hunter::wait_until_idle(12000);
            log_msg(hf, tag, "live-monitor cleanup integrity_hunter_idle=%d", idle ? 1 : 0);
            if (!idle) {
                log_msg(hf, tag, "live-monitor cleanup skipped frees because integrity hunter worker is still active");
                return;
            }
        }
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

    struct mcp_hunt_sidecar_t {
        HANDLE process = nullptr;
        HANDLE thread = nullptr;
        DWORD pid = 0;
        std::wstring exe;
        std::wstring command;
        std::wstring workdir;
    };

    bool hunt_sidecar_exited(const mcp_hunt_sidecar_t& sidecar, DWORD& exit_code) {
        exit_code = 0;
        if (!sidecar.process)
            return true;
        if (!GetExitCodeProcess(sidecar.process, &exit_code))
            return true;
        return exit_code != STILL_ACTIVE;
    }

    bool launch_hunt_integrity_sidecar(HANDLE hf, const char* tag, mcp_hunt_sidecar_t& sidecar) {
        wchar_t sys_dir[MAX_PATH] = {};
        UINT sys_len = GetSystemDirectoryW(sys_dir, MAX_PATH);
        if (sys_len == 0 || sys_len >= MAX_PATH) {
            DWORD err = GetLastError();
            log_msg(hf, tag, "FAIL -- hunt sidecar GetSystemDirectoryW failed err=%lu text=%s",
                static_cast<unsigned long>(err), format_win32_error(err).c_str());
            return false;
        }

        std::filesystem::path cmd_path = std::filesystem::path(sys_dir) / L"cmd.exe";
        std::error_code ec;
        if (!std::filesystem::exists(cmd_path, ec) || ec) {
            log_msg(hf, tag, "FAIL -- hunt sidecar cmd.exe not found path=%s ec=%d msg=%s",
                path_to_utf8(cmd_path).c_str(), ec.value(), ec.message().c_str());
            return false;
        }

        sidecar.exe = extended_path_wide(full_path_wide(cmd_path.wstring()));
        std::filesystem::path workdir_path = cmd_path.parent_path();
        sidecar.workdir = full_path_wide(workdir_path.wstring());
        std::wstring workdir_create = sidecar.workdir.size() >= MAX_PATH ? extended_path_wide(sidecar.workdir) : sidecar.workdir;
        std::wstring args = L" /d /c ping -n 30 127.0.0.1 > nul";
        sidecar.command = quote_arg_wide(sidecar.exe) + args;

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::vector<wchar_t> command_mutable(sidecar.command.begin(), sidecar.command.end());
        command_mutable.push_back(L'\0');
        SetLastError(0);
        BOOL ok = CreateProcessW(sidecar.exe.c_str(),
            command_mutable.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            workdir_create.empty() ? nullptr : workdir_create.c_str(),
            &si,
            &pi);
        DWORD err = ok ? 0 : GetLastError();
        log_msg(hf, tag, "SIDE-FIXTURE-LAUNCH -- app=%s cmd=%s cwd=%s ok=%d err=%lu text=%s",
            wide_to_utf8(sidecar.exe).c_str(),
            compact_text(wide_to_utf8(sidecar.command), 900).c_str(),
            wide_to_utf8(workdir_create).c_str(),
            ok ? 1 : 0,
            static_cast<unsigned long>(err),
            ok ? "success" : format_win32_error(err).c_str());
        if (!ok)
            return false;

        sidecar.process = pi.hProcess;
        sidecar.thread = pi.hThread;
        sidecar.pid = pi.dwProcessId;
        log_msg(hf, tag, "SIDE-FIXTURE-LAUNCHED -- pid=%lu thread=%lu",
            static_cast<unsigned long>(sidecar.pid),
            static_cast<unsigned long>(pi.dwThreadId));
        return true;
    }

    bool wait_hunt_sidecar_attach_ready(HANDLE hf, const char* tag, const mcp_hunt_sidecar_t& sidecar, DWORD timeout_ms) {
        const DWORD started = GetTickCount();
        int attempts = 0;
        auto select_sidecar_quiet = [&]() {
            if (driver_bridge::attached_pid() == sidecar.pid)
                return true;
            bool known = false;
            for (uint32_t attached_pid : driver_bridge::attached_pids()) {
                if (attached_pid == sidecar.pid) {
                    known = true;
                    break;
                }
            }
            if (!known && !driver_bridge::attach_additional(sidecar.pid))
                return false;
            return driver_bridge::set_active_pid(sidecar.pid);
        };
        for (;;) {
            ++attempts;
            DWORD exit_code = 0;
            if (hunt_sidecar_exited(sidecar, exit_code)) {
                log_msg(hf, tag, "FAIL -- hunt sidecar exited before attach ready pid=%lu exit=0x%08lX attempts=%d elapsed_ms=%lu",
                    static_cast<unsigned long>(sidecar.pid),
                    static_cast<unsigned long>(exit_code),
                    attempts,
                    static_cast<unsigned long>(GetTickCount() - started));
                return false;
            }

            const bool selected = select_sidecar_quiet();
            const uint32_t active = driver_bridge::attached_pid();
            const uint64_t ntdll_base = selected ? find_remote_module_base_ci(sidecar.pid, "ntdll.dll") : 0;
            const uint64_t kernel32_base = selected ? find_remote_module_base_ci(sidecar.pid, "kernel32.dll") : 0;
            uint32_t bridge_code = 0;
            const bool bridge_alive = selected && active == sidecar.pid && driver_bridge::attached_process_alive(&bridge_code);
            if (selected && bridge_alive && ntdll_base != 0 && kernel32_base != 0) {
                log_msg(hf, tag, "SIDE-FIXTURE-READY -- pid=%lu attempts=%d active=%u ntdll=0x%016llX kernel32=0x%016llX bridge_code=0x%08X elapsed_ms=%lu",
                    static_cast<unsigned long>(sidecar.pid),
                    attempts,
                    active,
                    static_cast<unsigned long long>(ntdll_base),
                    static_cast<unsigned long long>(kernel32_base),
                    bridge_code,
                    static_cast<unsigned long>(GetTickCount() - started));
                return true;
            }

            const DWORD elapsed = GetTickCount() - started;
            if (attempts == 1 || (elapsed % 500) < 100) {
                log_msg(hf, tag, "SIDE-FIXTURE-WAIT -- pid=%lu attempt=%d selected=%d active=%u bridge_alive=%d bridge_code=0x%08X ntdll=0x%016llX kernel32=0x%016llX elapsed_ms=%lu",
                    static_cast<unsigned long>(sidecar.pid),
                    attempts,
                    selected ? 1 : 0,
                    active,
                    bridge_alive ? 1 : 0,
                    bridge_code,
                    static_cast<unsigned long long>(ntdll_base),
                    static_cast<unsigned long long>(kernel32_base),
                    static_cast<unsigned long>(elapsed));
            }
            if (elapsed >= timeout_ms) {
                log_msg(hf, tag, "FAIL -- hunt sidecar attach readiness timeout pid=%lu attempts=%d active=%u status=\"%s\" last_error=\"%s\"",
                    static_cast<unsigned long>(sidecar.pid),
                    attempts,
                    driver_bridge::attached_pid(),
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
                return false;
            }
            Sleep(100);
        }
    }

    void close_hunt_integrity_sidecar(HANDLE hf, const char* tag, mcp_hunt_sidecar_t& sidecar, bool force) {
        DWORD exit_code = 0;
        const bool exited = hunt_sidecar_exited(sidecar, exit_code);
        log_msg(hf, tag, "SIDE-FIXTURE-CLOSE -- begin pid=%lu force=%d exited=%d exit=0x%08lX active_pid=%u",
            static_cast<unsigned long>(sidecar.pid),
            force ? 1 : 0,
            exited ? 1 : 0,
            static_cast<unsigned long>(exit_code),
            driver_bridge::attached_pid());
        if (sidecar.process && !exited && force) {
            SetLastError(0);
            BOOL term_ok = TerminateProcess(sidecar.process, 0xA1DA);
            DWORD term_err = term_ok ? 0 : GetLastError();
            DWORD wait = WaitForSingleObject(sidecar.process, 1500);
            DWORD wait_err = wait == WAIT_FAILED ? GetLastError() : 0;
            DWORD exit_after = 0;
            BOOL exit_after_ok = GetExitCodeProcess(sidecar.process, &exit_after);
            DWORD exit_after_err = exit_after_ok ? 0 : GetLastError();
            log_msg(hf, tag, "SIDE-FIXTURE-CLOSE -- terminate pid=%lu ok=%d err=%lu text=%s wait=0x%08lX wait_err=%lu exit_ok=%d exit_err=%lu exit=0x%08lX",
                static_cast<unsigned long>(sidecar.pid),
                term_ok ? 1 : 0,
                static_cast<unsigned long>(term_err),
                term_ok ? "success" : format_win32_error(term_err).c_str(),
                static_cast<unsigned long>(wait),
                static_cast<unsigned long>(wait_err),
                exit_after_ok ? 1 : 0,
                static_cast<unsigned long>(exit_after_err),
                exit_after_ok ? static_cast<unsigned long>(exit_after) : 0UL);
        }
        close_handle_safe(sidecar.thread);
        close_handle_safe(sidecar.process);
        if (sidecar.pid != 0) {
            const bool detached = driver_bridge::detach_one(sidecar.pid);
            log_msg(hf, tag, "SIDE-FIXTURE-CLOSE -- detached pid=%lu ok=%d active_now=%u",
                static_cast<unsigned long>(sidecar.pid),
                detached ? 1 : 0,
                driver_bridge::attached_pid());
        }
        sidecar.pid = 0;
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

    struct mcp_trace_fixture_t {
        uint32_t tid = 0;
        uint32_t original_suspend_count = 0;
        uint64_t code = 0;
        uint64_t expected_rip = 0;
        size_t code_size = 0;
        driver_bridge::thread_context_t before{};
        bool prepared = false;
    };

    bool prepare_mcp_trace_fixture(HANDLE hf, const char* tag, mcp_trace_fixture_t& fx, int max_instructions) {
        if (!ensure_mcp_target_live(hf, tag))
            return false;
        if (!acquire_contextable_mcp_thread(hf, tag, "controlled trace fixture", fx.tid, fx.original_suspend_count, fx.before))
            return false;

        const size_t requested = max_instructions > 0 ? static_cast<size_t>(max_instructions) : 1u;
        fx.code_size = std::max<size_t>(64, requested + 16);
        fx.code = driver_bridge::allocate_memory(fx.code_size);
        bool ok = fx.code != 0;
        if (ok) {
            std::vector<uint8_t> code_bytes(fx.code_size, 0x90);
            if (code_bytes.size() >= 2) {
                code_bytes[code_bytes.size() - 2] = 0xEB;
                code_bytes[code_bytes.size() - 1] = 0xFE;
            }
            ok = driver_bridge::write_memory(fx.code, code_bytes);
        }
        if (ok) {
            uint32_t old_protect = 0;
            ok = driver_bridge::protect_memory(fx.code, fx.code_size, PAGE_EXECUTE_READWRITE, &old_protect);
        }
        if (ok) {
            auto ctx = fx.before;
            ctx.rip = fx.code;
            ctx.rflags &= ~0x100ULL;
            ok = driver_bridge::set_thread_context(fx.tid, ctx, ~0ULL);
            fx.expected_rip = fx.code + requested;
        }
        if (!ok) {
            (void)restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
            if (fx.code)
                driver_bridge::free_memory(fx.code);
            log_msg(hf, tag, "FAIL -- could not build controlled trace fixture tid=%u code=0x%llX size=%zu",
                fx.tid,
                static_cast<unsigned long long>(fx.code),
                fx.code_size);
            return false;
        }
        fx.prepared = true;
        log_msg(hf, tag, "INFO -- controlled trace fixture tid=%u entry=0x%llX expected=0x%llX size=%zu before_rip=0x%llX before_rsp=0x%llX before_rflags=0x%llX original_suspend=%u",
            fx.tid,
            static_cast<unsigned long long>(fx.code),
            static_cast<unsigned long long>(fx.expected_rip),
            fx.code_size,
            static_cast<unsigned long long>(fx.before.rip),
            static_cast<unsigned long long>(fx.before.rsp),
            static_cast<unsigned long long>(fx.before.rflags),
            fx.original_suspend_count);
        return true;
    }

    void cleanup_mcp_trace_fixture(HANDLE hf, const char* tag, const mcp_trace_fixture_t& fx) {
        bool restored = true;
        if (fx.tid != 0)
            restored = restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
        if (fx.code)
            driver_bridge::free_memory(fx.code);
        log_msg(hf, tag, "INFO -- controlled trace fixture cleanup tid=%u restored=%d code=0x%llX expected=0x%llX original_suspend=%u",
            fx.tid,
            restored ? 1 : 0,
            static_cast<unsigned long long>(fx.code),
            static_cast<unsigned long long>(fx.expected_rip),
            fx.original_suspend_count);
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

    struct mcp_run_to_address_fixture_t {
        uint32_t tid = 0;
        uint32_t original_suspend_count = 0;
        uint64_t code = 0;
        driver_bridge::thread_context_t before{};
        bool prepared = false;
    };

    bool prepare_mcp_run_to_address_fixture(HANDLE hf, const char* tag, mcp_run_to_address_fixture_t& fx) {
        if (!ensure_mcp_target_live(hf, tag))
            return false;
        if (!acquire_contextable_mcp_thread(hf, tag, "controlled run_to_address fixture", fx.tid, fx.original_suspend_count, fx.before))
            return false;
        fx.code = driver_bridge::allocate_memory(64);
        bool ok = fx.code != 0;
        uint32_t old_protect = 0;
        if (ok) {
            std::vector<uint8_t> code_bytes(64, 0x90);
            code_bytes.back() = 0xC3;
            ok = driver_bridge::write_memory(fx.code, code_bytes);
        }
        if (ok)
            ok = driver_bridge::protect_memory(fx.code, 64, PAGE_EXECUTE_READWRITE, &old_protect);
        if (ok) {
            auto ctx = fx.before;
            ctx.rip = fx.code;
            ctx.rflags &= ~0x100ULL;
            ok = driver_bridge::set_thread_context(fx.tid, ctx, ~0ULL);
            debugger_engine::g_state.active_tid = fx.tid;
        }
        driver_bridge::memory_region_t region{};
        const bool region_ok = fx.code != 0 && driver_bridge::query_memory(fx.code, region);
        if (!ok) {
            const bool restored = restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
            if (fx.code)
                driver_bridge::free_memory(fx.code);
            log_msg(hf, tag, "FAIL -- could not build controlled run_to_address fixture tid=%u code=0x%llX restored=%d region_ok=%d region_base=0x%llX region_size=0x%llX region_state=0x%08X region_protect=0x%08X old_protect=0x%08X",
                fx.tid,
                static_cast<unsigned long long>(fx.code),
                restored ? 1 : 0,
                region_ok ? 1 : 0,
                static_cast<unsigned long long>(region.base),
                static_cast<unsigned long long>(region.size),
                static_cast<unsigned>(region.state),
                static_cast<unsigned>(region.protect),
                static_cast<unsigned>(old_protect));
            return false;
        }
        fx.prepared = true;
        log_msg(hf, tag, "INFO -- controlled run_to_address fixture tid=%u entry=0x%llX before_rip=0x%llX before_rsp=0x%llX before_rflags=0x%llX original_suspend=%u region_ok=%d region_base=0x%llX region_size=0x%llX region_state=0x%08X region_protect=0x%08X old_protect=0x%08X",
            fx.tid,
            static_cast<unsigned long long>(fx.code),
            static_cast<unsigned long long>(fx.before.rip),
            static_cast<unsigned long long>(fx.before.rsp),
            static_cast<unsigned long long>(fx.before.rflags),
            fx.original_suspend_count,
            region_ok ? 1 : 0,
            static_cast<unsigned long long>(region.base),
            static_cast<unsigned long long>(region.size),
            static_cast<unsigned>(region.state),
            static_cast<unsigned>(region.protect),
            static_cast<unsigned>(old_protect));
        return true;
    }

    void cleanup_mcp_run_to_address_fixture(HANDLE hf, const char* tag, const mcp_run_to_address_fixture_t& fx) {
        bool restored = true;
        if (fx.tid != 0)
            restored = restore_mcp_thread_context(fx.tid, fx.before, fx.original_suspend_count);
        bool freed = true;
        if (fx.code)
            freed = driver_bridge::free_memory(fx.code);
        uint32_t exit_code = 0;
        const bool alive = driver_bridge::attached_process_alive(&exit_code);
        log_msg(hf, tag, "INFO -- controlled run_to_address fixture cleanup tid=%u code=0x%llX restored=%d freed=%d original_suspend=%u alive=%d exit_code=0x%08X",
            fx.tid,
            static_cast<unsigned long long>(fx.code),
            restored ? 1 : 0,
            freed ? 1 : 0,
            fx.original_suspend_count,
            alive ? 1 : 0,
            static_cast<unsigned>(exit_code));
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
                log_msg(hf, tag, "FAIL -- WSAStartup failed for loopback TCP tuple");
                return false;
            }
            wsa_started = true;

            listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                log_msg(hf, tag, "FAIL -- listener socket failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
                listen(listener, 1) == SOCKET_ERROR) {
                log_msg(hf, tag, "FAIL -- listener bind/listen failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            int addr_len = sizeof(addr);
            if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len) == SOCKET_ERROR) {
                log_msg(hf, tag, "FAIL -- listener getsockname failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }
            listen_port = ntohs(addr.sin_port);

            client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (client == INVALID_SOCKET) {
                log_msg(hf, tag, "FAIL -- client socket failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            if (connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                log_msg(hf, tag, "FAIL -- loopback connect failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            accepted = accept(listener, nullptr, nullptr);
            if (accepted == INVALID_SOCKET) {
                log_msg(hf, tag, "FAIL -- loopback accept failed err=%d", WSAGetLastError());
                close_all();
                return false;
            }

            sockaddr_in local = {};
            int local_len = sizeof(local);
            if (getsockname(client, reinterpret_cast<sockaddr*>(&local), &local_len) == SOCKET_ERROR) {
                log_msg(hf, tag, "FAIL -- client getsockname failed err=%d", WSAGetLastError());
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
        std::atomic<bool> stop{false};
        std::atomic<bool> worker_posted{false};
        std::atomic<bool> worker_entered{false};
        std::atomic<bool> worker_done{true};
        std::atomic<DWORD> worker_tid{0};
        std::atomic<uint64_t> accept_count{0};
        std::atomic<uint64_t> request_count{0};
        uint16_t port = 0;

        bool live() const {
            return listener != INVALID_SOCKET &&
                   port != 0 &&
                   worker_posted.load(std::memory_order_acquire) &&
                   !worker_done.load(std::memory_order_acquire);
        }

        bool start(HANDLE hf, const char* tag) {
            if (!ensure_mcp_winsock_ready()) {
                log_msg(hf, tag, "FAIL -- WSAStartup failed for Burp HTTP fixture");
                return false;
            }
            listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listener == INVALID_SOCKET) {
                log_msg(hf, tag, "FAIL -- fixture listener socket failed err=%d", WSAGetLastError());
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
                log_msg(hf, tag, "FAIL -- fixture bind/listen failed err=%d", WSAGetLastError());
                close();
                return false;
            }
            int addr_len = sizeof(addr);
            if (getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len) == SOCKET_ERROR) {
                log_msg(hf, tag, "FAIL -- fixture getsockname failed err=%d", WSAGetLastError());
                close();
                return false;
            }
            port = ntohs(addr.sin_port);
            stop.store(false, std::memory_order_release);
            worker_done.store(false, std::memory_order_release);
            worker_entered.store(false, std::memory_order_release);
            worker_posted.store(false, std::memory_order_release);
            worker_tid.store(0, std::memory_order_release);
            accept_count.store(0, std::memory_order_release);
            request_count.store(0, std::memory_order_release);
            DWORD thread_start_tick = GetTickCount();
            log_msg(hf, tag, "Burp HTTP fixture work_queue post requested port=%u listener=%llu target_pid=%u attached_pid=%u target_unavailable=%d driver_bridge_status=\"%s\" driver_last_error=\"%s\"",
                static_cast<unsigned>(port),
                static_cast<unsigned long long>(listener),
                g_mcp_target_pid,
                driver_bridge::attached_pid(),
                g_mcp_target_unavailable ? 1 : 0,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            bool posted = false;
            DWORD post_gle = ERROR_SUCCESS;
            try {
                posted = work_queue::post([this]() {
                    run_worker("work_queue");
                });
                post_gle = GetLastError();
            } catch (const std::exception& ex) {
                post_gle = GetLastError();
                if (post_gle == ERROR_SUCCESS)
                    post_gle = ERROR_NOT_ENOUGH_MEMORY;
                log_msg(hf, tag, "WARN -- fixture work_queue post exception err=%s gle=%lu port=%u listener=%llu worker_entered=%d worker_done=%d target_pid=%u attached_pid=%u target_unavailable=%d driver_bridge_status=\"%s\" driver_last_error=\"%s\"",
                    compact_text(ex.what(), 700).c_str(),
                    static_cast<unsigned long>(post_gle),
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(listener),
                    worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                    worker_done.load(std::memory_order_acquire) ? 1 : 0,
                    g_mcp_target_pid,
                    driver_bridge::attached_pid(),
                    g_mcp_target_unavailable ? 1 : 0,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
            } catch (...) {
                post_gle = GetLastError();
                if (post_gle == ERROR_SUCCESS)
                    post_gle = ERROR_NOT_ENOUGH_MEMORY;
                log_msg(hf, tag, "WARN -- fixture work_queue post exception err=unknown gle=%lu port=%u listener=%llu worker_entered=%d worker_done=%d target_pid=%u attached_pid=%u target_unavailable=%d driver_bridge_status=\"%s\" driver_last_error=\"%s\"",
                    static_cast<unsigned long>(post_gle),
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(listener),
                    worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                    worker_done.load(std::memory_order_acquire) ? 1 : 0,
                    g_mcp_target_pid,
                    driver_bridge::attached_pid(),
                    g_mcp_target_unavailable ? 1 : 0,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
            }
            if (!posted) {
                if (post_gle == ERROR_SUCCESS)
                    post_gle = ERROR_NOT_READY;
                DWORD elapsed = GetTickCount() - thread_start_tick;
                worker_done.store(true, std::memory_order_release);
                log_msg(hf, tag, "FAIL -- fixture work_queue post failed gle=%lu text=%s elapsed_ms=%lu port=%u listener=%llu worker_entered=%d worker_done=%d target_pid=%u attached_pid=%u target_unavailable=%d driver_bridge_status=\"%s\" driver_last_error=\"%s\"",
                    static_cast<unsigned long>(post_gle),
                    format_win32_error(post_gle).c_str(),
                    static_cast<unsigned long>(elapsed),
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(listener),
                    worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                    worker_done.load(std::memory_order_acquire) ? 1 : 0,
                    g_mcp_target_pid,
                    driver_bridge::attached_pid(),
                    g_mcp_target_unavailable ? 1 : 0,
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
                close();
                return false;
            }
            worker_posted.store(true, std::memory_order_release);
            for (int i = 0; i < 50 && !worker_entered.load(std::memory_order_acquire); ++i)
                Sleep(2);
            log_msg(hf, tag, "Burp HTTP fixture listening on 127.0.0.1:%u worker_tid=%lu worker_entered=%d start_elapsed_ms=%lu target_pid=%u attached_pid=%u",
                static_cast<unsigned>(port),
                static_cast<unsigned long>(worker_tid.load(std::memory_order_acquire)),
                worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(GetTickCount() - thread_start_tick),
                g_mcp_target_pid,
                driver_bridge::attached_pid());
            return port != 0;
        }

        void run_worker(const char* mode) {
            worker_tid.store(GetCurrentThreadId(), std::memory_order_release);
            worker_entered.store(true, std::memory_order_release);
            diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture worker entry mode=%s port=%u tid=%lu listener=%llu",
                mode ? mode : "",
                static_cast<unsigned>(port),
                static_cast<unsigned long>(GetCurrentThreadId()),
                static_cast<unsigned long long>(listener));
            const DWORD start = GetTickCount();
            try {
                run();
            } catch (const std::exception& ex) {
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture worker exception mode=%s err='%s'", mode ? mode : "", ex.what());
            } catch (...) {
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture worker exception mode=%s err='<unknown>'", mode ? mode : "");
            }
            diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture worker exit mode=%s port=%u elapsed_ms=%lu accepts=%llu requests=%llu stop=%d",
                mode ? mode : "",
                static_cast<unsigned>(port),
                static_cast<unsigned long>(GetTickCount() - start),
                static_cast<unsigned long long>(accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(request_count.load(std::memory_order_acquire)),
                stop.load(std::memory_order_acquire) ? 1 : 0);
            worker_tid.store(0, std::memory_order_release);
            worker_done.store(true, std::memory_order_release);
        }

        void run() {
            int last_select_error = 0;
            while (!stop.load(std::memory_order_acquire)) {
                SOCKET ls = listener;
                if (ls == INVALID_SOCKET)
                    break;
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(ls, &rfds);
                timeval tv = {};
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                int sel = select(0, &rfds, nullptr, nullptr, &tv);
                if (sel == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (err != last_select_error) {
                        diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture select error port=%u err=%d stop=%d",
                            static_cast<unsigned>(port), err, stop.load(std::memory_order_acquire) ? 1 : 0);
                        last_select_error = err;
                    }
                    Sleep(10);
                    continue;
                }
                if (sel <= 0)
                    continue;
                SOCKET s = accept(ls, nullptr, nullptr);
                if (s == INVALID_SOCKET) {
                    int err = WSAGetLastError();
                    diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture accept failed port=%u err=%d stop=%d",
                        static_cast<unsigned>(port), err, stop.load(std::memory_order_acquire) ? 1 : 0);
                    continue;
                }
                uint64_t idx = accept_count.fetch_add(1, std::memory_order_acq_rel) + 1;
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture accepted port=%u accept=%llu socket=%llu",
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(idx),
                    static_cast<unsigned long long>(s));
                u_long blocking = 0;
                ioctlsocket(s, FIONBIO, &blocking);
                handle_client(s, idx);
                closesocket(s);
            }
        }

        void handle_client(SOCKET s, uint64_t accept_idx) {
            DWORD timeout = 1500;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            char buf[4096] = {};
            int got = recv(s, buf, sizeof(buf) - 1, 0);
            if (got <= 0) {
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture recv empty port=%u accept=%llu got=%d err=%d",
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(accept_idx),
                    got,
                    WSAGetLastError());
                return;
            }
            uint64_t req_idx = request_count.fetch_add(1, std::memory_order_acq_rel) + 1;
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
            std::string first_line;
            size_t first_line_end = req.find("\r\n");
            if (first_line_end != std::string::npos)
                first_line = req.substr(0, first_line_end);
            else
                first_line = req.substr(0, std::min<size_t>(req.size(), 160));
            diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture request port=%u accept=%llu request=%llu bytes=%zu first_line=%s",
                static_cast<unsigned>(port),
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(req_idx),
                req.size(),
                first_line.c_str());
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
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture websocket upgraded port=%u accept=%llu request=%llu",
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(req_idx));
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
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture connect tunnel acknowledged port=%u accept=%llu request=%llu",
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(req_idx));
                return;
            }
            std::string body;
            std::string content_type = "text/html; charset=utf-8";
            const char* route = "html";
            if (req.rfind("POST /token ", 0) == 0) {
                content_type = "application/json";
                body = "{\"access_token\":\"aida_mcp_access\",\"refresh_token\":\"aida_mcp_refresh\",\"expires_in\":3600,\"token_type\":\"Bearer\"}";
                route = "token";
            } else if (req.rfind("POST /graphql ", 0) == 0) {
                content_type = "application/json";
                body = "{\"data\":{\"__typename\":\"Query\",\"aidaStatus\":\"ready\",\"viewer\":{\"id\":\"fixture\",\"name\":\"AiDA Fixture\"},\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"types\":[{\"kind\":\"OBJECT\",\"name\":\"Query\",\"fields\":[{\"name\":\"__typename\",\"type\":{\"kind\":\"SCALAR\",\"name\":\"String\"},\"args\":[]},{\"name\":\"aidaStatus\",\"type\":{\"kind\":\"SCALAR\",\"name\":\"String\"},\"args\":[]},{\"name\":\"viewer\",\"type\":{\"kind\":\"OBJECT\",\"name\":\"AidaViewer\"},\"args\":[]}],\"interfaces\":[]},{\"kind\":\"OBJECT\",\"name\":\"AidaViewer\",\"fields\":[{\"name\":\"id\",\"type\":{\"kind\":\"SCALAR\",\"name\":\"ID\"},\"args\":[]},{\"name\":\"name\",\"type\":{\"kind\":\"SCALAR\",\"name\":\"String\"},\"args\":[]}],\"interfaces\":[]},{\"kind\":\"SCALAR\",\"name\":\"String\",\"fields\":[],\"interfaces\":[]},{\"kind\":\"SCALAR\",\"name\":\"ID\",\"fields\":[],\"interfaces\":[]}]}}}";
                route = "graphql";
            } else if (req.rfind("GET /aida-fixture.js ", 0) == 0) {
                content_type = "application/javascript";
                body = "window.aidaExternalFixture='AIDA_CAMOUFOX_SCRIPT_MARKER';function aidaFixtureSigner(p){return p.aida_value||'';}console.log('AIDA_CAMOUFOX_SCRIPT_READY');";
                route = "script";
            } else if (req.find(" /aida-mcp-test") != std::string::npos || req.find(" /FUZZ") != std::string::npos) {
                body = "aida-mcp-test";
                route = "plain";
            } else {
                std::string q = fixture_query_value(req, "q");
                std::string query_raw = fixture_request_query(req);
                std::string q_html = fixture_html_escape(q);
                std::string query_html = fixture_html_escape(fixture_url_decode(query_raw));
                const bool q_has_canary = q.find("__aida_xss_canary_") != std::string::npos;
                const bool q_has_svg = q.find("<svg") != std::string::npos || q.find("<SVG") != std::string::npos;
                const bool q_has_img = q.find("<img") != std::string::npos || q.find("<IMG") != std::string::npos;
                const bool q_has_script = q.find("<script") != std::string::npos || q.find("<SCRIPT") != std::string::npos;
                diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture dom_reflect q_len=%zu query_len=%zu has_canary=%d has_svg=%d has_img=%d has_script=%d port=%u accept=%llu request=%llu",
                    q.size(), query_raw.size(), q_has_canary ? 1 : 0, q_has_svg ? 1 : 0, q_has_img ? 1 : 0, q_has_script ? 1 : 0,
                    static_cast<unsigned>(port),
                    static_cast<unsigned long long>(accept_idx),
                    static_cast<unsigned long long>(req_idx));
                const std::string dom_script = R"JS(
window.aidaFixture=1;
window.aidaHookTarget=function(v){return 'hook:'+v;};
(function(){
var q=new URLSearchParams(location.search).get('q')||'';
var h=document.getElementById('dom-reflect');
window.aidaDomXssFixtureLog=window.aidaDomXssFixtureLog||[];
var emit=function(phase,data){try{data=data||{};data.phase=phase;data.readyState=String(document.readyState||'');data.qLen=q.length;data.hasTarget=!!h;data.hasCanary=q.indexOf('__aida_xss_canary_')>=0;data.hasSvg=q.toLowerCase().indexOf('<svg')>=0;data.hasImg=q.toLowerCase().indexOf('<img')>=0;data.hasScript=q.toLowerCase().indexOf('<script')>=0;window.aidaDomXssFixtureLog.push(data);console.log('AIDA_DOM_XSS_FIXTURE:'+JSON.stringify(data));}catch(e){}};
var fire=function(el,type){try{el.dispatchEvent(new Event(type,{bubbles:true,cancelable:true}));return true;}catch(e){try{var ev=document.createEvent('Event');ev.initEvent(type,true,true);el.dispatchEvent(ev);return true;}catch(e2){return false;}}};
var invoke=function(src){var hits=0;var called=0;var missing=0;var thrown=0;try{var re=/(__aida_xss_canary_[A-Za-z0-9]+__)\s*\(\s*(['"])(.*?)\2\s*\)/g;var m;var text=String(src||'');while((m=re.exec(text))){++hits;try{var fn=window[m[1]];if(typeof fn==='function'){fn(m[3]);++called;}else{++missing;}}catch(e){++thrown;}}}catch(e){++thrown;}return{hits:hits,called:called,missing:missing,thrown:thrown};};
var run=function(phase){var st={};try{if(q&&h){h.innerHTML=q;st.innerSet=1;st.domLen=h.innerHTML.length;}else{st.innerSet=0;}}catch(e){st.innerErr=String(e&&e.message?e.message:e).slice(0,160);}
try{var inv=invoke(q);st.invokeHits=inv.hits;st.invokeCalled=inv.called;st.invokeMissing=inv.missing;st.invokeThrown=inv.thrown;}catch(e){st.invokeOuterErr=String(e&&e.message?e.message:e).slice(0,160);}
try{var loadTargets=h?h.querySelectorAll('svg,[onload]'):[];st.loadTargets=loadTargets.length;st.loadFired=0;loadTargets.forEach(function(e){if(fire(e,'load'))++st.loadFired;});}catch(e){st.loadErr=String(e&&e.message?e.message:e).slice(0,160);}
try{var errorTargets=h?h.querySelectorAll('img,[onerror]'):[];st.errorTargets=errorTargets.length;st.errorFired=0;errorTargets.forEach(function(e){if(fire(e,'error'))++st.errorFired;});}catch(e){st.errorErr=String(e&&e.message?e.message:e).slice(0,160);}
emit(phase,st);};
run('inline');
try{document.addEventListener('DOMContentLoaded',function(){run('domcontentloaded');},{once:true});}catch(e){}
try{window.addEventListener('load',function(){run('load');},{once:true});}catch(e){}
[0,50,150,350,750].forEach(function(ms){try{setTimeout(function(){run('timeout_'+ms);},ms);}catch(e){}});
})();
)JS";
                body = "<!doctype html><html><head><title>AiDA MCP Fixture</title><meta name=\"generator\" content=\"WordPress 6.4\"><script src=\"/aida-fixture.js\"></script></head><body><a href=\"/aida-mcp-test\">fixture</a><input id=\"aida-input\" value=\"\"><div id=\"server-reflect\">" + q_html + "</div><div id=\"query-reflect\">" + query_html + "</div><div id=\"dom-reflect\"></div><script>" + dom_script + "</script></body></html>";
            }
            std::string resp = "HTTP/1.1 200 OK\r\n";
            resp += "Content-Type: " + content_type + "\r\n";
            resp += "Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval' data:\r\n";
            resp += "Server: nginx/1.24.0\r\n";
            resp += "X-Powered-By: PHP/8.2\r\n";
            resp += "X-AiDA-Fixture: mcp-local\r\n";
            resp += "X-Query-Echo: " + fixture_header_safe(fixture_request_query(req)) + "\r\n";
            resp += "Connection: close\r\n";
            resp += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
            resp += body;
            int sent = send(s, resp.data(), static_cast<int>(resp.size()), 0);
            diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture response port=%u accept=%llu request=%llu route=%s status=200 body=%zu sent=%d err=%d",
                static_cast<unsigned>(port),
                static_cast<unsigned long long>(accept_idx),
                static_cast<unsigned long long>(req_idx),
                route,
                body.size(),
                sent,
                sent == SOCKET_ERROR ? WSAGetLastError() : 0);
        }

        void close() {
            const DWORD close_start = GetTickCount();
            diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture close begin port=%u listener=%llu worker_posted=%d worker_entered=%d worker_done=%d worker_tid=%lu accepts=%llu requests=%llu",
                static_cast<unsigned>(port),
                static_cast<unsigned long long>(listener),
                worker_posted.load(std::memory_order_acquire) ? 1 : 0,
                worker_entered.load(std::memory_order_acquire) ? 1 : 0,
                worker_done.load(std::memory_order_acquire) ? 1 : 0,
                static_cast<unsigned long>(worker_tid.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(request_count.load(std::memory_order_acquire)));
            stop.store(true, std::memory_order_release);
            if (listener != INVALID_SOCKET) {
                closesocket(listener);
                listener = INVALID_SOCKET;
            }
            if (worker_posted.load(std::memory_order_acquire)) {
                DWORD next_log = 5000;
                while (!worker_done.load(std::memory_order_acquire)) {
                    DWORD elapsed = GetTickCount() - close_start;
                    if (elapsed >= 15000) {
                        diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture close timeout elapsed_ms=%lu worker_tid=%lu accepts=%llu requests=%llu",
                            static_cast<unsigned long>(elapsed),
                            static_cast<unsigned long>(worker_tid.load(std::memory_order_acquire)),
                            static_cast<unsigned long long>(accept_count.load(std::memory_order_acquire)),
                            static_cast<unsigned long long>(request_count.load(std::memory_order_acquire)));
                        break;
                    }
                    if (elapsed >= next_log) {
                        diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture worker still draining elapsed_ms=%lu",
                            static_cast<unsigned long>(elapsed));
                        next_log += 5000;
                    }
                    Sleep(10);
                }
                worker_posted.store(false, std::memory_order_release);
            }
            diag::log_tagged_fmt("test_all_mcp", "Burp HTTP fixture closed elapsed_ms=%lu accepts=%llu requests=%llu",
                static_cast<unsigned long>(GetTickCount() - close_start),
                static_cast<unsigned long long>(accept_count.load(std::memory_order_acquire)),
                static_cast<unsigned long long>(request_count.load(std::memory_order_acquire)));
            port = 0;
        }

        ~mcp_burp_http_fixture_t() {
            close();
        }
    };

    std::unique_ptr<mcp_burp_http_fixture_t> g_burp_http_fixture;

    bool ensure_burp_http_fixture(HANDLE hf, const char* tag) {
        if (g_burp_http_fixture && g_burp_http_fixture->port != 0) {
            if (g_burp_http_fixture->live())
                return true;
            log_msg(hf, tag, "INFO -- Burp HTTP fixture stale before reuse port=%u worker_done=%d listener=%d; recreating",
                static_cast<unsigned>(g_burp_http_fixture->port),
                g_burp_http_fixture->worker_done.load(std::memory_order_acquire) ? 1 : 0,
                g_burp_http_fixture->listener == INVALID_SOCKET ? 0 : 1);
            g_burp_http_fixture.reset();
            g_burp_fixture_base_url.clear();
            g_burp_fixture_wordlist_path.clear();
        }
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

    bool probe_burp_fixture_connect(HANDLE hf, const char* tag) {
        if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture || g_burp_http_fixture->port == 0)
            return false;
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, tag, "PROBE-FAIL -- WSAStartup failed for fixture probe");
            return false;
        }
        auto probe_existing = [&](int max_attempts, bool after_restart) -> bool {
            int last_err = 0;
            const unsigned port = static_cast<unsigned>(g_burp_http_fixture->port);
            for (int attempt = 1; attempt <= max_attempts; ++attempt) {
                SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (s == INVALID_SOCKET) {
                    last_err = WSAGetLastError();
                    log_msg(hf, tag, "PROBE-FAIL -- fixture probe socket failed attempt=%d port=%u err=%d",
                        attempt, port, last_err);
                    if (last_err == WSAENOBUFS || last_err == WSAEMFILE) {
                        Sleep(static_cast<DWORD>(25 * attempt));
                        continue;
                    }
                    return false;
                }
                DWORD timeout = 250;
                setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port = htons(g_burp_http_fixture->port);
                int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
                int err = rc == 0 ? 0 : WSAGetLastError();
                if (rc == 0) {
                    const std::string req = "GET /aida-mcp-test?source=probe HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
                    const int sent = send(s, req.data(), static_cast<int>(req.size()), 0);
                    std::string resp;
                    char tmp[512];
                    for (int read_attempt = 0; read_attempt < 4; ++read_attempt) {
                        int got = recv(s, tmp, sizeof(tmp), 0);
                        if (got > 0) {
                            resp.append(tmp, tmp + got);
                            if (resp.find("aida-mcp-test") != std::string::npos ||
                                resp.find("AiDA MCP Fixture") != std::string::npos)
                                break;
                        } else {
                            break;
                        }
                    }
                    closesocket(s);
                    if (sent > 0 &&
                        (resp.find("aida-mcp-test") != std::string::npos ||
                         resp.find("AiDA MCP Fixture") != std::string::npos)) {
                        log_msg(hf, tag, "PROBE-PASS -- fixture HTTP probe attempt=%d port=%u sent=%d resp_len=%zu restarted=%d accepts=%llu requests=%llu",
                            attempt,
                            port,
                            sent,
                            resp.size(),
                            after_restart ? 1 : 0,
                            static_cast<unsigned long long>(g_burp_http_fixture->accept_count.load(std::memory_order_acquire)),
                            static_cast<unsigned long long>(g_burp_http_fixture->request_count.load(std::memory_order_acquire)));
                        return true;
                    }
                    last_err = WSAGetLastError();
                    log_msg(hf, tag, "PROBE-RETRY -- fixture HTTP response missing attempt=%d port=%u sent=%d resp_len=%zu err=%d",
                        attempt, port, sent, resp.size(), last_err);
                    Sleep(static_cast<DWORD>(25 * attempt));
                    continue;
                }
                last_err = err;
                log_msg(hf, tag, "PROBE-RETRY -- fixture probe connect failed attempt=%d port=%u err=%d",
                    attempt, port, err);
                closesocket(s);
                if (err == WSAENOBUFS || err == WSAECONNREFUSED || err == WSAETIMEDOUT ||
                    err == WSAEADDRNOTAVAIL || err == WSAEADDRINUSE) {
                    Sleep(static_cast<DWORD>(25 * attempt));
                    continue;
                }
                break;
            }
            log_msg(hf, tag, "PROBE-FAIL -- fixture HTTP probe failed port=%u err=%d attempts=%d restarted=%d",
                port, last_err, max_attempts, after_restart ? 1 : 0);
            return false;
        };
        if (probe_existing(12, false))
            return true;
        if (g_burp_http_fixture) {
            log_msg(hf, tag, "INFO -- Burp HTTP fixture not responsive; restarting");
            g_burp_http_fixture.reset();
            g_burp_fixture_base_url.clear();
            g_burp_fixture_wordlist_path.clear();
            if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture || g_burp_http_fixture->port == 0)
                return false;
            return probe_existing(12, true);
        }
        return false;
    }

    std::string burp_fixture_url(HANDLE hf, const char* tag, const char* path = "/") {
        std::string suffix = path ? path : "/";
        if (suffix.empty() || suffix[0] != '/')
            suffix.insert(suffix.begin(), '/');
        if (!ensure_burp_http_fixture(hf, tag) || !probe_burp_fixture_connect(hf, tag)) {
            log_msg(hf, tag, "FIXTURE-FALLBACK -- using closed loopback URL for suffix=%s because Burp HTTP fixture is unavailable", suffix.c_str());
            return "http://127.0.0.1:1" + suffix;
        }
        log_msg(hf, tag, "FIXTURE-URL -- %s%s", g_burp_fixture_base_url.c_str(), suffix.c_str());
        return g_burp_fixture_base_url + suffix;
    }

    bool send_burp_fixture_tcp_payload(HANDLE hf, const char* tag, const std::vector<uint8_t>& payload) {
        if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture || g_burp_http_fixture->port == 0)
            return false;
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed for capture payload fixture");
            return false;
        }
        sockaddr_in dst = {};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(g_burp_http_fixture->port);
        int last_err = 0;
        int sent = 0;
        const unsigned port = static_cast<unsigned>(g_burp_http_fixture->port);
        for (int attempt = 1; attempt <= 12; ++attempt) {
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                last_err = WSAGetLastError();
                log_msg(hf, tag, "FAIL -- payload socket failed attempt=%d port=%u err=%d", attempt, port, last_err);
                return false;
            }
            DWORD timeout = 1500;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            if (connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) == SOCKET_ERROR) {
                last_err = WSAGetLastError();
                log_msg(hf, tag, "RETRY -- payload connect failed attempt=%d port=%u err=%d", attempt, port, last_err);
                closesocket(s);
                if (last_err == WSAECONNREFUSED || last_err == WSAETIMEDOUT ||
                    last_err == WSAEADDRNOTAVAIL || last_err == WSAENOBUFS) {
                    Sleep(static_cast<DWORD>(25 * attempt));
                    continue;
                }
                return false;
            }
            sent = send(s, reinterpret_cast<const char*>(payload.data()), static_cast<int>(payload.size()), 0);
            last_err = sent <= 0 ? WSAGetLastError() : 0;
            char tmp[256];
            recv(s, tmp, sizeof(tmp), 0);
            closesocket(s);
            if (sent > 0) {
                log_msg(hf, tag, "PAYLOAD-SENT -- port=%u attempt=%d bytes=%d", port, attempt, sent);
                break;
            }
            log_msg(hf, tag, "RETRY -- payload send failed attempt=%d port=%u err=%d", attempt, port, last_err);
            Sleep(static_cast<DWORD>(25 * attempt));
        }
        if (sent <= 0) {
            log_msg(hf, tag, "FAIL -- payload fixture send exhausted port=%u err=%d", port, last_err);
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

    bool seed_network_packet_queue(HANDLE hf, const char* tag, const std::vector<uint8_t>& payload) {
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded for packet queue fixture");
            return false;
        }
        if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture || g_burp_http_fixture->port == 0)
            return false;
        driver_bridge::stop_capture();
        const uint16_t port = g_burp_http_fixture->port;
        const DWORD start_tick = GetTickCount();
        if (!driver_bridge::start_capture(GetCurrentProcessId(), port, 6, nullptr, 1500)) {
            log_msg(hf, tag, "FAIL -- start_capture failed for packet queue fixture pid=%lu port=%u",
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned>(port));
            return false;
        }
        if (!send_burp_fixture_tcp_payload(hf, tag, payload)) {
            driver_bridge::stop_capture();
            return false;
        }
        Sleep(250);
        bool active = false;
        uint32_t captured = 0;
        uint32_t dropped = 0;
        driver_bridge::get_capture_status(active, captured, dropped);
        const bool stopped = driver_bridge::stop_capture();
        log_msg(hf, tag, "NETWORK-FIXTURE -- tcp packet queue seeded pid=%lu port=%u active_before_stop=%d captured=%u dropped=%u stopped=%d elapsed_ms=%lu requests=%llu",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned>(port),
            active ? 1 : 0,
            captured,
            dropped,
            stopped ? 1 : 0,
            static_cast<unsigned long>(GetTickCount() - start_tick),
            g_burp_http_fixture ? static_cast<unsigned long long>(g_burp_http_fixture->request_count.load(std::memory_order_acquire)) : 0ull);
        return captured > 0 || stopped;
    }

    bool send_udp_fixture_payload(HANDLE hf, const char* tag, uint16_t dst_port, const std::vector<uint8_t>& payload) {
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, tag, "FAIL -- WSAStartup failed for UDP fixture");
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            log_msg(hf, tag, "FAIL -- UDP socket failed err=%d", WSAGetLastError());
            return false;
        }
        sockaddr_in dst = {};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(dst_port);
        int sent = sendto(s,
            reinterpret_cast<const char*>(payload.data()),
            static_cast<int>(payload.size()),
            0,
            reinterpret_cast<sockaddr*>(&dst),
            sizeof(dst));
        const int err = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
        closesocket(s);
        if (sent <= 0) {
            log_msg(hf, tag, "FAIL -- UDP fixture send failed port=%u bytes=%zu err=%d",
                static_cast<unsigned>(dst_port),
                payload.size(),
                err);
            return false;
        }
        Sleep(250);
        log_msg(hf, tag, "NETWORK-FIXTURE -- udp payload sent pid=%lu dst=127.0.0.1:%u bytes=%d",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned>(dst_port),
            sent);
        return true;
    }

    bool seed_udp_capture_for_detection(HANDLE hf, const char* tag, uint16_t port, const std::vector<uint8_t>& payload) {
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded for UDP detection fixture");
            return false;
        }
        driver_bridge::stop_capture();
        const DWORD start_tick = GetTickCount();
        if (!driver_bridge::start_capture(GetCurrentProcessId(), port, 17, nullptr, 1500)) {
            log_msg(hf, tag, "FAIL -- start_capture failed for UDP fixture pid=%lu port=%u",
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned>(port));
            return false;
        }
        if (!send_udp_fixture_payload(hf, tag, port, payload)) {
            driver_bridge::stop_capture();
            return false;
        }
        bool active = false;
        uint32_t captured = 0;
        uint32_t dropped = 0;
        driver_bridge::get_capture_status(active, captured, dropped);
        log_msg(hf, tag, "NETWORK-FIXTURE -- udp capture seeded pid=%lu port=%u active=%d captured=%u dropped=%u elapsed_ms=%lu",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned>(port),
            active ? 1 : 0,
            captured,
            dropped,
            static_cast<unsigned long>(GetTickCount() - start_tick));
        return true;
    }

    std::vector<uint8_t> mcp_http_fixture_request_payload(const char* path) {
        std::string req = "GET ";
        req += path && *path ? path : "/aida-mcp-test";
        req += " HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: AiDA-MCP-Fixture\r\nConnection: close\r\n\r\n";
        return std::vector<uint8_t>(req.begin(), req.end());
    }

    bool seed_driver_stream_reassembly(HANDLE hf, const char* tag, mcp_loopback_tcp_pair_t& pair, const std::vector<uint8_t>& payload) {
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not loaded for stream reassembly fixture");
            return false;
        }
        if (!pair.open(hf, tag))
            return false;
        driver_bridge::stream_reassemble_op(4, 0, 0, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!driver_bridge::stream_reassemble_op(0, pair.client_port, pair.listen_port, GetCurrentProcessId(), nullptr, nullptr, nullptr, nullptr, nullptr)) {
            log_msg(hf, tag, "FAIL -- stream_reassemble start failed src=%u dst=%u pid=%lu",
                static_cast<unsigned>(pair.client_port),
                static_cast<unsigned>(pair.listen_port),
                static_cast<unsigned long>(GetCurrentProcessId()));
            return false;
        }
        DWORD timeout = 1500;
        setsockopt(pair.client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(pair.client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(pair.accepted, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(pair.accepted, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        int sent = send(pair.client,
            reinterpret_cast<const char*>(payload.data()),
            static_cast<int>(payload.size()),
            0);
        char recv_buf[512] = {};
        int got = recv(pair.accepted, recv_buf, sizeof(recv_buf), 0);
        const char reply[] = "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\naida-stream-reply";
        int reply_sent = send(pair.accepted, reply, static_cast<int>(sizeof(reply) - 1), 0);
        char client_buf[512] = {};
        int client_got = recv(pair.client, client_buf, sizeof(client_buf), 0);
        Sleep(350);
        log_msg(hf, tag, "NETWORK-FIXTURE -- stream tuple seeded src=%u dst=%u pid=%lu sent=%d got=%d reply_sent=%d client_got=%d",
            static_cast<unsigned>(pair.client_port),
            static_cast<unsigned>(pair.listen_port),
            static_cast<unsigned long>(GetCurrentProcessId()),
            sent,
            got,
            reply_sent,
            client_got);
        return sent > 0;
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

    void seed_burp_passive_scanner_exchange(HANDLE hf, const char* tag) {
        if (!ensure_burp_http_fixture(hf, tag) || !g_burp_http_fixture)
            return;
        aida::burp::passive_scanner::initialize();
        aida::burp::passive_scanner::set_enabled(true);
        auto before = aida::burp::passive_scanner::get_stats();
        aida::burp::exchange_observed_t ex;
        ex.id = static_cast<uint64_t>(GetTickCount64());
        ex.timestamp_ms = ex.id;
        ex.method = "GET";
        ex.scheme = "http";
        ex.host = "127.0.0.1";
        ex.port = g_burp_http_fixture->port;
        ex.path = "/";
        ex.query = "q=aida-passive";
        ex.req_headers.push_back({"Host", "127.0.0.1"});
        ex.status_code = 200;
        ex.reason_phrase = "OK";
        ex.resp_headers.push_back({"Content-Type", "text/html; charset=utf-8"});
        ex.resp_headers.push_back({"Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' data:"});
        ex.resp_headers.push_back({"X-Powered-By", "AiDA-Fixture"});
        std::string body = "<!doctype html><html><body>aida-passive</body></html>";
        ex.resp_body.assign(body.begin(), body.end());
        aida::events::publish(aida::burp::kExchangeObservedEvent, ex);
        for (int i = 0; i < 40; ++i) {
            auto now = aida::burp::passive_scanner::get_stats();
            if (now.exchanges_scanned > before.exchanges_scanned)
                return;
            Sleep(50);
        }
        log_msg(hf, tag, "WARN -- passive scanner seed did not advance exchange counter before status check");
    }

    bool seed_burp_sitemap_fixture(HANDLE hf, const char* tag) {
        if (g_burp_sitemap_exchange_id != 0)
            return true;
        if (!ensure_burp_http_fixture(hf, tag))
            return false;
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
        for (int i = 0; i < 100; ++i) {
            aida::burp::exchange_observed_t found;
            if (aida::burp::sitemap::find_exchange(e.id, found)) {
                g_burp_sitemap_exchange_id = e.id;
                return true;
            }
            Sleep(20);
        }
        log_msg(hf, tag, "FAIL -- sitemap fixture exchange was not indexed id=%llu port=%u",
            static_cast<unsigned long long>(e.id), static_cast<unsigned>(e.port));
        return false;
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
        int ide_chat_only_count = 0;
        for (const auto& t : tools) {
            if (t.visibility == mcp_standalone::tool_visibility_t::ide_chat_only) {
                ++ide_chat_only_count;
                continue;
            }
            if (is_ai_related_mcp_tool(t.name))
                ++ai_count;
            else
                ++non_ai_count;
        }
        if (non_ai_count > 0) {
            log_msg(hf, tag, "PASS -- general MCP tools registered non_ai=%d ai_or_workflow=%d ide_chat_only_hidden=%d",
                non_ai_count, ai_count, ide_chat_only_count);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- no non-AI tools registered ai_or_workflow=%d ide_chat_only_hidden=%d",
                ai_count, ide_chat_only_count);
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
        int enumerated_count = 0;
        int ide_chat_only_count = 0;
        for (const auto& t : tools) {
            if (t.visibility == mcp_standalone::tool_visibility_t::ide_chat_only) {
                ++ide_chat_only_count;
                continue;
            }
            if (t.read_only) ++read_only_count;
            else ++writable_count;
            ++enumerated_count;
            log_msg(hf, tag, "  tool: %-40s params=%zu ro=%s desc=\"%.80s\"",
                t.name.c_str(), t.params.size(),
                t.read_only ? "Y" : "N",
                t.description.c_str());
        }
        log_msg(hf, tag, "PASS -- enumerated %d tools (read_only=%d writable=%d ide_chat_only_hidden=%d)",
            enumerated_count, read_only_count, writable_count, ide_chat_only_count);
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
            if (t.visibility == mcp_standalone::tool_visibility_t::ide_chat_only)
                continue;
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
        int hidden = 0;
        for (const auto& t : tools) {
            if (t.visibility == mcp_standalone::tool_visibility_t::ide_chat_only) {
                ++hidden;
                continue;
            }
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
            log_msg(hf, tag, "PASS -- all %d general MCP tool schemas valid (name, desc, handler present; ide_chat_only_hidden=%d)", valid, hidden);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %d/%d general MCP tool schemas invalid ide_chat_only_hidden=%d", invalid, valid + invalid, hidden);
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
        int hidden = 0;
        for (const auto& t : srv->get_tools()) {
            if (t.visibility == mcp_standalone::tool_visibility_t::ide_chat_only) {
                ++hidden;
                continue;
            }
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
            log_msg(hf, tag, "PASS -- %zu general MCP tool names are unique ide_chat_only_hidden=%d", counts.size(), hidden);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- %d duplicate MCP tool registration(s) across %zu unique names ide_chat_only_hidden=%d",
                duplicates, counts.size(), hidden);
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
        std::string lifecycle_reason;
        if (!srv->is_running() || !mcp_standalone::lifecycle_authorized(&lifecycle_reason)) {
            log_msg(hf, tag, "FAIL -- JSON-RPC smoke requires running authorized MCP server running=%d reason=%s",
                srv->is_running() ? 1 : 0,
                lifecycle_reason.empty() ? "unknown" : lifecycle_reason.c_str());
            failed.fetch_add(1);
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
            for (const auto& tool : list_resp["result"]["tools"]) {
                if (!tool.contains("name") || !tool["name"].is_string())
                    continue;
                const std::string listed_name = tool["name"].get<std::string>();
                if (is_ai_related_mcp_tool(listed_name)) {
                    log_msg(hf, tag, "FAIL -- tools/list exposed internal AI/workflow tool \"%s\"",
                        listed_name.c_str());
                    failed.fetch_add(1);
                    return;
                }
                if (!tool.contains("description") || !tool["description"].is_string() ||
                    tool["description"].get<std::string>().empty()) {
                    log_msg(hf, tag, "FAIL -- tools/list exposed tool \"%s\" without a description",
                        listed_name.c_str());
                    failed.fetch_add(1);
                    return;
                }
            }

            mcp_standalone::json call_req = {
                {"jsonrpc", "2.0"},
                {"id", 3},
                {"method", "tools/call"},
                {"params", {
                    {"name", "debugger_get_attached"},
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
        args["names"] = mcp_standalone::json::array({"get_tool_descriptions", "sessions_manage", "switch_agent"});
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
        const bool has_sessions_manage = text_lc.find("### sessions_manage") != std::string::npos;
        const bool leaked_internal = text_lc.find("### switch_agent") != std::string::npos;
        const bool has_schema = text_lc.find("`names`") != std::string::npos &&
            text_lc.find("include_schema") != std::string::npos;
        if (has_self && has_sessions_manage && has_schema && !leaked_internal) {
            log_msg(hf, tag, "PASS -- returned detailed schemas for selected tools");
            record_tool_status("get_tool_descriptions", mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "FAIL -- response missing expected detail self=%s sessions_manage=%s schema=%s leaked_internal=%s text=%s",
            has_self ? "true" : "false",
            has_sessions_manage ? "true" : "false",
            has_schema ? "true" : "false",
            leaked_internal ? "true" : "false",
            compact_text(ir.text, 900).c_str());
        record_tool_status("get_tool_descriptions", mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_mcp_coverage_audit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.coverage_audit";
        set_progress_step("mcp finalization: coverage audit");
        auto* srv = get_server();
        if (!srv) {
            (void)skipped;
            log_msg(hf, tag, "FAIL -- no server instance");
            failed.fetch_add(1);
            return;
        }

        const auto cq_begin = critical_work_queue::stats();
        log_msg(hf, tag, "BEGIN -- tool_status_records=%zu explicit_invocations=%zu timed_out_records=%zu cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
            g_tool_attempt_stats.size(),
            g_invoked_tools.size(),
            copy_timed_out_invocations().size(),
            cq_begin.pending,
            static_cast<unsigned>(cq_begin.active),
            static_cast<unsigned long long>(cq_begin.started),
            static_cast<unsigned long long>(cq_begin.finished));

        std::set<std::string> registered;
        std::set<std::string> registered_all;
        int registered_total = 0;
        int registered_external = 0;
        int registered_internal = 0;
        int registered_ide_chat = 0;
        int destructive_schema_tools = 0;
        int non_ai_audited = 0;
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
            if (!registered_all.insert(t.name).second)
                continue;
            if (t.visibility == mcp_standalone::tool_visibility_t::ide_chat_only) {
                ++registered_ide_chat;
                continue;
            }
            ++registered_total;
            if (t.visibility == mcp_standalone::tool_visibility_t::internal_only)
                ++registered_internal;
            else
                ++registered_external;
            if (is_destructive_mcp_tool(t.name))
                ++destructive_schema_tools;
            if (is_ai_related_mcp_tool(t.name)) {
                ++skipped_ai;
                continue;
            }
            registered.insert(t.name);
            ++non_ai_audited;
            auto stats_it = g_tool_attempt_stats.find(t.name);
            if (stats_it != g_tool_attempt_stats.end() && stats_it->second.attempted > 0) {
                ++attempted;
                const auto& st = stats_it->second;
                if (st.passed > 0) {
                    ++covered;
                    ++passed_tools;
                    if (st.failed > 0 || st.timed_out > 0) {
                        log_msg(hf, tag, "MIXED-FAIL -- registered tool \"%s\" had pass evidence but also failed or timed out attempted=%d failed=%d skipped=%d timed_out=%d",
                            t.name.c_str(), st.attempted, st.failed, st.skipped, st.timed_out);
                    }
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

        log_msg(hf, tag, "DIAG -- registry total=%d external=%d internal=%d ide_chat_only=%d ai_excluded=%d non_ai_audited=%d destructive_schema_only=%d explicit_invocations=%zu",
            registered_total,
            registered_external,
            registered_internal,
            registered_ide_chat,
            skipped_ai,
            non_ai_audited,
            destructive_schema_tools,
            g_invoked_tools.size());

        if (missing == 0 && stale == 0 && no_pass == 0 && skipped_tools == 0 && failed_tools == 0 && timed_out_tools == 0) {
            log_msg(hf, tag, "PASS -- attempted=%d passed_tools=%d no_pass=%d failed_tools=%d skipped_tools=%d timed_out_tools=%d registered_total=%d external=%d internal=%d ide_chat_only=%d ai_excluded=%d non_ai_audited=%d destructive_schema_only=%d",
                attempted, passed_tools, no_pass, failed_tools, skipped_tools, timed_out_tools,
                registered_total, registered_external, registered_internal, registered_ide_chat, skipped_ai, non_ai_audited, destructive_schema_tools);
            passed.fetch_add(1);
        } else {
            log_msg(hf, tag, "FAIL -- missing=%d stale=%d attempted=%d passed_tools=%d no_pass=%d failed_tools=%d skipped_tools=%d timed_out_tools=%d registered_total=%d external=%d internal=%d ide_chat_only=%d ai_excluded=%d non_ai_audited=%d destructive_schema_only=%d strict=1",
                missing, stale, attempted, covered, no_pass, failed_tools, skipped_tools, timed_out_tools,
                registered_total, registered_external, registered_internal, registered_ide_chat, skipped_ai, non_ai_audited, destructive_schema_tools);
            failed.fetch_add(1);
        }
        const auto cq_end = critical_work_queue::stats();
        log_msg(hf, tag, "END -- missing=%d stale=%d no_pass=%d failed_tools=%d timed_out_tools=%d pass=%d fail=%d skip=%d cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
            missing,
            stale,
            no_pass,
            failed_tools,
            timed_out_tools,
            passed.load(std::memory_order_acquire),
            failed.load(std::memory_order_acquire),
            skipped.load(std::memory_order_acquire),
            cq_end.pending,
            static_cast<unsigned>(cq_end.active),
            static_cast<unsigned long long>(cq_end.started),
            static_cast<unsigned long long>(cq_end.finished));
    }




void test_tool_list_processes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.list_processes", get_server(), "list_processes", {}, passed, failed, skipped);
    }

    void test_tool_list_processes_filter(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["filter"] = "explorer";
        test_tool_call(hf, "mcp.list_processes_filter", get_server(), "list_processes", args, passed, failed, skipped);
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

    void test_tool_disassemble_zydis(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disassemble_zydis", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_call(hf, "mcp.disassemble_zydis", get_server(), "disassemble_zydis", args, passed, failed, skipped);
    }

    void test_tool_disassemble_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_small_pe_fixture_path();
        args["count"] = 16;
        test_tool_call(hf, "mcp.disassemble_file", get_server(), "disassemble_file", args, passed, failed, skipped);
    }


void test_tool_sandbox_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "sandbox_execute";
        mcp_standalone::json args;
        args["path"] = "C:\\Windows\\System32\\cmd.exe";
        args["arguments"] = "/c echo AIDA_SANDBOX_OK";
        args["timeout_ms"] = 120000;
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
            if (!require_tool_read_only_metadata(hf, "mcp.sandbox_execute.guard", tool_name, false, failed))
                return;
            const auto* tool = find_registered_tool(get_server(), tool_name);
            static const char* required_params[] = {"path", "arguments", "working_dir", "timeout_ms", "capture_stdout", "capture_stderr"};
            for (const char* param : required_params) {
                if (!tool || !tool_has_param(*tool, param)) {
                    log_msg(hf, "mcp.sandbox_execute.guard", "FAIL -- sandbox_execute dependency guard schema missing parameter \"%s\"", param);
                    record_tool_status(tool_name, mcp_tool_call_status_t::failed);
                    failed.fetch_add(1);
                    return;
                }
            }
            log_msg(hf, "mcp.sandbox_execute.guard", "PASS -- Windows Sandbox unavailable dependency guard returned an explicit refusal without host execution; schema and mutability metadata are intact: %s",
                compact_text(ir.text, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::passed);
            passed.fetch_add(1);
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
        args["path"] = mcp_workspace_file_fixture();
        args["max_bytes"] = 256;
        test_tool_call(hf, "mcp.read_file", get_server(), "read_file", args, passed, failed, skipped);
    }

    void test_tool_write_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = mcp_workspace_file_fixture();
        args["content"] = "mcp_test_content";
        test_tool_call(hf, "mcp.write_file", get_server(), "write_file", args, passed, failed, skipped);
    }

    void test_tool_edit_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = mcp_workspace_file_fixture();
        args["find_text"] = "mcp_test_content";
        args["replace_text"] = "mcp_test_edited";
        args["old_text"] = "mcp_test_content";
        args["new_text"] = "mcp_test_edited";
        test_tool_call(hf, "mcp.edit_file", get_server(), "edit_file", args, passed, failed, skipped);
    }

    void test_tool_delete_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = mcp_workspace_file_fixture();
        test_tool_call(hf, "mcp.delete_file", get_server(), "delete_file", args, passed, failed, skipped);
    }

    void test_tool_create_directory(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = mcp_workspace_dir_fixture();
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
        (void)skipped;
        const char* tag = "mcp.web_search";
        mcp_standalone::json args;
        args["query"] = "Microsoft Windows API";
        args["max_results"] = 2;
        args["timeout"] = 20;

        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: web_search", seq);
        set_progress_step(step);
        log_msg(hf, tag, "START -- \"web_search\" seq=%d args=%s", seq, compact_json(args).c_str());

        if (!require_tool_read_only_metadata(hf, tag, "web_search", true, failed))
            return;
        const auto* tool = find_registered_tool(get_server(), "web_search");
        if (!tool || !tool_has_param(*tool, "query")) {
            log_msg(hf, tag, "FAIL -- web_search schema missing query parameter");
            record_tool_status("web_search", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        std::string bridge_reason;
        if (!ensure_mcp_camoufox_bridge_ready_for_tool(hf, tag, "web_search", failed, &bridge_reason)) {
            log_msg(hf, tag, "FAIL -- web_search not dispatched because Camoufox bridge proof failed: %s",
                bridge_reason.empty() ? "<empty>" : compact_text(bridge_reason, 900).c_str());
            return;
        }

        g_invoked_tools.insert("web_search");
        auto timed = invoke_tool_bounded(get_server(), "web_search", args, tool_timeout_ms("web_search"), hf, tag, seq);
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
            log_msg(hf, tag, "FAIL -- Camoufox browser web_search failed: %s (elapsed %lld ms)",
                compact_text(ir.text, 900).c_str(), (long long)ms);
            record_tool_status("web_search", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }

        std::string semantic_failure;
        if (tool_payload_failure_reason("web_search", ir, semantic_failure)) {
            log_msg(hf, tag, "FAIL -- web_search success=true but payload failed semantic validation: %s data=%s text=%s (elapsed %lld ms)",
                semantic_failure.c_str(), compact_json(ir.data, 900).c_str(), compact_text(ir.text, 500).c_str(), (long long)ms);
            record_tool_status("web_search", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }

        std::string provider;
        (void)payload_string_field(ir.data, "provider", provider);
        std::string final_url;
        (void)payload_string_field(ir.data, "final_url", final_url);
        log_msg(hf, tag, "PASS -- web_search returned %zu Camoufox result(s) provider=%s final_url_len=%zu (elapsed %lld ms) -> %s",
            ir.data["results"].size(), provider.empty() ? "<empty>" : provider.c_str(), final_url.size(), (long long)ms, compact_text(ir.text, 500).c_str());
        record_tool_status("web_search", mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_webfetch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        const std::string url = burp_fixture_url(hf, "mcp.webfetch", "/aida-mcp-test?source=webfetch");
        if (!probe_burp_fixture_connect(hf, "mcp.webfetch.probe")) {
            log_msg(hf, "mcp.webfetch", "FAIL -- local HTTP fixture is not reachable before webfetch call url=%s", url.c_str());
            record_tool_status("webfetch", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        args["url"] = url;
        args["format"] = "text";
        args["timeout"] = 5;
        std::string bridge_reason;
        if (!ensure_mcp_camoufox_bridge_ready_for_tool(hf, "mcp.webfetch", "webfetch", failed, &bridge_reason)) {
            log_msg(hf, "mcp.webfetch", "FAIL -- webfetch not dispatched because Camoufox bridge proof failed: %s",
                bridge_reason.empty() ? "<empty>" : compact_text(bridge_reason, 900).c_str());
            return;
        }
        test_tool_call(hf, "mcp.webfetch", get_server(), "webfetch", args, passed, failed, skipped);
    }



void test_tool_driver_dump_module(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_name"] = "ntdll.dll";
        test_tool_call(hf, "mcp.driver_dump_module", get_server(), "driver_dump_module", args, passed, failed, skipped);
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

    void test_tool_driver_enumerate_kernel_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_kernel_modules", get_server(), "driver_enumerate_kernel_modules", {}, passed, failed, skipped);
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
        if (addr.empty()) {
            log_msg(hf, "mcp.driver_call_function", "FAIL -- NtClose fixture address unavailable for safe live-call fixture");
            record_tool_status("driver_call_function", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["address"] = addr;
        args["arg1"] = "0x0";
        args["confirm_unsafe"] = true;
        args[k_test_lab_safe_fixture_flag] = true;
        test_tool_call(hf, "mcp.driver_call_function", get_server(), "driver_call_function", args, passed, failed, skipped);
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


void test_tool_driver_read_peb(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_read_peb", get_server(), "driver_read_peb", {}, passed, failed, skipped);
    }


void test_tool_driver_set_hw_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr_raw = alloc_private_mcp_bp_region(hf, "mcp.driver_set_hw_breakpoint");
        if (addr_raw == 0) { skipped.fetch_add(1); return; }
        uint32_t tid = 0;
        uint32_t original_suspend = 0;
        driver_bridge::thread_context_t ctx{};
        if (!acquire_contextable_mcp_thread(hf, "mcp.driver_set_hw_breakpoint", "driver_set_hw_breakpoint", tid, original_suspend, ctx)) {
            driver_bridge::free_memory(addr_raw);
            record_fixture_failed_tool("driver_set_hw_breakpoint", failed);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr_raw);
        args["tid"] = std::to_string(tid);
        args["index"] = 0;
        args["type"] = "execute";
        args["size"] = 1;
        auto status = test_tool_call(hf, "mcp.driver_set_hw_breakpoint", get_server(), "driver_set_hw_breakpoint", args, passed, failed, skipped);
        (void)driver_bridge::resume_thread(tid, nullptr);
        if (status == mcp_tool_call_status_t::passed) {
            g_mcp_driver_hw_addr = addr_raw;
            g_mcp_driver_hw_tid = tid;
        } else {
            driver_bridge::free_memory(addr_raw);
        }
    }

    void test_tool_driver_clear_hw_breakpoint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        if (g_mcp_driver_hw_tid == 0) {
            uint32_t tid = 0;
            uint32_t original_suspend = 0;
            driver_bridge::thread_context_t ctx{};
            if (acquire_contextable_mcp_thread(hf, "mcp.driver_clear_hw_breakpoint", "driver_clear_hw_breakpoint", tid, original_suspend, ctx)) {
                g_mcp_driver_hw_tid = tid;
                (void)driver_bridge::resume_thread(tid, nullptr);
            }
        }
        if (g_mcp_driver_hw_tid == 0) {
            log_msg(hf, "mcp.driver_clear_hw_breakpoint", "FAIL -- target thread not found for clear test");
            record_fixture_failed_tool("driver_clear_hw_breakpoint", failed);
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
            {{"tool", "debugger_get_attached"}, {"params", mcp_standalone::json::object()}}
        });
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.driver_defer_action", get_server(), "driver_defer_action", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            json_u64_field(result.data, "action_id", g_mcp_deferred_action_id);
            g_mcp_deferred_action_resource_guarded = false;
        } else {
            g_mcp_deferred_action_id = 0;
            const std::string text_lc = lower_copy(result.text);
            if (text_lc.find("resource unavailable") != std::string::npos ||
                text_lc.find("thread start failed") != std::string::npos) {
                g_mcp_deferred_action_resource_guarded = true;
                log_msg(hf, "mcp.driver_defer_action", "FAIL -- deferred watcher thread unavailable; implementation returned deterministic resource failure without registering a stale action");
            }
        }
    }

    mcp_tool_call_status_t test_deferred_tool_direct(HANDLE hf, const char* tag, const char* tool_name,
                                                     const mcp_standalone::json& args,
                                                     std::atomic<int>& passed, std::atomic<int>& failed,
                                                     mcp_standalone::tool_result_t* out_result = nullptr) {
        const std::string tool_name_s = tool_name ? std::string(tool_name) : std::string();
        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        char step[256];
        _snprintf_s(step, sizeof(step), _TRUNCATE, "mcp tool #%d: %s", seq, tool_name ? tool_name : "<null>");
        set_progress_step(step);

        mcp_standalone::json call_args = args.is_null() ? mcp_standalone::json::object() : args;
        add_target_pid_if_needed(tool_name_s, call_args);
        const std::string args_preview = compact_json(call_args);
        log_msg(hf, tag, "START -- \"%s\" seq=%d direct=1 target_pid=%u attached_pid=%u args=%s",
            tool_name ? tool_name : "<null>",
            seq,
            g_mcp_target_pid,
            driver_bridge::attached_pid(),
            args_preview.c_str());
        g_invoked_tools.insert(tool_name_s);

        if (!tool_registered(get_server(), tool_name)) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" not registered for direct deferred dispatch", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }

        const auto t0 = std::chrono::steady_clock::now();
        invoke_result_t ir = invoke_tool(get_server(), tool_name, call_args);
        const auto ms = static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count());
        if (out_result)
            *out_result = { ir.success, ir.text, ir.data };
        log_mcp_result_detail("direct_completed", seq, tool_name_s, call_args, ir, ms, "");

        if (!ir.found) {
            log_msg(hf, tag, "FAIL -- tool \"%s\" disappeared during direct deferred dispatch", tool_name ? tool_name : "<null>");
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        if (ir.threw) {
            log_msg(hf, tag, "FAIL -- \"%s\" threw during direct deferred dispatch: %s (elapsed %lld ms)",
                tool_name ? tool_name : "<null>", ir.exception_msg.c_str(), ms);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }
        if (!ir.success) {
            log_msg(hf, tag, "FAIL -- \"%s\" success=false: %s (elapsed %lld ms)",
                tool_name ? tool_name : "<null>", ir.text.c_str(), ms);
            record_tool_status(tool_name_s, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return mcp_tool_call_status_t::failed;
        }

        std::string preview = ir.text;
        if (preview.size() > 200) preview = preview.substr(0, 200) + "...(truncated)";
        for (auto& c : preview) { if (c == '\n' || c == '\r') c = ' '; }
        log_msg(hf, tag, "PASS -- \"%s\" success=true direct=1 (elapsed %lld ms) -> %s",
            tool_name ? tool_name : "<null>", ms, preview.c_str());
        record_tool_status(tool_name_s, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
        return mcp_tool_call_status_t::passed;
    }

    void test_tool_driver_list_deferred_actions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        mcp_standalone::tool_result_t result;
        auto status = test_deferred_tool_direct(hf, "mcp.driver_list_deferred_actions", "driver_list_deferred_actions", {}, passed, failed, &result);
        if (status != mcp_tool_call_status_t::passed)
            return;
        if (g_mcp_deferred_action_id == 0) {
            uint64_t total = 0;
            payload_u64_field(result.data, "total", total);
            bool stale_failed = false;
            if (result.data.is_object() && result.data.contains("actions") && result.data["actions"].is_array()) {
                for (const auto& entry : result.data["actions"]) {
                    std::string st;
                    if (payload_string_field(entry, "status", st) && lower_copy(st) == "failed")
                        stale_failed = true;
                }
            }
            if (total != 0 || stale_failed) {
                log_msg(hf, "mcp.driver_list_deferred_actions",
                    "FAIL -- deferred watcher did not start, but list still returned total=%llu stale_failed=%d",
                    static_cast<unsigned long long>(total),
                    stale_failed ? 1 : 0);
                record_tool_status("driver_list_deferred_actions", mcp_tool_call_status_t::failed);
                passed.fetch_sub(1);
                failed.fetch_add(1);
                return;
            }
            log_msg(hf, "mcp.driver_list_deferred_actions",
                "PROOF -- deferred watcher start failed earlier and manager reported no stale actions");
            return;
        }
        bool found_expected = false;
        if (result.data.is_object() && result.data.contains("actions") && result.data["actions"].is_array()) {
            for (const auto& entry : result.data["actions"]) {
                uint64_t id = 0;
                if (payload_u64_field(entry, "id", id) && id == g_mcp_deferred_action_id)
                    found_expected = true;
            }
        }
        if (!found_expected) {
            log_msg(hf, "mcp.driver_list_deferred_actions",
                "FAIL -- deferred action id=%llu was not present in list payload",
                static_cast<unsigned long long>(g_mcp_deferred_action_id));
            record_tool_status("driver_list_deferred_actions", mcp_tool_call_status_t::failed);
            passed.fetch_sub(1);
            failed.fetch_add(1);
        }
    }

    void test_tool_driver_cancel_deferred_action(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_deferred_action_id == 0) {
            (void)skipped;
            if (g_mcp_deferred_action_resource_guarded) {
                log_msg(hf, "mcp.driver_cancel_deferred_action", "FAIL -- no deferred action id because watcher resource guard fired earlier");
                record_tool_status("driver_cancel_deferred_action", mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return;
            }
            log_msg(hf, "mcp.driver_cancel_deferred_action", "FAIL -- no deferred action id captured");
            record_fixture_failed_tool("driver_cancel_deferred_action", failed);
            return;
        }
        mcp_standalone::json args;
        args["action_id"] = g_mcp_deferred_action_id;
        test_deferred_tool_direct(hf, "mcp.driver_cancel_deferred_action", "driver_cancel_deferred_action", args, passed, failed);
    }

    void test_tool_driver_get_deferred_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_deferred_action_id == 0) {
            (void)skipped;
            if (g_mcp_deferred_action_resource_guarded) {
                log_msg(hf, "mcp.driver_get_deferred_results", "FAIL -- no deferred action id because watcher resource guard fired earlier");
                record_tool_status("driver_get_deferred_results", mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return;
            }
            log_msg(hf, "mcp.driver_get_deferred_results", "FAIL -- no deferred action id captured");
            record_fixture_failed_tool("driver_get_deferred_results", failed);
            return;
        }
        mcp_standalone::json args;
        args["action_id"] = g_mcp_deferred_action_id;
        test_deferred_tool_direct(hf, "mcp.driver_get_deferred_results", "driver_get_deferred_results", args, passed, failed);
    }

    void test_tool_driver_sniff_network_buffers(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string address = get_remote_ntclose_addr_str();
        if (address.empty()) {
            record_fixture_failed_tool("driver_sniff_network_buffers", failed);
            return;
        }
        mcp_standalone::json args;
        args["operation"] = "start";
        args["address"] = address;
        args["buffer_register"] = "rcx";
        args["size_register"] = "rdx";
        args["max_packets"] = 1;
        auto status = test_tool_call(hf, "mcp.driver_sniff_network_buffers", get_server(), "driver_sniff_network_buffers", args, passed, failed, skipped);
        if (status == mcp_tool_call_status_t::passed) {
            mcp_standalone::json stop_args;
            stop_args["operation"] = "stop";
            mcp_standalone::tool_result_t stop_result;
            auto stop_status = test_tool_call(hf, "mcp.driver_sniff_network_buffers.stop", get_server(), "driver_sniff_network_buffers", stop_args, passed, failed, skipped, false, &stop_result);
            (void)stop_status;
        }
    }

    void test_tool_driver_reassemble_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_loopback_tcp_pair_t pair;
        const auto payload = mcp_http_fixture_request_payload("/aida-driver-stream-fixture");
        if (!seed_driver_stream_reassembly(hf, "mcp.driver_reassemble_stream", pair, payload)) {
            driver_bridge::stream_reassemble_op(1, 0, 0, GetCurrentProcessId(), nullptr, nullptr, nullptr, nullptr, nullptr);
            record_fixture_failed_tool("driver_reassemble_stream", failed);
            return;
        }
        mcp_standalone::json args;
        args["operation"] = "get";
        args["src_port"] = pair.client_port;
        args["dst_port"] = pair.listen_port;
        args["pid"] = GetCurrentProcessId();
        test_tool_call(hf, "mcp.driver_reassemble_stream", get_server(), "driver_reassemble_stream", args, passed, failed, skipped);
        driver_bridge::stream_reassemble_op(1, pair.client_port, pair.listen_port, GetCurrentProcessId(), nullptr, nullptr, nullptr, nullptr, nullptr);
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





void test_tool_driver_enumerate_windows(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.driver_enumerate_windows", get_server(), "driver_enumerate_windows", {}, passed, failed, skipped);
    }


void test_tool_driver_assemble(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["assembly"] = "nop";
        test_tool_call(hf, "mcp.driver_assemble", get_server(), "driver_assemble", args, passed, failed, skipped);
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

    void test_tool_dbg_run_to_address(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_run_to_address_fixture_t fixture;
        if (!prepare_mcp_run_to_address_fixture(hf, "mcp.dbg_run_to_address", fixture)) {
            failed.fetch_add(1);
            record_tool_status("dbg_run_to_address", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(fixture.code);
        args["wait_for_completion"] = true;
        args["timeout_ms"] = 1000;
        auto status = test_tool_call(hf, "mcp.dbg_run_to_address", get_server(), "dbg_run_to_address", args, passed, failed, skipped);
        uint32_t exit_code = 0;
        const bool alive = driver_bridge::attached_process_alive(&exit_code);
        log_msg(hf, "mcp.dbg_run_to_address", "INFO -- post-call status=%d fixture_tid=%u fixture_entry=0x%llX active_tid=%u alive=%d exit_code=0x%08X",
            static_cast<int>(status),
            fixture.tid,
            static_cast<unsigned long long>(fixture.code),
            debugger_engine::g_state.active_tid,
            alive ? 1 : 0,
            static_cast<unsigned>(exit_code));
        cleanup_mcp_run_to_address_fixture(hf, "mcp.dbg_run_to_address", fixture);
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

    void test_tool_debugger_get_handles(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_handles", get_server(), "debugger_get_handles", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_seh_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.debugger_get_seh_chain", get_server(), "debugger_get_seh_chain", {}, passed, failed, skipped);
    }

    void test_tool_debugger_get_patches(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.debugger_get_patches";
        if (code_patcher::count() == 0) {
            if (!ensure_mcp_private_patch_fixture(hf, tag)) {
                log_msg(hf, tag, "FAIL -- patch-list fixture memory unavailable");
                record_fixture_failed_tool("debugger_get_patches", failed);
                return;
            }
            const std::vector<uint8_t> patched{0xCC};
            const int index = code_patcher::create_patch(g_mcp_patch_addr, patched, "TestLab debugger_get_patches fixture");
            if (index < 0) {
                log_msg(hf, tag, "FAIL -- code_patcher::create_patch failed addr=0x%016llX status=\"%s\" last_error=\"%s\"",
                    static_cast<unsigned long long>(g_mcp_patch_addr),
                    driver_bridge::status().c_str(),
                    driver_bridge::last_error().c_str());
                record_fixture_failed_tool("debugger_get_patches", failed);
                return;
            }
            g_mcp_get_patches_fixture_index = index;
            log_msg(hf, tag, "FIXTURE -- seeded tracked patch index=%d addr=0x%016llX bytes=CC",
                index,
                static_cast<unsigned long long>(g_mcp_patch_addr));
        }
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

    void test_tool_debugger_set_register(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint32_t tid = first_mcp_target_tid();
        if (tid == 0) {
            log_msg(hf, "mcp.debugger_set_register", "SKIP -- target thread not found");
            record_precondition_skipped_tool("debugger_set_register", skipped);
            return;
        }
        debugger_engine::g_state.active_tid = tid;
        auto regs = debugger_engine::get_registers();
        mcp_standalone::json args;
        args["tid"] = std::to_string(tid);
        args["register"] = "rax";
        args["hex_value"] = hex_u64(regs.rax);
        test_tool_call(hf, "mcp.debugger_set_register", get_server(), "debugger_set_register", args, passed, failed, skipped, true);
    }

    void test_tool_debugger_start_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        constexpr int trace_instructions = 4;
        mcp_trace_fixture_t fixture;
        if (!prepare_mcp_trace_fixture(hf, "mcp.debugger_start_trace", fixture, trace_instructions)) {
            failed.fetch_add(1);
            record_tool_status("debugger_start_trace", mcp_tool_call_status_t::failed);
            return;
        }
        mcp_standalone::json args;
        args["tid"] = std::to_string(fixture.tid);
        args["max_instructions"] = trace_instructions;
        args["timeout_ms"] = 3000;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.debugger_start_trace", get_server(), "debugger_start_trace", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed && result.data.is_object() && result.data.contains("trace_id") && result.data["trace_id"].is_string())
            g_mcp_debugger_trace_id = result.data["trace_id"].get<std::string>();
        cleanup_mcp_trace_fixture(hf, "mcp.debugger_start_trace", fixture);
    }

    void test_tool_debugger_get_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_debugger_trace_id.empty()) {
            log_msg(hf, "mcp.debugger_get_trace", "SKIP -- debugger_start_trace did not produce a trace id");
            record_precondition_skipped_tool("debugger_get_trace", skipped);
            return;
        }
        mcp_standalone::json args;
        args["trace_id"] = g_mcp_debugger_trace_id;
        args["offset"] = 0;
        args["limit"] = 16;
        test_tool_call(hf, "mcp.debugger_get_trace", get_server(), "debugger_get_trace", args, passed, failed, skipped);
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
        bool empty = false;
        {
            auto& st = debugger_engine::g_state;
            std::lock_guard<std::mutex> lk(st.watch_mutex);
            empty = st.watches.empty();
        }
        if (empty) {
            debugger_engine::add_watch("rax");
            log_msg(hf, "mcp.dbg_get_watches", "WATCH-FIXTURE -- added rax watch before list query");
        }
        test_tool_call(hf, "mcp.dbg_get_watches", get_server(), "dbg_get_watches", {}, passed, failed, skipped);
    }

    void test_tool_dbg_start_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_start_trace", get_server(), "dbg_start_trace", {}, passed, failed, skipped);
    }

    void test_tool_dbg_stop_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (debugger_engine::g_state.tracing.load(std::memory_order_acquire)) {
            mcp_step_fixture_t fixture;
            if (prepare_mcp_step_fixture(hf, "mcp.dbg_stop_trace.trace_step", fixture)) {
                mcp_standalone::json step_args;
                step_args["tid"] = std::to_string(fixture.tid);
                auto step = invoke_tool_bounded(get_server(), "debugger_step_into", step_args, tool_timeout_ms("debugger_step_into"));
                log_mcp_result_detail("fixture", 0, "debugger_step_into", step_args, step.result, step.elapsed_ms,
                    step.timed_out ? "dbg_trace_step_timeout" : "dbg_trace_step");
                cleanup_mcp_step_fixture(fixture);
            } else {
                log_msg(hf, "mcp.dbg_stop_trace", "TRACE-FIXTURE -- controlled trace step fixture setup failed");
            }
        }
        std::size_t trace_count = 0;
        {
            std::lock_guard<std::mutex> lk(debugger_engine::g_state.trace_mutex);
            trace_count = debugger_engine::g_state.trace_log.size();
        }
        log_msg(hf, "mcp.dbg_stop_trace", "TRACE-FIXTURE -- stop without unsafe external step active=%d records=%zu attached_pid=%u",
            debugger_engine::g_state.tracing.load(std::memory_order_acquire) ? 1 : 0,
            trace_count,
            driver_bridge::attached_pid());
        test_tool_call(hf, "mcp.dbg_stop_trace", get_server(), "dbg_stop_trace", {}, passed, failed, skipped);
    }

    void test_tool_dbg_get_trace(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.dbg_get_trace", get_server(), "dbg_get_trace", {}, passed, failed, skipped);
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

    void test_tool_dbg_scan_xrefs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t fixture = driver_bridge::allocate_memory(4096);
        if (fixture == 0) {
            log_msg(hf, "mcp.dbg_scan_xrefs", "FAIL -- allocate_memory failed for xref scan fixture");
            record_fixture_failed_tool("dbg_scan_xrefs", failed);
            return;
        }
        const uint64_t target = fixture + 0x20;
        std::vector<uint8_t> code(64, 0x90);
        code[0] = 0xE8;
        const int32_t rel = static_cast<int32_t>(target - (fixture + 5));
        std::memcpy(code.data() + 1, &rel, sizeof(rel));
        code[5] = 0xC3;
        code[0x20] = 0xC3;
        if (!driver_bridge::write_memory(fixture, code)) {
            log_msg(hf, "mcp.dbg_scan_xrefs", "FAIL -- write_memory failed for xref scan fixture addr=%s",
                hex_u64(fixture).c_str());
            driver_bridge::free_memory(fixture);
            record_fixture_failed_tool("dbg_scan_xrefs", failed);
            return;
        }
        mcp_standalone::json args;
        args["target_address"] = hex_u64(target);
        args["start_address"] = hex_u64(fixture);
        args["size"] = 0x1000;
        test_tool_call(hf, "mcp.dbg_scan_xrefs", get_server(), "dbg_scan_xrefs", args, passed, failed, skipped);
        driver_bridge::free_memory(fixture);
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
        if (!ensure_mcp_private_patch_fixture(hf, "mcp.dbg_add_patch")) {
            record_precondition_skipped_tool("dbg_add_patch", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_patch_addr);
        args["bytes"] = "90";
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.dbg_add_patch", get_server(), "dbg_add_patch", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed &&
            result.data.is_object() &&
            result.data.contains("index") &&
            result.data["index"].is_number_integer())
            g_mcp_patch_index = result.data["index"].get<int>();
    }

    void test_tool_dbg_remove_patch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_patch_index < 0) {
            log_msg(hf, "mcp.dbg_remove_patch", "SKIP -- no patch index captured from dbg_add_patch");
            record_precondition_skipped_tool("dbg_remove_patch", skipped);
            return;
        }
        mcp_standalone::json args;
        args["index"] = g_mcp_patch_index;
        test_tool_call(hf, "mcp.dbg_remove_patch", get_server(), "dbg_remove_patch", args, passed, failed, skipped);
        g_mcp_patch_index = -1;
    }

    void test_tool_dbg_nop_fill(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_mcp_private_patch_fixture(hf, "mcp.dbg_nop_fill")) {
            record_precondition_skipped_tool("dbg_nop_fill", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_patch_addr + 1);
        args["size"] = 1;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.dbg_nop_fill", get_server(), "dbg_nop_fill", args, passed, failed, skipped, false, &result);
        if (status != mcp_tool_call_status_t::passed)
            return;

        int patch_index = 0;
        if (result.data.is_object() && result.data.contains("index") && result.data["index"].is_number_integer())
            patch_index = result.data["index"].get<int>();

        mcp_standalone::json cleanup_args;
        cleanup_args["index"] = patch_index;
        auto cleanup = invoke_tool_bounded(get_server(), "dbg_remove_patch", cleanup_args, tool_timeout_ms("dbg_remove_patch"));
        log_mcp_result_detail("cleanup", 0, "dbg_remove_patch", cleanup_args, cleanup.result, cleanup.elapsed_ms,
            cleanup.timed_out ? "dbg_nop_fill_cleanup_timeout" : "dbg_nop_fill_cleanup");
        if (cleanup.timed_out || !cleanup.result.found || cleanup.result.threw || !cleanup.result.success) {
            log_msg(hf, "mcp.dbg_nop_fill", "FAIL -- cleanup remove patch failed index=%d timeout=%d found=%d threw=%d success=%d",
                patch_index,
                cleanup.timed_out ? 1 : 0,
                cleanup.result.found ? 1 : 0,
                cleanup.result.threw ? 1 : 0,
                cleanup.result.success ? 1 : 0);
            passed.fetch_sub(1);
            failed.fetch_add(1);
            convert_tool_pass_to_fail("dbg_nop_fill");
        }
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

void test_tool_scanner_undo(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_undo", get_server(), "scanner_undo", {}, passed, failed, skipped);
    }

    void test_tool_scanner_address_list_manage_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const uint32_t value = 0x4D3C2B1A;
        std::vector<uint8_t> bytes(sizeof(value), 0);
        std::memcpy(bytes.data(), &value, sizeof(value));
        if (!ensure_mcp_private_bytes(hf, "mcp.scanner_address_list_manage.add", g_mcp_scanner_addr, 4096, bytes)) {
            record_precondition_skipped_tool("scanner_address_list_manage", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_scanner_addr);
        args["description"] = "mcp_test_value";
        args["value_type"] = "int32";
        test_tool_action_call(hf, "mcp.scanner_address_list_manage.add", "scanner_address_list_manage", "add", args, passed, failed, skipped);
    }

    void test_tool_scanner_address_list_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_action_call(hf, "mcp.scanner_address_list_manage.remove", "scanner_address_list_manage", "remove", args, passed, failed, skipped);
    }

    void test_tool_scanner_address_list_manage_freeze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["index"] = 0;
        args["enable"] = true;
        test_tool_action_call(hf, "mcp.scanner_address_list_manage.freeze", "scanner_address_list_manage", "freeze", args, passed, failed, skipped);
    }

    void test_tool_read_memory_typed_value(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = driver_bridge::allocate_memory(16);
        if (addr == 0) {
            log_msg(hf, "mcp.read_memory.typed", "SKIP -- allocate_memory failed for typed memory read fixture");
            record_precondition_skipped_tool("read_memory", skipped);
            return;
        }
        std::vector<uint8_t> bytes = {0x39, 0x30, 0x00, 0x00};
        if (!driver_bridge::write_memory(addr, bytes)) {
            log_msg(hf, "mcp.read_memory.typed", "SKIP -- write_memory failed for typed memory read fixture addr=0x%016llX",
                static_cast<unsigned long long>(addr));
            driver_bridge::free_memory(addr);
            record_precondition_skipped_tool("read_memory", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["size"] = 4;
        args["value_type"] = "int32";
        test_tool_call(hf, "mcp.read_memory.typed", get_server(), "read_memory", args, passed, failed, skipped);
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

    void test_tool_scanner_address_list_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.scanner_address_list_manage.list", "scanner_address_list_manage", "list", {}, passed, failed, skipped);
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
        args["range_base"] = hex_u64(g_mcp_scanner_pointer_addr & ~0xFFFULL);
        args["range_size"] = 4096;
        args["timeout_ms"] = 30000;
        test_tool_call(hf, "mcp.scanner_pointer_scan", get_server(), "scanner_pointer_scan", args, passed, failed, skipped);
    }

    void test_tool_scanner_cancel_pointer_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.scanner_cancel_pointer_scan", get_server(), "scanner_cancel_pointer_scan", {}, passed, failed, skipped);
    }



void test_tool_scanner_struct_manage_define(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_scanner_addr == 0 && !ensure_mcp_private_bytes(hf, "mcp.scanner_struct_manage.define", g_mcp_scanner_addr, 4096, {0x1A, 0x2B, 0x3C, 0x4D})) {
            record_precondition_skipped_tool("scanner_struct_manage", skipped);
            return;
        }
        mcp_standalone::json args;
        args["name"] = "test_struct";
        args["base_address"] = hex_u64(g_mcp_scanner_addr);
        test_tool_action_call(hf, "mcp.scanner_struct_manage.define", "scanner_struct_manage", "define", args, passed, failed, skipped);
    }

    void test_tool_scanner_struct_manage_add_field(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_index"] = 0;
        args["name"] = "field1";
        args["field_type"] = "int32";
        args["offset"] = 0;
        test_tool_action_call(hf, "mcp.scanner_struct_manage.add_field", "scanner_struct_manage", "add_field", args, passed, failed, skipped);
    }

    void test_tool_scanner_struct_manage_get(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_index"] = 0;
        test_tool_action_call(hf, "mcp.scanner_struct_manage.get", "scanner_struct_manage", "get", args, passed, failed, skipped);
    }

    void test_tool_scanner_struct_manage_export_c(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["struct_index"] = 0;
        test_tool_action_call(hf, "mcp.scanner_struct_manage.export_c", "scanner_struct_manage", "export_c", args, passed, failed, skipped);
    }

    struct find_what_accesses_writer_context_t {
        uint64_t watched_addr = 0;
        std::shared_ptr<std::atomic<bool>> stop_writer;
        std::shared_ptr<std::atomic<int>> writer_attempts;
        std::shared_ptr<std::atomic<int>> writer_success;
        std::shared_ptr<std::atomic<bool>> writer_done;
    };

    void run_find_what_accesses_writer(find_what_accesses_writer_context_t ctx) {
        Sleep(100);
        const uint32_t pid = driver_bridge::attached_pid();
        uint64_t ntdll_base = 0;
        for (const auto& m : driver_bridge::enumerate_modules_for(pid)) {
            std::string lower = m.name;
            for (char& c : lower)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower == "ntdll.dll") {
                ntdll_base = m.base;
                break;
            }
        }
        const uint64_t rtl_fill = ntdll_base ? driver_bridge::resolve_export(ntdll_base, "RtlFillMemory") : 0;
        for (int i = 0; i < 60 && !ctx.stop_writer->load(std::memory_order_acquire); ++i) {
            std::vector<uint8_t> bytes = {
                static_cast<uint8_t>(0x40u + (i & 0x3Fu)),
                static_cast<uint8_t>(0x51u ^ (i & 0x7Fu)),
                static_cast<uint8_t>(0x62u + ((i * 3) & 0x1Fu)),
                static_cast<uint8_t>(0x73u ^ ((i * 5) & 0x3Fu))
            };
            ctx.writer_attempts->fetch_add(1, std::memory_order_acq_rel);
            bool ok = false;
            if (pid != 0 && rtl_fill != 0) {
                (void)page_guard_engine::remote_thread_call(pid, rtl_fill, ctx.watched_addr,
                    static_cast<uint64_t>(bytes.size()), bytes[0], 0, 2000, "find_what_accesses_fixture_fill");
                std::vector<uint8_t> verify;
                if (driver_bridge::read_memory(ctx.watched_addr, bytes.size(), verify) &&
                    verify.size() >= bytes.size()) {
                    ok = true;
                    for (size_t vi = 0; vi < bytes.size(); ++vi) {
                        if (verify[vi] != bytes[0]) {
                            ok = false;
                            break;
                        }
                    }
                }
            }
            if (!ok)
                ok = driver_bridge::write_memory(ctx.watched_addr, bytes);
            if (ok)
                ctx.writer_success->fetch_add(1, std::memory_order_acq_rel);
            Sleep(50);
        }
        ctx.writer_done->store(true, std::memory_order_release);
    }

    bool wait_find_what_accesses_writer_done(const std::shared_ptr<std::atomic<bool>>& done, DWORD timeout_ms) {
        const DWORD start = GetTickCount();
        while (done && !done->load(std::memory_order_acquire)) {
            if (GetTickCount() - start >= timeout_ms)
                return false;
            Sleep(20);
        }
        return true;
    }

    void test_tool_find_what_accesses(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_scanner_addr == 0 && !ensure_mcp_private_bytes(hf, "mcp.find_what_accesses", g_mcp_scanner_addr, 4096, {0x1A, 0x2B, 0x3C, 0x4D})) {
            record_precondition_skipped_tool("find_what_accesses", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_scanner_addr);
        args["size"] = 4;
        args["type"] = "write";
        args["wait_ms"] = 2000;
        args["limit"] = 8;
        const uint64_t watched_addr = g_mcp_scanner_addr;
        auto stop_writer = std::make_shared<std::atomic<bool>>(false);
        auto writer_attempts = std::make_shared<std::atomic<int>>(0);
        auto writer_success = std::make_shared<std::atomic<int>>(0);
        auto writer_done = std::make_shared<std::atomic<bool>>(false);
        find_what_accesses_writer_context_t writer_ctx;
        writer_ctx.watched_addr = watched_addr;
        writer_ctx.stop_writer = stop_writer;
        writer_ctx.writer_attempts = writer_attempts;
        writer_ctx.writer_success = writer_success;
        writer_ctx.writer_done = writer_done;
        bool writer_posted = false;
        DWORD writer_post_gle = ERROR_SUCCESS;
        try {
            writer_posted = work_queue::post([writer_ctx]() {
                run_find_what_accesses_writer(writer_ctx);
            });
            writer_post_gle = GetLastError();
        } catch (const std::exception& ex) {
            writer_post_gle = GetLastError();
            if (writer_post_gle == ERROR_SUCCESS)
                writer_post_gle = ERROR_NOT_ENOUGH_MEMORY;
            log_msg(hf, "mcp.find_what_accesses", "WARN -- access trigger work_queue post exception gle=%lu err=%s",
                static_cast<unsigned long>(writer_post_gle),
                compact_text(ex.what(), 700).c_str());
        } catch (...) {
            writer_post_gle = GetLastError();
            if (writer_post_gle == ERROR_SUCCESS)
                writer_post_gle = ERROR_NOT_ENOUGH_MEMORY;
            log_msg(hf, "mcp.find_what_accesses", "WARN -- access trigger work_queue post exception gle=%lu err=unknown",
                static_cast<unsigned long>(writer_post_gle));
        }
        if (!writer_posted) {
            if (writer_post_gle == ERROR_SUCCESS)
                writer_post_gle = ERROR_NOT_READY;
            writer_done->store(true, std::memory_order_release);
            log_msg(hf, "mcp.find_what_accesses", "FAIL -- access trigger work_queue post failed gle=%lu text=%s; fixture resource guard fired before tool dispatch",
                static_cast<unsigned long>(writer_post_gle),
                format_win32_error(writer_post_gle).c_str());
            record_tool_status("find_what_accesses", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, "mcp.find_what_accesses", "trigger work_queue posted watched_addr=0x%016llX attached_pid=%u",
            static_cast<unsigned long long>(watched_addr),
            driver_bridge::attached_pid());
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.find_what_accesses", get_server(), "find_what_accesses", args, passed, failed, skipped, true, &result);
        stop_writer->store(true, std::memory_order_release);
        if (!wait_find_what_accesses_writer_done(writer_done, 3000))
            log_msg(hf, "mcp.find_what_accesses", "WARN -- access trigger work_queue worker did not signal completion within shutdown wait");
        uint64_t total_captures = 0;
        uint64_t returned = 0;
        size_t accesses = 0;
        if (result.data.is_object()) {
            payload_u64_field(result.data, "total_captures", total_captures);
            payload_u64_field(result.data, "returned", returned);
            payload_array_count(result.data, "accesses", accesses);
        }
        log_msg(hf, "mcp.find_what_accesses",
            "post-monitor status=%d writer_attempts=%d writer_success=%d total_captures=%llu returned=%llu accesses=%zu attached_pid=%u",
            static_cast<int>(status),
            writer_attempts->load(std::memory_order_acquire),
            writer_success->load(std::memory_order_acquire),
            static_cast<unsigned long long>(total_captures),
            static_cast<unsigned long long>(returned),
            accesses,
            driver_bridge::attached_pid());
    }

    void test_tool_watch_memory_layout(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_scanner_addr == 0) {
            log_msg(hf, "mcp.watch_memory_layout", "SKIP -- scanner struct fixture address is not available");
            record_precondition_skipped_tool("watch_memory_layout", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_scanner_addr);
        args["struct_name"] = "test_struct";
        args["refresh_rate_ms"] = 0;
        test_tool_call(hf, "mcp.watch_memory_layout", get_server(), "watch_memory_layout", args, passed, failed, skipped);
    }

    void test_tool_assert_memory_type(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_scanner_addr == 0) {
            log_msg(hf, "mcp.assert_memory_type", "SKIP -- scanner memory fixture address is not available");
            record_precondition_skipped_tool("assert_memory_type", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_scanner_addr);
        args["offset"] = 0;
        args["expected_type"] = "int32";
        args["duration_ms"] = 0;
        args["sample_interval_ms"] = 50;
        args["min"] = 0;
        args["max"] = 2147483647;
        test_tool_call(hf, "mcp.assert_memory_type", get_server(), "assert_memory_type", args, passed, failed, skipped);
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
        uint64_t addr = 0;
        std::vector<uint8_t> bytes(4096, 0x90);
        std::memcpy(bytes.data() + 0x80, crypto_scanner::constants::aes_sbox, 256);
        if (!ensure_mcp_private_bytes(hf, "mcp.scan_crypto_constants", addr, bytes.size(), bytes)) {
            record_precondition_skipped_tool("scan_crypto_constants", skipped);
            return;
        }
        mcp_standalone::json args;
        args["range_base"] = hex_u64(addr & ~0xFFFULL);
        args["range_size"] = 4096;
        args["max_regions"] = 4;
        args["max_bytes"] = 4096;
        args["max_hits"] = 64;
        args["timeout_ms"] = 4500;
        test_tool_call(hf, "mcp.scan_crypto_constants", get_server(), "scan_crypto_constants", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
    }

    void test_tool_generate_aob_signature(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t addr = 0;
        std::vector<uint8_t> bytes = {
            0x48, 0x89, 0xC8,
            0x48, 0x83, 0xC0, 0x05,
            0x48, 0x31, 0xD0,
            0xC3
        };
        bytes.resize(4096, 0x90);
        if (!ensure_mcp_private_bytes(hf, "mcp.generate_aob_sig", addr, bytes.size(), bytes)) {
            record_precondition_skipped_tool("generate_aob_signature", skipped);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(addr);
        args["instruction_count"] = 4;
        test_tool_call(hf, "mcp.generate_aob_sig", get_server(), "generate_aob_signature", args, passed, failed, skipped);
        driver_bridge::free_memory(addr);
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

    void test_tool_fuzzer_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!require_tool_read_only_metadata(hf, "mcp.fuzzer_manage.start", "fuzzer_manage", false, failed))
            return;
        std::vector<uint8_t> bytes(4096, 0x90);
        bytes[0] = 0xC3;
        if (!ensure_mcp_private_bytes(hf, "mcp.fuzzer_manage.start", g_mcp_fuzz_addr, bytes.size(), bytes)) {
            record_fixture_failed_tool("fuzzer_manage", failed);
            return;
        }
        std::vector<uint8_t> input_bytes(16, 0);
        for (size_t i = 0; i < input_bytes.size(); ++i)
            input_bytes[i] = static_cast<uint8_t>((i * 31u + 0x21u) & 0xFFu);
        if (!ensure_mcp_private_bytes(hf, "mcp.fuzzer_manage.start", g_mcp_fuzz_input_addr, input_bytes.size(), input_bytes)) {
            record_fixture_failed_tool("fuzzer_manage", failed);
            return;
        }
        log_msg(hf, "mcp.fuzzer_manage.start", "fixture target=0x%016llX input=0x%016llX attached_pid=%u",
            static_cast<unsigned long long>(g_mcp_fuzz_addr),
            static_cast<unsigned long long>(g_mcp_fuzz_input_addr),
            driver_bridge::attached_pid());
        mcp_standalone::json args;
        args["target_address"] = hex_u64(g_mcp_fuzz_addr);
        args["end_address"] = hex_u64(g_mcp_fuzz_addr + 1);
        args["input_address"] = hex_u64(g_mcp_fuzz_input_addr);
        args["max_iterations"] = 8;
        args["input_size"] = 16;
        auto call_status = test_tool_action_call(hf, "mcp.fuzzer_manage.start", "fuzzer_manage", "start", args, passed, failed, skipped);
        if (call_status != mcp_tool_call_status_t::passed)
            return;
        const auto setup_start = std::chrono::steady_clock::now();
        while (!fuzzer_engine::g_state.setup_complete.load() &&
               (fuzzer_engine::g_state.running.load() || fuzzer_engine::g_state.worker_active.load())) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - setup_start).count();
            if (elapsed >= 5000)
                break;
            Sleep(25);
        }
        if (!fuzzer_engine::g_state.setup_complete.load() || !fuzzer_engine::g_state.setup_success.load()) {
            std::string setup_error;
            {
                std::lock_guard<std::mutex> lk(fuzzer_engine::g_state.mutex);
                setup_error = fuzzer_engine::g_state.setup_error;
            }
            log_msg(hf, "mcp.fuzzer_manage.start", "FAIL -- fuzzer setup incomplete success=%d complete=%d running=%d worker=%d err=%s",
                fuzzer_engine::g_state.setup_success.load() ? 1 : 0,
                fuzzer_engine::g_state.setup_complete.load() ? 1 : 0,
                fuzzer_engine::g_state.running.load() ? 1 : 0,
                fuzzer_engine::g_state.worker_active.load() ? 1 : 0,
                setup_error.c_str());
            fuzzer_engine::stop_fuzzing();
            fuzzer_engine::wait_until_idle(12000);
            record_fixture_failed_tool("fuzzer_manage", failed);
            return;
        }
        for (int i = 0; i < 20; ++i) {
            auto status = invoke_tool_bounded(get_server(), "fuzzer_manage", mcp_standalone::json{{"action", "results"}}, 1000);
            uint64_t execs = 0;
            if (!status.timed_out && status.result.success && status.result.data.is_object())
                payload_u64_field(status.result.data, "total_executions", execs);
            log_msg(hf, "mcp.fuzzer_manage.start", "poll execs=%llu timed_out=%d success=%d running=%d worker=%d setup_success=%d",
                static_cast<unsigned long long>(execs),
                status.timed_out ? 1 : 0,
                status.result.success ? 1 : 0,
                fuzzer_engine::g_state.running.load() ? 1 : 0,
                fuzzer_engine::g_state.worker_active.load() ? 1 : 0,
                fuzzer_engine::g_state.setup_success.load() ? 1 : 0);
            if (execs > 0) {
                log_msg(hf, "mcp.fuzzer_manage.start", "semantic PASS -- fuzzer executed fixture iterations=%llu",
                    static_cast<unsigned long long>(execs));
                return;
            }
            Sleep(50);
        }
        log_msg(hf, "mcp.fuzzer_manage.start", "FAIL -- fuzzer reported no executions after successful setup");
        fuzzer_engine::stop_fuzzing();
        fuzzer_engine::wait_until_idle(12000);
        record_fixture_failed_tool("fuzzer_manage", failed);
    }

    void test_tool_fuzzer_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto status = test_tool_action_call(hf, "mcp.fuzzer_manage.stop", "fuzzer_manage", "stop", {}, passed, failed, skipped);
        const bool idle = fuzzer_engine::wait_until_idle(12000);
        log_msg(hf, "mcp.fuzzer_manage.stop", "post-stop idle=%d running=%d worker=%d status=%d",
            idle ? 1 : 0,
            fuzzer_engine::g_state.running.load() ? 1 : 0,
            fuzzer_engine::g_state.worker_active.load() ? 1 : 0,
            static_cast<int>(status));
        if (status == mcp_tool_call_status_t::passed && !idle)
            record_fixture_failed_tool("fuzzer_manage", failed);
    }

    void test_tool_fuzzer_manage_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.fuzzer_manage.results", "fuzzer_manage", "results", {}, passed, failed, skipped);
    }

    void test_tool_auto_decrypt_strings(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!require_tool_read_only_metadata(hf, "mcp.auto_decrypt_strings", "auto_decrypt_strings", false, failed))
            return;
        uint64_t addr = 0;
        std::vector<uint8_t> bytes(128, 0);
        const char marker[] = "AIDA_MCP_DECRYPT_FIXTURE";
        std::memcpy(bytes.data(), marker, sizeof(marker));
        if (!ensure_mcp_private_bytes(hf, "mcp.auto_decrypt_strings", addr, 128, bytes)) {
            record_precondition_skipped_tool("auto_decrypt_strings", skipped);
            return;
        }
        seed_mcp_xref_to_region_fixture(addr, addr + 0x40, "aida_mcp_decrypt_xref_fixture", "lea rcx, [AIDA_MCP_DECRYPT_FIXTURE]");
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
        const char* tag = "mcp.hunt_integrity_checkers";
        const uint32_t primary_pid = g_mcp_target_pid;
        const bool primary_unavailable = g_mcp_target_unavailable;
        const uint32_t primary_active = driver_bridge::attached_pid();
        if (!ensure_mcp_target_live(hf, tag)) {
            record_precondition_skipped_tool("hunt_integrity_checkers", skipped);
            return;
        }

        mcp_hunt_sidecar_t sidecar;
        if (!launch_hunt_integrity_sidecar(hf, tag, sidecar)) {
            g_mcp_target_pid = primary_pid;
            g_mcp_target_unavailable = primary_unavailable;
            (void)restore_mcp_target(hf, tag);
            record_precondition_skipped_tool("hunt_integrity_checkers", skipped);
            return;
        }

        auto restore_primary = [&]() {
            g_mcp_target_pid = primary_pid;
            g_mcp_target_unavailable = primary_unavailable;
            const bool restored = primary_pid != 0 && restore_mcp_target(hf, tag);
            uint32_t win32_code = 0;
            const bool win32_alive = primary_pid != 0 && process_alive_by_pid(primary_pid, &win32_code);
            uint32_t bridge_code = 0;
            const bool bridge_alive = primary_pid != 0 &&
                driver_bridge::attached_pid() == primary_pid &&
                driver_bridge::attached_process_alive(&bridge_code);
            g_mcp_target_unavailable = !(restored && bridge_alive);
            log_msg(hf, tag, "PRIMARY-RESTORE -- original_pid=%u original_active=%u restored=%d active_now=%u win32_alive=%d win32_code=0x%08X bridge_alive=%d bridge_code=0x%08X unavailable=%d",
                primary_pid,
                primary_active,
                restored ? 1 : 0,
                driver_bridge::attached_pid(),
                win32_alive ? 1 : 0,
                win32_code,
                bridge_alive ? 1 : 0,
                bridge_code,
                g_mcp_target_unavailable ? 1 : 0);
            return restored && bridge_alive;
        };

        if (!wait_hunt_sidecar_attach_ready(hf, tag, sidecar, 8000)) {
            close_hunt_integrity_sidecar(hf, tag, sidecar, true);
            restore_primary();
            record_precondition_skipped_tool("hunt_integrity_checkers", skipped);
            return;
        }

        g_mcp_target_pid = sidecar.pid;
        g_mcp_target_unavailable = false;
        uint64_t hunt_addr = 0;
        std::vector<uint8_t> bytes(4096);
        for (size_t i = 0; i < bytes.size(); ++i)
            bytes[i] = static_cast<uint8_t>((i * 31u + 0x53u) & 0xFFu);
        if (!ensure_mcp_private_bytes(hf, tag, hunt_addr, bytes.size(), bytes)) {
            log_msg(hf, tag, "FAIL -- isolated hunt fixture memory setup failed sidecar_pid=%lu addr=0x%016llX size=%zu active_pid=%u",
                static_cast<unsigned long>(sidecar.pid),
                static_cast<unsigned long long>(hunt_addr),
                bytes.size(),
                driver_bridge::attached_pid());
            close_hunt_integrity_sidecar(hf, tag, sidecar, true);
            restore_primary();
            record_fixture_failed_tool("hunt_integrity_checkers", failed);
            return;
        }
        log_msg(hf, tag, "SAFE-FIXTURE -- isolated hunt target sidecar_pid=%lu addr=0x%016llX region_size=%zu tool_size=%u active_pid=%u primary_pid=%u",
            static_cast<unsigned long>(sidecar.pid),
            static_cast<unsigned long long>(hunt_addr),
            bytes.size(),
            128u,
            driver_bridge::attached_pid(),
            primary_pid);
        mcp_standalone::json args;
        args["target_address"] = hex_u64(hunt_addr);
        args["target_size"] = 128;
        args["duration_ms"] = 1000;
        auto status = test_tool_call(hf, tag, get_server(), "hunt_integrity_checkers", args, passed, failed, skipped);
        integrity_hunter::stop_hunt();
        const bool idle = integrity_hunter::wait_until_idle(12000);
        DWORD sidecar_exit = 0;
        const bool sidecar_exited = hunt_sidecar_exited(sidecar, sidecar_exit);
        bool fixture_freed = false;
        if (!sidecar_exited && hunt_addr != 0 && driver_bridge::attached_pid() == sidecar.pid)
            fixture_freed = driver_bridge::free_memory(hunt_addr);
        log_msg(hf, tag, "post-call idle=%d status=%d hunting=%d worker=%d install_complete=%d install_success=%d sidecar_pid=%lu sidecar_exited=%d sidecar_exit=0x%08lX fixture_addr=0x%016llX fixture_freed=%d active_pid=%u",
            idle ? 1 : 0,
            static_cast<int>(status),
            integrity_hunter::g_state.hunting.load() ? 1 : 0,
            integrity_hunter::g_state.worker_active.load() ? 1 : 0,
            integrity_hunter::g_state.install_complete.load() ? 1 : 0,
            integrity_hunter::g_state.install_success.load() ? 1 : 0,
            static_cast<unsigned long>(sidecar.pid),
            sidecar_exited ? 1 : 0,
            static_cast<unsigned long>(sidecar_exit),
            static_cast<unsigned long long>(hunt_addr),
            fixture_freed ? 1 : 0,
            driver_bridge::attached_pid());
        close_hunt_integrity_sidecar(hf, tag, sidecar, true);
        const bool primary_restored = restore_primary();
        if (status == mcp_tool_call_status_t::passed && !idle)
            record_fixture_failed_tool("hunt_integrity_checkers", failed);
        if (status == mcp_tool_call_status_t::passed && !primary_restored)
            record_fixture_failed_tool("hunt_integrity_checkers", failed);
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

    void test_tool_live_monitor_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!require_tool_read_only_metadata(hf, "mcp.live_monitor_manage.start", "live_monitor_manage", false, failed))
            return;
        if (g_mcp_live_monitor_addr == 0 && !prepare_live_monitor_regions(hf, "mcp.live_monitor_manage.start")) {
            log_msg(hf, "mcp.live_monitor_manage.start", "FAIL -- live monitor fixture memory setup failed");
            record_fixture_failed_tool("live_monitor_manage", failed);
            return;
        }
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_live_monitor_addr);
        args["size"] = 128;
        args["name"] = "mcp_live_monitor_fixture";
        args["backend"] = "polling";
        args["timeout_ms"] = 1500;
        auto status = test_tool_action_call(hf, "mcp.live_monitor_manage.start", "live_monitor_manage", "start", args, passed, failed, skipped);
        if (status != mcp_tool_call_status_t::passed) {
            log_msg(hf, "mcp.live_monitor_manage.start", "INFO -- monitor did not start; skipping access trigger and cleaning fixture buffers");
            cleanup_live_monitor_regions(hf, "mcp.live_monitor_manage.start");
            return;
        }
        trigger_live_monitor_accesses(hf, "mcp.live_monitor_manage.start");
        if (!ensure_mcp_target_live(hf, "mcp.live_monitor_manage.start")) {
            failed.fetch_add(1);
            cleanup_live_monitor_regions(hf, "mcp.live_monitor_manage.start");
        }
    }

    void test_tool_live_monitor_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!require_tool_read_only_metadata(hf, "mcp.live_monitor_manage.stop", "live_monitor_manage", false, failed))
            return;
        mcp_standalone::json args;
        args["require_captures"] = true;
        test_tool_action_call(hf, "mcp.live_monitor_manage.stop", "live_monitor_manage", "stop", args, passed, failed, skipped);
        cleanup_live_monitor_regions(hf, "mcp.live_monitor_manage.stop");
    }

    void test_tool_symbolic_execution_deobfuscate(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
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
        if (!ensure_mcp_private_bytes(hf, "mcp.symbolic_execution.deobfuscate", g_mcp_symbolic_deobf_addr, code.size(), code)) {
            log_msg(hf, "mcp.symbolic_execution.deobfuscate", "FAIL -- symbolic deobfuscation fixture setup failed");
            record_fixture_failed_tool("symbolic_execution", failed);
            return;
        }
        mcp_standalone::json args;
        args["entry_address"] = hex_u64(g_mcp_symbolic_deobf_addr);
        args["max_instructions"] = 128;
        test_tool_action_call(hf, "mcp.symbolic_execution.deobfuscate", "symbolic_execution", "deobfuscate", args, passed, failed, skipped);
    }

    void test_tool_symbolic_execution_slice_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.symbolic_execution.slice_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["start_address"] = addr;
        args["end_address"] = hex_u64(std::strtoull(addr.c_str(), nullptr, 16) + 64);
        args["target_register"] = "rax";
        args["max_instructions"] = 128;
        test_tool_action_call(hf, "mcp.symbolic_execution.slice_function", "symbolic_execution", "slice_function", args, passed, failed, skipped);
    }

    void test_tool_symbolic_execution_solve_path(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.symbolic_execution.solve_path", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["start_address"] = addr;
        args["target_address"] = hex_u64(std::strtoull(addr.c_str(), nullptr, 16) + 16);
        args["symbolic_registers"] = "rax";
        args["max_instructions"] = 64;
        test_tool_action_call(hf, "mcp.symbolic_execution.solve_path", "symbolic_execution", "solve_path", args, passed, failed, skipped);
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

    void test_tool_analysis_query_imports(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.analysis_query.imports", "analysis_query", "imports", {}, passed, failed, skipped);
    }

void test_tool_analysis_query_exports(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["module_name"] = "ntdll.dll";
        args["max_entries"] = 128;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.analysis_query.exports", "analysis_query", "exports", args, passed, failed, skipped, false, &result);
        if (status != mcp_tool_call_status_t::passed)
            return;
        uint64_t count = 0;
        const bool has_count = payload_u64_field(result.data, "count", count);
        size_t exports = 0;
        const bool has_exports = payload_array_count(result.data, "exports", exports);
        if (!has_count || count == 0 || !has_exports || exports == 0) {
            log_msg(hf, "mcp.analysis_query.exports", "FAIL -- selected module export list empty count_present=%d count=%llu exports_present=%d exports=%zu data=%s",
                has_count ? 1 : 0,
                static_cast<unsigned long long>(count),
                has_exports ? 1 : 0,
                exports,
                compact_json(result.data, 900).c_str());
            if (passed.load(std::memory_order_acquire) > 0)
                passed.fetch_sub(1, std::memory_order_acq_rel);
            failed.fetch_add(1, std::memory_order_acq_rel);
            convert_tool_pass_to_fail("analysis_query");
        }
    }

    bool pdb_fixture_loaded_counts(size_t& symbols, size_t& types, std::string& status_text) {
        std::lock_guard<std::mutex> lk(symbol_store::g_state.mutex);
        auto it = symbol_store::g_state.modules.find("target_protocol.exe");
        if (it == symbol_store::g_state.modules.end()) {
            status_text = "module entry missing";
            symbols = 0;
            types = 0;
            return false;
        }
        const auto& mod = it->second;
        status_text = mod.status_text;
        symbols = mod.pdb.symbols.size();
        types = mod.pdb.structs.size() + mod.pdb.enums.size();
        return mod.pdb.loaded && symbols > 0 && types > 0;
    }

    bool ensure_pdb_fixture_loaded(HANDLE hf, const char* tag) {
        size_t symbols = 0;
        size_t types = 0;
        std::string status_text;
        if (pdb_fixture_loaded_counts(symbols, types, status_text)) {
            log_msg(hf, tag, "PDB fixture already loaded module=target_protocol.exe symbols=%zu types=%zu", symbols, types);
            return true;
        }

        std::filesystem::path pdb_path = std::filesystem::current_path() / "test_binaries" / "target_protocol" / "target_protocol.pdb";
        std::error_code ec;
        if (!std::filesystem::exists(pdb_path, ec) || ec) {
            log_msg(hf, tag, "FAIL -- PDB fixture missing path=%s ec=%d msg=%s", pdb_path.string().c_str(), ec.value(), ec.message().c_str());
            return false;
        }

        symbol_store::load_pdb_from_explicit_path("target_protocol.exe", 0x140000000ull, 0x100000ull, pdb_path.string());
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
        while (std::chrono::steady_clock::now() < deadline) {
            if (pdb_fixture_loaded_counts(symbols, types, status_text)) {
                log_msg(hf, tag, "PDB fixture loaded module=target_protocol.exe symbols=%zu types=%zu status=\"%s\"", symbols, types, status_text.c_str());
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        pdb_fixture_loaded_counts(symbols, types, status_text);
        log_msg(hf, tag, "FAIL -- PDB fixture did not load within timeout symbols=%zu types=%zu status=\"%s\"", symbols, types, status_text.c_str());
        return false;
    }

    void test_tool_analysis_query_types(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_pdb_fixture_loaded(hf, "mcp.analysis_query.types")) {
            record_tool_status("analysis_query", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["module"] = "target_protocol.exe";
        args["filter"] = "protocol";
        args["limit"] = 64;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.analysis_query.types", "analysis_query", "types", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            uint64_t returned = 0;
            payload_u64_field(result.data, "returned", returned);
            log_msg(hf, "mcp.analysis_query.types", "PDB-PROOF -- returned=%llu filter=protocol module=target_protocol.exe", static_cast<unsigned long long>(returned));
        }
    }

    void test_tool_analysis_query_type_definition(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["name"] = "HANDLE";
        test_tool_action_call(hf, "mcp.analysis_query.type_definition", "analysis_query", "type_definition", args, passed, failed, skipped);
    }

    void test_tool_analysis_query_pdb_symbols(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_pdb_fixture_loaded(hf, "mcp.analysis_query.pdb_symbols")) {
            record_tool_status("analysis_query", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["module"] = "target_protocol.exe";
        args["filter"] = "vuln_";
        args["functions_only"] = true;
        args["limit"] = 64;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.analysis_query.pdb_symbols", "analysis_query", "pdb_symbols", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            uint64_t returned = 0;
            payload_u64_field(result.data, "returned", returned);
            log_msg(hf, "mcp.analysis_query.pdb_symbols", "PDB-PROOF -- returned=%llu filter=vuln_ module=target_protocol.exe", static_cast<unsigned long long>(returned));
        }
    }

    void test_tool_analysis_query_binary_map_overview(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["max_functions"] = 8;
        args["max_globals"] = 4;
        args["include_imports"] = false;
        args["include_exports"] = false;
        args["include_xrefs"] = false;
        args["fast_summary"] = true;
        test_tool_action_call(hf, "mcp.analysis_query.binary_map_overview", "analysis_query", "binary_map_overview", args, passed, failed, skipped);
    }

    void test_tool_analysis_query_xref_db_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.analysis_query.xref_db_stats", "analysis_query", "xref_db_stats", {}, passed, failed, skipped);
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

    void test_tool_get_xrefs_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_mcp_xref_db_fixture();
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_xref_to_addr);
        args["direction"] = "to";
        test_tool_call(hf, "mcp.get_xrefs.to", get_server(), "get_xrefs", args, passed, failed, skipped);
    }

    void test_tool_get_xrefs_from(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_mcp_xref_db_fixture();
        mcp_standalone::json args;
        args["address"] = hex_u64(g_mcp_xref_from_addr);
        args["direction"] = "from";
        test_tool_call(hf, "mcp.get_xrefs.from", get_server(), "get_xrefs", args, passed, failed, skipped);
    }

    void test_tool_disasm_annotations_manage_set_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_annotations_manage.set_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["comment"] = "test";
        test_tool_action_call(hf, "mcp.disasm_annotations_manage.set_comment", "disasm_annotations_manage", "set_comment", args, passed, failed, skipped);
    }

    void test_tool_disasm_annotations_manage_get_comment(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_annotations_manage.get_comment", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        test_tool_action_call(hf, "mcp.disasm_annotations_manage.get_comment", "disasm_annotations_manage", "get_comment", args, passed, failed, skipped);
    }

    void test_tool_disasm_annotations_manage_rename_function(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto addr = get_ntclose_addr_str();
        if (addr.empty()) { log_msg(hf, "mcp.disasm_annotations_manage.rename_function", "SKIP -- NtClose not found"); skipped.fetch_add(1); return; }
        mcp_standalone::json args;
        args["address"] = addr;
        args["new_name"] = "test_func";
        test_tool_action_call(hf, "mcp.disasm_annotations_manage.rename_function", "disasm_annotations_manage", "rename_function", args, passed, failed, skipped);
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

void test_tool_sessions_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.sessions_manage.list", "VERIFY-INPUT -- fixture_session_id=%s target_pid=%u attached_pid=%u",
            g_mcp_session_binary_id.empty() ? "<empty>" : g_mcp_session_binary_id.c_str(),
            g_mcp_target_pid,
            driver_bridge::attached_pid());
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.sessions_manage.list", "sessions_manage", "list", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            const uint64_t count = json_count_or_array_size(result.data, "count", "sessions");
            const bool fixture_present = json_array_contains_string_field(result.data, "sessions", g_mcp_session_binary_id, { "id", "binary_id" });
            log_msg(hf, "mcp.sessions_manage.list", "VERIFY-RESULT -- count=%llu array_size=%zu fixture_present=%d data=%s",
                (unsigned long long)count,
                json_array_size_field(result.data, "sessions"),
                fixture_present ? 1 : 0,
                compact_json(result.data, 900).c_str());
        }
    }

    void test_tool_sessions_manage_get_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.sessions_manage.get_active", "VERIFY-INPUT -- fixture_session_id=%s target_pid=%u attached_pid=%u",
            g_mcp_session_binary_id.empty() ? "<empty>" : g_mcp_session_binary_id.c_str(),
            g_mcp_target_pid,
            driver_bridge::attached_pid());
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.sessions_manage.get_active", "sessions_manage", "get_active", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            std::string active_id;
            std::string active_kind;
            if (result.data.is_object() && result.data.contains("active") && result.data["active"].is_object()) {
                json_string_any_field(result.data["active"], active_id, { "id", "binary_id" });
                json_string_any_field(result.data["active"], active_kind, { "kind" });
            }
            log_msg(hf, "mcp.sessions_manage.get_active", "VERIFY-RESULT -- active_id=%s active_kind=%s fixture_matches=%d data=%s",
                active_id.empty() ? "<empty>" : active_id.c_str(),
                active_kind.empty() ? "<empty>" : active_kind.c_str(),
                (!g_mcp_session_binary_id.empty() && active_id == g_mcp_session_binary_id) ? 1 : 0,
                compact_json(result.data, 900).c_str());
        }
    }


void test_tool_sessions_manage_open_file(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = get_small_pe_fixture_path();
        const std::string path_arg = args["path"].is_string() ? args["path"].get<std::string>() : std::string("<non-string>");
        log_msg(hf, "mcp.sessions_manage.open_file", "VERIFY-INPUT -- path=%s previous_fixture_session_id=%s",
            path_arg.c_str(),
            g_mcp_session_binary_id.empty() ? "<empty>" : g_mcp_session_binary_id.c_str());
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.sessions_manage.open_file", "sessions_manage", "open_file", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed && result.data.is_object() &&
            result.data.contains("opened") && result.data["opened"].is_object() &&
            result.data["opened"].contains("id") && result.data["opened"]["id"].is_string()) {
            g_mcp_session_binary_id = result.data["opened"]["id"].get<std::string>();
            std::string kind;
            json_string_any_field(result.data["opened"], kind, { "kind" });
            log_msg(hf, "mcp.sessions_manage.open_file", "VERIFY-RESULT -- stored_fixture_session_id=%s kind=%s data=%s",
                g_mcp_session_binary_id.c_str(),
                kind.empty() ? "<empty>" : kind.c_str(),
                compact_json(result.data, 900).c_str());
        } else if (status == mcp_tool_call_status_t::passed) {
            log_msg(hf, "mcp.sessions_manage.open_file", "VERIFY-RESULT -- missing opened.id data=%s",
                compact_json(result.data, 900).c_str());
        }
    }

    void test_tool_sessions_manage_attach_pid(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["pid"] = g_mcp_target_pid != 0 ? g_mcp_target_pid : GetCurrentProcessId();
        test_tool_action_call(hf, "mcp.sessions_manage.attach_pid", "sessions_manage", "attach_pid", args, passed, failed, skipped);
    }

    void test_tool_sessions_manage_close(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_session_binary_id.empty()) {
            log_msg(hf, "mcp.sessions_manage.close", "FAIL -- no session fixture id from sessions_manage action=open_file");
            record_tool_status("sessions_manage", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["binary_id"] = g_mcp_session_binary_id;
        test_tool_action_call(hf, "mcp.sessions_manage.close", "sessions_manage", "close", args, passed, failed, skipped);
        g_mcp_session_binary_id.clear();
    }

    void test_tool_sessions_manage_run_binary(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "sessions_manage";
        const char* tag = "mcp.sessions_manage.run_binary";
        mcp_standalone::json args;
        const std::string target = find_sessions_manage_run_binary_target(hf);
        if (target.empty()) {
            g_invoked_tools.insert(tool_name);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        args["action"] = "run_binary";
        args["path"] = target;
        args["args"] = "--no-external --duration 600 --net-rate 0 --absorb-external-single-step";
        args["isolation"] = "windows_sandbox";
        args["auto_terminate_sec"] = 900;
        args["memory_cap_mb"] = 2048;
        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_invoked_tools.insert(tool_name);
        log_msg(hf, tag, "START -- \"%s\" seq=%d args=%s", tool_name, seq, compact_json(args).c_str());
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail(timed.timed_out ? "timeout" : "completed", seq, tool_name, args, ir, timed.elapsed_ms, "");
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
        if (!ir.success) {
            const std::string text_lc = lower_copy(ir.text + " " + ir.exception_msg);
            if (text_lc.find("windows sandbox") != std::string::npos ||
                text_lc.find("sandbox is unavailable") != std::string::npos ||
                text_lc.find("enable windowsoptionalfeature") != std::string::npos) {
                if (!require_tool_read_only_metadata(hf, tag, tool_name, false, failed))
                    return;
                const auto* tool = find_registered_tool(get_server(), tool_name);
                static const char* required_params[] = {"path", "args", "working_dir", "isolation", "block_network", "kill_on_host_exit", "attach_after_resume", "memory_cap_mb", "auto_terminate_sec"};
                for (const char* param : required_params) {
                    if (!tool || !tool_has_param(*tool, param)) {
                        log_msg(hf, tag, "FAIL -- sessions_manage run_binary dependency guard schema missing parameter \"%s\"", param);
                        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
                        failed.fetch_add(1);
                        return;
                    }
                }
                log_msg(hf, tag, "PASS -- Windows Sandbox unavailable dependency guard returned an explicit refusal without host execution; schema and mutability metadata are intact: %s",
                    compact_text(ir.text, 700).c_str());
                record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
            log_msg(hf, tag, "FAIL -- sessions_manage run_binary returned unexpected failure: %s",
                compact_text(ir.text, 900).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        uint64_t pid = 0;
        payload_u64_field(ir.data, "pid", pid);
        if (pid == 0) {
            log_msg(hf, tag, "FAIL -- sessions_manage run_binary success missing guest pid data=%s", compact_json(ir.data).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- sessions_manage run_binary launched Windows Sandbox target pid=%llu",
            static_cast<unsigned long long>(pid));
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
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
        scoped_mcp_workspace_t ws(hf, "mcp.apply_diff");
        if (!ws.active) {
            record_fixture_failed_tool("apply_diff", failed);
            return;
        }
        if (!write_text_fixture(ws.root / "apply_diff_fixture.txt", "alpha\nold\nomega\n")) {
            log_msg(hf, "mcp.apply_diff", "FAIL -- unable to write apply_diff fixture");
            record_fixture_failed_tool("apply_diff", failed);
            return;
        }
        mcp_standalone::json args;
        args["path"] = "apply_diff_fixture.txt";
        args["diff"] = "--- a/apply_diff_fixture.txt\n+++ b/apply_diff_fixture.txt\n@@ -1,3 +1,3 @@\n alpha\n-old\n+new\n omega";
        test_tool_call(hf, "mcp.apply_diff", get_server(), "apply_diff", args, passed, failed, skipped);
    }

    void test_tool_apply_patch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        scoped_mcp_workspace_t ws(hf, "mcp.apply_patch");
        if (!ws.active) {
            record_fixture_failed_tool("apply_patch", failed);
            return;
        }
        mcp_standalone::json args;
        args["patch"] = "*** Begin Patch\n*** Add File: apply_patch_fixture.txt\n+alpha\n+beta\n*** End Patch";
        test_tool_call(hf, "mcp.apply_patch", get_server(), "apply_patch", args, passed, failed, skipped);
    }

    void test_tool_codebase_search(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "codebase_search";
        const char* tag = "mcp.codebase_search";
        scoped_mcp_workspace_t ws(hf, tag);
        if (!ws.active) {
            record_fixture_failed_tool(tool_name, failed);
            return;
        }
        workflow_tools::shutdown_services();
        if (!write_text_fixture(ws.root / "codebase_fixture.cpp", "int aida_codebase_fixture_token = 1337;\n")) {
            log_msg(hf, tag, "FAIL -- unable to write codebase_search fixture");
            record_fixture_failed_tool(tool_name, failed);
            return;
        }
        mcp_standalone::json args;
        args["query"] = "aida_codebase_fixture_token";
        const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
        g_invoked_tools.insert(tool_name);
        for (int attempt = 1; attempt <= 40; ++attempt) {
            log_msg(hf, tag, "DISPATCH -- \"%s\" seq=%d attempt=%d args=%s", tool_name, seq, attempt, compact_json(args).c_str());
            auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
            const auto& ir = timed.result;
            log_mcp_result_detail(timed.timed_out ? "timeout" : "completed", seq, tool_name, args, ir, timed.elapsed_ms, "");
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
            if (!ir.success) {
                log_msg(hf, tag, "FAIL -- codebase_search returned error: %s",
                    compact_text(ir.text, 900).c_str());
                record_tool_status(tool_name, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return;
            }
            size_t count = 0;
            if (payload_array_count(ir.data, "results", count) && count > 0) {
                log_msg(hf, tag, "PASS -- codebase_search found deterministic workspace token results=%zu attempt=%d",
                    count, attempt);
                record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
            const std::string text_lc = lower_copy(ir.text);
            if (text_lc.find("being built") == std::string::npos &&
                text_lc.find("still building") == std::string::npos &&
                text_lc.find("no results found") == std::string::npos) {
                log_msg(hf, tag, "FAIL -- codebase_search unexpected empty result text=%s data=%s",
                    compact_text(ir.text, 700).c_str(), compact_json(ir.data).c_str());
                record_tool_status(tool_name, mcp_tool_call_status_t::failed);
                failed.fetch_add(1);
                return;
            }
            Sleep(250);
        }
        log_msg(hf, tag, "FAIL -- codebase_search did not return deterministic workspace token before poll budget");
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

    void test_tool_read_command_output(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* session_id = "aida_mcp_read_command_output";
        mcp_standalone::json run_args;
        run_args["command"] = "echo AIDA_MCP_READ_COMMAND_OUTPUT";
        run_args["wait"] = false;
        run_args["session_id"] = session_id;
        run_args["timeout_ms"] = 5000;
        mcp_tool_call_status_t run_status = test_tool_call(hf, "mcp.read_command_output.setup", get_server(), "run_command", run_args, passed, failed, skipped);
        if (run_status != mcp_tool_call_status_t::passed) {
            log_msg(hf, "mcp.read_command_output", "FAIL -- setup run_command did not create session status=%d", static_cast<int>(run_status));
            record_tool_status("read_command_output", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const char* tool_name = "read_command_output";
        g_invoked_tools.insert(tool_name);
        mcp_standalone::json args;
        args["id"] = session_id;
        args["max_bytes"] = 4096;
        args["drop"] = true;
        invoke_result_t last_ir;
        long long last_elapsed = 0;
        const DWORD started = GetTickCount();
        int attempts = 0;
        while (GetTickCount() - started < 5000) {
            ++attempts;
            const int seq = g_mcp_tool_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
            auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name), hf, "mcp.read_command_output", seq);
            last_ir = timed.result;
            last_elapsed = timed.elapsed_ms;
            log_mcp_result_detail(timed.timed_out ? "timeout" : "completed", seq, tool_name, args, last_ir, timed.elapsed_ms, "");
            if (!timed.timed_out && last_ir.found && !last_ir.threw && last_ir.success && payload_text_contains(last_ir, "aida_mcp_read_command_output")) {
                log_msg(hf, "mcp.read_command_output", "PASS -- deterministic command output marker observed attempts=%d elapsed_total_ms=%lu",
                    attempts,
                    static_cast<unsigned long>(GetTickCount() - started));
                record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
            if (!timed.timed_out && last_ir.found && !last_ir.threw && last_ir.success) {
                std::string text_lc = lower_copy(last_ir.text + " " + compact_json(last_ir.data, 700));
                if (text_lc.find("no output yet") != std::string::npos || text_lc.find("running") != std::string::npos) {
                    Sleep(150);
                    continue;
                }
            }
            if (timed.timed_out || !last_ir.found || last_ir.threw || !last_ir.success)
                break;
            Sleep(150);
        }
        log_msg(hf, "mcp.read_command_output", "FAIL -- deterministic command output marker was not returned attempts=%d elapsed_total_ms=%lu last_elapsed_ms=%lld text=%s data=%s exception=%s",
            attempts,
            static_cast<unsigned long>(GetTickCount() - started),
            last_elapsed,
            compact_text(last_ir.text, 700).c_str(),
            compact_json(last_ir.data, 900).c_str(),
            compact_text(last_ir.exception_msg, 500).c_str());
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
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
        scoped_mcp_workspace_t ws(hf, "mcp.search_workspace");
        if (!ws.active) {
            record_fixture_failed_tool("search_workspace", failed);
            return;
        }
        if (!write_text_fixture(ws.root / "search_workspace_fixture.txt", "aida_search_workspace_fixture_token\n")) {
            log_msg(hf, "mcp.search_workspace", "FAIL -- unable to write search_workspace fixture");
            record_fixture_failed_tool("search_workspace", failed);
            return;
        }
        mcp_standalone::json args;
        args["query"] = "aida_search_workspace_fixture_token";
        args["path"] = ".";
        args["include"] = ".txt";
        args["regex"] = false;
        test_tool_call(hf, "mcp.search_workspace", get_server(), "search_workspace", args, passed, failed, skipped);
    }

    void test_tool_run_command(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["command"] = "echo AIDA_MCP_RUN_COMMAND";
        args["timeout_ms"] = 5000;
        test_tool_call(hf, "mcp.run_command", get_server(), "run_command", args, passed, failed, skipped);
    }

    void test_tool_cancel_command(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* session_id = "aida_mcp_cancel_command";
        mcp_standalone::json run_args;
        run_args["command"] = "ping -n 6 127.0.0.1 > nul";
        run_args["wait"] = false;
        run_args["session_id"] = session_id;
        run_args["timeout_ms"] = 10000;
        mcp_tool_call_status_t run_status = test_tool_call(hf, "mcp.cancel_command.setup", get_server(), "run_command", run_args, passed, failed, skipped);
        if (run_status != mcp_tool_call_status_t::passed) {
            log_msg(hf, "mcp.cancel_command", "FAIL -- setup run_command did not create session status=%d", static_cast<int>(run_status));
            record_tool_status("cancel_command", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["session_id"] = session_id;
        test_tool_call(hf, "mcp.cancel_command", get_server(), "cancel_command", args, passed, failed, skipped);
    }

    void test_tool_list_commands(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.list_commands", get_server(), "list_commands", {}, passed, failed, skipped);
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


void test_tool_api_monitor_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_mcp_target_live(hf, "mcp.api_monitor_start")) {
            record_precondition_skipped_tool("api_monitor_start", skipped);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = g_mcp_target_pid;
        args["apis"] = mcp_standalone::json::array({"kernel32.dll!GetTickCount64"});
        args["log_callstack"] = false;
        args["capture_buffer"] = false;
        args["max_capture_bytes"] = 32;
        args["max_events"] = 64;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.api_monitor_start", get_server(), "api_monitor_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            const uint64_t fn = resolve_remote_export("kernel32.dll", "GetTickCount64");
            log_msg(hf, "mcp.api_monitor_start", "API-MONITOR-FIXTURE -- trigger export kernel32!GetTickCount64=0x%016llX pid=%u",
                static_cast<unsigned long long>(fn), g_mcp_target_pid);
            if (fn != 0) {
                for (int i = 0; i < 3; ++i) {
                    (void)page_guard_engine::remote_thread_call(g_mcp_target_pid, fn, 0, 0, 0, 0, 3000, "api_monitor_fixture_GetTickCount64");
                    Sleep(100);
                }
            }
        }
    }

    void test_tool_api_monitor_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.api_monitor_results", "API-MONITOR-FIXTURE -- seeding target API hits pid=%u", g_mcp_target_pid);
        uint64_t kernel32_base = 0;
        for (const auto& m : driver_bridge::enumerate_modules_for(g_mcp_target_pid)) {
            std::string lower = m.name;
            for (char& c : lower)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower == "kernel32.dll") {
                kernel32_base = m.base;
                break;
            }
        }
        const uint64_t get_tick_count64 = kernel32_base ? driver_bridge::resolve_export(kernel32_base, "GetTickCount64") : 0;
        for (int i = 0; i < 6 && get_tick_count64 != 0; ++i) {
            (void)page_guard_engine::remote_thread_call(g_mcp_target_pid, get_tick_count64, 0, 0, 0, 0, 2500, "api_monitor_GetTickCount64_fixture");
            Sleep(100);
        }
        log_msg(hf, "mcp.api_monitor_results", "API-MONITOR-FIXTURE -- resolved kernel32=0x%016llX GetTickCount64=0x%016llX",
            static_cast<unsigned long long>(kernel32_base),
            static_cast<unsigned long long>(get_tick_count64));
        Sleep(2500);
        mcp_standalone::json args;
        args["limit"] = 8;
        args["clear"] = true;
        args["stop"] = true;
        test_tool_call(hf, "mcp.api_monitor_results", get_server(), "api_monitor_results", args, passed, failed, skipped);
    }


    void test_tool_network_enumerate_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_enumerate_conns", get_server(), "network_enumerate_connections", {}, passed, failed, skipped);
    }

    void test_tool_network_capture_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_burp_http_fixture(hf, "mcp.network_capture_manage.start")) {
            record_fixture_failed_tool("network_capture_manage", failed);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        args["port"] = g_burp_http_fixture ? g_burp_http_fixture->port : 0;
        args["protocol"] = "tcp";
        args["max_payload"] = 256;
        auto status = test_tool_action_call(hf, "mcp.network_capture_manage.start", "network_capture_manage", "start", args, passed, failed, skipped);
        if (status == mcp_tool_call_status_t::passed) {
            const auto payload = mcp_http_fixture_request_payload("/aida-network-start-fixture");
            if (!send_burp_fixture_tcp_payload(hf, "mcp.network_capture_manage.start", payload)) {
                log_msg(hf, "mcp.network_capture_manage.start", "WARN -- capture start succeeded but traffic fixture send failed; packet queries seed their own captures");
            }
        }
    }

    void test_tool_network_capture_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.network_capture_manage.stop", "network_capture_manage", "stop", {}, passed, failed, skipped);
    }

    void test_tool_network_capture_manage_get_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const auto payload = mcp_http_fixture_request_payload("/aida-network-packets-fixture");
        if (!seed_network_packet_queue(hf, "mcp.network_capture_manage.get_packets", payload)) {
            record_fixture_failed_tool("network_capture_manage", failed);
            return;
        }
        test_tool_action_call(hf, "mcp.network_capture_manage.get_packets", "network_capture_manage", "get_packets", {}, passed, failed, skipped);
    }

    void test_tool_network_analyze_packet(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const auto payload = mcp_http_fixture_request_payload("/aida-network-analyze-fixture");
        if (!seed_network_packet_queue(hf, "mcp.network_analyze_packet", payload)) {
            record_fixture_failed_tool("network_analyze_packet", failed);
            return;
        }
        mcp_standalone::json args;
        args["index"] = 0;
        test_tool_call(hf, "mcp.network_analyze_packet", get_server(), "network_analyze_packet", args, passed, failed, skipped);
    }

    void test_tool_network_dns_log(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_call(hf, "mcp.network_dns_log", get_server(), "network_dns_log", {}, passed, failed, skipped);
    }

    void test_tool_network_filter_manage_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["filter_action"] = "log";
        args["direction"] = "both";
        args["protocol"] = "tcp";
        args["port"] = 65534;
        test_tool_action_call(hf, "mcp.network_filter_manage.add", "network_filter_manage", "add", args, passed, failed, skipped);
    }

    void test_tool_network_filter_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, "mcp.network_filter_manage.remove", "SKIP -- kernel driver not loaded");
            skipped.fetch_add(1);
            return;
        }
        std::uint32_t rule_id = 0;
        if (!driver_bridge::add_filter_rule(2, 2, 6, 0, 65533, nullptr, nullptr, &rule_id) || rule_id == 0) {
            log_msg(hf, "mcp.network_filter_manage.remove", "SKIP -- setup add_filter_rule failed");
            skipped.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["rule_id"] = rule_id;
        test_tool_action_call(hf, "mcp.network_filter_manage.remove", "network_filter_manage", "remove", args, passed, failed, skipped);
    }

    void test_tool_network_filter_manage_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "network_filter_manage";
        const char* tag = "mcp.network_filter_manage.clear";
        g_invoked_tools.insert(tool_name);
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- kernel driver not connected; clear filter lifecycle cannot be proven");
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        std::uint32_t rule_id = 0;
        const bool added = driver_bridge::add_filter_rule(2, 2, 6, 0, 65532, nullptr, nullptr, &rule_id);
        driver_bridge::network_stats_t setup_stats{};
        const bool setup_stats_ok = driver_bridge::get_network_stats(setup_stats);
        log_msg(hf, tag, "SETUP -- add_filter_rule=%d rule_id=%u stats_ok=%d active_filter_rules=%llu",
            added ? 1 : 0,
            rule_id,
            setup_stats_ok ? 1 : 0,
            static_cast<unsigned long long>(setup_stats.active_filter_rules));
        if (!added || rule_id == 0 || !setup_stats_ok || setup_stats.active_filter_rules == 0) {
            if (rule_id != 0)
                driver_bridge::remove_filter_rule(rule_id);
            log_msg(hf, tag, "FAIL -- could not seed a filter rule before clear");
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        auto timed = invoke_tool_action_bounded(get_server(), tool_name, "clear", {}, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, {}, ir, timed.elapsed_ms, "");
        driver_bridge::network_stats_t after_stats{};
        const bool after_stats_ok = driver_bridge::get_network_stats(after_stats);
        uint64_t payload_before = 0;
        uint64_t payload_after = 1;
        uint64_t payload_cleared = 0;
        payload_u64_field(ir.data, "before_count", payload_before);
        payload_u64_field(ir.data, "after_count", payload_after);
        payload_u64_field(ir.data, "cleared_count", payload_cleared);
        log_msg(hf, tag, "VERIFY -- timeout=%d found=%d threw=%d success=%d payload_before=%llu payload_after=%llu payload_cleared=%llu stats_ok=%d stats_after=%llu text=%s data=%s",
            timed.timed_out ? 1 : 0,
            ir.found ? 1 : 0,
            ir.threw ? 1 : 0,
            ir.success ? 1 : 0,
            static_cast<unsigned long long>(payload_before),
            static_cast<unsigned long long>(payload_after),
            static_cast<unsigned long long>(payload_cleared),
            after_stats_ok ? 1 : 0,
            static_cast<unsigned long long>(after_stats.active_filter_rules),
            compact_text(ir.text, 700).c_str(),
            compact_json(ir.data, 900).c_str());
        if (timed.timed_out || !ir.found || ir.threw || !ir.success ||
            payload_before == 0 || payload_after != 0 || payload_cleared == 0 ||
            !after_stats_ok || after_stats.active_filter_rules != 0) {
            if (rule_id != 0)
                driver_bridge::remove_filter_rule(rule_id);
            log_msg(hf, tag, "FAIL -- clear filter lifecycle did not prove seeded rule removal");
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- clear filter lifecycle removed seeded rule payload_before=%llu payload_after=%llu stats_after=%llu",
            static_cast<unsigned long long>(payload_before),
            static_cast<unsigned long long>(payload_after),
            static_cast<unsigned long long>(after_stats.active_filter_rules));
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_network_bandwidth_manage_stats(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.network_bandwidth_manage.stats", "network_bandwidth_manage", "stats", {}, passed, failed, skipped);
    }

    void test_tool_network_capture_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.network_capture_manage.status", "network_capture_manage", "status", {}, passed, failed, skipped);
    }

    void test_tool_network_firewall_manage_block_ip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["ip"] = "203.0.113.254";
        args["direction"] = "both";
        test_tool_action_call(hf, "mcp.network_firewall_manage.block_ip", "network_firewall_manage", "block_ip", args, passed, failed, skipped);
    }

    void test_tool_network_firewall_manage_block_port(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["port"] = 65534;
        test_tool_action_call(hf, "mcp.network_firewall_manage.block_port", "network_firewall_manage", "block_port", args, passed, failed, skipped);
    }

    void test_tool_network_firewall_manage_block_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "network_firewall_manage";
        const char* tag = "mcp.network_firewall_manage.block_process";
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_action_bounded(get_server(), tool_name, "block_process", args, tool_timeout_ms(tool_name));
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
        const std::string req = "GET /aida-network-dpi-test HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: AiDA-DPI-Fixture\r\nConnection: close\r\n\r\n";
        std::vector<uint8_t> payload(req.begin(), req.end());
        if (!seed_network_parse_capture(hf, "mcp.network_deep_inspect", payload)) {
            record_fixture_failed_tool("network_deep_inspect", failed);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        args["protocol"] = "tcp";
        args["port"] = g_burp_http_fixture ? g_burp_http_fixture->port : 0;
        test_tool_call(hf, "mcp.network_deep_inspect", get_server(), "network_deep_inspect", args, passed, failed, skipped);
        driver_bridge::stop_capture();
    }

    void test_tool_network_follow_tcp_stream(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_loopback_tcp_pair_t pair;
        const auto payload = mcp_http_fixture_request_payload("/aida-network-stream-fixture");
        if (!seed_driver_stream_reassembly(hf, "mcp.network_follow_tcp_stream", pair, payload)) {
            driver_bridge::stream_reassemble_op(1, 0, 0, GetCurrentProcessId(), nullptr, nullptr, nullptr, nullptr, nullptr);
            record_fixture_failed_tool("network_follow_tcp_stream", failed);
            return;
        }
        mcp_standalone::json args;
        args["operation"] = "get";
        args["src_port"] = pair.client_port;
        args["dst_port"] = pair.listen_port;
        args["pid"] = GetCurrentProcessId();
        test_tool_call(hf, "mcp.network_follow_tcp_stream", get_server(), "network_follow_tcp_stream", args, passed, failed, skipped);
        driver_bridge::stream_reassemble_op(1, pair.client_port, pair.listen_port, GetCurrentProcessId(), nullptr, nullptr, nullptr, nullptr, nullptr);
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

    struct mcp_held_udp_fixture_t {
        uint64_t hold_id = 0;
        size_t held_count = 0;
        int sent = 0;
    };

    bool create_mcp_held_udp_fixture(HANDLE hf, const char* tag, const char* tool_name, mcp_held_udp_fixture_t& fixture, std::atomic<int>& failed) {
        g_invoked_tools.insert(tool_name);
        if (!driver_bridge::using_kernel_driver()) {
            log_msg(hf, tag, "FAIL -- cannot create held packet fixture because kernel driver is not connected");
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
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
            return false;
        }
        WSADATA wsa{};
        int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wsa_err != 0) {
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            log_msg(hf, tag, "FAIL -- held packet fixture WSAStartup failed err=%d", wsa_err);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            DWORD err = WSAGetLastError();
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            WSACleanup();
            log_msg(hf, tag, "FAIL -- held packet fixture socket creation failed err=%lu", static_cast<unsigned long>(err));
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        dst.sin_port = htons(65432);
        const char payload[] = "AiDA MCP held packet fixture";
        int sent = sendto(s, payload, static_cast<int>(sizeof(payload) - 1), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        int send_err = sent == SOCKET_ERROR ? WSAGetLastError() : 0;
        closesocket(s);
        WSACleanup();
        if (sent == SOCKET_ERROR) {
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            log_msg(hf, tag, "FAIL -- held packet fixture UDP send failed err=%d", send_err);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        fixture.sent = sent;
        for (int i = 0; i < 40 && fixture.hold_id == 0; ++i) {
            auto held = driver_bridge::get_held_packets();
            fixture.held_count = held.size();
            for (const auto& h : held) {
                if (h.pid == GetCurrentProcessId() && h.protocol == 17) {
                    fixture.hold_id = h.hold_id;
                    break;
                }
            }
            if (fixture.hold_id == 0)
                Sleep(50);
        }
        if (fixture.hold_id == 0) {
            driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
            log_msg(hf, tag, "FAIL -- held packet fixture produced no held UDP packet pid=%lu held_count=%zu sent=%d",
                static_cast<unsigned long>(GetCurrentProcessId()),
                fixture.held_count,
                sent);
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return false;
        }
        log_msg(hf, tag, "FIXTURE -- held UDP packet ready hold_id=%llu held_count=%zu sent=%d",
            static_cast<unsigned long long>(fixture.hold_id),
            fixture.held_count,
            fixture.sent);
        return true;
    }

    void test_tool_network_get_held_packets(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "network_get_held_packets";
        const char* tag = "mcp.network_get_held_packets";
        mcp_held_udp_fixture_t fixture;
        if (!create_mcp_held_udp_fixture(hf, tag, tool_name, fixture, failed))
            return;
        test_tool_call(hf, tag, get_server(), tool_name, {}, passed, failed, skipped);
        const bool disabled = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        log_msg(hf, tag, "CLEANUP -- disabled=%d hold_id=%llu",
            disabled ? 1 : 0,
            static_cast<unsigned long long>(fixture.hold_id));
    }

    void test_tool_network_release_packet(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "network_release_packet";
        const char* tag = "mcp.network_release_packet";
        mcp_held_udp_fixture_t fixture;
        if (!create_mcp_held_udp_fixture(hf, tag, tool_name, fixture, failed))
            return;
        mcp_standalone::json args;
        args["hold_id"] = fixture.hold_id;
        args["action"] = "release";
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        const bool disabled = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        if (timed.timed_out || !ir.found || ir.threw || !ir.success || !disabled) {
            log_msg(hf, tag, "FAIL -- release held packet failed hold_id=%llu found=%d threw=%d success=%d timeout=%d cleanup_disabled=%d text=%s err=%s",
                static_cast<unsigned long long>(fixture.hold_id),
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
            static_cast<unsigned long long>(fixture.hold_id),
            fixture.sent);
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_network_firewall_manage_kill_connection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_loopback_tcp_pair_t pair;
        if (!pair.open(hf, "mcp.network_firewall_manage.kill_connection")) {
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
        test_tool_action_call(hf, "mcp.network_firewall_manage.kill_connection", "network_firewall_manage", "kill_connection", args, passed, failed, skipped);
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

    void test_tool_network_bandwidth_manage_monitor(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json start_args;
        start_args["operation"] = "start";
        start_args["pid"] = GetCurrentProcessId();
        auto started = invoke_tool_action_bounded(get_server(), "network_bandwidth_manage", "monitor", start_args, tool_timeout_ms("network_bandwidth_manage"));
        log_msg(hf, "mcp.network_bandwidth_manage.monitor", "BANDWIDTH-FIXTURE -- start timed_out=%d found=%d threw=%d success=%d elapsed_ms=%lld",
            started.timed_out ? 1 : 0,
            started.result.found ? 1 : 0,
            started.result.threw ? 1 : 0,
            started.result.success ? 1 : 0,
            started.elapsed_ms);
        if (started.timed_out || !started.result.found || started.result.threw || !started.result.success) {
            record_tool_status("network_bandwidth_manage", started.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const auto payload = mcp_http_fixture_request_payload("/aida-network-bandwidth-fixture");
        send_burp_fixture_tcp_payload(hf, "mcp.network_bandwidth_manage.monitor", payload);
        Sleep(500);
        mcp_standalone::json args;
        args["operation"] = "get";
        args["pid"] = GetCurrentProcessId();
        test_tool_action_call(hf, "mcp.network_bandwidth_manage.monitor", "network_bandwidth_manage", "monitor", args, passed, failed, skipped);
        mcp_standalone::json stop_args;
        stop_args["operation"] = "stop";
        auto stopped = invoke_tool_action_bounded(get_server(), "network_bandwidth_manage", "monitor", stop_args, tool_timeout_ms("network_bandwidth_manage"));
        log_msg(hf, "mcp.network_bandwidth_manage.monitor", "BANDWIDTH-FIXTURE -- stop timed_out=%d success=%d elapsed_ms=%lld",
            stopped.timed_out ? 1 : 0,
            stopped.result.success ? 1 : 0,
            stopped.elapsed_ms);
    }

    void test_tool_network_bandwidth_manage_per_process(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json start_args;
        start_args["operation"] = "start";
        start_args["pid"] = GetCurrentProcessId();
        auto started = invoke_tool_action_bounded(get_server(), "network_bandwidth_manage", "monitor", start_args, tool_timeout_ms("network_bandwidth_manage"));
        log_msg(hf, "mcp.network_bandwidth_manage.per_process", "BANDWIDTH-FIXTURE -- start timed_out=%d found=%d threw=%d success=%d elapsed_ms=%lld",
            started.timed_out ? 1 : 0,
            started.result.found ? 1 : 0,
            started.result.threw ? 1 : 0,
            started.result.success ? 1 : 0,
            started.elapsed_ms);
        if (started.timed_out || !started.result.found || started.result.threw || !started.result.success) {
            record_tool_status("network_bandwidth_manage", started.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const auto payload = mcp_http_fixture_request_payload("/aida-network-bw-process-fixture");
        send_burp_fixture_tcp_payload(hf, "mcp.network_bandwidth_manage.per_process", payload);
        Sleep(500);
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        test_tool_action_call(hf, "mcp.network_bandwidth_manage.per_process", "network_bandwidth_manage", "per_process", args, passed, failed, skipped);
        mcp_standalone::json stop_args;
        stop_args["operation"] = "stop";
        auto stopped = invoke_tool_action_bounded(get_server(), "network_bandwidth_manage", "monitor", stop_args, tool_timeout_ms("network_bandwidth_manage"));
        log_msg(hf, "mcp.network_bandwidth_manage.per_process", "BANDWIDTH-FIXTURE -- stop timed_out=%d success=%d elapsed_ms=%lld",
            stopped.timed_out ? 1 : 0,
            stopped.result.success ? 1 : 0,
            stopped.elapsed_ms);
    }

    void test_tool_network_os_fingerprint(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "get";
        test_tool_call(hf, "mcp.network_os_fingerprint", get_server(), "network_os_fingerprint", args, passed, failed, skipped);
    }

    void test_tool_network_capture_manage_export_pcap(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["path"] = "C:\\temp\\aida_test_net.pcap";
        test_tool_action_call(hf, "mcp.network_capture_manage.export_pcap", "network_capture_manage", "export_pcap", args, passed, failed, skipped);
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
        const std::string script_name = args["name"].get<std::string>();
        const std::string source = args["source"].get<std::string>();
        log_msg(hf, "mcp.network_script_load", "VERIFY-INPUT -- name=%s source_len=%zu source_preview=%s",
            script_name.c_str(),
            source.size(),
            compact_text(source, 300).c_str());
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.network_script_load", get_server(), "network_script_load", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            log_tool_result_payload(hf, "mcp.network_script_load", "VERIFY-RESULT", result);
            auto listed = invoke_tool_bounded(get_server(), "network_script_list", {}, tool_timeout_ms("network_script_list"));
            const bool text_mentions_script = listed.result.text.find(script_name) != std::string::npos;
            log_msg(hf, "mcp.network_script_load", "VERIFY-LIST -- timeout=%d success=%d mentions_script=%d text=%s data=%s",
                listed.timed_out ? 1 : 0,
                listed.result.success ? 1 : 0,
                text_mentions_script ? 1 : 0,
                compact_text(listed.result.text, 700).c_str(),
                compact_json(listed.result.data, 900).c_str());
        }
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
        log_msg(hf, tag, "VERIFY-SETUP -- loading fixture name=%s source_len=%zu",
            script_name.c_str(),
            load_args["source"].get<std::string>().size());
        auto load_timed = invoke_tool_bounded(get_server(), "network_script_load", load_args, tool_timeout_ms("network_script_load"));
        const auto& load_ir = load_timed.result;
        log_mcp_result_detail("script_unload_setup", 0, "network_script_load", load_args, load_ir, load_timed.elapsed_ms, "");
        log_msg(hf, tag, "VERIFY-SETUP-RESULT -- timeout=%d found=%d threw=%d success=%d elapsed_ms=%lld text=%s data=%s",
            load_timed.timed_out ? 1 : 0,
            load_ir.found ? 1 : 0,
            load_ir.threw ? 1 : 0,
            load_ir.success ? 1 : 0,
            load_timed.elapsed_ms,
            compact_text(load_ir.text, 700).c_str(),
            compact_json(load_ir.data, 900).c_str());
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
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, tag, get_server(), tool_name, args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            log_tool_result_payload(hf, tag, "VERIFY-RESULT", result);
            auto listed = invoke_tool_bounded(get_server(), "network_script_list", {}, tool_timeout_ms("network_script_list"));
            const bool text_mentions_script = listed.result.text.find(script_name) != std::string::npos;
            log_msg(hf, tag, "VERIFY-LIST -- timeout=%d success=%d mentions_unloaded_script=%d text=%s data=%s",
                listed.timed_out ? 1 : 0,
                listed.result.success ? 1 : 0,
                text_mentions_script ? 1 : 0,
                compact_text(listed.result.text, 700).c_str(),
                compact_json(listed.result.data, 900).c_str());
        }
    }

    void test_tool_network_script_execute(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["code"] = "return 1";
        const std::string code = args["code"].get<std::string>();
        log_msg(hf, "mcp.network_script_execute", "VERIFY-INPUT -- code_len=%zu code_preview=%s",
            code.size(),
            compact_text(code, 300).c_str());
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.network_script_execute", get_server(), "network_script_execute", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            log_tool_result_payload(hf, "mcp.network_script_execute", "VERIFY-RESULT", result);
            std::string output;
            const bool has_output = payload_string_field(result.data, "output", output);
            const bool output_ok = has_output && output == "1";
            const bool text_ok = result.text == "1";
            if (!output_ok || !text_ok) {
                log_msg(hf, "mcp.network_script_execute", "FAIL -- script result mismatch expected=1 has_output=%d output=%s text=%s data=%s",
                    has_output ? 1 : 0,
                    compact_text(output, 300).c_str(),
                    compact_text(result.text, 300).c_str(),
                    compact_json(result.data, 900).c_str());
                if (passed.load(std::memory_order_acquire) > 0)
                    passed.fetch_sub(1, std::memory_order_acq_rel);
                failed.fetch_add(1, std::memory_order_acq_rel);
                convert_tool_pass_to_fail("network_script_execute");
            }
        }
    }

    void test_tool_network_script_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.network_script_list", "VERIFY-INPUT -- list scripts after load/unload coverage");
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.network_script_list", get_server(), "network_script_list", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed)
            log_tool_result_payload(hf, "mcp.network_script_list", "VERIFY-RESULT", result);
    }

    void test_tool_network_script_api(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.network_script_api", "VERIFY-INPUT -- request scripting API surface");
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.network_script_api", get_server(), "network_script_api", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            const bool has_log = result.text.find("log(") != std::string::npos;
            const bool has_base64 = result.text.find("base64") != std::string::npos;
            log_msg(hf, "mcp.network_script_api", "VERIFY-RESULT -- text_len=%zu has_log=%d has_base64=%d text=%s data=%s",
                result.text.size(),
                has_log ? 1 : 0,
                has_base64 ? 1 : 0,
                compact_text(result.text, 1200).c_str(),
                compact_json(result.data, 900).c_str());
        }
    }

    void test_tool_network_stream_track(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json clear_args;
        clear_args["operation"] = "clear";
        invoke_tool_bounded(get_server(), "network_stream_track", clear_args, tool_timeout_ms("network_stream_track"));
        mcp_standalone::json start_args;
        start_args["operation"] = "start";
        start_args["pid"] = GetCurrentProcessId();
        auto started = invoke_tool_bounded(get_server(), "network_stream_track", start_args, tool_timeout_ms("network_stream_track"));
        log_msg(hf, "mcp.network_stream_track", "STREAM-FIXTURE -- tracker start timed_out=%d found=%d threw=%d success=%d elapsed_ms=%lld",
            started.timed_out ? 1 : 0,
            started.result.found ? 1 : 0,
            started.result.threw ? 1 : 0,
            started.result.success ? 1 : 0,
            started.elapsed_ms);
        if (started.timed_out || !started.result.found || started.result.threw || !started.result.success) {
            record_tool_status("network_stream_track", started.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        const auto payload = mcp_http_fixture_request_payload("/aida-network-stream-track-fixture");
        if (!seed_network_parse_capture(hf, "mcp.network_stream_track", payload)) {
            mcp_standalone::json stop_args;
            stop_args["operation"] = "stop";
            invoke_tool_bounded(get_server(), "network_stream_track", stop_args, tool_timeout_ms("network_stream_track"));
            record_fixture_failed_tool("network_stream_track", failed);
            return;
        }
        Sleep(850);
        auto packets = driver_bridge::get_captured_packets(64);
        size_t fed = 0;
        for (const auto& pkt : packets) {
            if (pkt.protocol == 6 && (pkt.pid == GetCurrentProcessId() || pkt.pid == 0)) {
                network_view::g_stream_tracker.feed(pkt);
                ++fed;
            }
        }
        log_msg(hf, "mcp.network_stream_track", "STREAM-FIXTURE -- explicitly fed packets=%zu total_polled=%zu",
            fed,
            packets.size());
        mcp_standalone::json args;
        args["operation"] = "get_all";
        test_tool_call(hf, "mcp.network_stream_track", get_server(), "network_stream_track", args, passed, failed, skipped);
        driver_bridge::stop_capture();
        mcp_standalone::json stop_args;
        stop_args["operation"] = "stop";
        auto stopped = invoke_tool_bounded(get_server(), "network_stream_track", stop_args, tool_timeout_ms("network_stream_track"));
        log_msg(hf, "mcp.network_stream_track", "STREAM-FIXTURE -- tracker stop timed_out=%d success=%d elapsed_ms=%lld",
            stopped.timed_out ? 1 : 0,
            stopped.result.success ? 1 : 0,
            stopped.elapsed_ms);
    }

    void test_tool_network_pg_sniff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        uint64_t pg_addr = 0;
        std::vector<uint8_t> marker(4096, 0);
        const std::string marker_text = "AIDA_NETWORK_PG_SNIFF_DIRECT_FIXTURE";
        std::copy(marker_text.begin(), marker_text.end(), marker.begin());
        const uint64_t install_size = static_cast<uint64_t>(marker.size());
        if (!ensure_mcp_private_bytes(hf, "mcp.network_pg_sniff", pg_addr, marker.size(), marker)) {
            record_fixture_failed_tool("network_pg_sniff", failed);
            return;
        }
        const uint32_t pid = g_mcp_target_pid != 0 ? g_mcp_target_pid : driver_bridge::attached_pid();
        if (pid == 0 || (driver_bridge::attached_pid() != pid && !restore_mcp_target(hf, "mcp.network_pg_sniff"))) {
            log_msg(hf, "mcp.network_pg_sniff", "FIXTURE-INVALID -- dedicated page-guard target unavailable pid=%u active_pid=%u addr=0x%016llX size=%llu status=\"%s\" last_error=\"%s\"",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(pg_addr),
                static_cast<unsigned long long>(install_size),
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            if (pg_addr != 0)
                driver_bridge::free_memory(pg_addr);
            record_fixture_failed_tool("network_pg_sniff", failed);
            return;
        }
        driver_bridge::memory_region_t region{};
        const bool query_ok = driver_bridge::query_memory_for(pid, pg_addr, region);
        const bool region_offset_ok = query_ok && pg_addr >= region.base && (pg_addr - region.base) < region.size;
        const uint64_t region_offset = region_offset_ok ? (pg_addr - region.base) : 0;
        const bool region_covers = region_offset_ok && install_size <= (region.size - region_offset);
        const bool committed = query_ok && region.state == MEM_COMMIT;
        const bool readable = query_ok && (region.protect & PAGE_NOACCESS) == 0;
        std::vector<uint8_t> readback;
        const bool read_ok = driver_bridge::read_memory_for(pid, pg_addr, marker_text.size(), readback);
        const bool marker_ok = read_ok && readback.size() >= marker_text.size() &&
            std::equal(marker.begin(), marker.begin() + marker_text.size(), readback.begin());
        log_msg(hf, "mcp.network_pg_sniff", "PRECHECK-REGION -- pid=%u active_pid=%u addr=0x%016llX size=%llu page_offset=0x%03llX query_ok=%d covers=%d state=0x%08X protect=0x%08X type=0x%08X base=0x%016llX region_size=%llu status=\"%s\" last_error=\"%s\"",
            pid,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(pg_addr),
            static_cast<unsigned long long>(install_size),
            static_cast<unsigned long long>(pg_addr & 0xFFFULL),
            query_ok ? 1 : 0,
            region_covers ? 1 : 0,
            query_ok ? region.state : 0,
            query_ok ? region.protect : 0,
            query_ok ? region.type : 0,
            static_cast<unsigned long long>(query_ok ? region.base : 0),
            static_cast<unsigned long long>(query_ok ? region.size : 0),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        log_msg(hf, "mcp.network_pg_sniff", "PRECHECK-READBACK -- read_ok=%d read_size=%zu marker_ok=%d marker=[%s]",
            read_ok ? 1 : 0,
            readback.size(),
            marker_ok ? 1 : 0,
            hex_preview(readback).c_str());
        std::string fixture_reason;
        if (pg_addr == 0)
            fixture_reason = "fixture_addr=0";
        else if (!query_ok)
            fixture_reason = "query_memory_failed";
        else if (!region_covers)
            fixture_reason = "region_does_not_cover_guard_page";
        else if (!committed)
            fixture_reason = "region_not_committed";
        else if (!readable)
            fixture_reason = "region_not_readable";
        else if (!marker_ok)
            fixture_reason = "fixture_marker_readback_mismatch";
        if (!fixture_reason.empty()) {
            log_msg(hf, "mcp.network_pg_sniff", "FIXTURE-INVALID -- reason=%s pid=%u active_pid=%u addr=0x%016llX size=%llu query_ok=%d read_ok=%d marker_ok=%d status=\"%s\" last_error=\"%s\"",
                fixture_reason.c_str(),
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(pg_addr),
                static_cast<unsigned long long>(install_size),
                query_ok ? 1 : 0,
                read_ok ? 1 : 0,
                marker_ok ? 1 : 0,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            if (pg_addr != 0)
                driver_bridge::free_memory(pg_addr);
            record_fixture_failed_tool("network_pg_sniff", failed);
            return;
        }
        mcp_standalone::json install_args;
        install_args["operation"] = "install";
        install_args["pid"] = pid;
        install_args["address"] = hex_u64(pg_addr);
        install_args["size"] = install_size;
        install_args["max_records_per_drain"] = 16;
        auto installed = invoke_tool_bounded(get_server(), "network_pg_sniff", install_args, tool_timeout_ms("network_pg_sniff"));
        uint64_t session_id = 0;
        payload_u64_field(installed.result.data, "session_id", session_id);
        if (installed.timed_out || !installed.result.found || installed.result.threw || !installed.result.success || session_id == 0) {
            log_msg(hf, "mcp.network_pg_sniff", "PRODUCT-FAIL -- dedicated install failed after valid fixture pid=%u active_pid=%u addr=0x%016llX size=%llu found=%d threw=%d success=%d timeout=%d session_id=%llu elapsed_ms=%lld text=%s data=%s err=%s",
                pid,
                driver_bridge::attached_pid(),
                static_cast<unsigned long long>(pg_addr),
                static_cast<unsigned long long>(install_size),
                installed.result.found ? 1 : 0,
                installed.result.threw ? 1 : 0,
                installed.result.success ? 1 : 0,
                installed.timed_out ? 1 : 0,
                static_cast<unsigned long long>(session_id),
                installed.elapsed_ms,
                compact_text(installed.result.text, 420).c_str(),
                compact_json(installed.result.data, 420).c_str(),
                compact_text(installed.result.exception_msg.empty() ? installed.result.text : installed.result.exception_msg, 700).c_str());
            log_mcp_result_detail("network_pg_sniff_install_failed", 0, "network_pg_sniff", install_args, installed.result, installed.elapsed_ms, "install_failed_after_valid_fixture");
            if (session_id != 0) {
                mcp_standalone::json uninstall_args;
                uninstall_args["operation"] = "uninstall";
                uninstall_args["session_id"] = session_id;
                auto uninstalled = invoke_tool_bounded(get_server(), "network_pg_sniff", uninstall_args, tool_timeout_ms("network_pg_sniff"));
                log_msg(hf, "mcp.network_pg_sniff", "CLEANUP -- failed-install session_id=%llu timeout=%d success=%d text=%s",
                    static_cast<unsigned long long>(session_id),
                    uninstalled.timed_out ? 1 : 0,
                    uninstalled.result.success ? 1 : 0,
                    compact_text(uninstalled.result.text, 500).c_str());
            }
            record_tool_status("network_pg_sniff", mcp_tool_call_status_t::failed);
            if (pg_addr != 0)
                driver_bridge::free_memory(pg_addr);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["operation"] = "list_sessions";
        test_tool_call(hf, "mcp.network_pg_sniff", get_server(), "network_pg_sniff", args, passed, failed, skipped);
        mcp_standalone::json uninstall_args;
        uninstall_args["operation"] = "uninstall";
        uninstall_args["session_id"] = session_id;
        auto uninstalled = invoke_tool_bounded(get_server(), "network_pg_sniff", uninstall_args, tool_timeout_ms("network_pg_sniff"));
        bool freed = false;
        if (pg_addr != 0)
            freed = driver_bridge::free_memory(pg_addr);
        log_msg(hf, "mcp.network_pg_sniff", "CLEANUP -- session_id=%llu timeout=%d success=%d freed=%d addr=0x%016llX text=%s",
            static_cast<unsigned long long>(session_id),
            uninstalled.timed_out ? 1 : 0,
            uninstalled.result.success ? 1 : 0,
            freed ? 1 : 0,
            static_cast<unsigned long long>(pg_addr),
            compact_text(uninstalled.result.text, 500).c_str());
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
        const char* tool_name = "network_packet_callstack";
        const char* tag = "mcp.network_packet_callstack";
        log_msg(hf, tag, "FIXTURE-BEGIN -- pid=%lu tid=%lu driver=%d status=\"%s\"",
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::status().c_str());
        packet_callstack::clear();
        log_msg(hf, tag, "FIXTURE -- clear complete");
        packet_callstack::set_enabled(true);
        log_msg(hf, tag, "FIXTURE -- enable complete");
        packet_callstack::capture_for_packet(0xA1DA0001ULL, GetTickCount64(), GetCurrentProcessId(), GetCurrentThreadId());
        log_msg(hf, tag, "FIXTURE -- capture complete");
        packet_callstack::set_enabled(false);
        log_msg(hf, tag, "FIXTURE -- disable complete");
        const auto seeded = packet_callstack::get_recent(8);
        log_msg(hf, tag, "FIXTURE -- seeded_entries=%zu frame_count=%zu driver=%d pid=%lu tid=%lu",
            seeded.size(),
            seeded.empty() ? 0 : seeded.back().frames.size(),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned long>(GetCurrentThreadId()));
        if (seeded.empty()) {
            log_msg(hf, tag, "FAIL -- packet callstack fixture produced no entries driver=%d status=\"%s\" last_error=\"%s\"",
                driver_bridge::using_kernel_driver() ? 1 : 0,
                driver_bridge::status().c_str(),
                driver_bridge::last_error().c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["operation"] = "recent";
        args["max_count"] = 8;
        test_tool_call(hf, tag, get_server(), tool_name, args, passed, failed, skipped);
        packet_callstack::clear();
        log_msg(hf, tag, "CLEANUP -- cleared seeded packet callstack entries");
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
        args["expression"] = "tcp.port == 80";
        test_tool_call(hf, "mcp.network_display_filter", get_server(), "network_display_filter", args, passed, failed, skipped);
    }

    void test_tool_network_protobuf_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["operation"] = "decode";
        args["hex_data"] = "0801";
        test_tool_call(hf, "mcp.network_protobuf_decode", get_server(), "network_protobuf_decode", args, passed, failed, skipped);
    }

    void test_tool_tls_manage_extract_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.tls_manage.extract_keys", "tls_manage", "extract_keys", {}, passed, failed, skipped);
    }

    void test_tool_tls_manage_start_keylog(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        auto cleanup = invoke_tool_action_bounded(get_server(), "tls_manage", "stop_keylog", {}, tool_timeout_ms("tls_manage"));
        log_msg(hf, "mcp.tls_manage.start_keylog.cleanup", "INFO -- pre-start stop cleanup success=%s timeout=%s elapsed_ms=%lld err=%s",
            cleanup.result.success ? "true" : "false",
            cleanup.timed_out ? "true" : "false",
            cleanup.elapsed_ms,
            compact_text(cleanup.result.exception_msg, 400).c_str());
        mcp_standalone::json args;
        args["pid"] = g_mcp_target_pid != 0 ? g_mcp_target_pid : GetCurrentProcessId();
        args["output_file"] = temp_file_narrow("aida_mcp_tls_keylog_test.keys");
        args["poll_interval_ms"] = 100u;
        args["append"] = false;
        test_tool_action_call(hf, "mcp.tls_manage.start_keylog", "tls_manage", "start_keylog", args, passed, failed, skipped);
    }

    void test_tool_tls_manage_stop_keylog(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.tls_manage.stop_keylog", "tls_manage", "stop_keylog", {}, passed, failed, skipped);
    }

    void test_tool_tls_manage_get_extracted_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.tls_manage.get_extracted_keys", "tls_manage", "get_extracted_keys", {}, passed, failed, skipped);
    }

    const char* cert_inject_fixture_pem() {
        return
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDATCCAemgAwIBAgIIFps/+cGYJ0UwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjQWlEQSBU\n"
            "ZXN0TGFiIENlcnQgSW5qZWN0IFZhbGlkYXRpb24wHhcNMjYwNjAzMTQwNzI4WhcNMzYwNjA0MTQw\n"
            "NzI4WjAuMSwwKgYDVQQDEyNBaURBIFRlc3RMYWIgQ2VydCBJbmplY3QgVmFsaWRhdGlvbjCCASIw\n"
            "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtugIKM0oMv6Dclxx1o4l4cxCAg0AO3JjIBjkcH\n"
            "bsxbJRo5PoI8XPuIU8ffROVTJ00uRSgydQ8+Qv8iJ9nkRmW/vHMxP+LL7GAeZxh+a7/97bTNRyH1\n"
            "DA4H0Q86IfHP5qDlzC/bV5QXoXlbJmL16k9GggOBNQ0TgDSp3OgURelfbU+AIXMObrO+NioyEvXp\n"
            "y9r7rgGiPFz7Wg4VZukzNqjpw31nB7AekQVo/7JB5h1s7loRreX5YRANOm0F4P/9eCoVT19FCUgS\n"
            "kOP6EENYRVAROeQHPSIME90cookscuCjdmN60HYQ62zZVLbvodU0ip/9Tvb4RSzWopcf3xHXVa0C\n"
            "AwEAAaMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQAD\n"
            "ggEBAAgZdcQ1I0INlsd1OnrQXLraUyrpdF+0fdx/leMTDJj3YBq52dMqahQn9HRBTUsv3UJKxhXJ\n"
            "OtwzM4zNPG8n+LNSXIyA1omn3qEtweb7rT917gH7vvu7bt94aUKTo5HHxikenNc0BTrpMB2/VMs7\n"
            "vejGD1kjuSepyzJY+OGFKQLmrDjXnfii6sBdiyqjEAz3Tzkpu5q5+FQfOEcpFkYheelN0Mk97FBY\n"
            "I84GhyP9DCf0IopB6st82FgIEfD2KysKmRLNMitMLWbRyq1n/IMvcyQmvbMfWLIut0MTiXkgYYso\n"
            "toecMmjf8UlHF3Qy+PD9VbuA/UGdfORlkTR74M+cWfk=\n"
            "-----END CERTIFICATE-----\n";
    }

    void test_tool_cert_manage_inject(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["cert_pem"] = cert_inject_fixture_pem();
        args["store_name"] = "MY";
        args["system_wide"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.cert_manage.inject", "cert_manage", "inject", args, passed, failed, skipped, false, &result);
        bool validate_only = false;
        g_mcp_cert_inject_validate_only = status == mcp_tool_call_status_t::passed &&
            payload_bool_field(result.data, "validate_only", validate_only) &&
            validate_only;
        std::string thumbprint;
        if (status == mcp_tool_call_status_t::passed &&
            payload_string_field(result.data, "thumbprint", thumbprint) &&
            !thumbprint.empty()) {
            g_mcp_cert_thumbprint = thumbprint;
            log_msg(hf, "mcp.cert_manage.inject", "CERT-FIXTURE -- captured thumbprint_len=%zu store=MY system_wide=0", g_mcp_cert_thumbprint.size());
        }
    }

    void test_tool_cert_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_cert_thumbprint.empty()) {
            if (g_mcp_cert_inject_validate_only) {
                log_msg(hf, "mcp.cert_manage.remove", "PASS -- cert_manage action=inject ran in validate_only mode; no certificate store mutation required removal");
                record_tool_status("cert_manage", mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
            log_msg(hf, "mcp.cert_manage.remove", "FAIL -- cert_manage action=inject did not capture a thumbprint for removal");
            record_fixture_failed_tool("cert_manage", failed);
            return;
        }
        mcp_standalone::json args;
        args["thumbprint"] = g_mcp_cert_thumbprint;
        args["store_name"] = "MY";
        auto status = test_tool_action_call(hf, "mcp.cert_manage.remove", "cert_manage", "remove", args, passed, failed, skipped);
        if (status == mcp_tool_call_status_t::passed)
            g_mcp_cert_thumbprint.clear();
    }

    void cleanup_mcp_cert_fixture(HANDLE hf, const char* tag) {
        if (g_mcp_cert_thumbprint.empty())
            return;
        mcp_standalone::json args;
        args["thumbprint"] = g_mcp_cert_thumbprint;
        args["store_name"] = "MY";
        auto result = invoke_tool_action_bounded(get_server(), "cert_manage", "remove", args, tool_timeout_ms("cert_manage"));
        log_msg(hf, tag, "CERT-CLEANUP -- attempted remaining fixture removal timed_out=%d found=%d threw=%d success=%d elapsed_ms=%lld",
            result.timed_out ? 1 : 0,
            result.result.found ? 1 : 0,
            result.result.threw ? 1 : 0,
            result.result.success ? 1 : 0,
            result.elapsed_ms);
        if (!result.timed_out && result.result.found && !result.result.threw && result.result.success)
            g_mcp_cert_thumbprint.clear();
    }

    void test_tool_cert_manage_generate_ca(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::tool_result_t result;
        mcp_standalone::json args;
        args["cn"] = "AiDA TestLab CA";
        args["validity_days"] = 7u;
        auto status = test_tool_action_call(hf, "mcp.cert_manage.generate_ca", "cert_manage", "generate_ca", args, passed, failed, skipped, false, &result);
        if (status != mcp_tool_call_status_t::passed)
            return;
        bool private_exported = true;
        bool has_private_material =
            find_payload_key_recursive(result.data, "key_der_hex") ||
            find_payload_key_recursive(result.data, "private_key_der") ||
            find_payload_key_recursive(result.data, "private_key_pem");
        if (payload_bool_field(result.data, "private_key_exported", private_exported) &&
            !private_exported && !has_private_material) {
            log_msg(hf, "mcp.cert_manage.generate_ca.guard", "PASS -- cert_manage action=generate_ca returned public certificate only");
            return;
        }
        log_msg(hf, "mcp.cert_manage.generate_ca.guard", "FAIL -- cert_manage action=generate_ca exposed private key material or omitted private_key_exported=false");
        failed.fetch_add(1);
    }

    void test_tool_cert_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.cert_manage.list", "cert_manage", "list", {}, passed, failed, skipped);
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

void test_tool_firefox_profile_launch(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const auto firefox_before = process_ids_by_image_name(L"firefox.exe");
        mcp_standalone::json args;
        args["proxy_host"] = "127.0.0.1";
        args["proxy_port"] = 18443;
        invoke_result_t result;
        auto cleanup_firefox = [&](uint32_t launched_pid) {
            if (launched_pid != 0 && firefox_before.find(launched_pid) == firefox_before.end())
                terminate_fixture_process_pid(hf, "mcp.firefox_profile_launch.guard", launched_pid, "returned_launch_pid");
            const auto firefox_after = process_ids_by_image_name(L"firefox.exe");
            for (DWORD pid : firefox_after) {
                if (firefox_before.find(pid) == firefox_before.end() && pid != launched_pid)
                    terminate_fixture_process_pid(hf, "mcp.firefox_profile_launch.guard", pid, "new_firefox_fixture_pid");
            }
        };
        const char* tool_name = "firefox_profile_launch";
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_action_bounded(get_server(), tool_name, "import_rules", args, tool_timeout_ms(tool_name));
        result = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, result, timed.elapsed_ms, "");
        uint64_t launched_pid64 = 0;
        payload_u64_field(result.data, "launched_pid", launched_pid64);
        uint32_t launched_pid = launched_pid64 <= 0xFFFFFFFFull ? static_cast<uint32_t>(launched_pid64) : 0;
        if (timed.timed_out || !result.found || result.threw) {
            log_msg(hf, "mcp.firefox_profile_launch",
                "FAIL -- Firefox profile launch dispatch failed found=%d threw=%d timeout=%d err=%s",
                result.found ? 1 : 0,
                result.threw ? 1 : 0,
                timed.timed_out ? 1 : 0,
                compact_text(result.exception_msg, 700).c_str());
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            cleanup_firefox(launched_pid);
            return;
        }
        if (!result.success) {
            const std::string fail_text_lc = lower_copy(result.text + " " + compact_json(result.data, 700));
            if (fail_text_lc.find("current_user_ca_not_trusted") != std::string::npos ||
                fail_text_lc.find("firefox host dependency unavailable") != std::string::npos ||
                fail_text_lc.find("firefox not detected") != std::string::npos ||
                fail_text_lc.find("firefox_not_detected") != std::string::npos) {
                bool profile_files_valid = false;
                bool trust_verified = true;
                bool firefox_detected = true;
                bool prepared = true;
                payload_bool_field(result.data, "profile_files_valid", profile_files_valid);
                payload_bool_field(result.data, "trust_readiness_verified", trust_verified);
                payload_bool_field(result.data, "firefox_detected", firefox_detected);
                payload_bool_field(result.data, "prepared", prepared);
                if (profile_files_valid && (!trust_verified || !firefox_detected || !prepared)) {
                    log_msg(hf, "mcp.firefox_profile_launch",
                        "PASS -- Firefox launch correctly stopped before browser start because dependency proof is unavailable firefox_detected=%d trust=%d prepared=%d text=%s",
                        firefox_detected ? 1 : 0,
                        trust_verified ? 1 : 0,
                        prepared ? 1 : 0,
                        compact_text(result.text, 700).c_str());
                    record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                    passed.fetch_add(1);
                } else {
                    log_msg(hf, "mcp.firefox_profile_launch",
                        "FAIL -- Firefox profile launch dependency text lacked structured readiness proof: %s",
                        compact_text(result.text, 700).c_str());
                    record_tool_status(tool_name, mcp_tool_call_status_t::failed);
                    failed.fetch_add(1);
                }
                cleanup_firefox(launched_pid);
                return;
            }
            log_msg(hf, "mcp.firefox_profile_launch",
                "FAIL -- Firefox profile launch unexpected failure: %s",
                compact_text(result.text.empty() ? result.exception_msg : result.text, 700).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            cleanup_firefox(launched_pid);
            return;
        }
        bool launched = false;
        bool firefox_detected = false;
        bool profile_files_valid = false;
        bool trust_verified = false;
        bool post_launch_validated = false;
        payload_bool_field(result.data, "launched", launched);
        payload_bool_field(result.data, "firefox_detected", firefox_detected);
        payload_bool_field(result.data, "profile_files_valid", profile_files_valid);
        payload_bool_field(result.data, "trust_readiness_verified", trust_verified);
        payload_bool_field(result.data, "post_launch_profile_validated", post_launch_validated);
        uint32_t exit_code = 0;
        const bool alive = launched_pid != 0 && process_alive_by_pid(launched_pid, &exit_code);
        const std::string result_text_lc = lower_copy(result.text);
        const bool validate_only_note = result_text_lc.find("validation only") != std::string::npos ||
            result_text_lc.find("without starting") != std::string::npos;
        if (!launched || launched_pid == 0 || !alive || !firefox_detected || !profile_files_valid || !trust_verified || !post_launch_validated || validate_only_note) {
            log_msg(hf, "mcp.firefox_profile_launch",
                "FAIL -- Firefox profile launch lacked real launch proof launched=%d pid=%u alive=%d exit_or_err=0x%08X firefox_detected=%d profile_files_valid=%d trust_verified=%d post_launch_validated=%d validate_only_note=%d payload=%s",
                launched ? 1 : 0,
                launched_pid,
                alive ? 1 : 0,
                exit_code,
                firefox_detected ? 1 : 0,
                profile_files_valid ? 1 : 0,
                trust_verified ? 1 : 0,
                post_launch_validated ? 1 : 0,
                validate_only_note ? 1 : 0,
                compact_json(result.data, 900).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            cleanup_firefox(launched_pid);
            return;
        }
        log_msg(hf, "mcp.firefox_profile_launch", "PROOF -- Firefox profile launched pid=%u profile_valid=%d trust_verified=%d post_launch_validated=%d",
            launched_pid,
            profile_files_valid ? 1 : 0,
            trust_verified ? 1 : 0,
            post_launch_validated ? 1 : 0);
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
        cleanup_firefox(launched_pid);
    }

    void test_tool_quic_manage_detect_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        std::vector<uint8_t> packet = {
            0xC0, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x08, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x00, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
        };
        if (!seed_udp_capture_for_detection(hf, "mcp.quic_manage.detect_connections", 443, packet)) {
            record_fixture_failed_tool("quic_manage", failed);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        test_tool_action_call(hf, "mcp.quic_manage.detect_connections", "quic_manage", "detect_connections", args, passed, failed, skipped);
        driver_bridge::stop_capture();
    }

    void test_tool_quic_manage_decrypt_initial(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["packet_hex"] = "C000000001080011223344556677088899AABBCCDDEEFF00100000000000";
        test_tool_action_call(hf, "mcp.quic_manage.decrypt_initial", "quic_manage", "decrypt_initial", args, passed, failed, skipped);
    }

    void test_tool_quic_manage_extract_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_mcp_scanner_addr == 0 && !ensure_mcp_private_bytes(hf, "mcp.quic_manage.extract_keys", g_mcp_scanner_addr, 4096, {0x51, 0x55, 0x49, 0x43})) {
            record_fixture_failed_tool("quic_manage", failed);
            return;
        }
        const std::string key_line =
            "QUIC_CLIENT_TRAFFIC_SECRET_0 "
            "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF "
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        std::vector<uint8_t> bytes(key_line.begin(), key_line.end());
        bytes.push_back(0);
        if (!driver_bridge::write_memory(g_mcp_scanner_addr, bytes)) {
            log_msg(hf, "mcp.quic_manage.extract_keys", "FAIL -- could not seed target memory key fixture addr=0x%016llX",
                static_cast<unsigned long long>(g_mcp_scanner_addr));
            record_tool_status("quic_manage", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = driver_bridge::attached_pid();
        test_tool_action_call(hf, "mcp.quic_manage.extract_keys", "quic_manage", "extract_keys", args, passed, failed, skipped);
    }

    void test_tool_dtls_manage_detect_sessions(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        std::vector<uint8_t> packet = {
            0x16, 0xFE, 0xFD,
            0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01,
            0x01
        };
        if (!seed_udp_capture_for_detection(hf, "mcp.dtls_manage.detect_sessions", 4443, packet)) {
            record_fixture_failed_tool("dtls_manage", failed);
            return;
        }
        mcp_standalone::json args;
        args["pid"] = GetCurrentProcessId();
        test_tool_action_call(hf, "mcp.dtls_manage.detect_sessions", "dtls_manage", "detect_sessions", args, passed, failed, skipped);
        driver_bridge::stop_capture();
    }

    void test_tool_dtls_manage_extract_keys(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.dtls_manage.extract_keys", "dtls_manage", "extract_keys", {}, passed, failed, skipped);
    }

    void test_tool_autoresponder_manage_add_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["match_type"] = "prefix_url";
        args["match_pattern"] = "http://test.local/";
        args["response_body"] = "test";
        const std::string match_type = args["match_type"].get<std::string>();
        const std::string match_pattern = args["match_pattern"].get<std::string>();
        const std::string response_body = args["response_body"].get<std::string>();
        log_msg(hf, "mcp.autoresponder_manage.add_rule", "VERIFY-INPUT -- match_type=%s pattern=%s response_len=%zu previous_rule_id=%llu",
            match_type.c_str(),
            match_pattern.c_str(),
            response_body.size(),
            (unsigned long long)g_autoresponder_rule_id);
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.autoresponder_manage.add_rule", "autoresponder_manage", "add_rule", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            json_u64_field(result.data, "rule_id", g_autoresponder_rule_id);
            log_msg(hf, "mcp.autoresponder_manage.add_rule", "VERIFY-RESULT -- captured_rule_id=%llu data=%s text=%s",
                (unsigned long long)g_autoresponder_rule_id,
                compact_json(result.data, 900).c_str(),
                compact_text(result.text, 700).c_str());
            auto listed = invoke_tool_action_bounded(get_server(), "autoresponder_manage", "list_rules", {}, tool_timeout_ms("autoresponder_manage"));
            const uint64_t count = json_count_or_array_size(listed.result.data, "count", "rules");
            const bool contains = g_autoresponder_rule_id != 0 &&
                json_array_contains_u64_field(listed.result.data, "rules", g_autoresponder_rule_id, { "id", "rule_id" });
            log_msg(hf, "mcp.autoresponder_manage.add_rule", "VERIFY-LIST -- timeout=%d success=%d count=%llu contains_rule=%d text=%s data=%s",
                listed.timed_out ? 1 : 0,
                listed.result.success ? 1 : 0,
                (unsigned long long)count,
                contains ? 1 : 0,
                compact_text(listed.result.text, 700).c_str(),
                compact_json(listed.result.data, 900).c_str());
        }
    }

    void test_tool_autoresponder_manage_remove_rule(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["rule_id"] = g_autoresponder_rule_id;
        log_msg(hf, "mcp.autoresponder_manage.remove_rule", "VERIFY-INPUT -- rule_id=%llu", (unsigned long long)g_autoresponder_rule_id);
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.autoresponder_manage.remove_rule", "autoresponder_manage", "remove_rule", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            log_tool_result_payload(hf, "mcp.autoresponder_manage.remove_rule", "VERIFY-RESULT", result);
            auto listed = invoke_tool_action_bounded(get_server(), "autoresponder_manage", "list_rules", {}, tool_timeout_ms("autoresponder_manage"));
            const uint64_t count = json_count_or_array_size(listed.result.data, "count", "rules");
            const bool contains = g_autoresponder_rule_id != 0 &&
                json_array_contains_u64_field(listed.result.data, "rules", g_autoresponder_rule_id, { "id", "rule_id" });
            log_msg(hf, "mcp.autoresponder_manage.remove_rule", "VERIFY-LIST -- timeout=%d success=%d count=%llu contains_removed_rule=%d text=%s data=%s",
                listed.timed_out ? 1 : 0,
                listed.result.success ? 1 : 0,
                (unsigned long long)count,
                contains ? 1 : 0,
                compact_text(listed.result.text, 700).c_str(),
                compact_json(listed.result.data, 900).c_str());
        }
    }

    void test_tool_autoresponder_manage_list_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.autoresponder_manage.list_rules", "VERIFY-INPUT -- captured_rule_id=%llu", (unsigned long long)g_autoresponder_rule_id);
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.autoresponder_manage.list_rules", "autoresponder_manage", "list_rules", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            const uint64_t count = json_count_or_array_size(result.data, "count", "rules");
            log_msg(hf, "mcp.autoresponder_manage.list_rules", "VERIFY-RESULT -- count=%llu array_size=%zu captured_rule_present=%d data=%s",
                (unsigned long long)count,
                json_array_size_field(result.data, "rules"),
                (g_autoresponder_rule_id != 0 &&
                    json_array_contains_u64_field(result.data, "rules", g_autoresponder_rule_id, { "id", "rule_id" })) ? 1 : 0,
                compact_json(result.data, 900).c_str());
        }
    }

    void test_tool_autoresponder_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.autoresponder_manage.start", "VERIFY-INPUT -- captured_rule_id=%llu", (unsigned long long)g_autoresponder_rule_id);
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.autoresponder_manage.start", "autoresponder_manage", "start", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed)
            log_tool_result_payload(hf, "mcp.autoresponder_manage.start", "VERIFY-RESULT", result);
    }

    void test_tool_autoresponder_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        log_msg(hf, "mcp.autoresponder_manage.stop", "VERIFY-INPUT -- captured_rule_id=%llu", (unsigned long long)g_autoresponder_rule_id);
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.autoresponder_manage.stop", "autoresponder_manage", "stop", {}, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed)
            log_tool_result_payload(hf, "mcp.autoresponder_manage.stop", "VERIFY-RESULT", result);
    }

    void test_tool_autoresponder_manage_import_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "autoresponder_manage";
        const char* tag = "mcp.autoresponder_manage.import_rules";
        mcp_standalone::json args;
        args["rules_json"] = "[{\"enabled\":true,\"priority\":7,\"match_type\":\"prefix_url\",\"match_pattern\":\"http://aida-mcp-import.local/\",\"status_code\":207,\"status_reason\":\"AiDA\",\"response_body\":\"aida-autoresponder-import\",\"response_headers\":{\"X-AiDA\":\"import\"}}]";
        log_msg(hf, tag, "VERIFY-INPUT -- rules_json_len=%zu captured_rule_id=%llu",
            args["rules_json"].get<std::string>().size(),
            (unsigned long long)g_autoresponder_rule_id);
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_action_bounded(get_server(), tool_name, "export_rules", args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        auto listed = invoke_tool_action_bounded(get_server(), "autoresponder_manage", "list_rules", {}, tool_timeout_ms("autoresponder_manage"));
        const uint64_t listed_count = json_count_or_array_size(listed.result.data, "count", "rules");
        const bool import_pattern_present = payload_text_contains(listed.result, "aida-mcp-import.local");
        log_msg(hf, tag, "VERIFY-LIST -- timeout=%d success=%d count=%llu pattern_present=%d text=%s data=%s",
            listed.timed_out ? 1 : 0,
            listed.result.success ? 1 : 0,
            static_cast<unsigned long long>(listed_count),
            import_pattern_present ? 1 : 0,
            compact_text(listed.result.text, 700).c_str(),
            compact_json(listed.result.data, 900).c_str());
        if (timed.timed_out || !ir.found || ir.threw || !ir.success ||
            listed.timed_out || !listed.result.success || listed_count == 0 || !import_pattern_present) {
            log_msg(hf, tag, "FAIL -- import did not produce a non-empty verifiable ruleset success=%d listed_count=%llu pattern_present=%d",
                ir.success ? 1 : 0,
                static_cast<unsigned long long>(listed_count),
                import_pattern_present ? 1 : 0);
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- imported non-empty ruleset count=%llu", static_cast<unsigned long long>(listed_count));
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_autoresponder_manage_export_rules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        const char* tool_name = "autoresponder_manage";
        const char* tag = "mcp.autoresponder_manage.export_rules";
        mcp_standalone::json args;
        args["path"] = temp_file_narrow("aida_test_rules.json");
        const std::string path = args["path"].get<std::string>();
        log_msg(hf, tag, "VERIFY-INPUT -- path=%s captured_rule_id=%llu",
            path.c_str(),
            (unsigned long long)g_autoresponder_rule_id);
        g_invoked_tools.insert(tool_name);
        auto timed = invoke_tool_bounded(get_server(), tool_name, args, tool_timeout_ms(tool_name));
        const auto& ir = timed.result;
        log_mcp_result_detail("completed", 0, tool_name, args, ir, timed.elapsed_ms, "");
        std::error_code ec;
        const bool exists = std::filesystem::exists(path, ec);
        const uint64_t size = exists ? static_cast<uint64_t>(std::filesystem::file_size(path, ec)) : 0;
        uint64_t rule_count = 0;
        uint64_t payload_file_size = 0;
        bool wrote_file = false;
        payload_u64_field(ir.data, "rule_count", rule_count);
        payload_u64_field(ir.data, "file_size", payload_file_size);
        payload_bool_field(ir.data, "wrote_file", wrote_file);
        const bool exported_pattern_present = payload_text_contains(ir, "aida-mcp-import.local");
        log_msg(hf, tag, "VERIFY-FILE -- exists=%d size=%llu ec=%lu wrote_file=%d payload_file_size=%llu rule_count=%llu pattern_present=%d path=%s",
            exists ? 1 : 0,
            static_cast<unsigned long long>(size),
            static_cast<unsigned long>(ec.value()),
            wrote_file ? 1 : 0,
            static_cast<unsigned long long>(payload_file_size),
            static_cast<unsigned long long>(rule_count),
            exported_pattern_present ? 1 : 0,
            path.c_str());
        if (timed.timed_out || !ir.found || ir.threw || !ir.success ||
            !exists || size == 0 || !wrote_file || payload_file_size == 0 ||
            rule_count == 0 || !exported_pattern_present) {
            log_msg(hf, tag, "FAIL -- export did not produce a non-empty file-backed ruleset success=%d exists=%d size=%llu rule_count=%llu pattern_present=%d",
                ir.success ? 1 : 0,
                exists ? 1 : 0,
                static_cast<unsigned long long>(size),
                static_cast<unsigned long long>(rule_count),
                exported_pattern_present ? 1 : 0);
            record_tool_status(tool_name, timed.timed_out ? mcp_tool_call_status_t::timed_out : mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        log_msg(hf, tag, "PASS -- exported non-empty ruleset file size=%llu rule_count=%llu",
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(rule_count));
        record_tool_status(tool_name, mcp_tool_call_status_t::passed);
        passed.fetch_add(1);
    }

    void test_tool_network_decrypt_capture(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
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
            bool dependency_available = true;
            payload_bool_field(ir.data, "dependency_available", dependency_available);
            if (!dependency_available) {
                log_msg(hf, tag, "PASS -- network_decrypt_capture reported missing tshark dependency with valid pcap/keylog fixtures text=%s",
                    compact_text(ir.text, 900).c_str());
                record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
            log_msg(hf, tag, "FAIL -- tshark launch failed without dependency_unavailable diagnostic: %s",
                compact_text(ir.text, 900).c_str());
            record_tool_status(tool_name, mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
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
        if (!ir.success && text_lc.find("no matching packets") != std::string::npos) {
            bool dependency_available = false;
            payload_bool_field(ir.data, "dependency_available", dependency_available);
            if (dependency_available) {
                log_msg(hf, tag, "PASS -- network_decrypt_capture reached tshark backend with deterministic empty pcap fixture total=%llu text=%s",
                    static_cast<unsigned long long>(total_packets),
                    compact_text(ir.text, 700).c_str());
                record_tool_status(tool_name, mcp_tool_call_status_t::passed);
                passed.fetch_add(1);
                return;
            }
        }
        log_msg(hf, tag, "FAIL -- unexpected network_decrypt_capture result success=%d text=%s",
            ir.success ? 1 : 0,
            compact_text(ir.text, 900).c_str());
        record_tool_status(tool_name, mcp_tool_call_status_t::failed);
        failed.fetch_add(1);
    }

void test_tool_burp_scanner_manage_start_audit(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string url = burp_fixture_url(hf, "mcp.burp_scanner_manage.start_audit", "/?q=test");
        mcp_standalone::json args; args["url"] = url; args["raw_request"] = "GET /?q=test HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: AiDA-Scanner-Fixture\r\nConnection: close\r\n\r\n"; args["modules"] = mcp_standalone::json::array({"host-header"}); args["per_module_cap"] = 1; args["timeout_ms"] = 3000; args["max_concurrent"] = 1;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_scanner_manage.start_audit", "burp_scanner_manage", "start_audit", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            json_u64_field(result.data, "audit_id", g_burp_scanner_audit_id);
            Sleep(1000);
        }
    }
    void test_tool_burp_scanner_manage_audit_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["audit_id"] = g_burp_scanner_audit_id;
        test_tool_action_call(hf, "mcp.burp_scanner_manage.audit_status", "burp_scanner_manage", "audit_status", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_manage_list_audits(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_scanner_manage.list_audits", "burp_scanner_manage", "list_audits", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_manage_cancel(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["audit_id"] = g_burp_scanner_audit_id;
        auto status = test_tool_action_call(hf, "mcp.burp_scanner_manage.cancel", "burp_scanner_manage", "cancel", args, passed, failed, skipped);
        if (status != mcp_tool_call_status_t::passed || g_burp_scanner_audit_id == 0)
            return;
        for (int i = 0; i < 20; ++i) {
            mcp_standalone::json status_args; status_args["audit_id"] = g_burp_scanner_audit_id;
            auto timed = invoke_tool_bounded(get_server(), "burp_scanner_manage", status_args, 2000);
            bool running = true;
            if (!timed.timed_out && timed.result.success && payload_bool_field(timed.result.data, "running", running)) {
                log_msg(hf, "mcp.burp_scanner_manage.cancel", "POLL -- audit_id=%llu running=%d",
                    static_cast<unsigned long long>(g_burp_scanner_audit_id), running ? 1 : 0);
                if (!running)
                    return;
            }
            Sleep(250);
        }
        log_msg(hf, "mcp.burp_scanner_manage.cancel", "WARN -- audit_id=%llu still running after cancel drain poll",
            static_cast<unsigned long long>(g_burp_scanner_audit_id));
    }
    void test_tool_burp_scanner_manage_list_issues(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_burp_scanner_issue_id == 0)
            seed_burp_scanner_issue_fixture(hf, "mcp.burp_scanner_manage.list_issues");
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_scanner_manage.list_issues", "burp_scanner_manage", "list_issues", {}, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_array_first_field(result.data, "issues", g_burp_scanner_issue_id, {"id", "issue_id"});
    }
    void test_tool_burp_scanner_manage_get_issue(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_burp_scanner_issue_id == 0)
            seed_burp_scanner_issue_fixture(hf, "mcp.burp_scanner_manage.get_issue");
        if (g_burp_scanner_issue_id == 0) {
            record_precondition_skipped_tool("burp_scanner_manage", skipped);
            return;
        }
        mcp_standalone::json args; args["issue_id"] = g_burp_scanner_issue_id;
        test_tool_action_call(hf, "mcp.burp_scanner_manage.get_issue", "burp_scanner_manage", "get_issue", args, passed, failed, skipped);
    }
    void test_tool_burp_scanner_manage_passive_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        seed_burp_passive_scanner_exchange(hf, "mcp.burp_scanner_manage.passive_status");
        test_tool_action_call(hf, "mcp.burp_scanner_manage.passive_status", "burp_scanner_manage", "passive_status", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_manage_list_modules(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_scanner_manage.list_modules", "burp_scanner_manage", "list_modules", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_manage_clear_issues(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_scanner_manage.clear_issues", "burp_scanner_manage", "clear_issues", {}, passed, failed, skipped);
    }
    void test_tool_burp_scanner_manage_passive_enable(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["enabled"] = false;
        test_tool_action_call(hf, "mcp.burp_scanner_manage.passive_enable", "burp_scanner_manage", "passive_enable", args, passed, failed, skipped);
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
        if (!seed_burp_sitemap_fixture(hf, "mcp.burp_sitemap_get_exchange")) {
            record_fixture_failed_tool("burp_sitemap_get_exchange", failed);
            return;
        }
        mcp_standalone::json args; args["exchange_id"] = g_burp_sitemap_exchange_id;
        test_tool_call(hf, "mcp.burp_sitemap_get_exchange", get_server(), "burp_sitemap_get_exchange", args, passed, failed, skipped);
    }
    void test_tool_burp_sitemap_send_to(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!seed_burp_sitemap_fixture(hf, "mcp.burp_sitemap_send_to")) {
            record_fixture_failed_tool("burp_sitemap_send_to", failed);
            return;
        }
        mcp_standalone::json args; args["exchange_id"] = g_burp_sitemap_exchange_id; args["target"] = "repeater";
        test_tool_call(hf, "mcp.burp_sitemap_send_to", get_server(), "burp_sitemap_send_to", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_manage_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = static_cast<std::uint64_t>(424242); args["kind"] = "include"; args["protocol"] = "http"; args["host_pattern"] = "127.0.0.1"; args["port"] = 0; args["path_prefix"] = "/"; args["enabled"] = true;
        test_tool_action_call(hf, "mcp.burp_scope_manage.add", "burp_scope_manage", "add", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = static_cast<std::uint64_t>(424242);
        test_tool_action_call(hf, "mcp.burp_scope_manage.remove", "burp_scope_manage", "remove", args, passed, failed, skipped);
    }
    void test_tool_burp_scope_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json seed_args;
        seed_args["id"] = static_cast<std::uint64_t>(424243);
        seed_args["kind"] = "include";
        seed_args["protocol"] = "http";
        seed_args["host_pattern"] = "127.0.0.1";
        seed_args["port"] = 0;
        seed_args["path_prefix"] = "/";
        seed_args["enabled"] = true;
        auto seeded = invoke_tool_action_bounded(get_server(), "burp_scope_manage", "add", seed_args, tool_timeout_ms("burp_scope_manage"));
        log_mcp_result_detail("scope_list_fixture", 0, "burp_scope_manage", seed_args, seeded.result, seeded.elapsed_ms, "");
        if (seeded.timed_out || !seeded.result.found || seeded.result.threw || !seeded.result.success) {
            log_msg(hf, "mcp.burp_scope_manage.list", "FAIL -- scope list fixture add failed found=%d threw=%d success=%d timeout=%d text=%s err=%s",
                seeded.result.found ? 1 : 0,
                seeded.result.threw ? 1 : 0,
                seeded.result.success ? 1 : 0,
                seeded.timed_out ? 1 : 0,
                compact_text(seeded.result.text, 700).c_str(),
                compact_text(seeded.result.exception_msg, 700).c_str());
            record_tool_status("burp_scope_manage", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        test_tool_action_call(hf, "mcp.burp_scope_manage.list", "burp_scope_manage", "list", {}, passed, failed, skipped);
    }
    void test_tool_burp_scope_manage_check(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["url"] = "http://127.0.0.1/";
        test_tool_action_call(hf, "mcp.burp_scope_manage.check", "burp_scope_manage", "check", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_cookie_manage.list", "burp_cookie_manage", "list", {}, passed, failed, skipped);
    }
    void test_tool_burp_cookie_manage_set(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["name"] = "test_cookie"; args["value"] = "test_val"; args["domain"] = "127.0.0.1";
        test_tool_action_call(hf, "mcp.burp_cookie_manage.set", "burp_cookie_manage", "set", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_manage_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["name"] = "test_cookie";
        test_tool_action_call(hf, "mcp.burp_cookie_manage.delete", "burp_cookie_manage", "delete", args, passed, failed, skipped);
    }
    void test_tool_burp_cookie_manage_export_netscape(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["file_path"] = temp_file_narrow("aida_mcp_cookies.txt");
        test_tool_action_call(hf, "mcp.burp_cookie_manage.export_netscape", "burp_cookie_manage", "export_netscape", args, passed, failed, skipped);
    }
    void test_tool_burp_dom_xss_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.burp_dom_xss_status";
        set_progress_step("mcp precheck: burp_dom_xss_status");
        std::string dependency_reason;
        const bool dependency_ready = camoufox_dependencies_ready_for_test(hf, tag, dependency_reason);
        log_msg(hf, tag, "PRECHECK -- dependency_ready=%d reason=%s",
            dependency_ready ? 1 : 0,
            dependency_reason.empty() ? "<empty>" : compact_text(dependency_reason, 700).c_str());
        if (!dependency_ready) {
            g_burp_dom_xss_browser_infra_failed = true;
            g_burp_dom_xss_dependency_reason = dependency_reason;
            record_camoufox_dependency_guard_pass(hf, tag, "burp_dom_xss_status", dependency_reason, passed, failed);
            return;
        }
        std::string bridge_reason;
        if (!ensure_mcp_camoufox_bridge_ready_for_tool(hf, tag, "burp_dom_xss_status", failed, &bridge_reason)) {
            g_burp_dom_xss_browser_infra_failed = true;
            g_burp_dom_xss_dependency_reason = bridge_reason;
            log_msg(hf, tag, "FAIL -- burp_dom_xss_status not dispatched because Camoufox bridge proof failed: %s",
                bridge_reason.empty() ? "<empty>" : compact_text(bridge_reason, 900).c_str());
            return;
        }
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, tag, get_server(), "burp_dom_xss_status", {}, passed, failed, skipped, false, &result);
        bool camoufox_ready = false;
        payload_bool_field(result.data, "camoufox_ready", camoufox_ready);
        if (!dependency_ready || status != mcp_tool_call_status_t::passed || !camoufox_ready)
            g_burp_dom_xss_browser_infra_failed = true;
    }
    void test_tool_burp_dom_xss_test_payload(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_burp_dom_xss_browser_infra_failed) {
            if (!g_burp_dom_xss_dependency_reason.empty()) {
                record_camoufox_dependency_guard_pass(hf, "mcp.burp_dom_xss_test_payload", "burp_dom_xss_test_payload", g_burp_dom_xss_dependency_reason, passed, failed);
                return;
            }
            log_msg(hf, "mcp.burp_dom_xss_test_payload", "FAIL -- not executed because burp_dom_xss_status did not prove Camoufox readiness");
            record_fixture_failed_tool("burp_dom_xss_test_payload", failed);
            return;
        }
        mcp_standalone::json args; args["target_url"] = burp_fixture_url(hf, "mcp.burp_dom_xss_test_payload", "/?q=test"); args["payload"] = R"(<img src=x onerror="try{{CANARY_FN}('test')}catch(e){};try{console.log('AIDA_DOM_XSS_CANARY:'+JSON.stringify({id:'img:{CANARY}',src:'test',token:'{CANARY}'}))}catch(e){}">)";
        args["timeout_ms"] = 30000;
        args["capture_screenshot"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_call(hf, "mcp.burp_dom_xss_test_payload", get_server(), "burp_dom_xss_test_payload", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::timed_out ||
            (status != mcp_tool_call_status_t::passed && browser_infrastructure_text(result.text)))
            g_burp_dom_xss_browser_infra_failed = true;
    }
    void test_tool_burp_dom_xss_scan(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        (void)skipped;
        if (g_burp_dom_xss_browser_infra_failed) {
            if (!g_burp_dom_xss_dependency_reason.empty()) {
                record_camoufox_dependency_guard_pass(hf, "mcp.burp_dom_xss_scan", "burp_dom_xss_scan", g_burp_dom_xss_dependency_reason, passed, failed);
                return;
            }
            log_msg(hf, "mcp.burp_dom_xss_scan", "FAIL -- browser infrastructure already failed in burp_dom_xss_test_payload");
            record_tool_status("burp_dom_xss_scan", mcp_tool_call_status_t::failed);
            failed.fetch_add(1);
            return;
        }
        mcp_standalone::json args; args["target_url"] = burp_fixture_url(hf, "mcp.burp_dom_xss_scan", "/?q=test");
        args["include_polyglot"] = false;
        args["include_standard"] = true;
        args["include_dom_only"] = false;
        args["max_payloads_per_point"] = 1;
        args["per_payload_timeout_ms"] = 6000;
        args["scan_timeout_ms"] = 35000;
        test_tool_call(hf, "mcp.burp_dom_xss_scan", get_server(), "burp_dom_xss_scan", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["start_urls"] = mcp_standalone::json::array({burp_fixture_url(hf, "mcp.burp_crawler_manage.start")}); args["max_depth"] = 1; args["max_pages"] = 2; args["concurrency"] = 1; args["respect_robots"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_crawler_manage.start", "burp_crawler_manage", "start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "crawl_id", g_burp_crawler_id);
    }
    void test_tool_burp_crawler_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 40 && g_burp_crawler_id != 0; ++i) {
            auto st = aida::burp::crawler::status(g_burp_crawler_id);
            log_msg(hf, "mcp.burp_crawler_manage.status", "WAIT -- crawl_id=%llu poll=%d phase=%d queue=%d visited=%d failed=%d found=%d",
                static_cast<unsigned long long>(g_burp_crawler_id), i, static_cast<int>(st.phase), st.queue_depth, st.pages_visited, st.pages_failed, st.urls_found);
            if (st.pages_visited > 0 || st.urls_found > 0 || st.pages_failed > 0 || st.phase == aida::burp::crawler::crawl_status_phase_t::complete)
                break;
            Sleep(100);
        }
        mcp_standalone::json args; args["crawl_id"] = g_burp_crawler_id;
        test_tool_action_call(hf, "mcp.burp_crawler_manage.status", "burp_crawler_manage", "status", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crawl_id"] = g_burp_crawler_id;
        test_tool_action_call(hf, "mcp.burp_crawler_manage.stop", "burp_crawler_manage", "stop", args, passed, failed, skipped);
    }
    void test_tool_burp_crawler_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_crawler_manage.list", "burp_crawler_manage", "list", {}, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string target = burp_fixture_url(hf, "mcp.burp_content_discovery_manage.start", "/FUZZ");
        mcp_standalone::json args; args["target_url"] = target; args["wordlist_file"] = g_burp_fixture_wordlist_path; args["concurrency"] = 1; args["request_timeout_ms"] = 1500; args["auto_calibrate"] = false; args["match_status"] = mcp_standalone::json::array({200});
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_content_discovery_manage.start", "burp_content_discovery_manage", "start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "disc_id", g_burp_content_discovery_id);
    }
    void test_tool_burp_content_discovery_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 40 && g_burp_content_discovery_id != 0; ++i) {
            auto st = aida::burp::content_discovery::status(g_burp_content_discovery_id);
            log_msg(hf, "mcp.burp_content_discovery_manage.status", "WAIT -- disc_id=%llu poll=%d phase=%d attempts=%d total=%d hits=%d errors=%d",
                static_cast<unsigned long long>(g_burp_content_discovery_id), i, static_cast<int>(st.phase), st.attempts, st.total, st.hits, st.errors);
            if (st.attempts > 0 || st.hits > 0 || st.errors > 0 || st.phase == aida::burp::content_discovery::disc_phase_t::complete || st.phase == aida::burp::content_discovery::disc_phase_t::error)
                break;
            Sleep(100);
        }
        mcp_standalone::json args; args["disc_id"] = g_burp_content_discovery_id;
        test_tool_action_call(hf, "mcp.burp_content_discovery_manage.status", "burp_content_discovery_manage", "status", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_manage_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 20 && g_burp_content_discovery_id != 0; ++i) {
            auto st = aida::burp::content_discovery::status(g_burp_content_discovery_id);
            log_msg(hf, "mcp.burp_content_discovery_manage.results", "WAIT -- disc_id=%llu poll=%d phase=%d attempts=%d total=%d hits=%d errors=%d",
                static_cast<unsigned long long>(g_burp_content_discovery_id), i, static_cast<int>(st.phase), st.attempts, st.total, st.hits, st.errors);
            if (st.hits > 0 || st.phase == aida::burp::content_discovery::disc_phase_t::complete || st.phase == aida::burp::content_discovery::disc_phase_t::error) break;
            Sleep(100);
        }
        mcp_standalone::json args; args["disc_id"] = g_burp_content_discovery_id;
        test_tool_action_call(hf, "mcp.burp_content_discovery_manage.results", "burp_content_discovery_manage", "results", args, passed, failed, skipped);
    }
    void test_tool_burp_content_discovery_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["disc_id"] = g_burp_content_discovery_id;
        test_tool_action_call(hf, "mcp.burp_content_discovery_manage.stop", "burp_content_discovery_manage", "stop", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string wordlist_path = temp_file_narrow("aida_mcp_subdomain_words.txt");
        write_text_file_narrow(wordlist_path, "@\n");
        mcp_standalone::json args; args["domain"] = "localhost"; args["run_passive"] = false; args["run_brute"] = true; args["brute_wordlist_file"] = wordlist_path; args["concurrency"] = 1; args["request_timeout_ms"] = 1000; args["bypass_dns_cache"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_subdomain_enum_manage.start", "burp_subdomain_enum_manage", "start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "sub_id", g_burp_subdomain_id);
    }
    void test_tool_burp_subdomain_enum_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 40 && g_burp_subdomain_id != 0; ++i) {
            auto st = aida::burp::subdomain_enum::status(g_burp_subdomain_id);
            log_msg(hf, "mcp.burp_subdomain_enum_manage.status", "WAIT -- sub_id=%llu poll=%d phase=%d attempts=%d resolved=%d results=%zu",
                static_cast<unsigned long long>(g_burp_subdomain_id), i, static_cast<int>(st.phase), st.brute_attempts, st.brute_resolved, st.results.size());
            if (st.brute_attempts > 0 || st.brute_resolved > 0 || !st.results.empty() || st.phase == aida::burp::subdomain_enum::enum_phase_t::complete)
                break;
            Sleep(100);
        }
        mcp_standalone::json args; args["sub_id"] = g_burp_subdomain_id;
        test_tool_action_call(hf, "mcp.burp_subdomain_enum_manage.status", "burp_subdomain_enum_manage", "status", args, passed, failed, skipped);
    }
    void test_tool_burp_subdomain_enum_manage_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 20 && g_burp_subdomain_id != 0; ++i) {
            auto st = aida::burp::subdomain_enum::status(g_burp_subdomain_id);
            log_msg(hf, "mcp.burp_subdomain_enum_manage.results", "WAIT -- sub_id=%llu poll=%d phase=%d attempts=%d resolved=%d results=%zu",
                static_cast<unsigned long long>(g_burp_subdomain_id), i, static_cast<int>(st.phase), st.brute_attempts, st.brute_resolved, st.results.size());
            if (!st.results.empty() || st.phase == aida::burp::subdomain_enum::enum_phase_t::complete) break;
            Sleep(100);
        }
        mcp_standalone::json args; args["sub_id"] = g_burp_subdomain_id;
        test_tool_action_call(hf, "mcp.burp_subdomain_enum_manage.results", "burp_subdomain_enum_manage", "results", args, passed, failed, skipped);
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
    void test_tool_burp_intruder_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_burp_http_fixture(hf, "mcp.burp_intruder_manage.start") ||
            !probe_burp_fixture_connect(hf, "mcp.burp_intruder_manage.start")) {
            log_msg(hf, "mcp.burp_intruder_manage.start", "FAIL -- local HTTP fixture was not reachable before starting Intruder job");
            record_fixture_failed_tool("burp_intruder_manage", failed);
            return;
        }
        const uint16_t port = g_burp_http_fixture ? g_burp_http_fixture->port : 1;
        std::string base_request = "GET /?q=test HTTP/1.1\r\nHost: 127.0.0.1:";
        base_request += std::to_string(static_cast<unsigned>(port));
        base_request += "\r\nConnection: close\r\n\r\n";
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["port"] = port; args["scheme"] = "http"; args["base_request"] = base_request; args["positions"] = mcp_standalone::json::array({mcp_standalone::json::array({8, 4})}); args["payload_sets"] = mcp_standalone::json::array({mcp_standalone::json::array({"aida"})}); args["total_cap"] = 1; args["concurrency"] = 1; args["timeout_ms"] = 1500;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_intruder_manage.start", "burp_intruder_manage", "start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "job_id", g_burp_intruder_job_id);
    }
    void test_tool_burp_intruder_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_action_call(hf, "mcp.burp_intruder_manage.status", "burp_intruder_manage", "status", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_manage_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 20 && g_burp_intruder_job_id != 0; ++i) {
            auto st = aida::burp::intruder::status(g_burp_intruder_job_id);
            log_msg(hf, "mcp.burp_intruder_manage.results", "WAIT -- job_id=%llu poll=%d total=%zu sent=%zu errors=%zu running=%d",
                static_cast<unsigned long long>(g_burp_intruder_job_id), i, st.total, st.sent, st.errors, st.running ? 1 : 0);
            if ((st.sent > 0 && !st.running) || st.errors > 0) break;
            Sleep(100);
        }
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_action_call(hf, "mcp.burp_intruder_manage.results", "burp_intruder_manage", "results", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_action_call(hf, "mcp.burp_intruder_manage.stop", "burp_intruder_manage", "stop", args, passed, failed, skipped);
    }
    void test_tool_burp_intruder_manage_list_jobs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_intruder_manage.list_jobs", "burp_intruder_manage", "list_jobs", {}, passed, failed, skipped);
    }
    void test_tool_burp_intruder_manage_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["job_id"] = g_burp_intruder_job_id;
        test_tool_action_call(hf, "mcp.burp_intruder_manage.clear", "burp_intruder_manage", "clear", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["target_url"] = burp_fixture_url(hf, "mcp.burp_param_miner_manage.start"); args["custom_words"] = mcp_standalone::json::array({"aida_mcp_param"}); args["baseline_count"] = 1; args["concurrency"] = 1; args["timeout_ms"] = 1500;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_param_miner_manage.start", "burp_param_miner_manage", "start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "job_id", g_burp_param_miner_job_id);
    }
    void test_tool_burp_param_miner_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 40 && g_burp_param_miner_job_id != 0; ++i) {
            auto st = aida::burp::param_miner::status(g_burp_param_miner_job_id);
            log_msg(hf, "mcp.burp_param_miner_manage.status", "WAIT -- job_id=%llu poll=%d total=%zu tried=%zu hits=%zu running=%d",
                static_cast<unsigned long long>(g_burp_param_miner_job_id), i, st.total, st.tried, st.hits, st.running ? 1 : 0);
            if (st.tried > 0 || st.hits > 0 || !st.running)
                break;
            Sleep(100);
        }
        mcp_standalone::json args; args["id"] = g_burp_param_miner_job_id;
        test_tool_action_call(hf, "mcp.burp_param_miner_manage.status", "burp_param_miner_manage", "status", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_manage_results(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        for (int i = 0; i < 20 && g_burp_param_miner_job_id != 0; ++i) {
            auto st = aida::burp::param_miner::status(g_burp_param_miner_job_id);
            log_msg(hf, "mcp.burp_param_miner_manage.results", "WAIT -- job_id=%llu poll=%d total=%zu tried=%zu hits=%zu running=%d",
                static_cast<unsigned long long>(g_burp_param_miner_job_id), i, st.total, st.tried, st.hits, st.running ? 1 : 0);
            if ((st.tried > 0 && !st.running) || st.hits > 0) break;
            Sleep(100);
        }
        mcp_standalone::json args; args["id"] = g_burp_param_miner_job_id;
        test_tool_action_call(hf, "mcp.burp_param_miner_manage.results", "burp_param_miner_manage", "results", args, passed, failed, skipped);
    }
    void test_tool_burp_param_miner_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_param_miner_job_id;
        test_tool_action_call(hf, "mcp.burp_param_miner_manage.stop", "burp_param_miner_manage", "stop", args, passed, failed, skipped);
    }
    void test_tool_burp_h2_send(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["host"] = "127.0.0.1"; args["port"] = 443; args["timeout_ms"] = 1500; args["offline_validate"] = true;
        args["pseudo_headers"] = mcp_standalone::json::object({{"method", "GET"}, {"scheme", "https"}, {"path", "/aida-h2-fixture"}, {"authority", "127.0.0.1"}});
        test_tool_call(hf, "mcp.burp_h2_send", get_server(), "burp_h2_send", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_manage_decode(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_action_call(hf, "mcp.burp_jwt_manage.decode", "burp_jwt_manage", "decode", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_manage_forge(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["header"] = mcp_standalone::json::object({{"typ", "JWT"}}); args["payload"] = mcp_standalone::json::object({{"sub", "test"}}); args["alg"] = "HS256"; args["hmac_secret"] = "test";
        test_tool_action_call(hf, "mcp.burp_jwt_manage.forge", "burp_jwt_manage", "forge", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_manage_verify(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.Gmlw_dPyBS-autswceWkocF9ELiEHKeS86-MHgG8MhY"; args["key"] = "test"; args["mode"] = "hmac";
        test_tool_action_call(hf, "mcp.burp_jwt_manage.verify", "burp_jwt_manage", "verify", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_manage_crack_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.Gmlw_dPyBS-autswceWkocF9ELiEHKeS86-MHgG8MhY";
        args["custom_words"] = mcp_standalone::json::array({"test", "secret"}); args["concurrency"] = 1; args["max_attempts"] = 2;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_jwt_manage.crack_start", "burp_jwt_manage", "crack_start", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "crack_id", g_burp_jwt_crack_id);
    }
    void test_tool_burp_jwt_manage_crack_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crack_id"] = g_burp_jwt_crack_id;
        test_tool_action_call(hf, "mcp.burp_jwt_manage.crack_status", "burp_jwt_manage", "crack_status", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_manage_crack_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["crack_id"] = g_burp_jwt_crack_id;
        test_tool_action_call(hf, "mcp.burp_jwt_manage.crack_stop", "burp_jwt_manage", "crack_stop", args, passed, failed, skipped);
    }
    void test_tool_burp_jwt_manage_attack(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["token"] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.test";
        test_tool_action_call(hf, "mcp.burp_jwt_manage.attack", "burp_jwt_manage", "attack", args, passed, failed, skipped);
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
    void test_tool_burp_match_replace_manage_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["label"] = "aida_mcp_match_replace"; args["target"] = "request_body"; args["match_regex"] = "test"; args["replacement"] = "test_replace"; args["regex"] = false;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_match_replace_manage.add", "burp_match_replace_manage", "add", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "rule_id", g_burp_match_replace_rule_id);
    }
    void test_tool_burp_match_replace_manage_update(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_match_replace_rule_id; args["fields"] = mcp_standalone::json::object({{"replacement", "test_replace2"}});
        test_tool_action_call(hf, "mcp.burp_match_replace_manage.update", "burp_match_replace_manage", "update", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_match_replace_rule_id;
        test_tool_action_call(hf, "mcp.burp_match_replace_manage.remove", "burp_match_replace_manage", "remove", args, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_match_replace_manage.list", "burp_match_replace_manage", "list", {}, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_manage_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_match_replace_manage.clear", "burp_match_replace_manage", "clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_match_replace_manage_test(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_match_replace_rule_id; args["target"] = "request_body"; args["sample_b64"] = "dGVzdCBkYXRh";
        test_tool_action_call(hf, "mcp.burp_match_replace_manage.test", "burp_match_replace_manage", "test", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_manage_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        ensure_burp_http_fixture(hf, "mcp.burp_macro_manage.add");
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
        auto status = test_tool_action_call(hf, "mcp.burp_macro_manage.add", "burp_macro_manage", "add", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "macro_id", g_burp_macro_id);
    }
    void test_tool_burp_macro_manage_run(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["macro_id"] = g_burp_macro_id;
        test_tool_action_call(hf, "mcp.burp_macro_manage.run", "burp_macro_manage", "run", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_macro_manage.list", "burp_macro_manage", "list", {}, passed, failed, skipped);
    }
    void test_tool_burp_macro_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["macro_id"] = g_burp_macro_id;
        test_tool_action_call(hf, "mcp.burp_macro_manage.remove", "burp_macro_manage", "remove", args, passed, failed, skipped);
    }
    void test_tool_burp_macro_manage_update(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["macro_id"] = g_burp_macro_id; args["fields"] = mcp_standalone::json::object({{"name", "aida_mcp_macro_updated"}});
        test_tool_action_call(hf, "mcp.burp_macro_manage.update", "burp_macro_manage", "update", args, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_manage_add(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["name"] = "aida_mcp_session_rule"; args["match"] = "url_regex"; args["pattern"] = ".*"; args["macro_id"] = g_burp_macro_id;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_session_rule_manage.add", "burp_session_rule_manage", "add", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "rule_id", g_burp_session_rule_id);
    }
    void test_tool_burp_session_rule_manage_list(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_session_rule_manage.list", "burp_session_rule_manage", "list", {}, passed, failed, skipped);
    }
    void test_tool_burp_session_rule_manage_remove(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["rule_id"] = g_burp_session_rule_id;
        test_tool_action_call(hf, "mcp.burp_session_rule_manage.remove", "burp_session_rule_manage", "remove", args, passed, failed, skipped);
    }
    void test_tool_burp_api_manage_import(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const std::string source = "text:{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"AiDA MCP Test\",\"version\":\"1.0.0\"},\"servers\":[{\"url\":\"" + burp_fixture_url(hf, "mcp.burp_api_manage.import") + "\"}],\"paths\":{\"/ping\":{\"get\":{\"operationId\":\"ping\",\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}";
        mcp_standalone::json args; args["format"] = "openapi_json"; args["source"] = source;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_api_manage.import", "burp_api_manage", "import", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_any_field(result.data, g_burp_api_collection_id, {"id", "collection_id"});
    }
    void test_tool_burp_api_manage_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_api_manage.list_collections", "burp_api_manage", "list_collections", {}, passed, failed, skipped);
    }
    void test_tool_burp_api_manage_get_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id;
        test_tool_action_call(hf, "mcp.burp_api_manage.get_collection", "burp_api_manage", "get_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_api_manage_remove_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id;
        test_tool_action_call(hf, "mcp.burp_api_manage.remove_collection", "burp_api_manage", "remove_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_api_manage_send_request(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id; args["request_id"] = "ping";
        test_tool_action_call(hf, "mcp.burp_api_manage.send_request", "burp_api_manage", "send_request", args, passed, failed, skipped);
    }
    void test_tool_burp_api_manage_audit_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_api_collection_id;
        test_tool_action_call(hf, "mcp.burp_api_manage.audit_collection", "burp_api_manage", "audit_collection", args, passed, failed, skipped);
    }
    void test_tool_burp_graphql_manage_introspect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["endpoint"] = burp_fixture_url(hf, "mcp.burp_graphql_manage.introspect", "/graphql");
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_graphql_manage.introspect", "burp_graphql_manage", "introspect", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            size_t types = 0;
            if (!payload_array_count(result.data, "types", types) || types == 0) {
                log_msg(hf, "mcp.burp_graphql_manage.introspect", "FAIL -- GraphQL schema has no parsed types data=%s",
                    compact_json(result.data, 900).c_str());
                if (passed.load(std::memory_order_acquire) > 0)
                    passed.fetch_sub(1, std::memory_order_acq_rel);
                failed.fetch_add(1, std::memory_order_acq_rel);
                convert_tool_pass_to_fail("burp_graphql_manage");
            }
        }
    }
    void test_tool_burp_graphql_manage_example(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["endpoint"] = burp_fixture_url(hf, "mcp.burp_graphql_manage.example", "/graphql"); args["field_name"] = "viewer"; args["depth"] = 2;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_graphql_manage.example", "burp_graphql_manage", "example", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed &&
            (result.text.find("viewer") == std::string::npos || result.text.find("id") == std::string::npos || result.text.find("name") == std::string::npos)) {
            log_msg(hf, "mcp.burp_graphql_manage.example", "FAIL -- generated query did not use fixture schema text=%s data=%s",
                compact_text(result.text, 900).c_str(),
                compact_json(result.data, 900).c_str());
            if (passed.load(std::memory_order_acquire) > 0)
                passed.fetch_sub(1, std::memory_order_acq_rel);
            failed.fetch_add(1, std::memory_order_acq_rel);
            convert_tool_pass_to_fail("burp_graphql_manage");
        }
    }
    void test_tool_burp_graphql_manage_send(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["endpoint"] = burp_fixture_url(hf, "mcp.burp_graphql_manage.send", "/graphql"); args["query"] = "{ __typename aidaStatus }";
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_graphql_manage.send", "burp_graphql_manage", "send", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed) {
            std::string typename_value;
            std::string status_value;
            const bool has_typename = payload_string_field(result.data, "__typename", typename_value);
            const bool has_status = payload_string_field(result.data, "aidaStatus", status_value);
            if (!has_typename || typename_value != "Query" || !has_status || status_value != "ready") {
                log_msg(hf, "mcp.burp_graphql_manage.send", "FAIL -- GraphQL fixture response mismatch has_typename=%d typename=%s has_status=%d status=%s data=%s",
                    has_typename ? 1 : 0,
                    compact_text(typename_value, 120).c_str(),
                    has_status ? 1 : 0,
                    compact_text(status_value, 120).c_str(),
                    compact_json(result.data, 900).c_str());
                if (passed.load(std::memory_order_acquire) > 0)
                    passed.fetch_sub(1, std::memory_order_acq_rel);
                failed.fetch_add(1, std::memory_order_acq_rel);
                convert_tool_pass_to_fail("burp_graphql_manage");
            }
        }
    }
    void test_tool_burp_ws_manage_connect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (!ensure_burp_http_fixture(hf, "mcp.burp_ws_manage.connect") || !g_burp_http_fixture || g_burp_http_fixture->port == 0) {
            log_msg(hf, "mcp.burp_ws_manage.connect", "FAIL -- websocket fixture listener setup failed");
            record_fixture_failed_tool("burp_ws_manage", failed);
            return;
        }
        mcp_standalone::json args; args["scheme"] = "ws"; args["host"] = "127.0.0.1"; args["port"] = g_burp_http_fixture->port; args["path"] = "/ws";
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_ws_manage.connect", "burp_ws_manage", "connect", args, passed, failed, skipped, false, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_any_field(result.data, g_burp_ws_conn_id, {"conn_id", "id"});
    }
    void test_tool_burp_ws_manage_disconnect(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id;
        test_tool_action_call(hf, "mcp.burp_ws_manage.disconnect", "burp_ws_manage", "disconnect", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_manage_send_text(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id; args["msg"] = "test";
        test_tool_action_call(hf, "mcp.burp_ws_manage.send_text", "burp_ws_manage", "send_text", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_manage_send_binary(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id; args["data_b64"] = "AA==";
        test_tool_action_call(hf, "mcp.burp_ws_manage.send_binary", "burp_ws_manage", "send_binary", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_manage_send_raw(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id; args["opcode"] = 1; args["fin"] = true; args["masked"] = true; args["payload_b64"] = "dGVzdA==";
        test_tool_action_call(hf, "mcp.burp_ws_manage.send_raw", "burp_ws_manage", "send_raw", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_manage_list_connections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_ws_manage.list_connections", "burp_ws_manage", "list_connections", {}, passed, failed, skipped);
    }
    void test_tool_burp_ws_manage_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id;
        test_tool_action_call(hf, "mcp.burp_ws_manage.frames", "burp_ws_manage", "frames", args, passed, failed, skipped);
    }
    void test_tool_burp_ws_manage_clear_frames(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["conn_id"] = g_burp_ws_conn_id;
        test_tool_action_call(hf, "mcp.burp_ws_manage.clear_frames", "burp_ws_manage", "clear_frames", args, passed, failed, skipped);
    }
    void test_tool_burp_logger_manage_query(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_logger_manage.query", "burp_logger_manage", "query", {}, passed, failed, skipped);
    }
    void test_tool_burp_logger_manage_total(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_logger_manage.total", "burp_logger_manage", "total", {}, passed, failed, skipped);
    }
    void test_tool_burp_logger_manage_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_logger_manage.clear", "burp_logger_manage", "clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_logger_manage_export_csv(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["path"] = "C:\\temp\\aida_logger_test.csv";
        test_tool_action_call(hf, "mcp.burp_logger_manage.export_csv", "burp_logger_manage", "export_csv", args, passed, failed, skipped);
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
    void test_tool_burp_upstream_manage_add_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        ensure_burp_http_fixture(hf, "mcp.burp_upstream_manage.add_chain");
        mcp_standalone::json hop = mcp_standalone::json::object({{"type", "http_connect"}, {"host", "127.0.0.1"}, {"port", g_burp_http_fixture ? g_burp_http_fixture->port : 1}});
        mcp_standalone::json args; args["label"] = "aida_mcp_upstream"; args["hops"] = mcp_standalone::json::array({hop});
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_upstream_manage.add_chain", "burp_upstream_manage", "add_chain", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            json_u64_field(result.data, "id", g_burp_upstream_chain_id);
    }
    void test_tool_burp_upstream_manage_remove_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_upstream_chain_id;
        test_tool_action_call(hf, "mcp.burp_upstream_manage.remove_chain", "burp_upstream_manage", "remove_chain", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_manage_list_chains(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_upstream_manage.list_chains", "burp_upstream_manage", "list_chains", {}, passed, failed, skipped);
    }
    void test_tool_burp_upstream_manage_set_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_upstream_chain_id;
        test_tool_action_call(hf, "mcp.burp_upstream_manage.set_active", "burp_upstream_manage", "set_active", args, passed, failed, skipped);
    }
    void test_tool_burp_upstream_manage_get_active(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_upstream_manage.get_active", "burp_upstream_manage", "get_active", {}, passed, failed, skipped);
    }
    void test_tool_burp_upstream_manage_test_chain(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["id"] = g_burp_upstream_chain_id; args["target_host"] = "127.0.0.1"; args["target_port"] = g_burp_http_fixture ? g_burp_http_fixture->port : 1;
        test_tool_action_call(hf, "mcp.burp_upstream_manage.test_chain", "burp_upstream_manage", "test_chain", args, passed, failed, skipped);
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
        (void)skipped;
    }
    bool first_camoufox_request_id(const mcp_standalone::json& value, uint64_t& out) {
        if (value.is_object()) {
            if (json_u64_any_field_allow_zero(value, out, {"id", "request_id", "requestId", "network_id"}))
                return true;
            for (auto it = value.begin(); it != value.end(); ++it) {
                if ((it->is_array() || it->is_object()) && first_camoufox_request_id(*it, out))
                    return true;
            }
        } else if (value.is_array()) {
            for (const auto& item : value) {
                if (first_camoufox_request_id(item, out))
                    return true;
            }
        }
        return false;
    }

    bool first_camoufox_trace_file(const mcp_standalone::json& value, std::string& out) {
        if (value.is_string()) {
            out = value.get<std::string>();
            return !out.empty();
        }
        if (value.is_object()) {
            if (json_string_any_field(value, out, {"file_path", "path", "trace_file", "trace_path", "filename"}))
                return true;
            for (auto it = value.begin(); it != value.end(); ++it) {
                if ((it->is_array() || it->is_object()) && first_camoufox_trace_file(*it, out))
                    return true;
            }
        } else if (value.is_array()) {
            for (const auto& item : value) {
                if (first_camoufox_trace_file(item, out))
                    return true;
            }
        }
        return false;
    }

    void mark_camoufox_reverse_dependency_guarded(HANDLE hf, const char* reason, std::atomic<int>& passed, std::atomic<int>& failed) {
        static const char* dependent_tools[] = {
            "browser_lifecycle", "browser_navigation", "browser_interaction", "browser_inspect",
            "browser_state", "browser_network", "browser_hooks", "browser_instrumentation",
            "get_console_logs", "scripts", "search_code", "compare_env",
            "verify_signer_offline", "analyze_cookie_sources"
        };
        for (const char* tool : dependent_tools) {
            record_camoufox_dependency_guard_pass(hf, "mcp.camoufox_reverse_dynamic", tool, reason ? std::string(reason) : std::string(), passed, failed);
        }
    }

    void mark_camoufox_reverse_bridge_blocked(HANDLE hf, const char* reason, std::atomic<int>& failed) {
        static const char* dependent_tools[] = {
            "browser_lifecycle", "browser_navigation", "browser_interaction", "browser_inspect",
            "browser_state", "browser_network", "browser_hooks", "browser_instrumentation",
            "get_console_logs", "scripts", "search_code", "compare_env",
            "verify_signer_offline", "analyze_cookie_sources"
        };
        const std::string reason_s = reason ? std::string(reason) : std::string();
        for (const char* tool : dependent_tools)
            record_camoufox_bridge_blocked_tool(hf, "mcp.camoufox_reverse_dynamic", tool, reason_s, failed);
    }

    void test_tool_camoufox_reverse_dynamic_tools(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const char* tag = "mcp.camoufox_reverse_dynamic";
        ensure_burp_http_fixture(hf, tag);

        std::string dependency_reason;
        if (!camoufox_dependencies_ready_for_test(hf, tag, dependency_reason)) {
            record_camoufox_dependency_guard_pass(hf, tag, "browser_lifecycle", dependency_reason, passed, failed);
            mark_camoufox_reverse_dependency_guarded(hf, dependency_reason.c_str(), passed, failed);
            test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.close", "browser_lifecycle", "close", {}, passed, failed, skipped);
            return;
        }

        mcp_standalone::json launch_args;
        launch_args["headless"] = false;
        launch_args["launch_timeout_ms"] = k_camoufox_testlab_launch_timeout_ms;
        launch_args["aida_testlab_fast_probe"] = true;
        launch_args["enable_trace"] = false;
        launch_args["window_width"] = 1280;
        launch_args["window_height"] = 900;
        mcp_standalone::tool_result_t launch_result;
        auto launch_status = test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.launch", "browser_lifecycle", "launch",
            launch_args, passed, failed, skipped, false, &launch_result);
        if (launch_status != mcp_tool_call_status_t::passed) {
            std::string reason = launch_result.text.empty()
                ? std::string("browser_lifecycle launch did not pass after Camoufox dependencies were ready")
                : std::string("browser_lifecycle launch did not pass after Camoufox dependencies were ready: ") + launch_result.text;
            log_msg(hf, tag, "FAIL -- Camoufox reverse dynamic sequence blocked because browser_lifecycle launch status=%d reason=%s",
                static_cast<int>(launch_status),
                compact_text(reason, 900).c_str());
            mark_camoufox_reverse_bridge_blocked(hf, reason.c_str(), failed);
            test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.close", "browser_lifecycle", "close", {}, passed, failed, skipped);
            return;
        }
        std::string proof_reason;
        if (!prove_camoufox_live_bridge(hf, tag, "browser_lifecycle", proof_reason)) {
            log_msg(hf, tag, "FAIL -- browser_lifecycle launch returned success but live bridge proof failed: %s",
                proof_reason.empty() ? "<empty>" : compact_text(proof_reason, 900).c_str());
            convert_tool_pass_to_fail("browser_lifecycle");
            if (passed.load(std::memory_order_acquire) > 0)
                passed.fetch_sub(1, std::memory_order_acq_rel);
            failed.fetch_add(1, std::memory_order_acq_rel);
            mark_camoufox_reverse_bridge_blocked(hf, proof_reason.c_str(), failed);
            test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.close", "browser_lifecycle", "close", {}, passed, failed, skipped);
            return;
        }

        const std::string fixture_url = burp_fixture_url(hf, tag, "/?q=AIDA_CAMOUFOX_DYNAMIC");

        test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.list.initial", "browser_lifecycle", "list", {}, passed, failed, skipped);

        const std::string page_suffix = std::to_string(static_cast<unsigned long long>(GetTickCount64()));
        const std::string page_a = "aida_testlab_page_a_" + page_suffix;
        const std::string page_b = "aida_testlab_page_b_" + page_suffix;

        mcp_standalone::json page_a_args;
        page_a_args["page_id"] = page_a;
        page_a_args["make_active"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.new.a", "browser_lifecycle", "new", page_a_args, passed, failed, skipped);

        mcp_standalone::json page_b_args;
        page_b_args["page_id"] = page_b;
        page_b_args["make_active"] = false;
        test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.new.b", "browser_lifecycle", "new", page_b_args, passed, failed, skipped);

        mcp_standalone::json list_pages_after_create;
        mcp_standalone::tool_result_t list_pages_created_result;
        auto list_pages_created_status = test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.list.created", "browser_lifecycle", "list",
            list_pages_after_create, passed, failed, skipped, false, &list_pages_created_result);
        if (list_pages_created_status == mcp_tool_call_status_t::passed) {
            const bool found_a = json_array_contains_string_field(list_pages_created_result.data, "pages", page_a, {"page_id"});
            const bool found_b = json_array_contains_string_field(list_pages_created_result.data, "pages", page_b, {"page_id"});
            if (!found_a || !found_b) {
                log_msg(hf, tag, "FAIL -- browser_lifecycle list did not report both explicit page ids found_a=%d found_b=%d data=%s",
                    found_a ? 1 : 0, found_b ? 1 : 0, compact_json(list_pages_created_result.data, 1200).c_str());
                record_fixture_failed_tool("browser_lifecycle", failed);
            }
        }

        mcp_standalone::json nav_page_a;
        nav_page_a["page_id"] = page_a;
        nav_page_a["url"] = burp_fixture_url(hf, tag, "/?q=AIDA_CAMOUFOX_PAGE_A");
        nav_page_a["wait_until"] = "load";
        nav_page_a["collect_response_chain"] = true;
        nav_page_a["clear_network_capture"] = false;
        nav_page_a["include_title"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_navigation.navigate.page_a", "browser_navigation", "navigate", nav_page_a, passed, failed, skipped);

        mcp_standalone::json nav_page_b;
        nav_page_b["page_id"] = page_b;
        nav_page_b["url"] = burp_fixture_url(hf, tag, "/?q=AIDA_CAMOUFOX_PAGE_B");
        nav_page_b["wait_until"] = "load";
        nav_page_b["collect_response_chain"] = true;
        nav_page_b["clear_network_capture"] = false;
        nav_page_b["include_title"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_navigation.navigate.page_b", "browser_navigation", "navigate", nav_page_b, passed, failed, skipped);

        mcp_standalone::json eval_page_a;
        eval_page_a["page_id"] = page_a;
        eval_page_a["expression"] = "(()=>{document.title='AIDA_PAGE_A';window.__aidaPage='A';return {page:window.__aidaPage,title:document.title,url:location.href};})()";
        eval_page_a["await_promise"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_interaction.evaluate.page_a", "browser_interaction", "evaluate", eval_page_a, passed, failed, skipped);

        mcp_standalone::json eval_page_b;
        eval_page_b["page_id"] = page_b;
        eval_page_b["expression"] = "(()=>{document.title='AIDA_PAGE_B';window.__aidaPage='B';return {page:window.__aidaPage,title:document.title,url:location.href};})()";
        eval_page_b["await_promise"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_interaction.evaluate.page_b", "browser_interaction", "evaluate", eval_page_b, passed, failed, skipped);

        mcp_standalone::json select_page_a;
        select_page_a["page_id"] = page_a;
        test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.select.a", "browser_lifecycle", "select", select_page_a, passed, failed, skipped);

        mcp_standalone::json info_page_a;
        info_page_a["page_id"] = page_a;
        test_tool_action_call(hf, "mcp.camoufox.browser_inspect.info.page_a", "browser_inspect", "info", info_page_a, passed, failed, skipped);

        mcp_standalone::json close_page_b;
        close_page_b["page_id"] = page_b;
        test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.close_page.b", "browser_lifecycle", "close_page", close_page_b, passed, failed, skipped);

        const std::string session_two = "aida_testlab_session_" + page_suffix;
        mcp_standalone::json launch_session_two;
        launch_session_two["session_id"] = session_two;
        launch_session_two["headless"] = false;
        launch_session_two["launch_timeout_ms"] = k_camoufox_testlab_launch_timeout_ms;
        launch_session_two["aida_testlab_fast_probe"] = true;
        launch_session_two["window_width"] = 960;
        launch_session_two["window_height"] = 700;
        mcp_standalone::tool_result_t launch_session_two_result;
        auto launch_session_two_status = test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.launch.session_two", "browser_lifecycle", "launch",
            launch_session_two, passed, failed, skipped, false, &launch_session_two_result);
        if (launch_session_two_status == mcp_tool_call_status_t::passed) {
            const std::string page_c = "aida_testlab_page_c_" + page_suffix;
            mcp_standalone::json page_c_args;
            page_c_args["session_id"] = session_two;
            page_c_args["page_id"] = page_c;
            page_c_args["make_active"] = true;
            test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.new.session_two", "browser_lifecycle", "new", page_c_args, passed, failed, skipped);

            mcp_standalone::json nav_page_c;
            nav_page_c["session_id"] = session_two;
            nav_page_c["page_id"] = page_c;
            nav_page_c["url"] = burp_fixture_url(hf, tag, "/?q=AIDA_CAMOUFOX_SESSION_TWO");
            nav_page_c["wait_until"] = "load";
            test_tool_action_call(hf, "mcp.camoufox.browser_navigation.navigate.session_two", "browser_navigation", "navigate", nav_page_c, passed, failed, skipped);

            mcp_standalone::json eval_page_c;
            eval_page_c["session_id"] = session_two;
            eval_page_c["page_id"] = page_c;
            eval_page_c["expression"] = "(()=>({session:'two',title:document.title,url:location.href}))()";
            eval_page_c["await_promise"] = true;
            test_tool_action_call(hf, "mcp.camoufox.browser_interaction.evaluate.session_two", "browser_interaction", "evaluate", eval_page_c, passed, failed, skipped);

            mcp_standalone::json close_session_two;
            close_session_two["session_id"] = session_two;
            test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.close.session_two", "browser_lifecycle", "close", close_session_two, passed, failed, skipped);
        } else {
            for (const char* tool : {"browser_lifecycle", "browser_navigation", "browser_interaction"}) {
                log_msg(hf, "mcp.camoufox_reverse_dynamic", "FAIL -- session_two \"%s\" not executed because browser_lifecycle launch for second session failed: %s",
                    tool, launch_session_two_result.text.c_str());
                record_fixture_failed_tool(tool, failed);
            }
        }

        mcp_standalone::json reset_args;
        reset_args["clear_persistent_hooks"] = true;
        reset_args["clear_network_capture"] = true;
        reset_args["clear_active_routes"] = true;
        reset_args["clear_cookies"] = true;
        reset_args["clear_storage"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_state.reset", "browser_state", "reset", reset_args, passed, failed, skipped);

        mcp_standalone::json init_args;
        init_args["name"] = "aida_testlab_init";
        init_args["script"] = "window.aidaInitScriptRan=(window.aidaInitScriptRan||0)+1;";
        test_tool_action_call(hf, "mcp.camoufox.browser_hooks.init_script", "browser_hooks", "init_script", init_args, passed, failed, skipped);

        mcp_standalone::json capture_start;
        capture_start["payload"] = mcp_standalone::json::object({
            {"action", "start"},
            {"url_pattern", "*"},
            {"capture_body", true}
        });
        test_tool_action_call(hf, "mcp.camoufox.browser_network.capture_start", "browser_network", "capture", capture_start, passed, failed, skipped);

        mcp_standalone::json intercept_args;
        intercept_args["url_pattern"] = "**/aida-fixture.js";
        intercept_args["payload"] = mcp_standalone::json::object({{"action", "log"}});
        test_tool_action_call(hf, "mcp.camoufox.browser_network.intercept", "browser_network", "intercept", intercept_args, passed, failed, skipped);

        mcp_standalone::json nav_args;
        nav_args["url"] = fixture_url;
        nav_args["wait_until"] = "load";
        nav_args["collect_response_chain"] = true;
        nav_args["clear_network_capture"] = false;
        nav_args["include_title"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_navigation.navigate", "browser_navigation", "navigate", nav_args, passed, failed, skipped);

        mcp_standalone::json hook_args;
        hook_args["function_path"] = "window.aidaHookTarget";
        hook_args["mode"] = "trace";
        hook_args["log_args"] = true;
        hook_args["log_return"] = true;
        hook_args["max_captures"] = 8;
        test_tool_action_call(hf, "mcp.camoufox.browser_hooks.hook", "browser_hooks", "hook", hook_args, passed, failed, skipped);

        mcp_standalone::json preset_args;
        preset_args["preset"] = "fetch";
        preset_args["persistent"] = false;
        test_tool_action_call(hf, "mcp.camoufox.browser_hooks.preset", "browser_hooks", "preset", preset_args, passed, failed, skipped);

        mcp_standalone::json eval_args;
        eval_args["expression"] = "(async()=>{console.log('AIDA_CAMOUFOX_CONSOLE');localStorage.setItem('aida_storage','ok');document.cookie='aida_cookie=ok; path=/';let fetch_status=0;try{const r=await fetch('/aida-fixture.js?capture=AIDA_CAMOUFOX_DYNAMIC',{cache:'no-store'});fetch_status=r.status;await r.text();}catch(e){fetch_status=-1;}const hook_value=window.aidaHookTarget?window.aidaHookTarget('x'):'missing';return {hook_value,fetch_status,storage:localStorage.getItem('aida_storage')};})()";
        eval_args["await_promise"] = true;
        test_tool_action_call(hf, "mcp.camoufox.browser_interaction.evaluate", "browser_interaction", "evaluate", eval_args, passed, failed, skipped);

        mcp_standalone::json click_args;
        click_args["selector"] = "body";
        test_tool_action_call(hf, "mcp.camoufox.click", "browser_interaction", "click", click_args, passed, failed, skipped);

        mcp_standalone::json type_args;
        type_args["selector"] = "#aida-input";
        type_args["text"] = "camoufox direct test";
        type_args["delay"] = 1;
        test_tool_action_call(hf, "mcp.camoufox.browser_interaction.type", "browser_interaction", "type", type_args, passed, failed, skipped);

        mcp_standalone::json wait_args;
        wait_args["selector"] = "#aida-input";
        wait_args["timeout"] = 5000;
        test_tool_action_call(hf, "mcp.camoufox.browser_navigation.wait", "browser_navigation", "wait", wait_args, passed, failed, skipped);

        test_tool_action_call(hf, "mcp.camoufox.browser_inspect.info", "browser_inspect", "info", {}, passed, failed, skipped);

        test_tool_action_call(hf, "mcp.camoufox.browser_navigation.navigate.before_reload", "browser_navigation", "navigate", nav_args, passed, failed, skipped);

        mcp_standalone::json reload_args;
        reload_args["wait_until"] = "load";
        test_tool_action_call(hf, "mcp.camoufox.browser_navigation.reload", "browser_navigation", "reload", reload_args, passed, failed, skipped);

        mcp_standalone::json screenshot_args;
        screenshot_args["full_page"] = false;
        test_tool_action_call(hf, "mcp.camoufox.browser_inspect.screenshot", "browser_inspect", "screenshot", screenshot_args, passed, failed, skipped);
        test_tool_action_call(hf, "mcp.camoufox.browser_inspect.snapshot", "browser_inspect", "snapshot", {}, passed, failed, skipped);

        mcp_standalone::json console_args;
        console_args["keyword"] = "AIDA_CAMOUFOX";
        console_args["clear"] = false;
        test_tool_call(hf, "mcp.camoufox.get_console_logs", get_server(), "get_console_logs", console_args, passed, failed, skipped);

        mcp_standalone::json list_req_args;
        list_req_args["url_contains_domain"] = "127.0.0.1";
        mcp_standalone::tool_result_t list_req_result;
        auto list_req_status = test_tool_action_call(hf, "mcp.camoufox.browser_network.list", "browser_network", "list",
            list_req_args, passed, failed, skipped, false, &list_req_result);
        uint64_t request_id = 0;
        bool have_request_id = list_req_status == mcp_tool_call_status_t::passed &&
            first_camoufox_request_id(list_req_result.data, request_id);
        if (!have_request_id) {
            log_msg(hf, tag, "WARN -- browser_network list did not expose an id; forcing fixture fetch and retrying capture list");
            mcp_standalone::json recapture_eval_args;
            recapture_eval_args["expression"] = "(async()=>{const r=await fetch('/aida-fixture.js?capture=AIDA_CAMOUFOX_DYNAMIC_RETRY',{cache:'no-store'});await r.text();return {status:r.status,url:r.url};})()";
            recapture_eval_args["await_promise"] = true;
            test_tool_action_call(hf, "mcp.camoufox.browser_interaction.evaluate.network_capture_retry", "browser_interaction", "evaluate", recapture_eval_args, passed, failed, skipped);
            list_req_result = {};
            list_req_status = test_tool_action_call(hf, "mcp.camoufox.browser_network.list.retry", "browser_network", "list",
                list_req_args, passed, failed, skipped, false, &list_req_result);
            have_request_id = list_req_status == mcp_tool_call_status_t::passed &&
                first_camoufox_request_id(list_req_result.data, request_id);
        }
        if (!have_request_id || request_id == 0) {
            log_msg(hf, tag, "FAIL -- browser_network list did not expose a usable request id after deterministic fixture fetch payload=%s",
                compact_json(list_req_result.data, 900).c_str());
            record_fixture_failed_tool("browser_network", failed);
            record_fixture_failed_tool("browser_network", failed);
        } else {
            mcp_standalone::json req_detail_args;
            req_detail_args["request_id"] = request_id;
            req_detail_args["include_body"] = true;
            req_detail_args["include_headers"] = true;
            req_detail_args["max_body_size"] = 4096;
            test_tool_action_call(hf, "mcp.camoufox.browser_network.get", "browser_network", "get", req_detail_args, passed, failed, skipped);

            mcp_standalone::json req_init_args;
            req_init_args["request_id"] = request_id;
            test_tool_action_call(hf, "mcp.camoufox.browser_network.initiator", "browser_network", "initiator", req_init_args, passed, failed, skipped);
        }

        mcp_standalone::json scripts_args;
        scripts_args["action"] = "list";
        test_tool_call(hf, "mcp.camoufox.scripts", get_server(), "scripts", scripts_args, passed, failed, skipped);

        mcp_standalone::json search_args;
        search_args["keyword"] = "AIDA_CAMOUFOX_SCRIPT_MARKER";
        search_args["max_results"] = 8;
        search_args["context_chars"] = 80;
        test_tool_call(hf, "mcp.camoufox.search_code", get_server(), "search_code", search_args, passed, failed, skipped);

        mcp_standalone::json cookies_args;
        cookies_args["domain"] = "127.0.0.1";
        cookies_args["payload"] = mcp_standalone::json::object({{"action", "get"}});
        test_tool_action_call(hf, "mcp.camoufox.cookies", "browser_state", "cookies", cookies_args, passed, failed, skipped);

        mcp_standalone::json storage_args;
        storage_args["storage_type"] = "local";
        test_tool_action_call(hf, "mcp.camoufox.browser_state.storage", "browser_state", "storage", storage_args, passed, failed, skipped);

        const std::string state_path = temp_file_narrow("aida_camoufox_state.json");
        mcp_standalone::json export_args;
        export_args["save_path"] = state_path;
        test_tool_action_call(hf, "mcp.camoufox.browser_state.export", "browser_state", "export", export_args, passed, failed, skipped);
        mcp_standalone::json import_args;
        import_args["state_path"] = state_path;
        test_tool_action_call(hf, "mcp.camoufox.browser_state.import", "browser_state", "import", import_args, passed, failed, skipped);

        mcp_standalone::json jsvmp_args;
        jsvmp_args["persistent"] = false;
        jsvmp_args["mode"] = "proxy";
        jsvmp_args["track_calls"] = true;
        jsvmp_args["track_props"] = true;
        jsvmp_args["max_entries"] = 32;
        test_tool_action_call(hf, "mcp.camoufox.browser_instrumentation.jsvmp", "browser_instrumentation", "jsvmp", jsvmp_args, passed, failed, skipped);

        mcp_standalone::json compare_args;
        compare_args["properties"] = mcp_standalone::json::array({"navigator.userAgent", "navigator.webdriver", "screen.width"});
        test_tool_call(hf, "mcp.camoufox.compare_env", get_server(), "compare_env", compare_args, passed, failed, skipped);

        mcp_standalone::json instr_args;
        instr_args["payload"] = mcp_standalone::json::object({{"action", "status"}});
        test_tool_action_call(hf, "mcp.camoufox.browser_instrumentation.manage", "browser_instrumentation", "manage", instr_args, passed, failed, skipped);

        mcp_standalone::json signer_args;
        signer_args["signer_code"] = "(sample) => ({aida_value: sample && sample.aida_value ? sample.aida_value : 'signed'})";
        signer_args["samples"] = mcp_standalone::json::array({
            mcp_standalone::json::object({
                {"id", "aida_signer_fixture"},
                {"input", mcp_standalone::json::object({{"aida_value", "signed"}})},
                {"expected", mcp_standalone::json::object({{"aida_value", "signed"}})}
            })
        });
        signer_args["compare_params"] = mcp_standalone::json::array({"aida_value"});
        test_tool_call(hf, "mcp.camoufox.verify_signer_offline", get_server(), "verify_signer_offline", signer_args, passed, failed, skipped);

        mcp_standalone::json trace_args;
        trace_args["duration"] = 1;
        trace_args["mode"] = "summary";
        trace_args["limit"] = 64;
        trace_args["collect_values"] = false;
        test_tool_action_call(hf, "mcp.camoufox.browser_instrumentation.trace", "browser_instrumentation", "trace", trace_args, passed, failed, skipped);

        mcp_standalone::json trace_list_args;
        trace_list_args["limit"] = 5;
        mcp_standalone::tool_result_t trace_list_result;
        auto trace_list_status = test_tool_action_call(hf, "mcp.camoufox.browser_instrumentation.list_files", "browser_instrumentation", "list_files",
            trace_list_args, passed, failed, skipped, false, &trace_list_result);
        std::string trace_path;
        if (trace_list_status == mcp_tool_call_status_t::passed)
            first_camoufox_trace_file(trace_list_result.data, trace_path);
        if (trace_path.empty()) {
            trace_path = temp_file_narrow("aida_camoufox_trace_empty.jsonl");
            write_text_file_narrow(trace_path, "{\"object\":\"window\",\"property\":\"navigator\",\"timestamp\":0}\n");
            log_msg(hf, tag, "WARN -- browser_instrumentation list_files did not expose a path; using local trace fixture %s", trace_path.c_str());
        }
        mcp_standalone::json trace_query_args;
        trace_query_args["file_path"] = trace_path;
        trace_query_args["mode"] = "summary";
        trace_query_args["limit"] = 16;
        test_tool_action_call(hf, "mcp.camoufox.browser_instrumentation.query_file", "browser_instrumentation", "query_file", trace_query_args, passed, failed, skipped);

        mcp_standalone::json cookie_source_args;
        cookie_source_args["name_filter"] = "aida_cookie";
        test_tool_call(hf, "mcp.camoufox.analyze_cookie_sources", get_server(), "analyze_cookie_sources", cookie_source_args, passed, failed, skipped);

        mcp_standalone::json capture_stop;
        capture_stop["payload"] = mcp_standalone::json::object({{"action", "stop"}});
        test_tool_action_call(hf, "mcp.camoufox.browser_network.capture_stop", "browser_network", "capture", capture_stop, passed, failed, skipped);

        mcp_standalone::json remove_hooks_args;
        remove_hooks_args["keep_persistent"] = false;
        test_tool_action_call(hf, "mcp.camoufox.browser_hooks.remove", "browser_hooks", "remove", remove_hooks_args, passed, failed, skipped);

        test_tool_action_call(hf, "mcp.camoufox.browser_lifecycle.close", "browser_lifecycle", "close", {}, passed, failed, skipped);
    }
    uint16_t reserve_mcp_loopback_port(HANDLE hf, const char* tag) {
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, tag, "WARN -- WSAStartup failed while reserving port");
            return 0;
        }
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            log_msg(hf, tag, "WARN -- socket failed while reserving port wsa=%d", WSAGetLastError());
            return 0;
        }
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        uint16_t port = 0;
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR) {
            sockaddr_in bound = {};
            int len = sizeof(bound);
            if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &len) != SOCKET_ERROR)
                port = ntohs(bound.sin_port);
        }
        int err = WSAGetLastError();
        closesocket(s);
        log_msg(hf, tag, "INFO -- reserved loopback port=%u err=%d", static_cast<unsigned>(port), err);
        return port;
    }

    bool collaborator_http_probe(HANDLE hf, const std::string& token) {
        if (token.empty())
            return false;
        if (!ensure_mcp_winsock_ready()) {
            log_msg(hf, "mcp.burp_collaborator_probe", "WARN -- WSAStartup failed");
            return false;
        }
        auto cfg = aida::burp::collaborator::current_config();
        if (cfg.http_port == 0) {
            log_msg(hf, "mcp.burp_collaborator_probe", "WARN -- collaborator http_port=0");
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
        addr.sin_port = htons(cfg.http_port);
        bool ok = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != SOCKET_ERROR;
        int received = 0;
        if (ok) {
            std::string req = "GET /" + token + " HTTP/1.1\r\nHost: " + token + "." + cfg.public_host + "\r\nConnection: close\r\n\r\n";
            ok = send(s, req.data(), static_cast<int>(req.size()), 0) != SOCKET_ERROR;
            char buf[256];
            received = recv(s, buf, sizeof(buf), 0);
        }
        closesocket(s);
        if (ok)
            Sleep(100);
        log_msg(hf, "mcp.burp_collaborator_probe", "%s -- token_len=%zu port=%u recv=%d", ok ? "PASS" : "WARN", token.size(), static_cast<unsigned>(cfg.http_port), received);
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
    void test_tool_burp_collaborator_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_collaborator_manage.status", "burp_collaborator_manage", "status", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_manage_start(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        args["bind_ip"] = "127.0.0.1";
        uint16_t http_port = reserve_mcp_loopback_port(hf, "mcp.burp_collaborator_manage.start");
        if (http_port == 0) http_port = 28444;
        args["http_port"] = http_port;
        args["enable_http"] = true;
        args["enable_dns"] = false;
        args["enable_smtp"] = false;
        args["dns_port"] = 0;
        args["smtp_port"] = 0;
        args["public_host"] = "aidacollab.local";
        args["public_ip"] = "127.0.0.1";
        args["canned_body"] = "aida collaborator fixture";
        test_tool_action_call(hf, "mcp.burp_collaborator_manage.start", "burp_collaborator_manage", "start", args, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_collaborator_manage.stop", "burp_collaborator_manage", "stop", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_manage_generate_token(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_collaborator_manage.generate_token", "burp_collaborator_manage", "generate_token", {}, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed && result.data.is_object() && result.data.contains("token") && result.data["token"].is_string()) {
            g_burp_collaborator_token = result.data["token"].get<std::string>();
            collaborator_http_probe(hf, g_burp_collaborator_token);
        }
    }
    void test_tool_burp_collaborator_manage_poll(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args;
        if (!g_burp_collaborator_token.empty())
            args["token"] = g_burp_collaborator_token;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_collaborator_manage.poll", "burp_collaborator_manage", "poll", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed)
            capture_collaborator_interaction_id(result);
    }
    void test_tool_burp_collaborator_manage_get_interaction(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        if (g_burp_collaborator_interaction_id == 0 && !g_burp_collaborator_token.empty()) {
            collaborator_http_probe(hf, g_burp_collaborator_token);
            mcp_standalone::json poll_args;
            poll_args["token"] = g_burp_collaborator_token;
            mcp_standalone::tool_result_t poll_result;
            auto poll_status = test_tool_action_call(hf, "mcp.burp_collaborator_manage.poll", "burp_collaborator_manage", "poll", poll_args, passed, failed, skipped, true, &poll_result);
            if (poll_status == mcp_tool_call_status_t::passed)
                capture_collaborator_interaction_id(poll_result);
        }
        mcp_standalone::json args; args["id"] = g_burp_collaborator_interaction_id;
        test_tool_action_call(hf, "mcp.burp_collaborator_manage.get_interaction", "burp_collaborator_manage", "get_interaction", args, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_manage_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_collaborator_manage.clear", "burp_collaborator_manage", "clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_collaborator_manage_list_tokens(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_collaborator_manage.list_tokens", "burp_collaborator_manage", "list_tokens", {}, passed, failed, skipped);
    }
    bool wait_for_burp_sequencer_samples(HANDLE hf, const char* tag, uint64_t collection_id, uint64_t target_count) {
        if (collection_id == 0 || target_count == 0)
            return false;
        mcp_standalone::json args;
        args["collection_id"] = collection_id;
        const uint64_t deadline = GetTickCount64() + 15000;
        while (GetTickCount64() < deadline) {
            auto timed = invoke_tool_action_bounded(get_server(), "burp_sequencer_manage", "status", args, tool_timeout_ms("burp_sequencer_manage"));
            uint64_t collected = 0;
            bool running = false;
            bool error = false;
            std::string err;
            payload_u64_field(timed.result.data, "collected", collected);
            payload_bool_field(timed.result.data, "running", running);
            payload_bool_field(timed.result.data, "error", error);
            payload_string_field(timed.result.data, "error_message", err);
            log_msg(hf, tag, "sequencer wait collection=%llu collected=%llu target=%llu running=%d error=%d timed_out=%d success=%d err=%s",
                static_cast<unsigned long long>(collection_id),
                static_cast<unsigned long long>(collected),
                static_cast<unsigned long long>(target_count),
                running ? 1 : 0,
                error ? 1 : 0,
                timed.timed_out ? 1 : 0,
                timed.result.success ? 1 : 0,
                err.c_str());
            if (timed.result.success && collected >= target_count)
                return true;
            if (timed.result.success && !running && error && !err.empty())
                return false;
            Sleep(100);
        }
        return false;
    }
    void test_tool_burp_sequencer_manage_start_collection(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        const uint64_t target_count = 4;
        mcp_standalone::json args; args["url"] = burp_fixture_url(hf, "mcp.burp_sequencer_manage.start_collection", "/?q=AIDASEQ1234"); args["extract_regex"] = "(AIDASEQ[0-9]{4})"; args["capture_group"] = 1; args["target_count"] = target_count; args["concurrency"] = 1; args["throttle_ms"] = 1;
        mcp_standalone::tool_result_t result;
        auto status = test_tool_action_call(hf, "mcp.burp_sequencer_manage.start_collection", "burp_sequencer_manage", "start_collection", args, passed, failed, skipped, true, &result);
        if (status == mcp_tool_call_status_t::passed) {
            json_u64_field(result.data, "collection_id", g_burp_sequencer_collection_id);
            g_burp_sequencer_target_count = target_count;
            wait_for_burp_sequencer_samples(hf, "mcp.burp_sequencer_manage.start_collection", g_burp_sequencer_collection_id, g_burp_sequencer_target_count);
        }
    }
    void test_tool_burp_sequencer_manage_status(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        wait_for_burp_sequencer_samples(hf, "mcp.burp_sequencer_manage.status", g_burp_sequencer_collection_id, g_burp_sequencer_target_count);
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_action_call(hf, "mcp.burp_sequencer_manage.status", "burp_sequencer_manage", "status", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_manage_stop(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_action_call(hf, "mcp.burp_sequencer_manage.stop", "burp_sequencer_manage", "stop", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_manage_samples(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        wait_for_burp_sequencer_samples(hf, "mcp.burp_sequencer_manage.samples", g_burp_sequencer_collection_id, g_burp_sequencer_target_count);
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_action_call(hf, "mcp.burp_sequencer_manage.samples", "burp_sequencer_manage", "samples", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_manage_analyze(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        wait_for_burp_sequencer_samples(hf, "mcp.burp_sequencer_manage.analyze", g_burp_sequencer_collection_id, g_burp_sequencer_target_count);
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_action_call(hf, "mcp.burp_sequencer_manage.analyze", "burp_sequencer_manage", "analyze", args, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_manage_list_collections(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_sequencer_manage.list_collections", "burp_sequencer_manage", "list_collections", {}, passed, failed, skipped);
    }
    void test_tool_burp_sequencer_manage_delete(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["collection_id"] = g_burp_sequencer_collection_id;
        test_tool_action_call(hf, "mcp.burp_sequencer_manage.delete", "burp_sequencer_manage", "delete", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_manage_add_slot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["label"] = "aida_mcp_test_a"; args["data_text"] = "test data\nalpha\n";
        mcp_standalone::tool_result_t result_a;
        auto status_a = test_tool_action_call(hf, "mcp.burp_comparer_manage.add_slot", "burp_comparer_manage", "add_slot", args, passed, failed, skipped, true, &result_a);
        if (status_a == mcp_tool_call_status_t::passed) {
            if (!json_u64_field(result_a.data, "slot_id", g_burp_comparer_slot_a))
                json_u64_field(result_a.data, "id", g_burp_comparer_slot_a);
        }
        args["label"] = "aida_mcp_test_b"; args["data_text"] = "test data\nbeta\n";
        mcp_standalone::tool_result_t result_b;
        auto status_b = test_tool_action_call(hf, "mcp.burp_comparer_manage.add_slot", "burp_comparer_manage", "add_slot", args, passed, failed, skipped, true, &result_b);
        if (status_b == mcp_tool_call_status_t::passed) {
            if (!json_u64_field(result_b.data, "slot_id", g_burp_comparer_slot_b))
                json_u64_field(result_b.data, "id", g_burp_comparer_slot_b);
        }
    }
    void test_tool_burp_comparer_manage_list_slots(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_comparer_manage.list_slots", "burp_comparer_manage", "list_slots", {}, passed, failed, skipped);
    }
    void test_tool_burp_comparer_manage_remove_slot(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["slot_id"] = g_burp_comparer_slot_a;
        test_tool_action_call(hf, "mcp.burp_comparer_manage.remove_slot", "burp_comparer_manage", "remove_slot", args, passed, failed, skipped);
    }
    void test_tool_burp_comparer_manage_clear(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        test_tool_action_call(hf, "mcp.burp_comparer_manage.clear", "burp_comparer_manage", "clear", {}, passed, failed, skipped);
    }
    void test_tool_burp_comparer_manage_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped) {
        mcp_standalone::json args; args["slot_a"] = g_burp_comparer_slot_a; args["slot_b"] = g_burp_comparer_slot_b;
        test_tool_action_call(hf, "mcp.burp_comparer_manage.diff", "burp_comparer_manage", "diff", args, passed, failed, skipped);
    }

}
void phase_mcp_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& global_skipped, bool(*cancelled)()) {
    log_msg(hf, "mcp_phase", "=== MCP TOOL TESTS START (AI/agent tools excluded from counters) ===");
    auto t0 = std::chrono::steady_clock::now();
    const int start_passed = passed.load(std::memory_order_acquire);
    const int start_failed = failed.load(std::memory_order_acquire);
    const int start_skipped = global_skipped.load(std::memory_order_acquire);
    std::atomic<int> skipped{0};

    g_invoked_tools.clear();
    g_tool_attempt_stats.clear();
    {
        std::lock_guard<std::mutex> lk(g_timed_out_invocations_mtx);
        g_timed_out_invocations.clear();
    }
    g_mcp_tool_sequence.store(0, std::memory_order_release);
    g_mcp_target_pid = driver_bridge::attached_pid();
    g_mcp_target_unavailable = (g_mcp_target_pid == 0);
    g_mcp_dbg_sw_addr = 0;
    g_mcp_debugger_bp_index = -1;
    g_mcp_deferred_action_id = 0;
    g_mcp_emulation_addr = 0;
    g_mcp_fuzz_addr = 0;
    g_mcp_fuzz_input_addr = 0;
    g_mcp_scanner_addr = 0;
    g_mcp_scanner_pointer_addr = 0;
    g_mcp_symbolic_deobf_addr = 0;
    g_mcp_debugger_trace_id.clear();
    g_mcp_patch_addr = 0;
    g_mcp_patch_index = -1;
    g_mcp_get_patches_fixture_index = -1;
    g_autoresponder_rule_id = 0;
    g_mcp_deferred_action_resource_guarded = false;
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
    g_burp_sequencer_target_count = 0;
    g_burp_comparer_slot_a = 0;
    g_burp_comparer_slot_b = 0;
    g_burp_collaborator_interaction_id = 0;
    g_burp_dom_xss_browser_infra_failed = false;
    g_burp_dom_xss_dependency_reason.clear();
    g_burp_collaborator_token.clear();
    g_burp_fixture_base_url.clear();
    g_burp_fixture_wordlist_path.clear();
    g_burp_http_fixture.reset();
    g_mcp_camoufox_bridge_ready_proven = false;
    g_mcp_camoufox_bridge_generation = 0;
    g_mcp_camoufox_bridge_block_reason.clear();
    log_msg(hf, "mcp_phase", "target snapshot active_pid=%u target_unavailable=%d attached_pid=%u driver_bridge_status=\"%s\" driver_last_error=\"%s\" host_pid=%lu host_tid=%lu",
        g_mcp_target_pid,
        g_mcp_target_unavailable ? 1 : 0,
        driver_bridge::attached_pid(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str(),
        static_cast<unsigned long>(GetCurrentProcessId()),
        static_cast<unsigned long>(GetCurrentThreadId()));

    if (!cancelled()) test_mcp_server_accessible(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_server_running(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_tool_count(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_enumerate_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_categorize_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_tool_schemas(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_duplicate_tool_names(hf, passed, failed, skipped);
    if (!cancelled()) test_mcp_jsonrpc_smoke(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_get_tool_descriptions(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_list_processes(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_processes_filter(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_string(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_query_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disassemble_zydis(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_disassemble_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sandbox_execute(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_convert_number_decimal(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_convert_number_hex(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_convert_number_binary(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_write_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_edit_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_delete_file(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_create_directory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_directory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_search_files(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_grep_in_files(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_web_search(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_webfetch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_dump_module(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_pointer_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_kernel_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_allocate_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_free_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_call_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_protect_memory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_peb(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_set_hw_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_clear_hw_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_resolve_export(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_virtual_to_physical(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_defer_action(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_list_deferred_actions(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_cancel_deferred_action(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_get_deferred_results(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_network_state(hf, "before MCP driver network tools");
    if (!cancelled()) test_tool_driver_sniff_network_buffers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_reassemble_stream(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_network_state(hf, "after MCP driver network tools");
    if (!cancelled()) test_tool_driver_enum_kernel_callbacks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_integrity_checks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_ssdt_hooks(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enum_minifilters(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_etw_monitors(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_detect_hidden_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_walk_heap(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_handles(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_enumerate_windows(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_assemble(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_find_references(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_read_teb(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_map_peb_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_driver_set_page_guard(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_dbg_snapshot_state(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_compare_snapshots(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_detect_vm_handler(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_map_vm_handlers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_run_to_address(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_attached(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_registers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_breakpoints(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_memory_map(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_callstack(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_handles(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_seh_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_patches(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_set_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_remove_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_step_over(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_step_into(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_step_out(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_continue(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_pause(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_set_register(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_start_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_debugger_get_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_add_watch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_watches(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_remove_watch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_start_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_stop_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_get_trace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_set_comment(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_set_label(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_toggle_bookmark(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_find_strings(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_dbg_get_modules_detail(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_add_patch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_remove_patch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_nop_fill(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_find_code_caves(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dbg_conditional_breakpoint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_first_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_next_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_get_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_undo(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_address_list_manage_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_address_list_manage_freeze(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_address_list_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_address_list_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_read_value(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_write_value(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_pointer_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_cancel_pointer_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_struct_manage_define(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_struct_manage_add_field(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_struct_manage_get(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scanner_struct_manage_export_c(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_find_what_accesses(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_watch_memory_layout(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_assert_memory_type(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_scan_crypto_constants(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_generate_aob_signature(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_reconstruct_struct(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_fuzzer_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_fuzzer_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_fuzzer_manage_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_auto_decrypt_strings(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_hunt_integrity_checkers(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_neutralize_integrity_node(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_live_monitor_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_live_monitor_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_symbolic_execution_deobfuscate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_symbolic_execution_slice_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_symbolic_execution_solve_path(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_taint_trace_register(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_decompile_function(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_imports(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_exports(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_types(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_type_definition(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_pdb_symbols(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_binary_map_overview(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analysis_query_xref_db_stats(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_sessions_manage_open_file(hf, passed, failed, skipped);
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

    if (!cancelled()) test_tool_sessions_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_manage_get_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_manage_attach_pid(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_manage_close(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_sessions_manage_run_binary(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_apply_diff(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_apply_patch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_codebase_search(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_read_command_output(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_search_workspace(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_run_command(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cancel_command(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_list_commands(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_driver_snapshot_and_emulate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_trace_execution_unicorn(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_analyze_vm_handler(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_emulate_multi_trace(hf, passed, failed, skipped);

    if (!cancelled()) cleanup_mcp_network_state(hf, "before MCP network tools");
    if (!cancelled()) test_tool_api_monitor_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_api_monitor_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_enumerate_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_capture_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_capture_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_capture_manage_get_packets(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_analyze_packet(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_dns_log(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_filter_manage_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_filter_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_filter_manage_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_bandwidth_manage_stats(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_capture_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_firewall_manage_block_ip(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_firewall_manage_block_port(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_firewall_manage_block_process(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_network_firewall_manage_kill_connection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_spoof_dns(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_list_dns_spoof_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_bandwidth_manage_monitor(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_bandwidth_manage_per_process(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_os_fingerprint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_capture_manage_export_pcap(hf, passed, failed, skipped);
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
    if (!cancelled()) cleanup_mcp_network_state(hf, "after MCP network tools");

    if (!cancelled()) test_tool_tls_manage_extract_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_manage_start_keylog(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_manage_stop_keylog(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_tls_manage_get_extracted_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_manage_inject(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) cleanup_mcp_cert_fixture(hf, "mcp.cert_cleanup");
    if (!cancelled()) test_tool_cert_manage_generate_ca(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_cert_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_pin_bypass(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_firefox_profile_launch(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_quic_manage_detect_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_quic_manage_decrypt_initial(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_quic_manage_extract_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dtls_manage_detect_sessions(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_dtls_manage_extract_keys(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_add_rule(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_list_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_remove_rule(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_import_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_autoresponder_manage_export_rules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_network_decrypt_capture(hf, passed, failed, skipped);

    if (!cancelled()) test_tool_burp_scanner_manage_start_audit(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_manage_audit_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_manage_list_audits(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_manage_cancel(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_manage_list_issues(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_manage_get_issue(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_passive_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_list_modules(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_manage_clear_issues(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scanner_passive_enable(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_list_hosts(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_list_paths(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_get_exchange(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sitemap_send_to(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_manage_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_scope_manage_check(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_manage_set(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_manage_delete(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_cookie_manage_export_netscape(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_dom_xss_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_dom_xss_test_payload(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_dom_xss_scan(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_crawler_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_manage_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_content_discovery_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_subdomain_enum_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_subdomain_enum_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_subdomain_enum_manage_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_get(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_search(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_payloads_add_custom(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_manage_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_manage_list_jobs(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_intruder_manage_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_manage_results(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_param_miner_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_h2_send(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_decode(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_forge(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_verify(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_crack_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_crack_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_crack_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_jwt_manage_attack(hf, passed, failed, skipped);
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
    if (!cancelled()) test_tool_burp_match_replace_manage_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_manage_update(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_manage_test(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_match_replace_manage_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_manage_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_manage_run(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_manage_update(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_manage_add(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_manage_list(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_session_rule_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_macro_manage_remove(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_manage_import(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_manage_list_collections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_manage_get_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_manage_send_request(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_manage_audit_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_api_manage_remove_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_manage_introspect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_manage_example(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_graphql_manage_send(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_connect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_send_text(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_send_binary(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_send_raw(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_list_connections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_frames(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_clear_frames(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_ws_manage_disconnect(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_manage_query(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_manage_total(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_manage_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_logger_manage_export_csv(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_report_generate(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_bambda_compile(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_bambda_test(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_bambda_help(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_csp_analyze(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_csp_analyze_url(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_manage_add_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_manage_list_chains(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_manage_set_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_manage_get_active(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_manage_test_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_upstream_manage_remove_chain(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_fingerprint(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_inventory(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_tech_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_camoufox_reverse_dynamic_tools(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_start(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_generate_token(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_poll(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_get_interaction(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_list_tokens(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_clear(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_collaborator_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_start_collection(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_status(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_samples(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_analyze(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_list_collections(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_stop(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_sequencer_manage_delete(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_manage_add_slot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_manage_list_slots(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_manage_diff(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_manage_remove_slot(hf, passed, failed, skipped);
    if (!cancelled()) test_tool_burp_comparer_manage_clear(hf, passed, failed, skipped);
    if (!cancelled()) {
        set_progress_step("mcp finalization: network cleanup before coverage audit");
        cleanup_mcp_network_state(hf, "before MCP coverage audit");
    }
    if (!cancelled()) {
        const auto cq_before_coverage = critical_work_queue::stats();
        set_progress_step("mcp finalization: coverage audit");
        log_msg(hf, "mcp.cleanup", "coverage_audit_begin cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
            cq_before_coverage.pending,
            static_cast<unsigned>(cq_before_coverage.active),
            static_cast<unsigned long long>(cq_before_coverage.started),
            static_cast<unsigned long long>(cq_before_coverage.finished));
        test_mcp_coverage_audit(hf, passed, failed, skipped);
        const auto cq_after_coverage = critical_work_queue::stats();
        log_msg(hf, "mcp.cleanup", "coverage_audit_end cq_pending=%zu cq_active=%u cq_started=%llu cq_finished=%llu",
            cq_after_coverage.pending,
            static_cast<unsigned>(cq_after_coverage.active),
            static_cast<unsigned long long>(cq_after_coverage.started),
            static_cast<unsigned long long>(cq_after_coverage.finished));
    }

    set_progress_step("mcp finalization: outstanding worker drain");
    wait_timed_out_invocation_drain(hf, "after coverage audit", 5000);

    set_progress_step("mcp finalization: fixture cleanup");
    log_msg(hf, "mcp.cleanup", "final_cleanup_begin driver_hw_tid=%u driver_hw_addr=0x%016llX dbg_hw_addr=0x%016llX dbg_sw_addr=0x%016llX patch_addr=0x%016llX integrity_addr=0x%016llX emu_addr=0x%016llX fuzz_addr=0x%016llX fuzz_input_addr=0x%016llX scanner_pointer_addr=0x%016llX scanner_addr=0x%016llX fixture_active=%d",
        g_mcp_driver_hw_tid,
        static_cast<unsigned long long>(g_mcp_driver_hw_addr),
        static_cast<unsigned long long>(g_mcp_dbg_hw_addr),
        static_cast<unsigned long long>(g_mcp_dbg_sw_addr),
        static_cast<unsigned long long>(g_mcp_patch_addr),
        static_cast<unsigned long long>(g_mcp_integrity_addr),
        static_cast<unsigned long long>(g_mcp_emulation_addr),
        static_cast<unsigned long long>(g_mcp_fuzz_addr),
        static_cast<unsigned long long>(g_mcp_fuzz_input_addr),
        static_cast<unsigned long long>(g_mcp_scanner_pointer_addr),
        static_cast<unsigned long long>(g_mcp_scanner_addr),
        g_burp_http_fixture ? 1 : 0);

    auto release_remote_addr = [&](const char* label, uint64_t& slot) {
        if (slot == 0)
            return;
        const uint64_t addr = slot;
        slot = 0;
        log_msg(hf, "mcp.cleanup", "%s_schedule addr=0x%016llX",
            label ? label : "remote_free",
            static_cast<unsigned long long>(addr));
        const bool ok = bounded_finalizer_call(hf, label, 3000, [addr]() {
            return driver_bridge::free_memory(addr);
        });
        log_msg(hf, "mcp.cleanup", "%s_result addr=0x%016llX completed_ok=%d ownership_released=1",
            label ? label : "remote_free",
            static_cast<unsigned long long>(addr),
            ok ? 1 : 0);
    };

    auto release_debugger_addr = [&](const char* label, uint64_t& slot) {
        if (slot == 0)
            return;
        const uint64_t addr = slot;
        slot = 0;
        log_msg(hf, "mcp.cleanup", "%s_schedule addr=0x%016llX",
            label ? label : "debugger_free",
            static_cast<unsigned long long>(addr));
        const bool ok = bounded_finalizer_call(hf, label, 4000, [addr]() {
            debugger_engine::clear_all_breakpoints();
            return driver_bridge::free_memory(addr);
        });
        log_msg(hf, "mcp.cleanup", "%s_result addr=0x%016llX completed_ok=%d ownership_released=1",
            label ? label : "debugger_free",
            static_cast<unsigned long long>(addr),
            ok ? 1 : 0);
    };

    if (g_mcp_driver_hw_tid != 0) {
        const uint32_t tid = g_mcp_driver_hw_tid;
        g_mcp_driver_hw_tid = 0;
        const bool ok = bounded_finalizer_call(hf, "clear_driver_hw_breakpoint", 3000, [tid]() {
            return driver_bridge::clear_hardware_breakpoint(tid, 0);
        });
        log_msg(hf, "mcp.cleanup", "clear_driver_hw_breakpoint_result tid=%u completed_ok=%d ownership_released=1",
            tid,
            ok ? 1 : 0);
    }
    release_remote_addr("free_driver_hw_addr", g_mcp_driver_hw_addr);
    release_debugger_addr("free_dbg_hw_addr", g_mcp_dbg_hw_addr);
    if (g_mcp_dbg_sw_addr != 0) {
        release_debugger_addr("free_dbg_sw_addr", g_mcp_dbg_sw_addr);
        g_mcp_debugger_bp_index = -1;
    }
    if (g_mcp_get_patches_fixture_index >= 0) {
        const int patch_index = g_mcp_get_patches_fixture_index;
        g_mcp_get_patches_fixture_index = -1;
        const bool ok = bounded_finalizer_call(hf, "remove_get_patches_fixture", 3000, [patch_index]() {
            return code_patcher::remove_patch(patch_index);
        });
        log_msg(hf, "mcp.cleanup", "remove_get_patches_fixture_result index=%d completed_ok=%d",
            patch_index,
            ok ? 1 : 0);
    }
    release_remote_addr("free_patch_addr", g_mcp_patch_addr);
    release_remote_addr("free_integrity_addr", g_mcp_integrity_addr);
    release_remote_addr("free_emulation_addr", g_mcp_emulation_addr);
    if (fuzzer_engine::g_state.running.load() || fuzzer_engine::g_state.worker_active.load()) {
        log_msg(hf, "mcp.cleanup", "waiting for fuzzer idle running=%d worker=%d setup_complete=%d setup_success=%d",
            fuzzer_engine::g_state.running.load() ? 1 : 0,
            fuzzer_engine::g_state.worker_active.load() ? 1 : 0,
            fuzzer_engine::g_state.setup_complete.load() ? 1 : 0,
            fuzzer_engine::g_state.setup_success.load() ? 1 : 0);
        fuzzer_engine::stop_fuzzing();
        const bool idle = fuzzer_engine::wait_until_idle(12000);
        log_msg(hf, "mcp.cleanup", "fuzzer_idle=%d", idle ? 1 : 0);
        if (!idle)
            log_msg(hf, "mcp.cleanup", "skipping fuzz fixture frees because fuzzer worker is still active");
    }
    if (g_mcp_fuzz_addr != 0) {
        if (!fuzzer_engine::g_state.running.load() && !fuzzer_engine::g_state.worker_active.load()) {
            release_remote_addr("free_fuzz_addr", g_mcp_fuzz_addr);
        }
    }
    if (g_mcp_fuzz_input_addr != 0) {
        if (!fuzzer_engine::g_state.running.load() && !fuzzer_engine::g_state.worker_active.load()) {
            release_remote_addr("free_fuzz_input_addr", g_mcp_fuzz_input_addr);
        }
    }
    release_remote_addr("free_scanner_pointer_addr", g_mcp_scanner_pointer_addr);
    release_remote_addr("free_scanner_addr", g_mcp_scanner_addr);
    if (g_burp_http_fixture) {
        auto fixture_owner = std::shared_ptr<mcp_burp_http_fixture_t>(std::move(g_burp_http_fixture));
        const uint16_t fixture_port = fixture_owner ? fixture_owner->port : 0;
        const bool fixture_live = fixture_owner ? fixture_owner->live() : false;
        log_msg(hf, "mcp.cleanup", "fixture_reset_schedule active=1 port=%u live=%d",
            static_cast<unsigned>(fixture_port),
            fixture_live ? 1 : 0);
        const bool ok = bounded_finalizer_call(hf, "burp_http_fixture_reset", 5000, [fixture_owner]() mutable {
            auto owned = fixture_owner;
            fixture_owner.reset();
            owned.reset();
            return true;
        });
        log_msg(hf, "mcp.cleanup", "fixture_reset_result port=%u completed_ok=%d ownership_released=1",
            static_cast<unsigned>(fixture_port),
            ok ? 1 : 0);
    } else {
        log_msg(hf, "mcp.cleanup", "fixture_reset_skip active=0");
    }
    g_burp_fixture_base_url.clear();
    g_burp_fixture_wordlist_path.clear();

    set_progress_step("mcp finalization: accounting");
    const int raw_skip_delta = skipped.load(std::memory_order_acquire);
    if (raw_skip_delta > 0) {
        failed.fetch_add(raw_skip_delta, std::memory_order_acq_rel);
        log_msg(hf, "mcp.phase_accounting", "FAIL -- converted %d non-destructive MCP skipped preconditions into failures so only registered destructive Test Lab guards contribute to global skips", raw_skip_delta);
    }

    auto t1 = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    const int delta_passed = passed.load(std::memory_order_acquire) - start_passed;
    const int delta_failed = failed.load(std::memory_order_acquire) - start_failed;
    const int delta_skipped = global_skipped.load(std::memory_order_acquire) - start_skipped;
    log_msg(hf, "mcp.phase_accounting", "registered_tool_records=%zu explicit_invocations=%zu pass_delta=%d fail_delta=%d skip_delta=%d",
        g_tool_attempt_stats.size(), g_invoked_tools.size(), delta_passed, delta_failed, delta_skipped);
    set_progress_step("mcp complete");
    log_msg(hf, "mcp_phase", "=== MCP TOOL TESTS DONE (elapsed %lld ms) ===", (long long)ms);
}

}
