#include "test_all_ui.h"
#include "test_all_features.hpp"

#include "../../helpers/diag_log.hpp"
#include "../../helpers/globals.h"
#include "../analysis/analysis_hub_view.hpp"
#include "../analysis/stealth_view.hpp"
#include "../analysis/types_hub_view.hpp"
#include "../auth/auth_view.hpp"
#include "../debugger/debugger_view.hpp"
#include "../emulation/symbolic_view.hpp"
#include "../editor/code_editor.hpp"
#include "../editor/hex_view.hpp"
#include "../editor/image_view.hpp"
#include "../mcp/mcp_marketplace.hpp"
#include "../mcp/mcp_marketplace_view.hpp"
#include "../network/burp/api_view.hpp"
#include "../network/burp/burp_logger_view.hpp"
#include "../network/burp/graphql_view.hpp"
#include "../network/burp/report_view.hpp"
#include "../network/burp/ws_editor_view.hpp"
#include "../network/network_view.hpp"
#include "../scanner/aob_view.hpp"
#include "../scanner/scan_hub_view.hpp"
#include "../settings/standalone_settings.hpp"
#include "../runtime/diagnostic_exception_scope.hpp"
#include "../ui/ui_thread_dispatcher.hpp"

#include <Windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

extern HWND g_hwnd;

namespace test_all_features {

namespace {

static void format_timestamp(char* out, std::size_t cap) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        static_cast<unsigned>(st.wYear),
        static_cast<unsigned>(st.wMonth),
        static_cast<unsigned>(st.wDay),
        static_cast<unsigned>(st.wHour),
        static_cast<unsigned>(st.wMinute),
        static_cast<unsigned>(st.wSecond),
        static_cast<unsigned>(st.wMilliseconds));
}

static void write_log_file(HANDLE hf, const std::string& line) {
    test_all_features::write_full_test_log_line(hf, line.data(), line.size());
}

static void log_msg(HANDLE hf, const char* tag, const char* fmt, ...) {
    char ts[40];
    format_timestamp(ts, sizeof(ts));

    char detail[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);

    char line[1200];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] [%s] %s\n", ts, tag, detail);
    std::string s(line);
    write_log_file(hf, s);
    test_all_features::mirror_full_test_log_line(tag, detail, s.c_str());
}

struct check_accum_t {
    bool ok = true;
    int checked = 0;
    std::string failures;

    void require(bool cond, const char* label) {
        ++checked;
        if (cond) return;
        ok = false;
        if (failures.size() < 640) {
            if (!failures.empty()) failures += "; ";
            failures += label;
        }
    }
};

struct ui_phase_job_t {
    std::uint64_t id = 0;
    HANDLE hf = INVALID_HANDLE_VALUE;
    std::atomic<int>* passed = nullptr;
    std::atomic<int>* failed = nullptr;
    std::atomic<int>* skipped = nullptr;
    bool(*cancelled)() = nullptr;
    DWORD worker_tid = 0;
    DWORD ui_tid = 0;
    std::uint64_t queued_ms = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t finished_ms = 0;
    std::size_t next_step = 0;
    std::uint64_t processed_steps = 0;
    bool started = false;
    bool dispatch_cancelled = false;
    bool done = false;
};

std::mutex g_ui_phase_mtx;
std::condition_variable g_ui_phase_cv;
std::atomic<std::size_t> g_ui_phase_pending_jobs{0};
std::atomic<DWORD> g_ui_phase_thread_id{0};
std::atomic<std::uint64_t> g_ui_phase_next_job_id{0};
std::atomic<std::uint64_t> g_ui_phase_active_job_id{0};
std::atomic<DWORD> g_ui_phase_active_worker_tid{0};
std::atomic<int> g_ui_phase_active_step_index{-1};
std::atomic<const char*> g_ui_phase_active_step_name{"<idle>"};
std::atomic<std::uint64_t> g_ui_phase_last_lock_wait_ms{0};
std::atomic<std::uint64_t> g_ui_phase_last_job_run_ms{0};
std::atomic<std::uint64_t> g_ui_phase_last_job_wait_ms{0};
std::atomic<std::uint64_t> g_ui_phase_last_pump_wall_ms{0};
std::atomic<std::uint64_t> g_ui_phase_last_pump_seq{0};
std::atomic<std::uint64_t> g_ui_phase_skipped_by_budget_count{0};
std::atomic<std::uint64_t> g_ui_phase_skipped_no_job_count{0};
std::atomic<std::uint64_t> g_ui_phase_lock_busy_count{0};
std::atomic<std::uint64_t> g_ui_phase_steps_processed_total{0};
std::atomic<std::size_t> g_ui_phase_last_pending_count{0};

static std::uint64_t ui_now_ms() {
    return static_cast<std::uint64_t>(GetTickCount64());
}

static const char* center_view_name(center_view_t v) {
    switch (v) {
    case center_view_t::code_editor: return "code_editor";
    case center_view_t::disassembly: return "disassembly";
    case center_view_t::hex_view: return "hex_view";
    case center_view_t::welcome: return "welcome";
    case center_view_t::settings_view: return "settings_view";
    case center_view_t::network_view: return "network_view";
    case center_view_t::memory_scanner: return "memory_scanner";
    case center_view_t::debugger_view: return "debugger_view";
    case center_view_t::pseudocode: return "pseudocode";
    case center_view_t::struct_recon: return "struct_recon";
    case center_view_t::crypto_scanner: return "crypto_scanner";
    case center_view_t::aob_generator: return "aob_generator";
    case center_view_t::fuzzer_view: return "fuzzer_view";
    case center_view_t::xref_browser: return "xref_browser";
    case center_view_t::snapshot_diff: return "snapshot_diff";
    case center_view_t::pointer_scanner: return "pointer_scanner";
    case center_view_t::decrypt_oracle: return "decrypt_oracle";
    case center_view_t::integrity_hunter: return "integrity_hunter";
    case center_view_t::symbolic_view: return "symbolic_view";
    case center_view_t::taint_view: return "taint_view";
    case center_view_t::deobfuscation_view: return "deobfuscation_view";
    case center_view_t::stealth_view: return "stealth_view";
    case center_view_t::scan_hub: return "scan_hub";
    case center_view_t::types_hub: return "types_hub";
    case center_view_t::analysis_hub: return "analysis_hub";
    case center_view_t::binary_map: return "binary_map";
    case center_view_t::graph_view: return "graph_view";
    case center_view_t::image_view: return "image_view";
    case center_view_t::test_lab: return "test_lab";
    case center_view_t::workbench: return "workbench";
    }
    return "";
}

static bool is_scan_center_view(center_view_t v) {
    return v == center_view_t::scan_hub
        || v == center_view_t::memory_scanner
        || v == center_view_t::crypto_scanner
        || v == center_view_t::aob_generator
        || v == center_view_t::xref_browser
        || v == center_view_t::snapshot_diff
        || v == center_view_t::pointer_scanner
        || v == center_view_t::decrypt_oracle
        || v == center_view_t::integrity_hunter;
}

static bool is_analysis_center_view(center_view_t v) {
    return v == center_view_t::analysis_hub
        || v == center_view_t::symbolic_view
        || v == center_view_t::taint_view
        || v == center_view_t::deobfuscation_view
        || v == center_view_t::stealth_view
        || v == center_view_t::fuzzer_view;
}

static const char* network_tab_name(network_view::sub_tab_t tab) {
    switch (tab) {
    case network_view::sub_tab_t::connections: return "connections";
    case network_view::sub_tab_t::capture: return "capture";
    case network_view::sub_tab_t::intercept: return "intercept";
    case network_view::sub_tab_t::proxy: return "proxy";
    case network_view::sub_tab_t::dns: return "dns";
    case network_view::sub_tab_t::filters: return "filters";
    case network_view::sub_tab_t::bandwidth: return "bandwidth";
    case network_view::sub_tab_t::repeater: return "repeater";
    case network_view::sub_tab_t::keylog: return "keylog";
    case network_view::sub_tab_t::pcap_export: return "pcap_export";
    case network_view::sub_tab_t::fuzzer: return "fuzzer";
    case network_view::sub_tab_t::websocket: return "websocket";
    case network_view::sub_tab_t::scripting: return "scripting";
    case network_view::sub_tab_t::decoder: return "decoder";
    case network_view::sub_tab_t::sitemap: return "sitemap";
    case network_view::sub_tab_t::scope: return "scope";
    case network_view::sub_tab_t::cookies: return "cookies";
    case network_view::sub_tab_t::scanner: return "scanner";
    case network_view::sub_tab_t::recon: return "recon";
    case network_view::sub_tab_t::intruder: return "intruder";
    case network_view::sub_tab_t::collab: return "collab";
    case network_view::sub_tab_t::sequencer: return "sequencer";
    case network_view::sub_tab_t::comparer: return "comparer";
    case network_view::sub_tab_t::jwt: return "jwt";
    case network_view::sub_tab_t::mr: return "mr";
    case network_view::sub_tab_t::session: return "session";
    case network_view::sub_tab_t::api: return "api";
    case network_view::sub_tab_t::ws_edit: return "ws_edit";
    case network_view::sub_tab_t::h2_edit: return "h2_edit";
    case network_view::sub_tab_t::logger: return "logger";
    case network_view::sub_tab_t::csp: return "csp";
    case network_view::sub_tab_t::upstream: return "upstream";
    case network_view::sub_tab_t::browser: return "browser";
    case network_view::sub_tab_t::reports: return "reports";
    case network_view::sub_tab_t::headless: return "headless";
    case network_view::sub_tab_t::offensive: return "offensive";
    case network_view::sub_tab_t::COUNT: break;
    }
    return "";
}

static void copy_chars(char* dst, std::size_t dst_size, const char* src, std::size_t src_size) {
    if (!dst || !src || dst_size == 0) return;
    std::memset(dst, 0, dst_size);
    std::memcpy(dst, src, dst_size < src_size ? dst_size : src_size);
}

struct network_view_state_guard_t {
    bool active = network_view::g_state.active;
    network_view::sub_tab_t active_tab = network_view::g_state.active_tab;
    network_view::sub_tab_t prev_tab = network_view::g_state.prev_tab;
    int conn_selected = network_view::g_state.conn_selected;
    int cap_selected = network_view::g_state.cap_selected;
    int dns_selected = network_view::g_state.dns_selected;
    int filter_selected = network_view::g_state.filter_selected;
    int bw_selected = network_view::g_state.bw_selected;
    int repeater_selected = network_view::g_state.repeater_selected;
    int intercept_selected = network_view::g_state.intercept_selected;
    int proxy_selected = network_view::g_state.proxy_selected;
    int kl_selected = network_view::g_state.kl_selected;
    std::uint64_t fuzz_selected = network_view::g_state.fuzz_selected;
    int ws_selected = network_view::g_state.ws_selected;
    int script_selected = network_view::g_state.script_selected;
    int decoder_selected_step = network_view::g_state.decoder_selected_step;
    bool intercept_enabled = network_view::g_state.intercept_enabled;
    bool cap_auto_scroll = network_view::g_state.cap_auto_scroll;
    bool dns_auto_scroll = network_view::g_state.dns_auto_scroll;
    bool ws_auto_scroll = network_view::g_state.ws_auto_scroll;
    bool script_log_auto_scroll = network_view::g_state.script_log_auto_scroll;
    int proxy_port = network_view::g_state.proxy_port;
    bool proxy_decode_tls = network_view::g_state.proxy_decode_tls;
    uint32_t pcap_filter_pid = network_view::g_state.pcap_filter_pid;
    uint8_t pcap_filter_protocol = network_view::g_state.pcap_filter_protocol;
    bool cap_running = network_view::g_state.cap_running.load(std::memory_order_acquire);
    bool cap_start_pending = network_view::g_state.cap_start_pending.load(std::memory_order_acquire);
    bool cap_stop_pending = network_view::g_state.cap_stop_pending.load(std::memory_order_acquire);
    bool dns_polling = network_view::g_state.dns_polling.load(std::memory_order_acquire);
    bool bw_monitoring = network_view::g_state.bw_monitoring;
    bool bw_polling = network_view::g_state.bw_polling.load(std::memory_order_acquire);
    bool fuzz_running = network_view::g_state.fuzz_running.load(std::memory_order_acquire);
    std::uint64_t fuzz_progress = network_view::g_state.fuzz_progress.load(std::memory_order_acquire);
    std::uint64_t fuzz_total = network_view::g_state.fuzz_total.load(std::memory_order_acquire);
    uint32_t pcap_written_count = network_view::g_state.pcap_written_count.load(std::memory_order_acquire);
    bool pcap_writing = network_view::g_state.pcap_writing.load(std::memory_order_acquire);
    std::vector<network_view::filter_entry_t> filters = network_view::g_state.filters;
    std::vector<std::shared_ptr<network_view::repeater_entry_t>> repeater_entries = network_view::g_state.repeater_entries;
    std::vector<network_view::state_t::script_entry_t> scripts = network_view::g_state.scripts;
    std::vector<network_view::state_t::decoder_step_t> decoder_pipeline = network_view::g_state.decoder_pipeline;
    network_view::state_t::fuzzer_entry_t fuzz_config = network_view::g_state.fuzz_config;
    char conn_filter_text[sizeof(network_view::g_state.conn_filter_text)] = {};
    char cap_filter_text[sizeof(network_view::g_state.cap_filter_text)] = {};
    char dns_filter_text[sizeof(network_view::g_state.dns_filter_text)] = {};
    char proxy_bind_addr[sizeof(network_view::g_state.proxy_bind_addr)] = {};
    char proxy_filter_text[sizeof(network_view::g_state.proxy_filter_text)] = {};
    char kl_exe_path[sizeof(network_view::g_state.kl_exe_path)] = {};
    char kl_args[sizeof(network_view::g_state.kl_args)] = {};
    char kl_watch_path[sizeof(network_view::g_state.kl_watch_path)] = {};
    char pcap_path[sizeof(network_view::g_state.pcap_path)] = {};
    char ws_filter_text[sizeof(network_view::g_state.ws_filter_text)] = {};
    char script_editor_buf[sizeof(network_view::g_state.script_editor_buf)] = {};
    char decoder_input[sizeof(network_view::g_state.decoder_input)] = {};
    std::deque<network_view::packet_entry_t> captured_packets;
    std::deque<network_view::dns_entry_t> dns_entries;
    std::vector<network_view::bw_entry_t> bw_entries;
    std::deque<std::shared_ptr<const network_view::state_t::fuzzer_result_page_t>> fuzz_result_pages;
    std::vector<network_view::state_t::fuzzer_result_t> fuzz_result_pending;
    std::shared_ptr<const network_view::state_t::fuzzer_results_snapshot_t> fuzz_results_snapshot;
    std::shared_ptr<const std::vector<std::vector<std::string>>> fuzz_payload_catalog;
    std::uint64_t fuzz_retained_count = 0;
    std::uint64_t fuzz_dropped_count = 0;
    std::uint64_t fuzz_retained_bytes = 0;
    std::uint64_t fuzz_pending_bytes = 0;
    std::uint64_t fuzz_results_generation = 0;
    std::size_t fuzz_maximum_payload_columns = 1;
    bool fuzz_has_extracted_values = false;
    bool fuzz_has_failures = false;
    std::deque<network_view::state_t::ws_frame_entry_t> ws_frames;
    std::deque<std::string> script_log;
    std::string decoder_output = network_view::g_state.decoder_output;

    network_view_state_guard_t() {
        copy_chars(conn_filter_text, sizeof(conn_filter_text), network_view::g_state.conn_filter_text, sizeof(network_view::g_state.conn_filter_text));
        copy_chars(cap_filter_text, sizeof(cap_filter_text), network_view::g_state.cap_filter_text, sizeof(network_view::g_state.cap_filter_text));
        copy_chars(dns_filter_text, sizeof(dns_filter_text), network_view::g_state.dns_filter_text, sizeof(network_view::g_state.dns_filter_text));
        copy_chars(proxy_bind_addr, sizeof(proxy_bind_addr), network_view::g_state.proxy_bind_addr, sizeof(network_view::g_state.proxy_bind_addr));
        copy_chars(proxy_filter_text, sizeof(proxy_filter_text), network_view::g_state.proxy_filter_text, sizeof(network_view::g_state.proxy_filter_text));
        copy_chars(kl_exe_path, sizeof(kl_exe_path), network_view::g_state.kl_exe_path, sizeof(network_view::g_state.kl_exe_path));
        copy_chars(kl_args, sizeof(kl_args), network_view::g_state.kl_args, sizeof(network_view::g_state.kl_args));
        copy_chars(kl_watch_path, sizeof(kl_watch_path), network_view::g_state.kl_watch_path, sizeof(network_view::g_state.kl_watch_path));
        copy_chars(pcap_path, sizeof(pcap_path), network_view::g_state.pcap_path, sizeof(network_view::g_state.pcap_path));
        copy_chars(ws_filter_text, sizeof(ws_filter_text), network_view::g_state.ws_filter_text, sizeof(network_view::g_state.ws_filter_text));
        copy_chars(script_editor_buf, sizeof(script_editor_buf), network_view::g_state.script_editor_buf, sizeof(network_view::g_state.script_editor_buf));
        copy_chars(decoder_input, sizeof(decoder_input), network_view::g_state.decoder_input, sizeof(network_view::g_state.decoder_input));
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.cap_mutex);
            captured_packets = network_view::g_state.captured_packets;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.dns_mutex);
            dns_entries = network_view::g_state.dns_entries;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.bw_mutex);
            bw_entries = network_view::g_state.bw_entries;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.fuzz_mutex);
            fuzz_result_pages = network_view::g_state.fuzz_result_pages;
            fuzz_result_pending = network_view::g_state.fuzz_result_pending;
            fuzz_results_snapshot = std::atomic_load_explicit(
                &network_view::g_state.fuzz_results_snapshot, std::memory_order_acquire);
            fuzz_payload_catalog = network_view::g_state.fuzz_payload_catalog;
            fuzz_retained_count = network_view::g_state.fuzz_retained_count;
            fuzz_dropped_count = network_view::g_state.fuzz_dropped_count;
            fuzz_retained_bytes = network_view::g_state.fuzz_retained_bytes;
            fuzz_pending_bytes = network_view::g_state.fuzz_pending_bytes;
            fuzz_results_generation = network_view::g_state.fuzz_results_generation;
            fuzz_maximum_payload_columns = network_view::g_state.fuzz_maximum_payload_columns;
            fuzz_has_extracted_values = network_view::g_state.fuzz_has_extracted_values;
            fuzz_has_failures = network_view::g_state.fuzz_has_failures;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.ws_mutex);
            ws_frames = network_view::g_state.ws_frames;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.script_log_mutex);
            script_log = network_view::g_state.script_log;
        }
    }

    ~network_view_state_guard_t() {
        network_view::g_state.active = active;
        network_view::g_state.active_tab = active_tab;
        network_view::g_state.prev_tab = prev_tab;
        network_view::g_state.conn_selected = conn_selected;
        network_view::g_state.cap_selected = cap_selected;
        network_view::g_state.dns_selected = dns_selected;
        network_view::g_state.filter_selected = filter_selected;
        network_view::g_state.bw_selected = bw_selected;
        network_view::g_state.repeater_selected = repeater_selected;
        network_view::g_state.intercept_selected = intercept_selected;
        network_view::g_state.proxy_selected = proxy_selected;
        network_view::g_state.kl_selected = kl_selected;
        network_view::g_state.fuzz_selected = fuzz_selected;
        network_view::g_state.ws_selected = ws_selected;
        network_view::g_state.script_selected = script_selected;
        network_view::g_state.decoder_selected_step = decoder_selected_step;
        network_view::g_state.intercept_enabled = intercept_enabled;
        network_view::g_state.cap_auto_scroll = cap_auto_scroll;
        network_view::g_state.dns_auto_scroll = dns_auto_scroll;
        network_view::g_state.ws_auto_scroll = ws_auto_scroll;
        network_view::g_state.script_log_auto_scroll = script_log_auto_scroll;
        network_view::g_state.proxy_port = proxy_port;
        network_view::g_state.proxy_decode_tls = proxy_decode_tls;
        network_view::g_state.pcap_filter_pid = pcap_filter_pid;
        network_view::g_state.pcap_filter_protocol = pcap_filter_protocol;
        network_view::g_state.cap_running.store(cap_running, std::memory_order_release);
        network_view::g_state.cap_start_pending.store(cap_start_pending, std::memory_order_release);
        network_view::g_state.cap_stop_pending.store(cap_stop_pending, std::memory_order_release);
        network_view::g_state.dns_polling.store(dns_polling, std::memory_order_release);
        network_view::g_state.bw_monitoring = bw_monitoring;
        network_view::g_state.bw_polling.store(bw_polling, std::memory_order_release);
        network_view::g_state.fuzz_running.store(fuzz_running, std::memory_order_release);
        network_view::g_state.fuzz_progress.store(fuzz_progress, std::memory_order_release);
        network_view::g_state.fuzz_total.store(fuzz_total, std::memory_order_release);
        network_view::g_state.pcap_written_count.store(pcap_written_count, std::memory_order_release);
        network_view::g_state.pcap_writing.store(pcap_writing, std::memory_order_release);
        network_view::g_state.filters = filters;
        network_view::g_state.repeater_entries = repeater_entries;
        network_view::g_state.scripts = scripts;
        network_view::g_state.decoder_pipeline = decoder_pipeline;
        network_view::g_state.fuzz_config = fuzz_config;
        network_view::g_state.decoder_output = decoder_output;
        copy_chars(network_view::g_state.conn_filter_text, sizeof(network_view::g_state.conn_filter_text), conn_filter_text, sizeof(conn_filter_text));
        copy_chars(network_view::g_state.cap_filter_text, sizeof(network_view::g_state.cap_filter_text), cap_filter_text, sizeof(cap_filter_text));
        copy_chars(network_view::g_state.dns_filter_text, sizeof(network_view::g_state.dns_filter_text), dns_filter_text, sizeof(dns_filter_text));
        copy_chars(network_view::g_state.proxy_bind_addr, sizeof(network_view::g_state.proxy_bind_addr), proxy_bind_addr, sizeof(proxy_bind_addr));
        copy_chars(network_view::g_state.proxy_filter_text, sizeof(network_view::g_state.proxy_filter_text), proxy_filter_text, sizeof(proxy_filter_text));
        copy_chars(network_view::g_state.kl_exe_path, sizeof(network_view::g_state.kl_exe_path), kl_exe_path, sizeof(kl_exe_path));
        copy_chars(network_view::g_state.kl_args, sizeof(network_view::g_state.kl_args), kl_args, sizeof(kl_args));
        copy_chars(network_view::g_state.kl_watch_path, sizeof(network_view::g_state.kl_watch_path), kl_watch_path, sizeof(kl_watch_path));
        copy_chars(network_view::g_state.pcap_path, sizeof(network_view::g_state.pcap_path), pcap_path, sizeof(pcap_path));
        copy_chars(network_view::g_state.ws_filter_text, sizeof(network_view::g_state.ws_filter_text), ws_filter_text, sizeof(ws_filter_text));
        copy_chars(network_view::g_state.script_editor_buf, sizeof(network_view::g_state.script_editor_buf), script_editor_buf, sizeof(script_editor_buf));
        copy_chars(network_view::g_state.decoder_input, sizeof(network_view::g_state.decoder_input), decoder_input, sizeof(decoder_input));
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.cap_mutex);
            network_view::g_state.captured_packets = captured_packets;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.dns_mutex);
            network_view::g_state.dns_entries = dns_entries;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.bw_mutex);
            network_view::g_state.bw_entries = bw_entries;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.fuzz_mutex);
            network_view::g_state.fuzz_result_pages = fuzz_result_pages;
            network_view::g_state.fuzz_result_pending = fuzz_result_pending;
            std::atomic_store_explicit(&network_view::g_state.fuzz_results_snapshot,
                fuzz_results_snapshot, std::memory_order_release);
            network_view::g_state.fuzz_payload_catalog = fuzz_payload_catalog;
            network_view::g_state.fuzz_retained_count = fuzz_retained_count;
            network_view::g_state.fuzz_dropped_count = fuzz_dropped_count;
            network_view::g_state.fuzz_retained_bytes = fuzz_retained_bytes;
            network_view::g_state.fuzz_pending_bytes = fuzz_pending_bytes;
            network_view::g_state.fuzz_results_generation = fuzz_results_generation;
            network_view::g_state.fuzz_maximum_payload_columns = fuzz_maximum_payload_columns;
            network_view::g_state.fuzz_has_extracted_values = fuzz_has_extracted_values;
            network_view::g_state.fuzz_has_failures = fuzz_has_failures;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.ws_mutex);
            network_view::g_state.ws_frames = ws_frames;
        }
        {
            std::lock_guard<std::mutex> lk(network_view::g_state.script_log_mutex);
            network_view::g_state.script_log = script_log;
        }
    }
};

struct burp_detail_state_guard_t {
    bool ws_active;
    int ws_scheme_idx;
    int ws_port;
    int ws_selected_conn_index;
    int ws_compose_mode_idx;
    int ws_compose_opcode;
    bool ws_verify_tls;
    bool ws_compose_fin;
    bool ws_compose_masked;
    char ws_host_buf[sizeof(aida::burp::ws_editor_view::get_state().host_buf)] = {};
    char ws_path_buf[sizeof(aida::burp::ws_editor_view::get_state().path_buf)] = {};
    char ws_compose_text_buf[sizeof(aida::burp::ws_editor_view::get_state().compose_text_buf)] = {};
    std::string ws_last_action;
    std::string ws_last_action_kind;

    bool api_active;
    int api_selected_collection_index;
    int api_selected_request_index;
    int api_import_format_idx;
    bool api_sending;
    bool api_importing;
    bool api_auditing;
    char api_import_url_buf[sizeof(aida::burp::api_view::get_state().import_url_buf)] = {};
    char api_send_header_value_buf[sizeof(aida::burp::api_view::get_state().send_header_value_buf)] = {};
    std::deque<aida::burp::api_view::retained_exchange_t> api_retained_exchanges;
    std::string api_last_action_message;
    std::string api_last_action_kind;

    bool logger_active;
    int logger_status_min;
    int logger_status_max;
    int logger_row_limit;
    int logger_selected_row;
    char logger_method_filter_buf[sizeof(aida::burp::logger_view::get_state().method_filter_buf)] = {};
    char logger_host_regex_buf[sizeof(aida::burp::logger_view::get_state().host_regex_buf)] = {};
    char logger_export_path_buf[sizeof(aida::burp::logger_view::get_state().export_path_buf)] = {};
    std::string logger_last_action;
    std::string logger_last_action_kind;

    bool report_active;
    int report_format_idx;
    int report_selected_history;
    bool report_include_evidence;
    bool report_include_remediation;
    bool report_generating;
    char report_title_buf[sizeof(aida::burp::report_view::get_state().title_buf)] = {};
    char report_output_path_buf[sizeof(aida::burp::report_view::get_state().output_path_buf)] = {};
    std::string report_last_action;
    std::string report_last_action_kind;

    bool graphql_active;
    int graphql_active_tab;
    int graphql_depth;
    int graphql_batch_count;
    int graphql_selected_type_index;
    int graphql_selected_field_index;
    int graphql_last_status;
    uint64_t graphql_last_latency_ms;
    bool graphql_introspecting;
    bool graphql_sending;
    char graphql_endpoint_buf[sizeof(aida::burp::graphql_view::get_state().endpoint_buf)] = {};
    char graphql_headers_buf[sizeof(aida::burp::graphql_view::get_state().headers_buf)] = {};
    std::string graphql_last_schema_raw;
    std::string graphql_schema_status;
    std::string graphql_query_text;
    std::string graphql_variables_text;
    std::string graphql_last_response_raw;
    std::deque<aida::burp::graphql_view::history_row_t> graphql_history;
    size_t graphql_history_max;

    burp_detail_state_guard_t()
        : ws_active(aida::burp::ws_editor_view::get_state().active),
          ws_scheme_idx(aida::burp::ws_editor_view::get_state().scheme_idx),
          ws_port(aida::burp::ws_editor_view::get_state().port),
          ws_selected_conn_index(aida::burp::ws_editor_view::get_state().selected_conn_index),
          ws_compose_mode_idx(aida::burp::ws_editor_view::get_state().compose_mode_idx),
          ws_compose_opcode(aida::burp::ws_editor_view::get_state().compose_opcode),
          ws_verify_tls(aida::burp::ws_editor_view::get_state().verify_tls),
          ws_compose_fin(aida::burp::ws_editor_view::get_state().compose_fin),
          ws_compose_masked(aida::burp::ws_editor_view::get_state().compose_masked),
          api_active(aida::burp::api_view::get_state().active),
          api_selected_collection_index(aida::burp::api_view::get_state().selected_collection_index),
          api_selected_request_index(aida::burp::api_view::get_state().selected_request_index),
          api_import_format_idx(aida::burp::api_view::get_state().import_format_idx),
          api_sending(aida::burp::api_view::get_state().sending.load(std::memory_order_acquire)),
          api_importing(aida::burp::api_view::get_state().importing.load(std::memory_order_acquire)),
          api_auditing(aida::burp::api_view::get_state().auditing.load(std::memory_order_acquire)),
          logger_active(aida::burp::logger_view::get_state().active),
          logger_status_min(aida::burp::logger_view::get_state().status_min),
          logger_status_max(aida::burp::logger_view::get_state().status_max),
          logger_row_limit(aida::burp::logger_view::get_state().row_limit),
          logger_selected_row(aida::burp::logger_view::get_state().selected_row),
          report_active(aida::burp::report_view::get_state().active),
          report_format_idx(aida::burp::report_view::get_state().format_idx),
          report_selected_history(aida::burp::report_view::get_state().selected_history),
          report_include_evidence(aida::burp::report_view::get_state().include_evidence),
          report_include_remediation(aida::burp::report_view::get_state().include_remediation),
          report_generating(aida::burp::report_view::get_state().generating.load(std::memory_order_acquire)),
          graphql_active(aida::burp::graphql_view::get_state().active),
          graphql_active_tab(aida::burp::graphql_view::get_state().active_tab),
          graphql_depth(aida::burp::graphql_view::get_state().depth),
          graphql_batch_count(aida::burp::graphql_view::get_state().batch_count),
          graphql_selected_type_index(aida::burp::graphql_view::get_state().selected_type_index),
          graphql_selected_field_index(aida::burp::graphql_view::get_state().selected_field_index),
          graphql_last_status(aida::burp::graphql_view::get_state().last_status),
          graphql_last_latency_ms(aida::burp::graphql_view::get_state().last_latency_ms),
          graphql_introspecting(aida::burp::graphql_view::get_state().introspecting.load(std::memory_order_acquire)),
          graphql_sending(aida::burp::graphql_view::get_state().sending.load(std::memory_order_acquire)),
          graphql_history_max(aida::burp::graphql_view::get_state().history_max) {
        {
            auto& s = aida::burp::ws_editor_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            copy_chars(ws_host_buf, sizeof(ws_host_buf), s.host_buf, sizeof(s.host_buf));
            copy_chars(ws_path_buf, sizeof(ws_path_buf), s.path_buf, sizeof(s.path_buf));
            copy_chars(ws_compose_text_buf, sizeof(ws_compose_text_buf), s.compose_text_buf, sizeof(s.compose_text_buf));
            ws_last_action = s.last_action;
            ws_last_action_kind = s.last_action_kind;
        }
        {
            auto& s = aida::burp::api_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            copy_chars(api_import_url_buf, sizeof(api_import_url_buf), s.import_url_buf, sizeof(s.import_url_buf));
            copy_chars(api_send_header_value_buf, sizeof(api_send_header_value_buf), s.send_header_value_buf, sizeof(s.send_header_value_buf));
            api_retained_exchanges = s.retained_exchanges;
            api_last_action_message = s.last_action_message;
            api_last_action_kind = s.last_action_kind;
        }
        {
            auto& s = aida::burp::logger_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            copy_chars(logger_method_filter_buf, sizeof(logger_method_filter_buf), s.method_filter_buf, sizeof(s.method_filter_buf));
            copy_chars(logger_host_regex_buf, sizeof(logger_host_regex_buf), s.host_regex_buf, sizeof(s.host_regex_buf));
            copy_chars(logger_export_path_buf, sizeof(logger_export_path_buf), s.export_path_buf, sizeof(s.export_path_buf));
            logger_last_action = s.last_action;
            logger_last_action_kind = s.last_action_kind;
        }
        {
            auto& s = aida::burp::report_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            copy_chars(report_title_buf, sizeof(report_title_buf), s.title_buf, sizeof(s.title_buf));
            copy_chars(report_output_path_buf, sizeof(report_output_path_buf), s.output_path_buf, sizeof(s.output_path_buf));
            report_last_action = s.last_action;
            report_last_action_kind = s.last_action_kind;
        }
        {
            auto& s = aida::burp::graphql_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            copy_chars(graphql_endpoint_buf, sizeof(graphql_endpoint_buf), s.endpoint_buf, sizeof(s.endpoint_buf));
            copy_chars(graphql_headers_buf, sizeof(graphql_headers_buf), s.headers_buf, sizeof(s.headers_buf));
            graphql_last_schema_raw = s.last_schema_raw;
            graphql_schema_status = s.schema_status;
            graphql_query_text = s.query_text;
            graphql_variables_text = s.variables_text;
            graphql_last_response_raw = s.last_response_raw;
            graphql_history = s.history;
        }
    }

    ~burp_detail_state_guard_t() {
        {
            auto& s = aida::burp::ws_editor_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            s.active = ws_active;
            s.scheme_idx = ws_scheme_idx;
            s.port = ws_port;
            s.selected_conn_index = ws_selected_conn_index;
            s.compose_mode_idx = ws_compose_mode_idx;
            s.compose_opcode = ws_compose_opcode;
            s.verify_tls = ws_verify_tls;
            s.compose_fin = ws_compose_fin;
            s.compose_masked = ws_compose_masked;
            copy_chars(s.host_buf, sizeof(s.host_buf), ws_host_buf, sizeof(ws_host_buf));
            copy_chars(s.path_buf, sizeof(s.path_buf), ws_path_buf, sizeof(ws_path_buf));
            copy_chars(s.compose_text_buf, sizeof(s.compose_text_buf), ws_compose_text_buf, sizeof(ws_compose_text_buf));
            s.last_action = ws_last_action;
            s.last_action_kind = ws_last_action_kind;
        }
        {
            auto& s = aida::burp::api_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            s.active = api_active;
            s.selected_collection_index = api_selected_collection_index;
            s.selected_request_index = api_selected_request_index;
            s.import_format_idx = api_import_format_idx;
            s.sending.store(api_sending, std::memory_order_release);
            s.importing.store(api_importing, std::memory_order_release);
            s.auditing.store(api_auditing, std::memory_order_release);
            copy_chars(s.import_url_buf, sizeof(s.import_url_buf), api_import_url_buf, sizeof(api_import_url_buf));
            copy_chars(s.send_header_value_buf, sizeof(s.send_header_value_buf), api_send_header_value_buf, sizeof(api_send_header_value_buf));
            s.retained_exchanges = api_retained_exchanges;
            s.last_action_message = api_last_action_message;
            s.last_action_kind = api_last_action_kind;
        }
        {
            auto& s = aida::burp::logger_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            s.active = logger_active;
            s.status_min = logger_status_min;
            s.status_max = logger_status_max;
            s.row_limit = logger_row_limit;
            s.selected_row = logger_selected_row;
            copy_chars(s.method_filter_buf, sizeof(s.method_filter_buf), logger_method_filter_buf, sizeof(logger_method_filter_buf));
            copy_chars(s.host_regex_buf, sizeof(s.host_regex_buf), logger_host_regex_buf, sizeof(logger_host_regex_buf));
            copy_chars(s.export_path_buf, sizeof(s.export_path_buf), logger_export_path_buf, sizeof(logger_export_path_buf));
            s.last_action = logger_last_action;
            s.last_action_kind = logger_last_action_kind;
        }
        {
            auto& s = aida::burp::report_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            s.active = report_active;
            s.format_idx = report_format_idx;
            s.selected_history = report_selected_history;
            s.include_evidence = report_include_evidence;
            s.include_remediation = report_include_remediation;
            s.generating.store(report_generating, std::memory_order_release);
            copy_chars(s.title_buf, sizeof(s.title_buf), report_title_buf, sizeof(report_title_buf));
            copy_chars(s.output_path_buf, sizeof(s.output_path_buf), report_output_path_buf, sizeof(report_output_path_buf));
            s.last_action = report_last_action;
            s.last_action_kind = report_last_action_kind;
        }
        {
            auto& s = aida::burp::graphql_view::get_state();
            std::lock_guard<std::mutex> lk(s.lock);
            s.active = graphql_active;
            s.active_tab = graphql_active_tab;
            s.depth = graphql_depth;
            s.batch_count = graphql_batch_count;
            s.selected_type_index = graphql_selected_type_index;
            s.selected_field_index = graphql_selected_field_index;
            s.last_status = graphql_last_status;
            s.last_latency_ms = graphql_last_latency_ms;
            s.introspecting.store(graphql_introspecting, std::memory_order_release);
            s.sending.store(graphql_sending, std::memory_order_release);
            copy_chars(s.endpoint_buf, sizeof(s.endpoint_buf), graphql_endpoint_buf, sizeof(graphql_endpoint_buf));
            copy_chars(s.headers_buf, sizeof(s.headers_buf), graphql_headers_buf, sizeof(graphql_headers_buf));
            s.last_schema_raw = graphql_last_schema_raw;
            s.schema_status = graphql_schema_status;
            s.query_text = graphql_query_text;
            s.variables_text = graphql_variables_text;
            s.last_response_raw = graphql_last_response_raw;
            s.history = graphql_history;
            s.history_max = graphql_history_max;
        }
    }
};

struct ui_state_guard_t {
    center_view_t center = globals::ui::active_center_view;
    bool test_all_visible = globals::ui::test_all_visible;
    bool command_palette_open = globals::ui::command_palette_open;
    bool mcp_servers_dialog_open = globals::ui::mcp_servers_dialog_open;
    bool find_bar_open = globals::ui::find_bar_open;
    bool find_case_sensitive = globals::ui::find_case_sensitive;
    bool find_whole_word = globals::ui::find_whole_word;
    bool find_regex = globals::ui::find_regex;
    bool find_show_replace = globals::ui::find_show_replace;
    int find_match_count = globals::ui::find_match_count;
    int find_current_match = globals::ui::find_current_match;
    bool search_panel_open = workspace_search::g_search.panel_open;
    bool case_sensitive = workspace_search::g_search.case_sensitive;
    bool whole_word = workspace_search::g_search.whole_word;
    bool use_regex = workspace_search::g_search.use_regex;
    int selected_idx = workspace_search::g_search.selected_idx;
    int files_scanned = workspace_search::g_search.files_scanned.load(std::memory_order_acquire);
    int match_count = workspace_search::g_search.match_count.load(std::memory_order_acquire);
    std::string recent = g_sa_settings.recent_workspaces_json;
    std::string status_file = globals::ui::status_file_info;
    std::string status_driver = globals::ui::status_driver_info;
    std::string status_model = globals::ui::status_model_info;
    std::vector<char> code_buffer = code_editor::buffer;
    std::string code_filename = code_editor::filename;
    std::string code_filepath = code_editor::filepath;
    std::vector<OpenTab> tabs = file_tabs::tabs;
    int active_tab = file_tabs::active_tab;
    bool code_active = code_editor::active;
    bool code_dirty = code_editor::dirty;
    float code_scroll_y = code_editor::scroll_y;
    std::array<std::deque<std::string>, static_cast<std::size_t>(bottom_tab_t::COUNT)> log_lines;
    std::array<bool, static_cast<std::size_t>(bottom_tab_t::COUNT)> log_auto_scroll;
    std::array<bool, static_cast<std::size_t>(bottom_tab_t::COUNT)> log_select_all;
    char command_palette[sizeof(globals::ui::command_palette_buf)] = {};
    char find_buf[sizeof(globals::ui::find_buf)] = {};
    char replace_buf[sizeof(globals::ui::replace_buf)] = {};
    char query[sizeof(workspace_search::g_search.query_buf)] = {};
    char include[sizeof(workspace_search::g_search.include_buf)] = {};
    char exclude[sizeof(workspace_search::g_search.exclude_buf)] = {};
    std::vector<int> find_match_positions;
    std::vector<workspace_search::match_result_t> results;

    ui_state_guard_t() {
        std::memcpy(command_palette, globals::ui::command_palette_buf, sizeof(command_palette));
        std::memcpy(find_buf, globals::ui::find_buf, sizeof(find_buf));
        std::memcpy(replace_buf, globals::ui::replace_buf, sizeof(replace_buf));
        std::memcpy(query, workspace_search::g_search.query_buf, sizeof(query));
        std::memcpy(include, workspace_search::g_search.include_buf, sizeof(include));
        std::memcpy(exclude, workspace_search::g_search.exclude_buf, sizeof(exclude));
        find_match_positions = globals::ui::find_match_positions;
        {
            std::lock_guard<std::mutex> lk(workspace_search::g_search.results_mtx);
            results = workspace_search::g_search.results;
        }
        {
            std::lock_guard<std::mutex> log_lk(output_log::mutex);
            output_log::owner_scope log_owner(14, -1);
            for (int i = 0; i < static_cast<int>(bottom_tab_t::COUNT); ++i) {
                log_lines[static_cast<std::size_t>(i)] = output_log::lines[i];
                log_auto_scroll[static_cast<std::size_t>(i)] = output_log::auto_scroll[i];
                log_select_all[static_cast<std::size_t>(i)] = output_log::select_all[i];
            }
        }
    }

    ~ui_state_guard_t() {
        globals::ui::active_center_view = center;
        globals::ui::test_all_visible = test_all_visible;
        globals::ui::command_palette_open = command_palette_open;
        globals::ui::mcp_servers_dialog_open = mcp_servers_dialog_open;
        globals::ui::find_bar_open = find_bar_open;
        globals::ui::find_case_sensitive = find_case_sensitive;
        globals::ui::find_whole_word = find_whole_word;
        globals::ui::find_regex = find_regex;
        globals::ui::find_show_replace = find_show_replace;
        globals::ui::find_match_count = find_match_count;
        globals::ui::find_current_match = find_current_match;
        globals::ui::find_match_positions = find_match_positions;
        std::memcpy(globals::ui::command_palette_buf, command_palette, sizeof(command_palette));
        std::memcpy(globals::ui::find_buf, find_buf, sizeof(find_buf));
        std::memcpy(globals::ui::replace_buf, replace_buf, sizeof(replace_buf));
        workspace_search::g_search.panel_open = search_panel_open;
        workspace_search::g_search.case_sensitive = case_sensitive;
        workspace_search::g_search.whole_word = whole_word;
        workspace_search::g_search.use_regex = use_regex;
        workspace_search::g_search.selected_idx = selected_idx;
        workspace_search::g_search.files_scanned.store(files_scanned, std::memory_order_release);
        workspace_search::g_search.match_count.store(match_count, std::memory_order_release);
        workspace_search::g_search.cancel.store(false, std::memory_order_release);
        workspace_search::g_search.launch_pending.store(false, std::memory_order_release);
        workspace_search::g_search.searching.store(false, std::memory_order_release);
        std::memcpy(workspace_search::g_search.query_buf, query, sizeof(query));
        std::memcpy(workspace_search::g_search.include_buf, include, sizeof(include));
        std::memcpy(workspace_search::g_search.exclude_buf, exclude, sizeof(exclude));
        {
            std::lock_guard<std::mutex> lk(workspace_search::g_search.results_mtx);
            workspace_search::g_search.results = results;
        }
        g_sa_settings.recent_workspaces_json = recent;
        globals::ui::status_file_info = status_file;
        globals::ui::status_driver_info = status_driver;
        globals::ui::status_model_info = status_model;
        code_editor::buffer = code_buffer;
        code_editor::filename = code_filename;
        code_editor::filepath = code_filepath;
        code_editor::active = code_active;
        code_editor::dirty = code_dirty;
        code_editor::scroll_y = code_scroll_y;
        file_tabs::tabs = tabs;
        file_tabs::active_tab = active_tab;
        code_editor_widget::cancel_agent_edit();
        {
            std::lock_guard<std::mutex> log_lk(output_log::mutex);
            output_log::owner_scope log_owner(15, -1);
            for (int i = 0; i < static_cast<int>(bottom_tab_t::COUNT); ++i) {
                output_log::lines[i] = log_lines[static_cast<std::size_t>(i)];
                output_log::auto_scroll[i] = log_auto_scroll[static_cast<std::size_t>(i)];
                output_log::select_all[i] = log_select_all[static_cast<std::size_t>(i)];
                ++output_log::version[i];
            }
        }
    }
};

struct temp_workspace_t {
    std::filesystem::path root;

    temp_workspace_t() {
        wchar_t tmp[MAX_PATH] = {};
        constexpr DWORD tmp_cap = static_cast<DWORD>(sizeof(tmp) / sizeof(tmp[0]));
        DWORD len = GetTempPathW(tmp_cap, tmp);
        std::filesystem::path base = (len > 0 && len < tmp_cap) ? std::filesystem::path(tmp) : std::filesystem::temp_directory_path();
        root = base / ("aida_ui_test_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(GetTickCount64()));
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
    }

    ~temp_workspace_t() {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    std::filesystem::path write_file(const char* name, const char* content) const {
        std::filesystem::path p = root / name;
        std::error_code ec;
        std::filesystem::create_directories(p.parent_path(), ec);
        std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
        ofs.write(content, static_cast<std::streamsize>(std::strlen(content)));
        ofs.close();
        return p;
    }
};

static void pass(HANDLE hf, std::atomic<int>& passed, const char* tag, const char* fmt, ...) {
    char detail[768];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);
    log_msg(hf, tag, "PASS -- %s", detail);
    passed.fetch_add(1);
}

static void fail(HANDLE hf, std::atomic<int>& failed, const char* tag, const char* fmt, ...) {
    char detail[768];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(detail, sizeof(detail), _TRUNCATE, fmt, ap);
    va_end(ap);
    log_msg(hf, tag, "FAIL -- %s", detail);
    failed.fetch_add(1);
}

static std::string row_text(const terminal_view::TerminalSession& session, std::size_t row_idx) {
    std::lock_guard<std::mutex> lk(const_cast<std::mutex&>(session.buffer_mtx));
    if (row_idx >= session.lines.size()) return {};
    std::string out;
    for (const auto& c : session.lines[row_idx]) {
        if (c.ch == '\0') break;
        out.push_back(c.ch);
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

static bool recent_contains_path(const std::string& json, const std::string& path) {
    auto parsed = nlohmann::json::parse(json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array()) return false;
    for (const auto& entry : parsed) {
        if (entry.is_string() && entry.get<std::string>() == path)
            return true;
    }
    return false;
}

static void test_file_browser_directory_and_routes(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    ui_state_guard_t guard;
    temp_workspace_t tmp;
    std::error_code ec;
    std::filesystem::create_directories(tmp.root / "subdir", ec);
    auto text = tmp.write_file("subdir/route.cpp", "int route_value = 11;\r\n");
    auto binary = tmp.write_file("payload.bin", "not-a-pe-binary");

    std::vector<FileBrowserEntry> entries_before = file_browser::entries;
    std::string current_before = file_browser::current_dir;
    int selected_before = file_browser::selected_idx;
    bool needs_before = file_browser::needs_refresh;
    char path_before[sizeof(file_browser::path_buf)] = {};
    std::memcpy(path_before, file_browser::path_buf, sizeof(path_before));

    file_browser::open_path(tmp.root.string());
    bool dir_open_ok = file_browser::current_dir == tmp.root.string()
        && std::strlen(file_browser::path_buf) > 0;
    int dir_idx = -1;
    int file_idx = -1;
    for (int i = 0; i < static_cast<int>(file_browser::entries.size()); ++i) {
        const auto& e = file_browser::entries[static_cast<std::size_t>(i)];
        if (e.is_dir && e.name == "subdir") dir_idx = i;
    }
    if (dir_idx >= 0) {
        file_browser::toggle_dir(dir_idx);
        file_browser::refresh();
    }
    dir_idx = -1;
    for (int i = 0; i < static_cast<int>(file_browser::entries.size()); ++i) {
        const auto& e = file_browser::entries[static_cast<std::size_t>(i)];
        if (e.is_dir && e.name == "subdir" && e.expanded) dir_idx = i;
        if (!e.is_dir && e.name == text.filename().string()) {
            std::error_code eq_ec;
            bool same_path = std::filesystem::equivalent(std::filesystem::path(e.full_path), text, eq_ec);
            if (same_path || std::filesystem::path(e.full_path).lexically_normal() == text.lexically_normal())
                file_idx = i;
        }
    }
    bool toggle_ok = dir_idx >= 0 && file_idx >= 0;
    bool route_class_ok = image_view::is_image_extension(".png")
        && image_view::is_image_extension(".jpg")
        && image_view::is_image_extension(".ppm")
        && !image_view::is_image_extension(".exe")
        && !image_view::is_image_extension(".bin");
    auto hex_ctx = disasm_view::capture_selected_workspace();
    hex_view::activate(hex_ctx);
    bool binary_route_seed_ok = std::filesystem::exists(binary, ec) && !ec && hex_ctx.workspace
        && hex_view::active(hex_ctx)
        && hex_view::source_name(hex_ctx) == hex_ctx.workspace->identity().bin_name()
        && hex_view::last_error(hex_ctx).empty();
    std::string current_after = file_browser::current_dir;
    std::size_t entries_after = file_browser::entries.size();

    file_browser::entries = entries_before;
    file_browser::current_dir = current_before;
    file_browser::selected_idx = selected_before;
    file_browser::needs_refresh = needs_before;
    std::memcpy(file_browser::path_buf, path_before, sizeof(path_before));

    if (dir_open_ok && dir_idx >= 0 && file_idx >= 0 && toggle_ok && route_class_ok && binary_route_seed_ok) {
        pass(hf, passed, "ui_file_browser", "directory open, tree expansion, text child discovery, image route classifier, and binary hex route load are coherent");
    } else {
        fail(hf, failed, "ui_file_browser", "dir_open_ok=%d dir_idx=%d file_idx=%d toggle_ok=%d route_class_ok=%d binary_seed=%d hex_active=%d hex_size=%zu hex_name=%s hex_err=%s current=%s entries=%zu",
            dir_open_ok ? 1 : 0,
            dir_idx,
            file_idx,
            toggle_ok ? 1 : 0,
            route_class_ok ? 1 : 0,
            binary_route_seed_ok ? 1 : 0,
            hex_view::active(hex_ctx) ? 1 : 0,
            hex_ctx.workspace ? static_cast<std::size_t>(hex_ctx.workspace->provider().size()) : 0,
            hex_view::source_name(hex_ctx).c_str(),
            hex_view::last_error(hex_ctx).c_str(),
            current_after.c_str(),
            entries_after);
    }
}

static void test_code_editor_save_find_and_diff(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    ui_state_guard_t guard;
    temp_workspace_t tmp;
    auto p = tmp.write_file("editor_workflow.cpp", "alpha\r\nbeta\r\ngamma\r\n");

    file_tabs::tabs.clear();
    file_tabs::active_tab = -1;
    file_tabs::open_or_focus(p.string(), "editor_workflow.cpp", "alpha\r\nbeta\r\ngamma\r\n");
    code_editor::load("alpha\r\nbeta edited\r\ngamma\r\n", "editor_workflow.cpp", p.string());
    code_editor::dirty = true;
    file_tabs::snapshot_active_to_tab();
    bool save_ok = code_editor::save();
    std::ifstream saved_in(p, std::ios::binary);
    std::string saved((std::istreambuf_iterator<char>(saved_in)), std::istreambuf_iterator<char>());
    bool saved_content_ok = saved.find("beta edited") != std::string::npos;

    globals::ui::find_bar_open = true;
    globals::ui::find_show_replace = true;
    globals::ui::find_case_sensitive = true;
    globals::ui::find_whole_word = false;
    globals::ui::find_regex = false;
    std::strcpy(globals::ui::find_buf, "beta");
    std::strcpy(globals::ui::replace_buf, "delta");
    std::string content = code_editor::get_content();
    globals::ui::find_match_positions.clear();
    std::size_t pos = content.find("beta");
    while (pos != std::string::npos) {
        globals::ui::find_match_positions.push_back(static_cast<int>(pos));
        pos = content.find("beta", pos + 1);
    }
    globals::ui::find_match_count = static_cast<int>(globals::ui::find_match_positions.size());
    globals::ui::find_current_match = globals::ui::find_match_count > 0 ? 0 : -1;
    bool find_state_ok = globals::ui::find_bar_open
        && globals::ui::find_show_replace
        && globals::ui::find_match_count == 1
        && globals::ui::find_current_match == 0
        && std::strcmp(globals::ui::replace_buf, "delta") == 0;

    code_editor_widget::cancel_agent_edit();
    bool diff_begin = code_editor_widget::begin_agent_edit("ui-test");
    bool diff_propose = code_editor_widget::propose_replace_range(1, 2, "beta accepted");
    int hunk_count = code_editor_widget::pending_hunk_count();
    bool diff_pending = code_editor_widget::has_pending_diff() && hunk_count > 0;
    bool diff_accept = diff_pending && code_editor_widget::accept_hunk(0);
    bool diff_resolved = false;
    if (diff_accept) {
        const auto& diff = code_editor_widget::pending_diff();
        diff_resolved = diff.active && !diff.hunks.empty() && diff.hunks[0].state == code_editor_widget::diff_hunk_state_t::accepted;
    }
    code_editor_widget::cancel_agent_edit();
    bool diff_cancelled = !code_editor_widget::has_pending_diff();

    if (save_ok && saved_content_ok && find_state_ok && diff_begin && diff_propose && diff_pending && diff_accept && diff_resolved && diff_cancelled) {
        pass(hf, passed, "ui_editor", "save-to-disk, find/replace state, and diff hunk accept/cancel workflow completed");
    } else {
        fail(hf, failed, "ui_editor", "save_ok=%d saved_content=%d find_state=%d diff_begin=%d diff_propose=%d hunk_count=%d diff_accept=%d diff_resolved=%d diff_cancelled=%d last_error=%s",
            save_ok ? 1 : 0,
            saved_content_ok ? 1 : 0,
            find_state_ok ? 1 : 0,
            diff_begin ? 1 : 0,
            diff_propose ? 1 : 0,
            hunk_count,
            diff_accept ? 1 : 0,
            diff_resolved ? 1 : 0,
            diff_cancelled ? 1 : 0,
            code_editor_widget::last_error().c_str());
    }
}

static void test_command_palette_and_center_views(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    auto t0 = std::chrono::steady_clock::now();
    ui_state_guard_t guard;
    network_view_state_guard_t network_guard;
    burp_detail_state_guard_t burp_guard;
    auto scan_hub_before = scan_hub_view::g_state;
    const auto analysis_hub_before = analysis_hub_view::active_sub_tab();
    const auto types_hub_before = types_hub_view::active_sub_tab();
    auto debugger_before = debugger_view::g_ui;
    auto aob_format_before = aob_view::g_state.active_format;
    int symbolic_tab_before = symbolic_view::active_tab();
    int stealth_tab_before = stealth_view::active_sub_tab();

    globals::ui::command_palette_open = true;
    std::strcpy(globals::ui::command_palette_buf, "network");

    const center_view_t views[] = {
        center_view_t::code_editor, center_view_t::disassembly, center_view_t::hex_view,
        center_view_t::welcome, center_view_t::settings_view, center_view_t::network_view,
        center_view_t::memory_scanner, center_view_t::debugger_view, center_view_t::pseudocode,
        center_view_t::struct_recon, center_view_t::crypto_scanner, center_view_t::aob_generator,
        center_view_t::fuzzer_view, center_view_t::xref_browser, center_view_t::snapshot_diff,
        center_view_t::pointer_scanner, center_view_t::decrypt_oracle, center_view_t::integrity_hunter,
        center_view_t::symbolic_view, center_view_t::taint_view, center_view_t::deobfuscation_view,
        center_view_t::stealth_view, center_view_t::scan_hub, center_view_t::types_hub,
        center_view_t::analysis_hub, center_view_t::binary_map, center_view_t::graph_view,
        center_view_t::image_view, center_view_t::test_lab, center_view_t::workbench
    };

    check_accum_t ck;
    ck.require(static_cast<int>(center_view_t::workbench) + 1 == static_cast<int>(std::size(views)), "center_view enum contiguous count");
    ck.require(std::size(views) == 30, "center_view inventory count");

    bool all_roundtrip = true;
    for (center_view_t v : views) {
        globals::ui::active_center_view = v;
        ck.require(center_view_name(v)[0] != '\0', "center_view label present");
        if (globals::ui::active_center_view != v) {
            all_roundtrip = false;
            break;
        }
    }
    ck.require(all_roundtrip, "center_view active route roundtrip");
    ck.require(is_scan_center_view(center_view_t::memory_scanner)
        && is_scan_center_view(center_view_t::pointer_scanner)
        && is_scan_center_view(center_view_t::integrity_hunter)
        && !is_scan_center_view(center_view_t::network_view), "scan center route family");
    ck.require(is_analysis_center_view(center_view_t::symbolic_view)
        && is_analysis_center_view(center_view_t::stealth_view)
        && !is_analysis_center_view(center_view_t::types_hub), "analysis center route family");

    constexpr int kExpectedNetworkSubtabs = 36;
    ck.require(static_cast<int>(network_view::sub_tab_t::COUNT) == kExpectedNetworkSubtabs, "network subtab count");
    for (int i = 0; i < static_cast<int>(network_view::sub_tab_t::COUNT); ++i) {
        auto tab = static_cast<network_view::sub_tab_t>(i);
        auto prev = network_view::g_state.active_tab;
        network_view::g_state.prev_tab = prev;
        network_view::g_state.active_tab = tab;
        ck.require(network_view::g_state.active_tab == tab, "network active_tab route roundtrip");
        ck.require(network_tab_name(tab)[0] != '\0', "network tab label present");
    }
    network_view::g_state.active = true;
    network_view::g_state.conn_selected = 0;
    std::strcpy(network_view::g_state.conn_filter_text, "pid:1234");
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.cap_mutex);
        network_view::g_state.captured_packets.clear();
        network_view::packet_entry_t pkt;
        pkt.pid = 1234;
        pkt.protocol = 6;
        pkt.direction = 1;
        pkt.payload = { 'G', 'E', 'T' };
        pkt.payload_size = static_cast<uint32_t>(pkt.payload.size());
        pkt.protocol_label = "HTTP";
        pkt.summary = "ui capture packet";
        network_view::g_state.captured_packets.push_back(std::move(pkt));
    }
    network_view::g_state.cap_selected = 0;
    network_view::g_state.cap_running.store(false, std::memory_order_release);
    network_view::g_state.cap_start_pending.store(false, std::memory_order_release);
    network_view::g_state.cap_stop_pending.store(false, std::memory_order_release);
    std::strcpy(network_view::g_state.cap_filter_text, "GET");
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.dns_mutex);
        network_view::g_state.dns_entries.clear();
        network_view::dns_entry_t dns;
        dns.pid = 1234;
        dns.domain = "ui.example";
        dns.resolved_addr = "127.0.0.1";
        dns.ttl = 60;
        network_view::g_state.dns_entries.push_back(std::move(dns));
    }
    network_view::g_state.dns_selected = 0;
    std::strcpy(network_view::g_state.dns_filter_text, "ui.example");
    network_view::g_state.filters.clear();
    network_view::filter_entry_t filter;
    filter.rule_id = 77;
    filter.action = 1;
    filter.direction = 2;
    filter.protocol = 6;
    filter.pid = 1234;
    filter.port = 443;
    filter.ip_addr = "127.0.0.1";
    filter.active = true;
    network_view::g_state.filters.push_back(filter);
    network_view::g_state.filter_selected = 0;
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.bw_mutex);
        network_view::g_state.bw_entries.clear();
        network_view::bw_entry_t bw;
        bw.pid = 1234;
        bw.process_name = "ui.exe";
        bw.bytes_in = 100;
        bw.bytes_out = 250;
        bw.rate_in = 1.0f;
        bw.rate_out = 2.0f;
        network_view::g_state.bw_entries.push_back(bw);
    }
    network_view::g_state.bw_selected = 0;
    network_view::g_state.repeater_entries.clear();
    auto repeater = std::make_shared<network_view::repeater_entry_t>();
    repeater->host = "127.0.0.1";
    repeater->port = 8443;
    repeater->use_tls = false;
    repeater->raw_request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    network_view::g_state.repeater_entries.push_back(repeater);
    network_view::g_state.repeater_selected = 0;
    network_view::g_state.intercept_enabled = true;
    network_view::g_state.intercept_selected = 0;
    std::strcpy(network_view::g_state.proxy_bind_addr, "127.0.0.1");
    network_view::g_state.proxy_port = 18080;
    network_view::g_state.proxy_decode_tls = false;
    network_view::g_state.proxy_selected = 0;
    std::strcpy(network_view::g_state.proxy_filter_text, "ui");
    std::strcpy(network_view::g_state.kl_exe_path, "ui-target.exe");
    std::strcpy(network_view::g_state.kl_watch_path, "C:\\Temp");
    network_view::g_state.kl_selected = 0;
    std::strcpy(network_view::g_state.pcap_path, "C:\\Temp\\ui.pcap");
    network_view::g_state.pcap_writing.store(false, std::memory_order_release);
    network_view::g_state.pcap_written_count.store(3, std::memory_order_release);
    network_view::g_state.fuzz_config.host = "localhost";
    network_view::g_state.fuzz_config.port = 8080;
    network_view::g_state.fuzz_config.base_request = "GET /FUZZ HTTP/1.1\r\nHost: localhost\r\n\r\n";
    network_view::g_state.fuzz_config.payload_sets.clear();
    network_view::payload_set_t pset;
    pset.name = "ui payloads";
    pset.entries.push_back("one");
    network_view::g_state.fuzz_config.payload_sets.push_back(std::move(pset));
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.fuzz_mutex);
        network_view::g_state.fuzz_result_pages.clear();
        network_view::g_state.fuzz_result_pending.clear();
        network_view::state_t::fuzzer_result_t fr;
        fr.index = 1;
        fr.payload_indices.push_back(0);
        fr.response_preview = "one";
        fr.status_code = 200;
        fr.match = true;
        network_view::state_t::fuzzer_result_page_t page;
        page.rows.push_back(std::move(fr));
        page.retained_bytes = page.rows.front().response_preview.size();
        network_view::g_state.fuzz_result_pages.push_back(
            std::make_shared<const network_view::state_t::fuzzer_result_page_t>(
                std::move(page)));
        network_view::g_state.fuzz_retained_count = 1;
        network_view::g_state.fuzz_results_generation++;
    }
    network_view::g_state.fuzz_selected = 0;
    network_view::g_state.fuzz_progress.store(1, std::memory_order_release);
    network_view::g_state.fuzz_total.store(1, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.ws_mutex);
        network_view::g_state.ws_frames.clear();
        network_view::state_t::ws_frame_entry_t frame;
        frame.host = "localhost";
        frame.port = 443;
        frame.is_text = true;
        frame.opcode = 1;
        frame.preview = "hello";
        network_view::g_state.ws_frames.push_back(std::move(frame));
    }
    network_view::g_state.ws_selected = 0;
    std::strcpy(network_view::g_state.ws_filter_text, "hello");
    network_view::g_state.scripts.clear();
    network_view::g_state.scripts.push_back({ "ui-script", "C:\\Temp\\ui.js", true, true });
    network_view::g_state.script_selected = 0;
    std::strcpy(network_view::g_state.script_editor_buf, "function onRequest(req) { return req; }");
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.script_log_mutex);
        network_view::g_state.script_log.clear();
        network_view::g_state.script_log.push_back("ui script log");
    }
    network_view::g_state.decoder_pipeline.clear();
    network_view::state_t::decoder_step_t step;
    step.transform_name = "base64";
    step.params.push_back({ "mode", "decode" });
    network_view::g_state.decoder_pipeline.push_back(std::move(step));
    std::strcpy(network_view::g_state.decoder_input, "dWk=");
    network_view::g_state.decoder_output = "ui";
    network_view::g_state.decoder_selected_step = 0;

    bool network_state_ok = network_view::g_state.active
        && network_view::g_state.conn_selected == 0
        && std::strcmp(network_view::g_state.conn_filter_text, "pid:1234") == 0
        && network_view::g_state.cap_selected == 0
        && !network_view::g_state.cap_running.load(std::memory_order_acquire)
        && network_view::g_state.dns_selected == 0
        && network_view::g_state.filters.size() == 1
        && network_view::g_state.filter_selected == 0
        && network_view::g_state.repeater_entries.size() == 1
        && network_view::g_state.repeater_entries[0]->host == "127.0.0.1"
        && network_view::g_state.intercept_enabled
        && network_view::g_state.proxy_port == 18080
        && network_view::g_state.pcap_written_count.load(std::memory_order_acquire) == 3
        && network_view::g_state.fuzz_config.payload_sets.size() == 1
        && network_view::g_state.fuzz_progress.load(std::memory_order_acquire) == 1
        && network_view::g_state.ws_selected == 0
        && network_view::g_state.scripts.size() == 1
        && network_view::g_state.decoder_pipeline.size() == 1
        && network_view::g_state.decoder_output == "ui";
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.cap_mutex);
        network_state_ok = network_state_ok && network_view::g_state.captured_packets.size() == 1;
    }
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.dns_mutex);
        network_state_ok = network_state_ok && network_view::g_state.dns_entries.size() == 1;
    }
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.bw_mutex);
        network_state_ok = network_state_ok && network_view::g_state.bw_entries.size() == 1;
    }
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.fuzz_mutex);
        network_state_ok = network_state_ok && network_view::g_state.fuzz_result_pages.size() == 1
            && !network_view::g_state.fuzz_result_pages.front()->rows.empty();
    }
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.ws_mutex);
        network_state_ok = network_state_ok && network_view::g_state.ws_frames.size() == 1;
    }
    {
        std::lock_guard<std::mutex> lk(network_view::g_state.script_log_mutex);
        network_state_ok = network_state_ok && network_view::g_state.script_log.size() == 1;
    }
    ck.require(network_state_ok, "network subview backing state buckets");

    {
        auto& s = aida::burp::ws_editor_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        s.active = true;
        s.scheme_idx = 0;
        s.port = 8081;
        s.selected_conn_index = 2;
        s.compose_mode_idx = 1;
        s.compose_opcode = 2;
        s.verify_tls = false;
        s.compose_fin = true;
        s.compose_masked = false;
        std::strcpy(s.host_buf, "ws.local");
        std::strcpy(s.path_buf, "/socket");
        std::strcpy(s.compose_text_buf, "ui websocket payload");
        s.last_action = "ui-ws";
        s.last_action_kind = "ok";
    }
    {
        auto& s = aida::burp::api_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        s.active = true;
        s.selected_collection_index = 1;
        s.selected_request_index = 3;
        s.import_format_idx = 2;
        s.sending.store(false, std::memory_order_release);
        s.importing.store(false, std::memory_order_release);
        s.auditing.store(false, std::memory_order_release);
        std::strcpy(s.import_url_buf, "https://api.local/openapi.json");
        std::strcpy(s.send_header_value_buf, "X-AiDA: ui");
        s.retained_exchanges.clear();
        aida::burp::api_view::retained_exchange_t exchange;
        exchange.id = 1;
        exchange.generation = 1;
        exchange.label = "ui-api";
        exchange.response_status = 204;
        exchange.response_latency_ms = 44;
        const std::string response = "HTTP/1.1 204 No Content";
        exchange.response.assign(response.begin(), response.end());
        exchange.response_size = exchange.response.size();
        s.retained_exchanges.push_back(std::move(exchange));
        s.last_action_message = "ui-api";
        s.last_action_kind = "ok";
    }
    {
        auto& s = aida::burp::logger_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        s.active = true;
        s.status_min = 200;
        s.status_max = 499;
        s.row_limit = 321;
        s.selected_row = 7;
        std::strcpy(s.method_filter_buf, "POST");
        std::strcpy(s.host_regex_buf, "local");
        std::strcpy(s.export_path_buf, "C:\\Temp\\logger.json");
        s.last_action = "ui-logger";
        s.last_action_kind = "ok";
    }
    {
        auto& s = aida::burp::report_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        s.active = true;
        s.format_idx = 1;
        s.selected_history = 4;
        s.include_evidence = false;
        s.include_remediation = true;
        s.generating.store(false, std::memory_order_release);
        std::strcpy(s.title_buf, "Ui Report");
        std::strcpy(s.output_path_buf, "C:\\Temp\\ui-report.html");
        s.last_action = "ui-report";
        s.last_action_kind = "ok";
    }
    {
        auto& s = aida::burp::graphql_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        s.active = true;
        s.active_tab = 2;
        s.depth = 4;
        s.batch_count = 9;
        s.selected_type_index = 1;
        s.selected_field_index = 2;
        s.last_status = 200;
        s.last_latency_ms = 55;
        s.introspecting.store(false, std::memory_order_release);
        s.sending.store(false, std::memory_order_release);
        std::strcpy(s.endpoint_buf, "https://api.local/graphql");
        std::strcpy(s.headers_buf, "Authorization: Bearer redacted");
        s.last_schema_raw = "type Query { ui: String }";
        s.schema_status = "loaded";
        s.query_text = "{ ui }";
        s.variables_text = "{}";
        s.last_response_raw = "{\"data\":{\"ui\":\"ok\"}}";
        s.history.clear();
        aida::burp::graphql_view::history_row_t row;
        row.endpoint = "https://api.local/graphql";
        row.query_preview = "{ ui }";
        row.status_code = 200;
        row.latency_ms = 55;
        s.history.push_back(std::move(row));
        s.history_max = 32;
    }
    bool burp_detail_state_ok = true;
    {
        auto& s = aida::burp::ws_editor_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        burp_detail_state_ok = burp_detail_state_ok
            && s.active && s.scheme_idx == 0 && s.port == 8081
            && s.selected_conn_index == 2 && s.compose_opcode == 2
            && !s.verify_tls && !s.compose_masked
            && std::strcmp(s.host_buf, "ws.local") == 0
            && std::strcmp(s.path_buf, "/socket") == 0
            && s.last_action_kind == "ok";
    }
    {
        auto& s = aida::burp::api_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        const bool retained_ok = !s.retained_exchanges.empty() &&
            s.retained_exchanges.back().response_status == 204 &&
            s.retained_exchanges.back().response_latency_ms == 44 &&
            std::string(s.retained_exchanges.back().response.begin(),
                s.retained_exchanges.back().response.end()).find("204") != std::string::npos;
        burp_detail_state_ok = burp_detail_state_ok
            && s.active && s.selected_collection_index == 1
            && s.selected_request_index == 3 && s.import_format_idx == 2
            && retained_ok
            && !s.sending.load(std::memory_order_acquire)
            && std::strcmp(s.import_url_buf, "https://api.local/openapi.json") == 0;
    }
    {
        auto& s = aida::burp::logger_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        burp_detail_state_ok = burp_detail_state_ok
            && s.active && s.status_min == 200 && s.status_max == 499
            && s.row_limit == 321 && s.selected_row == 7
            && std::strcmp(s.method_filter_buf, "POST") == 0
            && std::strcmp(s.host_regex_buf, "local") == 0;
    }
    {
        auto& s = aida::burp::report_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        burp_detail_state_ok = burp_detail_state_ok
            && s.active && s.format_idx == 1 && s.selected_history == 4
            && !s.include_evidence && s.include_remediation
            && !s.generating.load(std::memory_order_acquire)
            && std::strcmp(s.title_buf, "Ui Report") == 0;
    }
    {
        auto& s = aida::burp::graphql_view::get_state();
        std::lock_guard<std::mutex> lk(s.lock);
        burp_detail_state_ok = burp_detail_state_ok
            && s.active && s.active_tab == 2 && s.depth == 4 && s.batch_count == 9
            && s.selected_type_index == 1 && s.selected_field_index == 2
            && s.last_status == 200 && s.last_latency_ms == 55
            && !s.introspecting.load(std::memory_order_acquire)
            && !s.sending.load(std::memory_order_acquire)
            && std::strcmp(s.endpoint_buf, "https://api.local/graphql") == 0
            && s.history.size() == 1 && s.history_max == 32;
    }
    ck.require(burp_detail_state_ok, "burp detail view state transitions");

    ck.require(static_cast<int>(scan_hub_view::sub_tab_t::COUNT) == 7, "scan hub subtab count");
    for (int i = 0; i < static_cast<int>(scan_hub_view::sub_tab_t::COUNT); ++i) {
        scan_hub_view::set_sub_tab(static_cast<scan_hub_view::sub_tab_t>(i));
        ck.require(static_cast<int>(scan_hub_view::active_sub_tab()) == i, "scan hub active subtab");
        ck.require(scan_hub_view::g_state.strip.active == i, "scan hub strip active");
    }
    ck.require(static_cast<int>(analysis_hub_view::sub_tab_t::COUNT) == 5, "analysis hub subtab count");
    for (int i = 0; i < static_cast<int>(analysis_hub_view::sub_tab_t::COUNT); ++i) {
        auto tab = static_cast<analysis_hub_view::sub_tab_t>(i);
        analysis_hub_view::set_sub_tab(tab);
        ck.require(static_cast<int>(analysis_hub_view::active_sub_tab()) == i, "analysis hub active subtab");
        ck.require(analysis_hub_view::sub_tab_label(tab)[0] != '\0', "analysis hub label");
    }
    ck.require(analysis_hub_view::sub_tab_label(static_cast<analysis_hub_view::sub_tab_t>(99))[0] == '\0', "analysis hub invalid label guard");
    ck.require(static_cast<int>(types_hub_view::sub_tab_t::COUNT) == 7, "types hub subtab count");
    for (int i = 0; i < static_cast<int>(types_hub_view::sub_tab_t::COUNT); ++i) {
        auto tab = static_cast<types_hub_view::sub_tab_t>(i);
        types_hub_view::set_sub_tab(tab);
        ck.require(static_cast<int>(types_hub_view::active_sub_tab()) == i, "types hub active subtab");
        ck.require(types_hub_view::sub_tab_label(tab)[0] != '\0', "types hub label");
    }
    ck.require(types_hub_view::sub_tab_label(static_cast<types_hub_view::sub_tab_t>(99))[0] == '\0', "types hub invalid label guard");
    ck.require(static_cast<int>(debugger_view::sub_tab_t::COUNT) == 14, "debugger subtab count");
    ck.require(debugger_view::visible_sub_tab_count() == static_cast<int>(debugger_view::sub_tab_t::COUNT), "debugger visible subtab count");
    ck.require(static_cast<int>(debugger_view::g_ui.active_tab) >= 0
        && static_cast<int>(debugger_view::g_ui.active_tab) < static_cast<int>(debugger_view::sub_tab_t::COUNT), "debugger active subtab readable");
    for (int i = 0; i < static_cast<int>(debugger_view::sub_tab_t::COUNT); ++i) {
        auto prev = debugger_view::g_ui.active_tab;
        auto tab = static_cast<debugger_view::sub_tab_t>(i);
        debugger_view::g_ui.prev_tab = prev;
        debugger_view::g_ui.active_tab = tab;
        debugger_view::g_ui.list_selected = i;
        ck.require(static_cast<int>(debugger_view::g_ui.active_tab) == i, "debugger active subtab");
        ck.require(debugger_view::is_visible_sub_tab(tab), "debugger visible subtab");
        ck.require(debugger_view::g_ui.list_selected == i, "debugger list selected state");
    }
    std::strcpy(debugger_view::g_ui.add_bp_addr_buf, "401000");
    std::strcpy(debugger_view::g_ui.add_watch_buf, "rax");
    std::strcpy(debugger_view::g_ui.trace_filter_buf, "ret");
    debugger_view::g_ui.cpu_edit_reg_idx = 1;
    debugger_view::g_ui.handle_close_idx = 2;
    debugger_view::g_ui.thread_kill_tid = 33;
    ck.require(std::strcmp(debugger_view::g_ui.add_bp_addr_buf, "401000") == 0
        && std::strcmp(debugger_view::g_ui.add_watch_buf, "rax") == 0
        && std::strcmp(debugger_view::g_ui.trace_filter_buf, "ret") == 0
        && debugger_view::g_ui.cpu_edit_reg_idx == 1
        && debugger_view::g_ui.handle_close_idx == 2
        && debugger_view::g_ui.thread_kill_tid == 33, "debugger edit/guard buffers");
    ck.require(symbolic_view::tab_count() == 6, "symbolic subtab count");
    for (int i = 0; i < symbolic_view::tab_count(); ++i) {
        symbolic_view::set_active_tab(i);
        ck.require(symbolic_view::active_tab() == i, "symbolic active tab");
        ck.require(symbolic_view::tab_label(i)[0] != '\0', "symbolic tab label");
    }
    int symbolic_valid = symbolic_view::active_tab();
    symbolic_view::set_active_tab(-1);
    symbolic_view::set_active_tab(symbolic_view::tab_count());
    ck.require(symbolic_view::active_tab() == symbolic_valid, "symbolic invalid tab guard");
    ck.require(stealth_view::sub_tab_count() == 2, "stealth subtab count");
    for (int i = 0; i < stealth_view::sub_tab_count(); ++i) {
        stealth_view::set_sub_tab(i);
        ck.require(stealth_view::active_sub_tab() == i, "stealth active subtab");
        ck.require(stealth_view::sub_tab_label(i)[0] != '\0', "stealth tab label");
    }
    int stealth_valid = stealth_view::active_sub_tab();
    stealth_view::set_sub_tab(-1);
    stealth_view::set_sub_tab(stealth_view::sub_tab_count());
    ck.require(stealth_view::active_sub_tab() == stealth_valid, "stealth invalid tab guard");
    ck.require(static_cast<int>(aob_view::format_tab_t::COUNT) == 4, "aob format count");
    for (int i = 0; i < static_cast<int>(aob_view::format_tab_t::COUNT); ++i) {
        auto fmt = static_cast<aob_view::format_tab_t>(i);
        aob_view::g_state.active_format = fmt;
        ck.require(aob_view::g_state.active_format == fmt, "aob active format");
        ck.require(aob_view::detail::tab_name(fmt)[0] != '\0', "aob format label");
    }

    bool palette_ok = globals::ui::command_palette_open
        && std::strcmp(globals::ui::command_palette_buf, "network") == 0;
    globals::ui::active_center_view = center_view_t::network_view;
    globals::ui::command_palette_open = false;
    globals::ui::command_palette_buf[0] = '\0';
    bool dispatch_state_ok = globals::ui::active_center_view == center_view_t::network_view
        && !globals::ui::command_palette_open
        && globals::ui::command_palette_buf[0] == '\0';

    scan_hub_view::g_state = scan_hub_before;
    analysis_hub_view::set_sub_tab(analysis_hub_before);
    types_hub_view::set_sub_tab(types_hub_before);
    debugger_view::g_ui = debugger_before;
    aob_view::g_state.active_format = aob_format_before;
    symbolic_view::set_active_tab(symbolic_tab_before);
    stealth_view::set_sub_tab(stealth_tab_before);

    long long us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ui_commands_routes", "STATE -- ck_checks=%d ck_ok=%d palette_ok=%d dispatch_state_ok=%d roundtrip_views=%zu network_subtabs=%d failures=\"%s\" elapsed_us=%lld",
        ck.checked,
        ck.ok ? 1 : 0,
        palette_ok ? 1 : 0,
        dispatch_state_ok ? 1 : 0,
        std::size(views),
        static_cast<int>(network_view::sub_tab_t::COUNT),
        ck.failures.c_str(),
        us);
    if (palette_ok && ck.ok && dispatch_state_ok) {
        pass(hf, passed, "ui_palette_views", "command palette, %d center routes, %d network tabs, hub/debugger/emulation subviews, and backing route state invariants passed (%d checks, elapsed_us=%lld)",
            static_cast<int>(std::size(views)), static_cast<int>(network_view::sub_tab_t::COUNT), ck.checked, us);
    } else {
        fail(hf, failed, "ui_palette_views", "palette_ok=%d checks_ok=%d dispatch_state_ok=%d active_view=%d palette_open=%d query=%s checked=%d failures=%s elapsed_us=%lld",
            palette_ok ? 1 : 0,
            ck.ok ? 1 : 0,
            dispatch_state_ok ? 1 : 0,
            static_cast<int>(globals::ui::active_center_view),
            globals::ui::command_palette_open ? 1 : 0,
            globals::ui::command_palette_buf,
            ck.checked,
            ck.failures.c_str(),
            us);
    }
}

static void test_settings_sandbox_mcp_roundtrip(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    auto t0 = std::chrono::steady_clock::now();
    const auto workspace_before = g_sa_settings.workspace;
    const auto sandbox_before = g_sa_settings.sandbox;
    const auto mcp_before = g_sa_settings.mcp_client_servers;
    const bool mcp_enabled_before = g_sa_settings.mcp_enabled;
    const int mcp_port_before = g_sa_settings.mcp_port;
    const std::string marketplace_before = g_sa_settings.marketplace_installed_json;
    auto& market_view = aida::mcp_marketplace_view::state();
    const bool market_view_open_before = market_view.open.load(std::memory_order_acquire);
    const bool market_view_initialized_before = market_view.initialized.load(std::memory_order_acquire);
    char market_view_search_before[sizeof(market_view.search_buf)] = {};
    std::vector<mcp_marketplace::package_info_t> market_view_results_before;
    mcp_marketplace::search_state_t market_view_search_state_before;
    std::string market_view_error_before;
    std::string market_view_selected_before;
    bool market_view_detail_before;
    std::deque<std::string> market_view_install_log_before;
    std::string market_view_installing_before;
    bool market_view_show_log_before;
    std::string market_view_query_before;
    bool market_view_first_search_before;
    {
        std::lock_guard<std::mutex> lk(market_view.mtx);
        copy_chars(market_view_search_before, sizeof(market_view_search_before), market_view.search_buf, sizeof(market_view.search_buf));
        market_view_results_before = market_view.last_results;
        market_view_search_state_before = market_view.last_search_state;
        market_view_error_before = market_view.last_search_error;
        market_view_selected_before = market_view.selected_pkg;
        market_view_detail_before = market_view.detail_view_open;
        market_view_install_log_before = market_view.install_log;
        market_view_installing_before = market_view.installing_pkg;
        market_view_show_log_before = market_view.show_install_log;
        market_view_query_before = market_view.last_query_committed;
        market_view_first_search_before = market_view.first_search_done;
    }

    g_sa_settings.workspace.view_visibility_json = R"({"left":false,"bottom":true})";
    g_sa_settings.workspace.right_visible = true;
    g_sa_settings.workspace.legacy_bottom_visible = true;
    g_sa_settings.workspace.active_view = "network";
    g_sa_settings.sandbox.enabled = true;
    g_sa_settings.sandbox.timeout_ms = 45000;
    g_sa_settings.sandbox.memory_limit_mb = 512;
    g_sa_settings.sandbox.network_mode = "off";
    g_sa_settings.mcp_enabled = true;
    g_sa_settings.mcp_port = 29117;
    g_sa_settings.mcp_client_servers.clear();
    g_sa_settings.mcp_client_servers.push_back({ "ui-local", "http://127.0.0.1:29117/mcp", "http_sse", "", "", "", true, false });

    mcp_marketplace::load_installed(R"([{"package_name":"aida-ui-test-mcp","version":"1.0.0","registry":"npm","install_path":"C:/AiDA/Test","transport":"stdio","command":"node","args":["server.js"],"env":{"AIDA_TEST":"1"},"enabled":true,"auto_connect":false}])");
    std::string serialized_market = mcp_marketplace::save_installed();
    auto installed = mcp_marketplace::get_installed();
    {
        std::lock_guard<std::mutex> lk(market_view.mtx);
        market_view.open.store(true, std::memory_order_release);
        market_view.initialized.store(true, std::memory_order_release);
        std::strcpy(market_view.search_buf, "aida-ui");
        mcp_marketplace::package_info_t pkg;
        pkg.name = "aida-ui-test-mcp";
        pkg.display_name = "AiDA UI Test MCP";
        pkg.description = "local test package";
        pkg.version = "1.0.0";
        pkg.registry = mcp_marketplace::registry_t::npm;
        pkg.weekly_downloads = 12400;
        market_view.last_results.clear();
        market_view.last_results.push_back(pkg);
        market_view.last_search_state = mcp_marketplace::search_state_t::done;
        market_view.last_search_error.clear();
        market_view.selected_pkg = pkg.name;
        market_view.detail_view_open = true;
        market_view.install_log.clear();
        market_view.install_log.push_back("Installing aida-ui-test-mcp...");
        market_view.installing_pkg = pkg.name;
        market_view.show_install_log = true;
        market_view.last_query_committed = "aida-ui";
        market_view.first_search_done = true;
    }

    const auto workspace_visibility = nlohmann::json::parse(
        g_sa_settings.workspace.view_visibility_json, nullptr, false);
    bool workspace_ok = !workspace_visibility.is_discarded()
        && workspace_visibility.value("left", true) == false
        && workspace_visibility.value("bottom", false) == true
        && g_sa_settings.workspace.right_visible
        && g_sa_settings.workspace.legacy_bottom_visible
        && g_sa_settings.workspace.active_view == "network";
    bool sandbox_ok = g_sa_settings.sandbox.enabled
        && g_sa_settings.sandbox.timeout_ms == 45000
        && g_sa_settings.sandbox.memory_limit_mb == 512
        && g_sa_settings.sandbox.network_mode == "off";
    bool mcp_ok = g_sa_settings.mcp_enabled
        && g_sa_settings.mcp_port == 29117
        && g_sa_settings.mcp_client_servers.size() == 1
        && g_sa_settings.mcp_client_servers[0].name == "ui-local"
        && !g_sa_settings.mcp_client_servers[0].auto_connect;
    bool marketplace_ok = installed.size() == 1
        && installed[0].package_name == "aida-ui-test-mcp"
        && installed[0].args.size() == 1
        && serialized_market.find("aida-ui-test-mcp") != std::string::npos;
    bool marketplace_view_ok = false;
    {
        std::lock_guard<std::mutex> lk(market_view.mtx);
        marketplace_view_ok = aida::mcp_marketplace_view::is_open()
            && market_view.initialized.load(std::memory_order_acquire)
            && std::strcmp(market_view.search_buf, "aida-ui") == 0
            && market_view.last_results.size() == 1
            && market_view.last_results[0].name == "aida-ui-test-mcp"
            && market_view.last_search_state == mcp_marketplace::search_state_t::done
            && market_view.detail_view_open
            && market_view.selected_pkg == "aida-ui-test-mcp"
            && market_view.show_install_log
            && market_view.install_log.size() == 1
            && aida::mcp_marketplace_view::is_pkg_installed("aida-ui-test-mcp")
            && aida::mcp_marketplace_view::lower_copy("AiDA") == "aida"
            && aida::mcp_marketplace_view::format_count(12400) == "12.4K"
            && aida::mcp_marketplace_view::truncate_text("abcdef", 3) == "abc...";
    }
    bool auth_passive_ok = !aida::auth_view::any_login_in_progress();

    g_sa_settings.workspace = workspace_before;
    g_sa_settings.sandbox = sandbox_before;
    g_sa_settings.mcp_client_servers = mcp_before;
    g_sa_settings.mcp_enabled = mcp_enabled_before;
    g_sa_settings.mcp_port = mcp_port_before;
    g_sa_settings.marketplace_installed_json = marketplace_before;
    mcp_marketplace::load_installed(marketplace_before.empty() ? "[]" : marketplace_before);
    {
        std::lock_guard<std::mutex> lk(market_view.mtx);
        market_view.open.store(market_view_open_before, std::memory_order_release);
        market_view.initialized.store(market_view_initialized_before, std::memory_order_release);
        copy_chars(market_view.search_buf, sizeof(market_view.search_buf), market_view_search_before, sizeof(market_view_search_before));
        market_view.last_results = market_view_results_before;
        market_view.last_search_state = market_view_search_state_before;
        market_view.last_search_error = market_view_error_before;
        market_view.selected_pkg = market_view_selected_before;
        market_view.detail_view_open = market_view_detail_before;
        market_view.install_log = market_view_install_log_before;
        market_view.installing_pkg = market_view_installing_before;
        market_view.show_install_log = market_view_show_log_before;
        market_view.last_query_committed = market_view_query_before;
        market_view.first_search_done = market_view_first_search_before;
    }

    long long us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ui_settings_mcp", "STATE -- workspace_ok=%d sandbox_ok=%d mcp_ok=%d marketplace_ok=%d marketplace_view_ok=%d auth_passive_ok=%d installed=%zu elapsed_us=%lld",
        workspace_ok ? 1 : 0,
        sandbox_ok ? 1 : 0,
        mcp_ok ? 1 : 0,
        marketplace_ok ? 1 : 0,
        marketplace_view_ok ? 1 : 0,
        auth_passive_ok ? 1 : 0,
        installed.size(),
        us);
    if (workspace_ok && sandbox_ok && mcp_ok && marketplace_ok && marketplace_view_ok && auth_passive_ok) {
        pass(hf, passed, "ui_settings_mcp", "workspace, sandbox, MCP client, marketplace storage, marketplace modal state, and passive auth state round-tripped in memory (elapsed_us=%lld)", us);
    } else {
        fail(hf, failed, "ui_settings_mcp", "workspace_ok=%d sandbox_ok=%d mcp_ok=%d marketplace_ok=%d marketplace_view_ok=%d auth_passive_ok=%d installed=%zu serialized=%s elapsed_us=%lld",
            workspace_ok ? 1 : 0,
            sandbox_ok ? 1 : 0,
            mcp_ok ? 1 : 0,
            marketplace_ok ? 1 : 0,
            marketplace_view_ok ? 1 : 0,
            auth_passive_ok ? 1 : 0,
            installed.size(),
            serialized_market.c_str(),
            us);
    }
}

static void test_center_view_file_open(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    ui_state_guard_t guard;
    temp_workspace_t tmp;
    auto p = tmp.write_file("ui_center.cpp", "int ui_center = 7;\r\n");
    const int tab_before = static_cast<int>(file_tabs::tabs.size());

    file_browser::open_path(p.string());

    bool tab_added = static_cast<int>(file_tabs::tabs.size()) == tab_before + 1;
    bool center_ok = globals::ui::active_center_view == center_view_t::code_editor;
    bool editor_ok = code_editor::active && code_editor::filepath == p.string() && code_editor::get_content().find("ui_center") != std::string::npos;
    bool active_tab_ok = file_tabs::active_tab >= 0
        && file_tabs::active_tab < static_cast<int>(file_tabs::tabs.size())
        && file_tabs::tabs[static_cast<std::size_t>(file_tabs::active_tab)].filepath == p.string();

    if (tab_added && center_ok && editor_ok && active_tab_ok) {
        pass(hf, passed, "ui_center", "file_browser::open_path selected code editor, opened tab, and loaded temp text file");
    } else {
        fail(hf, failed, "ui_center", "tab_added=%d center=%d editor_ok=%d active_tab_ok=%d active_tab=%d tabs=%zu path=%s",
            tab_added ? 1 : 0,
            static_cast<int>(globals::ui::active_center_view),
            editor_ok ? 1 : 0,
            active_tab_ok ? 1 : 0,
            file_tabs::active_tab,
            file_tabs::tabs.size(),
            code_editor::filepath.c_str());
    }
}

static void test_file_tab_lifecycle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    ui_state_guard_t guard;
    temp_workspace_t tmp;
    auto a = tmp.write_file("ui_tab_a.txt", "alpha\r\n");
    auto b = tmp.write_file("ui_tab_b.txt", "beta\r\n");

    file_tabs::tabs.clear();
    file_tabs::active_tab = -1;
    code_editor::active = false;
    code_editor::buffer.clear();
    code_editor::filename.clear();
    code_editor::filepath.clear();
    code_editor::dirty = false;

    file_tabs::open_or_focus(a.string(), "ui_tab_a.txt", "alpha\r\n");
    code_editor::load("alpha changed\r\n", "ui_tab_a.txt", a.string());
    code_editor::dirty = true;
    file_tabs::open_or_focus(b.string(), "ui_tab_b.txt", "beta\r\n");
    file_tabs::switch_to(0);
    bool switched_back = file_tabs::active_tab == 0
        && code_editor::filepath == a.string()
        && code_editor::get_content() == "alpha changed\r\n"
        && code_editor::dirty;
    file_tabs::close_tab(0);
    bool closed_active = file_tabs::tabs.size() == 1
        && file_tabs::active_tab == 0
        && code_editor::filepath == b.string()
        && code_editor::get_content() == "beta\r\n";
    file_tabs::close_tab(0);
    bool cleared = file_tabs::tabs.empty()
        && file_tabs::active_tab == -1
        && !code_editor::active
        && code_editor::buffer.empty()
        && code_editor::filepath.empty();

    if (switched_back && closed_active && cleared) {
        pass(hf, passed, "ui_tabs", "open_or_focus, snapshot, switch_to, close active, and close final tab all preserved editor state");
    } else {
        fail(hf, failed, "ui_tabs", "switched_back=%d closed_active=%d cleared=%d tabs=%zu active_tab=%d editor_active=%d editor_path=%s",
            switched_back ? 1 : 0,
            closed_active ? 1 : 0,
            cleared ? 1 : 0,
            file_tabs::tabs.size(),
            file_tabs::active_tab,
            code_editor::active ? 1 : 0,
            code_editor::filepath.c_str());
    }
}

static void test_activity_search_recent(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    ui_state_guard_t guard;
    temp_workspace_t tmp;
    auto p = tmp.write_file("recent_target.exe", "MZ");

    workspace_search::g_search.panel_open = true;
    std::strcpy(workspace_search::g_search.query_buf, "Needle");
    std::strcpy(workspace_search::g_search.include_buf, "*.cpp,*.h");
    std::strcpy(workspace_search::g_search.exclude_buf, "build,*_generated.h");
    workspace_search::g_search.case_sensitive = true;
    workspace_search::g_search.whole_word = true;
    workspace_search::g_search.use_regex = false;
    {
        std::lock_guard<std::mutex> lk(workspace_search::g_search.results_mtx);
        workspace_search::g_search.results.clear();
        workspace_search::g_search.results.push_back({ p.string(), p.filename().string(), 1, 3, 9, "int Needle = 1;" });
        workspace_search::g_search.selected_idx = 0;
    }
    workspace_search::g_search.files_scanned.store(1, std::memory_order_release);
    workspace_search::g_search.match_count.store(1, std::memory_order_release);

    file_browser::record_recent_workspace(p.string());
    bool search_state_ok = workspace_search::g_search.panel_open
        && std::strcmp(workspace_search::g_search.query_buf, "Needle") == 0
        && workspace_search::g_search.case_sensitive
        && workspace_search::g_search.whole_word
        && !workspace_search::g_search.use_regex
        && workspace_search::g_search.selected_idx == 0
        && workspace_search::g_search.match_count.load(std::memory_order_acquire) == 1;
    bool recent_ok = recent_contains_path(g_sa_settings.recent_workspaces_json, p.string());

    if (search_state_ok && recent_ok) {
        pass(hf, passed, "ui_activity", "search panel state, result selection, recent workspace recording, and recent rail selection are coherent");
    } else {
        fail(hf, failed, "ui_activity", "search_state_ok=%d recent_ok=%d recent_json=%s query=%s selected=%d matches=%d",
            search_state_ok ? 1 : 0,
            recent_ok ? 1 : 0,
            g_sa_settings.recent_workspaces_json.c_str(),
            workspace_search::g_search.query_buf,
            workspace_search::g_search.selected_idx,
            workspace_search::g_search.match_count.load(std::memory_order_acquire));
    }
}

static void test_bottom_log_tabs(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    auto t0 = std::chrono::steady_clock::now();
    ui_state_guard_t guard;
    for (int i = 0; i < static_cast<int>(bottom_tab_t::COUNT); ++i)
        output_log::clear(static_cast<bottom_tab_t>(i));

    output_log::push(bottom_tab_t::output, "output ui log");
    output_log::push(bottom_tab_t::mcp_log, "mcp ui log");
    output_log::push(bottom_tab_t::driver_log, "driver ui log");
    output_log::push(bottom_tab_t::sandbox_log, "sandbox ui log");
    output_log::push(bottom_tab_t::terminal, "terminal must not enter output_log");
    output_log::set_select_all(bottom_tab_t::driver_log, true);
    output_log::clear(bottom_tab_t::driver_log);

    size_t output_count = output_log::size(bottom_tab_t::output);
    size_t mcp_count = output_log::size(bottom_tab_t::mcp_log);
    size_t driver_count = output_log::size(bottom_tab_t::driver_log);
    size_t sandbox_count = output_log::size(bottom_tab_t::sandbox_log);
    size_t terminal_count = output_log::size(bottom_tab_t::terminal);
    bool lines_ok = output_count == 1
        && mcp_count == 1
        && driver_count == 0
        && sandbox_count == 1
        && terminal_count == 0;
    bool clear_ok = !output_log::is_select_all(bottom_tab_t::driver_log);
    bool tab_ok = true;

    long long us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ui_bottom", "STATE -- output=%zu mcp=%zu driver=%zu sandbox=%zu terminal=%zu clear_ok=%d tab_ok=%d lines_ok=%d elapsed_us=%lld",
        output_count,
        mcp_count,
        driver_count,
        sandbox_count,
        terminal_count,
        clear_ok ? 1 : 0,
        tab_ok ? 1 : 0,
        lines_ok ? 1 : 0,
        us);
    if (lines_ok && clear_ok && tab_ok) {
        pass(hf, passed, "ui_bottom", "bottom log tabs accepted per-tab output, ignored terminal log push, and clear reset selection (elapsed_us=%lld)", us);
    } else {
        fail(hf, failed, "ui_bottom", "lines_ok=%d clear_ok=%d tab_ok=%d output=%zu mcp=%zu driver=%zu sandbox=%zu terminal=%zu elapsed_us=%lld",
            lines_ok ? 1 : 0,
            clear_ok ? 1 : 0,
            tab_ok ? 1 : 0,
            output_count,
            mcp_count,
            driver_count,
            sandbox_count,
            terminal_count,
            us);
    }
}

static void test_terminal_buffer_lifecycle(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    auto t0 = std::chrono::steady_clock::now();
    terminal_view::TerminalSession session;
    session.cols = 32;
    session.rows_vis = 8;
    const char* payload = "one\r\ntwo\x1b[31m red\x1b[0m\r\n";
    terminal_view::process_output(session, payload, std::strlen(payload));
    std::string first = row_text(session, 0);
    std::string second = row_text(session, 1);
    bool parsed = first.find("one") != std::string::npos
        && second.find("two red") != std::string::npos
        && session.lines.size() >= 2
        && session.cursor_row >= 1;
    terminal_view::clear_session(session);
    bool cleared = session.lines.empty()
        && session.line_entrance_time.empty()
        && session.cursor_row == 0
        && session.cursor_col == 0
        && session.scroll_y == 0.f
        && session.scroll_to_bottom
        && session.auto_follow
        && session.prev_line_count == 0;
    terminal_view::TerminalManager mgr;
    bool manager_empty = !mgr.has_active() && mgr.current() == nullptr && mgr.active_tab == -1;
    mgr.shutdown();
    bool manager_shutdown = mgr.sessions.empty() && mgr.active_tab == -1;

    long long us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ui_terminal", "STATE -- parsed=%d cleared=%d manager_empty=%d manager_shutdown=%d lines=%zu cursor_row=%d elapsed_us=%lld",
        parsed ? 1 : 0,
        cleared ? 1 : 0,
        manager_empty ? 1 : 0,
        manager_shutdown ? 1 : 0,
        session.lines.size(),
        session.cursor_row,
        us);
    if (parsed && cleared && manager_empty && manager_shutdown) {
        pass(hf, passed, "ui_terminal", "terminal parser, clear_session, and empty manager lifecycle work without spawning a shell (elapsed_us=%lld)", us);
    } else {
        fail(hf, failed, "ui_terminal", "parsed=%d cleared=%d manager_empty=%d manager_shutdown=%d first=\"%s\" second=\"%s\" lines=%zu cursor_row=%d elapsed_us=%lld",
            parsed ? 1 : 0,
            cleared ? 1 : 0,
            manager_empty ? 1 : 0,
            manager_shutdown ? 1 : 0,
            first.c_str(),
            second.c_str(),
            session.lines.size(),
            session.cursor_row,
            us);
    }
}

static void test_testlab_view_state(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed) {
    auto t0 = std::chrono::steady_clock::now();
    ui_state_guard_t guard;
    globals::ui::active_center_view = center_view_t::test_lab;
    globals::ui::test_all_visible = true;
    globals::ui::status_file_info = "ui-test-file";
    set_progress_step("ui coverage phase");
    char snap[1200] = {};
    format_debug_snapshot(snap, sizeof(snap));

    bool view_ok = globals::ui::active_center_view == center_view_t::test_lab && globals::ui::test_all_visible;
    bool snapshot_ok = std::strstr(snap, "ui coverage phase") != nullptr
        && std::strstr(snap, "running=") != nullptr
        && std::strstr(snap, "pass=") != nullptr
        && std::strstr(snap, "fail=") != nullptr;
    bool running_ok = is_running() && std::strstr(snap, "running=1") != nullptr;

    long long us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count();
    log_msg(hf, "ui_testlab", "STATE -- view_ok=%d snapshot_ok=%d running_ok=%d elapsed_us=%lld",
        view_ok ? 1 : 0,
        snapshot_ok ? 1 : 0,
        running_ok ? 1 : 0,
        us);
    if (view_ok && snapshot_ok && running_ok) {
        pass(hf, passed, "ui_testlab", "Test Lab center view state, overlay visibility, progress step, running state, and debug snapshot are readable (elapsed_us=%lld)", us);
    } else {
        fail(hf, failed, "ui_testlab", "view_ok=%d snapshot_ok=%d running_ok=%d snapshot=%s elapsed_us=%lld",
            view_ok ? 1 : 0,
            snapshot_ok ? 1 : 0,
            running_ok ? 1 : 0,
            snap,
            us);
    }
}

}

using ui_phase_step_fn_t = void(*)(HANDLE, std::atomic<int>&, std::atomic<int>&);

struct ui_phase_step_t {
    const char* tag;
    ui_phase_step_fn_t fn;
};

static constexpr ui_phase_step_t k_ui_phase_steps[] = {
    { "ui_center", test_center_view_file_open },
    { "ui_file_browser", test_file_browser_directory_and_routes },
    { "ui_tabs", test_file_tab_lifecycle },
    { "ui_editor", test_code_editor_save_find_and_diff },
    { "ui_activity", test_activity_search_recent },
    { "ui_commands_routes", test_command_palette_and_center_views },
    { "ui_bottom", test_bottom_log_tabs },
    { "ui_terminal", test_terminal_buffer_lifecycle },
    { "ui_settings_mcp", test_settings_sandbox_mcp_roundtrip },
    { "ui_testlab", test_testlab_view_state },
};

static constexpr std::size_t k_ui_phase_step_count = sizeof(k_ui_phase_steps) / sizeof(k_ui_phase_steps[0]);

static bool run_ui_phase_step(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::size_t step_index, bool(*cancelled)(), std::uint64_t job_id) {
    if (step_index >= k_ui_phase_step_count)
        return false;
    const auto& step = k_ui_phase_steps[step_index];
    const int ordinal = static_cast<int>(step_index + 1);
    g_ui_phase_active_step_index.store(ordinal, std::memory_order_release);
    g_ui_phase_active_step_name.store(step.tag, std::memory_order_release);
    if (cancelled && cancelled()) {
        log_msg(hf, "ui_phase", "cancel before job=%llu idx=%d name=%s tid=%lu",
            static_cast<unsigned long long>(job_id),
            ordinal,
            step.tag,
            static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    const int pass_before = passed.load(std::memory_order_acquire);
    const int fail_before = failed.load(std::memory_order_acquire);
    const std::uint64_t started = ui_now_ms();
    log_msg(hf, "ui_phase", "BEGIN job=%llu idx=%d name=%s tid=%lu pass=%d fail=%d",
        static_cast<unsigned long long>(job_id),
        ordinal,
        step.tag,
        static_cast<unsigned long>(GetCurrentThreadId()),
        pass_before,
        fail_before);
    step.fn(hf, passed, failed);
    const std::uint64_t elapsed = ui_now_ms() - started;
    g_ui_phase_last_job_run_ms.store(elapsed, std::memory_order_release);
    const int pass_after = passed.load(std::memory_order_acquire);
    const int fail_after = failed.load(std::memory_order_acquire);
    log_msg(hf, "ui_phase", "END job=%llu idx=%d name=%s tid=%lu elapsed_ms=%llu pass_delta=%d fail_delta=%d pass=%d fail=%d",
        static_cast<unsigned long long>(job_id),
        ordinal,
        step.tag,
        static_cast<unsigned long>(GetCurrentThreadId()),
        static_cast<unsigned long long>(elapsed),
        pass_after - pass_before,
        fail_after - fail_before,
        pass_after,
        fail_after);
    return true;
}

static void phase_ui_tests_inline(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    (void)skipped;
    const DWORD tid = GetCurrentThreadId();
    log_msg(hf, "ui_phase", "running standalone UI state/workflow tests tid=%lu",
        static_cast<unsigned long>(tid));

    g_ui_phase_active_job_id.store(0, std::memory_order_release);
    g_ui_phase_active_worker_tid.store(0, std::memory_order_release);
    for (std::size_t i = 0; i < k_ui_phase_step_count; ++i) {
        const bool ran = run_ui_phase_step(hf, passed, failed, i, cancelled, 0);
        if (!ran)
            break;
        g_ui_phase_steps_processed_total.fetch_add(1u, std::memory_order_acq_rel);
    }
    g_ui_phase_active_step_index.store(-1, std::memory_order_release);
    g_ui_phase_active_step_name.store("<idle>", std::memory_order_release);
}

static void fail_pending_ui_dispatch(HANDLE hf, std::atomic<int>& failed, const char* reason, DWORD worker_tid, DWORD ui_tid, std::uint64_t elapsed_ms) {
    char snap[1200] = {};
    test_all_features::format_debug_snapshot(snap, sizeof(snap));
    fail(hf, failed, "ui_dispatch", "render-thread dispatch failed reason=%s worker_tid=%lu ui_tid=%lu elapsed_ms=%llu snapshot=%s",
        reason ? reason : "unknown",
        static_cast<unsigned long>(worker_tid),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long long>(elapsed_ms),
        snap);
    failed.fetch_add(9, std::memory_order_acq_rel);
}

static void decrement_ui_phase_pending()
{
    std::size_t current = g_ui_phase_pending_jobs.load(std::memory_order_acquire);
    while (current != 0) {
        if (g_ui_phase_pending_jobs.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel))
            break;
    }
    g_ui_phase_last_pending_count.store(g_ui_phase_pending_jobs.load(std::memory_order_acquire), std::memory_order_release);
}

static void mark_ui_phase_job_done_locked(const std::shared_ptr<ui_phase_job_t>& job, DWORD ui_tid)
{
    if (!job || job->done)
        return;
    job->done = true;
    job->finished_ms = ui_now_ms();
    if (ui_tid != 0)
        job->ui_tid = ui_tid;
    decrement_ui_phase_pending();
}

static void run_ui_phase_dispatch_job(std::shared_ptr<ui_phase_job_t> job);

static bool post_ui_phase_dispatch_job(const std::shared_ptr<ui_phase_job_t>& job, const char* phase)
{
    if (!job)
        return false;
    aida::ui_thread::post_options_t options;
    options.subsystem = "testlab";
    options.label = "ui_phase";
    options.phase = phase ? phase : "<none>";
    options.owner = "testlab";
    options.priority = aida::ui_thread::priority_t::high;
    options.deadline_ms = ui_now_ms() + 15000ULL;
    options.cancelled = [job]() {
        std::lock_guard<std::mutex> lk(g_ui_phase_mtx);
        return !job || job->dispatch_cancelled || job->done || (job->cancelled && job->cancelled());
    };
    const aida::ui_thread::enqueue_result_t result = aida::ui_thread::post([job]() {
        run_ui_phase_dispatch_job(job);
    }, std::move(options));
    const bool posted = result == aida::ui_thread::enqueue_result_t::accepted;
    std::uint64_t id = 0;
    DWORD worker_tid = 0;
    DWORD ui_tid = 0;
    bool started = false;
    bool done = false;
    bool dispatch_cancelled = false;
    {
        std::lock_guard<std::mutex> lk(g_ui_phase_mtx);
        id = job->id;
        worker_tid = job->worker_tid;
        ui_tid = job->ui_tid;
        started = job->started;
        done = job->done;
        dispatch_cancelled = job->dispatch_cancelled;
    }
    diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
        "post phase=%s posted=%d result=%s job=%llu worker_tid=%lu ui_tid=%lu pending=%llu dispatcher_pending=%zu started=%d done=%d cancelled=%d",
        phase ? phase : "<none>",
        posted ? 1 : 0,
        aida::ui_thread::result_name(result),
        static_cast<unsigned long long>(id),
        static_cast<unsigned long>(worker_tid),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)),
        aida::ui_thread::pending_count(),
        started ? 1 : 0,
        done ? 1 : 0,
        dispatch_cancelled ? 1 : 0);
    return posted;
}

static void reset_ui_phase_active_state()
{
    g_ui_phase_active_job_id.store(0, std::memory_order_release);
    g_ui_phase_active_worker_tid.store(0, std::memory_order_release);
    g_ui_phase_active_step_index.store(-1, std::memory_order_release);
    g_ui_phase_active_step_name.store("<idle>", std::memory_order_release);
}

static void run_ui_phase_dispatch_job(std::shared_ptr<ui_phase_job_t> job)
{
    const DWORD ui_tid = GetCurrentThreadId();
    g_ui_phase_thread_id.store(ui_tid, std::memory_order_release);
    aida::ui_thread::capture_owner_tid(ui_tid, "testlab", "ui_phase", "dispatch_run");
    if (!aida::ui_thread::require_owner("testlab", "ui_phase", "dispatch_run"))
        return;
    const std::uint64_t pump_seq = g_ui_phase_last_pump_seq.fetch_add(1, std::memory_order_acq_rel) + 1;
    const std::uint64_t pump_start = ui_now_ms();
    if (!job) {
        g_ui_phase_skipped_no_job_count.fetch_add(1u, std::memory_order_acq_rel);
        diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
            "discard_null seq=%llu ui_tid=%lu",
            static_cast<unsigned long long>(pump_seq),
            static_cast<unsigned long>(ui_tid));
        return;
    }

    std::size_t step_index = 0;
    std::size_t remaining_before = 0;
    std::uint64_t wait_ms = 0;
    {
        std::unique_lock<std::mutex> lk(g_ui_phase_mtx);
        remaining_before = g_ui_phase_pending_jobs.load(std::memory_order_acquire);
        g_ui_phase_last_pending_count.store(remaining_before, std::memory_order_release);
        if (job->done) {
            lk.unlock();
            g_ui_phase_skipped_no_job_count.fetch_add(1u, std::memory_order_acq_rel);
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "discard_stale_done seq=%llu job=%llu ui_tid=%lu pending=%llu",
                static_cast<unsigned long long>(pump_seq),
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(ui_tid),
                static_cast<unsigned long long>(remaining_before));
            return;
        }
        if (job->dispatch_cancelled || (job->cancelled && job->cancelled())) {
            job->dispatch_cancelled = true;
            mark_ui_phase_job_done_locked(job, ui_tid);
            reset_ui_phase_active_state();
            lk.unlock();
            g_ui_phase_cv.notify_all();
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "discard_cancelled_before_start seq=%llu job=%llu ui_tid=%lu worker_tid=%lu pending=%llu",
                static_cast<unsigned long long>(pump_seq),
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(ui_tid),
                static_cast<unsigned long>(job->worker_tid),
                static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)));
            return;
        }
        if (!job->started) {
            job->started = true;
            job->started_ms = ui_now_ms();
        }
        job->ui_tid = ui_tid;
        wait_ms = job->started_ms >= job->queued_ms ? job->started_ms - job->queued_ms : 0;
        g_ui_phase_last_job_wait_ms.store(wait_ms, std::memory_order_release);
        g_ui_phase_active_job_id.store(job->id, std::memory_order_release);
        g_ui_phase_active_worker_tid.store(job->worker_tid, std::memory_order_release);
        step_index = job->next_step;
        if (step_index < k_ui_phase_step_count) {
            g_ui_phase_active_step_index.store(static_cast<int>(step_index + 1), std::memory_order_release);
            g_ui_phase_active_step_name.store(k_ui_phase_steps[step_index].tag, std::memory_order_release);
        } else {
            g_ui_phase_active_step_index.store(-1, std::memory_order_release);
            g_ui_phase_active_step_name.store("<complete>", std::memory_order_release);
        }
    }
    g_ui_phase_cv.notify_all();

    log_msg(job->hf, "ui_phase", "dispatcher job step start seq=%llu job=%llu ui_tid=%lu worker_tid=%lu wait_ms=%llu pending=%llu next_step=%llu",
        static_cast<unsigned long long>(pump_seq),
        static_cast<unsigned long long>(job->id),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long>(job->worker_tid),
        static_cast<unsigned long long>(wait_ms),
        static_cast<unsigned long long>(remaining_before),
        static_cast<unsigned long long>(step_index + 1));
    diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
        "step_start seq=%llu job=%llu ui_tid=%lu worker_tid=%lu wait_ms=%llu pending=%llu step=%llu/%llu name=%s dispatcher_pending=%zu",
        static_cast<unsigned long long>(pump_seq),
        static_cast<unsigned long long>(job->id),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long>(job->worker_tid),
        static_cast<unsigned long long>(wait_ms),
        static_cast<unsigned long long>(remaining_before),
        static_cast<unsigned long long>(step_index + 1),
        static_cast<unsigned long long>(k_ui_phase_step_count),
        step_index < k_ui_phase_step_count ? k_ui_phase_steps[step_index].tag : "<complete>",
        aida::ui_thread::pending_count());

    bool finished = false;
    bool requeue = false;
    bool ran_step = false;
    const std::uint64_t run_start = ui_now_ms();
    if (job->passed && job->failed && job->skipped) {
        try {
            aida::diagnostic_exception_scope::scope_t exception_scope("test_all_features.ui_dispatcher.run_ui_phase_step");
            if (step_index < k_ui_phase_step_count) {
                ran_step = run_ui_phase_step(job->hf, *job->passed, *job->failed, step_index, job->cancelled, job->id);
            } else {
                finished = true;
            }
        } catch (...) {
            fail_pending_ui_dispatch(job->hf, *job->failed, "cpp_exception", job->worker_tid, ui_tid, 0);
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "step_cpp_exception seq=%llu job=%llu ui_tid=%lu worker_tid=%lu step=%llu",
                static_cast<unsigned long long>(pump_seq),
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(ui_tid),
                static_cast<unsigned long>(job->worker_tid),
                static_cast<unsigned long long>(step_index + 1));
            finished = true;
        }
    } else {
        if (job->failed)
            fail_pending_ui_dispatch(job->hf, *job->failed, "bad_job_state", job->worker_tid, ui_tid, 0);
        finished = true;
    }

    const std::uint64_t run_elapsed = ui_now_ms() - run_start;
    g_ui_phase_last_job_run_ms.store(run_elapsed, std::memory_order_release);
    if (!finished) {
        std::unique_lock<std::mutex> lk(g_ui_phase_mtx);
        if (job->done) {
            finished = true;
        } else if (job->dispatch_cancelled || (job->cancelled && job->cancelled())) {
            job->dispatch_cancelled = true;
            mark_ui_phase_job_done_locked(job, ui_tid);
            reset_ui_phase_active_state();
            finished = true;
        } else {
            if (ran_step && job->next_step == step_index) {
                ++job->next_step;
                ++job->processed_steps;
                g_ui_phase_steps_processed_total.fetch_add(1u, std::memory_order_acq_rel);
            } else if (!ran_step) {
                finished = true;
            }
            if (!finished && job->next_step >= k_ui_phase_step_count)
                finished = true;
            if (finished) {
                mark_ui_phase_job_done_locked(job, ui_tid);
                reset_ui_phase_active_state();
            } else {
                requeue = true;
                g_ui_phase_skipped_by_budget_count.fetch_add(1u, std::memory_order_acq_rel);
                if (job->next_step < k_ui_phase_step_count) {
                    g_ui_phase_active_step_index.store(static_cast<int>(job->next_step + 1), std::memory_order_release);
                    g_ui_phase_active_step_name.store(k_ui_phase_steps[job->next_step].tag, std::memory_order_release);
                }
                g_ui_phase_active_job_id.store(0, std::memory_order_release);
                g_ui_phase_active_worker_tid.store(0, std::memory_order_release);
            }
        }
    } else {
        std::unique_lock<std::mutex> lk(g_ui_phase_mtx);
        mark_ui_phase_job_done_locked(job, ui_tid);
        reset_ui_phase_active_state();
    }
    g_ui_phase_cv.notify_all();

    if (requeue && !post_ui_phase_dispatch_job(job, "requeue")) {
        std::unique_lock<std::mutex> lk(g_ui_phase_mtx);
        if (!job->done) {
            if (job->failed)
                fail_pending_ui_dispatch(job->hf, *job->failed, "dispatcher_requeue_failed", job->worker_tid, ui_tid, 0);
            mark_ui_phase_job_done_locked(job, ui_tid);
            reset_ui_phase_active_state();
        }
        lk.unlock();
        g_ui_phase_cv.notify_all();
    }

    const std::uint64_t pump_wall = ui_now_ms() - pump_start;
    g_ui_phase_last_pump_wall_ms.store(pump_wall, std::memory_order_release);
    log_msg(job->hf, "ui_phase", "dispatcher job step end seq=%llu job=%llu ui_tid=%lu worker_tid=%lu run_ms=%llu wall_ms=%llu finished=%d requeued=%d ran_step=%d next_step=%llu pending=%llu",
        static_cast<unsigned long long>(pump_seq),
        static_cast<unsigned long long>(job->id),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long>(job->worker_tid),
        static_cast<unsigned long long>(run_elapsed),
        static_cast<unsigned long long>(pump_wall),
        finished ? 1 : 0,
        requeue ? 1 : 0,
        ran_step ? 1 : 0,
        static_cast<unsigned long long>(job->next_step + 1),
        static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)));
    diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
        "step_end seq=%llu job=%llu ui_tid=%lu worker_tid=%lu run_ms=%llu wall_ms=%llu finished=%d requeued=%d ran_step=%d next_step=%llu pending=%llu dispatcher_pending=%zu skipped_budget=%llu processed_total=%llu",
        static_cast<unsigned long long>(pump_seq),
        static_cast<unsigned long long>(job->id),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long>(job->worker_tid),
        static_cast<unsigned long long>(run_elapsed),
        static_cast<unsigned long long>(pump_wall),
        finished ? 1 : 0,
        requeue ? 1 : 0,
        ran_step ? 1 : 0,
        static_cast<unsigned long long>(job->next_step + 1),
        static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)),
        aida::ui_thread::pending_count(),
        static_cast<unsigned long long>(g_ui_phase_skipped_by_budget_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_steps_processed_total.load(std::memory_order_acquire)));
}

void phase_ui_tests(HANDLE hf, std::atomic<int>& passed, std::atomic<int>& failed, std::atomic<int>& skipped, bool(*cancelled)()) {
    const DWORD current_tid = GetCurrentThreadId();
    DWORD window_tid = 0;
    if (g_hwnd)
        window_tid = GetWindowThreadProcessId(g_hwnd, nullptr);
    DWORD ui_tid = aida::ui_thread::owner_tid();
    if (ui_tid == 0)
        ui_tid = g_ui_phase_thread_id.load(std::memory_order_acquire);
    if (ui_tid == 0 && window_tid != 0)
        ui_tid = window_tid;
    if (ui_tid != 0 && ui_tid == current_tid) {
        g_ui_phase_thread_id.store(current_tid, std::memory_order_release);
        aida::ui_thread::capture_owner_tid(current_tid, "testlab", "ui_phase", "inline");
        if (!aida::ui_thread::require_owner("testlab", "ui_phase", "inline"))
            return;
        log_msg(hf, "ui_phase", "dispatch inline on ui thread tid=%lu",
            static_cast<unsigned long>(current_tid));
        phase_ui_tests_inline(hf, passed, failed, skipped, cancelled);
        return;
    }

    auto job = std::make_shared<ui_phase_job_t>();
    job->id = g_ui_phase_next_job_id.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    job->hf = hf;
    job->passed = &passed;
    job->failed = &failed;
    job->skipped = &skipped;
    job->cancelled = cancelled;
    job->worker_tid = current_tid;
    job->ui_tid = ui_tid;
    job->queued_ms = ui_now_ms();

    const std::size_t pending_after_add = g_ui_phase_pending_jobs.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    g_ui_phase_last_pending_count.store(pending_after_add, std::memory_order_release);
    const bool posted = post_ui_phase_dispatch_job(job, "initial");
    if (!posted) {
        decrement_ui_phase_pending();
        fail_pending_ui_dispatch(hf, failed, "dispatcher_post_failed", current_tid, ui_tid, 0);
        diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
            "post_failed job=%llu worker_tid=%lu known_ui_tid=%lu pending=%llu dispatcher_pending=%zu",
            static_cast<unsigned long long>(job->id),
            static_cast<unsigned long>(current_tid),
            static_cast<unsigned long>(ui_tid),
            static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)),
            aida::ui_thread::pending_count());
        return;
    }

    constexpr std::uint64_t kDispatchPickupTimeoutMs = 15000;
    log_msg(hf, "ui_phase", "queued dispatcher UI tests job=%llu worker_tid=%lu known_ui_tid=%lu pending=%llu pickup_timeout_ms=%llu",
        static_cast<unsigned long long>(job->id),
        static_cast<unsigned long>(current_tid),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long long>(pending_after_add),
        static_cast<unsigned long long>(kDispatchPickupTimeoutMs));
    diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
        "queued job=%llu worker_tid=%lu known_ui_tid=%lu pending=%llu dispatcher_pending=%zu pickup_timeout_ms=%llu",
        static_cast<unsigned long long>(job->id),
        static_cast<unsigned long>(current_tid),
        static_cast<unsigned long>(ui_tid),
        static_cast<unsigned long long>(pending_after_add),
        aida::ui_thread::pending_count(),
        static_cast<unsigned long long>(kDispatchPickupTimeoutMs));

    std::unique_lock<std::mutex> lk(g_ui_phase_mtx);
    for (;;) {
        if (job->done) {
            std::uint64_t elapsed = job->finished_ms >= job->queued_ms ? job->finished_ms - job->queued_ms : 0;
            DWORD actual_ui_tid = job->ui_tid;
            const std::uint64_t steps = job->processed_steps;
            lk.unlock();
            log_msg(hf, "ui_phase", "dispatcher UI tests complete job=%llu worker_tid=%lu ui_tid=%lu elapsed_ms=%llu steps=%llu",
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(current_tid),
                static_cast<unsigned long>(actual_ui_tid),
                static_cast<unsigned long long>(elapsed),
                static_cast<unsigned long long>(steps));
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "complete job=%llu worker_tid=%lu ui_tid=%lu elapsed_ms=%llu steps=%llu pending=%llu dispatcher_pending=%zu",
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(current_tid),
                static_cast<unsigned long>(actual_ui_tid),
                static_cast<unsigned long long>(elapsed),
                static_cast<unsigned long long>(steps),
                static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)),
                aida::ui_thread::pending_count());
            return;
        }

        if (cancelled && cancelled() && !job->started) {
            job->dispatch_cancelled = true;
            mark_ui_phase_job_done_locked(job, ui_tid);
            lk.unlock();
            g_ui_phase_cv.notify_all();
            log_msg(hf, "ui_phase", "dispatcher UI tests cancelled before pickup job=%llu worker_tid=%lu known_ui_tid=%lu",
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(current_tid),
                static_cast<unsigned long>(ui_tid));
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "cancel_before_pickup job=%llu worker_tid=%lu known_ui_tid=%lu pending=%llu dispatcher_pending=%zu",
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(current_tid),
                static_cast<unsigned long>(ui_tid),
                static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)),
                aida::ui_thread::pending_count());
            return;
        }

        std::uint64_t now = ui_now_ms();
        std::uint64_t elapsed = now >= job->queued_ms ? now - job->queued_ms : 0;
        if (!job->started && elapsed >= kDispatchPickupTimeoutMs) {
            job->dispatch_cancelled = true;
            DWORD last_ui_tid = g_ui_phase_thread_id.load(std::memory_order_acquire);
            if (last_ui_tid == 0)
                last_ui_tid = aida::ui_thread::owner_tid();
            mark_ui_phase_job_done_locked(job, last_ui_tid);
            lk.unlock();
            g_ui_phase_cv.notify_all();
            fail_pending_ui_dispatch(hf, failed, "pickup_timeout", current_tid, last_ui_tid, elapsed);
            diag::log_tagged_critical_fmt("TESTLAB-UI-DISPATCH",
                "pickup_timeout job=%llu worker_tid=%lu known_ui_tid=%lu elapsed_ms=%llu pending=%llu dispatcher_pending=%zu",
                static_cast<unsigned long long>(job->id),
                static_cast<unsigned long>(current_tid),
                static_cast<unsigned long>(last_ui_tid),
                static_cast<unsigned long long>(elapsed),
                static_cast<unsigned long long>(g_ui_phase_pending_jobs.load(std::memory_order_acquire)),
                aida::ui_thread::pending_count());
            return;
        }

        g_ui_phase_cv.wait_for(lk, std::chrono::milliseconds(job->started ? 250 : 25));
    }
}

void format_ui_phase_snapshot(char* out, std::size_t cap) {
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    std::size_t pending = g_ui_phase_pending_jobs.load(std::memory_order_acquire);
    bool lock_busy = false;
    std::uint64_t lock_start = ui_now_ms();
    std::unique_lock<std::mutex> lk(g_ui_phase_mtx, std::try_to_lock);
    const std::uint64_t lock_wait = ui_now_ms() - lock_start;
    g_ui_phase_last_lock_wait_ms.store(lock_wait, std::memory_order_release);
    if (lk.owns_lock()) {
        g_ui_phase_last_pending_count.store(pending, std::memory_order_release);
        lk.unlock();
    } else {
        lock_busy = true;
        g_ui_phase_lock_busy_count.fetch_add(1u, std::memory_order_acq_rel);
    }
    const char* step_name = g_ui_phase_active_step_name.load(std::memory_order_acquire);
    _snprintf_s(out, cap, _TRUNCATE,
        "ui_pending=%zu ui_lock_busy=%d ui_active_job=%llu ui_active_worker_tid=%lu ui_tid=%lu ui_step_idx=%d ui_step=\"%.96s\" ui_last_lock_wait_ms=%llu ui_snapshot_lock_wait_ms=%llu ui_last_job_wait_ms=%llu ui_last_job_run_ms=%llu ui_last_pump_wall_ms=%llu ui_last_pump_seq=%llu ui_skipped_budget=%llu ui_skipped_no_job=%llu ui_lock_busy_total=%llu ui_steps_processed=%llu",
        pending,
        lock_busy ? 1 : 0,
        static_cast<unsigned long long>(g_ui_phase_active_job_id.load(std::memory_order_acquire)),
        static_cast<unsigned long>(g_ui_phase_active_worker_tid.load(std::memory_order_acquire)),
        static_cast<unsigned long>(g_ui_phase_thread_id.load(std::memory_order_acquire)),
        g_ui_phase_active_step_index.load(std::memory_order_acquire),
        step_name ? step_name : "<null>",
        static_cast<unsigned long long>(g_ui_phase_last_lock_wait_ms.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(lock_wait),
        static_cast<unsigned long long>(g_ui_phase_last_job_wait_ms.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_last_job_run_ms.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_last_pump_wall_ms.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_last_pump_seq.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_skipped_by_budget_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_skipped_no_job_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_lock_busy_count.load(std::memory_order_acquire)),
        static_cast<unsigned long long>(g_ui_phase_steps_processed_total.load(std::memory_order_acquire)));
}

}
