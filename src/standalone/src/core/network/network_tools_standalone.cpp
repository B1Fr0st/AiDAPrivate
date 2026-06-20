

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include "standalone_compat.hpp"
#include "standalone_driver.hpp"
#include "obfuscation.hpp"
#include "pro.h"
#include "decoder_pipeline.hpp"
#include "script_engine.hpp"
#include "tcp_stream_tracker.hpp"
#include "page_guard_engine.hpp"
#include "packet_callstack.hpp"
#include "pre_encrypt_hook.hpp"
#include "api_monitor.hpp"
#include "display_filter.hpp"
#include "protobuf_codec.hpp"
#include "network_view.hpp"
#include "mitm_proxy.hpp"
#include "../infra/work_queue.hpp"
#include "helpers/diag_log.hpp"
#include "burp/burp_module.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;
namespace network_tools
{


static std::string format_ip(const std::uint8_t* addr, std::uint32_t af) {
    char buf[64] = {};
    if (af == 23) {
        qsnprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    } else {
        qsnprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

static bool parse_ipv4(const std::string& s, std::uint8_t* out) {
    unsigned a, b, c, d;
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    out[0] = (std::uint8_t)a; out[1] = (std::uint8_t)b;
    out[2] = (std::uint8_t)c; out[3] = (std::uint8_t)d;
    return true;
}

static std::string protocol_name(std::uint32_t proto) {
    switch (proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        default: return std::to_string(proto);
    }
}

static std::string hex_u64(std::uint64_t value) {
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << value;
    return os.str();
}

static bool ensure_network_script_engine_initialized(const char* action, json& out, std::string& error) {
    const uint64_t started = GetTickCount64();
    const bool before = script_engine::is_initialized();
    out = json::object();
    out["action"] = action ? action : "script";
    out["initialized_before"] = before;
    out["caller_tid"] = static_cast<unsigned long>(GetCurrentThreadId());
    out["backend"] = "script_engine_initialize";
    if (before) {
        out["initialized_after"] = true;
        out["init_attempted"] = false;
        out["elapsed_ms"] = 0;
        out["success"] = true;
        return true;
    }

    bool init_ok = false;
    bool threw = false;
    std::string exception_text;
    try {
        init_ok = script_engine::initialize();
    } catch (const std::exception& e) {
        threw = true;
        exception_text = e.what();
    } catch (...) {
        threw = true;
        exception_text = "unknown exception";
    }

    const bool after = script_engine::is_initialized();
    out["initialized_after"] = after;
    out["init_attempted"] = true;
    out["init_returned"] = init_ok;
    out["threw"] = threw;
    out["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started);
    out["success"] = after;
    if (threw)
        out["exception"] = exception_text;
    diag::log_tagged_fmt("net_tools", "network_script_ensure action=%s before=%d init_ok=%d after=%d threw=%d elapsed_ms=%llu",
        action ? action : "script",
        before ? 1 : 0,
        init_ok ? 1 : 0,
        after ? 1 : 0,
        threw ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - started));
    if (after)
        return true;
    error = threw
        ? std::string("Script engine initialization threw: ") + exception_text
        : "Script engine is not initialized and could not be initialized within the bounded startup path.";
    out["error"] = error;
    return false;
}

static tool_result_t network_param_error(const std::string& message, const std::string& parameter, const std::string& code = "invalid_param") {
    json d;
    d["success"] = false;
    d["parameter"] = parameter;
    d["code"] = code;
    return tool_result_t::error(message, code, d);
}

static bool parse_json_u32_param(const json& params, const char* name, uint32_t& out, std::string& error) {
    if (!params.contains(name))
        return true;
    const auto& v = params[name];
    if (v.is_number_unsigned()) {
        const uint64_t raw = v.get<uint64_t>();
        if (raw > UINT32_MAX) {
            error = std::string("'") + name + "' exceeds uint32 range";
            return false;
        }
        out = static_cast<uint32_t>(raw);
        return true;
    }
    if (v.is_number_integer()) {
        const int64_t raw = v.get<int64_t>();
        if (raw < 0 || raw > UINT32_MAX) {
            error = std::string("'") + name + "' exceeds uint32 range";
            return false;
        }
        out = static_cast<uint32_t>(raw);
        return true;
    }
    if (v.is_string()) {
        std::string s = v.get<std::string>();
        auto not_space = [](unsigned char c) { return !std::isspace(c); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
        s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
        if (s.empty()) {
            error = std::string("'") + name + "' is empty";
            return false;
        }
        char* end = nullptr;
        errno = 0;
        const unsigned long long raw = std::strtoull(s.c_str(), &end, 10);
        if (errno != 0 || end == s.c_str() || *end != '\0' || raw > UINT32_MAX) {
            error = std::string("'") + name + "' must be an unsigned integer";
            return false;
        }
        out = static_cast<uint32_t>(raw);
        return true;
    }
    error = std::string("'") + name + "' must be a number or numeric string";
    return false;
}

static std::uint32_t pre_encrypt_armed_thread_count_locked() {
    std::uint32_t count = 0;
    for (const auto& t : pre_encrypt_hook::g_state.targets)
        count += static_cast<std::uint32_t>(t.armed_tids.size());
    return count;
}

static json pre_encrypt_arm_results_json_locked(const pre_encrypt_hook::hook_target_t& target, std::uint32_t& failures) {
    json arr = json::array();
    failures = 0;
    for (const auto& item : target.arm_results) {
        json r;
        r["timestamp"] = item.timestamp;
        r["tid"] = item.tid;
        r["bp_slot"] = item.bp_index;
        r["address"] = hex_u64(item.address);
        r["ok"] = item.ok;
        r["win32_error"] = static_cast<unsigned long>(item.win32_error);
        if (!item.driver_error.empty())
            r["driver_error"] = item.driver_error;
        if (!item.ok)
            ++failures;
        arr.push_back(std::move(r));
    }
    return arr;
}

static json pre_encrypt_hook_summary_locked() {
    json hooks = json::array();
    for (const auto& t : pre_encrypt_hook::g_state.targets) {
        json h;
        std::uint32_t arm_failures = 0;
        h["name"] = t.function_name;
        h["address"] = hex_u64(t.address);
        h["hooked"] = t.active;
        h["bp_slot"] = t.bp_index;
        h["armed_thread_count"] = static_cast<int>(t.armed_tids.size());
        h["armed_tids"] = t.armed_tids;
        h["buffer_reg"] = t.buffer_reg;
        h["size_reg"] = t.size_reg;
        h["arm_results"] = pre_encrypt_arm_results_json_locked(t, arm_failures);
        h["arm_result_count"] = static_cast<int>(t.arm_results.size());
        h["arm_failure_count"] = arm_failures;
        hooks.push_back(std::move(h));
    }
    return hooks;
}

static std::string win32_error_message(DWORD error);

static json pre_encrypt_status_payload(std::uint32_t pid = 0) {
    json r;
    std::lock_guard<std::mutex> lock(pre_encrypt_hook::g_state.mutex);
    const std::uint32_t state_pid = pre_encrypt_hook::g_state.attached_pid;
    r["pid"] = pid != 0 ? pid : state_pid;
    r["active"] = pre_encrypt_hook::g_state.active.load();
    r["debug_attached"] = pre_encrypt_hook::g_state.debug_attached.load();
    r["debug_loop_running"] = pre_encrypt_hook::g_state.debug_loop_running.load();
    r["debugger_error"] = static_cast<unsigned long>(pre_encrypt_hook::g_state.debugger_error.load());
    r["debug_loop_tid"] = static_cast<unsigned long>(pre_encrypt_hook::g_state.debug_loop_tid.load());
    r["hook_count"] = static_cast<int>(pre_encrypt_hook::g_state.targets.size());
    r["capture_count"] = static_cast<int>(pre_encrypt_hook::g_state.captures.size());
    r["armed_thread_count"] = pre_encrypt_armed_thread_count_locked();
    r["hooks"] = pre_encrypt_hook_summary_locked();
    r["auto_hook_root_pid"] = pre_encrypt_hook::g_state.last_auto_hook_root_pid;
    r["auto_hook_selected_pid"] = pre_encrypt_hook::g_state.last_auto_hook_selected_pid;
    r["auto_hook_snapshot_error"] = static_cast<unsigned long>(pre_encrypt_hook::g_state.last_auto_hook_snapshot_error);
    r["auto_hook_snapshot_message"] = win32_error_message(pre_encrypt_hook::g_state.last_auto_hook_snapshot_error);
    r["auto_hook_error"] = pre_encrypt_hook::g_state.last_auto_hook_error;
    json candidates = json::array();
    for (const auto& candidate : pre_encrypt_hook::g_state.last_auto_hook_candidates) {
        json c;
        c["pid"] = candidate.pid;
        c["parent_pid"] = candidate.parent_pid;
        c["process_name"] = candidate.process_name;
        c["root"] = candidate.root;
        c["alive"] = candidate.alive;
        c["module_enum_ok"] = candidate.module_enum_ok;
        c["module_count"] = candidate.module_count;
        c["has_nss3"] = candidate.has_nss3;
        c["has_pr_write"] = candidate.has_pr_write;
        c["resolved_count"] = candidate.resolved_count;
        c["hook_count"] = candidate.hook_count;
        c["score"] = candidate.score;
        c["selected"] = candidate.selected;
        c["set_active_ok"] = candidate.set_active_ok;
        c["win32_error"] = static_cast<unsigned long>(candidate.win32_error);
        c["win32_message"] = win32_error_message(candidate.win32_error);
        c["driver_error"] = candidate.driver_error;
        c["module_hits"] = candidate.module_hits;
        c["resolved_targets"] = candidate.resolved_targets;
        c["resolve_misses"] = candidate.resolve_misses;
        candidates.push_back(std::move(c));
    }
    r["auto_hook_candidates"] = std::move(candidates);
    return r;
}

static bool pre_encrypt_find_hook(std::uint64_t address, json& out) {
    std::lock_guard<std::mutex> lock(pre_encrypt_hook::g_state.mutex);
    for (const auto& t : pre_encrypt_hook::g_state.targets) {
        if (t.address != address)
            continue;
        out["address"] = hex_u64(t.address);
        out["name"] = t.function_name;
        out["hooked"] = t.active;
        out["bp_slot"] = t.bp_index;
        out["armed_thread_count"] = static_cast<int>(t.armed_tids.size());
        out["armed_tids"] = t.armed_tids;
        out["buffer_reg"] = t.buffer_reg;
        out["size_reg"] = t.size_reg;
        std::uint32_t arm_failures = 0;
        out["arm_results"] = pre_encrypt_arm_results_json_locked(t, arm_failures);
        out["arm_result_count"] = static_cast<int>(t.arm_results.size());
        out["arm_failure_count"] = arm_failures;
        return true;
    }
    return false;
}

static void add_driver_request_fields(json& r, bool ok, DWORD gle = GetLastError()) {
    const DWORD effective_gle = ok ? ERROR_SUCCESS : gle;
    r["driver_request_ok"] = ok;
    r["driver_status"] = driver_bridge::status();
    r["driver_last_error"] = driver_bridge::last_error();
    r["driver_loaded"] = driver_bridge::is_loaded();
    r["driver_connected"] = driver_bridge::using_kernel_driver();
    r["driver_attached_pid"] = driver_bridge::attached_pid();
    r["win32_error"] = static_cast<unsigned long>(effective_gle);
    r["win32_message"] = win32_error_message(effective_gle);
}

static bool process_exists(std::uint32_t pid) {
    if (pid == 0 || pid == 4)
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;
    DWORD exit_code = 0;
    const bool alive = GetExitCodeProcess(h, &exit_code) && exit_code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
}

static std::string win32_error_message(DWORD error) {
    if (error == ERROR_SUCCESS)
        return "ERROR_SUCCESS";
    char* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageA(flags, nullptr, error, 0, reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
    if (len == 0 || !buffer)
        return {};
    std::string text(buffer, buffer + len);
    LocalFree(buffer);
    while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '\t'))
        text.pop_back();
    return text;
}

struct socket_owner_row_t {
    std::uint32_t pid = 0;
    std::uint32_t protocol = 0;
    std::uint32_t state = 0;
    std::uint32_t local_port = 0;
    std::uint32_t remote_port = 0;
    std::uint32_t address_family = 0;
    std::uint8_t local_addr[16] = {};
    std::uint8_t remote_addr[16] = {};
};

static std::uint32_t iphelper_port(DWORD port) {
    return static_cast<std::uint32_t>(ntohs(static_cast<u_short>(port & 0xFFFFu)));
}

static void copy_ipv4_addr(DWORD addr, std::uint8_t* out) {
    std::memcpy(out, &addr, 4);
}

static void append_tcp4_owner_rows(std::vector<socket_owner_row_t>& rows) {
    ULONG size = 0;
    SetLastError(ERROR_SUCCESS);
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_tcp4_size rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR)
        return;
    if (size == 0)
        return;

    std::vector<std::uint8_t> buffer(size);
    rc = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_tcp4_query rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != NO_ERROR)
        return;

    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        socket_owner_row_t out;
        out.pid = row.dwOwningPid;
        out.protocol = 6;
        out.state = row.dwState;
        out.address_family = AF_INET;
        out.local_port = iphelper_port(row.dwLocalPort);
        out.remote_port = iphelper_port(row.dwRemotePort);
        copy_ipv4_addr(row.dwLocalAddr, out.local_addr);
        copy_ipv4_addr(row.dwRemoteAddr, out.remote_addr);
        rows.push_back(out);
    }
}

static void append_udp4_owner_rows(std::vector<socket_owner_row_t>& rows) {
    ULONG size = 0;
    SetLastError(ERROR_SUCCESS);
    DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_udp4_size rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR)
        return;
    if (size == 0)
        return;

    std::vector<std::uint8_t> buffer(size);
    rc = GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_udp4_query rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != NO_ERROR)
        return;

    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        socket_owner_row_t out;
        out.pid = row.dwOwningPid;
        out.protocol = 17;
        out.state = 0;
        out.address_family = AF_INET;
        out.local_port = iphelper_port(row.dwLocalPort);
        copy_ipv4_addr(row.dwLocalAddr, out.local_addr);
        rows.push_back(out);
    }
}

static void append_tcp6_owner_rows(std::vector<socket_owner_row_t>& rows) {
    ULONG size = 0;
    SetLastError(ERROR_SUCCESS);
    DWORD rc = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_tcp6_size rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR)
        return;
    if (size == 0)
        return;

    std::vector<std::uint8_t> buffer(size);
    rc = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_tcp6_query rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != NO_ERROR)
        return;

    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        socket_owner_row_t out;
        out.pid = row.dwOwningPid;
        out.protocol = 6;
        out.state = row.dwState;
        out.address_family = AF_INET6;
        out.local_port = iphelper_port(row.dwLocalPort);
        out.remote_port = iphelper_port(row.dwRemotePort);
        std::memcpy(out.local_addr, row.ucLocalAddr, 16);
        std::memcpy(out.remote_addr, row.ucRemoteAddr, 16);
        rows.push_back(out);
    }
}

static void append_udp6_owner_rows(std::vector<socket_owner_row_t>& rows) {
    ULONG size = 0;
    SetLastError(ERROR_SUCCESS);
    DWORD rc = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_udp6_size rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR)
        return;
    if (size == 0)
        return;

    std::vector<std::uint8_t> buffer(size);
    rc = GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    diag::log_tagged_fmt("net_tools",
        "iphelper_udp6_query rc=%lu size=%lu message=%s",
        static_cast<unsigned long>(rc),
        static_cast<unsigned long>(size),
        win32_error_message(rc).c_str());
    if (rc != NO_ERROR)
        return;

    const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        socket_owner_row_t out;
        out.pid = row.dwOwningPid;
        out.protocol = 17;
        out.state = 0;
        out.address_family = AF_INET6;
        out.local_port = iphelper_port(row.dwLocalPort);
        std::memcpy(out.local_addr, row.ucLocalAddr, 16);
        rows.push_back(out);
    }
}

static std::vector<socket_owner_row_t> enumerate_socket_owner_rows(std::uint32_t filter_pid = 0) {
    std::vector<socket_owner_row_t> rows;
    append_tcp4_owner_rows(rows);
    append_udp4_owner_rows(rows);
    append_tcp6_owner_rows(rows);
    append_udp6_owner_rows(rows);
    if (filter_pid != 0) {
        rows.erase(std::remove_if(rows.begin(), rows.end(), [filter_pid](const socket_owner_row_t& row) {
            return row.pid != filter_pid;
        }), rows.end());
    }
    diag::log_tagged_fmt("net_tools",
        "iphelper_socket_owner_rows filter_pid=%u count=%zu",
        filter_pid,
        rows.size());
    return rows;
}

static std::string socket_key(std::uint32_t pid, std::uint32_t protocol, std::uint32_t af,
                              const std::uint8_t* local_addr, std::uint32_t local_port,
                              const std::uint8_t* remote_addr, std::uint32_t remote_port) {
    return std::to_string(pid) + "|" + std::to_string(protocol) + "|" + std::to_string(af) + "|" +
        format_ip(local_addr, af) + "|" + std::to_string(local_port) + "|" +
        format_ip(remote_addr, af) + "|" + std::to_string(remote_port);
}

static std::string tcp_state_name(std::uint32_t state);

static json socket_owner_row_json(const socket_owner_row_t& row) {
    json entry;
    entry["handle"] = nullptr;
    entry["handle_available"] = false;
    entry["source"] = "ip_helper_owner_table";
    entry["pid"] = row.pid;
    entry["protocol"] = protocol_name(row.protocol);
    entry["state"] = (row.protocol == 6) ? tcp_state_name(row.state) : "N/A";
    entry["local"] = format_ip(row.local_addr, row.address_family) + ":" + std::to_string(row.local_port);
    entry["remote"] = format_ip(row.remote_addr, row.address_family) + ":" + std::to_string(row.remote_port);
    return entry;
}

static std::string tcp_state_name(std::uint32_t state) {
    switch (state) {
        case 0: return "CLOSED";
        case 1: return "LISTEN";
        case 2: return "SYN_SENT";
        case 3: return "SYN_RCVD";
        case 4: return "ESTABLISHED";
        case 5: return "FIN_WAIT1";
        case 6: return "FIN_WAIT2";
        case 7: return "CLOSE_WAIT";
        case 8: return "CLOSING";
        case 9: return "LAST_ACK";
        case 10: return "TIME_WAIT";
        case 11: return "DELETE_TCB";
        default: return std::to_string(state);
    }
}

static std::string direction_name(std::uint32_t dir) {
    return dir == 0 ? "INBOUND" : "OUTBOUND";
}

static std::string hex_dump(const std::uint8_t* data, std::size_t len, std::size_t max_bytes = 256) {
    std::string result;
    std::size_t show = (len < max_bytes) ? len : max_bytes;
    for (std::size_t i = 0; i < show; i++) {
        char hex[4];
        qsnprintf(hex, sizeof(hex), "%02X ", data[i]);
        result += hex;
        if ((i + 1) % 16 == 0) result += "\n";
    }
    if (show < len) result += "... (" + std::to_string(len - show) + " more bytes)";
    return result;
}

static std::string extract_ascii(const std::uint8_t* data, std::size_t len, std::size_t max_chars = 512) {
    std::string result;
    std::size_t show = (len < max_chars) ? len : max_chars;
    for (std::size_t i = 0; i < show; i++) {
        result += (data[i] >= 0x20 && data[i] < 0x7F) ? (char)data[i] : '.';
    }
    return result;
}

tool_result_t network_enumerate_connections(const json& params)
{
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    std::uint32_t filter_pid = 0, filter_protocol = 0;
    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    } else if (params.contains("protocol") && params["protocol"].is_number()) {
        filter_protocol = params["protocol"].get<std::uint32_t>();
    }

    diag::log_tagged_fmt("network", "mcp_enumerate_connections filter_pid=%u filter_proto=%u",
        filter_pid, filter_protocol);
    auto conns = driver_bridge::enumerate_connections(filter_pid, filter_protocol);
    diag::log_tagged_fmt("network", "mcp_enumerate_connections_done count=%zu", conns.size());

    json arr = json::array();
    for (const auto& c : conns) {
        json entry;
        entry["pid"] = c.pid;
        entry["protocol"] = protocol_name(c.protocol);
        entry["state"] = (c.protocol == 6) ? tcp_state_name(c.state) : "N/A";
        entry["local_address"] = format_ip(c.local_addr, c.address_family);
        entry["local_port"] = c.local_port;
        entry["remote_address"] = format_ip(c.remote_addr, c.address_family);
        entry["remote_port"] = c.remote_port;
        arr.push_back(entry);
    }

    return tool_result_t::ok(
        std::to_string(conns.size()) + OBFSTR(" active connections found"), arr);
}

tool_result_t network_start_capture(const json& params)
{
    diag::log_tagged_fmt("net_tools", "network_start_capture entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first."));

    std::uint32_t filter_pid = 0, filter_port = 0, filter_protocol = 0, max_payload = 1500;
    std::uint8_t filter_ip[16] = {};

    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number())
        filter_port = params["port"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    } else if (params.contains("protocol") && params["protocol"].is_number()) {
        filter_protocol = params["protocol"].get<std::uint32_t>();
    }
    if (params.contains("ip") && params["ip"].is_string()) {
        parse_ipv4(params["ip"].get<std::string>(), filter_ip);
    }
    if (params.contains("max_payload") && params["max_payload"].is_number())
        max_payload = params["max_payload"].get<std::uint32_t>();

    diag::log_tagged_fmt("net_tools", "network_start_capture pid=%u port=%u proto=%u max_payload=%u", filter_pid, filter_port, filter_protocol, max_payload);
    bool ok = driver_bridge::start_capture(filter_pid, filter_port, filter_protocol,
        filter_ip, max_payload);
    diag::log_tagged_fmt("net_tools", "network_start_capture result=%d", (int)ok);

    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to start packet capture. Network subsystem may not be ready."));

    json result;
    result["capture_active"] = true;
    if (filter_pid) result["filter_pid"] = filter_pid;
    if (filter_port) result["filter_port"] = filter_port;
    if (filter_protocol) result["filter_protocol"] = protocol_name(filter_protocol);
    if (params.contains("ip")) result["filter_ip"] = params["ip"];
    result["max_payload"] = max_payload;

    return tool_result_t::ok(OBFSTR("Packet capture started via kernel WFP callouts"), result);
}

tool_result_t network_stop_capture(const json&)
{
    diag::log_tagged("net_tools", "network_stop_capture entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    bool ok = driver_bridge::stop_capture();
    diag::log_tagged_fmt("net_tools", "network_stop_capture result=%d", (int)ok);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to stop packet capture."));

    return tool_result_t::ok(OBFSTR("Packet capture stopped"));
}

tool_result_t network_get_packets(const json& params)
{
    diag::log_tagged("net_tools", "network_get_packets entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_packets = 32;
    if (params.contains("count") && params["count"].is_number())
        max_packets = params["count"].get<std::uint32_t>();
    if (max_packets > 32) max_packets = 32;

    auto packets = driver_bridge::get_captured_packets(max_packets);
    diag::log_tagged_fmt("net_tools", "network_get_packets retrieved=%zu max=%u", packets.size(), max_packets);

    json arr = json::array();
    for (const auto& p : packets) {
        json entry;
        entry["timestamp"] = p.timestamp;
        entry["pid"] = p.pid;
        entry["protocol"] = protocol_name(p.protocol);
        entry["direction"] = direction_name(p.direction);
        entry["local_address"] = format_ip(p.local_addr, p.address_family);
        entry["local_port"] = p.local_port;
        entry["remote_address"] = format_ip(p.remote_addr, p.address_family);
        entry["remote_port"] = p.remote_port;
        entry["payload_size"] = p.payload_size;
        if (!p.payload.empty()) {
            entry["hex_dump"] = hex_dump(p.payload.data(), p.payload.size());
            entry["ascii"] = extract_ascii(p.payload.data(), p.payload.size());
        }
        arr.push_back(entry);
    }

    return tool_result_t::ok(
        std::to_string(packets.size()) + OBFSTR(" packets retrieved"), arr);
}

tool_result_t network_analyze_packet(const json& params)
{
    diag::log_tagged("net_tools", "network_analyze_packet entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));


    auto packets = driver_bridge::get_captured_packets(1);
    diag::log_tagged_fmt("net_tools", "network_analyze_packet packets_avail=%zu", packets.size());
    if (packets.empty()) {
        json result;
        result["packet_count"] = 0;
        result["index"] = params.value("index", 0);
        result["capture_empty"] = true;
        result["message"] = "No packets are currently available for analysis.";
        return tool_result_t::ok(OBFSTR("No packets available"), result);
    }

    const auto& p = packets[0];
    json result;
    result["timestamp"] = p.timestamp;
    result["pid"] = p.pid;
    result["protocol"] = protocol_name(p.protocol);
    result["direction"] = direction_name(p.direction);
    result["src"] = format_ip(p.direction == 0 ? p.remote_addr : p.local_addr, p.address_family)
                    + ":" + std::to_string(p.direction == 0 ? p.remote_port : p.local_port);
    result["dst"] = format_ip(p.direction == 0 ? p.local_addr : p.remote_addr, p.address_family)
                    + ":" + std::to_string(p.direction == 0 ? p.local_port : p.remote_port);
    result["payload_size"] = p.payload_size;

    if (!p.payload.empty()) {
        result["hex_dump"] = hex_dump(p.payload.data(), p.payload.size(), 512);
        result["ascii_render"] = extract_ascii(p.payload.data(), p.payload.size());


        if (p.payload.size() >= 4) {
            std::string first4((const char*)p.payload.data(), std::min(p.payload.size(), (std::size_t)4));
            if (first4 == "GET " || first4 == "POST" || first4 == "HEAD" || first4 == "PUT " ||
                first4 == "DELE" || first4 == "HTTP") {
                result["detected_protocol"] = "HTTP";
                std::string http_text((const char*)p.payload.data(), p.payload.size());
                result["http_content"] = http_text;
            } else if (p.payload.size() >= 5 && p.payload[0] == 0x16 && p.payload[1] == 0x03) {
                result["detected_protocol"] = "TLS";
                std::uint8_t tls_ver_major = p.payload[1];
                std::uint8_t tls_ver_minor = p.payload[2];
                result["tls_version"] = std::to_string(tls_ver_major) + "." + std::to_string(tls_ver_minor);
                std::uint8_t content_type = p.payload[0];
                result["tls_content_type"] = content_type == 0x16 ? "Handshake" :
                    content_type == 0x17 ? "Application Data" :
                    content_type == 0x15 ? "Alert" : std::to_string(content_type);
            } else if (p.remote_port == 53 || p.local_port == 53) {
                result["detected_protocol"] = "DNS";
            }
        }
    }

    diag::log_tagged_fmt("net_tools", "network_analyze_packet complete payload_size=%u", (unsigned)p.payload_size);
    return tool_result_t::ok(OBFSTR("Packet analysis complete"), result);
}

tool_result_t network_dns_log(const json& params)
{
    diag::log_tagged("net_tools", "network_dns_log entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();

    diag::log_tagged_fmt("net_tools", "network_dns_log filter_pid=%u", filter_pid);
    auto entries = driver_bridge::get_dns_queries(filter_pid);
    diag::log_tagged_fmt("net_tools", "network_dns_log entries=%zu", entries.size());

    json arr = json::array();
    for (const auto& e : entries) {
        json entry;
        entry["timestamp"] = e.timestamp;
        entry["pid"] = e.pid;
        entry["domain"] = e.domain;
        entry["query_type"] = e.query_type;
        entry["response_code"] = e.response_code;
        entry["ttl"] = e.ttl;

        bool has_addr = false;
        for (int i = 0; i < 16; i++) if (e.resolved_addr[i]) { has_addr = true; break; }
        if (has_addr) {
            entry["resolved_address"] = format_ip(e.resolved_addr, (e.query_type == 28) ? 23u : 2u);
        }


        switch (e.query_type) {
            case 1: entry["type_name"] = "A"; break;
            case 28: entry["type_name"] = "AAAA"; break;
            case 5: entry["type_name"] = "CNAME"; break;
            case 15: entry["type_name"] = "MX"; break;
            case 2: entry["type_name"] = "NS"; break;
            case 12: entry["type_name"] = "PTR"; break;
            case 16: entry["type_name"] = "TXT"; break;
            case 6: entry["type_name"] = "SOA"; break;
            case 33: entry["type_name"] = "SRV"; break;
            default: entry["type_name"] = "Type " + std::to_string(e.query_type); break;
        }

        arr.push_back(entry);
    }

    return tool_result_t::ok(
        std::to_string(entries.size()) + OBFSTR(" DNS entries retrieved"), arr);
}

tool_result_t network_add_filter(const json& params)
{
    diag::log_tagged("net_tools", "network_add_filter entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t action = 2;
    std::uint32_t direction = 2;
    std::uint32_t protocol = 0, pid = 0, port = 0;
    std::uint8_t ip_addr[16] = {}, ip_mask[16] = {};

    const char* filter_action_key = params.contains("filter_action") && params["filter_action"].is_string()
        ? "filter_action"
        : "action";
    if (params.contains(filter_action_key) && params[filter_action_key].is_string()) {
        std::string a = params[filter_action_key].get<std::string>();
        if (a == "allow") action = 0;
        else if (a == "block") action = 1;
        else if (a == "log") action = 2;
    }
    if (params.contains("direction") && params["direction"].is_string()) {
        std::string d = params["direction"].get<std::string>();
        if (d == "inbound" || d == "in") direction = 0;
        else if (d == "outbound" || d == "out") direction = 1;
        else if (d == "both") direction = 2;
    }
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") protocol = 6;
        else if (p == "udp" || p == "UDP") protocol = 17;
    } else if (params.contains("protocol") && params["protocol"].is_number()) {
        protocol = params["protocol"].get<std::uint32_t>();
    }
    if (params.contains("pid") && params["pid"].is_number())
        pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number())
        port = params["port"].get<std::uint32_t>();
    if (params.contains("ip") && params["ip"].is_string()) {
        parse_ipv4(params["ip"].get<std::string>(), ip_addr);
        std::memset(ip_mask, 0xFF, 4);
    }

    std::uint32_t rule_id = 0;
    diag::log_tagged_fmt("net_tools", "network_add_filter action=%u direction=%u protocol=%u pid=%u port=%u", action, direction, protocol, pid, port);
    bool ok = driver_bridge::add_filter_rule(action, direction, protocol, pid, port,
        ip_addr, ip_mask, &rule_id);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_add_filter result=%d rule_id=%u", (int)ok, rule_id);

    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to add filter rule. Rule table may be full."));

    json result;
    result["rule_id"] = rule_id;
    result["action"] = (action == 0) ? "allow" : (action == 1) ? "block" : "log";
    result["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
    if (protocol) result["protocol"] = protocol_name(protocol);
    if (pid) result["pid"] = pid;
    if (port) result["port"] = port;
    if (params.contains("ip")) result["ip"] = params["ip"];
    result["operation"] = "add";
    add_driver_request_fields(result, ok, gle);

    return tool_result_t::ok(OBFSTR("Filter rule added (ID: ") + std::to_string(rule_id) + ")", result);
}

tool_result_t network_remove_filter(const json& params)
{
    diag::log_tagged("net_tools", "network_remove_filter entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("rule_id") || !params["rule_id"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));

    std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
    diag::log_tagged_fmt("net_tools", "network_remove_filter rule_id=%u", rule_id);
    bool ok = driver_bridge::remove_filter_rule(rule_id);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_remove_filter result=%d", (int)ok);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to remove filter rule ") + std::to_string(rule_id));

    driver_bridge::network_stats_t after{};
    const bool after_ok = driver_bridge::get_network_stats(after);
    json result;
    result["operation"] = "remove";
    result["rule_id"] = rule_id;
    result["remaining_count"] = after_ok ? after.active_filter_rules : 0;
    result["stats_after_ok"] = after_ok;
    add_driver_request_fields(result, ok, gle);
    return tool_result_t::ok(OBFSTR("Filter rule ") + std::to_string(rule_id) + OBFSTR(" removed"), result);
}

tool_result_t network_clear_filters(const json&)
{
    diag::log_tagged("net_tools", "network_clear_filters entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    driver_bridge::network_stats_t before{};
    driver_bridge::network_stats_t after{};
    const bool before_ok = driver_bridge::get_network_stats(before);
    bool ok = driver_bridge::clear_filter_rules();
    const DWORD gle = GetLastError();
    const bool after_ok = driver_bridge::get_network_stats(after);
    diag::log_tagged_fmt("net_tools", "network_clear_filters result=%d before_ok=%d before_rules=%llu after_ok=%d after_rules=%llu",
        (int)ok, before_ok ? 1 : 0, static_cast<unsigned long long>(before.active_filter_rules),
        after_ok ? 1 : 0, static_cast<unsigned long long>(after.active_filter_rules));
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to clear filter rules."));

    json result;
    result["before_count"] = before_ok ? before.active_filter_rules : 0;
    result["after_count"] = after_ok ? after.active_filter_rules : 0;
    result["stats_before_ok"] = before_ok;
    result["stats_after_ok"] = after_ok;
    result["cleared_count"] = before_ok && before.active_filter_rules >= after.active_filter_rules ?
        before.active_filter_rules - after.active_filter_rules : 0;
    result["operation"] = "clear";
    result["remaining_count"] = after_ok ? after.active_filter_rules : 0;
    add_driver_request_fields(result, ok, gle);
    return tool_result_t::ok(OBFSTR("All filter rules cleared"), result);
}

tool_result_t network_stats(const json&)
{
    diag::log_tagged("net_tools", "network_stats entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    driver_bridge::network_stats_t stats{};
    bool ok = driver_bridge::get_network_stats(stats);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to get network stats."));

    std::uint32_t enumerated_active = 0;
    bool active_connections_degraded = false;
    if (stats.active_connections == 0) {
        auto enumerated = driver_bridge::enumerate_connections(0, 0);
        if (!enumerated.empty()) {
            enumerated_active = enumerated.size() > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<std::uint32_t>(enumerated.size());
            stats.active_connections = enumerated_active;
            active_connections_degraded = true;
        }
    }
    diag::log_tagged_fmt("net_tools", "network_stats result=%d active_connections=%u enumerated_active=%u degraded=%d bytes_sent=%llu bytes_recv=%llu captured=%llu dropped=%llu", (int)ok, stats.active_connections, enumerated_active, active_connections_degraded ? 1 : 0, static_cast<unsigned long long>(stats.bytes_sent), static_cast<unsigned long long>(stats.bytes_received), static_cast<unsigned long long>(stats.total_captured), static_cast<unsigned long long>(stats.total_dropped));

    json result;
    result["bytes_sent"] = stats.bytes_sent;
    result["bytes_received"] = stats.bytes_received;
    result["packets_sent"] = stats.packets_sent;
    result["packets_received"] = stats.packets_received;
    result["active_connections"] = stats.active_connections;
    result["active_connections_enumerated"] = enumerated_active;
    result["active_connections_degraded"] = active_connections_degraded;
    result["capture_active"] = stats.capture_active != 0;
    result["total_captured"] = stats.total_captured;
    result["total_dropped"] = stats.total_dropped;
    result["total_dns_logged"] = stats.total_dns_logged;
    result["active_filter_rules"] = stats.active_filter_rules;

    return tool_result_t::ok(OBFSTR("Network statistics"), result);
}

tool_result_t network_capture_status(const json&)
{
    diag::log_tagged("net_tools", "network_capture_status entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    bool active = false;
    std::uint32_t captured = 0, dropped = 0;
    bool ok = driver_bridge::get_capture_status(active, captured, dropped);
    diag::log_tagged_fmt("net_tools", "network_capture_status result=%d active=%d captured=%u dropped=%u", (int)ok, (int)active, captured, dropped);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to get capture status."));

    json result;
    result["capture_active"] = active;
    result["packets_captured"] = captured;
    result["packets_dropped"] = dropped;

    return tool_result_t::ok(active ? OBFSTR("Capture is active") : OBFSTR("Capture is stopped"), result);
}

tool_result_t network_block_ip(const json& params)
{
    diag::log_tagged("net_tools", "network_block_ip entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("ip") || !params["ip"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: ip (e.g. '192.168.1.1')"));

    std::uint8_t ip[16] = {}, mask[16] = {};
    if (!parse_ipv4(params["ip"].get<std::string>(), ip))
        return tool_result_t::error(OBFSTR("Invalid IPv4 address"));

    std::memset(mask, 0xFF, 4);

    std::uint32_t direction = 2;
    if (params.contains("direction") && params["direction"].is_string()) {
        std::string d = params["direction"].get<std::string>();
        if (d == "inbound" || d == "in") direction = 0;
        else if (d == "outbound" || d == "out") direction = 1;
    }

    std::uint32_t rule_id = 0;
    diag::log_tagged_fmt("net_tools", "network_block_ip ip=%s direction=%u", params["ip"].get<std::string>().c_str(), direction);
    bool block_ok = driver_bridge::add_filter_rule(1, direction, 0, 0, 0, ip, mask, &rule_id);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_block_ip result=%d rule_id=%u", (int)block_ok, rule_id);
    if (!block_ok)
        return tool_result_t::error(OBFSTR("Failed to add block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_ip"] = params["ip"];
    result["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
    result["operation"] = "block_ip";
    add_driver_request_fields(result, block_ok, gle);
    return tool_result_t::ok(OBFSTR("IP blocked: ") + params["ip"].get<std::string>(), result);
}

tool_result_t network_block_port(const json& params)
{
    diag::log_tagged("net_tools", "network_block_port entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("port") || !params["port"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: port"));

    std::uint32_t port = params["port"].get<std::uint32_t>();
    std::uint32_t protocol = 0;
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") protocol = 6;
        else if (p == "udp" || p == "UDP") protocol = 17;
    }

    std::uint32_t rule_id = 0;
    diag::log_tagged_fmt("net_tools", "network_block_port port=%u protocol=%u", port, protocol);
    bool port_ok = driver_bridge::add_filter_rule(1, 2, protocol, 0, port, nullptr, nullptr, &rule_id);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_block_port result=%d rule_id=%u", (int)port_ok, rule_id);
    if (!port_ok)
        return tool_result_t::error(OBFSTR("Failed to add port block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_port"] = port;
    if (protocol) result["protocol"] = protocol_name(protocol);
    result["operation"] = "block_port";
    add_driver_request_fields(result, port_ok, gle);
    return tool_result_t::ok(OBFSTR("Port blocked: ") + std::to_string(port), result);
}

tool_result_t network_block_process(const json& params)
{
    diag::log_tagged("net_tools", "network_block_process entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("pid") || !params["pid"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: pid"));

    std::uint32_t pid = params["pid"].get<std::uint32_t>();
    diag::log_tagged_fmt("net_tools", "network_block_process pid=%u", pid);
    if (!process_exists(pid)) {
        diag::log_tagged_fmt("net_tools", "network_block_process rejected missing pid=%u", pid);
        return tool_result_t::error(OBFSTR("Cannot block network traffic for a process that is not running."));
    }

    std::uint32_t rule_id = 0;
    bool proc_ok = driver_bridge::add_filter_rule(1, 2, 0, pid, 0, nullptr, nullptr, &rule_id);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_block_process result=%d rule_id=%u", (int)proc_ok, rule_id);
    if (!proc_ok)
        return tool_result_t::error(OBFSTR("Failed to add process block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_pid"] = pid;
    result["pid"] = pid;
    result["operation"] = "block_process";
    add_driver_request_fields(result, proc_ok, gle);
    return tool_result_t::ok(OBFSTR("All network traffic blocked for PID ") + std::to_string(pid), result);
}


struct parsed_http_msg_t {
    bool is_request = false;
    bool is_response = false;
    std::string method;
    std::string uri;
    std::string http_version;
    int status_code = 0;
    std::string reason_phrase;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool body_truncated = false;
};

static bool try_parse_http_msg(const std::uint8_t* data, std::size_t len, parsed_http_msg_t& out) {
    if (len < 10) return false;
    std::size_t parse_len = (len > 16384) ? 16384 : len;
    std::string text(reinterpret_cast<const char*>(data), parse_len);

    auto crlf = text.find("\r\n");
    if (crlf == std::string::npos) return false;
    std::string first_line = text.substr(0, crlf);

    static const char* http_methods[] = {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"};
    for (const char* m : http_methods) {
        std::size_t mlen = std::strlen(m);
        if (first_line.size() > mlen + 1 && first_line.compare(0, mlen, m) == 0 && first_line[mlen] == ' ') {
            out.is_request = true;
            out.method = m;
            auto sp = first_line.rfind(' ');
            if (sp != std::string::npos && sp > mlen + 1) {
                out.uri = first_line.substr(mlen + 1, sp - mlen - 1);
                out.http_version = first_line.substr(sp + 1);
            } else {
                out.uri = first_line.substr(mlen + 1);
            }
            break;
        }
    }

    if (!out.is_request && first_line.size() > 12 && first_line.compare(0, 5, "HTTP/") == 0) {
        out.is_response = true;
        auto sp1 = first_line.find(' ');
        if (sp1 != std::string::npos) {
            out.http_version = first_line.substr(0, sp1);
            auto sp2 = first_line.find(' ', sp1 + 1);
            std::string code_str = (sp2 != std::string::npos) ? first_line.substr(sp1+1, sp2-sp1-1) : first_line.substr(sp1+1);
            out.status_code = std::atoi(code_str.c_str());
            if (sp2 != std::string::npos) out.reason_phrase = first_line.substr(sp2 + 1);
        }
    }

    if (!out.is_request && !out.is_response) return false;

    std::size_t pos = crlf + 2;
    while (pos < text.size()) {
        auto next = text.find("\r\n", pos);
        if (next == std::string::npos) break;
        if (next == pos) { pos += 2; break; }
        std::string line = text.substr(pos, next - pos);
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            while (!value.empty() && (value[0] == ' ' || value[0] == '\t')) value.erase(0, 1);
            out.headers.emplace_back(name, value);
        }
        pos = next + 2;
    }

    if (pos < parse_len) {
        std::size_t body_max = 4096;
        std::size_t avail = parse_len - pos;
        out.body = text.substr(pos, (avail < body_max) ? avail : body_max);
        out.body_truncated = (avail > body_max);
    }
    return true;
}

struct parsed_tls_info_t {
    std::uint8_t content_type = 0;
    std::uint16_t record_version = 0;
    std::uint8_t handshake_type = 0;
    std::uint16_t client_version = 0;
    std::string sni;
    std::vector<std::string> alpn_protocols;
    std::vector<std::uint16_t> cipher_suites;
    std::uint16_t selected_cipher = 0;
    bool is_http2 = false;
};

static std::string tls_cipher_name(std::uint16_t cs) {
    switch (cs) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xCCA9: return "TLS_ECDHE_ECDSA_CHACHA20_POLY1305";
        case 0xCCA8: return "TLS_ECDHE_RSA_CHACHA20_POLY1305";
        case 0x009E: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009F: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0x00FF: return "RENEGOTIATION_INFO_SCSV";
        default: { char buf[16]; qsnprintf(buf, sizeof(buf), "0x%04X", cs); return buf; }
    }
}

static std::string tls_version_str(std::uint16_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: { char buf[16]; qsnprintf(buf, sizeof(buf), "0x%04X", ver); return buf; }
    }
}

static std::string tls_content_type_str(std::uint8_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec";
        case 21: return "Alert";
        case 22: return "Handshake";
        case 23: return "ApplicationData";
        default: return std::to_string(ct);
    }
}

static std::string tls_handshake_type_str(std::uint8_t ht) {
    switch (ht) {
        case 1: return "ClientHello"; case 2: return "ServerHello";
        case 11: return "Certificate"; case 12: return "ServerKeyExchange";
        case 14: return "ServerHelloDone"; case 16: return "ClientKeyExchange";
        case 20: return "Finished";
        default: return "Type " + std::to_string(ht);
    }
}

static bool try_parse_tls_record(const std::uint8_t* data, std::size_t len, parsed_tls_info_t& out) {
    if (len < 5) return false;
    out.content_type = data[0];
    out.record_version = (static_cast<std::uint16_t>(data[1]) << 8) | data[2];
    if (out.content_type < 20 || out.content_type > 23) return false;
    if (data[1] != 0x03) return false;
    if (out.content_type != 22 || len < 9) return true;

    std::size_t off = 5;
    out.handshake_type = data[off];
    if (out.handshake_type != 1 && out.handshake_type != 2) return true;
    if (off + 6 >= len) return true;
    out.client_version = (static_cast<std::uint16_t>(data[off+4]) << 8) | data[off+5];

    std::size_t pos = off + 4 + 2 + 32;
    if (pos >= len) return true;
    std::uint8_t sid_len = data[pos++];
    pos += sid_len;
    if (pos >= len) return true;

    if (out.handshake_type == 1) {
        if (pos + 2 > len) return true;
        std::uint16_t cs_len = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        pos += 2;
        for (std::uint16_t i = 0; i + 1 < cs_len && pos + 1 < len; i += 2) {
            out.cipher_suites.push_back((static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1]);
            pos += 2;
        }
        if (pos >= len) return true;
        std::uint8_t comp_len = data[pos++];
        pos += comp_len;
    } else {
        if (pos + 2 > len) return true;
        out.selected_cipher = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        pos += 3;
    }

    if (pos + 2 > len) return true;
    std::uint16_t ext_total = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    std::size_t ext_end = pos + ext_total;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        std::uint16_t ext_type = (static_cast<std::uint16_t>(data[pos]) << 8) | data[pos + 1];
        std::uint16_t ext_len = (static_cast<std::uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0 && ext_len >= 5) {
            std::size_t sp = pos + 2;
            if (sp < pos + ext_len && data[sp] == 0) {
                sp++;
                if (sp + 2 <= pos + ext_len) {
                    std::uint16_t nlen = (static_cast<std::uint16_t>(data[sp]) << 8) | data[sp+1];
                    sp += 2;
                    if (sp + nlen <= pos + ext_len)
                        out.sni.assign(reinterpret_cast<const char*>(&data[sp]), nlen);
                }
            }
        }
        if (ext_type == 16 && ext_len >= 2) {
            std::size_t ap = pos + 2;
            while (ap < pos + ext_len) {
                std::uint8_t plen = data[ap++];
                if (ap + plen > pos + ext_len) break;
                std::string proto(reinterpret_cast<const char*>(&data[ap]), plen);
                out.alpn_protocols.push_back(proto);
                if (proto == "h2") out.is_http2 = true;
                ap += plen;
            }
        }
        pos += ext_len;
    }
    return true;
}

static const char* http_method_id_name(std::uint32_t m) {
    switch (m) {
        case 1: return "GET"; case 2: return "POST"; case 3: return "PUT";
        case 4: return "DELETE"; case 5: return "HEAD"; case 6: return "OPTIONS";
        case 7: return "PATCH"; case 8: return "CONNECT"; case 9: return "TRACE";
        default: return "UNKNOWN";
    }
}

static std::vector<std::uint8_t> hex_string_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if (c != ' ' && c != ':' && c != '-') clean += c;
    }
    out.reserve(clean.size() / 2);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int h = nib(clean[i]), l = nib(clean[i+1]);
        if (h >= 0 && l >= 0) out.push_back(static_cast<std::uint8_t>((h << 4) | l));
    }
    return out;
}

static std::string bytes_to_hex_string(const std::uint8_t* data, std::size_t len, std::size_t max_bytes = 512) {
    std::string result;
    std::size_t show = (len < max_bytes) ? len : max_bytes;
    for (std::size_t i = 0; i < show; i++) {
        char hex[4]; qsnprintf(hex, sizeof(hex), "%02X", data[i]);
        result += hex;
    }
    if (show < len) result += "...(" + std::to_string(len - show) + " more)";
    return result;
}

static std::string format_mac(const std::uint8_t* mac) {
    char buf[20];
    qsnprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::string format_ipv4_bytes(const std::uint8_t* ip) {
    char buf[20];
    qsnprintf(buf, sizeof(buf), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}


tool_result_t network_deep_inspect(const json& params)
{
    diag::log_tagged("net_tools", "network_deep_inspect entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0, filter_protocol = 0, filter_port = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number()) filter_port = params["port"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }

    diag::log_tagged_fmt("net_tools", "network_deep_inspect filter_pid=%u proto=%u port=%u", filter_pid, filter_protocol, filter_port);
    auto results = driver_bridge::get_dpi_results(filter_pid, filter_protocol, filter_port, 0);
    diag::log_tagged_fmt("net_tools", "network_deep_inspect results=%zu", results.size());
    json arr = json::array();
    for (const auto& d : results) {
        json entry;
        entry["timestamp"] = d.timestamp;
        entry["direction"] = direction_name(d.direction);
        entry["protocol"] = protocol_name(d.protocol);
        entry["src"] = format_ip(d.src_addr, d.af) + ":" + std::to_string(d.src_port);
        entry["dst"] = format_ip(d.dst_addr, d.af) + ":" + std::to_string(d.dst_port);
        entry["pid"] = d.pid;
        entry["payload_size"] = d.payload_size;
        if (d.protocol == 6) {
            entry["tcp_flags"] = d.tcp_flags;
            entry["tcp_window"] = d.tcp_window;
        }
        if (d.is_http) {
            entry["app_protocol"] = "HTTP";
            entry["http_method"] = http_method_id_name(d.http_method);
            if (!d.http_host.empty()) entry["http_host"] = d.http_host;
            if (!d.http_path.empty()) entry["http_path"] = d.http_path;
        }
        if (d.is_tls) {
            entry["app_protocol"] = "TLS";
            entry["tls_version"] = tls_version_str(static_cast<std::uint16_t>(d.tls_version));
            entry["tls_content_type"] = tls_content_type_str(static_cast<std::uint8_t>(d.tls_content_type));
            if (!d.tls_sni.empty()) entry["tls_sni"] = d.tls_sni;
        }
        if (d.is_dns) entry["app_protocol"] = "DNS";
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(results.size()) + OBFSTR(" DPI results"), arr);
}

tool_result_t network_follow_tcp_stream(const json& params)
{
    diag::log_tagged("net_tools", "network_follow_tcp_stream entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('start', 'stop', or 'get')"));

    std::string op = params["operation"].get<std::string>();
    std::uint32_t src_port = 0, dst_port = 0, pid = 0;
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();
    diag::log_tagged_fmt("net_tools", "network_follow_tcp_stream op=%s src_port=%u dst_port=%u pid=%u", op.c_str(), src_port, dst_port, pid);

    if (op == "start") {
        bool ok = driver_bridge::stream_reassemble_op(0, src_port, dst_port, pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        diag::log_tagged_fmt("net_tools", "network_follow_tcp_stream start result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to start stream reassembly. Max 1024 concurrent streams."));
        json r; r["status"] = "started"; r["src_port"] = src_port; r["dst_port"] = dst_port;
        return tool_result_t::ok(OBFSTR("TCP stream reassembly started"), r);
    } else if (op == "stop") {
        bool ok = driver_bridge::stream_reassemble_op(1, src_port, dst_port, pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        diag::log_tagged_fmt("net_tools", "network_follow_tcp_stream stop result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to stop stream reassembly."));
        return tool_result_t::ok(OBFSTR("TCP stream reassembly stopped"));
    } else if (op == "get") {
        std::vector<std::uint8_t> stream_data;
        std::uint32_t total_packets = 0, truncated = 0;
        bool ok = driver_bridge::stream_reassemble_op(2, src_port, dst_port, pid, nullptr, nullptr, &stream_data, &total_packets, &truncated);
        diag::log_tagged_fmt("net_tools", "network_follow_tcp_stream get result=%d bytes=%zu packets=%u truncated=%u", (int)ok, stream_data.size(), total_packets, truncated);
        if (!ok && src_port == 0 && dst_port == 0 && pid == 0) {
            json r;
            r["total_bytes"] = 0;
            r["total_packets"] = 0;
            r["truncated"] = 0;
            r["stream_empty"] = true;
            r["message"] = "No stream selector was provided and no active reassembly data is available.";
            return tool_result_t::ok(OBFSTR("0 bytes reassembled"), r);
        }
        if (!ok) return tool_result_t::error(OBFSTR("Failed to get reassembled stream data."));
        json r;
        r["total_bytes"] = stream_data.size();
        r["total_packets"] = total_packets;
        r["truncated"] = truncated;
        if (!stream_data.empty()) {
            r["hex_dump"] = hex_dump(stream_data.data(), stream_data.size(), 1024);
            r["ascii"] = extract_ascii(stream_data.data(), stream_data.size(), 2048);
        }
        return tool_result_t::ok(std::to_string(stream_data.size()) + OBFSTR(" bytes reassembled"), r);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'start', 'stop', or 'get'."));
}

tool_result_t network_parse_http(const json& params)
{
    diag::log_tagged("net_tools", "network_parse_http entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_pkts = 32;
    if (params.contains("count") && params["count"].is_number())
        max_pkts = params["count"].get<std::uint32_t>();
    if (max_pkts > 32) max_pkts = 32;

    auto packets = driver_bridge::get_captured_packets(max_pkts);
    diag::log_tagged_fmt("net_tools", "network_parse_http packets=%zu max=%u", packets.size(), max_pkts);
    json arr = json::array();
    for (const auto& p : packets) {
        if (p.payload.empty()) continue;
        parsed_http_msg_t msg{};
        if (!try_parse_http_msg(p.payload.data(), p.payload.size(), msg)) continue;
        json entry;
        entry["direction"] = direction_name(p.direction);
        entry["pid"] = p.pid;
        entry["src"] = format_ip(p.direction == 0 ? p.remote_addr : p.local_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.remote_port : p.local_port);
        entry["dst"] = format_ip(p.direction == 0 ? p.local_addr : p.remote_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.local_port : p.remote_port);
        if (msg.is_request) {
            entry["type"] = "request";
            entry["method"] = msg.method;
            entry["uri"] = msg.uri;
            entry["version"] = msg.http_version;
        } else {
            entry["type"] = "response";
            entry["status_code"] = msg.status_code;
            entry["reason"] = msg.reason_phrase;
            entry["version"] = msg.http_version;
        }
        json hdrs = json::object();
        for (const auto& [name, value] : msg.headers)
            hdrs[name] = value;
        entry["headers"] = hdrs;
        if (!msg.body.empty()) {
            entry["body_preview"] = msg.body;
            entry["body_truncated"] = msg.body_truncated;
        }
        arr.push_back(entry);
    }

    diag::log_tagged_fmt("net_tools", "network_parse_http parsed=%zu", arr.size());
    if (arr.empty())
        return tool_result_t::ok(OBFSTR("No HTTP messages found in captured packets. Ensure capture is active and HTTP traffic is flowing."), arr);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" HTTP messages parsed"), arr);
}

tool_result_t network_parse_tls(const json& params)
{
    diag::log_tagged("net_tools", "network_parse_tls entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_pkts = 32;
    if (params.contains("count") && params["count"].is_number())
        max_pkts = params["count"].get<std::uint32_t>();
    if (max_pkts > 32) max_pkts = 32;

    auto packets = driver_bridge::get_captured_packets(max_pkts);
    diag::log_tagged_fmt("net_tools", "network_parse_tls packets=%zu max=%u", packets.size(), max_pkts);
    json arr = json::array();
    for (const auto& p : packets) {
        if (p.payload.size() < 5) continue;
        parsed_tls_info_t tls{};
        if (!try_parse_tls_record(p.payload.data(), p.payload.size(), tls)) continue;
        json entry;
        entry["direction"] = direction_name(p.direction);
        entry["pid"] = p.pid;
        entry["src"] = format_ip(p.direction == 0 ? p.remote_addr : p.local_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.remote_port : p.local_port);
        entry["dst"] = format_ip(p.direction == 0 ? p.local_addr : p.remote_addr, p.address_family)
            + ":" + std::to_string(p.direction == 0 ? p.local_port : p.remote_port);
        entry["content_type"] = tls_content_type_str(tls.content_type);
        entry["record_version"] = tls_version_str(tls.record_version);
        if (tls.handshake_type != 0) {
            entry["handshake_type"] = tls_handshake_type_str(tls.handshake_type);
            entry["client_version"] = tls_version_str(tls.client_version);
        }
        if (!tls.sni.empty()) entry["sni"] = tls.sni;
        if (!tls.alpn_protocols.empty()) {
            json alpn = json::array();
            for (const auto& pr : tls.alpn_protocols) alpn.push_back(pr);
            entry["alpn"] = alpn;
            entry["http2"] = tls.is_http2;
        }
        if (!tls.cipher_suites.empty()) {
            json suites = json::array();
            for (auto cs : tls.cipher_suites) suites.push_back(tls_cipher_name(cs));
            entry["cipher_suites"] = suites;
            entry["cipher_count"] = tls.cipher_suites.size();
        }
        if (tls.selected_cipher != 0) entry["selected_cipher"] = tls_cipher_name(tls.selected_cipher);
        arr.push_back(entry);
    }

    diag::log_tagged_fmt("net_tools", "network_parse_tls parsed=%zu", arr.size());
    if (arr.empty())
        return tool_result_t::ok(OBFSTR("No TLS records found in captured packets. Ensure capture is active and HTTPS traffic is flowing."), arr);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" TLS records parsed"), arr);
}

static const char* wfp_action_type_name(std::uint32_t action)
{
    switch (action) {
    case 0x00001001u: return "block";
    case 0x00001002u: return "permit";
    case 0x00001003u: return "callout_terminating";
    case 0x00001004u: return "callout_inspection";
    case 0x00001005u: return "callout_unknown";
    default: return "unknown";
    }
}

static const char* wfp_fallback_reason_name(std::uint32_t reason)
{
    switch (reason) {
    case 1u: return "missing_bfe_enum_functions";
    case 2u: return "engine_open_failed";
    case 3u: return "bfe_returned_zero_entries";
    default: return "unknown";
    }
}

static std::string hex_u32(std::uint32_t value)
{
    char buf[16];
    qsnprintf(buf, sizeof(buf), "0x%08X", value);
    return buf;
}

static const char* wfp_guid_label(const std::string& guid)
{
    if (guid == "5926DFC8-E3CF-4426-A283-DC393F5D0F9D") return "FWPM_LAYER_INBOUND_TRANSPORT_V4";
    if (guid == "09E61AEA-D214-46E2-9B21-B26B0B2F28C8") return "FWPM_LAYER_OUTBOUND_TRANSPORT_V4";
    if (guid == "3D08BF4E-45F6-4930-A922-417098E20027") return "FWPM_LAYER_DATAGRAM_DATA_V4";
    if (guid == "C38D57D1-05A7-4C33-904F-7FBCEEE60E82") return "FWPM_LAYER_ALE_AUTH_CONNECT_V4";
    if (guid == "E1CD9FE7-F4B5-4273-96C0-592E487B8650") return "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4";
    if (guid == "7A8B3C1D-2E4F-5A6B-8C9D-A1B2C3D4E5F6") return "AiDA inbound callout";
    if (guid == "7A8B3C1E-2E4F-5A6B-8C9D-A1B2C3D4E5F7") return "AiDA outbound callout";
    if (guid == "7A8B3C22-2E4F-5A6B-8C9D-A1B2C3D4E5FB") return "AiDA datagram callout";
    if (guid == "7A8B3C20-2E4F-5A6B-8C9D-A1B2C3D4E5F9") return "AiDA ALE connect callout";
    if (guid == "7A8B3C21-2E4F-5A6B-8C9D-A1B2C3D4E5FA") return "AiDA ALE recv callout";
    if (guid == "7A8B3C1F-2E4F-5A6B-8C9D-A1B2C3D4E5F8") return "AiDA network sublayer";
    return "";
}

tool_result_t network_enumerate_wfp_callouts(const json& params)
{
    diag::log_tagged("net_tools", "network_enumerate_wfp_callouts entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::string filter_module;
    if (params.contains("module") && params["module"].is_string())
        filter_module = params["module"].get<std::string>();

    diag::log_tagged_fmt("net_tools", "network_enumerate_wfp_callouts filter_module=%s", filter_module.c_str());
    auto callouts = driver_bridge::enumerate_wfp_callouts(filter_module);
    diag::log_tagged_fmt("net_tools", "network_enumerate_wfp_callouts count=%zu", callouts.size());
    json arr = json::array();
    std::size_t runtime_fallback_count = 0;
    std::size_t bfe_count = 0;
    for (const auto& c : callouts) {
        json entry;
        const bool is_filter = c.entry_type == 1;
        const bool runtime_fallback = (c.aida_match_reason & 0x80000000u) != 0;
        if (runtime_fallback)
            ++runtime_fallback_count;
        else
            ++bfe_count;
        entry["entry_type"] = is_filter ? "filter" : "callout";
        entry["entry_type_id"] = c.entry_type;
        entry["enumeration_source"] = runtime_fallback ? "runtime_registered_fallback" : "bfe";
        entry["degraded_inventory"] = runtime_fallback;
        entry["callout_id"] = c.callout_id;
        entry["layer_id"] = c.layer_id;
        entry["owning_module"] = c.owning_module;
        entry["identity_preview"] = c.owning_module;
        entry["callout_key"] = c.callout_key_str;
        entry["callout_key_label"] = wfp_guid_label(c.callout_key_str);
        entry["applicable_layer"] = c.applicable_layer_str;
        entry["applicable_layer_label"] = wfp_guid_label(c.applicable_layer_str);
        char addr_buf[32]; qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.classify_fn);
        entry["classify_fn"] = addr_buf;
        qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.owning_module_base);
        entry["module_base"] = addr_buf;
        entry["flags"] = c.flags;
        entry["flags_hex"] = hex_u32(c.flags);
        entry["provider_present"] = c.provider_present != 0;
        if (c.provider_present != 0)
            entry["provider_guid"] = "not_returned_by_driver_abi";
        entry["aida_match_reason"] = c.aida_match_reason;
        json reasons = json::array();
        if ((c.aida_match_reason & 0x00000001u) != 0)
            reasons.push_back("sublayer");
        if ((c.aida_match_reason & 0x00000002u) != 0)
            reasons.push_back("action_callout");
        if ((c.aida_match_reason & 0x00000004u) != 0)
            reasons.push_back("display_data");
        if (runtime_fallback)
            reasons.push_back("runtime_registered_fallback");
        entry["aida_match_reasons"] = reasons;
        if (runtime_fallback) {
            const auto fallback_reason = static_cast<std::uint32_t>(c.filter_id & 0xFFFFFFFFull);
            const auto fallback_win32 = static_cast<std::uint32_t>((c.filter_id >> 32) & 0xFFFFFFFFull);
            entry["degraded_reason"] = wfp_fallback_reason_name(fallback_reason);
            entry["degraded_reason_code"] = fallback_reason;
            entry["bfe_auth_service"] = c.action_type;
            entry["bfe_auth_service_hex"] = hex_u32(c.action_type);
            entry["engine_open_status"] = hex_u32(c.flags);
            entry["engine_open_win32"] = fallback_win32;
            entry["registered_callback_address_returned"] = c.classify_fn != 0;
            entry["registered_callback_match"] = c.classify_fn != 0;
        }
        if (is_filter) {
            qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.filter_id);
            entry["filter_id"] = addr_buf;
            entry["layer"] = c.applicable_layer_str;
            entry["layer_label"] = wfp_guid_label(c.applicable_layer_str);
            entry["sublayer_key"] = c.sublayer_key_str;
            entry["sublayer_label"] = wfp_guid_label(c.sublayer_key_str);
            entry["action_type"] = c.action_type;
            entry["action_type_hex"] = hex_u32(c.action_type);
            entry["action_type_label"] = wfp_action_type_name(c.action_type);
            entry["action_callout_key"] = c.callout_key_str;
            entry["action_callout_label"] = wfp_guid_label(c.callout_key_str);
            entry["display_description_app_preview"] = c.owning_module;
        }
        arr.push_back(entry);
    }
    diag::log_tagged_fmt("net_tools", "network_enumerate_wfp_callouts source_counts bfe=%zu runtime_registered_fallback=%zu",
                         bfe_count, runtime_fallback_count);
    return tool_result_t::ok(std::to_string(callouts.size()) + OBFSTR(" WFP entries found"), arr);
}

tool_result_t network_get_socket_handles(const json& params)
{
    diag::log_tagged("net_tools", "network_get_socket_handles entry");

    std::uint32_t target_pid = 0;
    std::string parse_error;
    if (!parse_json_u32_param(params, "pid", target_pid, parse_error))
        return network_param_error(parse_error, "pid");

    diag::log_tagged_fmt("net_tools", "network_get_socket_handles target_pid=%u", target_pid);
    auto owner_rows = enumerate_socket_owner_rows(target_pid);
    const bool driver_connected = driver_bridge::using_kernel_driver();
    if (!driver_connected) {
        json arr = json::array();
        for (const auto& row : owner_rows)
            arr.push_back(socket_owner_row_json(row));
        diag::log_tagged_fmt("net_tools",
            "network_get_socket_handles driver_unavailable owner_rows=%zu status=%s error=%s",
            owner_rows.size(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (arr.empty()) {
            json d;
            d["pid"] = target_pid;
            d["owner_rows"] = owner_rows.size();
            add_driver_request_fields(d, false, ERROR_INVALID_FUNCTION);
            d["diagnostic"] = "kernel driver is not connected and IP Helper returned no socket owners";
            return tool_result_t::error(OBFSTR("No socket owner rows available without the kernel driver."), d);
        }
        return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" socket entries found via IP Helper; handle values unavailable without the kernel driver"), arr);
    }

    std::set<std::uint32_t> query_pids;
    if (target_pid != 0) {
        query_pids.insert(target_pid);
    } else {
        for (const auto& row : owner_rows) {
            if (row.pid != 0 && row.pid != 4)
                query_pids.insert(row.pid);
        }
    }

    std::vector<driver_bridge::socket_info_t> socks;
    for (std::uint32_t pid : query_pids) {
        SetLastError(ERROR_SUCCESS);
        auto pid_socks = driver_bridge::get_socket_handles(pid);
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_tools",
            "network_get_socket_handles driver_query pid=%u count=%zu gle=%lu message=%s driver_error=%s",
            pid,
            pid_socks.size(),
            static_cast<unsigned long>(gle),
            win32_error_message(gle).c_str(),
            driver_bridge::last_error().c_str());
        socks.insert(socks.end(), pid_socks.begin(), pid_socks.end());
    }
    diag::log_tagged_fmt("net_tools",
        "network_get_socket_handles driver_total=%zu owner_rows=%zu queried_pids=%zu",
        socks.size(),
        owner_rows.size(),
        query_pids.size());

    json arr = json::array();
    std::set<std::string> represented;
    for (const auto& s : socks) {
        json entry;
        char buf[24]; qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)s.handle_value);
        entry["handle"] = buf;
        entry["handle_available"] = s.handle_value != 0;
        entry["source"] = "driver_handle_enum";
        entry["pid"] = s.pid;
        entry["protocol"] = protocol_name(s.protocol);
        entry["state"] = (s.protocol == 6) ? tcp_state_name(s.state) : "N/A";
        entry["local"] = format_ip(s.local_addr, s.address_family) + ":" + std::to_string(s.local_port);
        entry["remote"] = format_ip(s.remote_addr, s.address_family) + ":" + std::to_string(s.remote_port);
        represented.insert(socket_key(s.pid, s.protocol, s.address_family, s.local_addr, s.local_port, s.remote_addr, s.remote_port));
        arr.push_back(entry);
    }

    std::size_t fallback_count = 0;
    for (const auto& row : owner_rows) {
        const auto key = socket_key(row.pid, row.protocol, row.address_family, row.local_addr, row.local_port, row.remote_addr, row.remote_port);
        if (represented.find(key) != represented.end())
            continue;
        arr.push_back(socket_owner_row_json(row));
        represented.insert(key);
        ++fallback_count;
    }

    diag::log_tagged_fmt("net_tools",
        "network_get_socket_handles result entries=%zu driver_handles=%zu owner_fallback=%zu",
        arr.size(),
        socks.size(),
        fallback_count);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" socket entries found"), arr);
}

tool_result_t network_dump_tcpip(const json& params)
{
    diag::log_tagged("net_tools", "network_dump_tcpip entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t target_pid = 0, filter_protocol = 0;
    if (params.contains("pid") && params["pid"].is_number()) target_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }

    diag::log_tagged_fmt("net_tools", "network_dump_tcpip pid=%u proto=%u", target_pid, filter_protocol);
    auto conns = driver_bridge::dump_tcpip_connections(target_pid, filter_protocol);
    diag::log_tagged_fmt("net_tools", "network_dump_tcpip count=%zu", conns.size());
    json arr = json::array();
    for (const auto& c : conns) {
        json entry;
        entry["pid"] = c.pid;
        entry["protocol"] = protocol_name(c.protocol);
        entry["state"] = (c.protocol == 6) ? tcp_state_name(c.state) : "N/A";
        entry["local"] = format_ip(c.local_addr, c.address_family) + ":" + std::to_string(c.local_port);
        entry["remote"] = format_ip(c.remote_addr, c.address_family) + ":" + std::to_string(c.remote_port);
        entry["bytes_in"] = c.bytes_in;
        entry["bytes_out"] = c.bytes_out;
        char buf[24]; qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)c.tcb_address);
        entry["tcb_address"] = buf;
        qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)c.owning_module_base);
        entry["module_base"] = buf;
        entry["create_time"] = c.create_time;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(conns.size()) + OBFSTR(" TCPIP connections dumped"), arr);
}

tool_result_t network_enumerate_interfaces(const json&)
{
    diag::log_tagged("net_tools", "network_enumerate_interfaces entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto ifaces = driver_bridge::enumerate_interfaces();
    diag::log_tagged_fmt("net_tools", "network_enumerate_interfaces count=%zu", ifaces.size());
    json arr = json::array();
    for (const auto& ifc : ifaces) {
        json entry;
        entry["index"] = ifc.if_index;
        entry["name"] = ifc.name;
        entry["description"] = ifc.description;
        entry["type"] = ifc.if_type;
        entry["mtu"] = ifc.mtu;
        entry["speed_mbps"] = ifc.speed / 1000000;
        entry["oper_status"] = (ifc.oper_status == 1) ? "Up" : (ifc.oper_status == 2) ? "Down" : std::to_string(ifc.oper_status);
        entry["mac"] = format_mac(ifc.mac_addr);
        entry["ipv4"] = format_ipv4_bytes(ifc.ipv4_addr);
        entry["ipv4_mask"] = format_ipv4_bytes(ifc.ipv4_mask);
        entry["in_bytes"] = ifc.in_octets;
        entry["out_bytes"] = ifc.out_octets;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(ifaces.size()) + OBFSTR(" network interfaces"), arr);
}

tool_result_t network_inject_packet(const json& params)
{
    diag::log_tagged("net_tools", "network_inject_packet entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t direction = 1, protocol = 6, af = 2;
    std::uint32_t src_port = 0, dst_port = 0;
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};
    std::uint32_t tcp_flags = 0, tcp_seq = 0, tcp_ack = 0;

    if (params.contains("direction") && params["direction"].is_string()) {
        std::string d = params["direction"].get<std::string>();
        if (d == "inbound" || d == "in") direction = 0;
    }
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "udp" || p == "UDP") protocol = 17;
    }
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("src_ip") && params["src_ip"].is_string()) parse_ipv4(params["src_ip"].get<std::string>(), src_addr);
    if (params.contains("dst_ip") && params["dst_ip"].is_string()) parse_ipv4(params["dst_ip"].get<std::string>(), dst_addr);
    if (params.contains("tcp_flags") && params["tcp_flags"].is_number()) tcp_flags = params["tcp_flags"].get<std::uint32_t>();
    if (params.contains("tcp_seq") && params["tcp_seq"].is_number()) tcp_seq = params["tcp_seq"].get<std::uint32_t>();
    if (params.contains("tcp_ack") && params["tcp_ack"].is_number()) tcp_ack = params["tcp_ack"].get<std::uint32_t>();

    std::vector<std::uint8_t> payload;
    if (params.contains("payload_hex") && params["payload_hex"].is_string())
        payload = hex_string_to_bytes(params["payload_hex"].get<std::string>());
    else if (params.contains("payload_text") && params["payload_text"].is_string()) {
        std::string text = params["payload_text"].get<std::string>();
        payload.assign(text.begin(), text.end());
    }
    if (payload.empty())
        return tool_result_t::error(OBFSTR("Payload required. Provide 'payload_hex' or 'payload_text'."));

    diag::log_tagged_fmt("net_tools", "network_inject_packet direction=%u protocol=%u src_port=%u dst_port=%u payload=%zu", direction, protocol, src_port, dst_port, payload.size());
    bool ok = driver_bridge::inject_packet(direction, protocol, af, src_port, dst_port,
        src_addr, dst_addr, payload.data(), static_cast<std::uint32_t>(payload.size()),
        tcp_flags, tcp_seq, tcp_ack);
    diag::log_tagged_fmt("net_tools", "network_inject_packet result=%d", (int)ok);

    if (!ok) return tool_result_t::error(OBFSTR("Packet injection failed."));
    json r;
    r["direction"] = (direction == 0) ? "inbound" : "outbound";
    r["protocol"] = protocol_name(protocol);
    r["payload_size"] = payload.size();
    return tool_result_t::ok(OBFSTR("Packet injected successfully"), r);
}

tool_result_t network_modify_packet_rule(const json& params)
{
    diag::log_tagged("net_tools", "network_modify_packet_rule entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
    diag::log_tagged_fmt("net_tools", "network_modify_packet_rule op=%s", op.c_str());
    if (op == "add") {
        std::uint32_t direction = 2, protocol = 0, port = 0, pid = 0;
        if (params.contains("direction") && params["direction"].is_string()) {
            std::string d = params["direction"].get<std::string>();
            if (d == "inbound" || d == "in") direction = 0;
            else if (d == "outbound" || d == "out") direction = 1;
        }
        if (params.contains("protocol") && params["protocol"].is_string()) {
            std::string p = params["protocol"].get<std::string>();
            if (p == "tcp" || p == "TCP") protocol = 6;
            else if (p == "udp" || p == "UDP") protocol = 17;
        }
        if (params.contains("port") && params["port"].is_number()) port = params["port"].get<std::uint32_t>();
        if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

        std::vector<std::uint8_t> pattern, replacement;
        if (params.contains("pattern_hex") && params["pattern_hex"].is_string())
            pattern = hex_string_to_bytes(params["pattern_hex"].get<std::string>());
        if (params.contains("replacement_hex") && params["replacement_hex"].is_string())
            replacement = hex_string_to_bytes(params["replacement_hex"].get<std::string>());
        if (params.contains("pattern_text") && params["pattern_text"].is_string()) {
            std::string t = params["pattern_text"].get<std::string>();
            pattern.assign(t.begin(), t.end());
        }
        if (params.contains("replacement_text") && params["replacement_text"].is_string()) {
            std::string t = params["replacement_text"].get<std::string>();
            replacement.assign(t.begin(), t.end());
        }
        if (pattern.empty())
            return tool_result_t::error(OBFSTR("Pattern required for 'add'. Provide 'pattern_hex' or 'pattern_text'."));

        std::uint32_t rule_id = 0;
        diag::log_tagged_fmt("net_tools", "network_modify_packet_rule add direction=%u proto=%u port=%u pid=%u pattern=%zu replacement=%zu", direction, protocol, port, pid, pattern.size(), replacement.size());
        bool ok = driver_bridge::packet_mod_rule_op(0, 0, direction, protocol, port, pid,
            pattern.data(), static_cast<std::uint32_t>(pattern.size()),
            replacement.empty() ? nullptr : replacement.data(), static_cast<std::uint32_t>(replacement.size()),
            &rule_id);
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_tools", "network_modify_packet_rule add result=%d rule_id=%u", (int)ok, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add modification rule. Max 32 rules."));
        auto remaining = driver_bridge::list_packet_mod_rules();
        json r;
        r["operation"] = "add";
        r["rule_id"] = rule_id;
        r["remaining_count"] = remaining.size();
        r["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
        r["protocol"] = protocol_name(protocol);
        r["port"] = port;
        r["pid"] = pid;
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("Packet modification rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = driver_bridge::packet_mod_rule_op(1, rule_id);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove modification rule."));
        auto remaining = driver_bridge::list_packet_mod_rules();
        json r;
        r["operation"] = "remove";
        r["rule_id"] = rule_id;
        r["remaining_count"] = remaining.size();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("Modification rule ") + std::to_string(rule_id) + OBFSTR(" removed"), r);
    } else if (op == "clear") {
        auto before = driver_bridge::list_packet_mod_rules();
        bool ok = driver_bridge::packet_mod_rule_op(3);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear modification rules."));
        auto remaining = driver_bridge::list_packet_mod_rules();
        json r;
        r["operation"] = "clear";
        r["before_count"] = static_cast<uint64_t>(before.size());
        r["after_count"] = static_cast<uint64_t>(remaining.size());
        r["cleared_count"] = static_cast<uint64_t>(before.size() >= remaining.size() ? before.size() - remaining.size() : 0);
        r["remaining_count"] = remaining.size();
        r["cleared"] = remaining.empty();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("All packet modification rules cleared"), r);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_mod_rules(const json&)
{
    diag::log_tagged("net_tools", "network_list_mod_rules entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = driver_bridge::list_packet_mod_rules();
    diag::log_tagged_fmt("net_tools", "network_list_mod_rules count=%zu", rules.size());
    json arr = json::array();
    for (const auto& r : rules) {
        json entry;
        entry["rule_id"] = r.rule_id;
        entry["direction"] = (r.direction == 0) ? "inbound" : (r.direction == 1) ? "outbound" : "both";
        entry["protocol"] = protocol_name(r.protocol);
        entry["port"] = r.port;
        entry["pid"] = r.pid;
        entry["match_count"] = r.match_count;
        entry["active"] = r.active != 0;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + OBFSTR(" packet modification rules"), arr);
}

tool_result_t network_redirect_traffic(const json& params)
{
    diag::log_tagged("net_tools", "network_redirect_traffic entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
    diag::log_tagged_fmt("net_tools", "network_redirect_traffic op=%s", op.c_str());
    if (op == "add") {
        std::uint32_t protocol = 6, match_port = 0, redirect_port = 0, af = 2;
        std::uint8_t match_addr[16] = {}, redirect_addr[16] = {};
        if (params.contains("protocol") && params["protocol"].is_string()) {
            std::string p = params["protocol"].get<std::string>();
            if (p == "udp" || p == "UDP") protocol = 17;
        }
        if (params.contains("match_port") && params["match_port"].is_number()) match_port = params["match_port"].get<std::uint32_t>();
        if (params.contains("redirect_port") && params["redirect_port"].is_number()) redirect_port = params["redirect_port"].get<std::uint32_t>();
        if (params.contains("match_ip") && params["match_ip"].is_string()) parse_ipv4(params["match_ip"].get<std::string>(), match_addr);
        if (params.contains("redirect_ip") && params["redirect_ip"].is_string()) parse_ipv4(params["redirect_ip"].get<std::string>(), redirect_addr);

        std::uint32_t rule_id = 0;
        bool ok = driver_bridge::traffic_redirect_op(0, 0, protocol, match_port, match_addr, redirect_port, redirect_addr, af, &rule_id);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add redirect rule. Max 16 rules."));
        auto remaining = driver_bridge::list_redirect_rules();
        json r;
        r["operation"] = "add";
        r["rule_id"] = rule_id;
        r["remaining_count"] = remaining.size();
        r["protocol"] = protocol_name(protocol);
        r["match_port"] = match_port;
        r["redirect_port"] = redirect_port;
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("Traffic redirect rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = driver_bridge::traffic_redirect_op(1, rule_id);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove redirect rule."));
        auto remaining = driver_bridge::list_redirect_rules();
        json r;
        r["operation"] = "remove";
        r["rule_id"] = rule_id;
        r["remaining_count"] = remaining.size();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("Redirect rule ") + std::to_string(rule_id) + OBFSTR(" removed"), r);
    } else if (op == "clear") {
        auto before = driver_bridge::list_redirect_rules();
        bool ok = driver_bridge::traffic_redirect_op(3);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear redirect rules."));
        auto remaining = driver_bridge::list_redirect_rules();
        json r;
        r["operation"] = "clear";
        r["before_count"] = static_cast<uint64_t>(before.size());
        r["after_count"] = static_cast<uint64_t>(remaining.size());
        r["cleared_count"] = static_cast<uint64_t>(before.size() >= remaining.size() ? before.size() - remaining.size() : 0);
        r["remaining_count"] = remaining.size();
        r["cleared"] = remaining.empty();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("All traffic redirect rules cleared"), r);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_redirect_rules(const json&)
{
    diag::log_tagged("net_tools", "network_list_redirect_rules entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = driver_bridge::list_redirect_rules();
    diag::log_tagged_fmt("net_tools", "network_list_redirect_rules count=%zu", rules.size());
    json arr = json::array();
    for (const auto& r : rules) {
        json entry;
        entry["rule_id"] = r.rule_id;
        entry["protocol"] = protocol_name(r.protocol);
        entry["match_port"] = r.match_port;
        entry["redirect_port"] = r.redirect_port;
        entry["match_count"] = r.match_count;
        entry["active"] = r.active != 0;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + OBFSTR(" traffic redirect rules"), arr);
}

tool_result_t network_intercept(const json& params)
{
    diag::log_tagged("net_tools", "network_intercept entry");
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('enable' or 'disable')"));

    std::string op = params["operation"].get<std::string>();
    diag::log_tagged_fmt("net_tools", "network_intercept op=%s", op.c_str());
    if (op == "enable") {
        std::uint32_t filter_pid = 0, filter_port = 0, filter_protocol = 0;
        if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
        if (params.contains("port") && params["port"].is_number()) filter_port = params["port"].get<std::uint32_t>();
        if (params.contains("protocol") && params["protocol"].is_string()) {
            std::string p = params["protocol"].get<std::string>();
            if (p == "tcp" || p == "TCP") filter_protocol = 6;
            else if (p == "udp" || p == "UDP") filter_protocol = 17;
        }
        if (filter_pid == 0 && filter_port == 0 && filter_protocol == 0) {
            json r;
            r["operation"] = "enable";
            r["active"] = false;
            r["held_count"] = 0;
            r["pid"] = filter_pid;
            r["port"] = filter_port;
            r["protocol"] = "any";
            r["failure_phase"] = "validate_filter";
            r["diagnostic"] = "packet interception enable requires at least one explicit filter: pid, port, or protocol";
            r["driver_request_attempted"] = false;
            r["driver_request_ok"] = false;
            r["driver_status"] = driver_bridge::status();
            r["driver_last_error"] = driver_bridge::last_error();
            r["driver_loaded"] = driver_bridge::is_loaded();
            r["driver_connected"] = driver_bridge::using_kernel_driver();
            r["driver_attached_pid"] = driver_bridge::attached_pid();
            r["win32_error"] = static_cast<unsigned long>(ERROR_INVALID_PARAMETER);
            r["win32_message"] = win32_error_message(ERROR_INVALID_PARAMETER);
            diag::log_tagged_fmt("net_tools",
                "network_intercept enable rejected phase=validate_filter pid=%u port=%u proto=%u gle=%lu driver_request_attempted=0",
                filter_pid,
                filter_port,
                filter_protocol,
                static_cast<unsigned long>(ERROR_INVALID_PARAMETER));
            return tool_result_t::error(OBFSTR("Packet interception enable requires at least one explicit filter."), r);
        }
        if (!driver_bridge::using_kernel_driver())
            return tool_result_t::error(OBFSTR("Driver not connected."));
        std::uint32_t held_count = 0; bool active = false;
        diag::log_tagged_fmt("net_tools", "network_intercept enable pid=%u port=%u proto=%u", filter_pid, filter_port, filter_protocol);
        SetLastError(ERROR_SUCCESS);
        bool ok = driver_bridge::intercept_op(0, filter_pid, filter_port, filter_protocol, 0, nullptr, 0, &held_count, &active);
        const DWORD gle = GetLastError();
        json r;
        r["operation"] = "enable";
        r["active"] = active;
        r["held_count"] = held_count;
        r["pid"] = filter_pid;
        r["port"] = filter_port;
        r["protocol"] = filter_protocol == 0 ? "any" : protocol_name(filter_protocol);
        add_driver_request_fields(r, ok, gle);
        r["driver_request_attempted"] = true;
        diag::log_tagged_fmt("net_tools",
            "network_intercept enable result=%d active=%d held=%u gle=%lu message=%s driver_status=%s driver_error=%s",
            (int)ok,
            (int)active,
            held_count,
            static_cast<unsigned long>(gle),
            win32_error_message(gle).c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (!ok) {
            r["failure_phase"] = "driver_intercept_enable_ioctl";
            r["diagnostic"] = "driver rejected packet interception enable request";
            return tool_result_t::error(OBFSTR("Failed to enable packet interception: Win32 error ") +
                std::to_string(static_cast<unsigned long>(gle)) + OBFSTR(" (") + win32_error_message(gle) + OBFSTR(")."), r);
        }
        return tool_result_t::ok(OBFSTR("Packet interception enabled. Matching packets will be held for inspection."), r);
    } else if (op == "disable") {
        if (!driver_bridge::using_kernel_driver())
            return tool_result_t::error(OBFSTR("Driver not connected."));
        SetLastError(ERROR_SUCCESS);
        bool ok = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        const DWORD gle = GetLastError();
        auto remaining = driver_bridge::get_held_packets();
        json r;
        r["operation"] = "disable";
        r["active"] = false;
        r["remaining_held_count"] = remaining.size();
        add_driver_request_fields(r, ok, gle);
        r["driver_request_attempted"] = true;
        diag::log_tagged_fmt("net_tools",
            "network_intercept disable result=%d gle=%lu message=%s remaining=%zu",
            (int)ok,
            static_cast<unsigned long>(gle),
            win32_error_message(gle).c_str(),
            remaining.size());
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable packet interception: Win32 error ") +
            std::to_string(static_cast<unsigned long>(gle)) + OBFSTR(" (") + win32_error_message(gle) + OBFSTR(")."), r);
        return tool_result_t::ok(OBFSTR("Packet interception disabled. All held packets released."), r);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'enable' or 'disable'."));
}

tool_result_t network_get_held_packets(const json&)
{
    diag::log_tagged("net_tools", "network_get_held_packets entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto held = driver_bridge::get_held_packets();
    diag::log_tagged_fmt("net_tools", "network_get_held_packets count=%zu", held.size());
    json arr = json::array();
    for (const auto& h : held) {
        json entry;
        entry["hold_id"] = h.hold_id;
        entry["timestamp"] = h.timestamp;
        entry["direction"] = direction_name(h.direction);
        entry["protocol"] = protocol_name(h.protocol);
        entry["src"] = format_ip(h.src_addr, h.af) + ":" + std::to_string(h.src_port);
        entry["dst"] = format_ip(h.dst_addr, h.af) + ":" + std::to_string(h.dst_port);
        entry["pid"] = h.pid;
        entry["payload_size"] = h.payload_size;
        if (!h.payload.empty()) {
            entry["hex_dump"] = hex_dump(h.payload.data(), h.payload.size(), 512);
            entry["ascii"] = extract_ascii(h.payload.data(), h.payload.size());
        }
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(held.size()) + OBFSTR(" packets held for inspection"), arr);
}

tool_result_t network_release_packet(const json& params)
{
    diag::log_tagged("net_tools", "network_release_packet entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("hold_id") || !params["hold_id"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: hold_id"));

    std::uint64_t hold_id = params["hold_id"].get<std::uint64_t>();
    diag::log_tagged_fmt("net_tools", "network_release_packet hold_id=%llu", static_cast<unsigned long long>(hold_id));
    auto held = driver_bridge::get_held_packets();
    const bool hold_exists = std::any_of(held.begin(), held.end(), [hold_id](const auto& h) {
        return h.hold_id == hold_id;
    });
    diag::log_tagged_fmt("net_tools", "network_release_packet held_count=%zu hold_exists=%d", held.size(), hold_exists ? 1 : 0);
    if (!hold_exists)
        return tool_result_t::error(OBFSTR("Held packet ID was not found."));

    std::vector<std::uint8_t> modify_payload;
    std::uint32_t operation = 3;

    if (params.contains("action") && params["action"].is_string()) {
        std::string act = params["action"].get<std::string>();
        if (act == "drop") operation = 4;
        else if (act == "modify") operation = 5;
    }

    if (operation == 5) {
        if (params.contains("payload_hex") && params["payload_hex"].is_string())
            modify_payload = hex_string_to_bytes(params["payload_hex"].get<std::string>());
        else if (params.contains("payload_text") && params["payload_text"].is_string()) {
            std::string t = params["payload_text"].get<std::string>();
            modify_payload.assign(t.begin(), t.end());
        }
    }

    diag::log_tagged_fmt("net_tools", "network_release_packet operation=%u modify_payload=%zu", operation, modify_payload.size());
    bool ok = driver_bridge::intercept_op(operation, 0, 0, 0, hold_id,
        modify_payload.empty() ? nullptr : modify_payload.data(),
        static_cast<std::uint32_t>(modify_payload.size()), nullptr, nullptr);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_release_packet result=%d operation=%u", (int)ok, operation);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to release/process held packet."));

    std::string action_str = (operation == 4) ? "dropped" : (operation == 5) ? "modified and released" : "released";
    auto remaining = driver_bridge::get_held_packets();
    json r;
    r["action"] = params.value("action", std::string("release"));
    r["operation"] = operation;
    r["hold_id"] = hold_id;
    r["remaining_held_count"] = remaining.size();
    r["modified_payload_size"] = modify_payload.size();
    add_driver_request_fields(r, ok, gle);
    return tool_result_t::ok(OBFSTR("Packet ") + action_str, r);
}

tool_result_t network_kill_connection(const json& params)
{
    diag::log_tagged("net_tools", "network_kill_connection entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t protocol = 6, af = 2, src_port = 0, dst_port = 0, pid = 0;
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};

    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "udp" || p == "UDP") protocol = 17;
    }
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    const bool has_src_ip = params.contains("src_ip") && params["src_ip"].is_string() &&
        parse_ipv4(params["src_ip"].get<std::string>(), src_addr);
    const bool has_dst_ip = params.contains("dst_ip") && params["dst_ip"].is_string() &&
        parse_ipv4(params["dst_ip"].get<std::string>(), dst_addr);
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

    auto addr_is_zero = [](const std::uint8_t* addr) {
        return addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0;
    };
    if (!has_src_ip || !has_dst_ip || addr_is_zero(src_addr) || addr_is_zero(dst_addr)) {
        return tool_result_t::error(OBFSTR("Refusing to kill connection without explicit non-wildcard src_ip and dst_ip"));
    }
    if (src_port == 0 || dst_port == 0) {
        return tool_result_t::error(OBFSTR("Refusing to kill connection without explicit non-zero src_port and dst_port"));
    }

    diag::log_tagged_fmt("net_tools", "network_kill_connection protocol=%u src_port=%u dst_port=%u pid=%u", protocol, src_port, dst_port, pid);
    bool ok = driver_bridge::kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid);
    const DWORD gle = GetLastError();
    diag::log_tagged_fmt("net_tools", "network_kill_connection result=%d", (int)ok);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to kill connection. Tries socket close + RST injection."));
    json r;
    r["action"] = "kill_connection";
    r["pid"] = pid;
    r["protocol"] = protocol_name(protocol);
    r["src_ip"] = params.value("src_ip", std::string());
    r["src_port"] = src_port;
    r["dst_ip"] = params.value("dst_ip", std::string());
    r["dst_port"] = dst_port;
    r["tuple"] = r["src_ip"].get<std::string>() + ":" + std::to_string(src_port) + " -> " +
        r["dst_ip"].get<std::string>() + ":" + std::to_string(dst_port);
    add_driver_request_fields(r, ok, gle);
    return tool_result_t::ok(OBFSTR("Connection killed successfully"), r);
}

tool_result_t network_spoof_dns(const json& params)
{
    diag::log_tagged("net_tools", "network_spoof_dns entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
    diag::log_tagged_fmt("net_tools", "network_spoof_dns op=%s", op.c_str());
    if (op == "add") {
        if (!params.contains("domain") || !params["domain"].is_string())
            return tool_result_t::error(OBFSTR("Missing required parameter: domain"));
        if (!params.contains("spoof_ip") || !params["spoof_ip"].is_string())
            return tool_result_t::error(OBFSTR("Missing required parameter: spoof_ip"));

        std::string domain = params["domain"].get<std::string>();
        std::uint8_t spoof_addr[16] = {};
        parse_ipv4(params["spoof_ip"].get<std::string>(), spoof_addr);
        std::uint32_t ttl = 300;
        if (params.contains("ttl") && params["ttl"].is_number()) ttl = params["ttl"].get<std::uint32_t>();

        std::uint32_t rule_id = 0;
        diag::log_tagged_fmt("net_tools", "network_spoof_dns add domain=%s ttl=%u", domain.c_str(), ttl);
        bool ok = driver_bridge::dns_spoof_op(0, 0, domain.c_str(), spoof_addr, 2, ttl, &rule_id);
        const DWORD gle = GetLastError();
        diag::log_tagged_fmt("net_tools", "network_spoof_dns add result=%d rule_id=%u", (int)ok, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add DNS spoof rule. Max 32 rules."));
        auto remaining = driver_bridge::list_dns_spoof_rules();
        json r;
        r["operation"] = "add";
        r["action"] = "add_spoof";
        r["rule_id"] = rule_id;
        r["domain"] = domain;
        r["spoof_ip"] = params["spoof_ip"].get<std::string>();
        r["ttl"] = ttl;
        r["remaining_count"] = remaining.size();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("DNS spoof rule added: ") + domain + OBFSTR(" -> ") + params["spoof_ip"].get<std::string>(), r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = driver_bridge::dns_spoof_op(1, rule_id, nullptr, nullptr, 2, 0, nullptr);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove DNS spoof rule."));
        auto remaining = driver_bridge::list_dns_spoof_rules();
        json r;
        r["operation"] = "remove";
        r["action"] = "remove_spoof";
        r["rule_id"] = rule_id;
        r["remaining_count"] = remaining.size();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("DNS spoof rule ") + std::to_string(rule_id) + OBFSTR(" removed"), r);
    } else if (op == "clear") {
        auto before = driver_bridge::list_dns_spoof_rules();
        bool ok = driver_bridge::dns_spoof_op(3, 0, nullptr, nullptr, 2, 0, nullptr);
        const DWORD gle = GetLastError();
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear DNS spoof rules."));
        auto remaining = driver_bridge::list_dns_spoof_rules();
        json r;
        r["operation"] = "clear";
        r["action"] = "clear_spoof";
        r["before_count"] = static_cast<uint64_t>(before.size());
        r["after_count"] = static_cast<uint64_t>(remaining.size());
        r["cleared_count"] = static_cast<uint64_t>(before.size() >= remaining.size() ? before.size() - remaining.size() : 0);
        r["remaining_count"] = remaining.size();
        r["cleared"] = remaining.empty();
        add_driver_request_fields(r, ok, gle);
        return tool_result_t::ok(OBFSTR("All DNS spoof rules cleared"), r);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_dns_spoof_rules(const json&)
{
    diag::log_tagged("net_tools", "network_list_dns_spoof_rules entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = driver_bridge::list_dns_spoof_rules();
    diag::log_tagged_fmt("net_tools", "network_list_dns_spoof_rules count=%zu", rules.size());
    json arr = json::array();
    for (const auto& r : rules) {
        json entry;
        entry["rule_id"] = r.rule_id;
        entry["domain"] = r.domain;
        entry["ttl"] = r.ttl;
        entry["match_count"] = r.match_count;
        entry["active"] = r.active != 0;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(rules.size()) + OBFSTR(" DNS spoof rules"), arr);
}

tool_result_t network_bandwidth_monitor(const json& params)
{
    diag::log_tagged("net_tools", "network_bandwidth_monitor entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('start', 'stop', 'get', or 'reset')"));

    std::string op = params["operation"].get<std::string>();
    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
    diag::log_tagged_fmt("net_tools", "network_bandwidth_monitor op=%s pid=%u", op.c_str(), filter_pid);

    if (op == "start") {
        bool ok = driver_bridge::bw_monitor_op(0, filter_pid, nullptr);
        diag::log_tagged_fmt("net_tools", "network_bandwidth_monitor start result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to start bandwidth monitoring."));
        return tool_result_t::ok(OBFSTR("Bandwidth monitoring started"));
    } else if (op == "stop") {
        bool ok = driver_bridge::bw_monitor_op(1, 0, nullptr);
        diag::log_tagged_fmt("net_tools", "network_bandwidth_monitor stop result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to stop bandwidth monitoring."));
        return tool_result_t::ok(OBFSTR("Bandwidth monitoring stopped"));
    } else if (op == "get") {
        driver_bridge::bw_stats_t stats{};
        bool ok = driver_bridge::bw_monitor_op(2, filter_pid, &stats);
        diag::log_tagged_fmt("net_tools", "network_bandwidth_monitor get result=%d active=%d bps_in=%llu bps_out=%llu", (int)ok, (int)stats.active, static_cast<unsigned long long>(stats.bps_in), static_cast<unsigned long long>(stats.bps_out));
        if (!ok) return tool_result_t::error(OBFSTR("Failed to get bandwidth stats."));
        json r;
        r["active"] = stats.active;
        r["total_bytes_sent"] = stats.total_bytes_sent;
        r["total_bytes_recv"] = stats.total_bytes_recv;
        r["total_packets_sent"] = stats.total_packets_sent;
        r["total_packets_recv"] = stats.total_packets_recv;
        r["bps_in"] = stats.bps_in;
        r["bps_out"] = stats.bps_out;
        return tool_result_t::ok(OBFSTR("Bandwidth statistics"), r);
    } else if (op == "reset") {
        bool ok = driver_bridge::bw_monitor_op(3, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to reset bandwidth counters."));
        return tool_result_t::ok(OBFSTR("Bandwidth counters reset"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'start', 'stop', 'get', or 'reset'."));
}

tool_result_t network_bandwidth_per_process(const json& params)
{
    diag::log_tagged("net_tools", "network_bandwidth_per_process entry");

    std::uint32_t filter_pid = 0;
    std::string pid_parse_error;
    if (!parse_json_u32_param(params, "pid", filter_pid, pid_parse_error))
        return network_param_error(pid_parse_error, "pid");
    std::uint32_t sample_ms = 350;
    if (params.contains("sample_ms")) {
        std::string parse_error;
        std::uint32_t parsed_sample_ms = sample_ms;
        if (parse_json_u32_param(params, "sample_ms", parsed_sample_ms, parse_error)) {
            sample_ms = parsed_sample_ms;
        } else {
            diag::log_tagged_fmt("net_tools",
                "network_bandwidth_per_process sample_ms_parse_failed error=%s",
                parse_error.c_str());
        }
    }
    if (sample_ms < 50) sample_ms = 50;
    if (sample_ms > 2000) sample_ms = 2000;

    diag::log_tagged_fmt("net_tools", "network_bandwidth_per_process filter_pid=%u", filter_pid);
    if (!driver_bridge::using_kernel_driver()) {
        auto owner_rows = enumerate_socket_owner_rows(filter_pid);
        std::map<std::uint32_t, std::uint32_t> socket_counts;
        for (const auto& row : owner_rows)
            ++socket_counts[row.pid];
        json arr = json::array();
        for (const auto& item : socket_counts) {
            json entry;
            entry["pid"] = item.first;
            entry["bytes_sent"] = 0;
            entry["bytes_recv"] = 0;
            entry["packets_sent"] = 0;
            entry["packets_recv"] = 0;
            entry["last_activity"] = 0;
            entry["socket_count"] = item.second;
            entry["source"] = "ip_helper_owner_table";
            entry["monitoring_active_before"] = false;
            entry["auto_sampled"] = false;
            entry["sample_ms"] = 0;
            entry["bytes_observed"] = false;
            entry["diagnostic"] = "kernel driver is not connected; socket ownership is available but bandwidth counters are unavailable";
            arr.push_back(entry);
        }
        diag::log_tagged_fmt("net_tools",
            "network_bandwidth_per_process driver_unavailable owner_rows=%zu grouped=%zu status=%s error=%s",
            owner_rows.size(),
            arr.size(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        if (arr.empty()) {
            json d;
            d["filter_pid"] = filter_pid;
            d["owner_rows"] = owner_rows.size();
            add_driver_request_fields(d, false, ERROR_INVALID_FUNCTION);
            d["diagnostic"] = "kernel driver is not connected and IP Helper returned no active socket owners";
            return tool_result_t::error(OBFSTR("No per-process bandwidth rows or socket owners were available."), d);
        }
        return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" processes with socket ownership data"), arr);
    }

    driver_bridge::bw_stats_t stats_before{};
    SetLastError(ERROR_SUCCESS);
    const bool stats_ok = driver_bridge::bw_monitor_op(2, filter_pid, &stats_before);
    const DWORD stats_gle = GetLastError();
    diag::log_tagged_fmt("net_tools",
        "network_bandwidth_per_process stats_before ok=%d active=%d sent=%llu recv=%llu gle=%lu message=%s",
        stats_ok ? 1 : 0,
        stats_before.active ? 1 : 0,
        static_cast<unsigned long long>(stats_before.total_bytes_sent),
        static_cast<unsigned long long>(stats_before.total_bytes_recv),
        static_cast<unsigned long>(stats_gle),
        win32_error_message(stats_gle).c_str());

    auto procs = driver_bridge::get_bw_per_process(filter_pid);
    bool auto_sampled = false;
    bool auto_start_ok = false;
    bool auto_stop_ok = false;
    DWORD auto_start_gle = ERROR_SUCCESS;
    DWORD auto_stop_gle = ERROR_SUCCESS;
    if (procs.empty() && (!stats_ok || !stats_before.active)) {
        auto_sampled = true;
        SetLastError(ERROR_SUCCESS);
        auto_start_ok = driver_bridge::bw_monitor_op(0, filter_pid, nullptr);
        auto_start_gle = GetLastError();
        diag::log_tagged_fmt("net_tools",
            "network_bandwidth_per_process auto_sample_start ok=%d filter_pid=%u sample_ms=%u gle=%lu message=%s",
            auto_start_ok ? 1 : 0,
            filter_pid,
            sample_ms,
            static_cast<unsigned long>(auto_start_gle),
            win32_error_message(auto_start_gle).c_str());
        if (auto_start_ok) {
            std::this_thread::sleep_for(std::chrono::milliseconds(sample_ms));
            procs = driver_bridge::get_bw_per_process(filter_pid);
            SetLastError(ERROR_SUCCESS);
            auto_stop_ok = driver_bridge::bw_monitor_op(1, 0, nullptr);
            auto_stop_gle = GetLastError();
            diag::log_tagged_fmt("net_tools",
                "network_bandwidth_per_process auto_sample_stop ok=%d count=%zu gle=%lu message=%s",
                auto_stop_ok ? 1 : 0,
                procs.size(),
                static_cast<unsigned long>(auto_stop_gle),
                win32_error_message(auto_stop_gle).c_str());
        }
    }

    diag::log_tagged_fmt("net_tools",
        "network_bandwidth_per_process count=%zu auto_sampled=%d start_ok=%d stop_ok=%d",
        procs.size(),
        auto_sampled ? 1 : 0,
        auto_start_ok ? 1 : 0,
        auto_stop_ok ? 1 : 0);
    json arr = json::array();
    for (const auto& p : procs) {
        json entry;
        entry["pid"] = p.pid;
        entry["bytes_sent"] = p.bytes_sent;
        entry["bytes_recv"] = p.bytes_recv;
        entry["packets_sent"] = p.packets_sent;
        entry["packets_recv"] = p.packets_recv;
        entry["last_activity"] = p.last_activity;
        entry["source"] = auto_sampled ? "driver_auto_sample" : "driver_monitor";
        entry["monitoring_active_before"] = stats_before.active;
        entry["auto_sampled"] = auto_sampled;
        entry["sample_ms"] = auto_sampled ? sample_ms : 0;
        entry["bytes_observed"] = (p.bytes_sent != 0 || p.bytes_recv != 0 || p.packets_sent != 0 || p.packets_recv != 0);
        arr.push_back(entry);
    }
    if (arr.empty()) {
        auto owner_rows = enumerate_socket_owner_rows(filter_pid);
        std::map<std::uint32_t, std::uint32_t> socket_counts;
        for (const auto& row : owner_rows)
            ++socket_counts[row.pid];
        for (const auto& item : socket_counts) {
            json entry;
            entry["pid"] = item.first;
            entry["bytes_sent"] = 0;
            entry["bytes_recv"] = 0;
            entry["packets_sent"] = 0;
            entry["packets_recv"] = 0;
            entry["last_activity"] = 0;
            entry["socket_count"] = item.second;
            entry["source"] = "ip_helper_owner_table";
            entry["monitoring_active_before"] = stats_before.active;
            entry["auto_sampled"] = auto_sampled;
            entry["sample_ms"] = auto_sampled ? sample_ms : 0;
            entry["bytes_observed"] = false;
            entry["diagnostic"] = "active sockets found but no bandwidth counters were captured during the sample window";
            arr.push_back(entry);
        }
        diag::log_tagged_fmt("net_tools",
            "network_bandwidth_per_process owner_fallback rows=%zu grouped=%zu",
            owner_rows.size(),
            arr.size());
    }

    if (arr.empty()) {
        json d;
        d["filter_pid"] = filter_pid;
        d["stats_query_ok"] = stats_ok;
        d["monitoring_active_before"] = stats_before.active;
        d["auto_sampled"] = auto_sampled;
        d["auto_start_ok"] = auto_start_ok;
        d["auto_start_win32_error"] = static_cast<unsigned long>(auto_start_gle);
        d["auto_start_win32_message"] = win32_error_message(auto_start_gle);
        d["auto_stop_ok"] = auto_stop_ok;
        d["auto_stop_win32_error"] = static_cast<unsigned long>(auto_stop_gle);
        d["auto_stop_win32_message"] = win32_error_message(auto_stop_gle);
        add_driver_request_fields(d, stats_ok, stats_gle);
        return tool_result_t::error(OBFSTR("No per-process bandwidth rows or active socket owners were available."), d);
    }

    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" processes with bandwidth data"), arr);
}

tool_result_t network_os_fingerprint(const json& params)
{
    diag::log_tagged("net_tools", "network_os_fingerprint entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('enable', 'disable', or 'get')"));

    std::string op = params["operation"].get<std::string>();
    diag::log_tagged_fmt("net_tools", "network_os_fingerprint op=%s", op.c_str());
    if (op == "enable") {
        bool ok = driver_bridge::fingerprint_op(0);
        diag::log_tagged_fmt("net_tools", "network_os_fingerprint enable result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to enable OS fingerprinting."));
        return tool_result_t::ok(OBFSTR("Passive OS fingerprinting enabled. Analyzing TCP SYN packets."));
    } else if (op == "disable") {
        bool ok = driver_bridge::fingerprint_op(1);
        diag::log_tagged_fmt("net_tools", "network_os_fingerprint disable result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable OS fingerprinting."));
        return tool_result_t::ok(OBFSTR("OS fingerprinting disabled"));
    } else if (op == "get") {
        auto fps = driver_bridge::get_fingerprints();
        diag::log_tagged_fmt("net_tools", "network_os_fingerprint get count=%zu", fps.size());
        json arr = json::array();
        for (const auto& f : fps) {
            json entry;
            entry["remote_ip"] = format_ip(f.remote_addr, f.af);
            entry["os_guess"] = f.os_guess;
            entry["ttl"] = f.ttl;
            entry["window_size"] = f.window_size;
            entry["mss"] = f.mss;
            entry["window_scale"] = f.window_scale;
            entry["df_flag"] = f.df_flag != 0;
            entry["sack_permitted"] = f.sack_permitted != 0;
            arr.push_back(entry);
        }
        return tool_result_t::ok(std::to_string(fps.size()) + OBFSTR(" OS fingerprints collected"), arr);
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'enable', 'disable', or 'get'."));
}

tool_result_t network_export_pcap(const json& params)
{
    diag::log_tagged("net_tools", "network_export_pcap entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0, filter_protocol = 0, max_packets = 256;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }
    if (params.contains("max_packets") && params["max_packets"].is_number())
        max_packets = params["max_packets"].get<std::uint32_t>();
    if (max_packets > 256) max_packets = 256;

    driver_bridge::pcap_export_result_t pcap{};
    diag::log_tagged_fmt("net_tools", "network_export_pcap filter_pid=%u proto=%u max=%u", filter_pid, filter_protocol, max_packets);
    bool ok = driver_bridge::export_pcap(filter_pid, filter_protocol, max_packets, &pcap);
    diag::log_tagged_fmt("net_tools", "network_export_pcap driver_result=%d packets=%zu", (int)ok, pcap.packets.size());
    if (!ok) return tool_result_t::error(OBFSTR("Failed to export PCAP data from driver."));

    std::string filename;
    if (params.contains("filename") && params["filename"].is_string())
        filename = params["filename"].get<std::string>();
    else
        filename = "aida_capture.pcap";

    std::string path = get_downloads_folder() + filename;
    ensure_parent_dir_exists(path);

    HANDLE hf = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return tool_result_t::error(OBFSTR("Failed to create PCAP file: ") + path);

    DWORD written = 0;
    bool write_ok = true;
    if (!WriteFile(hf, &pcap.header, sizeof(pcap.header), &written, nullptr)) write_ok = false;

    struct { std::uint32_t ts_sec, ts_usec, incl_len, orig_len; } rec_hdr;
    for (const auto& pkt : pcap.packets) {
        if (!write_ok) break;
        rec_hdr.ts_sec = pkt.ts_sec;
        rec_hdr.ts_usec = pkt.ts_usec;
        rec_hdr.incl_len = static_cast<std::uint32_t>(pkt.data.size());
        rec_hdr.orig_len = static_cast<std::uint32_t>(pkt.data.size());
        if (!WriteFile(hf, &rec_hdr, sizeof(rec_hdr), &written, nullptr)) { write_ok = false; break; }
        if (!pkt.data.empty()) {
            if (!WriteFile(hf, pkt.data.data(), static_cast<DWORD>(pkt.data.size()), &written, nullptr))
                { write_ok = false; break; }
        }
    }
    CloseHandle(hf);

    if (!write_ok) return tool_result_t::error(OBFSTR("Failed to write PCAP file."));

    json r;
    r["file_path"] = path;
    r["packet_count"] = pcap.packets.size();
    diag::log_tagged_fmt("net_tools", "network_export_pcap complete path=%s packets=%zu", path.c_str(), pcap.packets.size());
    return tool_result_t::ok(std::to_string(pcap.packets.size()) + OBFSTR(" packets exported to ") + path, r);
}

tool_result_t api_monitor_start(const json& params)
{
    const uint64_t handler_start_ms = GetTickCount64();
    if (!params.contains("apis") || !params["apis"].is_array())
        return tool_result_t::error(OBFSTR("Missing required parameter: apis"));

    std::vector<api_monitor::api_request_t> apis;
    apis.reserve(params["apis"].size());
    for (const auto& item : params["apis"]) {
        api_monitor::api_request_t request;
        std::string error;
        if (!api_monitor::parse_request_json(item, request, error))
            return tool_result_t::error(OBFSTR("Invalid apis entry: ") + error);
        apis.push_back(std::move(request));
    }

    uint32_t pid = 0;
    if (params.contains("pid")) {
        if (params["pid"].is_number_unsigned()) {
            const auto raw = params["pid"].get<uint64_t>();
            if (raw <= UINT32_MAX)
                pid = static_cast<uint32_t>(raw);
        } else if (params["pid"].is_number_integer()) {
            const auto raw = params["pid"].get<int64_t>();
            if (raw > 0 && raw <= UINT32_MAX)
                pid = static_cast<uint32_t>(raw);
        } else if (params["pid"].is_string()) {
            uint64_t parsed = 0;
            if (api_monitor::parse_u64(params["pid"].get<std::string>(), parsed) && parsed <= UINT32_MAX)
                pid = static_cast<uint32_t>(parsed);
        }
    }

    const bool log_callstack = params.value("log_callstack", false);
    const bool capture_buffer = params.value("capture_buffer", true);
    uint32_t max_capture_bytes = params.value("max_capture_bytes", static_cast<uint32_t>(256));
    size_t max_events = params.value("max_events", static_cast<size_t>(4096));

    diag::log_tagged_fmt("net_tools", "api_monitor_start pid=%u apis=%zu callstack=%d capture=%d max_bytes=%u",
        pid, apis.size(), log_callstack ? 1 : 0, capture_buffer ? 1 : 0, max_capture_bytes);

    json summary = json::object();
    std::string error;
    if (!api_monitor::start(pid, apis, log_callstack, capture_buffer, max_capture_bytes, max_events, summary, error)) {
        const uint64_t handler_elapsed_ms = GetTickCount64() - handler_start_ms;
        diag::log_tagged_fmt("net_tools", "api_monitor_start failed pid=%u elapsed_ms=%llu error=%s", pid, static_cast<unsigned long long>(handler_elapsed_ms), error.c_str());
        if (!summary.is_object())
            summary = json::object();
        summary["success"] = false;
        summary["error"] = error;
        summary["handler_elapsed_ms"] = handler_elapsed_ms;
        if (summary.contains("failed_phase") && !summary.contains("phase"))
            summary["phase"] = summary["failed_phase"];
        if (!summary.contains("last_error"))
            summary["last_error"] = static_cast<unsigned long>(GetLastError());
        if (!summary.contains("elapsed_ms"))
            summary["elapsed_ms"] = handler_elapsed_ms;
        if (!summary.contains("status"))
            summary["status"] = api_monitor::status_json();
        return tool_result_t::error(error, summary);
    }

    const int resolved_count = summary.contains("resolved") && summary["resolved"].is_array()
        ? static_cast<int>(summary["resolved"].size()) : 0;
    diag::log_tagged_fmt("net_tools", "api_monitor_start active resolved=%d", resolved_count);
    return tool_result_t::ok(OBFSTR("API monitor started with ") + std::to_string(resolved_count) + OBFSTR(" resolved API target(s)"), summary);
}

tool_result_t api_monitor_results(const json& params)
{
    size_t limit = params.value("limit", static_cast<size_t>(64));
    std::string filter_api;
    if (params.contains("filter_api") && params["filter_api"].is_string())
        filter_api = params["filter_api"].get<std::string>();
    const bool clear_after = params.value("clear", false);
    const bool stop_after = params.value("stop", false);

    diag::log_tagged_fmt("net_tools", "api_monitor_results limit=%zu filter=%s clear=%d stop=%d",
        limit, filter_api.c_str(), clear_after ? 1 : 0, stop_after ? 1 : 0);

    json result = api_monitor::results(limit, filter_api, clear_after, stop_after);
    const int count = result.value("count", 0);
    if (count == 0) {
        diag::log_tagged_fmt("net_tools", "api_monitor_results empty stop=%d clear=%d", stop_after ? 1 : 0, clear_after ? 1 : 0);
        if (stop_after)
            return tool_result_t::ok(OBFSTR("API monitor stopped with no captured events."), result);
        return tool_result_t::error(OBFSTR("No API monitor events captured."), result);
    }
    return tool_result_t::ok(std::to_string(count) + OBFSTR(" API monitor event(s)"), result);
}

void register_network_tools(mcp_standalone::server_t& srv) {
    diag::log_tagged("net_tools", "register_network_tools entry");
        aida::burp::register_all_tools(srv);

    register_compat(srv, {
        OBFSTR("network_capture_manage"), OBFSTR("network"),
        OBFSTR("Manage kernel packet capture. Actions: start, stop, get_packets, status, export_pcap."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("start|stop|get_packets|status|export_pcap"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "start") return network_start_capture(p);
            if (action == "stop") return network_stop_capture(p);
            if (action == "get_packets") return network_get_packets(p);
            if (action == "status") return network_capture_status(p);
            if (action == "export_pcap") return network_export_pcap(p);
            return compat_unknown_action("network_capture_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_analyze_packet"), OBFSTR("network"),
        OBFSTR("Retrieve and deeply analyze a single captured packet. "
               "Auto-detects application protocol (HTTP, TLS, DNS), extracts headers, "
               "provides full hex dump and ASCII render. Like Fiddler's packet inspector."),
        {},
        network_analyze_packet, true});

    register_compat(srv, {
        OBFSTR("network_filter_manage"), OBFSTR("network"),
        OBFSTR("Manage kernel-level network filter rules. Actions: add, remove, clear."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("add|remove|clear"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "add") return network_add_filter(p);
            if (action == "remove") return network_remove_filter(p);
            if (action == "clear") return network_clear_filters(p);
            return compat_unknown_action("network_filter_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_bandwidth_manage"), OBFSTR("network"),
        OBFSTR("Manage network bandwidth monitoring and summary stats. Actions: monitor, per_process, stats."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("monitor|per_process|stats"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            json p = params.is_object() ? params : json::object();
            if (params.contains("payload") && params["payload"].is_object()) {
                for (auto it = params["payload"].begin(); it != params["payload"].end(); ++it)
                    p[it.key()] = it.value();
            }
            p.erase("action");
            p.erase("payload");
            const std::string operation = p.contains("operation") && p["operation"].is_string()
                ? p["operation"].get<std::string>()
                : std::string();
            diag::log_tagged_fmt("net_tools",
                "network_bandwidth_manage dispatch action=%s operation=%s preserved_operation=%d payload_keys=%zu",
                action.c_str(),
                operation.c_str(),
                operation.empty() ? 0 : 1,
                p.is_object() ? p.size() : 0);
            auto finish = [&](const char* mapped, tool_result_t result) -> tool_result_t {
                diag::log_tagged_fmt("net_tools",
                    "network_bandwidth_manage result action=%s operation=%s mapped=%s success=%d data_object=%d text=%s",
                    action.c_str(),
                    operation.c_str(),
                    mapped,
                    result.success ? 1 : 0,
                    result.data.is_object() ? 1 : 0,
                    result.text.c_str());
                return result;
            };
            if (action == "monitor") return finish("network_bandwidth_monitor", network_bandwidth_monitor(p));
            if (action == "per_process") return finish("network_bandwidth_per_process", network_bandwidth_per_process(p));
            if (action == "stats") return finish("network_stats", network_stats(p));
            return compat_unknown_action("network_bandwidth_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_firewall_manage"), OBFSTR("network"),
        OBFSTR("Manage quick firewall actions. Actions: block_ip, block_port, block_process, kill_connection."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("block_ip|block_port|block_process|kill_connection"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            const json p = compat_action_payload(params);
            if (action == "block_ip") return network_block_ip(p);
            if (action == "block_port") return network_block_port(p);
            if (action == "block_process") return network_block_process(p);
            if (action == "kill_connection") return network_kill_connection(p);
            return compat_unknown_action("network_firewall_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_deep_inspect"), OBFSTR("network"),
        OBFSTR("Deep packet inspection of captured traffic. Returns protocol-level analysis: HTTP method/host/path, "
               "TLS version/SNI/content type, DNS detection. Requires active capture (network_start_capture). "
               "Filter by pid, port, or protocol. Superior to basic packet view - identifies application-layer protocols."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Filter by port number"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false}},
        network_deep_inspect, true});

    register_compat(srv, {
        OBFSTR("network_parse_http"), OBFSTR("network"),
        OBFSTR("Parse HTTP request/response messages from captured packets. Extracts method, URI, status code, "
               "all headers (Host, Content-Type, User-Agent, Cookie, Authorization, etc.), and body preview. "
               "Equivalent to Wireshark HTTP dissector or HTTP Debugger request/response view. Requires active capture."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max packets to scan (default 32, max 32)"), false}},
        network_parse_http, true});

    register_compat(srv, {
        OBFSTR("network_parse_tls"), OBFSTR("network"),
        OBFSTR("Parse TLS/SSL handshake details from captured packets. Extracts: record type, TLS version, "
               "handshake type (ClientHello/ServerHello), SNI (Server Name Indication), ALPN protocols (detects HTTP/2), "
               "cipher suites offered/selected. Equivalent to Wireshark TLS dissector. Requires active capture."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max packets to scan (default 32, max 32)"), false}},
        network_parse_tls, true});

    register_compat(srv, {
        OBFSTR("network_enumerate_wfp_callouts"), OBFSTR("network"),
        OBFSTR("Enumerate registered WFP (Windows Filtering Platform) callouts and filters. Shows BFE inventory source, "
               "degraded runtime-fallback status, action/layer/sublayer/callout GUID labels, display/app-condition previews, "
               "and classify/notify addresses where available. Use to audit stale block filters or security products hooking network traffic."),
        {{OBFSTR("module"), OBFSTR("string"), OBFSTR("Filter by owning module name (case-insensitive substring)"), false}},
        network_enumerate_wfp_callouts, true});

    register_compat(srv, {
        OBFSTR("network_get_socket_handles"), OBFSTR("network"),
        OBFSTR("Enumerate kernel socket handle objects for a process. Returns handle value, AFD endpoint address, "
               "protocol, state, local/remote address:port. Lower-level than netstat - works from kernel object tables."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = all processes)"), false}},
        network_get_socket_handles, true});

    register_compat(srv, {
        OBFSTR("network_dump_tcpip"), OBFSTR("network"),
        OBFSTR("Deep kernel TCPIP stack connection dump. Returns TCB address, owning module, bytes in/out, "
               "create time, and full connection tuple. More detailed than netstat - reads kernel TCPIP internal structures."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false}},
        network_dump_tcpip, true});

    register_compat(srv, {
        OBFSTR("network_enumerate_interfaces"), OBFSTR("network"),
        OBFSTR("List all network interfaces with details: name, description, type, MTU, speed, operational status, "
               "MAC address, IPv4/IPv6 addresses, in/out byte counters. Equivalent to Wireshark's capture interface list."),
        {},
        network_enumerate_interfaces, true});

    register_compat(srv, {
        OBFSTR("network_inject_packet"), OBFSTR("network"),
        OBFSTR("Inject a crafted packet into the network stack at the WFP transport layer. Specify direction, "
               "protocol, source/destination IP:port, payload (hex or text), and TCP flags/sequence numbers. "
               "Use for testing, replaying requests, or active response injection. Equivalent to Scapy packet crafting."),
        {{OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound' or 'outbound' (default: outbound)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' or 'udp' (default: tcp)"), false},
         {OBFSTR("src_ip"), OBFSTR("string"), OBFSTR("Source IP address"), false},
         {OBFSTR("dst_ip"), OBFSTR("string"), OBFSTR("Destination IP address"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination port"), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("Payload as hex string (e.g. '48656C6C6F')"), false},
         {OBFSTR("payload_text"), OBFSTR("string"), OBFSTR("Payload as ASCII text"), false},
         {OBFSTR("tcp_flags"), OBFSTR("number"), OBFSTR("TCP flags bitmask (SYN=2, ACK=16, RST=4, FIN=1, PSH=8)"), false},
         {OBFSTR("tcp_seq"), OBFSTR("number"), OBFSTR("TCP sequence number"), false},
         {OBFSTR("tcp_ack"), OBFSTR("number"), OBFSTR("TCP acknowledgment number"), false}},
        network_inject_packet, false});

    register_compat(srv, {
        OBFSTR("network_packet_mod_manage"), OBFSTR("network"),
        OBFSTR("Manage packet modification rules. Actions: add, remove, clear, list."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("add|remove|clear|list"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            json p = compat_action_payload(params);
            if (action == "list") return network_list_mod_rules(p);
            if (action == "add" || action == "remove" || action == "clear") {
                p["operation"] = action;
                return network_modify_packet_rule(p);
            }
            return compat_unknown_action("network_packet_mod_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_redirect_manage"), OBFSTR("network"),
        OBFSTR("Manage traffic redirect rules. Actions: add, remove, clear, list."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("add|remove|clear|list"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            json p = compat_action_payload(params);
            if (action == "list") return network_list_redirect_rules(p);
            if (action == "add" || action == "remove" || action == "clear") {
                p["operation"] = action;
                return network_redirect_traffic(p);
            }
            return compat_unknown_action("network_redirect_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_intercept_manage"), OBFSTR("network"),
        OBFSTR("Manage packet interception and held-packet decisions. Actions: enable, disable, list, release, drop, modify. "
               "The enable action requires at least one explicit filter: pid, port, or protocol."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("enable|disable|list|release|drop|modify"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Enable filter: process ID. At least one of pid, port, or protocol is required for enable."), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Enable filter: local or remote port. At least one of pid, port, or protocol is required for enable."), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Enable filter: 'tcp' or 'udp'. At least one of pid, port, or protocol is required for enable."), false},
         {OBFSTR("hold_id"), OBFSTR("number"), OBFSTR("Held packet ID for release, drop, or modify."), false},
         {OBFSTR("payload_text"), OBFSTR("string"), OBFSTR("Replacement payload text for modify."), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("Replacement payload hex for modify."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            json p = compat_action_payload(params);
            if (action == "enable" || action == "disable") {
                p["operation"] = action;
                return network_intercept(p);
            }
            if (action == "list") return network_get_held_packets(p);
            if (action == "release" || action == "drop" || action == "modify") {
                p["action"] = action;
                return network_release_packet(p);
            }
            return compat_unknown_action("network_intercept_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_dns_manage"), OBFSTR("network"),
        OBFSTR("Manage DNS diagnostics and spoofing rules. Actions: log, add_spoof, remove_spoof, clear_spoof, list_spoof."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("log|add_spoof|remove_spoof|clear_spoof|list_spoof"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Action-specific parameters; top-level action-specific fields are also accepted."), false}},
        [](const json& params) -> tool_result_t {
            const std::string action = compat_action_name(params);
            json p = compat_action_payload(params);
            if (action == "log") return network_dns_log(p);
            if (action == "list_spoof") return network_list_dns_spoof_rules(p);
            if (action == "add_spoof") {
                p["operation"] = "add";
                return network_spoof_dns(p);
            }
            if (action == "remove_spoof") {
                p["operation"] = "remove";
                return network_spoof_dns(p);
            }
            if (action == "clear_spoof") {
                p["operation"] = "clear";
                return network_spoof_dns(p);
            }
            return compat_unknown_action("network_dns_manage", action);
        },
        false});

    register_compat(srv, {
        OBFSTR("network_os_fingerprint"), OBFSTR("network"),
        OBFSTR("Passive OS fingerprinting via TCP SYN packet analysis (p0f-style). 'enable' starts collecting "
               "fingerprints from incoming connections. 'get' returns results: remote IP, OS guess, TTL, window size, "
               "MSS, window scale, DF flag, SACK. 'disable' stops. Like p0f or Wireshark OS detection."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable', 'disable', or 'get'"), true}},
        network_os_fingerprint, false});

    register_compat(srv, {
        OBFSTR("network_decode_data"), OBFSTR("network"),
        OBFSTR("Apply a sequence of data transformations to input data (CyberChef-style). "
               "Supports: base64_encode, base64_decode, hex_encode, hex_decode, url_encode, url_decode, "
               "html_entities_encode, html_entities_decode, gzip_compress, gzip_decompress, brotli_decompress, "
               "deflate_decompress, xor (needs 'key' param), aes_encrypt, aes_decrypt (needs 'key','iv','mode' params), "
               "md5, sha1, sha256, sha512, hmac (needs 'key','algorithm' params), json_beautify, json_minify, "
               "hex_dump, protobuf_decode, grpc_decode, upper, lower, reverse, byte_count, entropy. "
               "Input as text or hex. Pipeline steps applied in order."),
        {{OBFSTR("input"), OBFSTR("string"), OBFSTR("Input data (text)"), false},
         {OBFSTR("input_hex"), OBFSTR("string"), OBFSTR("Input data (hex encoded) - use instead of 'input' for binary"), false},
         {OBFSTR("pipeline"), OBFSTR("array"), OBFSTR("Array of transform step objects: [{\"name\":\"base64_decode\"}, {\"transform\":\"xor\",\"params\":{\"key\":\"41\"}}]; transform is accepted as an alias for name"), true}},
        [](const json& args) -> tool_result_t {
            diag::log_tagged("net_tools", "network_decode_data entry");
            std::vector<uint8_t> data;
            if (args.contains("input_hex") && args["input_hex"].is_string()) {
                std::string hex = args["input_hex"].get<std::string>();
                auto nib = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
                    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
                    return -1;
                };
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    int hi = nib(hex[i]);
                    int lo = nib(hex[i + 1]);
                    if (hi < 0 || lo < 0) {
                        return network_param_error("Invalid hex character in 'input_hex'", "input_hex");
                    }
                    data.push_back(static_cast<uint8_t>((hi << 4) | lo));
                }
            } else if (args.contains("input") && args["input"].is_string()) {
                std::string input = args["input"].get<std::string>();
                data.assign(input.begin(), input.end());
            } else {
                return network_param_error("Either 'input' or 'input_hex' required", "input", "missing_required");
            }

            if (!args.contains("pipeline") || !args["pipeline"].is_array())
                return network_param_error("'pipeline' array required", "pipeline", "missing_required");

            auto& reg = decoder_pipeline::registry::instance();
            for (const auto& step : args["pipeline"]) {
                if (!step.is_object())
                    return network_param_error("Each pipeline step must be an object", "pipeline");
                std::string name = step.value("name", "");
                if (name.empty() && step.contains("transform") && step["transform"].is_string()) {
                    name = step["transform"].get<std::string>();
                    diag::log_tagged_fmt("net_tools", "network_decode_data normalized transform_alias=%s", name.c_str());
                }
                if (name.empty())
                    return network_param_error("Each pipeline step needs 'name'", "pipeline.name", "missing_required");

                std::map<std::string, std::string> params;
                if (step.contains("params") && step["params"].is_object()) {
                    for (auto& [k, v] : step["params"].items())
                        params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                }

                diag::log_tagged_fmt("net_tools", "network_decode_data step=%s", name.c_str());
                auto result = decoder_pipeline::apply_single(name, data, params);
                if (!result.success) {
                    diag::log_tagged_fmt("net_tools", "network_decode_data step_failed step=%s error=%s", name.c_str(), result.error.c_str());
                    json d;
                    d["success"] = false;
                    d["parameter"] = "pipeline";
                    d["transform"] = name;
                    d["error"] = result.error;
                    d["code"] = "transform_failed";
                    return tool_result_t::error("Transform '" + name + "' failed: " + result.error, "transform_failed", d);
                }
                data = std::move(result.data);
            }


            bool printable = true;
            for (uint8_t b : data) {
                if (b != '\n' && b != '\r' && b != '\t' && (b < 32 || b > 126)) {
                    printable = false;
                    break;
                }
            }

            json r;
            if (printable) {
                std::string text(data.begin(), data.end());
                r["output"] = text;
                r["output_hex"] = false;
                return tool_result_t::ok(text, r);
            } else {
                std::string hex;
                hex.reserve(data.size() * 2);
                for (uint8_t b : data) {
                    char h[3];
                    snprintf(h, sizeof(h), "%02x", b);
                    hex += h;
                }
                r["output"] = hex;
                r["output_hex"] = true;
                r["output_size"] = data.size();
                return tool_result_t::ok("Binary output (" + std::to_string(data.size()) + " bytes): " + hex.substr(0, 200), r);
            }
        }, false});

    register_compat(srv, {
        OBFSTR("network_list_transforms"), OBFSTR("network"),
        OBFSTR("List all available decoder pipeline transforms with categories and descriptions. "
               "Use to discover available transforms for network_decode_data pipeline."),
        {},
        [](const json&) -> tool_result_t {
            diag::log_tagged("net_tools", "network_list_transforms entry");
            auto& reg = decoder_pipeline::registry::instance();
            auto transforms = reg.all();
            diag::log_tagged_fmt("net_tools", "network_list_transforms count=%zu", transforms.size());
            json arr = json::array();
            for (const auto* t : transforms) {
                json obj;
                obj["id"] = t->id;
                obj["name"] = t->name;
                obj["category"] = t->category;
                arr.push_back(obj);
            }
            json r;
            r["transforms"] = arr;
            r["count"] = transforms.size();
            return tool_result_t::ok(std::to_string(transforms.size()) + " transforms available", r);
        }, true});


    register_compat(srv, {
        OBFSTR("network_script_load"), OBFSTR("network"),
        OBFSTR("Load a Lua script into the proxy scripting engine. Script can register hooks for "
               "on_request, on_response, on_websocket_frame, on_packet, on_dns, on_connection events. "
               "Provide either a file path or inline source code."),
        {{OBFSTR("path"), OBFSTR("string"), OBFSTR("Path to .lua script file"), false},
         {OBFSTR("source"), OBFSTR("string"), OBFSTR("Inline Lua source code"), false},
         {OBFSTR("source_code"), OBFSTR("string"), OBFSTR("Alias for inline Lua source code"), false},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Script name (default: derived from path)"), false}},
        [](const json& args) -> tool_result_t {
            std::string name = args.value("name", "");
            diag::log_tagged_fmt("net_tools", "network_script_load entry name=%s", name.c_str());
            json init_diag;
            std::string init_error;
            if (!ensure_network_script_engine_initialized("load", init_diag, init_error))
                return tool_result_t::error(init_error, "script_engine_unavailable", init_diag);
            bool ok = false;
            if (args.contains("source") && args["source"].is_string()) {
                std::string src = args["source"].get<std::string>();
                if (name.empty()) name = "_inline_";
                ok = script_engine::load_script_source(name, src);
            } else if (args.contains("source_code") && args["source_code"].is_string()) {
                std::string src = args["source_code"].get<std::string>();
                if (name.empty()) name = "_inline_";
                diag::log_tagged_fmt("net_tools", "network_script_load normalized source_code_alias len=%zu", src.size());
                ok = script_engine::load_script_source(name, src);
            } else if (args.contains("path") && args["path"].is_string()) {
                std::string path = args["path"].get<std::string>();
                if (name.empty()) {
                    auto pos = path.find_last_of("\\/");
                    name = (pos != std::string::npos) ? path.substr(pos + 1) : path;
                }
                ok = script_engine::load_script(path);
            } else {
                return network_param_error("Either 'path', 'source', or 'source_code' required", "source", "missing_required");
            }
            diag::log_tagged_fmt("net_tools", "network_script_load result=%d name=%s", (int)ok, name.c_str());
            auto scripts = script_engine::get_scripts();
            json r;
            r["action"] = "load";
            r["name"] = name;
            r["loaded"] = ok;
            r["success"] = ok;
            r["script_count"] = scripts.size();
            r["hook_count"] = script_engine::registered_hook_count();
            r["initialization"] = std::move(init_diag);
            if (!ok)
                return tool_result_t::error("Failed to load script", "script_load_failed", r);
            return tool_result_t::ok("Script '" + name + "' loaded", r);
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_unload"), OBFSTR("network"),
        OBFSTR("Unload a previously loaded Lua script by name."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Script name to unload"), true}},
        [](const json& args) -> tool_result_t {
            std::string name = args.value("name", "");
            diag::log_tagged_fmt("net_tools", "network_script_unload name=%s", name.c_str());
            if (name.empty())
                return tool_result_t::error("Missing required parameter: name");
            json init_diag;
            std::string init_error;
            if (!ensure_network_script_engine_initialized("unload", init_diag, init_error))
                return tool_result_t::error(init_error, init_diag);
            if (!script_engine::unload_script(name)) {
                diag::log_tagged_fmt("net_tools", "network_script_unload not_loaded name=%s", name.c_str());
                json r;
                r["action"] = "unload";
                r["name"] = name;
                r["success"] = false;
                r["initialization"] = std::move(init_diag);
                return tool_result_t::error("Script '" + name + "' is not loaded", r);
            }
            auto scripts = script_engine::get_scripts();
            json r;
            r["action"] = "unload";
            r["name"] = name;
            r["unloaded"] = true;
            r["loaded"] = false;
            r["success"] = true;
            r["script_count"] = scripts.size();
            r["hook_count"] = script_engine::registered_hook_count();
            r["initialization"] = std::move(init_diag);
            return tool_result_t::ok("Script '" + name + "' unloaded", r);
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_execute"), OBFSTR("network"),
        OBFSTR("Execute Lua code in the script engine console. Returns the output/result. "
               "Useful for querying state, testing hooks, or running one-off transformations."),
        {{OBFSTR("code"), OBFSTR("string"), OBFSTR("Lua code to execute"), true}},
        [](const json& args) -> tool_result_t {
            std::string code = args.value("code", "");
            diag::log_tagged_fmt("net_tools", "network_script_execute code_len=%zu", code.size());
            const uint64_t started = GetTickCount64();
            json init_diag;
            std::string init_error;
            if (!ensure_network_script_engine_initialized("execute", init_diag, init_error))
                return tool_result_t::error(init_error, init_diag);
            const bool initialized_before = init_diag.value("initialized_before", false);
            const uint64_t exec_started = GetTickCount64();
            std::string result = script_engine::execute(code);
            const uint64_t execution_elapsed = GetTickCount64() - exec_started;
            diag::log_tagged_fmt("net_tools", "network_script_execute result_len=%zu", result.size());
            std::string normalized = code;
            auto not_space = [](unsigned char c) { return !std::isspace(c); };
            normalized.erase(normalized.begin(), std::find_if(normalized.begin(), normalized.end(), not_space));
            normalized.erase(std::find_if(normalized.rbegin(), normalized.rend(), not_space).base(), normalized.end());
            json r;
            r["action"] = "execute";
            r["output"] = result;
            r["output_len"] = static_cast<uint64_t>(result.size());
            r["output_empty"] = result.empty();
            r["output_nontrivial"] = !result.empty() && result != "[error: engine not initialized]";
            r["initialized_before"] = initialized_before;
            r["initialized_after"] = script_engine::is_initialized();
            r["script_count"] = script_engine::get_scripts().size();
            r["hook_count"] = script_engine::registered_hook_count();
            r["elapsed_ms"] = static_cast<unsigned long long>(GetTickCount64() - started);
            r["execution_elapsed_ms"] = static_cast<unsigned long long>(execution_elapsed);
            r["expected_output_available"] = false;
            if (normalized == "return 1") {
                r["expected_output_available"] = true;
                r["expected_output"] = "1";
                r["expected_output_matched"] = result == "1";
            } else if (normalized == "return true") {
                r["expected_output_available"] = true;
                r["expected_output"] = "true";
                r["expected_output_matched"] = result == "true";
            } else if (normalized == "return false") {
                r["expected_output_available"] = true;
                r["expected_output"] = "false";
                r["expected_output_matched"] = result == "false";
            }
            r["initialization"] = std::move(init_diag);
            if (result == "[error: engine not initialized]") {
                r["success"] = false;
                r["error"] = "script engine not initialized";
                return tool_result_t::error("Script engine is not initialized.", r);
            }
            r["success"] = true;
            return tool_result_t::ok(result.empty() ? "(no output)" : result, r);
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_list"), OBFSTR("network"),
        OBFSTR("List all loaded Lua scripts with their enabled/disabled status."),
        {},
        [](const json&) -> tool_result_t {
            json init_diag;
            std::string init_error;
            if (!ensure_network_script_engine_initialized("list", init_diag, init_error))
                return tool_result_t::error(init_error, init_diag);
            auto scripts = script_engine::get_scripts();
            json arr = json::array();
            for (const auto& s : scripts) {
                json obj;
                obj["name"] = s.name;
                obj["enabled"] = s.enabled;
                obj["loaded"] = s.loaded;
                obj["path"] = s.path;
                arr.push_back(obj);
            }
            json r;
            r["scripts"] = arr;
            r["count"] = scripts.size();
            r["success"] = true;
            r["initialization"] = std::move(init_diag);
            return tool_result_t::ok(std::to_string(scripts.size()) + " scripts loaded", r);
        }, true});

    register_compat(srv, {
        OBFSTR("network_script_api"), OBFSTR("network"),
        OBFSTR("Get the complete Lua API reference for the AiDA scripting engine. Lists all available "
               "functions, hook types, and data structures."),
        {},
        [](const json&) -> tool_result_t {
            json init_diag;
            std::string init_error;
            if (!ensure_network_script_engine_initialized("api", init_diag, init_error))
                return tool_result_t::error(init_error, init_diag);
            auto funcs = script_engine::get_api_listing();
            json arr = json::array();
            std::string text;
            for (const auto& f : funcs) {
                json obj;
                obj["name"] = f.name;
                obj["signature"] = f.signature;
                obj["description"] = f.description;
                arr.push_back(obj);
                text += f.signature + "  -- " + f.description + "\n";
            }
            json r;
            r["api"] = arr;
            r["success"] = true;
            r["initialization"] = std::move(init_diag);
            return tool_result_t::ok(text, r);
        }, true});


    register_compat(srv, {
        OBFSTR("network_stream_track"), OBFSTR("network"),
        OBFSTR("Dynamic TCP stream tracker backed by the kernel driver. Operations: "
               "'start' begins tracking (optional pid filter), 'stop' halts tracking, "
               "'get_all' returns all reassembled streams with hex+ASCII payloads, "
               "'get_stream' fetches a single stream by src_ip/src_port/dst_ip/dst_port, "
               "'clear' evicts all cached streams."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("start|stop|get_all|get_stream|clear"), true},
         {OBFSTR("pid"),       OBFSTR("number"), OBFSTR("Process ID filter for 'start' (0 = all); numeric strings are accepted"), false},
         {OBFSTR("src_ip"),    OBFSTR("string"), OBFSTR("Source IPv4 (dotted-quad) for get_stream"), false},
         {OBFSTR("src_port"),  OBFSTR("number"), OBFSTR("Source port for get_stream"), false},
         {OBFSTR("dst_ip"),    OBFSTR("string"), OBFSTR("Destination IPv4 (dotted-quad) for get_stream"), false},
         {OBFSTR("dst_port"),  OBFSTR("number"), OBFSTR("Destination port for get_stream"), false}},
        [](const json& params) -> tool_result_t {
            const std::string op = params.value("operation", "");
            diag::log_tagged_fmt("net_tools", "network_stream_track op=%s", op.c_str());

            if (op == "start") {
                uint32_t pid = 0;
                std::string pid_error;
                if (!parse_json_u32_param(params, "pid", pid, pid_error))
                    return network_param_error(pid_error, "pid");
                diag::log_tagged_fmt("net_tools", "network_stream_track start pid=%u", pid);
                network_view::g_stream_tracker.start(pid);
                json r;
                r["status"] = "started";
                r["pid"]    = pid;
                return tool_result_t::ok("TCP stream tracker started (pid=" +
                                         std::to_string(pid) + ")", r);
            }

            if (op == "stop") {
                network_view::g_stream_tracker.stop();
                return tool_result_t::ok("TCP stream tracker stopped");
            }

            if (op == "clear") {
                network_view::g_stream_tracker.clear();
                return tool_result_t::ok("TCP stream tracker cleared");
            }


            auto format_payload = [](const std::vector<uint8_t>& data) -> std::string {
                std::ostringstream hex_oss, asc_oss;
                for (size_t i = 0; i < data.size() && i < 4096; ++i) {
                    hex_oss << std::hex << std::setw(2) << std::setfill('0')
                            << static_cast<int>(data[i]) << ' ';
                    asc_oss << (data[i] >= 0x20 && data[i] < 0x7f
                                ? static_cast<char>(data[i]) : '.');
                }
                return hex_oss.str() + " | " + asc_oss.str();
            };


            auto snap_to_json = [&](const network_view::stream_snapshot_t& s) -> json {
                char src_buf[32] = {}, dst_buf[32] = {};
                uint32_t sip = s.key.src_ip4, dip = s.key.dst_ip4;
                snprintf(src_buf, sizeof(src_buf), "%u.%u.%u.%u",
                         sip & 0xFF, (sip >> 8) & 0xFF,
                         (sip >> 16) & 0xFF, (sip >> 24) & 0xFF);
                snprintf(dst_buf, sizeof(dst_buf), "%u.%u.%u.%u",
                         dip & 0xFF, (dip >> 8) & 0xFF,
                         (dip >> 16) & 0xFF, (dip >> 24) & 0xFF);
                json o;
                o["src_ip"]        = src_buf;
                o["src_port"]      = s.key.src_port;
                o["dst_ip"]        = dst_buf;
                o["dst_port"]      = s.key.dst_port;
                o["proto"]         = s.key.proto;
                o["total_bytes"]   = s.total_bytes;
                o["total_packets"] = s.total_packets;
                o["syn_seen"]      = s.syn_seen;
                o["fin_seen"]      = s.fin_seen;
                o["payload"]       = format_payload(s.assembled);
                return o;
            };

            if (op == "get_all") {
                auto snaps = network_view::g_stream_tracker.get_all();
                diag::log_tagged_fmt("net_tools", "network_stream_track get_all count=%zu", snaps.size());
                json arr = json::array();
                for (auto& s : snaps)
                    arr.push_back(snap_to_json(s));
                json r;
                r["streams"] = arr;
                r["count"]   = static_cast<int>(snaps.size());
                return tool_result_t::ok(std::to_string(snaps.size()) + " stream(s) tracked", r);
            }

            if (op == "get_stream") {
                std::string src_ip = params.value("src_ip", "");
                std::string dst_ip = params.value("dst_ip", "");
                uint16_t src_port  = static_cast<uint16_t>(params.value("src_port", 0));
                uint16_t dst_port  = static_cast<uint16_t>(params.value("dst_port", 0));


                auto parse_ip4 = [](const std::string& s) -> uint32_t {
                    uint32_t a = 0, b = 0, c = 0, d = 0;
                    sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
                    return a | (b << 8) | (c << 16) | (d << 24);
                };

                network_view::stream_key_t key{};
                key.src_ip4  = parse_ip4(src_ip);
                key.dst_ip4  = parse_ip4(dst_ip);
                key.src_port = src_port;
                key.dst_port = dst_port;
                key.proto    = 6;

                auto snap = network_view::g_stream_tracker.get_stream(key);
                if (!snap)
                    return tool_result_t::error("Stream not found");

                json r;
                r["stream"] = snap_to_json(*snap);
                return tool_result_t::ok("Stream found", r);
            }

            return tool_result_t::error("Unknown operation '" + op +
                                        "'. Use start|stop|get_all|get_stream|clear");
        }, false});


    register_compat(srv, {
        OBFSTR("network_pg_sniff"), OBFSTR("network"),
        OBFSTR("Pre-encryption page guard sniffer. Installs a VEH-based PAGE_GUARD trap on a "
               "target memory region in another process to capture all reads/writes before "
               "encryption occurs. Uses page-fault + single-step re-arm (no HW breakpoint limit). "
               "Capture output includes bounded plaintext and hex previews from the guarded region. "
               "Operations: 'install' (pid, address, size) returns session_id; "
               "'get_captures' (session_id) drains pending captures; "
               "'uninstall' (session_id) removes the guard and restores protection; "
               "'list_sessions' lists all active sessions."),
        {{OBFSTR("operation"),  OBFSTR("string"), OBFSTR("install|get_captures|uninstall|list_sessions"), true},
         {OBFSTR("pid"),        OBFSTR("number"), OBFSTR("Target process ID (install)"), false},
         {OBFSTR("address"),    OBFSTR("string"), OBFSTR("Target memory address as hex string, e.g. '0x7FFE0000' (install)"), false},
         {OBFSTR("size"),       OBFSTR("number"), OBFSTR("Region size in bytes (install, default 0x1000)"), false},
         {OBFSTR("max_records_per_drain"), OBFSTR("number"), OBFSTR("Maximum page-guard ring records to drain per poll (install, default 32)"), false},
         {OBFSTR("session_id"), OBFSTR("number"), OBFSTR("Session ID returned by install (get_captures/uninstall)"), false}},
        [](const json& params) -> tool_result_t {
            const std::string op = params.value("operation", "");
            diag::log_tagged_fmt("net_tools", "network_pg_sniff op=%s", op.c_str());

            if (op == "install") {
                uint32_t pid = params.value("pid", 0u);
                if (pid == 0)
                    return tool_result_t::error("'pid' is required for install");


                uint64_t addr = 0;
                if (params.contains("address")) {
                    auto& av = params["address"];
                    if (av.is_string()) {
                        std::string s = av.get<std::string>();
                        char* end = nullptr;
                        errno = 0;
                        unsigned long long v = strtoull(s.c_str(), &end, 0);
                        if (errno == 0 && end != s.c_str()) addr = static_cast<uint64_t>(v);
                    } else if (av.is_number()) {
                        addr = av.get<uint64_t>();
                    }
                }
                if (addr == 0)
                    return tool_result_t::error("'address' is required for install");

                uint64_t size = params.value("size", static_cast<uint64_t>(0x1000));
                uint32_t max_records = params.value("max_records_per_drain", 32u);
                if (max_records == 0)
                    max_records = 32;
                if (max_records > 256)
                    max_records = 256;

                const ULONGLONG t0 = GetTickCount64();
                diag::log_tagged_fmt("net_tools", "network_pg_sniff install pid=%u addr=0x%llX size=%llu max_drain=%u", pid, static_cast<unsigned long long>(addr), static_cast<unsigned long long>(size), max_records);
                uint32_t sid = page_guard_engine::g_pg_engine.install(pid, addr, size, true, max_records);
                diag::log_tagged_fmt("net_tools", "network_pg_sniff install sid=%u max_drain=%u elapsed_ms=%llu", sid, max_records, static_cast<unsigned long long>(GetTickCount64() - t0));
                if (sid == 0) {
                    auto failure = page_guard_engine::g_pg_engine.last_install_failure();
                    json d;
                    char buf[32];
                    d["success"] = false;
                    d["reason"] = failure.reason.empty() ? "install_failed" : failure.reason;
                    d["detail"] = failure.detail;
                    d["pid"] = failure.pid != 0 ? failure.pid : pid;
                    qsnprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(failure.requested_addr != 0 ? failure.requested_addr : addr));
                    d["requested_address"] = buf;
                    d["requested_size"] = failure.requested_size != 0 ? failure.requested_size : size;
                    qsnprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(failure.guard_addr));
                    d["guard_address"] = buf;
                    d["guard_size"] = failure.guard_size;
                    qsnprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(failure.region_base));
                    d["region_base"] = buf;
                    d["region_size"] = failure.region_size;
                    d["region_state"] = failure.region_state;
                    d["region_protect"] = failure.region_protect;
                    d["region_type"] = failure.region_type;
                    d["attempted_protect"] = failure.attempted_protect;
                    d["win32_error"] = failure.win32_error;
                    d["driver_status"] = failure.driver_status;
                    d["driver_last_error"] = failure.driver_last_error;
                    const std::string reason = d["reason"].get<std::string>();
                    diag::log_tagged_fmt("net_tools", "network_pg_sniff install_failed reason=%s detail=%s requested=0x%llX size=%llu guard=0x%llX guard_size=%llu region_base=0x%llX region_size=%llu state=0x%08X protect=0x%08X type=0x%08X attempted=0x%08X win32=%u driver_status=%s driver_last_error=%s",
                        reason.c_str(),
                        failure.detail.c_str(),
                        static_cast<unsigned long long>(failure.requested_addr),
                        static_cast<unsigned long long>(failure.requested_size),
                        static_cast<unsigned long long>(failure.guard_addr),
                        static_cast<unsigned long long>(failure.guard_size),
                        static_cast<unsigned long long>(failure.region_base),
                        static_cast<unsigned long long>(failure.region_size),
                        failure.region_state,
                        failure.region_protect,
                        failure.region_type,
                        failure.attempted_protect,
                        failure.win32_error,
                        failure.driver_status.c_str(),
                        failure.driver_last_error.c_str());
                    return tool_result_t::error(std::string("Failed to install page guard: ") + reason, "page_guard_install_failed", d);
                }
                json r;
                r["session_id"] = sid;
                r["pid"]        = pid;
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(addr));
                r["address"]    = buf;
                r["size"]       = size;
                r["max_records_per_drain"] = max_records;
                return tool_result_t::ok("Page guard installed, session_id=" +
                                         std::to_string(sid), r);
            }

            if (op == "get_captures") {
                uint32_t sid = params.value("session_id", 0u);
                if (sid == 0)
                    return tool_result_t::error("'session_id' is required");

                const ULONGLONG t0 = GetTickCount64();
                diag::log_tagged_fmt("net_tools", "network_pg_sniff get_captures sid=%u", sid);
                auto caps = page_guard_engine::g_pg_engine.get_capture_records(sid);
                diag::log_tagged_fmt("net_tools", "network_pg_sniff get_captures count=%zu elapsed_ms=%llu", caps.size(), static_cast<unsigned long long>(GetTickCount64() - t0));
                json arr  = json::array();
                for (auto& c : caps) {
                    const auto& meta = c.metadata;
                    json o;
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(meta.fault_addr));
                    o["fault_addr"]     = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(meta.rip));
                    o["rip"]            = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(meta.ctx_rax));
                    o["rax"]            = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(meta.ctx_rcx));
                    o["rcx"]            = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(meta.ctx_rdx));
                    o["rdx"]            = buf;
                    o["timestamp"]      = meta.timestamp;
                    o["exception_code"] = meta.exception_code;
                    o["access_type"]    = meta.access_type == 0 ? "read" : (meta.access_type == 8 ? "execute" : "write");
                    page_guard_engine::serialize_payload_fields(o, c);
                    arr.push_back(o);
                }
                json r;
                r["session_id"] = sid;
                r["captures"]   = arr;
                r["count"]      = static_cast<int>(caps.size());
                return tool_result_t::ok(std::to_string(caps.size()) + " capture(s)", r);
            }

            if (op == "uninstall") {
                uint32_t sid = params.value("session_id", 0u);
                if (sid == 0)
                    return tool_result_t::error("'session_id' is required");

                bool ok = page_guard_engine::g_pg_engine.uninstall(sid);
                if (!ok)
                    return tool_result_t::error("Session " + std::to_string(sid) + " not found");
                return tool_result_t::ok("Session " + std::to_string(sid) + " uninstalled");
            }

            if (op == "list_sessions") {
                auto sessions = page_guard_engine::g_pg_engine.list_sessions();
                json arr = json::array();
                for (auto& s : sessions) {
                    json o;
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(s.target_addr));
                    o["session_id"]       = s.session_id;
                    o["pid"]              = s.pid;
                    o["target_addr"]      = buf;
                    o["region_size"]      = s.region_size;
                    o["pending_captures"] = static_cast<int>(s.pending_captures);
                    arr.push_back(o);
                }
                json r;
                r["sessions"] = arr;
                r["count"]    = static_cast<int>(sessions.size());
                return tool_result_t::ok(std::to_string(sessions.size()) + " session(s) active", r);
            }

            return tool_result_t::error("Unknown operation '" + op +
                                        "'. Use install|get_captures|uninstall|list_sessions");
        }, false});

    register_compat(srv, {
        OBFSTR("network_packet_callstack"), OBFSTR("network"),
        OBFSTR("Capture or retrieve the call stack associated with a network packet. "
               "When a packet is captured with a thread ID, this snapshots the thread's registers "
               "and walks the RBP chain to show exactly which code sent the packet. "
               "Operations: enable, disable, get (by packet_index), recent, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("Operation: enable|disable|get|recent|clear"), true},
         {OBFSTR("packet_index"), OBFSTR("number"), OBFSTR("Packet index for 'get' operation"), false},
         {OBFSTR("max_count"), OBFSTR("number"), OBFSTR("Max entries for 'recent' operation (default 64)"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error("Missing 'operation' parameter");

            diag::log_tagged_fmt("net_tools", "network_packet_callstack op=%s", op.c_str());
            if (op == "enable") {
                packet_callstack::set_enabled(true);
                diag::log_tagged("net_tools", "network_packet_callstack enabled");
                return tool_result_t::ok("Packet callstack capture enabled");
            }
            if (op == "disable") {
                packet_callstack::set_enabled(false);
                diag::log_tagged("net_tools", "network_packet_callstack disabled");
                return tool_result_t::ok("Packet callstack capture disabled");
            }
            if (op == "clear") {
                packet_callstack::clear();
                diag::log_tagged("net_tools", "network_packet_callstack cleared");
                return tool_result_t::ok("Packet callstack entries cleared");
            }
            if (op == "get") {
                uint64_t idx = args.value("packet_index", static_cast<uint64_t>(0));
                diag::log_tagged_fmt("net_tools", "network_packet_callstack get idx=%llu", static_cast<unsigned long long>(idx));
                packet_callstack::packet_callstack_entry_t entry{};
                if (!packet_callstack::get_callstack(idx, entry))
                    return tool_result_t::error("No callstack found for packet " + std::to_string(idx));
                json r;
                r["packet_index"] = entry.packet_index;
                r["pid"] = entry.pid;
                r["tid"] = entry.tid;
                r["rip"] = (std::ostringstream() << "0x" << std::hex << entry.rip).str();
                r["rsp"] = (std::ostringstream() << "0x" << std::hex << entry.rsp).str();
                json frames = json::array();
                for (const auto& f : entry.frames) {
                    json fj;
                    fj["address"] = (std::ostringstream() << "0x" << std::hex << f.address).str();
                    fj["return_address"] = (std::ostringstream() << "0x" << std::hex << f.return_address).str();
                    fj["module"] = f.module_name;
                    fj["offset"] = (std::ostringstream() << "0x" << std::hex << f.module_offset).str();
                    frames.push_back(fj);
                }
                r["frames"] = frames;
                return tool_result_t::ok(std::to_string(entry.frames.size()) + " frames captured", r);
            }
            if (op == "recent") {
                size_t max_count = args.value("max_count", 64);
                auto entries = packet_callstack::get_recent(max_count);
                diag::log_tagged_fmt("net_tools", "network_packet_callstack recent count=%zu", entries.size());
                json arr = json::array();
                for (const auto& e : entries) {
                    json ej;
                    ej["packet_index"] = e.packet_index;
                    ej["pid"] = e.pid;
                    ej["tid"] = e.tid;
                    ej["frame_count"] = static_cast<int>(e.frames.size());
                    if (!e.frames.empty())
                        ej["top_frame"] = e.frames[0].module_name + "+0x" +
                            (std::ostringstream() << std::hex << e.frames[0].module_offset).str();
                    arr.push_back(ej);
                }
                return tool_result_t::ok(std::to_string(entries.size()) + " callstack entries", arr);
            }
            return tool_result_t::error("Unknown operation '" + op + "'. Use enable|disable|get|recent|clear");
        }, false});

    register_compat(srv, {
        OBFSTR("api_monitor_start"), OBFSTR("network"),
        OBFSTR("Start a native dynamic API monitor for an attached x64 target process. "
               "Resolves requested APIs such as ws2_32.dll!send, ws2_32.dll!WSASend, "
               "kernel32.dll!DeviceIoControl, or ntdll.dll!NtDeviceIoControlFile in the target, "
               "programs hardware execute breakpoints through the existing driver bridge, and "
               "records calls in a background debug-event loop without patching target code. "
               "Captured events include API name, timestamp, thread, return address, caller module "
               "where resolvable, handle/socket/IOCTL metadata, and bounded hex buffers for outbound "
               "or input buffers where obtainable."),
        {{OBFSTR("apis"), OBFSTR("array"), OBFSTR("Array of API specs like 'ws2_32.dll!send' or objects with api, buffer_kind, buffer_reg, size_reg"), true},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target PID. Defaults to the currently attached driver target"), false},
         {OBFSTR("log_callstack"), OBFSTR("boolean"), OBFSTR("Capture a bounded callstack for each API hit"), false},
         {OBFSTR("capture_buffer"), OBFSTR("boolean"), OBFSTR("Read bounded input/outbound buffers from the target process"), false},
         {OBFSTR("max_capture_bytes"), OBFSTR("number"), OBFSTR("Maximum bytes captured per buffer, capped at 2048"), false},
         {OBFSTR("max_events"), OBFSTR("number"), OBFSTR("Maximum buffered events, capped at 16384"), false}},
        api_monitor_start, false});

    register_compat(srv, {
        OBFSTR("api_monitor_results"), OBFSTR("network"),
        OBFSTR("Return buffered native API monitor events. Results can be filtered by API name and "
               "include exact return addresses, caller address when direct-call decoding is possible, "
               "register snapshots, endpoint/handle/IOCTL metadata, and bounded hex buffer captures. "
               "Optional clear drains buffered events; optional stop tears down the active monitor."),
        {{OBFSTR("limit"), OBFSTR("number"), OBFSTR("Maximum events to return, capped at 512"), false},
         {OBFSTR("filter_api"), OBFSTR("string"), OBFSTR("Case-insensitive substring filter for API name"), false},
         {OBFSTR("clear"), OBFSTR("boolean"), OBFSTR("Clear buffered events after reading"), false},
         {OBFSTR("stop"), OBFSTR("boolean"), OBFSTR("Stop the active monitor after reading results"), false}},
        api_monitor_results, false});

    register_compat(srv, {
        OBFSTR("network_pre_encrypt_hook"), OBFSTR("network"),
        OBFSTR("Hook SSL/TLS encryption functions to capture plaintext data before encryption. "
               "Auto-detects SSL_write, PR_Write, EncryptMessage, send, WSASend across OpenSSL, NSS, Schannel, Winsock. "
               "Uses hardware breakpoints (DR0-DR3) with normal Windows debug-event delivery for authorized lab targets. "
               "Operations: auto_hook (auto-detect and hook), hook_address (manual), unhook_all, get_captures, clear, status."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("Operation: auto_hook|hook_address|unhook_all|get_captures|clear|status"), true},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID for auto_hook or hook_address"), false},
         {OBFSTR("address"), OBFSTR("string"), OBFSTR("Hex address for hook_address (e.g. '0x7FFA1234')"), false},
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Function name label for hook_address"), false},
         {OBFSTR("buffer_reg"), OBFSTR("number"), OBFSTR("Register index for buffer ptr: 0=RCX 1=RDX 2=R8 3=R9"), false},
         {OBFSTR("size_reg"), OBFSTR("number"), OBFSTR("Register index for size param"), false},
         {OBFSTR("max_count"), OBFSTR("number"), OBFSTR("Max captures to return (default 64)"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error("Missing 'operation' parameter");

            diag::log_tagged_fmt("net_tools", "network_pre_encrypt_hook op=%s", op.c_str());
            if (op == "auto_hook") {
                uint32_t pid = args.value("pid", static_cast<uint32_t>(0));
                if (pid == 0)
                    return tool_result_t::error("Missing 'pid' parameter for auto_hook");
                diag::log_tagged_fmt("net_tools", "network_pre_encrypt_hook auto_hook pid=%u", pid);
                if (!pre_encrypt_hook::auto_hook(pid)) {
                    diag::log_tagged_fmt("net_tools", "network_pre_encrypt_hook auto_hook failed pid=%u", pid);
                    json r = pre_encrypt_status_payload(pid);
                    r["operation"] = "auto_hook";
                    r["requested_pid"] = pid;
                    r["hooked"] = false;
                    return tool_result_t::error("Failed to auto-hook encryption functions in PID " + std::to_string(pid), r);
                }
                const bool started_polling = pre_encrypt_hook::start_polling();
                if (!started_polling) {
                    DWORD err = pre_encrypt_hook::g_state.debugger_error.load();
                json r = pre_encrypt_status_payload(pid);
                r["operation"] = "auto_hook";
                r["requested_pid"] = pid;
                r["started_polling"] = false;
                r["hooked"] = false;
                r["start_error"] = static_cast<unsigned long>(err);
                pre_encrypt_hook::unhook_all();
                    return tool_result_t::error("Failed to start authorized debug capture for PID " + std::to_string(pid) +
                                                ", error=" + std::to_string(static_cast<unsigned long>(err)), r);
                }
                json r = pre_encrypt_status_payload(pid);
                r["operation"] = "auto_hook";
                r["requested_pid"] = pid;
                r["started_polling"] = started_polling;
                r["hooked"] = r.value("hook_count", 0) > 0;
                r["hooks_installed"] = r["hook_count"];
                diag::log_tagged_fmt("net_tools", "network_pre_encrypt_hook auto_hook hooks=%d armed=%u captures=%d",
                    r.value("hook_count", 0),
                    r.value("armed_thread_count", 0u),
                    r.value("capture_count", 0));
                return tool_result_t::ok("Hooked " + std::to_string(r.value("hook_count", 0)) + " encryption functions", r);
            }
            if (op == "hook_address") {
                std::string addr_str = args.value("address", "");
                if (addr_str.empty())
                    return tool_result_t::error("Missing 'address' parameter");
                uint32_t pid = args.value("pid", static_cast<uint32_t>(0));
                if (pid != 0 && driver_bridge::attached_pid() != pid) {
                    bool already_attached = false;
                    const auto attached = driver_bridge::attached_pids();
                    for (uint32_t attached_pid : attached) {
                        if (attached_pid == pid) {
                            already_attached = true;
                            break;
                        }
                    }
                    if (already_attached) {
                        if (!driver_bridge::set_active_pid(pid))
                            return tool_result_t::error("Failed to select PID " + std::to_string(pid));
                    } else if (!driver_bridge::attach(pid)) {
                        return tool_result_t::error("Failed to attach PID " + std::to_string(pid));
                    }
                }
                if (pid == 0 && driver_bridge::attached_pid() == 0)
                    return tool_result_t::error("Missing 'pid' parameter and no driver target is attached");
                uint64_t addr = std::strtoull(addr_str.c_str(), nullptr, 16);
                std::string name = args.value("name", "custom_hook");
                uint32_t buf_reg = args.value("buffer_reg", static_cast<uint32_t>(1));
                uint32_t sz_reg = args.value("size_reg", static_cast<uint32_t>(2));
                if (!pre_encrypt_hook::hook_address(addr, name, buf_reg, sz_reg))
                    return tool_result_t::error("Failed to hook address " + addr_str);
                const bool started_polling = pre_encrypt_hook::start_polling();
                if (!started_polling) {
                    DWORD err = pre_encrypt_hook::g_state.debugger_error.load();
                    json r = pid == 0 ? pre_encrypt_status_payload() : pre_encrypt_status_payload(pid);
                    r["operation"] = "hook_address";
                    r["address"] = hex_u64(addr);
                    r["name"] = name;
                    r["started_polling"] = false;
                    r["hooked"] = false;
                    r["start_error"] = static_cast<unsigned long>(err);
                    pre_encrypt_hook::unhook_all();
                    return tool_result_t::error("Failed to start authorized debug capture for address " + addr_str +
                                                ", error=" + std::to_string(static_cast<unsigned long>(err)), r);
                }
                json r = pid == 0 ? pre_encrypt_status_payload() : pre_encrypt_status_payload(pid);
                json hook;
                const bool found = pre_encrypt_find_hook(addr, hook);
                r["operation"] = "hook_address";
                r["address"] = hex_u64(addr);
                r["name"] = name;
                r["hooked"] = found && hook.value("hooked", false);
                r["bp_slot"] = found ? hook.value("bp_slot", 0u) : 0u;
                r["started_polling"] = started_polling;
                if (found)
                    r["hook"] = std::move(hook);
                return tool_result_t::ok("Hooked " + name + " at " + addr_str, r);
            }
            if (op == "unhook_all") {
                json before = pre_encrypt_status_payload();
                const uint32_t removed = pre_encrypt_hook::unhook_all();
                json r = pre_encrypt_status_payload();
                r["operation"] = "unhook_all";
                r["unhooked_count"] = removed;
                r["removed_hook_count"] = removed;
                r["hook_count_before"] = before.value("hook_count", 0);
                r["capture_count_before"] = before.value("capture_count", 0);
                r["hooked"] = false;
                return tool_result_t::ok("All pre-encryption hooks removed", r);
            }
            if (op == "get_captures") {
                size_t max_count = args.value("max_count", 64);
                auto caps = pre_encrypt_hook::get_captures(max_count);
                diag::log_tagged_fmt("net_tools", "network_pre_encrypt_hook get_captures count=%zu", caps.size());
                json arr = json::array();
                for (const auto& c : caps) {
                    json cj;
                    cj["tid"] = c.tid;
                    cj["function"] = c.function_name;
                    cj["buffer_size"] = static_cast<int>(c.buffer.size());
                    if (c.buffer.size() <= 256) {
                        std::string text(c.buffer.begin(), c.buffer.end());
                        bool printable = true;
                        for (auto b : c.buffer) if (b < 0x20 && b != '\n' && b != '\r' && b != '\t') { printable = false; break; }
                        if (printable) cj["plaintext"] = text;
                        else {
                            std::ostringstream hex;
                            for (size_t i = 0; i < c.buffer.size() && i < 64; ++i)
                                hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c.buffer[i]) << " ";
                            cj["hex_preview"] = hex.str();
                        }
                    } else {
                        std::ostringstream hex;
                        for (size_t i = 0; i < 64 && i < c.buffer.size(); ++i)
                            hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c.buffer[i]) << " ";
                        cj["hex_preview"] = hex.str();
                    }
                    if (!c.module_name.empty())
                        cj["module"] = c.module_name + "+0x" + (std::ostringstream() << std::hex << c.module_offset).str();
                    arr.push_back(cj);
                }
                return tool_result_t::ok(std::to_string(caps.size()) + " plaintext captures", arr);
            }
            if (op == "clear") {
                const size_t cleared = pre_encrypt_hook::clear_captures();
                json r = pre_encrypt_status_payload();
                r["operation"] = "clear";
                r["cleared_count"] = cleared;
                r["clear_count"] = cleared;
                r["hooked"] = r.value("hook_count", 0) > 0;
                return tool_result_t::ok("Pre-encryption captures cleared", r);
            }
            if (op == "status") {
                json r = pre_encrypt_status_payload();
                r["operation"] = "status";
                r["hooked"] = r.value("hook_count", 0) > 0;
                return tool_result_t::ok(pre_encrypt_hook::is_active() ? "Active" : "Inactive", r);
            }
            return tool_result_t::error("Unknown operation '" + op + "'. Use auto_hook|hook_address|unhook_all|get_captures|clear|status");
        }, false});

    register_compat(srv, {
        OBFSTR("network_display_filter"), OBFSTR("network"),
        OBFSTR("Compile and test BPF-style display filter expressions for packet filtering. "
               "Supports fields: tcp.port, ip.src, ip.dst, http.method, http.status, dns.query, "
               "tcp.len, pid, protocol, direction, host, summary. "
               "Operators: ==, !=, >, <, >=, <=, contains. Boolean: && || !. Grouping: (). "
               "Operations: compile (validate expression), test (test against packet fields), validate."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("Operation: compile|test|validate"), true},
         {OBFSTR("expression"), OBFSTR("string"), OBFSTR("Filter expression e.g. 'tcp.port == 443 && http.method == \"POST\"'"), true},
         {OBFSTR("packet"), OBFSTR("object"), OBFSTR("Packet fields object for 'test' operation"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "compile");
            std::string expr = args.value("expression", "");
            if (expr.empty())
                return tool_result_t::error("Missing 'expression' parameter");

            diag::log_tagged_fmt("net_tools", "network_display_filter op=%s expr_len=%zu", op.c_str(), expr.size());
            if (op == "validate") {
                std::string error;
                bool valid = display_filter::validate(expr, error);
                diag::log_tagged_fmt("net_tools", "network_display_filter validate valid=%d", (int)valid);
                json r;
                r["valid"] = valid;
                if (!valid) r["error"] = error;
                return tool_result_t::ok(valid ? "Filter is valid" : "Filter invalid: " + error, r);
            }
            if (op == "compile" || op == "test") {
                auto filter = display_filter::compile(expr);
                if (!filter.valid)
                    return tool_result_t::error("Filter compilation failed: " + filter.error);

                if (op == "compile") {
                    json r;
                    r["valid"] = true;
                    r["expression"] = expr;
                    return tool_result_t::ok("Filter compiled successfully", r);
                }

                display_filter::packet_fields_t pkt{};
                if (args.contains("packet") && args["packet"].is_object()) {
                    const auto& p = args["packet"];
                    pkt.pid = p.value("pid", static_cast<uint32_t>(0));
                    pkt.protocol = static_cast<uint8_t>(p.value("protocol", 0));
                    pkt.direction = static_cast<uint8_t>(p.value("direction", 0));
                    pkt.src_port = static_cast<uint16_t>(p.value("src_port", 0));
                    pkt.dst_port = static_cast<uint16_t>(p.value("dst_port", 0));
                    pkt.payload_size = p.value("payload_size", static_cast<uint32_t>(0));
                    pkt.src_ip = p.value("src_ip", "");
                    pkt.dst_ip = p.value("dst_ip", "");
                    pkt.protocol_label = p.value("protocol_label", "");
                    pkt.http_method = p.value("http_method", "");
                    pkt.http_status = p.value("http_status", 0);
                    pkt.dns_query = p.value("dns_query", "");
                    pkt.summary = p.value("summary", "");
                    pkt.host = p.value("host", "");
                }

                bool match = filter.matches(pkt);
                diag::log_tagged_fmt("net_tools", "network_display_filter test matches=%d", (int)match);
                json r;
                r["matches"] = match;
                r["expression"] = expr;
                return tool_result_t::ok(match ? "Packet matches filter" : "Packet does not match filter", r);
            }
            return tool_result_t::error("Unknown operation '" + op + "'. Use compile|test|validate");
        }, true});

    register_compat(srv, {
        OBFSTR("network_protobuf_decode"), OBFSTR("network"),
        OBFSTR("Decode, encode, and edit Protocol Buffer wire format data without .proto files. "
               "Supports raw protobuf and gRPC length-prefixed frames. "
               "Operations: decode (binary to field tree), encode (field tree to binary), "
               "decode_grpc (gRPC frames), modify (edit field by path), auto_detect (heuristic type inference)."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("Operation: decode|encode|decode_grpc|modify|auto_detect"), true},
         {OBFSTR("hex_data"), OBFSTR("string"), OBFSTR("Hex-encoded protobuf data for decode/decode_grpc"), false},
         {OBFSTR("fields"), OBFSTR("array"), OBFSTR("Field tree array for encode operation"), false},
         {OBFSTR("path"), OBFSTR("string"), OBFSTR("Dot-separated field path for modify (e.g. '1.3.2')"), false},
         {OBFSTR("value"), OBFSTR("string"), OBFSTR("New value for modify operation"), false},
         {OBFSTR("field_type"), OBFSTR("string"), OBFSTR("Type for modify: uint|sint|int|bool|float|double|string|bytes"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error("Missing 'operation' parameter");

            diag::log_tagged_fmt("net_tools", "network_protobuf_decode op=%s", op.c_str());
            auto hex_to_bytes = [](const std::string& hex) -> std::vector<uint8_t> {
                std::vector<uint8_t> result;
                for (size_t i = 0; i < hex.size(); i += 2) {
                    while (i < hex.size() && (hex[i] == ' ' || hex[i] == ':')) ++i;
                    if (i + 1 >= hex.size()) break;
                    std::string byte_str = hex.substr(i, 2);
                    result.push_back(static_cast<uint8_t>(std::strtoul(byte_str.c_str(), nullptr, 16)));
                }
                return result;
            };

            auto bytes_to_hex = [](const std::vector<uint8_t>& data) -> std::string {
                const char hexc[] = "0123456789abcdef";
                std::string out;
                out.reserve(data.size() * 3);
                for (size_t i = 0; i < data.size(); ++i) {
                    if (i > 0) out += ' ';
                    out += hexc[(data[i] >> 4) & 0xF];
                    out += hexc[data[i] & 0xF];
                }
                return out;
            };

            auto field_to_json = [](const protobuf_codec::field_t& f, auto& self) -> json {
                json fj;
                fj["field_number"] = f.field_number;
                fj["wire_type"] = static_cast<int>(f.wire_type);
                fj["display_type"] = static_cast<int>(f.display_type);
                fj["value"] = protobuf_codec::format_field_value(f);
                if (f.is_nested && !f.nested_fields.empty()) {
                    json nested = json::array();
                    for (const auto& nf : f.nested_fields)
                        nested.push_back(self(nf, self));
                    fj["nested"] = nested;
                }
                return fj;
            };

            if (op == "decode") {
                std::string hex = args.value("hex_data", "");
                if (hex.empty())
                    return tool_result_t::error("Missing 'hex_data' parameter");
                auto bytes = hex_to_bytes(hex);
                diag::log_tagged_fmt("net_tools", "network_protobuf_decode decode bytes=%zu", bytes.size());
                auto fields = protobuf_codec::decode(bytes.data(), bytes.size());
                diag::log_tagged_fmt("net_tools", "network_protobuf_decode decode fields=%zu", fields.size());
                if (fields.empty())
                    return tool_result_t::error("Failed to decode protobuf data");
                protobuf_codec::auto_detect_types(fields);
                json arr = json::array();
                for (const auto& f : fields)
                    arr.push_back(field_to_json(f, field_to_json));
                json r;
                r["fields"] = arr;
                r["field_count"] = static_cast<int>(fields.size());
                return tool_result_t::ok(std::to_string(fields.size()) + " protobuf fields decoded", r);
            }
            if (op == "decode_grpc") {
                std::string hex = args.value("hex_data", "");
                if (hex.empty())
                    return tool_result_t::error("Missing 'hex_data' parameter");
                auto bytes = hex_to_bytes(hex);
                auto frames = protobuf_codec::parse_grpc_frames(bytes.data(), bytes.size());
                if (frames.empty())
                    return tool_result_t::error("No valid gRPC frames found");
                json arr = json::array();
                for (size_t i = 0; i < frames.size(); ++i) {
                    json fj;
                    fj["frame_index"] = static_cast<int>(i);
                    fj["compressed"] = frames[i].compressed != 0;
                    fj["length"] = frames[i].length;
                    auto fields = protobuf_codec::decode(frames[i].data.data(), frames[i].data.size());
                    protobuf_codec::auto_detect_types(fields);
                    json fields_arr = json::array();
                    for (const auto& f : fields)
                        fields_arr.push_back(field_to_json(f, field_to_json));
                    fj["fields"] = fields_arr;
                    arr.push_back(fj);
                }
                json r;
                r["frames"] = arr;
                r["frame_count"] = static_cast<int>(frames.size());
                return tool_result_t::ok(std::to_string(frames.size()) + " gRPC frames decoded", r);
            }
            if (op == "auto_detect") {
                std::string hex = args.value("hex_data", "");
                if (hex.empty())
                    return tool_result_t::error("Missing 'hex_data' parameter");
                auto bytes = hex_to_bytes(hex);
                auto fields = protobuf_codec::decode(bytes.data(), bytes.size());
                if (fields.empty())
                    return tool_result_t::error("Failed to decode protobuf data");
                protobuf_codec::auto_detect_types(fields);
                json arr = json::array();
                for (const auto& f : fields)
                    arr.push_back(field_to_json(f, field_to_json));
                json r;
                r["fields"] = arr;
                return tool_result_t::ok("Type detection complete", r);
            }
            return tool_result_t::error("Unknown operation '" + op + "'. Use decode|encode|decode_grpc|modify|auto_detect");
        }, true});





}

}
