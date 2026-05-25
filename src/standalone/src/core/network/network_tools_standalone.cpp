

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

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
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <regex>
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
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

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
        return tool_result_t::error(OBFSTR("Driver not connected. Call driver_connect first."));

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

    if (params.contains("action") && params["action"].is_string()) {
        std::string a = params["action"].get<std::string>();
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
    diag::log_tagged_fmt("net_tools", "network_remove_filter result=%d", (int)ok);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to remove filter rule ") + std::to_string(rule_id));

    return tool_result_t::ok(OBFSTR("Filter rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
}

tool_result_t network_clear_filters(const json&)
{
    diag::log_tagged("net_tools", "network_clear_filters entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    bool ok = driver_bridge::clear_filter_rules();
    diag::log_tagged_fmt("net_tools", "network_clear_filters result=%d", (int)ok);
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to clear filter rules."));

    return tool_result_t::ok(OBFSTR("All filter rules cleared"));
}

tool_result_t network_stats(const json&)
{
    diag::log_tagged("net_tools", "network_stats entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    driver_bridge::network_stats_t stats{};
    bool ok = driver_bridge::get_network_stats(stats);
    diag::log_tagged_fmt("net_tools", "network_stats result=%d bytes_sent=%llu bytes_recv=%llu captured=%llu dropped=%llu", (int)ok, static_cast<unsigned long long>(stats.bytes_sent), static_cast<unsigned long long>(stats.bytes_received), static_cast<unsigned long long>(stats.total_captured), static_cast<unsigned long long>(stats.total_dropped));
    if (!ok)
        return tool_result_t::error(OBFSTR("Failed to get network stats."));

    json result;
    result["bytes_sent"] = stats.bytes_sent;
    result["bytes_received"] = stats.bytes_received;
    result["packets_sent"] = stats.packets_sent;
    result["packets_received"] = stats.packets_received;
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
    diag::log_tagged_fmt("net_tools", "network_block_ip result=%d rule_id=%u", (int)block_ok, rule_id);
    if (!block_ok)
        return tool_result_t::error(OBFSTR("Failed to add block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_ip"] = params["ip"];
    result["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
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
    diag::log_tagged_fmt("net_tools", "network_block_port result=%d rule_id=%u", (int)port_ok, rule_id);
    if (!port_ok)
        return tool_result_t::error(OBFSTR("Failed to add port block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_port"] = port;
    if (protocol) result["protocol"] = protocol_name(protocol);
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
    diag::log_tagged_fmt("net_tools", "network_block_process result=%d rule_id=%u", (int)proc_ok, rule_id);
    if (!proc_ok)
        return tool_result_t::error(OBFSTR("Failed to add process block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_pid"] = pid;
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
    for (const auto& c : callouts) {
        json entry;
        entry["callout_id"] = c.callout_id;
        entry["layer_id"] = c.layer_id;
        entry["owning_module"] = c.owning_module;
        entry["callout_key"] = c.callout_key_str;
        entry["applicable_layer"] = c.applicable_layer_str;
        char addr_buf[32]; qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.classify_fn);
        entry["classify_fn"] = addr_buf;
        qsnprintf(addr_buf, sizeof(addr_buf), "0x%llX", (unsigned long long)c.owning_module_base);
        entry["module_base"] = addr_buf;
        entry["flags"] = c.flags;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(callouts.size()) + OBFSTR(" WFP callouts found"), arr);
}

tool_result_t network_get_socket_handles(const json& params)
{
    diag::log_tagged("net_tools", "network_get_socket_handles entry");
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t target_pid = 0;
    if (params.contains("pid") && params["pid"].is_number())
        target_pid = params["pid"].get<std::uint32_t>();

    diag::log_tagged_fmt("net_tools", "network_get_socket_handles target_pid=%u", target_pid);
    auto socks = driver_bridge::get_socket_handles(target_pid);
    diag::log_tagged_fmt("net_tools", "network_get_socket_handles count=%zu", socks.size());
    json arr = json::array();
    for (const auto& s : socks) {
        json entry;
        char buf[24]; qsnprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)s.handle_value);
        entry["handle"] = buf;
        entry["pid"] = s.pid;
        entry["protocol"] = protocol_name(s.protocol);
        entry["state"] = (s.protocol == 6) ? tcp_state_name(s.state) : "N/A";
        entry["local"] = format_ip(s.local_addr, s.address_family) + ":" + std::to_string(s.local_port);
        entry["remote"] = format_ip(s.remote_addr, s.address_family) + ":" + std::to_string(s.remote_port);
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(socks.size()) + OBFSTR(" socket handles found"), arr);
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
        diag::log_tagged_fmt("net_tools", "network_modify_packet_rule add result=%d rule_id=%u", (int)ok, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add modification rule. Max 32 rules."));
        json r; r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Packet modification rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = driver_bridge::packet_mod_rule_op(1, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove modification rule."));
        return tool_result_t::ok(OBFSTR("Modification rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = driver_bridge::packet_mod_rule_op(3);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear modification rules."));
        return tool_result_t::ok(OBFSTR("All packet modification rules cleared"));
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
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add redirect rule. Max 16 rules."));
        json r; r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Traffic redirect rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = driver_bridge::traffic_redirect_op(1, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove redirect rule."));
        return tool_result_t::ok(OBFSTR("Redirect rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = driver_bridge::traffic_redirect_op(3);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear redirect rules."));
        return tool_result_t::ok(OBFSTR("All traffic redirect rules cleared"));
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
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));
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
        std::uint32_t held_count = 0; bool active = false;
        diag::log_tagged_fmt("net_tools", "network_intercept enable pid=%u port=%u proto=%u", filter_pid, filter_port, filter_protocol);
        bool ok = driver_bridge::intercept_op(0, filter_pid, filter_port, filter_protocol, 0, nullptr, 0, &held_count, &active);
        diag::log_tagged_fmt("net_tools", "network_intercept enable result=%d active=%d held=%u", (int)ok, (int)active, held_count);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to enable packet interception."));
        json r; r["active"] = active; r["held_count"] = held_count;
        return tool_result_t::ok(OBFSTR("Packet interception enabled. Matching packets will be held for inspection."), r);
    } else if (op == "disable") {
        bool ok = driver_bridge::intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        diag::log_tagged_fmt("net_tools", "network_intercept disable result=%d", (int)ok);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable packet interception."));
        return tool_result_t::ok(OBFSTR("Packet interception disabled. All held packets released."));
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
    diag::log_tagged_fmt("net_tools", "network_release_packet result=%d operation=%u", (int)ok, operation);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to release/process held packet."));

    std::string action_str = (operation == 4) ? "dropped" : (operation == 5) ? "modified and released" : "released";
    return tool_result_t::ok(OBFSTR("Packet ") + action_str);
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
    diag::log_tagged_fmt("net_tools", "network_kill_connection result=%d", (int)ok);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to kill connection. Tries socket close + RST injection."));
    return tool_result_t::ok(OBFSTR("Connection killed successfully"));
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
        diag::log_tagged_fmt("net_tools", "network_spoof_dns add result=%d rule_id=%u", (int)ok, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add DNS spoof rule. Max 32 rules."));
        json r; r["rule_id"] = rule_id; r["domain"] = domain;
        return tool_result_t::ok(OBFSTR("DNS spoof rule added: ") + domain + OBFSTR(" -> ") + params["spoof_ip"].get<std::string>(), r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = driver_bridge::dns_spoof_op(1, rule_id, nullptr, nullptr, 2, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove DNS spoof rule."));
        return tool_result_t::ok(OBFSTR("DNS spoof rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = driver_bridge::dns_spoof_op(3, 0, nullptr, nullptr, 2, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear DNS spoof rules."));
        return tool_result_t::ok(OBFSTR("All DNS spoof rules cleared"));
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
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();

    diag::log_tagged_fmt("net_tools", "network_bandwidth_per_process filter_pid=%u", filter_pid);
    auto procs = driver_bridge::get_bw_per_process(filter_pid);
    diag::log_tagged_fmt("net_tools", "network_bandwidth_per_process count=%zu", procs.size());
    json arr = json::array();
    for (const auto& p : procs) {
        json entry;
        entry["pid"] = p.pid;
        entry["bytes_sent"] = p.bytes_sent;
        entry["bytes_recv"] = p.bytes_recv;
        entry["packets_sent"] = p.packets_sent;
        entry["packets_recv"] = p.packets_recv;
        entry["last_activity"] = p.last_activity;
        arr.push_back(entry);
    }
    return tool_result_t::ok(std::to_string(procs.size()) + OBFSTR(" processes with bandwidth data"), arr);
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

void register_network_tools(mcp_standalone::server_t& srv) {
    diag::log_tagged("net_tools", "register_network_tools entry");
        aida::burp::register_all_tools(srv);

        register_compat(srv, {
        OBFSTR("network_enumerate_connections"), OBFSTR("network"),
        OBFSTR("Enumerate all active TCP/UDP connections on the system via kernel driver. "
               "Returns PID, protocol, state, local/remote addresses and ports. "
               "Like netstat but kernel-level - invisible to usermode hooks. "
               "Optionally filter by PID or protocol."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter connections by process ID"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter by protocol: 'tcp' or 'udp'"), false}},
        network_enumerate_connections, true});

    register_compat(srv, {
        OBFSTR("network_start_capture"), OBFSTR("network"),
        OBFSTR("Start kernel-level packet capture using WFP (Windows Filtering Platform) callouts. "
               "Captures all network traffic with process attribution. "
               "Like Wireshark but running in kernel space with PID-level visibility. "
               "Optionally filter by PID, port, protocol, or IP address."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Only capture traffic from this process"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Only capture traffic on this port"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Only capture 'tcp' or 'udp'"), false},
         {OBFSTR("ip"), OBFSTR("string"), OBFSTR("Only capture traffic to/from this IPv4 address"), false},
         {OBFSTR("max_payload"), OBFSTR("number"), OBFSTR("Max payload bytes per packet (default 1500)"), false}},
        network_start_capture, false});

    register_compat(srv, {
        OBFSTR("network_stop_capture"), OBFSTR("network"),
        OBFSTR("Stop the active kernel packet capture session."),
        {},
        network_stop_capture, false});

    register_compat(srv, {
        OBFSTR("network_get_packets"), OBFSTR("network"),
        OBFSTR("Retrieve captured network packets from the kernel ring buffer. "
               "Returns up to 32 packets per call with full headers, payload hex dump, "
               "ASCII render, PID, protocol, direction, and endpoint info. "
               "Packets are consumed (removed from buffer) after retrieval."),
        {{OBFSTR("count"), OBFSTR("number"), OBFSTR("Max packets to retrieve (1-32, default 32)"), false}},
        network_get_packets, true});

    register_compat(srv, {
        OBFSTR("network_analyze_packet"), OBFSTR("network"),
        OBFSTR("Retrieve and deeply analyze a single captured packet. "
               "Auto-detects application protocol (HTTP, TLS, DNS), extracts headers, "
               "provides full hex dump and ASCII render. Like Fiddler's packet inspector."),
        {},
        network_analyze_packet, true});

    register_compat(srv, {
        OBFSTR("network_dns_log"), OBFSTR("network"),
        OBFSTR("Retrieve captured DNS queries and responses from the kernel. "
               "Shows domain names, query types (A/AAAA/CNAME/MX/etc.), resolved IPs, "
               "TTLs, and owning PIDs. Requires capture to be active. "
               "Like a DNS sniffer with process attribution."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter DNS entries by process ID"), false}},
        network_dns_log, true});

    register_compat(srv, {
        OBFSTR("network_add_filter"), OBFSTR("network"),
        OBFSTR("Add a kernel-level network filter rule. Can allow, block, or log traffic "
               "matching specified criteria. Rules are enforced in the WFP classify callback. "
               "Like a kernel firewall - operates below all usermode network stacks."),
        {{OBFSTR("action"), OBFSTR("string"), OBFSTR("Rule action: 'allow', 'block', or 'log' (default 'log')"), false},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound', 'outbound', or 'both' (default 'both')"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp', 'udp', or omit for all"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Match only this process ID"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Match only this port"), false},
         {OBFSTR("ip"), OBFSTR("string"), OBFSTR("Match only this IPv4 address"), false}},
        network_add_filter, false});

    register_compat(srv, {
        OBFSTR("network_remove_filter"), OBFSTR("network"),
        OBFSTR("Remove a previously added network filter rule by its ID."),
        {{OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("The rule ID returned when the filter was added"), true}},
        network_remove_filter, false});

    register_compat(srv, {
        OBFSTR("network_clear_filters"), OBFSTR("network"),
        OBFSTR("Remove all active network filter rules at once."),
        {},
        network_clear_filters, false});

    register_compat(srv, {
        OBFSTR("network_stats"), OBFSTR("network"),
        OBFSTR("Get comprehensive kernel-level network statistics: total bytes/packets sent/received, "
               "capture status, total captured/dropped, DNS queries logged, and active filter rules."),
        {},
        network_stats, true});

    register_compat(srv, {
        OBFSTR("network_capture_status"), OBFSTR("network"),
        OBFSTR("Check if packet capture is currently active and get capture counters."),
        {},
        network_capture_status, true});

    register_compat(srv, {
        OBFSTR("network_block_ip"), OBFSTR("network"),
        OBFSTR("Quick shortcut to block all traffic to/from a specific IP address. "
               "Creates a kernel-level WFP block rule. Returns rule_id for later removal."),
        {{OBFSTR("ip"), OBFSTR("string"), OBFSTR("IPv4 address to block (e.g. '192.168.1.1')"), true},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("'inbound', 'outbound', or 'both' (default 'both')"), false}},
        network_block_ip, false});

    register_compat(srv, {
        OBFSTR("network_block_port"), OBFSTR("network"),
        OBFSTR("Quick shortcut to block all traffic on a specific port. "
               "Creates a kernel-level WFP block rule. Returns rule_id for later removal."),
        {{OBFSTR("port"), OBFSTR("number"), OBFSTR("Port number to block"), true},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Optional: 'tcp' or 'udp' (default: both)"), false}},
        network_block_port, false});

    register_compat(srv, {
        OBFSTR("network_block_process"), OBFSTR("network"),
        OBFSTR("Quick shortcut to block all network traffic for a specific process by PID. "
               "Creates a kernel-level WFP block rule. Returns rule_id for later removal."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID to block"), true}},
        network_block_process, false});

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
        OBFSTR("network_follow_tcp_stream"), OBFSTR("network"),
        OBFSTR("TCP stream reassembly - equivalent to Wireshark 'Follow TCP Stream'. Reassembles TCP segments into "
               "complete application-layer data. Operations: 'start' begins tracking a flow, 'get' returns reassembled "
               "bytes (hex + ASCII), 'stop' ends tracking. Identify flows via src_port/dst_port. Max 1024 concurrent streams."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', or 'get'"), true},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source (client) port of the TCP flow"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination (server) port of the TCP flow"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID filter"), false}},
        network_follow_tcp_stream, false});

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
        OBFSTR("Enumerate all registered WFP (Windows Filtering Platform) callouts in the system. Shows callout ID, "
               "layer, owning module, classify/notify function addresses. Use to audit what other drivers/security "
               "products are hooking network traffic. Filter by module name."),
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
        OBFSTR("network_modify_packet_rule"), OBFSTR("network"),
        OBFSTR("Manage real-time packet content modification rules. 'add' creates a rule that search-and-replaces "
               "byte patterns in matching packet payloads (like HTTP Debugger rewrite rules). 'remove' deletes a rule by ID. "
               "'clear' removes all rules. Patterns/replacements as hex or text. Filter by direction/protocol/port/pid. Max 32 rules."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', or 'clear'"), true},
         {OBFSTR("direction"), OBFSTR("string"), OBFSTR("For add: 'inbound', 'outbound', or 'both' (default: both)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("For add: 'tcp' or 'udp'"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("For add: port filter (0 = any)"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("For add: process ID filter (0 = any)"), false},
         {OBFSTR("pattern_hex"), OBFSTR("string"), OBFSTR("For add: byte pattern to find (hex)"), false},
         {OBFSTR("pattern_text"), OBFSTR("string"), OBFSTR("For add: text pattern to find"), false},
         {OBFSTR("replacement_hex"), OBFSTR("string"), OBFSTR("For add: replacement bytes (hex)"), false},
         {OBFSTR("replacement_text"), OBFSTR("string"), OBFSTR("For add: replacement text"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("For remove: rule ID to remove"), false}},
        network_modify_packet_rule, false});

    register_compat(srv, {
        OBFSTR("network_list_mod_rules"), OBFSTR("network"),
        OBFSTR("List all active packet modification rules. Shows rule ID, direction, protocol, port/pid filters, "
               "match count, and active status."),
        {},
        network_list_mod_rules, true});

    register_compat(srv, {
        OBFSTR("network_redirect_traffic"), OBFSTR("network"),
        OBFSTR("Manage kernel-level traffic redirect rules. 'add' redirects traffic matching IP:port to a different "
               "IP:port (transparent proxy). 'remove' deletes by rule ID. 'clear' removes all. Filter by protocol. "
               "Equivalent to iptables REDIRECT/DNAT but at WFP level. Max 16 rules."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', or 'clear'"), true},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("For add: 'tcp' or 'udp' (default: tcp)"), false},
         {OBFSTR("match_port"), OBFSTR("number"), OBFSTR("For add: original destination port to match"), false},
         {OBFSTR("match_ip"), OBFSTR("string"), OBFSTR("For add: original destination IP to match"), false},
         {OBFSTR("redirect_port"), OBFSTR("number"), OBFSTR("For add: new destination port"), false},
         {OBFSTR("redirect_ip"), OBFSTR("string"), OBFSTR("For add: new destination IP"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("For remove: rule ID"), false}},
        network_redirect_traffic, false});

    register_compat(srv, {
        OBFSTR("network_list_redirect_rules"), OBFSTR("network"),
        OBFSTR("List all active traffic redirect rules with match counts and status."),
        {},
        network_list_redirect_rules, true});

    register_compat(srv, {
        OBFSTR("network_intercept"), OBFSTR("network"),
        OBFSTR("Enable/disable real-time packet interception and hold. When enabled, matching packets are "
               "held in a queue (like Fiddler breakpoints). Use network_get_held_packets to inspect them, then "
               "network_release_packet to release, drop, or modify-and-release each packet. Filter by pid/port/protocol."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable' or 'disable'"), true},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("For enable: process ID filter (0 = all)"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("For enable: port filter (0 = all)"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("For enable: 'tcp' or 'udp'"), false}},
        network_intercept, false});

    register_compat(srv, {
        OBFSTR("network_get_held_packets"), OBFSTR("network"),
        OBFSTR("Retrieve packets currently held by the interceptor. Returns hold_id, timestamp, direction, "
               "protocol, src/dst endpoints, pid, and payload (hex dump + ASCII). Use hold_id with "
               "network_release_packet to decide each packet's fate."),
        {},
        network_get_held_packets, true});

    register_compat(srv, {
        OBFSTR("network_release_packet"), OBFSTR("network"),
        OBFSTR("Release a held packet from the interceptor. Actions: 'release' (forward as-is, default), "
               "'drop' (discard silently), 'modify' (replace payload then forward). For 'modify', provide "
               "new payload as hex or text. Like Fiddler's 'Run to Completion' / 'Drop' / 'Edit & Reissue'."),
        {{OBFSTR("hold_id"), OBFSTR("number"), OBFSTR("Held packet ID from network_get_held_packets"), true},
         {OBFSTR("action"), OBFSTR("string"), OBFSTR("'release', 'drop', or 'modify' (default: release)"), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("For modify: new payload as hex string"), false},
         {OBFSTR("payload_text"), OBFSTR("string"), OBFSTR("For modify: new payload as ASCII text"), false}},
        network_release_packet, false});

    register_compat(srv, {
        OBFSTR("network_kill_connection"), OBFSTR("network"),
        OBFSTR("Forcefully terminate a network connection. Uses kernel-level socket close + TCP RST injection. "
               "Specify the connection by src/dst IP:port and/or PID. Like right-click 'Kill Connection' in TCPView."),
        {{OBFSTR("protocol"), OBFSTR("string"), OBFSTR("'tcp' or 'udp' (default: tcp)"), false},
         {OBFSTR("src_ip"), OBFSTR("string"), OBFSTR("Source (local) IP address"), false},
         {OBFSTR("dst_ip"), OBFSTR("string"), OBFSTR("Destination (remote) IP address"), false},
         {OBFSTR("src_port"), OBFSTR("number"), OBFSTR("Source (local) port"), false},
         {OBFSTR("dst_port"), OBFSTR("number"), OBFSTR("Destination (remote) port"), false},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("Process ID owning the connection"), false}},
        network_kill_connection, false});

    register_compat(srv, {
        OBFSTR("network_spoof_dns"), OBFSTR("network"),
        OBFSTR("Manage kernel-level DNS spoofing rules. 'add' creates a rule to intercept DNS queries for a domain "
               "and return a spoofed A/AAAA record. 'remove' deletes by rule ID. 'clear' removes all. Like a kernel "
               "hosts file - intercepts at the WFP layer before packets leave. Max 32 rules."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'add', 'remove', or 'clear'"), true},
         {OBFSTR("domain"), OBFSTR("string"), OBFSTR("For add: domain name to intercept (e.g. 'example.com')"), false},
         {OBFSTR("spoof_ip"), OBFSTR("string"), OBFSTR("For add: IP address to return in DNS response"), false},
         {OBFSTR("ttl"), OBFSTR("number"), OBFSTR("For add: TTL in seconds for spoofed response (default: 300)"), false},
         {OBFSTR("rule_id"), OBFSTR("number"), OBFSTR("For remove: rule ID"), false}},
        network_spoof_dns, false});

    register_compat(srv, {
        OBFSTR("network_list_dns_spoof_rules"), OBFSTR("network"),
        OBFSTR("List all active DNS spoof rules with domain, spoof address, TTL, match counts, and status."),
        {},
        network_list_dns_spoof_rules, true});

    register_compat(srv, {
        OBFSTR("network_bandwidth_monitor"), OBFSTR("network"),
        OBFSTR("Real-time bandwidth monitoring at the kernel level. 'start' begins tracking (optionally for a specific PID). "
               "'get' returns total bytes/packets sent/received plus current throughput (bps). 'stop' ends monitoring. "
               "'reset' zeroes all counters. Like Wireshark I/O graphs + NetLimiter bandwidth view."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'start', 'stop', 'get', or 'reset'"), true},
         {OBFSTR("pid"), OBFSTR("number"), OBFSTR("For start/get: filter by process ID (0 = all)"), false}},
        network_bandwidth_monitor, false});

    register_compat(srv, {
        OBFSTR("network_bandwidth_per_process"), OBFSTR("network"),
        OBFSTR("Get per-process bandwidth usage breakdown. Shows bytes/packets sent/received and last activity "
               "timestamp for each process. Requires bandwidth monitoring to be active (network_bandwidth_monitor start)."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID (0 = all processes)"), false}},
        network_bandwidth_per_process, true});

    register_compat(srv, {
        OBFSTR("network_os_fingerprint"), OBFSTR("network"),
        OBFSTR("Passive OS fingerprinting via TCP SYN packet analysis (p0f-style). 'enable' starts collecting "
               "fingerprints from incoming connections. 'get' returns results: remote IP, OS guess, TTL, window size, "
               "MSS, window scale, DF flag, SACK. 'disable' stops. Like p0f or Wireshark OS detection."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("'enable', 'disable', or 'get'"), true}},
        network_os_fingerprint, false});

    register_compat(srv, {
        OBFSTR("network_export_pcap"), OBFSTR("network"),
        OBFSTR("Export captured packets to a PCAP file that can be opened in Wireshark. Writes standard libpcap "
               "format with global header + packet records. Filter by pid/protocol. File saved to Downloads folder "
               "by default. Max 256 packets per export."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Max packets to export (default 256, max 256)"), false},
         {OBFSTR("filename"), OBFSTR("string"), OBFSTR("Output filename (default: 'aida_capture.pcap')"), false}},
        network_export_pcap, false});


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
         {OBFSTR("pipeline"), OBFSTR("array"), OBFSTR("Array of transform step objects: [{\"name\":\"base64_decode\"}, {\"name\":\"xor\",\"params\":{\"key\":\"41\"}}]"), true}},
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
                        return tool_result_t::error("Invalid hex character in 'input_hex'");
                    }
                    data.push_back(static_cast<uint8_t>((hi << 4) | lo));
                }
            } else if (args.contains("input") && args["input"].is_string()) {
                std::string input = args["input"].get<std::string>();
                data.assign(input.begin(), input.end());
            } else {
                return tool_result_t::error("Either 'input' or 'input_hex' required");
            }

            if (!args.contains("pipeline") || !args["pipeline"].is_array())
                return tool_result_t::error("'pipeline' array required");

            auto& reg = decoder_pipeline::registry::instance();
            for (const auto& step : args["pipeline"]) {
                std::string name = step.value("name", "");
                if (name.empty()) return tool_result_t::error("Each pipeline step needs 'name'");

                std::map<std::string, std::string> params;
                if (step.contains("params") && step["params"].is_object()) {
                    for (auto& [k, v] : step["params"].items())
                        params[k] = v.is_string() ? v.get<std::string>() : v.dump();
                }

                diag::log_tagged_fmt("net_tools", "network_decode_data step=%s", name.c_str());
                auto result = decoder_pipeline::apply_single(name, data, params);
                if (!result.success) {
                    diag::log_tagged_fmt("net_tools", "network_decode_data step_failed step=%s error=%s", name.c_str(), result.error.c_str());
                    return tool_result_t::error("Transform '" + name + "' failed: " + result.error);
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
         {OBFSTR("name"), OBFSTR("string"), OBFSTR("Script name (default: derived from path)"), false}},
        [](const json& args) -> tool_result_t {
            std::string name = args.value("name", "");
            diag::log_tagged_fmt("net_tools", "network_script_load entry name=%s", name.c_str());
            bool ok = false;
            if (args.contains("source") && args["source"].is_string()) {
                std::string src = args["source"].get<std::string>();
                if (name.empty()) name = "_inline_";
                ok = script_engine::load_script_source(name, src);
            } else if (args.contains("path") && args["path"].is_string()) {
                std::string path = args["path"].get<std::string>();
                if (name.empty()) {
                    auto pos = path.find_last_of("\\/");
                    name = (pos != std::string::npos) ? path.substr(pos + 1) : path;
                }
                ok = script_engine::load_script(path);
            } else {
                return tool_result_t::error("Either 'path' or 'source' required");
            }
            diag::log_tagged_fmt("net_tools", "network_script_load result=%d name=%s", (int)ok, name.c_str());
            return ok ? tool_result_t::ok("Script '" + name + "' loaded") : tool_result_t::error("Failed to load script");
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
            if (!script_engine::unload_script(name)) {
                diag::log_tagged_fmt("net_tools", "network_script_unload not_loaded name=%s", name.c_str());
                return tool_result_t::error("Script '" + name + "' is not loaded");
            }
            return tool_result_t::ok("Script '" + name + "' unloaded");
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_execute"), OBFSTR("network"),
        OBFSTR("Execute Lua code in the script engine console. Returns the output/result. "
               "Useful for querying state, testing hooks, or running one-off transformations."),
        {{OBFSTR("code"), OBFSTR("string"), OBFSTR("Lua code to execute"), true}},
        [](const json& args) -> tool_result_t {
            std::string code = args.value("code", "");
            diag::log_tagged_fmt("net_tools", "network_script_execute code_len=%zu", code.size());
            std::string result = script_engine::execute(code);
            diag::log_tagged_fmt("net_tools", "network_script_execute result_len=%zu", result.size());
            json r;
            r["output"] = result;
            return tool_result_t::ok(result.empty() ? "(no output)" : result, r);
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_list"), OBFSTR("network"),
        OBFSTR("List all loaded Lua scripts with their enabled/disabled status."),
        {},
        [](const json&) -> tool_result_t {
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
            return tool_result_t::ok(std::to_string(scripts.size()) + " scripts loaded", r);
        }, true});

    register_compat(srv, {
        OBFSTR("network_script_api"), OBFSTR("network"),
        OBFSTR("Get the complete Lua API reference for the AiDA scripting engine. Lists all available "
               "functions, hook types, and data structures."),
        {},
        [](const json&) -> tool_result_t {
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
         {OBFSTR("pid"),       OBFSTR("number"), OBFSTR("Process ID filter for 'start' (0 = all)"), false},
         {OBFSTR("src_ip"),    OBFSTR("string"), OBFSTR("Source IPv4 (dotted-quad) for get_stream"), false},
         {OBFSTR("src_port"),  OBFSTR("number"), OBFSTR("Source port for get_stream"), false},
         {OBFSTR("dst_ip"),    OBFSTR("string"), OBFSTR("Destination IPv4 (dotted-quad) for get_stream"), false},
         {OBFSTR("dst_port"),  OBFSTR("number"), OBFSTR("Destination port for get_stream"), false}},
        [](const json& params) -> tool_result_t {
            const std::string op = params.value("operation", "");
            diag::log_tagged_fmt("net_tools", "network_stream_track op=%s", op.c_str());

            if (op == "start") {
                uint32_t pid = params.value("pid", 0u);
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

                diag::log_tagged_fmt("net_tools", "network_pg_sniff install pid=%u addr=0x%llX size=%llu", pid, static_cast<unsigned long long>(addr), static_cast<unsigned long long>(size));
                uint32_t sid = page_guard_engine::g_pg_engine.install(pid, addr, size);
                diag::log_tagged_fmt("net_tools", "network_pg_sniff install sid=%u", sid);
                if (sid == 0)
                    return tool_result_t::error("Failed to install page guard. "
                                                "Ensure the driver is connected and the "
                                                "target address is valid.");
                json r;
                r["session_id"] = sid;
                r["pid"]        = pid;
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(addr));
                r["address"]    = buf;
                r["size"]       = size;
                return tool_result_t::ok("Page guard installed, session_id=" +
                                         std::to_string(sid), r);
            }

            if (op == "get_captures") {
                uint32_t sid = params.value("session_id", 0u);
                if (sid == 0)
                    return tool_result_t::error("'session_id' is required");

                diag::log_tagged_fmt("net_tools", "network_pg_sniff get_captures sid=%u", sid);
                auto caps = page_guard_engine::g_pg_engine.get_capture_records(sid);
                diag::log_tagged_fmt("net_tools", "network_pg_sniff get_captures count=%zu", caps.size());
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
        }, true});

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
                    return tool_result_t::error("Failed to auto-hook encryption functions in PID " + std::to_string(pid));
                }
                if (!pre_encrypt_hook::start_polling()) {
                    DWORD err = pre_encrypt_hook::g_state.debugger_error.load();
                    pre_encrypt_hook::unhook_all();
                    return tool_result_t::error("Failed to start authorized debug capture for PID " + std::to_string(pid) +
                                                ", error=" + std::to_string(static_cast<unsigned long>(err)));
                }
                json r;
                std::lock_guard<std::mutex> lock(pre_encrypt_hook::g_state.mutex);
                diag::log_tagged_fmt("net_tools", "network_pre_encrypt_hook auto_hook hooks=%zu", pre_encrypt_hook::g_state.targets.size());
                r["hooks_installed"] = static_cast<int>(pre_encrypt_hook::g_state.targets.size());
                uint32_t armed_thread_breakpoints = 0;
                json hooks = json::array();
                for (const auto& t : pre_encrypt_hook::g_state.targets) {
                    armed_thread_breakpoints += static_cast<uint32_t>(t.armed_tids.size());
                    if (t.active) {
                        json h;
                        h["name"] = t.function_name;
                        h["address"] = (std::ostringstream() << "0x" << std::hex << t.address).str();
                        h["bp_slot"] = t.bp_index;
                        h["armed_threads"] = static_cast<int>(t.armed_tids.size());
                        hooks.push_back(h);
                    }
                }
                r["armed_thread_breakpoints"] = armed_thread_breakpoints;
                r["hooks"] = hooks;
                return tool_result_t::ok("Hooked " + std::to_string(hooks.size()) + " encryption functions", r);
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
                if (!pre_encrypt_hook::start_polling()) {
                    DWORD err = pre_encrypt_hook::g_state.debugger_error.load();
                    pre_encrypt_hook::unhook_all();
                    return tool_result_t::error("Failed to start authorized debug capture for address " + addr_str +
                                                ", error=" + std::to_string(static_cast<unsigned long>(err)));
                }
                return tool_result_t::ok("Hooked " + name + " at " + addr_str);
            }
            if (op == "unhook_all") {
                pre_encrypt_hook::unhook_all();
                return tool_result_t::ok("All pre-encryption hooks removed");
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
                pre_encrypt_hook::clear_captures();
                return tool_result_t::ok("Pre-encryption captures cleared");
            }
            if (op == "status") {
                json r;
                r["active"] = pre_encrypt_hook::is_active();
                r["debug_attached"] = pre_encrypt_hook::g_state.debug_attached.load();
                r["debug_loop_running"] = pre_encrypt_hook::g_state.debug_loop_running.load();
                r["debugger_error"] = static_cast<unsigned long>(pre_encrypt_hook::g_state.debugger_error.load());
                std::lock_guard<std::mutex> lock(pre_encrypt_hook::g_state.mutex);
                r["hook_count"] = static_cast<int>(pre_encrypt_hook::g_state.targets.size());
                r["capture_count"] = static_cast<int>(pre_encrypt_hook::g_state.captures.size());
                uint32_t armed_thread_breakpoints = 0;
                for (const auto& t : pre_encrypt_hook::g_state.targets)
                    armed_thread_breakpoints += static_cast<uint32_t>(t.armed_tids.size());
                r["armed_thread_breakpoints"] = armed_thread_breakpoints;
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

    register_compat(srv, {
        OBFSTR("network_fuzzer"), OBFSTR("network"),
        OBFSTR("HTTP fuzzer / intruder. Configure target, base request with injection points, "
               "payload sets, and attack mode. Then start fuzzing to send requests with substituted "
               "payloads and collect responses. Operations: configure, start, stop, status, get_results, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("configure|start|stop|status|get_results|clear"), true},
         {OBFSTR("host"), OBFSTR("string"), OBFSTR("Target host for configure"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Target port"), false},
         {OBFSTR("use_tls"), OBFSTR("boolean"), OBFSTR("Use HTTPS"), false},
         {OBFSTR("base_request"), OBFSTR("string"), OBFSTR("HTTP request template with injection points"), false},
         {OBFSTR("attack_mode"), OBFSTR("string"), OBFSTR("sniper|pitchfork|clusterbomb"), false},
         {OBFSTR("payload_source"), OBFSTR("string"), OBFSTR("Wordlist path or inline data"), false},
         {OBFSTR("payload_type"), OBFSTR("number"), OBFSTR("0=wordlist, 1=sequential, 2=charset"), false},
         {OBFSTR("thread_count"), OBFSTR("number"), OBFSTR("Concurrent workers 1-32"), false},
         {OBFSTR("delay_ms"), OBFSTR("number"), OBFSTR("Throttle between requests in ms"), false},
         {OBFSTR("match_status"), OBFSTR("number"), OBFSTR("Filter by HTTP status code (0=any)"), false},
         {OBFSTR("stop_on_match"), OBFSTR("boolean"), OBFSTR("Stop fuzzing when a match is found"), false},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Max results to return for get_results (default 100)"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error(OBFSTR("Missing 'operation' parameter"));

            diag::log_tagged_fmt("net_tools", "network_fuzzer op=%s", op.c_str());
            auto& state = network_view::g_state;

            if (op == "configure") {
                auto& cfg = state.fuzz_config;
                if (args.contains("host") && args["host"].is_string())
                    cfg.host = args["host"].get<std::string>();
                if (args.contains("port") && args["port"].is_number())
                    cfg.port = static_cast<uint16_t>(args["port"].get<int>());
                if (args.contains("use_tls") && args["use_tls"].is_boolean())
                    cfg.use_tls = args["use_tls"].get<bool>();
                if (args.contains("base_request") && args["base_request"].is_string())
                    cfg.base_request = args["base_request"].get<std::string>();
                if (args.contains("attack_mode") && args["attack_mode"].is_string()) {
                    std::string m = args["attack_mode"].get<std::string>();
                    if (m == "pitchfork") cfg.attack_mode = network_view::fuzzer_attack_mode_t::pitchfork;
                    else if (m == "clusterbomb") cfg.attack_mode = network_view::fuzzer_attack_mode_t::clusterbomb;
                    else cfg.attack_mode = network_view::fuzzer_attack_mode_t::sniper;
                }
                if (args.contains("payload_source") && args["payload_source"].is_string())
                    cfg.payload_source = args["payload_source"].get<std::string>();
                if (args.contains("payload_type") && args["payload_type"].is_number())
                    cfg.payload_type = args["payload_type"].get<int>();
                if (args.contains("thread_count") && args["thread_count"].is_number())
                    cfg.thread_count = std::max(1, std::min(32, args["thread_count"].get<int>()));
                if (args.contains("delay_ms") && args["delay_ms"].is_number())
                    cfg.delay_ms = args["delay_ms"].get<int>();
                if (args.contains("match_status") && args["match_status"].is_number())
                    cfg.match_status = args["match_status"].get<int>();
                if (args.contains("stop_on_match") && args["stop_on_match"].is_boolean())
                    cfg.stop_on_match = args["stop_on_match"].get<bool>();
                json r;
                r["host"] = cfg.host;
                r["port"] = cfg.port;
                r["use_tls"] = cfg.use_tls;
                r["attack_mode"] = static_cast<int>(cfg.attack_mode);
                r["thread_count"] = cfg.thread_count;
                diag::log_tagged_fmt("net_tools", "network_fuzzer configure host=%s port=%u use_tls=%d threads=%d", cfg.host.c_str(), cfg.port, (int)cfg.use_tls, cfg.thread_count);
                return tool_result_t::ok(OBFSTR("Fuzzer configured"), r);
            }

            if (op == "start") {
                diag::log_tagged_fmt("net_tools", "network_fuzzer start host=%s port=%u use_tls=%d", state.fuzz_config.host.c_str(), state.fuzz_config.port, (int)state.fuzz_config.use_tls);
                if (state.fuzz_running.load())
                    return tool_result_t::error(OBFSTR("Fuzzer is already running"));
                {
                    std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                    state.fuzz_results.clear();
                }
                state.fuzz_progress.store(0);
                state.fuzz_total.store(0);
                state.fuzz_running.store(true);
                while (!state.fuzz_thread_done.load(std::memory_order_acquire))
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                state.fuzz_thread_done.store(false, std::memory_order_release);
                network_view::state_t* state_ptr = &state;
                if (!work_queue::post([state_ptr]() {
                    auto& state = *state_ptr;
                    auto& cfg = state.fuzz_config;

                    auto load_set = [](const network_view::payload_set_t& ps) -> std::vector<std::string> {
                        std::vector<std::string> lines;
                        auto push_line = [&](std::istream& is) {
                            std::string line;
                            while (std::getline(is, line)) {
                                if (!line.empty() && line.back() == '\r') line.pop_back();
                                if (!line.empty()) lines.push_back(std::move(line));
                            }
                        };
                        if (ps.type == 0) {
                            std::ifstream f(ps.source);
                            if (f.is_open()) push_line(f);
                        } else {
                            std::istringstream ss(ps.source);
                            push_line(ss);
                        }
                        return lines;
                    };

                    auto load_legacy_set = [&]() -> std::vector<std::string> {
                        network_view::payload_set_t tmp;
                        tmp.type = cfg.payload_type;
                        tmp.source = cfg.payload_source;
                        if (cfg.payload_type == 1) {
                            std::vector<std::string> nums;
                            int start_n = 0, end_n = 100;
                            if (sscanf(cfg.payload_source.c_str(), "%d-%d", &start_n, &end_n) >= 1)
                                for (int n = start_n; n <= end_n; n++)
                                    nums.push_back(std::to_string(n));
                            return nums;
                        } else if (cfg.payload_type == 2) {
                            std::string charset = cfg.payload_source.empty()
                                ? "abcdefghijklmnopqrstuvwxyz0123456789" : cfg.payload_source;
                            std::vector<std::string> v;
                            for (char c : charset) v.push_back(std::string(1, c));
                            for (char a : charset)
                                for (char b : charset)
                                    v.push_back(std::string(1, a) + b);
                            return v;
                        }
                        return load_set(tmp);
                    };

                    auto make_request_multi = [](const std::string& tmpl,
                                                  const std::vector<std::string>& payloads) -> std::string {
                        const std::string marker = "\xc2\xa7";
                        std::string result;
                        result.reserve(tmpl.size() + 512);
                        size_t pos = 0;
                        size_t pi = 0;
                        while (pos < tmpl.size()) {
                            size_t s = tmpl.find(marker, pos);
                            if (s == std::string::npos) { result.append(tmpl, pos, std::string::npos); break; }
                            size_t e = tmpl.find(marker, s + marker.size());
                            if (e == std::string::npos) { result.append(tmpl, pos, std::string::npos); break; }
                            result.append(tmpl, pos, s - pos);
                            if (pi < payloads.size()) result.append(payloads[pi]);
                            pi++;
                            pos = e + marker.size();
                        }
                        if (!payloads.empty()) {
                            size_t fp = 0;
                            const std::string fuzz_tok = "FUZZ";
                            while ((fp = result.find(fuzz_tok, fp)) != std::string::npos) {
                                result.replace(fp, fuzz_tok.size(), payloads[0]);
                                fp += payloads[0].size();
                            }
                        }
                        return result;
                    };

                    using combo_t = std::vector<std::string>;
                    std::vector<combo_t> combos;

                    switch (cfg.attack_mode) {
                        case network_view::fuzzer_attack_mode_t::sniper: {
                            std::vector<std::string> payloads = cfg.payload_sets.empty()
                                ? load_legacy_set()
                                : load_set(cfg.payload_sets[0]);
                            combos.reserve(payloads.size());
                            for (auto& p : payloads) combos.push_back({ p });
                            break;
                        }
                        case network_view::fuzzer_attack_mode_t::pitchfork: {
                            if (cfg.payload_sets.empty()) { state.fuzz_running.store(false); return; }
                            std::vector<std::vector<std::string>> sets;
                            sets.reserve(cfg.payload_sets.size());
                            for (auto& ps : cfg.payload_sets) {
                                sets.push_back(load_set(ps));
                                if (sets.back().empty()) { state.fuzz_running.store(false); return; }
                            }
                            size_t min_len = sets[0].size();
                            for (auto& s : sets) min_len = std::min(min_len, s.size());
                            combos.reserve(min_len);
                            for (size_t i = 0; i < min_len; i++) {
                                combo_t c;
                                c.reserve(sets.size());
                                for (auto& s : sets) c.push_back(s[i]);
                                combos.push_back(std::move(c));
                            }
                            break;
                        }
                        case network_view::fuzzer_attack_mode_t::clusterbomb: {
                            if (cfg.payload_sets.empty()) { state.fuzz_running.store(false); return; }
                            std::vector<std::vector<std::string>> sets;
                            sets.reserve(cfg.payload_sets.size());
                            for (auto& ps : cfg.payload_sets) {
                                sets.push_back(load_set(ps));
                                if (sets.back().empty()) { state.fuzz_running.store(false); return; }
                            }
                            combos.push_back(combo_t{});
                            for (auto& s : sets) {
                                std::vector<combo_t> next;
                                next.reserve(combos.size() * s.size());
                                for (auto& base : combos)
                                    for (auto& val : s) {
                                        combo_t nc = base;
                                        nc.push_back(val);
                                        next.push_back(std::move(nc));
                                    }
                                combos = std::move(next);
                            }
                            break;
                        }
                    }

                    if (combos.empty()) { state.fuzz_running.store(false); return; }

                    state.fuzz_total.store(static_cast<int>(combos.size()));
                    state.fuzz_progress.store(0);

                    std::atomic<int> next_index{0};
                    int total = static_cast<int>(combos.size());
                    int threads = std::min(std::max(cfg.thread_count, 1), 32);

                    auto worker = [&]() {
                        while (state.fuzz_running.load()) {
                            int idx = next_index.fetch_add(1);
                            if (idx >= total) break;
                            auto& combo = combos[static_cast<size_t>(idx)];
                            std::string req_s = make_request_multi(cfg.base_request, combo);
                            std::vector<uint8_t> raw_req(req_s.begin(), req_s.end());
                            auto t0 = GetTickCount64();
                            auto res = mitm_proxy::repeat_request(cfg.host, cfg.port, cfg.use_tls, raw_req);
                            auto elapsed = GetTickCount64() - t0;
                            network_view::state_t::fuzzer_result_t fr;
                            fr.index = idx;
                            fr.payloads = combo;
                            fr.payload = combo.empty() ? std::string() : combo[0];
                            fr.latency_ms = elapsed;
                            if (res.success) {
                                fr.status_code = res.exchange.response.status_code;
                                fr.response_len = res.exchange.raw_response.size();
                                std::string body(res.exchange.raw_response.begin(),
                                                 res.exchange.raw_response.end());
                                fr.response_preview = body.substr(0, std::min<size_t>(200, body.size()));
                                fr.match = (cfg.match_status > 0) ? (fr.status_code == cfg.match_status) : true;
                            }
                            {
                                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                                state.fuzz_results.push_back(std::move(fr));
                            }
                            state.fuzz_progress.fetch_add(1);
                            if (cfg.stop_on_match && fr.match) {
                                state.fuzz_running.store(false);
                                break;
                            }
                            if (cfg.delay_ms > 0) Sleep(static_cast<DWORD>(cfg.delay_ms));
                        }
                    };

                    std::atomic<int> remaining{threads};
                    for (int t = 0; t < threads; t++) {
                        if (!work_queue::post([worker, &remaining]() {
                                worker();
                                remaining.fetch_sub(1, std::memory_order_acq_rel);
                            }))
                        {
                            remaining.fetch_sub(1, std::memory_order_acq_rel);
                        }
                    }
                    while (remaining.load(std::memory_order_acquire) > 0)
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    state.fuzz_running.store(false);
                    state.fuzz_thread_done.store(true, std::memory_order_release);
                }))
                {
                    state.fuzz_thread_done.store(true, std::memory_order_release);
                }
                json r;
                r["status"] = "started";
                r["host"] = state.fuzz_config.host;
                r["port"] = state.fuzz_config.port;
                return tool_result_t::ok(OBFSTR("Fuzzer started"), r);
            }

            if (op == "stop") {
                bool was_running = state.fuzz_running.load();
                diag::log_tagged_fmt("net_tools", "network_fuzzer stop was_running=%d", (int)was_running);
                if (!was_running)
                    return tool_result_t::ok(OBFSTR("Fuzzer is not running"));
                state.fuzz_running.store(false);
                return tool_result_t::ok(OBFSTR("Fuzzer stop signal sent"));
            }

            if (op == "status") {
                json r;
                r["running"] = state.fuzz_running.load();
                r["progress"] = state.fuzz_progress.load();
                r["total"] = state.fuzz_total.load();
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                r["result_count"] = static_cast<int>(state.fuzz_results.size());
                diag::log_tagged_fmt("net_tools", "network_fuzzer status running=%d progress=%d total=%d results=%zu", (int)state.fuzz_running.load(), (int)state.fuzz_progress.load(), (int)state.fuzz_total.load(), state.fuzz_results.size());
                return tool_result_t::ok(state.fuzz_running.load() ? OBFSTR("Fuzzer running") : OBFSTR("Fuzzer idle"), r);
            }

            if (op == "get_results") {
                int max_count = args.value("max_results", 100);
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                json arr = json::array();
                int count = 0;
                for (auto it = state.fuzz_results.rbegin();
                     it != state.fuzz_results.rend() && count < max_count; ++it, ++count) {
                    json ej;
                    ej["index"] = it->index;
                    ej["payload"] = it->payload;
                    if (it->payloads.size() > 1) {
                        json pa = json::array();
                        for (const auto& p : it->payloads) pa.push_back(p);
                        ej["payloads"] = pa;
                    }
                    ej["status_code"] = it->status_code;
                    ej["response_len"] = it->response_len;
                    ej["latency_ms"] = it->latency_ms;
                    ej["match"] = it->match;
                    if (!it->response_preview.empty())
                        ej["response_preview"] = it->response_preview;
                    if (!it->extracted_value.empty())
                        ej["extracted_value"] = it->extracted_value;
                    arr.push_back(ej);
                }
                json r;
                r["results"] = arr;
                r["total"] = static_cast<int>(state.fuzz_results.size());
                diag::log_tagged_fmt("net_tools", "network_fuzzer get_results returned=%zu total=%zu", arr.size(), state.fuzz_results.size());
                return tool_result_t::ok(std::to_string(state.fuzz_results.size()) + OBFSTR(" total results"), r);
            }

            if (op == "clear") {
                std::lock_guard<std::mutex> lk(state.fuzz_mutex);
                size_t was = state.fuzz_results.size();
                state.fuzz_results.clear();
                state.fuzz_progress.store(0);
                state.fuzz_total.store(0);
                diag::log_tagged_fmt("net_tools", "network_fuzzer clear cleared=%zu", was);
                return tool_result_t::ok(OBFSTR("Fuzzer results cleared"));
            }

            return tool_result_t::error(OBFSTR("Unknown operation. Use configure|start|stop|status|get_results|clear"));
        }, false});

    register_compat(srv, {
        OBFSTR("network_websocket"), OBFSTR("network"),
        OBFSTR("WebSocket frame viewer and injector. List captured WebSocket frames from proxy connections, "
               "filter by host or content, inject new frames, or clear the frame buffer. "
               "Operations: list_frames, inject_frame, clear."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("list_frames|inject_frame|clear"), true},
         {OBFSTR("max_count"), OBFSTR("number"), OBFSTR("Max frames to return for list_frames (default 64)"), false},
         {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Substring filter on host/preview"), false},
         {OBFSTR("host"), OBFSTR("string"), OBFSTR("Target host for inject_frame"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Target port for inject_frame"), false},
         {OBFSTR("opcode"), OBFSTR("number"), OBFSTR("WebSocket opcode: 0x1=text, 0x2=binary"), false},
         {OBFSTR("payload"), OBFSTR("string"), OBFSTR("Frame payload text or hex string"), false},
         {OBFSTR("is_hex"), OBFSTR("boolean"), OBFSTR("If true, interpret payload as hex"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error(OBFSTR("Missing 'operation' parameter"));

            diag::log_tagged_fmt("net_tools", "network_websocket op=%s", op.c_str());

            auto& state = network_view::g_state;

            if (op == "list_frames") {
                int max_count = args.value("max_count", 64);
                std::string filter = args.value("filter", "");
                diag::log_tagged_fmt("net_tools", "network_websocket list_frames max_count=%d filter=%s", max_count, filter.c_str());
                std::lock_guard<std::mutex> lk(state.ws_mutex);
                json arr = json::array();
                int count = 0;
                for (auto it = state.ws_frames.rbegin();
                     it != state.ws_frames.rend() && count < max_count; ++it) {
                    if (!filter.empty()) {
                        if (it->host.find(filter) == std::string::npos &&
                            it->preview.find(filter) == std::string::npos)
                            continue;
                    }
                    json fj;
                    fj["direction"] = it->is_outbound ? "outbound" : "inbound";
                    fj["host"] = it->host;
                    fj["port"] = it->port;
                    fj["opcode"] = it->opcode;
                    fj["is_text"] = it->is_text;
                    fj["size"] = it->payload.size();
                    fj["preview"] = it->preview;
                    fj["exchange_id"] = it->exchange_id;
                    fj["timestamp"] = it->timestamp;
                    arr.push_back(fj);
                    count++;
                }
                json r;
                r["frames"] = arr;
                r["total_buffered"] = static_cast<int>(state.ws_frames.size());
                diag::log_tagged_fmt("net_tools", "network_websocket list_frames returned=%d total_buffered=%zu", count, state.ws_frames.size());
                return tool_result_t::ok(std::to_string(count) + OBFSTR(" WebSocket frames"), r);
            }

            if (op == "inject_frame") {
                diag::log_tagged("net_tools", "network_websocket inject_frame not_supported");
                return tool_result_t::error(OBFSTR("WebSocket frame injection requires an active proxy connection with an established WebSocket upgrade. Use the proxy to intercept and modify frames instead."));
            }

            if (op == "clear") {
                std::lock_guard<std::mutex> lk(state.ws_mutex);
                size_t was = state.ws_frames.size();
                state.ws_frames.clear();
                diag::log_tagged_fmt("net_tools", "network_websocket clear cleared=%zu", was);
                return tool_result_t::ok(OBFSTR("WebSocket frame buffer cleared"));
            }

            diag::log_tagged_fmt("net_tools", "network_websocket unknown_op op=%s", op.c_str());
            return tool_result_t::error(OBFSTR("Unknown operation. Use list_frames|inject_frame|clear"));
        }, true});

    register_compat(srv, {
        OBFSTR("network_proxy"), OBFSTR("network"),
        OBFSTR("HTTP/HTTPS MITM proxy with TLS interception. Start a local proxy that captures all HTTP traffic, "
               "decrypts TLS, and logs request/response pairs. Supports WebSocket and HTTP/2. "
               "Operations: start, stop, status, get_history, clear_history, get_exchange."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("start|stop|status|get_history|clear_history|get_exchange"), true},
         {OBFSTR("bind_addr"), OBFSTR("string"), OBFSTR("Bind address for start (default 127.0.0.1)"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Bind port for start (default 8443)"), false},
         {OBFSTR("decode_tls"), OBFSTR("boolean"), OBFSTR("Enable TLS MITM decryption"), false},
         {OBFSTR("max_count"), OBFSTR("number"), OBFSTR("Max entries for get_history"), false},
         {OBFSTR("filter"), OBFSTR("string"), OBFSTR("Filter on host/method/path"), false},
         {OBFSTR("exchange_id"), OBFSTR("number"), OBFSTR("Exchange ID for get_exchange"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error(OBFSTR("Missing 'operation' parameter"));

            diag::log_tagged_fmt("net_tools", "network_proxy op=%s", op.c_str());

            if (op == "start") {
                bool already_running = mitm_proxy::is_running();
                diag::log_tagged_fmt("net_tools", "network_proxy start already_running=%d", (int)already_running);
                if (already_running)
                    return tool_result_t::error(OBFSTR("Proxy is already running"));
                mitm_proxy::proxy_config cfg;
                cfg.bind_addr = args.value("bind_addr", std::string("127.0.0.1"));
                if (args.contains("port") && args["port"].is_number())
                    cfg.bind_port = static_cast<uint16_t>(args["port"].get<int>());
                if (args.contains("decode_tls") && args["decode_tls"].is_boolean())
                    cfg.decode_tls = args["decode_tls"].get<bool>();
                diag::log_tagged_fmt("net_tools", "network_proxy start bind_addr=%s port=%u decode_tls=%d", cfg.bind_addr.c_str(), (unsigned)cfg.bind_port, (int)cfg.decode_tls);
                bool ok = mitm_proxy::start(cfg);
                diag::log_tagged_fmt("net_tools", "network_proxy start result=%d", (int)ok);
                if (!ok)
                    return tool_result_t::error(OBFSTR("Failed to start proxy"));
                json r;
                r["bind_addr"] = cfg.bind_addr;
                r["bind_port"] = cfg.bind_port;
                r["decode_tls"] = cfg.decode_tls;
                return tool_result_t::ok(OBFSTR("Proxy started on ") + cfg.bind_addr + ":" + std::to_string(cfg.bind_port), r);
            }

            if (op == "stop") {
                bool was_running = mitm_proxy::is_running();
                diag::log_tagged_fmt("net_tools", "network_proxy stop was_running=%d", (int)was_running);
                if (!was_running)
                    return tool_result_t::ok(OBFSTR("Proxy is not running"));
                mitm_proxy::stop();
                diag::log_tagged("net_tools", "network_proxy stop done");
                return tool_result_t::ok(OBFSTR("Proxy stopped"));
            }

            if (op == "status") {
                auto stats = mitm_proxy::get_stats();
                diag::log_tagged_fmt("net_tools", "network_proxy status running=%d requests=%llu history=%zu held=%zu active=%zu",
                    (int)stats.running, (unsigned long long)stats.total_requests, stats.history_size, stats.held_count, stats.active_connections);
                json r;
                r["running"] = stats.running;
                r["total_requests"] = stats.total_requests;
                r["total_bytes_in"] = stats.total_bytes_in;
                r["total_bytes_out"] = stats.total_bytes_out;
                r["active_connections"] = stats.active_connections;
                r["history_size"] = stats.history_size;
                r["held_count"] = stats.held_count;
                return tool_result_t::ok(stats.running ? OBFSTR("Proxy running") : OBFSTR("Proxy stopped"), r);
            }

            if (op == "get_history") {
                size_t max_count = args.value("max_count", static_cast<size_t>(100));
                std::string filter = args.value("filter", "");
                diag::log_tagged_fmt("net_tools", "network_proxy get_history max_count=%zu filter=%s", max_count, filter.c_str());
                auto history = mitm_proxy::get_history(max_count);
                json arr = json::array();
                for (const auto& ex : history) {
                    if (!filter.empty()) {
                        bool match = ex.target_host.find(filter) != std::string::npos ||
                                     ex.request.method.find(filter) != std::string::npos ||
                                     ex.request.uri.find(filter) != std::string::npos;
                        if (!match) continue;
                    }
                    json ej;
                    ej["id"] = ex.id;
                    ej["method"] = ex.request.method;
                    ej["host"] = ex.target_host;
                    ej["port"] = ex.target_port;
                    ej["path"] = ex.request.uri;
                    ej["status_code"] = ex.response.status_code;
                    ej["is_tls"] = ex.is_tls;
                    ej["is_websocket"] = ex.is_websocket;
                    ej["latency_ms"] = ex.latency_ms;
                    ej["request_size"] = ex.request_size;
                    ej["response_size"] = ex.response_size;
                    arr.push_back(ej);
                }
                json r;
                r["exchanges"] = arr;
                r["count"] = static_cast<int>(arr.size());
                diag::log_tagged_fmt("net_tools", "network_proxy get_history returned=%zu fetched=%zu", arr.size(), history.size());
                return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" proxy exchanges"), r);
            }

            if (op == "clear_history") {
                mitm_proxy::clear_history();
                diag::log_tagged("net_tools", "network_proxy clear_history done");
                return tool_result_t::ok(OBFSTR("Proxy history cleared"));
            }

            if (op == "get_exchange") {
                if (!args.contains("exchange_id") || !args["exchange_id"].is_number())
                    return tool_result_t::error(OBFSTR("Missing 'exchange_id' parameter"));
                uint64_t eid = args["exchange_id"].get<uint64_t>();
                diag::log_tagged_fmt("net_tools", "network_proxy get_exchange eid=%llu", (unsigned long long)eid);
                const auto* ex = mitm_proxy::find_exchange(eid);
                if (!ex) {
                    diag::log_tagged_fmt("net_tools", "network_proxy get_exchange not_found eid=%llu", (unsigned long long)eid);
                    return tool_result_t::error(OBFSTR("Exchange not found: ") + std::to_string(eid));
                }
                diag::log_tagged_fmt("net_tools", "network_proxy get_exchange found eid=%llu method=%s host=%s status=%d", (unsigned long long)eid, ex->request.method.c_str(), ex->target_host.c_str(), ex->response.status_code);
                json r;
                r["id"] = ex->id;
                r["method"] = ex->request.method;
                r["host"] = ex->target_host;
                r["port"] = ex->target_port;
                r["path"] = ex->request.uri;
                r["status_code"] = ex->response.status_code;
                r["is_tls"] = ex->is_tls;
                r["latency_ms"] = ex->latency_ms;
                json req_headers = json::object();
                for (const auto& h : ex->request.headers)
                    req_headers[h.name] = h.value;
                r["request_headers"] = req_headers;
                if (!ex->raw_request.empty()) {
                    std::string req_body(ex->raw_request.begin(), ex->raw_request.end());
                    r["raw_request"] = req_body.substr(0, std::min<size_t>(4096, req_body.size()));
                }
                json resp_headers = json::object();
                for (const auto& h : ex->response.headers)
                    resp_headers[h.name] = h.value;
                r["response_headers"] = resp_headers;
                if (!ex->raw_response.empty()) {
                    std::string resp_body(ex->raw_response.begin(), ex->raw_response.end());
                    r["raw_response"] = resp_body.substr(0, std::min<size_t>(4096, resp_body.size()));
                }
                if (ex->is_websocket) {
                    r["ws_frames_sent"] = ex->ws_frames_sent;
                    r["ws_frames_recv"] = ex->ws_frames_recv;
                }
                if (!ex->tls_sni.empty()) r["tls_sni"] = ex->tls_sni;
                if (!ex->tls_version_str.empty()) r["tls_version"] = ex->tls_version_str;
                if (!ex->alpn_protocol.empty()) r["alpn"] = ex->alpn_protocol;
                return tool_result_t::ok(OBFSTR("Exchange ") + std::to_string(eid), r);
            }

            diag::log_tagged_fmt("net_tools", "network_proxy unknown_op op=%s", op.c_str());
            return tool_result_t::error(OBFSTR("Unknown operation. Use start|stop|status|get_history|clear_history|get_exchange"));
        }, false});

    register_compat(srv, {
        OBFSTR("network_repeater"), OBFSTR("network"),
        OBFSTR("HTTP request repeater. Create entries with host/port/request, send them, and inspect responses. "
               "Like Burp Suite Repeater. Operations: create, send, list, get, delete."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("create|send|list|get|delete"), true},
         {OBFSTR("host"), OBFSTR("string"), OBFSTR("Target host"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Target port"), false},
         {OBFSTR("use_tls"), OBFSTR("boolean"), OBFSTR("Use HTTPS"), false},
         {OBFSTR("raw_request"), OBFSTR("string"), OBFSTR("Raw HTTP request to send"), false},
         {OBFSTR("index"), OBFSTR("number"), OBFSTR("Repeater entry index"), false},
         {OBFSTR("max_count"), OBFSTR("number"), OBFSTR("Max entries to return for list"), false}},
        [](const json& args) -> tool_result_t {
            std::string op = args.value("operation", "");
            if (op.empty())
                return tool_result_t::error(OBFSTR("Missing 'operation' parameter"));

            diag::log_tagged_fmt("net_tools", "network_repeater op=%s", op.c_str());

            auto& state = network_view::g_state;

            if (op == "create") {
                auto entry = std::make_shared<network_view::repeater_entry_t>();
                entry->host = args.value("host", std::string("localhost"));
                if (args.contains("port") && args["port"].is_number())
                    entry->port = static_cast<uint16_t>(args["port"].get<int>());
                if (args.contains("use_tls") && args["use_tls"].is_boolean())
                    entry->use_tls = args["use_tls"].get<bool>();
                if (args.contains("raw_request") && args["raw_request"].is_string())
                    entry->raw_request = args["raw_request"].get<std::string>();
                state.repeater_entries.push_back(entry);
                int idx = static_cast<int>(state.repeater_entries.size()) - 1;
                diag::log_tagged_fmt("net_tools", "network_repeater create host=%s port=%u use_tls=%d idx=%d", entry->host.c_str(), (unsigned)entry->port, (int)entry->use_tls, idx);
                json r;
                r["index"] = idx;
                r["host"] = entry->host;
                r["port"] = entry->port;
                return tool_result_t::ok(OBFSTR("Repeater entry created at index ") + std::to_string(idx), r);
            }

            if (op == "send") {
                if (!args.contains("index") || !args["index"].is_number())
                    return tool_result_t::error(OBFSTR("Missing 'index' parameter"));
                int idx = args["index"].get<int>();
                diag::log_tagged_fmt("net_tools", "network_repeater send idx=%d total_entries=%zu", idx, state.repeater_entries.size());
                if (idx < 0 || idx >= static_cast<int>(state.repeater_entries.size()))
                    return tool_result_t::error(OBFSTR("Invalid repeater entry index"));
                std::shared_ptr<network_view::repeater_entry_t> entry = state.repeater_entries[static_cast<size_t>(idx)];
                if (!entry)
                    return tool_result_t::error(OBFSTR("Invalid repeater entry"));
                if (entry->in_progress.load()) {
                    diag::log_tagged_fmt("net_tools", "network_repeater send already_in_progress idx=%d", idx);
                    return tool_result_t::error(OBFSTR("Request already in progress for this entry"));
                }
                if (args.contains("raw_request") && args["raw_request"].is_string())
                    entry->raw_request = args["raw_request"].get<std::string>();
                if (args.contains("host") && args["host"].is_string())
                    entry->host = args["host"].get<std::string>();
                if (args.contains("port") && args["port"].is_number())
                    entry->port = static_cast<uint16_t>(args["port"].get<int>());
                if (args.contains("use_tls") && args["use_tls"].is_boolean())
                    entry->use_tls = args["use_tls"].get<bool>();
                entry->in_progress.store(true);
                entry->raw_response.clear();
                entry->status_code = 0;
                entry->latency_ms = 0;
                std::string host = entry->host;
                uint16_t port = entry->port;
                bool tls = entry->use_tls;
                std::vector<uint8_t> raw(entry->raw_request.begin(), entry->raw_request.end());
                diag::log_tagged_fmt("net_tools", "network_repeater send dispatch host=%s port=%u tls=%d raw_size=%zu idx=%d", host.c_str(), (unsigned)port, (int)tls, raw.size(), idx);
                work_queue::post([entry, host, port, tls, raw]() {
                    diag::log_tagged_fmt("net_tools", "network_repeater send_worker host=%s port=%u tls=%d raw_size=%zu", host.c_str(), (unsigned)port, (int)tls, raw.size());
                    auto t0 = GetTickCount64();
                    auto res = mitm_proxy::repeat_request(host, port, tls, raw);
                    uint64_t latency = GetTickCount64() - t0;
                    entry->latency_ms = latency;
                    if (res.success) {
                        entry->status_code = res.exchange.response.status_code;
                        entry->raw_response = std::string(res.exchange.raw_response.begin(),
                                                          res.exchange.raw_response.end());
                        diag::log_tagged_fmt("net_tools", "network_repeater send_worker success status=%d latency_ms=%llu resp_size=%zu", entry->status_code, (unsigned long long)latency, entry->raw_response.size());
                    } else {
                        entry->status_code = 0;
                        entry->raw_response = res.error;
                        diag::log_tagged_fmt("net_tools", "network_repeater send_worker failed error=%s latency_ms=%llu", res.error.c_str(), (unsigned long long)latency);
                    }
                    entry->in_progress.store(false);
                });
                json r;
                r["index"] = idx;
                r["status"] = "sending";
                return tool_result_t::ok(OBFSTR("Request sent for repeater entry ") + std::to_string(idx), r);
            }

            if (op == "list") {
                int max_count = args.value("max_count", static_cast<int>(state.repeater_entries.size()));
                diag::log_tagged_fmt("net_tools", "network_repeater list max_count=%d total=%zu", max_count, state.repeater_entries.size());
                json arr = json::array();
                for (int i = 0; i < static_cast<int>(state.repeater_entries.size()) && i < max_count; i++) {
                    const auto& e_ptr = state.repeater_entries[static_cast<size_t>(i)];
                    if (!e_ptr) continue;
                    const auto& e = *e_ptr;
                    json ej;
                    ej["index"] = i;
                    ej["host"] = e.host;
                    ej["port"] = e.port;
                    ej["use_tls"] = e.use_tls;
                    ej["status_code"] = e.status_code;
                    ej["latency_ms"] = e.latency_ms;
                    ej["in_progress"] = e.in_progress.load();
                    arr.push_back(ej);
                }
                json r;
                r["entries"] = arr;
                r["count"] = static_cast<int>(state.repeater_entries.size());
                diag::log_tagged_fmt("net_tools", "network_repeater list returned=%zu total=%zu", arr.size(), state.repeater_entries.size());
                return tool_result_t::ok(std::to_string(state.repeater_entries.size()) + OBFSTR(" repeater entries"), r);
            }

            if (op == "get") {
                if (!args.contains("index") || !args["index"].is_number())
                    return tool_result_t::error(OBFSTR("Missing 'index' parameter"));
                int idx = args["index"].get<int>();
                diag::log_tagged_fmt("net_tools", "network_repeater get idx=%d total=%zu", idx, state.repeater_entries.size());
                if (idx < 0 || idx >= static_cast<int>(state.repeater_entries.size()))
                    return tool_result_t::error(OBFSTR("Invalid repeater entry index"));
                const auto& e_ptr = state.repeater_entries[static_cast<size_t>(idx)];
                if (!e_ptr)
                    return tool_result_t::error(OBFSTR("Invalid repeater entry"));
                const auto& e = *e_ptr;
                diag::log_tagged_fmt("net_tools", "network_repeater get found idx=%d host=%s port=%u status=%d in_progress=%d", idx, e.host.c_str(), (unsigned)e.port, e.status_code, (int)e.in_progress.load());
                json r;
                r["index"] = idx;
                r["host"] = e.host;
                r["port"] = e.port;
                r["use_tls"] = e.use_tls;
                r["status_code"] = e.status_code;
                r["latency_ms"] = e.latency_ms;
                r["in_progress"] = e.in_progress.load();
                r["raw_request"] = e.raw_request;
                r["raw_response"] = e.raw_response.substr(0, std::min<size_t>(4096, e.raw_response.size()));
                return tool_result_t::ok(OBFSTR("Repeater entry ") + std::to_string(idx), r);
            }

            if (op == "delete") {
                if (!args.contains("index") || !args["index"].is_number())
                    return tool_result_t::error(OBFSTR("Missing 'index' parameter"));
                int idx = args["index"].get<int>();
                diag::log_tagged_fmt("net_tools", "network_repeater delete idx=%d total=%zu", idx, state.repeater_entries.size());
                if (idx < 0 || idx >= static_cast<int>(state.repeater_entries.size()))
                    return tool_result_t::error(OBFSTR("Invalid repeater entry index"));
                const auto& del_ptr = state.repeater_entries[static_cast<size_t>(idx)];
                if (del_ptr && del_ptr->in_progress.load()) {
                    diag::log_tagged_fmt("net_tools", "network_repeater delete blocked_in_progress idx=%d", idx);
                    return tool_result_t::error(OBFSTR("Cannot delete entry while request is in progress"));
                }
                state.repeater_entries.erase(state.repeater_entries.begin() + idx);
                diag::log_tagged_fmt("net_tools", "network_repeater delete done idx=%d remaining=%zu", idx, state.repeater_entries.size());
                return tool_result_t::ok(OBFSTR("Repeater entry ") + std::to_string(idx) + OBFSTR(" deleted"));
            }

            diag::log_tagged_fmt("net_tools", "network_repeater unknown_op op=%s", op.c_str());
            return tool_result_t::error(OBFSTR("Unknown operation. Use create|send|list|get|delete"));
        }, false});

}

}
