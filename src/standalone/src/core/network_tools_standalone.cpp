


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "comm.h"
#include "obfuscation.hpp"
#include "pro.h"
#include "decoder_pipeline.hpp"
#include "script_engine.hpp"
#include "tcp_stream_tracker.hpp"
#include "page_guard_engine.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <map>
#include <mutex>
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
    if (!device->is_connected())
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

    auto conns = device->enumerate_connections(filter_pid, filter_protocol);

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
    if (!device->is_connected())
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

    bool ok = device->start_capture(filter_pid, filter_port, filter_protocol,
        filter_ip, max_payload);

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!device->stop_capture())
        return tool_result_t::error(OBFSTR("Failed to stop packet capture."));

    return tool_result_t::ok(OBFSTR("Packet capture stopped"));
}

tool_result_t network_get_packets(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_packets = 32;
    if (params.contains("count") && params["count"].is_number())
        max_packets = params["count"].get<std::uint32_t>();
    if (max_packets > 32) max_packets = 32;

    auto packets = device->get_captured_packets(max_packets);

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));


    auto packets = device->get_captured_packets(1);
    if (packets.empty())
        return tool_result_t::error(OBFSTR("No packets available. Start capture first."));

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

    return tool_result_t::ok(OBFSTR("Packet analysis complete"), result);
}

tool_result_t network_dns_log(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number())
        filter_pid = params["pid"].get<std::uint32_t>();

    auto entries = device->get_dns_queries(filter_pid);

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
    if (!device->is_connected())
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
    bool ok = device->add_filter_rule(action, direction, protocol, pid, port,
        ip_addr, ip_mask, &rule_id);

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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("rule_id") || !params["rule_id"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));

    std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
    if (!device->remove_filter_rule(rule_id))
        return tool_result_t::error(OBFSTR("Failed to remove filter rule ") + std::to_string(rule_id));

    return tool_result_t::ok(OBFSTR("Filter rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
}

tool_result_t network_clear_filters(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!device->clear_filter_rules())
        return tool_result_t::error(OBFSTR("Failed to clear filter rules."));

    return tool_result_t::ok(OBFSTR("All filter rules cleared"));
}

tool_result_t network_stats(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    voyager::device_t::network_stats stats{};
    if (!device->get_network_stats(stats))
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    bool active = false;
    std::uint32_t captured = 0, dropped = 0;
    if (!device->get_capture_status(active, captured, dropped))
        return tool_result_t::error(OBFSTR("Failed to get capture status."));

    json result;
    result["capture_active"] = active;
    result["packets_captured"] = captured;
    result["packets_dropped"] = dropped;

    return tool_result_t::ok(active ? OBFSTR("Capture is active") : OBFSTR("Capture is stopped"), result);
}

tool_result_t network_block_ip(const json& params)
{
    if (!device->is_connected())
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
    if (!device->add_filter_rule(1, direction, 0, 0, 0, ip, mask, &rule_id))
        return tool_result_t::error(OBFSTR("Failed to add block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_ip"] = params["ip"];
    result["direction"] = (direction == 0) ? "inbound" : (direction == 1) ? "outbound" : "both";
    return tool_result_t::ok(OBFSTR("IP blocked: ") + params["ip"].get<std::string>(), result);
}

tool_result_t network_block_port(const json& params)
{
    if (!device->is_connected())
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
    if (!device->add_filter_rule(1, 2, protocol, 0, port, nullptr, nullptr, &rule_id))
        return tool_result_t::error(OBFSTR("Failed to add port block rule"));

    json result;
    result["rule_id"] = rule_id;
    result["blocked_port"] = port;
    if (protocol) result["protocol"] = protocol_name(protocol);
    return tool_result_t::ok(OBFSTR("Port blocked: ") + std::to_string(port), result);
}

tool_result_t network_block_process(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    if (!params.contains("pid") || !params["pid"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: pid"));

    std::uint32_t pid = params["pid"].get<std::uint32_t>();

    std::uint32_t rule_id = 0;
    if (!device->add_filter_rule(1, 2, 0, pid, 0, nullptr, nullptr, &rule_id))
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0, filter_protocol = 0, filter_port = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("port") && params["port"].is_number()) filter_port = params["port"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }

    auto results = device->get_dpi_results(filter_pid, filter_protocol, filter_port, 0);
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('start', 'stop', or 'get')"));

    std::string op = params["operation"].get<std::string>();
    std::uint32_t src_port = 0, dst_port = 0, pid = 0;
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

    if (op == "start") {
        bool ok = device->stream_reassemble_op(0, src_port, dst_port, pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to start stream reassembly. Max 1024 concurrent streams."));
        json r; r["status"] = "started"; r["src_port"] = src_port; r["dst_port"] = dst_port;
        return tool_result_t::ok(OBFSTR("TCP stream reassembly started"), r);
    } else if (op == "stop") {
        bool ok = device->stream_reassemble_op(1, src_port, dst_port, pid, nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to stop stream reassembly."));
        return tool_result_t::ok(OBFSTR("TCP stream reassembly stopped"));
    } else if (op == "get") {
        std::vector<std::uint8_t> stream_data;
        std::uint32_t total_packets = 0, truncated = 0;
        bool ok = device->stream_reassemble_op(2, src_port, dst_port, pid, nullptr, nullptr, &stream_data, &total_packets, &truncated);
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_pkts = 32;
    if (params.contains("count") && params["count"].is_number())
        max_pkts = params["count"].get<std::uint32_t>();
    if (max_pkts > 32) max_pkts = 32;

    auto packets = device->get_captured_packets(max_pkts);
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

    if (arr.empty())
        return tool_result_t::ok(OBFSTR("No HTTP messages found in captured packets. Ensure capture is active and HTTP traffic is flowing."), arr);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" HTTP messages parsed"), arr);
}

tool_result_t network_parse_tls(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t max_pkts = 32;
    if (params.contains("count") && params["count"].is_number())
        max_pkts = params["count"].get<std::uint32_t>();
    if (max_pkts > 32) max_pkts = 32;

    auto packets = device->get_captured_packets(max_pkts);
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

    if (arr.empty())
        return tool_result_t::ok(OBFSTR("No TLS records found in captured packets. Ensure capture is active and HTTPS traffic is flowing."), arr);
    return tool_result_t::ok(std::to_string(arr.size()) + OBFSTR(" TLS records parsed"), arr);
}

tool_result_t network_enumerate_wfp_callouts(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::string filter_module;
    if (params.contains("module") && params["module"].is_string())
        filter_module = params["module"].get<std::string>();

    auto callouts = device->enumerate_wfp_callouts(filter_module);
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t target_pid = 0;
    if (params.contains("pid") && params["pid"].is_number())
        target_pid = params["pid"].get<std::uint32_t>();

    auto socks = device->get_socket_handles(target_pid);
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t target_pid = 0, filter_protocol = 0;
    if (params.contains("pid") && params["pid"].is_number()) target_pid = params["pid"].get<std::uint32_t>();
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "tcp" || p == "TCP") filter_protocol = 6;
        else if (p == "udp" || p == "UDP") filter_protocol = 17;
    }

    auto conns = device->dump_tcpip_connections(target_pid, filter_protocol);
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto ifaces = device->enumerate_interfaces();
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
    if (!device->is_connected())
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

    bool ok = device->inject_packet(direction, protocol, af, src_port, dst_port,
        src_addr, dst_addr, payload.data(), static_cast<std::uint32_t>(payload.size()),
        tcp_flags, tcp_seq, tcp_ack);

    if (!ok) return tool_result_t::error(OBFSTR("Packet injection failed."));
    json r;
    r["direction"] = (direction == 0) ? "inbound" : "outbound";
    r["protocol"] = protocol_name(protocol);
    r["payload_size"] = payload.size();
    return tool_result_t::ok(OBFSTR("Packet injected successfully"), r);
}

tool_result_t network_modify_packet_rule(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
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
        bool ok = device->packet_mod_rule_op(0, 0, direction, protocol, port, pid,
            pattern.data(), static_cast<std::uint32_t>(pattern.size()),
            replacement.empty() ? nullptr : replacement.data(), static_cast<std::uint32_t>(replacement.size()),
            &rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add modification rule. Max 32 rules."));
        json r; r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Packet modification rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = device->packet_mod_rule_op(1, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove modification rule."));
        return tool_result_t::ok(OBFSTR("Modification rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = device->packet_mod_rule_op(3);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear modification rules."));
        return tool_result_t::ok(OBFSTR("All packet modification rules cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_mod_rules(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = device->list_packet_mod_rules();
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
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
        bool ok = device->traffic_redirect_op(0, 0, protocol, match_port, match_addr, redirect_port, redirect_addr, af, &rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add redirect rule. Max 16 rules."));
        json r; r["rule_id"] = rule_id;
        return tool_result_t::ok(OBFSTR("Traffic redirect rule added (ID: ") + std::to_string(rule_id) + ")", r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = device->traffic_redirect_op(1, rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove redirect rule."));
        return tool_result_t::ok(OBFSTR("Redirect rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = device->traffic_redirect_op(3);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear redirect rules."));
        return tool_result_t::ok(OBFSTR("All traffic redirect rules cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_redirect_rules(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = device->list_redirect_rules();
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('enable' or 'disable')"));

    std::string op = params["operation"].get<std::string>();
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
        bool ok = device->intercept_op(0, filter_pid, filter_port, filter_protocol, 0, nullptr, 0, &held_count, &active);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to enable packet interception."));
        json r; r["active"] = active; r["held_count"] = held_count;
        return tool_result_t::ok(OBFSTR("Packet interception enabled. Matching packets will be held for inspection."), r);
    } else if (op == "disable") {
        bool ok = device->intercept_op(1, 0, 0, 0, 0, nullptr, 0, nullptr, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable packet interception."));
        return tool_result_t::ok(OBFSTR("Packet interception disabled. All held packets released."));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'enable' or 'disable'."));
}

tool_result_t network_get_held_packets(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto held = device->get_held_packets();
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("hold_id") || !params["hold_id"].is_number())
        return tool_result_t::error(OBFSTR("Missing required parameter: hold_id"));

    std::uint64_t hold_id = params["hold_id"].get<std::uint64_t>();
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

    bool ok = device->intercept_op(operation, 0, 0, 0, hold_id,
        modify_payload.empty() ? nullptr : modify_payload.data(),
        static_cast<std::uint32_t>(modify_payload.size()), nullptr, nullptr);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to release/process held packet."));

    std::string action_str = (operation == 4) ? "dropped" : (operation == 5) ? "modified and released" : "released";
    return tool_result_t::ok(OBFSTR("Packet ") + action_str);
}

tool_result_t network_kill_connection(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t protocol = 6, af = 2, src_port = 0, dst_port = 0, pid = 0;
    std::uint8_t src_addr[16] = {}, dst_addr[16] = {};

    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        if (p == "udp" || p == "UDP") protocol = 17;
    }
    if (params.contains("src_port") && params["src_port"].is_number()) src_port = params["src_port"].get<std::uint32_t>();
    if (params.contains("dst_port") && params["dst_port"].is_number()) dst_port = params["dst_port"].get<std::uint32_t>();
    if (params.contains("src_ip") && params["src_ip"].is_string()) parse_ipv4(params["src_ip"].get<std::string>(), src_addr);
    if (params.contains("dst_ip") && params["dst_ip"].is_string()) parse_ipv4(params["dst_ip"].get<std::string>(), dst_addr);
    if (params.contains("pid") && params["pid"].is_number()) pid = params["pid"].get<std::uint32_t>();

    bool ok = device->kill_connection(protocol, af, src_port, dst_port, src_addr, dst_addr, pid);
    if (!ok) return tool_result_t::error(OBFSTR("Failed to kill connection. Tries socket close + RST injection."));
    return tool_result_t::ok(OBFSTR("Connection killed successfully"));
}

tool_result_t network_spoof_dns(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('add', 'remove', or 'clear')"));

    std::string op = params["operation"].get<std::string>();
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
        bool ok = device->dns_spoof_op(0, 0, domain.c_str(), spoof_addr, 2, ttl, &rule_id);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to add DNS spoof rule. Max 32 rules."));
        json r; r["rule_id"] = rule_id; r["domain"] = domain;
        return tool_result_t::ok(OBFSTR("DNS spoof rule added: ") + domain + OBFSTR(" -> ") + params["spoof_ip"].get<std::string>(), r);
    } else if (op == "remove") {
        if (!params.contains("rule_id") || !params["rule_id"].is_number())
            return tool_result_t::error(OBFSTR("Missing required parameter: rule_id"));
        std::uint32_t rule_id = params["rule_id"].get<std::uint32_t>();
        bool ok = device->dns_spoof_op(1, rule_id, nullptr, nullptr, 2, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to remove DNS spoof rule."));
        return tool_result_t::ok(OBFSTR("DNS spoof rule ") + std::to_string(rule_id) + OBFSTR(" removed"));
    } else if (op == "clear") {
        bool ok = device->dns_spoof_op(3, 0, nullptr, nullptr, 2, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to clear DNS spoof rules."));
        return tool_result_t::ok(OBFSTR("All DNS spoof rules cleared"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'add', 'remove', or 'clear'."));
}

tool_result_t network_list_dns_spoof_rules(const json&)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    auto rules = device->list_dns_spoof_rules();
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('start', 'stop', 'get', or 'reset')"));

    std::string op = params["operation"].get<std::string>();
    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();

    if (op == "start") {
        bool ok = device->bw_monitor_op(0, filter_pid, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to start bandwidth monitoring."));
        return tool_result_t::ok(OBFSTR("Bandwidth monitoring started"));
    } else if (op == "stop") {
        bool ok = device->bw_monitor_op(1, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to stop bandwidth monitoring."));
        return tool_result_t::ok(OBFSTR("Bandwidth monitoring stopped"));
    } else if (op == "get") {
        voyager::device_t::bw_stats stats{};
        bool ok = device->bw_monitor_op(2, filter_pid, &stats);
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
        bool ok = device->bw_monitor_op(3, 0, nullptr);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to reset bandwidth counters."));
        return tool_result_t::ok(OBFSTR("Bandwidth counters reset"));
    }
    return tool_result_t::error(OBFSTR("Invalid operation. Use 'start', 'stop', 'get', or 'reset'."));
}

tool_result_t network_bandwidth_per_process(const json& params)
{
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));

    std::uint32_t filter_pid = 0;
    if (params.contains("pid") && params["pid"].is_number()) filter_pid = params["pid"].get<std::uint32_t>();

    auto procs = device->get_bw_per_process(filter_pid);
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
    if (!device->is_connected())
        return tool_result_t::error(OBFSTR("Driver not connected."));
    if (!params.contains("operation") || !params["operation"].is_string())
        return tool_result_t::error(OBFSTR("Missing required parameter: operation ('enable', 'disable', or 'get')"));

    std::string op = params["operation"].get<std::string>();
    if (op == "enable") {
        bool ok = device->fingerprint_op(0);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to enable OS fingerprinting."));
        return tool_result_t::ok(OBFSTR("Passive OS fingerprinting enabled. Analyzing TCP SYN packets."));
    } else if (op == "disable") {
        bool ok = device->fingerprint_op(1);
        if (!ok) return tool_result_t::error(OBFSTR("Failed to disable OS fingerprinting."));
        return tool_result_t::ok(OBFSTR("OS fingerprinting disabled"));
    } else if (op == "get") {
        auto fps = device->get_fingerprints();
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
    if (!device->is_connected())
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

    voyager::device_t::pcap_export_result pcap{};
    bool ok = device->export_pcap(filter_pid, filter_protocol, max_packets, &pcap);
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
    return tool_result_t::ok(std::to_string(pcap.packets.size()) + OBFSTR(" packets exported to ") + path, r);
}

void register_network_tools(mcp_standalone::server_t& srv) {
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
               "Filter by pid, port, or protocol. Superior to basic packet view Ã¢â‚¬â€ identifies application-layer protocols."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Filter by process ID"), false},
         {OBFSTR("port"), OBFSTR("number"), OBFSTR("Filter by port number"), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Filter: 'tcp' or 'udp'"), false}},
        network_deep_inspect, true});

    register_compat(srv, {
        OBFSTR("network_follow_tcp_stream"), OBFSTR("network"),
        OBFSTR("TCP stream reassembly Ã¢â‚¬â€ equivalent to Wireshark 'Follow TCP Stream'. Reassembles TCP segments into "
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
               "protocol, state, local/remote address:port. Lower-level than netstat Ã¢â‚¬â€ works from kernel object tables."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID (0 = all processes)"), false}},
        network_get_socket_handles, true});

    register_compat(srv, {
        OBFSTR("network_dump_tcpip"), OBFSTR("network"),
        OBFSTR("Deep kernel TCPIP stack connection dump. Returns TCB address, owning module, bytes in/out, "
               "create time, and full connection tuple. More detailed than netstat Ã¢â‚¬â€ reads kernel TCPIP internal structures."),
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
               "hosts file Ã¢â‚¬â€ intercepts at the WFP layer before packets leave. Max 32 rules."),
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
         {OBFSTR("input_hex"), OBFSTR("string"), OBFSTR("Input data (hex encoded) — use instead of 'input' for binary"), false},
         {OBFSTR("pipeline"), OBFSTR("array"), OBFSTR("Array of transform step objects: [{\"name\":\"base64_decode\"}, {\"name\":\"xor\",\"params\":{\"key\":\"41\"}}]"), true}},
        [](const json& args) -> tool_result_t {
            std::vector<uint8_t> data;
            if (args.contains("input_hex") && args["input_hex"].is_string()) {
                std::string hex = args["input_hex"].get<std::string>();
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    data.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
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

                auto result = decoder_pipeline::apply_single(name, data, params);
                if (!result.success)
                    return tool_result_t::error("Transform '" + name + "' failed: " + result.error);
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
            auto& reg = decoder_pipeline::registry::instance();
            auto transforms = reg.all();
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
            return ok ? tool_result_t::ok("Script '" + name + "' loaded") : tool_result_t::error("Failed to load script");
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_unload"), OBFSTR("network"),
        OBFSTR("Unload a previously loaded Lua script by name."),
        {{OBFSTR("name"), OBFSTR("string"), OBFSTR("Script name to unload"), true}},
        [](const json& args) -> tool_result_t {
            std::string name = args.value("name", "");
            script_engine::unload_script(name);
            return tool_result_t::ok("Script '" + name + "' unloaded");
        }, false});

    register_compat(srv, {
        OBFSTR("network_script_execute"), OBFSTR("network"),
        OBFSTR("Execute Lua code in the script engine console. Returns the output/result. "
               "Useful for querying state, testing hooks, or running one-off transformations."),
        {{OBFSTR("code"), OBFSTR("string"), OBFSTR("Lua code to execute"), true}},
        [](const json& args) -> tool_result_t {
            std::string code = args.value("code", "");
            std::string result = script_engine::execute(code);
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

    // -----------------------------------------------------------------------
    // network_stream_track
    // -----------------------------------------------------------------------
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

            if (op == "start") {
                uint32_t pid = params.value("pid", 0u);
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

            // Helper: format raw bytes as "XX XX XX ..." + printable ASCII side-by-side
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

            // Helper: build JSON object from a snapshot
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

                // Parse dotted-quad IPv4 into uint32_t (little-endian byte order)
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

    // -----------------------------------------------------------------------
    // network_pg_sniff
    // -----------------------------------------------------------------------
    register_compat(srv, {
        OBFSTR("network_pg_sniff"), OBFSTR("network"),
        OBFSTR("Pre-encryption page guard sniffer. Installs a VEH-based PAGE_GUARD trap on a "
               "target memory region in another process to capture all reads/writes before "
               "encryption occurs. Uses page-fault + single-step re-arm (no HW breakpoint limit). "
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

            if (op == "install") {
                uint32_t pid = params.value("pid", 0u);
                if (pid == 0)
                    return tool_result_t::error("'pid' is required for install");

                // Accept address as hex string or plain number
                uint64_t addr = 0;
                if (params.contains("address")) {
                    auto& av = params["address"];
                    if (av.is_string()) {
                        addr = std::stoull(av.get<std::string>(), nullptr, 0);
                    } else if (av.is_number()) {
                        addr = av.get<uint64_t>();
                    }
                }
                if (addr == 0)
                    return tool_result_t::error("'address' is required for install");

                uint64_t size = params.value("size", static_cast<uint64_t>(0x1000));

                uint32_t sid = page_guard_engine::g_pg_engine.install(pid, addr, size);
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

                auto caps = page_guard_engine::g_pg_engine.get_captures(sid);
                json arr  = json::array();
                for (auto& c : caps) {
                    json o;
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(c.fault_addr));
                    o["fault_addr"]     = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(c.rip));
                    o["rip"]            = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(c.ctx_rax));
                    o["rax"]            = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(c.ctx_rcx));
                    o["rcx"]            = buf;
                    snprintf(buf, sizeof(buf), "0x%llX",
                             static_cast<unsigned long long>(c.ctx_rdx));
                    o["rdx"]            = buf;
                    o["timestamp"]      = c.timestamp;
                    o["exception_code"] = c.exception_code;
                    o["access_type"]    = c.access_type == 0 ? "read" : "write";
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
}

}
