#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "game_protocol.hpp"

#include "protocol_parser.hpp"
#include "protobuf_codec.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

namespace game_protocol {
namespace {

struct replay_session_t {
    std::string id;
    std::uint64_t created_ms = 0;
    std::uint32_t filter_pid = 0;
    std::vector<driver_bridge::captured_packet_t> packets;
    nlohmann::json detection;
};

std::mutex& replay_mutex()
{
    static std::mutex m;
    return m;
}

std::map<std::string, replay_session_t>& replay_sessions()
{
    static std::map<std::string, replay_session_t> sessions;
    return sessions;
}

std::atomic<std::uint64_t>& replay_counter()
{
    static std::atomic<std::uint64_t> c{1};
    return c;
}

std::string make_session_id(const char* prefix)
{
    const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t n = replay_counter().fetch_add(1, std::memory_order_relaxed);
    std::ostringstream os;
    os << prefix << "_" << std::hex << std::uppercase << now << "_" << n;
    return os.str();
}

std::uint16_t be16(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t be32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint16_t le16(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[1]) << 8) | p[0]);
}

std::uint32_t le32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[3]) << 24) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           static_cast<std::uint32_t>(p[0]);
}

bool is_printable(std::uint8_t b)
{
    return (b >= 0x20 && b <= 0x7e) || b == '\r' || b == '\n' || b == '\t';
}

double printable_ratio(const std::vector<std::uint8_t>& data)
{
    if (data.empty())
        return 0.0;
    std::size_t printable = 0;
    for (std::uint8_t b : data)
        if (is_printable(b))
            ++printable;
    return static_cast<double>(printable) / static_cast<double>(data.size());
}

bool has_raknet_magic(const std::vector<std::uint8_t>& data, std::size_t& offset)
{
    static const std::uint8_t magic[] = {
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
        0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78
    };
    if (data.size() < sizeof(magic))
        return false;
    for (std::size_t i = 0; i + sizeof(magic) <= data.size(); ++i) {
        if (std::memcmp(data.data() + i, magic, sizeof(magic)) == 0) {
            offset = i;
            return true;
        }
    }
    return false;
}

const char* enet_command_name(std::uint8_t command)
{
    switch (command & 0x0f) {
    case 1: return "acknowledge";
    case 2: return "connect";
    case 3: return "verify_connect";
    case 4: return "disconnect";
    case 5: return "ping";
    case 6: return "send_reliable";
    case 7: return "send_unreliable";
    case 8: return "send_fragment";
    case 9: return "send_unsequenced";
    case 10: return "bandwidth_limit";
    case 11: return "throttle_configure";
    case 12: return "send_unreliable_fragment";
    default: return "unknown";
    }
}

std::size_t enet_command_fixed_size(std::uint8_t command)
{
    switch (command & 0x0f) {
    case 1: return 8;
    case 2: return 48;
    case 3: return 44;
    case 4: return 8;
    case 5: return 4;
    case 6: return 6;
    case 7: return 8;
    case 8: return 24;
    case 9: return 8;
    case 10: return 12;
    case 11: return 16;
    case 12: return 24;
    default: return 4;
    }
}

bool looks_like_enet(const std::vector<std::uint8_t>& data, std::vector<std::string>& evidence, double& confidence)
{
    confidence = 0.0;
    if (data.size() < 8)
        return false;

    const std::uint16_t peer = be16(data.data());
    const std::uint16_t sent_time = be16(data.data() + 2);
    const std::uint8_t cmd = data[4] & 0x0f;
    const std::uint8_t flags = data[4] & 0xf0;
    const std::uint8_t channel = data[5];
    const std::size_t fixed_size = enet_command_fixed_size(data[4]);

    double score = 0.0;
    if (cmd >= 1 && cmd <= 12) {
        score += 0.32;
        evidence.push_back(std::string("first_command=") + enet_command_name(data[4]));
    }
    if (fixed_size <= data.size() - 4 || cmd == 6 || cmd == 7 || cmd == 8 || cmd == 9 || cmd == 12)
        score += 0.15;
    if (channel < 32)
        score += 0.12;
    if ((flags & 0x30) == 0)
        score += 0.08;
    if ((peer & 0x0fff) != 0x0fff)
        score += 0.05;
    if (sent_time != 0)
        score += 0.05;

    std::size_t off = 4;
    std::uint32_t parsed = 0;
    while (off + 4 <= data.size() && parsed < 6) {
        const std::uint8_t c = data[off] & 0x0f;
        if (c < 1 || c > 12)
            break;
        std::size_t size = enet_command_fixed_size(data[off]);
        if (c == 6 && off + 6 <= data.size())
            size += be16(data.data() + off + 4);
        else if ((c == 7 || c == 9) && off + 8 <= data.size())
            size += be16(data.data() + off + 6);
        else if ((c == 8 || c == 12) && off + 24 <= data.size())
            size += be16(data.data() + off + 6);
        if (size < 4 || off + size > data.size())
            break;
        ++parsed;
        off += size;
    }
    if (parsed > 1) {
        score += 0.18;
        evidence.push_back("multiple_enet_commands=" + std::to_string(parsed));
    }

    confidence = (std::min)(0.92, score);
    return confidence >= 0.45;
}

bool looks_like_photon(const std::vector<std::uint8_t>& data, std::vector<std::string>& evidence, double& confidence)
{
    confidence = 0.0;
    if (data.size() < 4)
        return false;

    double score = 0.0;
    if (data[0] == 0xf3) {
        score += 0.45;
        evidence.push_back("photon_tcp_magic_f3");
    }
    if (data.size() >= 12) {
        const std::uint8_t command_count = data[5];
        const std::uint8_t command_type = data[7];
        if (command_count > 0 && command_count <= 32) {
            score += 0.18;
            evidence.push_back("small_command_count=" + std::to_string(command_count));
        }
        if (command_type >= 1 && command_type <= 12) {
            score += 0.17;
            evidence.push_back("photon_command_type_range=" + std::to_string(command_type));
        }
    }
    if (data.size() >= 2 && data[0] == 0xfb && data[1] <= 0x10) {
        score += 0.2;
        evidence.push_back("photon_reliable_udp_prefix");
    }
    confidence = (std::min)(0.82, score);
    return confidence >= 0.38;
}

bool looks_like_protobuf(const std::vector<std::uint8_t>& data, std::vector<std::string>& evidence, double& confidence)
{
    confidence = 0.0;
    if (data.size() < 2 || data.size() > 65536)
        return false;
    auto fields = protobuf_codec::decode(data.data(), data.size());
    if (fields.empty())
        return false;
    std::uint32_t sensible = 0;
    for (const auto& f : fields) {
        if (f.field_number > 0 && f.field_number < 2048)
            ++sensible;
    }
    if (sensible == 0)
        return false;
    confidence = (std::min)(0.76, 0.28 + 0.08 * static_cast<double>((std::min)(std::size_t(sensible), std::size_t(6))));
    evidence.push_back("protobuf_wire_fields=" + std::to_string(fields.size()));
    return confidence >= 0.42;
}

std::string format_ip(const std::uint8_t* addr, std::uint32_t af)
{
    char buf[80] = {};
    if (af == 23) {
        std::snprintf(buf, sizeof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    } else {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
    return buf;
}

bool parse_ipv4(const std::string& text, std::uint8_t* out)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(text.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return false;
    out[0] = static_cast<std::uint8_t>(a);
    out[1] = static_cast<std::uint8_t>(b);
    out[2] = static_cast<std::uint8_t>(c);
    out[3] = static_cast<std::uint8_t>(d);
    return true;
}

bool is_loopback(const std::uint8_t* addr, std::uint32_t af)
{
    if (af == 23) {
        for (int i = 0; i < 15; ++i)
            if (addr[i] != 0)
                return false;
        return addr[15] == 1;
    }
    return addr[0] == 127;
}

bool is_blocked_target(const std::uint8_t* addr, std::uint32_t af)
{
    if (af == 23)
        return false;
    if (addr[0] == 0 || addr[0] >= 224 || addr[0] == 255)
        return true;
    if (addr[0] == 169 && addr[1] == 254)
        return true;
    return false;
}

std::string protocol_name(std::uint32_t protocol)
{
    if (protocol == 6)
        return "TCP";
    if (protocol == 17)
        return "UDP";
    if (protocol == 1)
        return "ICMP";
    return std::to_string(protocol);
}

std::string direction_name(std::uint32_t direction)
{
    return direction == 0 ? "inbound" : "outbound";
}

void add_field(nlohmann::json& fields,
               std::size_t offset,
               std::size_t size,
               const std::string& type,
               double confidence,
               const nlohmann::json& samples,
               const nlohmann::json& evidence)
{
    nlohmann::json f;
    f["offset"] = offset;
    f["size"] = size;
    f["type_guess"] = type;
    f["confidence"] = confidence;
    f["sample_values"] = samples;
    f["evidence"] = evidence;
    fields.push_back(std::move(f));
}

} 

std::vector<std::uint8_t> hex_to_bytes(const std::string& text,
                                       std::string* error,
                                       std::size_t max_bytes)
{
    std::string compact;
    compact.reserve(text.size());
    for (char ch : text) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (std::isxdigit(c))
            compact.push_back(ch);
        else if (std::isspace(c) || ch == ':' || ch == '-' || ch == '_')
            continue;
        else {
            if (error)
                *error = "invalid hex character";
            return {};
        }
    }
    if ((compact.size() & 1u) != 0) {
        if (error)
            *error = "hex input has odd length";
        return {};
    }
    if (compact.size() / 2 > max_bytes) {
        if (error)
            *error = "hex input exceeds byte cap";
        return {};
    }

    std::vector<std::uint8_t> out;
    out.reserve(compact.size() / 2);
    for (std::size_t i = 0; i < compact.size(); i += 2) {
        char tmp[3] = { compact[i], compact[i + 1], 0 };
        out.push_back(static_cast<std::uint8_t>(std::strtoul(tmp, nullptr, 16)));
    }
    return out;
}

std::string bytes_to_hex(const std::uint8_t* data, std::size_t len, std::size_t max_bytes)
{
    if (!data || len == 0)
        return {};
    const std::size_t show = (std::min)(len, max_bytes);
    std::string out;
    out.reserve(show * 2 + 32);
    for (std::size_t i = 0; i < show; ++i) {
        char b[3] = {};
        std::snprintf(b, sizeof(b), "%02X", data[i]);
        out += b;
    }
    if (show < len)
        out += "...";
    return out;
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& data, std::size_t max_bytes)
{
    return bytes_to_hex(data.data(), data.size(), max_bytes);
}

double shannon_entropy(const std::uint8_t* data, std::size_t len)
{
    if (!data || len == 0)
        return 0.0;
    double freq[256] = {};
    for (std::size_t i = 0; i < len; ++i)
        freq[data[i]] += 1.0;
    double entropy = 0.0;
    const double denom = static_cast<double>(len);
    for (double count : freq) {
        if (count <= 0.0)
            continue;
        const double p = count / denom;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

bool capture_packets_bounded(const capture_options_t& input,
                             std::vector<driver_bridge::captured_packet_t>& out,
                             std::string& error)
{
    out.clear();
    error.clear();
    const std::uint64_t t0 = static_cast<std::uint64_t>(GetTickCount64());
    diag::log_tagged_fmt("gameproto",
        "capture_begin pid=%u protocol=%u capture_ms=%u max_packets=%u max_payload=%u driver=%d",
        input.pid,
        input.protocol,
        input.capture_ms,
        input.max_packets,
        input.max_payload,
        driver_bridge::using_kernel_driver() ? 1 : 0);
    if (!driver_bridge::using_kernel_driver()) {
        error = "driver bridge is not connected";
        diag::log_tagged_fmt("gameproto", "capture_failed reason=driver_unavailable elapsed_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    capture_options_t options = input;
    if (options.capture_ms == 0)
        options.capture_ms = 5000;
    if (options.capture_ms > 15000)
        options.capture_ms = 15000;
    if (options.max_packets == 0)
        options.max_packets = 64;
    if (options.max_packets > 512)
        options.max_packets = 512;
    if (options.max_payload == 0)
        options.max_payload = 1500;
    if (options.max_payload > 8192)
        options.max_payload = 8192;

    if (!driver_bridge::start_capture(options.pid, 0, options.protocol, nullptr, options.max_payload)) {
        error = driver_bridge::last_error().empty() ? "failed to start packet capture" : driver_bridge::last_error();
        diag::log_tagged_fmt("gameproto",
            "capture_failed reason=start_capture pid=%u protocol=%u error=%s elapsed_ms=%llu",
            options.pid,
            options.protocol,
            error.c_str(),
            static_cast<unsigned long long>(GetTickCount64() - t0));
        return false;
    }

    const DWORD started = GetTickCount();
    while (GetTickCount() - started < options.capture_ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    out = driver_bridge::get_captured_packets(options.max_packets);
    const size_t raw_count = out.size();
    driver_bridge::stop_capture();

    if (options.pid != 0 || options.protocol != 0) {
        std::vector<driver_bridge::captured_packet_t> filtered;
        filtered.reserve(out.size());
        for (auto& p : out) {
            if (options.pid != 0 && p.pid != options.pid)
                continue;
            if (options.protocol != 0 && p.protocol != options.protocol)
                continue;
            filtered.push_back(std::move(p));
        }
        out = std::move(filtered);
    }

    if (out.size() > options.max_packets)
        out.resize(options.max_packets);
    diag::log_tagged_fmt("gameproto",
        "capture_done pid=%u protocol=%u raw_count=%zu filtered_count=%zu capture_ms=%u elapsed_ms=%llu",
        options.pid,
        options.protocol,
        raw_count,
        out.size(),
        options.capture_ms,
        static_cast<unsigned long long>(GetTickCount64() - t0));
    return true;
}

nlohmann::json detect_protocols(const std::vector<driver_bridge::captured_packet_t>& packets,
                                std::size_t max_detected_packets)
{
    struct aggregate_t {
        double score = 0.0;
        std::uint32_t count = 0;
        std::set<std::string> evidence;
    };

    std::map<std::string, aggregate_t> aggregates;
    nlohmann::json detected = nlohmann::json::array();
    std::size_t packet_index = 0;

    for (const auto& pkt : packets) {
        const auto& data = pkt.payload;
        if (data.empty()) {
            ++packet_index;
            continue;
        }

        std::string best = "custom_binary";
        double best_conf = 0.18;
        std::vector<std::string> evidence;

        std::size_t raknet_off = 0;
        if (has_raknet_magic(data, raknet_off)) {
            best = "raknet";
            best_conf = 0.96;
            evidence.push_back("raknet_offline_magic_offset=" + std::to_string(raknet_off));
            if (!data.empty())
                evidence.push_back("message_id=0x" + bytes_to_hex(data.data(), 1, 1));
        } else {
            std::vector<std::string> enet_evidence;
            double enet_conf = 0.0;
            if (looks_like_enet(data, enet_evidence, enet_conf) && enet_conf > best_conf) {
                best = "enet";
                best_conf = enet_conf;
                evidence = std::move(enet_evidence);
            }

            std::vector<std::string> photon_evidence;
            double photon_conf = 0.0;
            if (looks_like_photon(data, photon_evidence, photon_conf) && photon_conf > best_conf) {
                best = "photon";
                best_conf = photon_conf;
                evidence = std::move(photon_evidence);
            }

            std::vector<std::string> pb_evidence;
            double pb_conf = 0.0;
            if (looks_like_protobuf(data, pb_evidence, pb_conf) && pb_conf > best_conf) {
                best = "protobuf";
                best_conf = pb_conf;
                evidence = std::move(pb_evidence);
            }

            if (data.size() >= 2 && data[0] == 0x1f && data[1] == 0x8b && best_conf < 0.7) {
                best = "gzip_framed";
                best_conf = 0.72;
                evidence = {"gzip_magic"};
            }
        }

        const auto parsed = protocol_parser::detect_protocol(
            data.data(), data.size(),
            static_cast<std::uint16_t>(pkt.local_port),
            static_cast<std::uint16_t>(pkt.remote_port),
            pkt.protocol);
        if (parsed.protocol != protocol_parser::detected_protocol_t::unknown && best_conf < 0.5) {
            evidence.push_back("generic_parser=" + parsed.label);
            if (best == "custom_binary") {
                best = parsed.label.empty() ? "known_transport_protocol" : parsed.label;
                best_conf = 0.48;
            }
        }

        const double entropy = shannon_entropy(data.data(), data.size());
        const double ascii = printable_ratio(data);
        if (best == "custom_binary") {
            if (entropy > 6.8) {
                best_conf = 0.36;
                evidence.push_back("high_entropy_binary");
            } else if (ascii > 0.75) {
                best_conf = 0.32;
                evidence.push_back("mostly_printable_payload");
            } else {
                best_conf = 0.28;
                evidence.push_back("opaque_binary_payload");
            }
        }

        auto& agg = aggregates[best];
        agg.score += best_conf;
        ++agg.count;
        for (const auto& e : evidence)
            agg.evidence.insert(e);

        if (detected.size() < max_detected_packets && best_conf >= 0.28) {
            nlohmann::json p;
            p["index"] = packet_index;
            p["pid"] = pkt.pid;
            p["protocol"] = protocol_name(pkt.protocol);
            p["direction"] = direction_name(pkt.direction);
            p["local"] = format_ip(pkt.local_addr, pkt.address_family) + ":" + std::to_string(pkt.local_port);
            p["remote"] = format_ip(pkt.remote_addr, pkt.address_family) + ":" + std::to_string(pkt.remote_port);
            p["payload_size"] = data.size();
            p["protocol_guess"] = best;
            p["confidence"] = best_conf;
            p["entropy"] = entropy;
            p["hex_preview"] = bytes_to_hex(data, 96);
            p["evidence"] = evidence;
            detected.push_back(std::move(p));
        }

        ++packet_index;
    }

    std::string top_protocol = "unknown";
    double top_confidence = 0.0;
    nlohmann::json alternatives = nlohmann::json::array();
    for (const auto& [name, agg] : aggregates) {
        const double avg = agg.count ? agg.score / static_cast<double>(agg.count) : 0.0;
        const double weighted = (std::min)(0.98, avg + 0.03 * static_cast<double>((std::min)(agg.count, 6u)));
        if (weighted > top_confidence) {
            top_confidence = weighted;
            top_protocol = name;
        }
        nlohmann::json a;
        a["protocol"] = name;
        a["confidence"] = weighted;
        a["packet_count"] = agg.count;
        nlohmann::json ev = nlohmann::json::array();
        for (const auto& e : agg.evidence) {
            if (ev.size() >= 8)
                break;
            ev.push_back(e);
        }
        a["evidence"] = std::move(ev);
        alternatives.push_back(std::move(a));
    }

    nlohmann::json out;
    out["protocol"] = top_protocol;
    out["confidence"] = top_confidence;
    out["packet_count"] = packets.size();
    out["detected_packets"] = std::move(detected);
    out["alternatives"] = std::move(alternatives);
    if (packets.empty())
        out["evidence"] = nlohmann::json::array({"no_packets_available"});
    return out;
}

nlohmann::json decode_enet_packet(const std::vector<std::uint8_t>& packet,
                                  std::optional<std::uint32_t> channel_filter)
{
    nlohmann::json out;
    out["valid"] = false;
    out["protocol"] = "enet";
    out["packet_size"] = packet.size();
    out["confidence"] = 0.0;
    out["commands"] = nlohmann::json::array();

    if (packet.size() < 4) {
        out["error"] = "packet too small for ENet header";
        return out;
    }

    const std::uint16_t peer_raw = be16(packet.data());
    const std::uint16_t sent_time = be16(packet.data() + 2);
    out["peer_id"] = peer_raw & 0x0fff;
    out["header_flags"] = peer_raw & 0xf000;
    out["sent_time"] = sent_time;

    std::size_t offset = 4;
    std::uint32_t command_count = 0;
    while (offset + 4 <= packet.size() && command_count < 64) {
        const std::uint8_t raw_command = packet[offset];
        const std::uint8_t command_id = raw_command & 0x0f;
        const std::uint8_t command_flags = raw_command & 0xf0;
        const std::uint8_t channel = packet[offset + 1];
        const std::uint16_t reliable_seq = be16(packet.data() + offset + 2);

        if (command_id == 0 || command_id > 12) {
            nlohmann::json e;
            e["offset"] = offset;
            e["reason"] = "command id outside known ENet range";
            e["raw_command"] = raw_command;
            out["parse_stop"] = std::move(e);
            break;
        }

        std::size_t header_size = enet_command_fixed_size(raw_command);
        std::size_t payload_len = 0;
        nlohmann::json extra;

        if (command_id == 6 && offset + 6 <= packet.size()) {
            payload_len = be16(packet.data() + offset + 4);
            extra["data_length"] = payload_len;
            header_size = 6;
        } else if ((command_id == 7 || command_id == 9) && offset + 8 <= packet.size()) {
            extra["unreliable_or_group_sequence"] = be16(packet.data() + offset + 4);
            payload_len = be16(packet.data() + offset + 6);
            extra["data_length"] = payload_len;
            header_size = 8;
        } else if ((command_id == 8 || command_id == 12) && offset + 24 <= packet.size()) {
            extra["start_sequence"] = be16(packet.data() + offset + 4);
            payload_len = be16(packet.data() + offset + 6);
            extra["fragment_count"] = be32(packet.data() + offset + 8);
            extra["fragment_number"] = be32(packet.data() + offset + 12);
            extra["total_length"] = be32(packet.data() + offset + 16);
            extra["fragment_offset"] = be32(packet.data() + offset + 20);
            header_size = 24;
        } else if (command_id == 1 && offset + 8 <= packet.size()) {
            extra["received_reliable_sequence"] = be16(packet.data() + offset + 4);
            extra["received_sent_time"] = be16(packet.data() + offset + 6);
        } else if (command_id == 4 && offset + 8 <= packet.size()) {
            extra["disconnect_data"] = be32(packet.data() + offset + 4);
        } else if (command_id == 10 && offset + 12 <= packet.size()) {
            extra["incoming_bandwidth"] = be32(packet.data() + offset + 4);
            extra["outgoing_bandwidth"] = be32(packet.data() + offset + 8);
        } else if (command_id == 11 && offset + 16 <= packet.size()) {
            extra["packet_throttle_interval"] = be32(packet.data() + offset + 4);
            extra["packet_throttle_acceleration"] = be32(packet.data() + offset + 8);
            extra["packet_throttle_deceleration"] = be32(packet.data() + offset + 12);
        }

        if (offset + header_size > packet.size()) {
            out["truncated_at_offset"] = offset;
            break;
        }
        if (payload_len > packet.size() - offset - header_size) {
            extra["declared_payload_exceeds_packet"] = true;
            payload_len = packet.size() - offset - header_size;
        }

        if (!channel_filter || *channel_filter == channel) {
            nlohmann::json cmd;
            cmd["offset"] = offset;
            cmd["command_raw"] = raw_command;
            cmd["command_type"] = enet_command_name(raw_command);
            cmd["command_id"] = command_id;
            cmd["command_flags"] = command_flags;
            cmd["channel"] = channel;
            cmd["reliable_sequence"] = reliable_seq;
            cmd["header_size"] = header_size;
            cmd["payload_size"] = payload_len;
            cmd["payload_hex_preview"] = payload_len ? bytes_to_hex(packet.data() + offset + header_size, payload_len, 128) : "";
            if (!extra.empty())
                cmd["fields"] = std::move(extra);
            out["commands"].push_back(std::move(cmd));
        }

        ++command_count;
        offset += header_size + payload_len;
        if (payload_len == 0 && header_size == 0)
            break;
    }

    out["valid"] = command_count > 0;
    out["parsed_command_count"] = command_count;
    out["bytes_consumed"] = offset;
    out["trailing_bytes"] = offset < packet.size() ? packet.size() - offset : 0;
    out["confidence"] = command_count ? (std::min)(0.95, 0.52 + 0.08 * static_cast<double>((std::min)(command_count, 4u))) : 0.12;
    return out;
}

nlohmann::json decode_payload_heuristic(const std::vector<std::uint8_t>& payload,
                                        const std::string& context_hint)
{
    nlohmann::json out;
    out["payload_size"] = payload.size();
    out["context_hint"] = context_hint;
    out["entropy"] = shannon_entropy(payload.data(), payload.size());
    out["printable_ratio"] = printable_ratio(payload);
    out["fields"] = nlohmann::json::array();
    out["evidence"] = nlohmann::json::array();

    if (payload.empty()) {
        out["evidence"].push_back("empty_payload");
        return out;
    }

    if (payload.size() > 65536) {
        out["truncated_analysis"] = true;
    }

    const std::size_t limit = (std::min)(payload.size(), std::size_t(8192));
    nlohmann::json& fields = out["fields"];

    auto proto_fields = protobuf_codec::decode(payload.data(), limit);
    if (!proto_fields.empty()) {
        out["evidence"].push_back("protobuf_wire_decode_succeeded");
        for (const auto& pf : proto_fields) {
            if (fields.size() >= 64)
                break;
            nlohmann::json samples = nlohmann::json::array();
            std::string type = "protobuf_field";
            if (pf.display_type == protobuf_codec::field_display_t::string_val) {
                type = "string";
                samples.push_back(pf.string_value.substr(0, 96));
            } else if (pf.display_type == protobuf_codec::field_display_t::uint_val ||
                       pf.display_type == protobuf_codec::field_display_t::int_val) {
                type = "varint";
                samples.push_back(pf.varint_value);
            } else if (pf.display_type == protobuf_codec::field_display_t::fixed32_val) {
                type = "fixed32";
                samples.push_back(pf.fixed32_value);
            } else if (pf.display_type == protobuf_codec::field_display_t::fixed64_val) {
                type = "fixed64";
                samples.push_back(pf.fixed64_value);
            } else if (pf.display_type == protobuf_codec::field_display_t::nested_message) {
                type = "nested_message";
                samples.push_back("nested_fields=" + std::to_string(pf.nested_fields.size()));
            } else {
                samples.push_back("bytes=" + std::to_string(pf.bytes_value.size()));
            }
            nlohmann::json ev = nlohmann::json::array();
            ev.push_back("field_number=" + std::to_string(pf.field_number));
            add_field(fields, 0, 0, type, 0.58, samples, ev);
        }
    }

    for (std::size_t i = 0; i + 4 <= limit && fields.size() < 96; ) {
        if (!is_printable(payload[i])) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < limit && is_printable(payload[j]) && j - i < 256)
            ++j;
        if (j - i >= 4) {
            std::string s(payload.begin() + static_cast<std::ptrdiff_t>(i),
                          payload.begin() + static_cast<std::ptrdiff_t>(j));
            nlohmann::json samples = nlohmann::json::array({s.substr(0, 96)});
            nlohmann::json ev = nlohmann::json::array({"printable_run"});
            add_field(fields, i, j - i, "string_or_ascii_blob", 0.52, samples, ev);
            i = j;
        } else {
            ++i;
        }
    }

    for (std::size_t i = 0; i + 2 <= limit && fields.size() < 128; ++i) {
        const std::uint8_t len8 = payload[i];
        if (len8 >= 4 && i + 1 + len8 <= limit) {
            bool printable = true;
            for (std::size_t j = i + 1; j < i + 1 + len8; ++j) {
                if (!is_printable(payload[j])) {
                    printable = false;
                    break;
                }
            }
            if (printable) {
                std::string s(payload.begin() + static_cast<std::ptrdiff_t>(i + 1),
                              payload.begin() + static_cast<std::ptrdiff_t>(i + 1 + len8));
                add_field(fields, i, 1 + len8, "u8_length_prefixed_string", 0.66,
                          nlohmann::json::array({s.substr(0, 96)}),
                          nlohmann::json::array({"length_byte=" + std::to_string(len8)}));
            }
        }
        if (i + 4 <= limit) {
            const std::uint16_t l16le = le16(payload.data() + i);
            const std::uint16_t l16be = be16(payload.data() + i);
            const std::uint16_t chosen = (l16le >= 4 && i + 2 + l16le <= limit) ? l16le :
                                         (l16be >= 4 && i + 2 + l16be <= limit) ? l16be : 0;
            if (chosen != 0 && chosen <= 512) {
                std::size_t printable = 0;
                for (std::size_t j = i + 2; j < i + 2 + chosen; ++j)
                    if (is_printable(payload[j]))
                        ++printable;
                if (printable * 100 >= chosen * 80) {
                    add_field(fields, i, 2 + chosen, "u16_length_prefixed_blob", 0.54,
                              nlohmann::json::array({"len=" + std::to_string(chosen)}),
                              nlohmann::json::array({"u16_length_prefix"}));
                }
            }
        }
    }

    for (std::size_t i = 0; i + 4 <= limit && fields.size() < 192; i += 4) {
        std::uint32_t u = le32(payload.data() + i);
        float f = 0.0f;
        std::memcpy(&f, payload.data() + i, sizeof(f));
        if (std::isfinite(f) && std::fabs(f) > 0.00001f && std::fabs(f) < 1000000.0f) {
            double conf = 0.34;
            nlohmann::json ev = nlohmann::json::array({"finite_ieee754_le"});
            if (context_hint == "position" || context_hint == "entity_update") {
                if (i + 12 <= limit) {
                    float f2 = 0.0f;
                    float f3 = 0.0f;
                    std::memcpy(&f2, payload.data() + i + 4, sizeof(f2));
                    std::memcpy(&f3, payload.data() + i + 8, sizeof(f3));
                    if (std::isfinite(f2) && std::isfinite(f3) &&
                        std::fabs(f2) < 1000000.0f && std::fabs(f3) < 1000000.0f) {
                        conf = 0.62;
                        ev.push_back("three_float_vector_candidate");
                    }
                }
            }
            add_field(fields, i, 4, "float32_le_candidate", conf,
                      nlohmann::json::array({f}), ev);
        } else if (u != 0 && u != 0xffffffffu && u < 0x40000000u) {
            double conf = (u < 1000000u) ? 0.42 : 0.3;
            add_field(fields, i, 4, "uint32_le_candidate", conf,
                      nlohmann::json::array({u}),
                      nlohmann::json::array({"aligned_nonzero_integer"}));
        }
    }

    for (std::size_t stride : {std::size_t(8), std::size_t(12), std::size_t(16), std::size_t(24), std::size_t(32), std::size_t(48), std::size_t(64)}) {
        if (limit < stride * 3)
            continue;
        std::uint32_t similar = 0;
        const std::size_t rows = limit / stride;
        for (std::size_t row = 1; row < rows && row < 32; ++row) {
            std::uint32_t small_delta = 0;
            for (std::size_t off = 0; off + 4 <= stride; off += 4) {
                const std::uint32_t a = le32(payload.data() + off);
                const std::uint32_t b = le32(payload.data() + row * stride + off);
                if ((a == 0 && b == 0) || (a != 0 && b != 0 && std::llabs(static_cast<long long>(a) - static_cast<long long>(b)) < 1000000))
                    ++small_delta;
            }
            if (small_delta >= 2)
                ++similar;
        }
        if (similar >= 2) {
            out["repeated_record_candidate"] = {
                {"stride", stride},
                {"rows_observed", rows},
                {"confidence", (std::min)(0.7, 0.36 + 0.04 * static_cast<double>(similar))}
            };
            break;
        }
    }

    while (fields.size() > 128)
        fields.erase(fields.size() - 1);
    out["field_count"] = fields.size();
    return out;
}

nlohmann::json record_replay_session(const capture_options_t& options,
                                     std::string& error)
{
    std::vector<driver_bridge::captured_packet_t> packets;
    if (!capture_packets_bounded(options, packets, error))
        return nlohmann::json::object();

    replay_session_t session;
    session.id = make_session_id("gpr");
    session.created_ms = static_cast<std::uint64_t>(GetTickCount64());
    session.filter_pid = options.pid;
    session.packets = std::move(packets);
    session.detection = detect_protocols(session.packets, 16);

    nlohmann::json out;
    {
        std::lock_guard<std::mutex> lock(replay_mutex());
        auto& map = replay_sessions();
        while (map.size() >= 16)
            map.erase(map.begin());
        out["session_id"] = session.id;
        out["packet_count"] = session.packets.size();
        out["detection"] = session.detection;
        out["backend"] = "driver_capture";
        out["filter_pid"] = options.pid;
        out["filter_protocol"] = options.protocol;
        out["capture_ms"] = options.capture_ms;
        out["requires_recorded_session"] = true;
        map[session.id] = std::move(session);
    }
    diag::log_tagged_fmt("gameproto",
        "record_replay_session session_id=%s packets=%u pid=%u protocol=%u",
        out.value("session_id", std::string()).c_str(),
        out.value("packet_count", 0u),
        options.pid,
        options.protocol);
    return out;
}

nlohmann::json stop_replay_recording(const std::string& requested_session_id,
                                     std::uint32_t max_packets,
                                     std::string& error)
{
    error.clear();
    if (!driver_bridge::using_kernel_driver()) {
        error = "driver bridge is not connected";
        return nlohmann::json::object();
    }
    if (max_packets == 0)
        max_packets = 128;
    if (max_packets > 512)
        max_packets = 512;

    auto packets = driver_bridge::get_captured_packets(max_packets);
    driver_bridge::stop_capture();

    replay_session_t session;
    session.id = requested_session_id.empty() ? make_session_id("gpr") : requested_session_id;
    session.created_ms = static_cast<std::uint64_t>(GetTickCount64());
    session.packets = std::move(packets);
    session.detection = detect_protocols(session.packets, 16);

    nlohmann::json out;
    {
        std::lock_guard<std::mutex> lock(replay_mutex());
        auto& map = replay_sessions();
        while (map.size() >= 16)
            map.erase(map.begin());
        out["session_id"] = session.id;
        out["packet_count"] = session.packets.size();
        out["detection"] = session.detection;
        out["backend"] = "driver_capture_stop";
        out["requires_recorded_session"] = true;
        map[session.id] = std::move(session);
    }
    diag::log_tagged_fmt("gameproto",
        "stop_replay_recording session_id=%s packets=%u",
        out.value("session_id", std::string()).c_str(),
        out.value("packet_count", 0u));
    return out;
}

nlohmann::json list_replay_sessions()
{
    nlohmann::json arr = nlohmann::json::array();
    std::lock_guard<std::mutex> lock(replay_mutex());
    for (const auto& [id, s] : replay_sessions()) {
        nlohmann::json j;
        j["session_id"] = id;
        j["created_ms"] = s.created_ms;
        j["filter_pid"] = s.filter_pid;
        j["packet_count"] = s.packets.size();
        j["protocol"] = s.detection.value("protocol", "unknown");
        j["confidence"] = s.detection.value("confidence", 0.0);
        arr.push_back(std::move(j));
    }
    nlohmann::json out;
    out["sessions"] = std::move(arr);
    out["count"] = out["sessions"].size();
    out["requires_recorded_session"] = true;
    out["record_operation"] = "record";
    return out;
}

bool replay_session(const replay_options_t& input,
                    nlohmann::json& out,
                    std::string& error)
{
    out = nlohmann::json::object();
    error.clear();
    if (!input.allow_unsafe || !input.confirm_unsafe) {
        error = "replay requires allow_unsafe=true and confirm_unsafe=true";
        return false;
    }
    if (!driver_bridge::using_kernel_driver()) {
        error = "driver bridge is not connected";
        return false;
    }
    if (input.session_id.empty()) {
        error = "session_id is required";
        return false;
    }

    replay_session_t session;
    {
        std::lock_guard<std::mutex> lock(replay_mutex());
        auto it = replay_sessions().find(input.session_id);
        if (it == replay_sessions().end()) {
            error = "session_id not found";
            return false;
        }
        session = it->second;
    }

    replay_options_t options = input;
    if (options.max_packets == 0)
        options.max_packets = 32;
    if (options.max_packets > 128)
        options.max_packets = 128;
    if (options.payload_cap == 0)
        options.payload_cap = 1024;
    if (options.payload_cap > 4096)
        options.payload_cap = 4096;
    if (options.replay_delay_ms > 1000)
        options.replay_delay_ms = 1000;

    std::uint8_t target_addr[16] = {};
    bool has_target_override = false;
    if (!options.target_ip.empty()) {
        if (!parse_ipv4(options.target_ip, target_addr)) {
            error = "target_ip must be an IPv4 literal";
            return false;
        }
        has_target_override = true;
        if (is_blocked_target(target_addr, 2)) {
            error = "target_ip is multicast, broadcast, unspecified, or link-local";
            return false;
        }
        if (!is_loopback(target_addr, 2) && !options.allow_non_loopback) {
            error = "non-loopback replay requires allow_non_loopback=true";
            return false;
        }
    }

    std::uint32_t sent = 0;
    std::uint32_t skipped_payload_cap = 0;
    std::uint32_t skipped_target = 0;
    nlohmann::json sent_packets = nlohmann::json::array();

    for (const auto& pkt : session.packets) {
        if (sent >= options.max_packets)
            break;
        if (pkt.payload.empty())
            continue;
        if (pkt.payload.size() > options.payload_cap) {
            ++skipped_payload_cap;
            continue;
        }

        std::uint32_t direction = 1;
        if (options.direction == "original")
            direction = pkt.direction;
        else if (options.direction == "inbound")
            direction = 0;

        std::uint32_t protocol = pkt.protocol == 0 ? 17 : pkt.protocol;
        std::uint32_t af = pkt.address_family == 23 ? 23 : 2;
        std::uint8_t src_addr[16] = {};
        std::uint8_t dst_addr[16] = {};
        std::uint32_t src_port = options.source_port ? options.source_port : pkt.local_port;
        std::uint32_t dst_port = options.target_port ? options.target_port : pkt.remote_port;

        if (direction == 0) {
            std::memcpy(src_addr, pkt.remote_addr, 16);
            std::memcpy(dst_addr, pkt.local_addr, 16);
            if (!options.target_port)
                dst_port = pkt.local_port;
            if (!options.source_port)
                src_port = pkt.remote_port;
        } else {
            std::memcpy(src_addr, pkt.local_addr, 16);
            std::memcpy(dst_addr, pkt.remote_addr, 16);
        }

        if (has_target_override) {
            af = 2;
            std::memcpy(dst_addr, target_addr, 4);
            if (src_addr[0] == 0 || !is_loopback(src_addr, 2)) {
                src_addr[0] = 127;
                src_addr[1] = 0;
                src_addr[2] = 0;
                src_addr[3] = 1;
            }
        }

        if (dst_port == 0 || src_port == 0 || is_blocked_target(dst_addr, af) ||
            (!is_loopback(dst_addr, af) && !options.allow_non_loopback)) {
            ++skipped_target;
            continue;
        }

        const bool ok = driver_bridge::inject_packet(direction, protocol, af, src_port, dst_port,
            src_addr, dst_addr, pkt.payload.data(), static_cast<std::uint32_t>(pkt.payload.size()));

        nlohmann::json s;
        s["ok"] = ok;
        s["direction"] = direction_name(direction);
        s["protocol"] = protocol_name(protocol);
        s["source"] = format_ip(src_addr, af) + ":" + std::to_string(src_port);
        s["target"] = format_ip(dst_addr, af) + ":" + std::to_string(dst_port);
        s["payload_size"] = pkt.payload.size();
        s["hex_preview"] = bytes_to_hex(pkt.payload, 64);
        if (sent_packets.size() < 32)
            sent_packets.push_back(std::move(s));
        if (ok)
            ++sent;

        if (options.replay_delay_ms)
            std::this_thread::sleep_for(std::chrono::milliseconds(options.replay_delay_ms));
    }

    out["session_id"] = options.session_id;
    out["recorded_packet_count"] = session.packets.size();
    out["replay_requires_existing_session"] = true;
    out["attempted_or_sent"] = sent;
    out["max_packets"] = options.max_packets;
    out["payload_cap"] = options.payload_cap;
    out["skipped_payload_cap"] = skipped_payload_cap;
    out["skipped_target"] = skipped_target;
    out["packets"] = std::move(sent_packets);
    out["limitations"] = nlohmann::json::array({
        "kernel transport injection is packet-level and does not recreate application socket state",
        "non-loopback targets are rejected unless explicitly allowed",
        "payloads above the configured cap are skipped"
    });
    return true;
}

}
