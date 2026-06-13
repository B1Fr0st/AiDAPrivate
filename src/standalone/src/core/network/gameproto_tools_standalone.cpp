#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "game_protocol.hpp"
#include "obfuscation.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace gameproto_tools {
namespace {

std::uint32_t protocol_from_param(const json& params)
{
    if (params.contains("protocol") && params["protocol"].is_number()) {
        const auto v = params["protocol"].get<std::int64_t>();
        if (v >= 0 && v <= 255)
            return static_cast<std::uint32_t>(v);
    }
    if (params.contains("protocol") && params["protocol"].is_string()) {
        std::string p = params["protocol"].get<std::string>();
        std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (p == "tcp")
            return 6;
        if (p == "udp")
            return 17;
    }
    return 0;
}

game_protocol::capture_options_t capture_options_from_params(const json& params,
                                                             std::uint32_t default_ms,
                                                             std::uint32_t default_packets)
{
    game_protocol::capture_options_t options;
    if (params.contains("pid") && params["pid"].is_number()) {
        const auto v = params["pid"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            options.pid = static_cast<std::uint32_t>(v);
    }
    if (params.contains("filter_pid") && params["filter_pid"].is_number()) {
        const auto v = params["filter_pid"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            options.pid = static_cast<std::uint32_t>(v);
    }
    options.protocol = protocol_from_param(params);
    const double capture_sec = params.value("capture_sec", static_cast<double>(default_ms) / 1000.0);
    options.capture_ms = static_cast<std::uint32_t>((std::max)(0.1, capture_sec) * 1000.0);
    if (options.capture_ms > 15000)
        options.capture_ms = 15000;
    options.max_packets = params.value("max_packets", default_packets);
    if (options.max_packets > 512)
        options.max_packets = 512;
    options.max_payload = params.value("max_payload", 1500u);
    if (options.max_payload > 8192)
        options.max_payload = 8192;
    return options;
}

tool_result_t handle_gameproto_detect(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    auto options = capture_options_from_params(params, 5000, 64);
    if ((params.contains("payload_hex") && params["payload_hex"].is_string()) ||
        (params.contains("packet_hex") && params["packet_hex"].is_string())) {
        const std::string hex = params.contains("payload_hex") && params["payload_hex"].is_string()
            ? params["payload_hex"].get<std::string>()
            : params["packet_hex"].get<std::string>();
        std::string error;
        auto bytes = game_protocol::hex_to_bytes(hex, &error, options.max_payload);
        if (bytes.empty() && !hex.empty())
            return tool_result_t::error(error.empty() ? OBFSTR("invalid payload_hex") : error);
        driver_bridge::captured_packet_t pkt{};
        pkt.pid = options.pid;
        pkt.protocol = options.protocol == 0 ? 17 : options.protocol;
        pkt.direction = 1;
        pkt.address_family = 2;
        pkt.local_addr[0] = 127;
        pkt.local_addr[3] = 1;
        pkt.remote_addr[0] = 127;
        pkt.remote_addr[3] = 1;
        pkt.local_port = params.value("local_port", 40000u);
        pkt.remote_port = params.value("remote_port", 40001u);
        pkt.payload = std::move(bytes);
        pkt.payload_size = static_cast<std::uint32_t>(pkt.payload.size());
        std::vector<driver_bridge::captured_packet_t> packets;
        packets.push_back(std::move(pkt));
        json result = game_protocol::detect_protocols(packets, 32);
        result["backend"] = "provided_payload";
        result["capture_performed"] = false;
        result["deterministic_input"] = true;
        result["filter_pid"] = options.pid;
        result["filter_protocol"] = options.protocol == 0 ? "any" : (options.protocol == 17 ? "udp" : (options.protocol == 6 ? "tcp" : std::to_string(options.protocol)));
        result["payload_bytes"] = packets.front().payload.size();
        diag::log_tagged_fmt("gameproto", "detect provided_payload bytes=%zu protocol=%u pid=%u confidence=%.3f",
            packets.front().payload.size(), packets.front().protocol, packets.front().pid, result.value("confidence", 0.0));
        return tool_result_t::ok(OBFSTR("Game protocol detection completed from provided payload."), result);
    }
    if (options.pid == 0)
        return tool_result_t::error(OBFSTR("'pid' is required for live protocol detection."));

    std::vector<driver_bridge::captured_packet_t> packets;
    std::string error;
    if (!game_protocol::capture_packets_bounded(options, packets, error))
        return tool_result_t::error(error.empty() ? OBFSTR("capture failed") : error);

    json result = game_protocol::detect_protocols(packets, 32);
    result["backend"] = "driver_capture";
    result["capture_performed"] = true;
    result["capture_ms"] = options.capture_ms;
    result["pid"] = options.pid;
    result["filter_pid"] = options.pid;
    result["filter_protocol"] = options.protocol == 0 ? "any" : (options.protocol == 17 ? "udp" : (options.protocol == 6 ? "tcp" : std::to_string(options.protocol)));
    result["max_packets"] = options.max_packets;
    result["max_payload"] = options.max_payload;
    diag::log_tagged_fmt("gameproto", "detect live pid=%u protocol=%u packets=%zu confidence=%.3f",
        options.pid, options.protocol, packets.size(), result.value("confidence", 0.0));
    return tool_result_t::ok(OBFSTR("Game protocol detection completed."), result);
}

tool_result_t handle_gameproto_enet_decode(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    if (!params.contains("packet_hex") || !params["packet_hex"].is_string())
        return tool_result_t::error(OBFSTR("'packet_hex' is required."));
    std::string error;
    auto bytes = game_protocol::hex_to_bytes(params["packet_hex"].get<std::string>(), &error, 65536);
    if (bytes.empty() && !params["packet_hex"].get<std::string>().empty())
        return tool_result_t::error(error.empty() ? OBFSTR("invalid packet_hex") : error);

    std::optional<std::uint32_t> channel;
    if (params.contains("channel_id") && params["channel_id"].is_number()) {
        const auto v = params["channel_id"].get<std::int64_t>();
        if (v >= 0 && v <= 255)
            channel = static_cast<std::uint32_t>(v);
    }

    json result = game_protocol::decode_enet_packet(bytes, channel);
    return tool_result_t::ok(OBFSTR("ENet packet decoded with heuristic confidence."), result);
}

tool_result_t handle_gameproto_decode_heuristic(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    if (!params.contains("payload_hex") || !params["payload_hex"].is_string())
        return tool_result_t::error(OBFSTR("'payload_hex' is required."));

    std::string error;
    auto bytes = game_protocol::hex_to_bytes(params["payload_hex"].get<std::string>(), &error, 65536);
    if (bytes.empty() && !params["payload_hex"].get<std::string>().empty())
        return tool_result_t::error(error.empty() ? OBFSTR("invalid payload_hex") : error);

    const std::string hint = params.value("context_hint", std::string());
    json result = game_protocol::decode_payload_heuristic(bytes, hint);
    return tool_result_t::ok(OBFSTR("Payload heuristic decode completed."), result);
}

tool_result_t handle_gameproto_replay(const json& raw_params)
{
    const std::string operation = compat_action_name(raw_params);
    const json params = compat_action_payload(raw_params);
    const std::string op = operation.empty() ? params.value("operation", std::string()) : operation;

    if (op == "record") {
        auto options = capture_options_from_params(params, 5000, 128);
        if (options.protocol == 0)
            options.protocol = 17;
        std::string error;
        json result = game_protocol::record_replay_session(options, error);
        if (!error.empty())
            return tool_result_t::error(error);
        return tool_result_t::ok(OBFSTR("Game protocol replay session recorded."), result);
    }

    if (op == "stop") {
        std::string error;
        json result = game_protocol::stop_replay_recording(
            params.value("session_id", std::string()),
            params.value("max_packets", 128u),
            error);
        if (!error.empty())
            return tool_result_t::error(error);
        return tool_result_t::ok(OBFSTR("Game protocol replay recording stopped."), result);
    }

    if (op == "list") {
        json result = game_protocol::list_replay_sessions();
        result["operation"] = "list";
        result["requires_recorded_session"] = true;
        result["record_operation"] = "gameproto_replay operation=record";
        result["replay_requires_existing_session"] = true;
        diag::log_tagged_fmt("gameproto", "replay list sessions=%u", result.value("count", 0u));
        return tool_result_t::ok(OBFSTR("Game protocol replay sessions listed."), result);
    }

    if (op == "replay") {
        game_protocol::replay_options_t options;
        options.session_id = params.value("session_id", std::string());
        options.target_ip = params.value("target_ip", std::string());
        options.target_port = params.value("target_port", 0u);
        options.source_port = params.value("source_port", 0u);
        options.direction = params.value("direction", std::string("outbound"));
        options.max_packets = params.value("max_packets", 32u);
        options.payload_cap = params.value("payload_cap", params.value("max_payload", 1024u));
        options.replay_delay_ms = params.value("replay_delay_ms", 0u);
        options.allow_non_loopback = params.value("allow_non_loopback", false);
        options.allow_unsafe = params.value("allow_unsafe", false);
        options.confirm_unsafe = params.value("confirm_unsafe", false);

        json result;
        std::string error;
        if (!game_protocol::replay_session(options, result, error))
            return tool_result_t::error(error.empty() ? OBFSTR("replay failed") : error);
        return tool_result_t::ok(OBFSTR("Game protocol replay attempted with bounded packet caps."), result);
    }

    return compat_unknown_action("gameproto_replay", op);
}

}

void register_gameproto_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged("gameproto", "register_gameproto_tools entry");

    register_compat(srv, {
        OBFSTR("gameproto_detect"), OBFSTR("gameproto"),
        OBFSTR("Capture a bounded live traffic sample for a PID and return protocol confidence and packet evidence for ENet, Photon, RakNet, protobuf, gzip, and custom binary formats."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Target process ID."), true},
         {OBFSTR("capture_sec"), OBFSTR("number"), OBFSTR("Capture duration in seconds, default 5, max 15."), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Maximum packets to inspect, default 64, max 512."), false},
         {OBFSTR("protocol"), OBFSTR("string"), OBFSTR("Optional tcp or udp capture filter."), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("Optional payload for deterministic local protocol detection without live capture."), false},
         {OBFSTR("packet_hex"), OBFSTR("string"), OBFSTR("Alias for payload_hex."), false}},
        handle_gameproto_detect, false});

    register_compat(srv, {
        OBFSTR("gameproto_enet_decode"), OBFSTR("gameproto"),
        OBFSTR("Decode ENet packet bytes into header and command components with channel, sequence, length, payload preview, confidence, and parse-stop evidence."),
        {{OBFSTR("packet_hex"), OBFSTR("string"), OBFSTR("Hex-encoded ENet packet bytes."), true},
         {OBFSTR("channel_id"), OBFSTR("number"), OBFSTR("Optional channel filter."), false}},
        handle_gameproto_enet_decode, true});

    register_compat(srv, {
        OBFSTR("gameproto_decode_heuristic"), OBFSTR("gameproto"),
        OBFSTR("Heuristically classify fields in an unknown binary protocol payload using entropy, strings, length prefixes, protobuf wire format, numeric values, and repeated records."),
        {{OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("Hex-encoded payload bytes."), true},
         {OBFSTR("context_hint"), OBFSTR("string"), OBFSTR("Optional hint such as entity_update, position, or damage."), false}},
        handle_gameproto_decode_heuristic, true});

    register_compat(srv, {
        OBFSTR("gameproto_replay"), OBFSTR("gameproto"),
        OBFSTR("Record, stop, list, or replay bounded captured packets. Replay requires allow_unsafe and confirm_unsafe, payload caps, packet caps, and loopback-safe targeting by default."),
        {{OBFSTR("operation"), OBFSTR("string"), OBFSTR("record|stop|replay|list"), true},
         {OBFSTR("payload"), OBFSTR("object"), OBFSTR("Operation-specific parameters; top-level fields are also accepted."), false},
         {OBFSTR("session_id"), OBFSTR("string"), OBFSTR("Replay session ID for stop or replay."), false},
         {OBFSTR("filter_pid"), OBFSTR("number"), OBFSTR("PID filter for record."), false},
         {OBFSTR("target_ip"), OBFSTR("string"), OBFSTR("IPv4 replay target. Non-loopback requires allow_non_loopback."), false},
         {OBFSTR("target_port"), OBFSTR("number"), OBFSTR("Replay target port."), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Replay or capture packet cap."), false},
         {OBFSTR("payload_cap"), OBFSTR("number"), OBFSTR("Maximum replay payload bytes, hard-capped at 4096."), false},
         {OBFSTR("allow_unsafe"), OBFSTR("boolean"), OBFSTR("Required true for replay."), false},
         {OBFSTR("confirm_unsafe"), OBFSTR("boolean"), OBFSTR("Required true for replay."), false}},
        handle_gameproto_replay, false});
}

}
