#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "net_proto_analysis.hpp"
#include "obfuscation.hpp"
#include "helpers/diag_log.hpp"

#include <cstdint>
#include <optional>
#include <string>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace net_proto_tools {
namespace {

std::uint32_t process_id_from_params(const json& params)
{
    if (params.contains("process_id") && params["process_id"].is_number()) {
        const auto v = params["process_id"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            return static_cast<std::uint32_t>(v);
    }
    if (params.contains("pid") && params["pid"].is_number()) {
        const auto v = params["pid"].get<std::int64_t>();
        if (v > 0 && v <= 0xffffffffLL)
            return static_cast<std::uint32_t>(v);
    }
    return 0;
}

tool_result_t handle_find_sendrecv(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    net_proto_analysis::sendrecv_scan_options_t options;
    options.process_id = process_id_from_params(params);
    options.max_results = params.value("max_results", 64u);
    options.max_modules = params.value("max_modules", 32u);
    options.max_scan_bytes = params.value("max_scan_bytes", static_cast<std::uint64_t>(67108864));

    json result;
    std::string error;
    if (!net_proto_analysis::find_sendrecv_handlers(options, result, error))
        return tool_result_t::error(error.empty() ? OBFSTR("send/recv scan failed") : error);
    return tool_result_t::ok(OBFSTR("Socket send/recv callsite scan completed."), result);
}

tool_result_t handle_trace_serializer(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    if (!params.contains("serializer_va") && !params.contains("address"))
        return tool_result_t::error(OBFSTR("'serializer_va' is required."));

    std::optional<std::uint64_t> va;
    if (params.contains("serializer_va") && params["serializer_va"].is_string())
        va = sa_parse_address(params["serializer_va"].get<std::string>());
    else if (params.contains("address") && params["address"].is_string())
        va = sa_parse_address(params["address"].get<std::string>());
    else if (params.contains("serializer_va") && params["serializer_va"].is_number_unsigned())
        va = params["serializer_va"].get<std::uint64_t>();
    else if (params.contains("address") && params["address"].is_number_unsigned())
        va = params["address"].get<std::uint64_t>();
    else if (params.contains("serializer_va") && params["serializer_va"].is_number_integer()) {
        const auto v = params["serializer_va"].get<std::int64_t>();
        if (v > 0)
            va = static_cast<std::uint64_t>(v);
    } else if (params.contains("address") && params["address"].is_number_integer()) {
        const auto v = params["address"].get<std::int64_t>();
        if (v > 0)
            va = static_cast<std::uint64_t>(v);
    }
    if (!va)
        return tool_result_t::error(OBFSTR("Invalid serializer_va."));

    net_proto_analysis::serializer_trace_options_t options;
    options.process_id = process_id_from_params(params);
    options.serializer_va = *va;
    options.buffer_reg = params.value("buffer_reg", std::string("rdx"));
    options.size_reg = params.value("size_reg", std::string("r8"));
    options.tid = params.value("tid", 0u);
    options.max_captures = params.value("max_captures", 16u);
    options.sample_ms = params.value("sample_ms", params.value("capture_ms", 2000u));

    json result;
    std::string error;
    if (!net_proto_analysis::trace_serializer(options, result, error))
        return tool_result_t::error(error.empty() ? OBFSTR("serializer trace failed") : error);
    result["serializer_va_normalized"] = sa_format_address(*va);
    return tool_result_t::ok(OBFSTR("Serializer sampling completed with bounded captures."), result);
}

tool_result_t handle_udp_reassemble(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    net_proto_analysis::udp_reassemble_options_t options;
    options.pid = process_id_from_params(params);
    double capture_sec = params.value("capture_sec", 10.0);
    if (capture_sec < 0.1)
        capture_sec = 0.1;
    if (capture_sec > 15.0)
        capture_sec = 15.0;
    options.capture_ms = static_cast<std::uint32_t>(capture_sec * 1000.0);
    options.max_packets = params.value("max_packets", 256u);
    options.max_payload = params.value("max_payload", 1500u);

    json result;
    std::string error;
    if (!net_proto_analysis::reassemble_udp_sessions(options, result, error))
        return tool_result_t::error(error.empty() ? OBFSTR("UDP reassembly failed") : error);
    return tool_result_t::ok(OBFSTR("UDP logical sessions reassembled with heuristic evidence."), result);
}

tool_result_t handle_replay_mutate(const json& raw_params)
{
    const std::string action = compat_action_name(raw_params);
    if (!action.empty() && action != "mutate" && action != "replay")
        return compat_unknown_action("net_replay_mutate", action);
    const json params = compat_action_payload(raw_params);

    net_proto_analysis::replay_mutate_options_t options;
    options.session_id = params.value("session_id", std::string());
    options.target_ip = params.value("target_ip", std::string());
    options.target_port = params.value("target_port", 0u);
    options.source_port = params.value("source_port", 0u);
    options.mutation_strategy = params.value("mutation_strategy", std::string("boundary"));
    options.max_mutations = params.value("max_mutations", 64u);
    options.payload_cap = params.value("payload_cap", params.value("max_payload", 1024u));
    options.response_wait_ms = params.value("response_wait_ms", 500u);
    options.allow_non_loopback = params.value("allow_non_loopback", false);
    options.allow_unsafe = params.value("allow_unsafe", false);
    options.confirm_unsafe = params.value("confirm_unsafe", false);

    json result;
    std::string error;
    if (!net_proto_analysis::replay_mutate(options, result, error))
        return tool_result_t::error(error.empty() ? OBFSTR("mutation replay failed") : error);
    return tool_result_t::ok(OBFSTR("Mutation replay attempted with bounded unsafe caps."), result);
}

}

void register_net_proto_tools(mcp_standalone::server_t& srv)
{
    diag::log_tagged("net_proto", "register_net_proto_tools entry");

    register_compat(srv, {
        OBFSTR("net_proto_find_sendrecv"), OBFSTR("net_proto"),
        OBFSTR("Locate probable send/recv handlers by scanning application modules for direct and IAT-indirect calls into Winsock APIs, returning confidence and serializer/deserializer evidence."),
        {{OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Target process ID. Defaults to attached process."), false},
         {OBFSTR("max_results"), OBFSTR("number"), OBFSTR("Maximum findings, default 64, max 128."), false},
         {OBFSTR("max_modules"), OBFSTR("number"), OBFSTR("Maximum non-system modules to scan."), false},
         {OBFSTR("max_scan_bytes"), OBFSTR("number"), OBFSTR("Global byte scan cap."), false}},
        handle_find_sendrecv, true});

    register_compat(srv, {
        OBFSTR("net_proto_trace_serializer"), OBFSTR("net_proto"),
        OBFSTR("Sample a serializer function through bounded pre-encryption hooks or network-buffer sniffing and infer output fields from captured bytes and variance evidence."),
        {{OBFSTR("serializer_va"), OBFSTR("string"), OBFSTR("Serializer function VA."), true},
         {OBFSTR("buffer_reg"), OBFSTR("string"), OBFSTR("Buffer pointer register, default rdx."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Target process ID. Defaults to attached process."), false},
         {OBFSTR("size_reg"), OBFSTR("string"), OBFSTR("Size register, default r8."), false},
         {OBFSTR("tid"), OBFSTR("number"), OBFSTR("Optional thread ID filter for driver sniff fallback."), false},
         {OBFSTR("sample_ms"), OBFSTR("number"), OBFSTR("Bounded sampling window, default 2000, max 10000."), false},
         {OBFSTR("max_captures"), OBFSTR("number"), OBFSTR("Capture cap, default 16, max 32."), false}},
        handle_trace_serializer, false});

    register_compat(srv, {
        OBFSTR("net_udp_session_reassemble"), OBFSTR("net_proto"),
        OBFSTR("Capture bounded UDP traffic and group datagrams into logical sessions with sequence, length-prefix, and ENet-like evidence for later analysis or guarded mutation."),
        {{OBFSTR("pid"), OBFSTR("number"), OBFSTR("Optional PID filter."), false},
         {OBFSTR("capture_sec"), OBFSTR("number"), OBFSTR("Capture duration in seconds, default 10, max 15."), false},
         {OBFSTR("max_packets"), OBFSTR("number"), OBFSTR("Packet cap, default 256, max 512."), false},
         {OBFSTR("max_payload"), OBFSTR("number"), OBFSTR("Payload capture cap, default 1500, max 4096."), false}},
        handle_udp_reassemble, false});

    register_compat(srv, {
        OBFSTR("net_replay_mutate"), OBFSTR("net_proto"),
        OBFSTR("Replay a stored UDP session with bounded numeric field mutations. Requires allow_unsafe and confirm_unsafe; loopback-only by default and hard-capped mutation/payload counts."),
        {{OBFSTR("session_id"), OBFSTR("string"), OBFSTR("Session ID returned by net_udp_session_reassemble."), true},
         {OBFSTR("target_ip"), OBFSTR("string"), OBFSTR("IPv4 mutation target. Non-loopback requires allow_non_loopback."), true},
         {OBFSTR("target_port"), OBFSTR("number"), OBFSTR("UDP target port."), true},
         {OBFSTR("mutation_strategy"), OBFSTR("string"), OBFSTR("boundary|random|bitflip, default boundary."), false},
         {OBFSTR("max_mutations"), OBFSTR("number"), OBFSTR("Mutation cap, default 64, max 256."), false},
         {OBFSTR("payload_cap"), OBFSTR("number"), OBFSTR("Payload cap, default 1024, max 4096."), false},
         {OBFSTR("allow_unsafe"), OBFSTR("boolean"), OBFSTR("Required true."), false},
         {OBFSTR("confirm_unsafe"), OBFSTR("boolean"), OBFSTR("Required true."), false},
         {OBFSTR("allow_non_loopback"), OBFSTR("boolean"), OBFSTR("Allow non-loopback target."), false}},
        handle_replay_mutate, false});
}

}
