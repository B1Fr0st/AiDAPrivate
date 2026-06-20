#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "standalone_compat.hpp"
#include "net_proto_analysis.hpp"
#include "game_protocol.hpp"
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

std::optional<std::uint64_t> u64_from_params(const json& params, const char* name)
{
    if (!name || !params.contains(name))
        return std::nullopt;
    const auto& v = params[name];
    if (v.is_string())
        return sa_parse_address(v.get<std::string>());
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>();
    if (v.is_number_integer()) {
        const auto n = v.get<std::int64_t>();
        if (n >= 0)
            return static_cast<std::uint64_t>(n);
    }
    return std::nullopt;
}

tool_result_t handle_find_sendrecv(const json& raw_params)
{
    const ULONGLONG started = GetTickCount64();
    const json params = compat_action_payload(raw_params);
    net_proto_analysis::sendrecv_scan_options_t options;
    options.process_id = process_id_from_params(params);
    options.max_results = params.value("max_results", 64u);
    options.max_modules = params.value("max_modules", 32u);
    options.max_scan_bytes = params.value("max_scan_bytes", static_cast<std::uint64_t>(67108864));
    options.timeout_ms = params.value("timeout_ms", 2500u);
    if (params.contains("module_name") && params["module_name"].is_string())
        options.module_name = params["module_name"].get<std::string>();
    else if (params.contains("module") && params["module"].is_string())
        options.module_name = params["module"].get<std::string>();
    else if (params.contains("module_filter") && params["module_filter"].is_string())
        options.module_name = params["module_filter"].get<std::string>();
    if (auto v = u64_from_params(params, "module_base"))
        options.module_base = *v;
    if (auto v = u64_from_params(params, "scan_base"))
        options.scan_base = *v;
    if (auto v = u64_from_params(params, "scan_size"))
        options.scan_size = *v;
    diag::log_tagged_fmt("net_proto",
        "net_proto_find_sendrecv_handler_begin process_id=%u max_results=%u max_modules=%u max_scan_bytes=%llu timeout_ms=%u module_name=%s module_base=0x%llX scan_base=0x%llX scan_size=0x%llX",
        options.process_id,
        options.max_results,
        options.max_modules,
        static_cast<unsigned long long>(options.max_scan_bytes),
        options.timeout_ms,
        options.module_name.empty() ? "<empty>" : options.module_name.c_str(),
        static_cast<unsigned long long>(options.module_base),
        static_cast<unsigned long long>(options.scan_base),
        static_cast<unsigned long long>(options.scan_size));

    json result;
    std::string error;
    if (!net_proto_analysis::find_sendrecv_handlers(options, result, error)) {
        const ULONGLONG elapsed = GetTickCount64() - started;
        if (result.is_object() && !result.contains("handler_elapsed_ms"))
            result["handler_elapsed_ms"] = elapsed;
        diag::log_tagged_fmt("net_proto",
            "net_proto_find_sendrecv_handler_done ok=0 process_id=%u elapsed_ms=%llu error=%s",
            options.process_id,
            static_cast<unsigned long long>(elapsed),
            error.c_str());
        return tool_result_t::error(error.empty() ? OBFSTR("send/recv scan failed") : error, result);
    }
    if (result.is_object() && !result.contains("handler_elapsed_ms"))
        result["handler_elapsed_ms"] = GetTickCount64() - started;
    diag::log_tagged_fmt("net_proto",
        "net_proto_find_sendrecv_handler_done ok=1 process_id=%u elapsed_ms=%llu result_count=%u deadline_hit=%d stage=%s",
        options.process_id,
        static_cast<unsigned long long>(GetTickCount64() - started),
        result.value("result_count", 0u),
        result.value("deadline_hit", false) ? 1 : 0,
        result.value("stage", std::string()).c_str());
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
        return tool_result_t::error(error.empty() ? OBFSTR("serializer trace failed") : error, result);
    result["serializer_va_normalized"] = sa_format_address(*va);
    if (result.value("capture_count", 0u) == 0)
        return tool_result_t::error(OBFSTR("Serializer trace completed with zero captured serializer outputs."), result);
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
    if (params.contains("payload_hex") && params["payload_hex"].is_string()) {
        std::string error;
        auto bytes = game_protocol::hex_to_bytes(params["payload_hex"].get<std::string>(), &error, options.max_payload);
        if (bytes.empty() && !params["payload_hex"].get<std::string>().empty())
            return tool_result_t::error(error.empty() ? OBFSTR("invalid payload_hex") : error);
        options.fixture_payloads.push_back(std::move(bytes));
    }
    if (params.contains("payloads_hex") && params["payloads_hex"].is_array()) {
        for (const auto& item : params["payloads_hex"]) {
            if (!item.is_string())
                continue;
            std::string error;
            auto bytes = game_protocol::hex_to_bytes(item.get<std::string>(), &error, options.max_payload);
            if (bytes.empty() && !item.get<std::string>().empty())
                return tool_result_t::error(error.empty() ? OBFSTR("invalid payloads_hex entry") : error);
            options.fixture_payloads.push_back(std::move(bytes));
        }
    }

    json result;
    std::string error;
    if (!net_proto_analysis::reassemble_udp_sessions(options, result, error))
        return tool_result_t::error(error.empty() ? OBFSTR("UDP reassembly failed") : error);
    return tool_result_t::ok(OBFSTR("UDP logical sessions reassembled with heuristic evidence."), result);
}

tool_result_t handle_replay_mutate(const json& raw_params)
{
    const std::string action = compat_action_name(raw_params);
    if (!action.empty() && action != "mutate" && action != "replay") {
        return tool_result_t::error("net_replay_mutate unknown action: " + action,
            json{{"tool", "net_replay_mutate"},
                 {"action", action},
                 {"validation_code", "unknown_action"},
                 {"allowed_actions", json::array({"mutate", "replay"})}});
    }
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
        return tool_result_t::error(error.empty() ? OBFSTR("mutation replay failed") : error, result);
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
         {OBFSTR("max_scan_bytes"), OBFSTR("number"), OBFSTR("Global byte scan cap."), false},
         {OBFSTR("timeout_ms"), OBFSTR("number"), OBFSTR("Internal scan deadline in milliseconds, default 2500."), false},
         {OBFSTR("module_name"), OBFSTR("string"), OBFSTR("Optional deterministic module name/path filter."), false},
         {OBFSTR("module_base"), OBFSTR("string"), OBFSTR("Optional deterministic module base filter."), false},
         {OBFSTR("scan_base"), OBFSTR("string"), OBFSTR("Optional scan start VA constrained to the selected module."), false},
         {OBFSTR("scan_size"), OBFSTR("number"), OBFSTR("Optional scan byte length constrained to the selected module."), false}},
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
         {OBFSTR("max_payload"), OBFSTR("number"), OBFSTR("Payload capture cap, default 1500, max 4096."), false},
         {OBFSTR("payload_hex"), OBFSTR("string"), OBFSTR("Optional single UDP payload for deterministic local reassembly analysis."), false},
         {OBFSTR("payloads_hex"), OBFSTR("array"), OBFSTR("Optional UDP payload list for deterministic local reassembly analysis."), false}},
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
