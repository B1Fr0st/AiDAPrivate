#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "standalone_compat.hpp"
#include "net_proto_analysis.hpp"
#include "game_protocol.hpp"
#include "obfuscation.hpp"
#include "helpers/diag_log.hpp"
#include "executor_status.hpp"
#include "../runtime/standalone_driver.hpp"

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace net_proto_tools {
namespace {

int current_wsa_last_error()
{
    HMODULE ws2 = GetModuleHandleW(L"Ws2_32.dll");
    if (!ws2)
        return 0;
    using wsa_get_last_error_fn = int(__stdcall*)();
    auto fn = reinterpret_cast<wsa_get_last_error_fn>(GetProcAddress(ws2, "WSAGetLastError"));
    return fn ? fn() : 0;
}

bool process_alive_for_net_proto(std::uint32_t pid)
{
    if (pid == 0)
        return false;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!h)
        return false;
    const DWORD wait = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return wait == WAIT_TIMEOUT;
}

json net_proto_runtime_status(std::uint32_t pid, const char* operation)
{
    json j;
    DWORD handle_count = 0;
    const bool handle_count_ok = GetProcessHandleCount(GetCurrentProcess(), &handle_count) != FALSE;
    const std::vector<std::uint32_t> attached = driver_bridge::attached_pids();
    j["operation"] = operation ? operation : "";
    j["target_pid"] = pid;
    j["target_pid_alive"] = process_alive_for_net_proto(pid);
    j["driver_loaded"] = driver_bridge::is_loaded();
    j["driver_status"] = driver_bridge::status();
    j["driver_last_error"] = driver_bridge::last_error();
    j["driver_attached_pid"] = driver_bridge::attached_pid();
    j["driver_attached_pids"] = attached;
    j["driver_attached_pid_count"] = static_cast<std::uint64_t>(attached.size());
    j["gle"] = static_cast<std::uint32_t>(GetLastError());
    j["wsa_error"] = current_wsa_last_error();
    j["handle_count_ok"] = handle_count_ok;
    j["process_handle_count"] = handle_count_ok ? static_cast<std::uint32_t>(handle_count) : 0u;
    aida::network::executor_status::attach_executor_snapshots(j);
    return j;
}

std::string first_string_field(const json& j, const char* key)
{
    if (j.is_object() && key && j.contains(key) && j[key].is_string())
        return j[key].get<std::string>();
    return {};
}

json udp_reassemble_result_summary(const json& result,
                                   double capture_sec_requested,
                                   double capture_sec_effective,
                                   const std::string& clamp_reason)
{
    json summary;
    summary["backend"] = result.value("backend", std::string());
    summary["capture_performed"] = result.value("capture_performed", false);
    summary["deterministic_input"] = result.value("deterministic_input", false);
    summary["packet_count"] = result.value("packet_count", 0u);
    summary["session_count"] = result.value("session_count", 0u);
    summary["fragment_group_count"] = result.value("fragment_group_count", 0u);
    summary["reassembled_group_count"] = result.value("reassembled_group_count", 0u);
    summary["incomplete_fragment_group_count"] = result.value("incomplete_fragment_group_count", 0u);
    summary["capture_sec_requested"] = capture_sec_requested;
    summary["capture_sec_effective"] = capture_sec_effective;
    summary["capture_clamp_applied"] = clamp_reason != "none";
    summary["capture_clamp_reason"] = clamp_reason;
    summary["stimulus_observed"] = result.value("stimulus_observed", false);
    summary["zero_capture_due_to_no_stimulus"] = result.value("zero_capture_due_to_no_stimulus", false);
    summary["zero_packet_reason"] = result.value("packet_count", 0u) == 0
        ? (result.value("capture_performed", false) ? std::string("driver_capture_returned_zero_packets") : std::string("provided_payload_empty"))
        : std::string();
    if (result.contains("sessions") && result["sessions"].is_array() && !result["sessions"].empty() && result["sessions"][0].is_object())
    {
        const json& s = result["sessions"][0];
        summary["first_session_id"] = first_string_field(s, "session_id");
        summary["first_session_key"] = first_string_field(s, "key");
        summary["first_session_message_count"] = s.value("message_count", 0u);
        summary["first_session_confidence"] = s.value("confidence", 0.0);
        if (s.contains("evidence"))
            summary["first_session_evidence"] = s["evidence"];
        if (s.contains("messages") && s["messages"].is_array() && !s["messages"].empty() && s["messages"][0].is_object())
        {
            const json& m = s["messages"][0];
            summary["first_message_payload_size"] = m.value("payload_size", 0u);
            summary["first_message_scheme"] = first_string_field(m, "scheme");
            summary["first_message_src"] = first_string_field(m, "src");
            summary["first_message_dst"] = first_string_field(m, "dst");
            summary["first_message_payload_hex_preview"] = first_string_field(m, "payload_hex");
            summary["first_message_reassembled"] = m.value("reassembled", false);
            summary["first_message_reassembly_complete"] = m.value("reassembly_complete", false);
        }
    }
    return summary;
}

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

json net_proto_va_contract(const json& params, const std::vector<const char*>& names)
{
    json out;
    out["present"] = false;
    out["field"] = nullptr;
    out["value"] = nullptr;
    out["normalized"] = nullptr;
    for (const char* name : names) {
        if (!name || !params.contains(name))
            continue;
        out["present"] = true;
        out["field"] = name;
        out["value"] = params[name];
        if (auto v = u64_from_params(params, name))
            out["normalized"] = sa_format_address(*v);
        return out;
    }
    return out;
}

void attach_serializer_trace_contract(json& result,
                                      const json& params,
                                      const net_proto_analysis::serializer_trace_options_t& options,
                                      const std::string& error)
{
    if (!result.is_object())
        result = json::object();
    const bool has_capture_count = result.contains("capture_count");
    json c;
    c["operation"] = "net_proto_trace_serializer";
    c["process_id"] = options.process_id;
    c["serializer_va_normalized"] = sa_format_address(options.serializer_va);
    c["descriptor_va"] = net_proto_va_contract(params, {"descriptor_va", "descriptor", "protocol_descriptor_va"});
    c["emitter_va"] = net_proto_va_contract(params, {"emitter_va", "emit_fn_va", "deterministic_emit_fn_va", "replay_emitter_va"});
    c["serializer_va"] = net_proto_va_contract(params, {"serializer_va", "serializer_fn_va", "address"});
    c["buffer_reg"] = options.buffer_reg;
    c["size_reg"] = options.size_reg;
    c["tid"] = options.tid;
    c["sample_ms"] = options.sample_ms;
    c["max_captures"] = options.max_captures;
    const std::uint64_t capture_count = has_capture_count ? result.value("capture_count", 0u) : 0;
    c["capture_count"] = has_capture_count ? json(capture_count) : json(nullptr);
    c["observed_capture_count"] = has_capture_count ? json(capture_count) : json(nullptr);
    c["serializer_output_count_known"] = has_capture_count;
    c["serializer_output_count"] = has_capture_count ? json(capture_count) : json(nullptr);
    c["serializer_invocation_count_known"] = result.contains("serializer_invocation_count") || result.contains("invocation_count");
    c["serializer_invocation_count"] = result.contains("serializer_invocation_count") ? result["serializer_invocation_count"] : (result.contains("invocation_count") ? result["invocation_count"] : json(nullptr));
    c["dropped_count_known"] = result.contains("dropped_count") || result.contains("dropped_capture_count");
    c["dropped_count"] = result.contains("dropped_count") ? result["dropped_count"] : (result.contains("dropped_capture_count") ? result["dropped_capture_count"] : json(nullptr));
    c["last_error"] = !error.empty() ? json(error) : (result.contains("last_error") ? result["last_error"] : (result.contains("error") ? result["error"] : json(nullptr)));
    c["trace_done"] = true;
    c["done"] = json(nullptr);
    c["posted"] = json(nullptr);
    c["attempts"] = json(nullptr);
    c["packets_sent"] = json(nullptr);
    c["stimulus_observed"] = capture_count > 0 || result.value("stimulus_observed", false);
    c["stimulus_source"] = capture_count > 0 ? "serializer_trace_capture" : "unproven";
    c["re_emit_attempted"] = false;
    result["serializer_trace_contract"] = c;
    result["protocol_re_emit_stimulus"] = c;
    diag::log_tagged_fmt("net_proto",
        "serializer_trace_contract process_id=%u serializer_va=0x%llX capture_known=%d capture_count=%llu re_emit_attempted=0 invocation_known=%d dropped_known=%d last_error_present=%d",
        options.process_id,
        static_cast<unsigned long long>(options.serializer_va),
        has_capture_count ? 1 : 0,
        static_cast<unsigned long long>(capture_count),
        c.value("serializer_invocation_count_known", false) ? 1 : 0,
        c.value("dropped_count_known", false) ? 1 : 0,
        c["last_error"].is_null() ? 0 : 1);
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

    diag::log_tagged_fmt("net_proto",
        "net_proto_trace_serializer handler_begin pid=%u serializer_va=0x%llX buffer_reg=%s size_reg=%s sample_ms=%u max_captures=%u tid=%u driver_loaded=%d driver_connected=%d",
        options.process_id,
        static_cast<unsigned long long>(options.serializer_va),
        options.buffer_reg.c_str(),
        options.size_reg.c_str(),
        options.sample_ms,
        options.max_captures,
        options.tid,
        driver_bridge::is_loaded() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0);

    json result;
    std::string error;
    if (!net_proto_analysis::trace_serializer(options, result, error)) {
        if (!result.is_object())
            result = json::object();
        diag::log_tagged_fmt("net_proto",
            "net_proto_trace_serializer handler_fail pid=%u serializer_va=0x%llX sample_ms=%u capture_count=%u driver_sniff_started=%d driver_connected=%d error=%s",
            options.process_id,
            static_cast<unsigned long long>(options.serializer_va),
            options.sample_ms,
            result.value("capture_count", 0u),
            result.value("driver_sniff_started", false) ? 1 : 0,
            driver_bridge::using_kernel_driver() ? 1 : 0,
            error.c_str());
        result["serializer_va_normalized"] = sa_format_address(*va);
        result["trace_runtime_status"] = net_proto_runtime_status(options.process_id, "net_proto_trace_serializer");
        attach_serializer_trace_contract(result, params, options, error);
        result["diagnostic_contract"] = "zero_capture_without_stimulus_is_not_functional_capture_evidence";
        return tool_result_t::error(error.empty() ? OBFSTR("serializer trace failed") : error, result);
    }
    diag::log_tagged_fmt("net_proto",
        "net_proto_trace_serializer handler_done pid=%u serializer_va=0x%llX sample_ms=%u capture_count=%u driver_sniff_started=%d backend=%s zero_capture=%d",
        options.process_id,
        static_cast<unsigned long long>(options.serializer_va),
        options.sample_ms,
        result.value("capture_count", 0u),
        result.value("driver_sniff_started", false) ? 1 : 0,
        result.value("backend", std::string()).c_str(),
        result.value("capture_count", 0u) == 0 ? 1 : 0);
    result["serializer_va_normalized"] = sa_format_address(*va);
    result["trace_runtime_status"] = net_proto_runtime_status(options.process_id, "net_proto_trace_serializer");
    attach_serializer_trace_contract(result, params, options, error);
    result["zero_capture_due_to_no_stimulus"] = result.value("capture_count", 0u) == 0 && result.value("stimulus_observed", false) == false;
    result["diagnostic_contract"] = "zero_capture_without_stimulus_is_not_functional_capture_evidence";
    if (result.value("capture_count", 0u) == 0)
        return tool_result_t::error(OBFSTR("Serializer trace completed with zero captured serializer outputs."), result);
    return tool_result_t::ok(OBFSTR("Serializer sampling completed with bounded captures."), result);
}

tool_result_t handle_udp_reassemble(const json& raw_params)
{
    const json params = compat_action_payload(raw_params);
    net_proto_analysis::udp_reassemble_options_t options;
    options.pid = process_id_from_params(params);
    const double capture_sec_requested = params.value("capture_sec", 10.0);
    double capture_sec = capture_sec_requested;
    std::string capture_clamp_reason = "none";
    if (capture_sec < 0.1) {
        capture_sec = 0.1;
        capture_clamp_reason = "below_min_0.1s";
    }
    if (capture_sec > 15.0) {
        capture_sec = 15.0;
        capture_clamp_reason = "above_max_15s";
    }
    options.capture_ms = static_cast<std::uint32_t>(capture_sec * 1000.0);
    const std::uint32_t max_packets_requested = params.value("max_packets", 256u);
    const std::uint32_t max_payload_requested = params.value("max_payload", 1500u);
    options.max_packets = max_packets_requested;
    options.max_payload = max_payload_requested;
    if (params.contains("payload_hex") && params["payload_hex"].is_string()) {
        const std::string hex = params["payload_hex"].get<std::string>();
        if (hex.empty()) {
            json result;
            result["backend"] = "provided_payload";
            result["capture_performed"] = false;
            result["deterministic_input"] = false;
            result["packet_count"] = 0;
            result["session_count"] = 0;
            result["payload_bytes"] = 0;
            result["stimulus_observed"] = false;
            result["no_stimulus"] = true;
            result["diagnostic_contract"] = "empty_provided_payload_is_not_functional_udp_reassembly_evidence";
            return tool_result_t::error(OBFSTR("payload_hex must contain at least one byte."), result);
        }
        std::string error;
        auto bytes = game_protocol::hex_to_bytes(hex, &error, options.max_payload);
        if (bytes.empty())
            return tool_result_t::error(error.empty() ? OBFSTR("invalid payload_hex") : error);
        options.fixture_payloads.push_back(std::move(bytes));
    }
    if (params.contains("payloads_hex") && params["payloads_hex"].is_array()) {
        for (const auto& item : params["payloads_hex"]) {
            if (!item.is_string())
                continue;
            const std::string hex = item.get<std::string>();
            if (hex.empty()) {
                json result;
                result["backend"] = "provided_payload";
                result["capture_performed"] = false;
                result["deterministic_input"] = false;
                result["packet_count"] = 0;
                result["session_count"] = 0;
                result["payload_bytes"] = 0;
                result["stimulus_observed"] = false;
                result["no_stimulus"] = true;
                result["diagnostic_contract"] = "empty_provided_payload_is_not_functional_udp_reassembly_evidence";
                return tool_result_t::error(OBFSTR("payloads_hex entries must contain at least one byte."), result);
            }
            std::string error;
            auto bytes = game_protocol::hex_to_bytes(hex, &error, options.max_payload);
            if (bytes.empty())
                return tool_result_t::error(error.empty() ? OBFSTR("invalid payloads_hex entry") : error);
            options.fixture_payloads.push_back(std::move(bytes));
        }
    }

    const bool has_fixture_payloads = !options.fixture_payloads.empty();
    diag::log_tagged_fmt("net_proto",
        "net_udp_session_reassemble handler_begin pid=%u fixture_payloads=%zu capture_ms=%u max_packets=%u max_payload=%u backend=%s driver_loaded=%d driver_connected=%d",
        options.pid,
        options.fixture_payloads.size(),
        options.capture_ms,
        options.max_packets,
        options.max_payload,
        has_fixture_payloads ? "provided_payload" : "driver_capture",
        driver_bridge::is_loaded() ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0);

    json result;
    std::string error;
    if (!net_proto_analysis::reassemble_udp_sessions(options, result, error)) {
        if (!result.is_object())
            result = json::object();
        result["capture_sec_requested"] = capture_sec_requested;
        result["capture_sec_effective"] = capture_sec;
        result["capture_clamp_applied"] = capture_clamp_reason != "none";
        result["capture_clamp_reason"] = capture_clamp_reason;
        result["max_packets_requested"] = max_packets_requested;
        result["max_payload_requested"] = max_payload_requested;
        result["selected_local_port"] = params.value("local_port", params.value("source_port", 0u));
        result["selected_remote_port"] = params.value("remote_port", params.value("target_port", 0u));
        const std::uint64_t packet_count = result.value("packet_count", 0u);
        const bool capture_performed = result.value("capture_performed", false);
        const bool deterministic_input = result.value("deterministic_input", false);
        const bool stimulus_observed = packet_count > 0 && (capture_performed || deterministic_input || result.value("stimulus_observed", false));
        result["stimulus_observed"] = stimulus_observed;
        result["stimulus_source"] = deterministic_input ? "provided_payload" : (capture_performed ? "driver_capture_packets" : "none");
        result["zero_capture_due_to_no_stimulus"] = packet_count == 0 && capture_performed && !stimulus_observed;
        result["no_stimulus"] = !stimulus_observed;
        result["runtime_status"] = net_proto_runtime_status(options.pid, "net_udp_session_reassemble");
        result["result_summary"] = udp_reassemble_result_summary(result, capture_sec_requested, capture_sec, capture_clamp_reason);
        diag::log_tagged_fmt("net_proto",
            "net_udp_stimulus_status operation=net_udp_session_reassemble ok=0 pid=%u target_pid_alive=%d driver_attached_pid=%u gle=%lu wsa=%d local_port=%u remote_port=%u work_pending=%llu work_active=%u critical_pending=%llu critical_active=%u capture_sec_requested=%.3f capture_sec_effective=%.3f clamp=%s max_packets_requested=%u max_payload_requested=%u packet_count=%u session_count=%u err=%s",
            options.pid,
            process_alive_for_net_proto(options.pid) ? 1 : 0,
            driver_bridge::attached_pid(),
            static_cast<unsigned long>(GetLastError()),
            current_wsa_last_error(),
            params.value("local_port", params.value("source_port", 0u)),
            params.value("remote_port", params.value("target_port", 0u)),
            static_cast<unsigned long long>(aida::network::executor_status::work_pending()),
            aida::network::executor_status::work_active(),
            static_cast<unsigned long long>(aida::network::executor_status::critical_pending()),
            aida::network::executor_status::critical_active(),
            capture_sec_requested,
            capture_sec,
            capture_clamp_reason.c_str(),
            max_packets_requested,
            max_payload_requested,
            result.value("packet_count", 0u),
            result.value("session_count", 0u),
            error.c_str());
        return tool_result_t::error(error.empty() ? OBFSTR("UDP reassembly failed") : error, result);
    }
    result["capture_sec_requested"] = capture_sec_requested;
    result["capture_sec_effective"] = capture_sec;
    result["capture_clamp_applied"] = capture_clamp_reason != "none";
    result["capture_clamp_reason"] = capture_clamp_reason;
    result["max_packets_requested"] = max_packets_requested;
    result["max_payload_requested"] = max_payload_requested;
    result["selected_local_port"] = params.value("local_port", params.value("source_port", 0u));
    result["selected_remote_port"] = params.value("remote_port", params.value("target_port", 0u));
    const std::uint64_t packet_count = result.value("packet_count", 0u);
    const std::uint64_t session_count = result.value("session_count", 0u);
    const bool capture_performed = result.value("capture_performed", false);
    const bool deterministic_input = result.value("deterministic_input", false);
    const bool stimulus_observed = packet_count > 0 && (capture_performed || deterministic_input || result.value("stimulus_observed", false));
    result["stimulus_observed"] = stimulus_observed;
    result["stimulus_source"] = deterministic_input ? "provided_payload" : (capture_performed ? "driver_capture_packets" : "none");
    result["zero_capture_due_to_no_stimulus"] = packet_count == 0 && capture_performed && !stimulus_observed;
    result["no_stimulus"] = !stimulus_observed;
    result["runtime_status"] = net_proto_runtime_status(options.pid, "net_udp_session_reassemble");
    result["result_summary"] = udp_reassemble_result_summary(result, capture_sec_requested, capture_sec, capture_clamp_reason);
    const std::string result_backend = result.value("backend", std::string());
    const std::string first_session_id = first_string_field(result["result_summary"], "first_session_id");
    diag::log_tagged_fmt("net_proto",
        "net_udp_stimulus_status operation=net_udp_session_reassemble ok=1 pid=%u target_pid_alive=%d driver_attached_pid=%u backend=%s gle=%lu wsa=%d local_port=%u remote_port=%u work_pending=%llu work_active=%u critical_pending=%llu critical_active=%u capture_sec_requested=%.3f capture_sec_effective=%.3f clamp=%s max_packets_requested=%u max_packets_effective=%u max_payload_requested=%u max_payload_effective=%u packet_count=%u session_count=%u zero_due_to_no_stimulus=%d first_session=%s",
        options.pid,
        process_alive_for_net_proto(options.pid) ? 1 : 0,
        driver_bridge::attached_pid(),
        result_backend.c_str(),
        static_cast<unsigned long>(GetLastError()),
        current_wsa_last_error(),
        params.value("local_port", params.value("source_port", 0u)),
        params.value("remote_port", params.value("target_port", 0u)),
        static_cast<unsigned long long>(aida::network::executor_status::work_pending()),
        aida::network::executor_status::work_active(),
        static_cast<unsigned long long>(aida::network::executor_status::critical_pending()),
        aida::network::executor_status::critical_active(),
        capture_sec_requested,
        capture_sec,
        capture_clamp_reason.c_str(),
        max_packets_requested,
        result.value("max_packets", 0u),
        max_payload_requested,
        result.value("max_payload", 0u),
        result.value("packet_count", 0u),
        result.value("session_count", 0u),
        result.value("zero_capture_due_to_no_stimulus", false) ? 1 : 0,
        first_session_id.empty() ? "<none>" : first_session_id.c_str());
    if (packet_count == 0)
        return tool_result_t::error(OBFSTR("UDP reassembly completed with zero packets; no functional capture evidence was produced."), result);
    if (session_count == 0)
        return tool_result_t::error(OBFSTR("UDP reassembly completed with zero sessions; no functional protocol evidence was produced."), result);
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

    if (options.session_id.empty()) {
        diag::log_tagged_fmt("net_proto",
            "net_replay_mutate handler_reject session_id_empty allow_unsafe=%d confirm_unsafe=%d target_ip=%s target_port=%u",
            options.allow_unsafe ? 1 : 0,
            options.confirm_unsafe ? 1 : 0,
            options.target_ip.empty() ? "<empty>" : options.target_ip.c_str(),
            options.target_port);
        return tool_result_t::error(OBFSTR("session_id is required."),
            json{{"tool", "net_replay_mutate"},
                 {"validation_code", "session_id_required"},
                 {"guard", "session_lookup"}});
    }
    diag::log_tagged_fmt("net_proto",
        "net_replay_mutate handler_begin session_id=%s target_ip=%s target_port=%u allow_unsafe=%d confirm_unsafe=%d driver_connected=%d",
        options.session_id.c_str(),
        options.target_ip.empty() ? "<empty>" : options.target_ip.c_str(),
        options.target_port,
        options.allow_unsafe ? 1 : 0,
        options.confirm_unsafe ? 1 : 0,
        driver_bridge::using_kernel_driver() ? 1 : 0);

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
        OBFSTR("Locate probable send/recv handlers by scanning application modules for direct, thunked, IAT-indirect, and register-loaded Winsock API calls, returning ranked serializer/deserializer evidence."),
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
        OBFSTR("Sample a serializer function through bounded register-derived hooks or network-buffer sniffing and infer output fields with explicit output-byte provenance."),
        {{OBFSTR("serializer_va"), OBFSTR("string"), OBFSTR("Serializer function VA."), true},
         {OBFSTR("buffer_reg"), OBFSTR("string"), OBFSTR("Buffer pointer register, default rdx."), true},
         {OBFSTR("process_id"), OBFSTR("number"), OBFSTR("Target process ID. Defaults to attached process."), false},
         {OBFSTR("size_reg"), OBFSTR("string"), OBFSTR("Size register, default r8."), false},
         {OBFSTR("tid"), OBFSTR("number"), OBFSTR("Optional thread ID filter for kernel driver buffer sniffing."), false},
         {OBFSTR("sample_ms"), OBFSTR("number"), OBFSTR("Bounded sampling window, default 2000, max 10000."), false},
         {OBFSTR("max_captures"), OBFSTR("number"), OBFSTR("Capture cap, default 16, max 32."), false}},
        handle_trace_serializer, false});

    register_compat(srv, {
        OBFSTR("net_udp_session_reassemble"), OBFSTR("net_proto"),
        OBFSTR("Capture bounded UDP traffic and group datagrams into logical sessions with endpoint fields, length-prefix framing, and multi-datagram fragment reassembly evidence for later analysis or guarded mutation."),
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
         {OBFSTR("source_port"), OBFSTR("number"), OBFSTR("Optional UDP source port. Defaults to the recorded session local port."), false},
         {OBFSTR("mutation_strategy"), OBFSTR("string"), OBFSTR("boundary|random|bitflip, default boundary."), false},
         {OBFSTR("max_mutations"), OBFSTR("number"), OBFSTR("Mutation cap, default 64, max 256."), false},
         {OBFSTR("payload_cap"), OBFSTR("number"), OBFSTR("Payload cap, default 1024, max 4096."), false},
         {OBFSTR("response_wait_ms"), OBFSTR("number"), OBFSTR("Bounded response capture wait, default 500, max 5000."), false},
         {OBFSTR("allow_unsafe"), OBFSTR("boolean"), OBFSTR("Required true."), false},
         {OBFSTR("confirm_unsafe"), OBFSTR("boolean"), OBFSTR("Required true."), false},
         {OBFSTR("allow_non_loopback"), OBFSTR("boolean"), OBFSTR("Allow non-loopback target."), false}},
        handle_replay_mutate, false});
}

}
