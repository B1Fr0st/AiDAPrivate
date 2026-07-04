#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "net_proto_analysis.hpp"

#include "game_protocol.hpp"
#include "standalone_driver.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace net_proto_analysis {
namespace {

struct api_target_t {
    std::string name;
    std::string direction;
    std::uint64_t address = 0;
};

enum class socket_module_kind_t {
    none,
    ws2_32,
    wsock32,
    mswsock
};

struct udp_message_t {
    std::uint64_t sequence = 0;
    std::uint64_t ack = 0;
    std::vector<std::uint8_t> payload;
    std::uint32_t local_port = 0;
    std::uint32_t remote_port = 0;
    std::uint32_t address_family = 2;
    std::uint8_t local_addr[16] = {};
    std::uint8_t remote_addr[16] = {};
    std::string src;
    std::string dst;
    std::string src_ip;
    std::string dst_ip;
    std::uint32_t src_port = 0;
    std::uint32_t dst_port = 0;
    std::string scheme;
    bool reassembled = false;
    bool reassembly_complete = true;
    std::uint32_t fragment_id = 0;
    std::uint32_t fragment_index = 0;
    std::uint32_t fragment_count = 0;
    std::uint32_t fragment_offset = 0;
    std::uint32_t logical_size = 0;
    nlohmann::json reassembly_evidence = nlohmann::json::array();
};

struct udp_session_t {
    std::string id;
    std::string key;
    std::uint64_t created_ms = 0;
    std::vector<udp_message_t> messages;
};

struct internal_call_t {
    std::uint64_t call_va = 0;
    std::uint64_t target_va = 0;
    std::size_t offset = 0;
    std::string relation;
};

struct callsite_context_t {
    std::uint64_t function_start = 0;
    std::uint64_t function_end = 0;
    std::uint64_t basic_block_start = 0;
    std::uint64_t basic_block_end = 0;
    std::uint64_t serializer_candidate = 0;
    std::uint64_t deserializer_candidate = 0;
    double candidate_confidence = 0.0;
    nlohmann::json upstream_calls = nlohmann::json::array();
    nlohmann::json downstream_calls = nlohmann::json::array();
    nlohmann::json evidence = nlohmann::json::array();
};

struct serializer_sample_t {
    std::vector<std::uint8_t> buffer;
    std::uint64_t timestamp = 0;
    std::uint64_t thread_id = 0;
    std::uint64_t rip = 0;
    std::string function_name;
    std::string backend;
    std::string module_name;
    std::uint64_t module_offset = 0;
};

struct udp_fragment_info_t {
    bool valid = false;
    std::size_t header_size = 0;
    std::uint64_t sequence = 0;
    std::uint64_t ack = 0;
    std::uint32_t fragment_id = 0;
    std::uint32_t fragment_index = 0;
    std::uint32_t fragment_count = 0;
    std::uint32_t fragment_offset = 0;
    std::uint32_t declared_payload_size = 0;
    std::uint32_t logical_size = 0;
    std::string scheme;
    double confidence = 0.0;
    nlohmann::json evidence = nlohmann::json::array();
};

struct udp_fragment_piece_t {
    udp_message_t message;
    udp_fragment_info_t fragment;
};

struct udp_fragment_group_t {
    std::string session_key;
    std::vector<udp_message_t> pieces;
};

struct scored_call_t {
    internal_call_t call;
    double score = 0.0;
    nlohmann::json evidence = nlohmann::json::array();
    nlohmann::json nested_calls = nlohmann::json::array();
};

struct numeric_field_candidate_t {
    std::size_t offset = 0;
    std::size_t size = 0;
    bool big_endian = false;
    std::uint64_t value = 0;
    std::string type;
    double confidence = 0.0;
    nlohmann::json evidence = nlohmann::json::array();
};

struct mutation_payload_t {
    std::vector<std::uint8_t> payload;
    nlohmann::json evidence;
    std::size_t source_message_index = 0;
    std::size_t field_offset = 0;
    std::size_t field_size = 0;
    bool big_endian = false;
    std::uint64_t original_value = 0;
    std::uint64_t mutated_value = 0;
    std::string strategy;
};

struct scan_deadline_t {
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point deadline;
    std::uint32_t timeout_ms = 0;
    bool hit = false;
    bool cancelled = false;
    std::string stage = "entry";

    explicit scan_deadline_t(std::uint32_t ms)
        : started(std::chrono::steady_clock::now()),
          deadline(started + std::chrono::milliseconds(ms)),
          timeout_ms(ms)
    {
    }

    bool expired(const char* next_stage)
    {
        stage = next_stage ? next_stage : stage;
        if (hit)
            return true;
        if (mcp_standalone::current_call_cancelled()) {
            hit = true;
            cancelled = true;
            diag::log_tagged_fmt("net_proto",
                "scan_deadline_cancelled stage=%s elapsed_ms=%llu timeout_ms=%u",
                stage.c_str(),
                static_cast<unsigned long long>(elapsed_ms()),
                timeout_ms);
            return true;
        }
        if (std::chrono::steady_clock::now() < deadline)
            return false;
        hit = true;
        diag::log_tagged_fmt("net_proto",
            "scan_deadline_timeout stage=%s elapsed_ms=%llu timeout_ms=%u",
            stage.c_str(),
            static_cast<unsigned long long>(elapsed_ms()),
            timeout_ms);
        return true;
    }

    std::uint64_t elapsed_ms() const
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    }

    std::uint64_t remaining_ms() const
    {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return 0;
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now).count());
    }
};

std::mutex& udp_mutex()
{
    static std::mutex m;
    return m;
}

std::map<std::string, udp_session_t>& udp_sessions()
{
    static std::map<std::string, udp_session_t> s;
    return s;
}

std::atomic<std::uint64_t>& session_counter()
{
    static std::atomic<std::uint64_t> c{1};
    return c;
}

std::string make_session_id(const char* prefix)
{
    std::ostringstream os;
    os << prefix << "_" << std::hex << std::uppercase
       << static_cast<std::uint64_t>(GetTickCount64()) << "_"
       << session_counter().fetch_add(1, std::memory_order_relaxed);
    return os.str();
}

nlohmann::json replay_mutate_error_data(const replay_mutate_options_t& input,
                                        const char* validation_code,
                                        const char* guard,
                                        const char* detail)
{
    nlohmann::json active_ids = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(udp_mutex());
        for (const auto& [id, session] : udp_sessions()) {
            (void)session;
            active_ids.push_back(id);
        }
    }
    const auto active_count = active_ids.size();
    const bool driver_connected = driver_bridge::using_kernel_driver();
    nlohmann::json out{
        {"tool", "net_replay_mutate"},
        {"action", "mutate"},
        {"validation_code", validation_code ? validation_code : "net_replay_mutate_failed"},
        {"guard", guard ? guard : ""},
        {"session_id", input.session_id},
        {"active_session_count", active_count},
        {"active_session_ids", active_ids},
        {"target_ip", input.target_ip},
        {"target_port", input.target_port},
        {"mutation_strategy", input.mutation_strategy},
        {"allowed_mutation_strategies", nlohmann::json::array({"boundary", "random", "bitflip"})},
        {"allow_unsafe", input.allow_unsafe},
        {"confirm_unsafe", input.confirm_unsafe},
        {"allow_non_loopback", input.allow_non_loopback},
        {"driver_connected", driver_connected}
    };
    if (detail && *detail)
        out["detail"] = detail;
    diag::log_tagged_fmt("net_proto",
        "replay_mutate_guard validation_code=%s guard=%s session_id='%s' active_count=%zu target_ip='%s' target_port=%u allow_unsafe=%d confirm_unsafe=%d allow_non_loopback=%d driver_connected=%d",
        validation_code ? validation_code : "",
        guard ? guard : "",
        input.session_id.c_str(),
        static_cast<std::size_t>(active_count),
        input.target_ip.c_str(),
        input.target_port,
        input.allow_unsafe ? 1 : 0,
        input.confirm_unsafe ? 1 : 0,
        input.allow_non_loopback ? 1 : 0,
        driver_connected ? 1 : 0);
    return out;
}

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

void increment_json_counter(nlohmann::json& object, const std::string& key)
{
    std::uint64_t value = 0;
    if (object.is_object() && object.contains(key) && object[key].is_number_unsigned())
        value = object[key].get<std::uint64_t>();
    object[key] = value + 1;
}

std::string fmt_addr(std::uint64_t va)
{
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex << va;
    return os.str();
}

nlohmann::json dynamic_ioctl_state_json()
{
    const auto dyn = driver_bridge::dynamic_ioctl_state();
    return nlohmann::json{
        {"loaded", dyn.loaded},
        {"kernel", dyn.kernel},
        {"connected", dyn.connected},
        {"ready", dyn.ready},
        {"instance_server_seed", dyn.instance_server_seed},
        {"instance_ioctl_seed", dyn.instance_ioctl_seed},
        {"global_server_seed", dyn.global_server_seed},
        {"global_ioctl_seed", dyn.global_ioctl_seed},
        {"ioctl_seed_hash", dyn.ioctl_seed_hash},
        {"heartbeat_ioctl_seed_hash", dyn.heartbeat_ioctl_seed_hash}
    };
}

nlohmann::json memory_region_json(bool ok,
                                  const driver_bridge::memory_region_t& region,
                                  DWORD gle,
                                  const std::string& driver_error)
{
    return nlohmann::json{
        {"query_ok", ok},
        {"gle", static_cast<unsigned long>(gle)},
        {"driver_error", driver_error},
        {"base", ok ? nlohmann::json(fmt_addr(region.base)) : nlohmann::json(nullptr)},
        {"size", ok ? nlohmann::json(region.size) : nlohmann::json(nullptr)},
        {"state", ok ? nlohmann::json(region.state) : nlohmann::json(nullptr)},
        {"protect", ok ? nlohmann::json(region.protect) : nlohmann::json(nullptr)},
        {"type", ok ? nlohmann::json(region.type) : nlohmann::json(nullptr)}
    };
}

std::uint16_t be16(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint16_t le16(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[1]) << 8) | p[0]);
}

std::uint32_t be32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint32_t le32(const std::uint8_t* p)
{
    return (static_cast<std::uint32_t>(p[3]) << 24) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           static_cast<std::uint32_t>(p[0]);
}

std::uint64_t le64(const std::uint8_t* p)
{
    std::uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

std::uint64_t rel32_target(std::uint64_t next, std::int32_t rel)
{
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(next) + static_cast<std::int64_t>(rel));
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

bool is_blocked_target(const std::uint8_t* addr)
{
    if (addr[0] == 0 || addr[0] >= 224 || addr[0] == 255)
        return true;
    if (addr[0] == 169 && addr[1] == 254)
        return true;
    return false;
}

bool ensure_process_context(std::uint32_t requested_pid, std::uint32_t& resolved_pid, std::string& error)
{
    resolved_pid = requested_pid ? requested_pid : driver_bridge::attached_pid();
    if (resolved_pid == 0) {
        error = "process_id is required when no process is attached";
        return false;
    }
    if (!driver_bridge::using_kernel_driver()) {
        error = "driver bridge is not connected";
        return false;
    }
    if (driver_bridge::attached_pid() == resolved_pid)
        return true;

    bool already_attached = false;
    for (std::uint32_t pid : driver_bridge::attached_pids()) {
        if (pid == resolved_pid) {
            already_attached = true;
            break;
        }
    }
    if (already_attached) {
        if (!driver_bridge::set_active_pid(resolved_pid)) {
            error = driver_bridge::last_error().empty() ? "failed to set active process" : driver_bridge::last_error();
            return false;
        }
        return true;
    }
    if (driver_bridge::attached_pid() == 0) {
        if (!driver_bridge::attach(resolved_pid)) {
            error = driver_bridge::last_error().empty() ? "failed to attach process" : driver_bridge::last_error();
            return false;
        }
        return true;
    }
    if (!driver_bridge::attach_additional(resolved_pid)) {
        error = driver_bridge::last_error().empty() ? "failed to attach additional process" : driver_bridge::last_error();
        return false;
    }
    if (!driver_bridge::set_active_pid(resolved_pid)) {
        error = driver_bridge::last_error().empty() ? "failed to activate attached process" : driver_bridge::last_error();
        return false;
    }
    return true;
}

socket_module_kind_t socket_module_kind(const std::string& lower_name)
{
    if (lower_name.find("ws2_32") != std::string::npos)
        return socket_module_kind_t::ws2_32;
    if (lower_name.find("wsock32") != std::string::npos)
        return socket_module_kind_t::wsock32;
    if (lower_name.find("mswsock") != std::string::npos)
        return socket_module_kind_t::mswsock;
    return socket_module_kind_t::none;
}

bool is_socket_module(const std::string& lower_name)
{
    return socket_module_kind(lower_name) != socket_module_kind_t::none;
}

const char* socket_module_kind_name(socket_module_kind_t kind)
{
    switch (kind) {
    case socket_module_kind_t::ws2_32:
        return "ws2_32";
    case socket_module_kind_t::wsock32:
        return "wsock32";
    case socket_module_kind_t::mswsock:
        return "mswsock";
    default:
        return "none";
    }
}

int socket_module_rank(socket_module_kind_t kind)
{
    switch (kind) {
    case socket_module_kind_t::ws2_32:
        return 0;
    case socket_module_kind_t::wsock32:
        return 1;
    case socket_module_kind_t::mswsock:
        return 2;
    default:
        return 100;
    }
}

bool socket_module_exports_requested_api(socket_module_kind_t kind, const char* export_name)
{
    if (!export_name)
        return false;
    if (kind == socket_module_kind_t::ws2_32)
        return std::strcmp(export_name, "send") == 0 ||
               std::strcmp(export_name, "WSASend") == 0 ||
               std::strcmp(export_name, "sendto") == 0 ||
               std::strcmp(export_name, "recv") == 0 ||
               std::strcmp(export_name, "WSARecv") == 0 ||
               std::strcmp(export_name, "recvfrom") == 0;
    if (kind == socket_module_kind_t::wsock32)
        return std::strcmp(export_name, "send") == 0 ||
               std::strcmp(export_name, "sendto") == 0 ||
               std::strcmp(export_name, "recv") == 0 ||
               std::strcmp(export_name, "recvfrom") == 0;
    return false;
}

const wchar_t* socket_module_dll_name(const std::string& lower_name)
{
    const socket_module_kind_t kind = socket_module_kind(lower_name);
    if (kind == socket_module_kind_t::ws2_32)
        return L"ws2_32.dll";
    if (kind == socket_module_kind_t::wsock32)
        return L"wsock32.dll";
    if (kind == socket_module_kind_t::mswsock)
        return L"mswsock.dll";
    return nullptr;
}

std::uint64_t sendrecv_target_scan_reserve_ms(std::uint32_t timeout_ms)
{
    return (std::max<std::uint64_t>)(125, (std::min<std::uint64_t>)(5000, timeout_ms / 2));
}

std::uint64_t socket_resolution_app_scan_reserve_ms(const scan_deadline_t& deadline)
{
    return sendrecv_target_scan_reserve_ms(deadline.timeout_ms);
}

std::uint32_t socket_resolution_budget_ms(std::uint32_t timeout_ms,
                                          std::uint64_t remaining_ms,
                                          std::uint64_t reserve_ms)
{
    if (remaining_ms == 0)
        return 1;
    const std::uint64_t available = remaining_ms > reserve_ms + 50 ? remaining_ms - reserve_ms : (std::max<std::uint64_t>)(1, remaining_ms / 3);
    const std::uint64_t cap = (std::max<std::uint64_t>)(150, (std::min<std::uint64_t>)(3000, timeout_ms / 3));
    std::uint64_t budget = (std::min)(available, cap);
    if (budget < 75 && remaining_ms >= 75)
        budget = 75;
    if (budget > remaining_ms)
        budget = remaining_ms;
    return static_cast<std::uint32_t>((std::max<std::uint64_t>)(1, budget));
}

struct local_module_lookup_result_t {
    HMODULE module = nullptr;
    DWORD gle = ERROR_SUCCESS;
    DWORD seh = 0;
    std::uint64_t elapsed_ms = 0;
};

struct local_export_cache_entry_t {
    bool ok = false;
    bool module_loaded = false;
    std::uint64_t rva = 0;
    std::uint64_t module_size = 0;
    std::uint64_t remote_read_bytes = 0;
    HMODULE module = nullptr;
    std::string source;
    DWORD getmodule_gle = ERROR_SUCCESS;
    DWORD remote_read_gle = ERROR_SUCCESS;
    DWORD getmodule_seh = 0;
    DWORD parse_seh = 0;
    std::uint64_t getmodule_elapsed_ms = 0;
    std::uint64_t remote_read_elapsed_ms = 0;
    std::uint64_t parse_elapsed_ms = 0;
    std::string reason;
};

struct export_rva_lookup_result_t {
    bool ok = false;
    bool forwarded = false;
    std::uint64_t rva = 0;
    std::uint64_t module_size = 0;
    std::uint64_t remote_read_bytes = 0;
    DWORD gle = ERROR_SUCCESS;
    DWORD seh = 0;
    std::uint64_t elapsed_ms = 0;
    std::uint64_t remote_read_elapsed_ms = 0;
    std::string source;
    std::string reason;
};

std::mutex& local_export_cache_mutex()
{
    static std::mutex m;
    return m;
}

std::map<std::string, local_export_cache_entry_t>& local_export_cache()
{
    static std::map<std::string, local_export_cache_entry_t> cache;
    return cache;
}

local_module_lookup_result_t local_get_module_handle_w_seh(const wchar_t* dll)
{
    local_module_lookup_result_t r;
    const ULONGLONG t0 = GetTickCount64();
    __try {
        SetLastError(ERROR_SUCCESS);
        r.module = GetModuleHandleW(dll);
        r.gle = GetLastError();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        r.seh = GetExceptionCode();
        r.gle = GetLastError();
        r.module = nullptr;
    }
    r.elapsed_ms = GetTickCount64() - t0;
    return r;
}

const char* socket_module_dll_label(const std::string& lower_name)
{
    const socket_module_kind_t kind = socket_module_kind(lower_name);
    if (kind == socket_module_kind_t::ws2_32)
        return "ws2_32.dll";
    if (kind == socket_module_kind_t::wsock32)
        return "wsock32.dll";
    if (kind == socket_module_kind_t::mswsock)
        return "mswsock.dll";
    return "";
}

std::string local_export_cache_key(const std::string& lower_module_name, const char* export_name)
{
    std::string key = lower_module_name;
    key.push_back('!');
    if (export_name)
        key += export_name;
    return key;
}

void apply_local_export_cache_entry(nlohmann::json& diag, const local_export_cache_entry_t& entry)
{
    diag["ok"] = entry.ok;
    diag["cache_hit"] = true;
    diag["module"] = fmt_addr(reinterpret_cast<std::uint64_t>(entry.module));
    diag["module_size"] = entry.module_size;
    diag["remote_read_bytes"] = entry.remote_read_bytes;
    diag["module_loaded"] = entry.module_loaded;
    if (!entry.source.empty())
        diag["resolution_source"] = entry.source;
    diag["getmodule_gle"] = entry.getmodule_gle;
    diag["remote_read_gle"] = entry.remote_read_gle;
    diag["getmodule_seh"] = entry.getmodule_seh;
    diag["parse_seh"] = entry.parse_seh;
    diag["getmodule_elapsed_ms"] = entry.getmodule_elapsed_ms;
    diag["remote_read_elapsed_ms"] = entry.remote_read_elapsed_ms;
    diag["parse_elapsed_ms"] = entry.parse_elapsed_ms;
    if (entry.rva)
        diag["rva"] = fmt_addr(entry.rva);
    if (!entry.reason.empty())
        diag["reason"] = entry.reason;
}

std::string scan_module_skip_reason(const driver_bridge::module_info_t& module)
{
    const std::string name = lower_copy(module.name);
    const std::string path = lower_copy(module.path);
    if (is_socket_module(name))
        return "socket_runtime_module";
    if (name == "ntdll.dll" || name == "kernel32.dll" || name == "kernelbase.dll" ||
        name == "ucrtbase.dll" || name == "vcruntime140.dll")
        return "known_runtime_module";
    if (path.find("\\windows\\system32\\") != std::string::npos ||
        path.find("\\windows\\syswow64\\") != std::string::npos)
        return "system_directory_module";
    return {};
}

bool module_matches_scan_target(const driver_bridge::module_info_t& module,
                                const sendrecv_scan_options_t& options)
{
    if (options.module_base != 0 && module.base != options.module_base)
        return false;
    if (options.module_name.empty())
        return true;
    const std::string wanted = lower_copy(options.module_name);
    const std::string name = lower_copy(module.name);
    const std::string path = lower_copy(module.path);
    if (name == wanted || path == wanted)
        return true;
    if (name.find(wanted) != std::string::npos || path.find(wanted) != std::string::npos)
        return true;
    std::size_t slash = path.find_last_of("\\/");
    const std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    return base == wanted || base.find(wanted) != std::string::npos;
}

std::vector<driver_bridge::module_info_t> prioritize_sendrecv_scan_modules(const std::vector<driver_bridge::module_info_t>& modules,
                                                                           const sendrecv_scan_options_t& options,
                                                                           nlohmann::json& diagnostics)
{
    diagnostics = nlohmann::json::object();
    diagnostics["filter_present"] = options.module_base != 0 || !options.module_name.empty();
    diagnostics["module_name"] = options.module_name;
    diagnostics["module_base"] = options.module_base == 0 ? nlohmann::json(nullptr) : nlohmann::json(fmt_addr(options.module_base));
    diagnostics["input_module_count"] = modules.size();
    diagnostics["matched_modules"] = nlohmann::json::array();
    diagnostics["ordered_samples"] = nlohmann::json::array();
    std::vector<driver_bridge::module_info_t> ordered;
    ordered.reserve(modules.size());
    std::vector<std::size_t> matched;
    matched.reserve(modules.size());
    std::vector<std::size_t> unmatched;
    unmatched.reserve(modules.size());
    for (std::size_t i = 0; i < modules.size(); ++i) {
        if (module_matches_scan_target(modules[i], options))
            matched.push_back(i);
        else
            unmatched.push_back(i);
    }
    for (const std::size_t index : matched) {
        const auto& module = modules[index];
        ordered.push_back(module);
        if (diagnostics["matched_modules"].size() < 16)
            diagnostics["matched_modules"].push_back(nlohmann::json{{"name", module.name}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}, {"original_index", index}});
    }
    for (const std::size_t index : unmatched)
        ordered.push_back(modules[index]);
    for (std::size_t i = 0; i < ordered.size() && i < 16; ++i)
        diagnostics["ordered_samples"].push_back(nlohmann::json{{"name", ordered[i].name}, {"base", fmt_addr(ordered[i].base)}, {"size", ordered[i].size}, {"path", ordered[i].path}, {"priority_index", i}, {"target_match", module_matches_scan_target(ordered[i], options)}});
    diagnostics["matched_count"] = matched.size();
    diagnostics["unmatched_count"] = unmatched.size();
    diagnostics["ordered_module_count"] = ordered.size();
    diagnostics["target_prioritized"] = diagnostics.value("filter_present", false) && !matched.empty();
    return ordered;
}

bool compute_scan_window(const driver_bridge::module_info_t& module,
                         const sendrecv_scan_options_t& options,
                         std::uint64_t& read_base,
                         std::uint64_t& read_size)
{
    read_base = module.base;
    read_size = module.size;
    const std::uint64_t module_end = module.base + module.size;
    if (module.base == 0 || module.size == 0 || module_end <= module.base)
        return false;
    if (options.scan_base != 0 || options.scan_size != 0) {
        const std::uint64_t requested_base = options.scan_base != 0 ? options.scan_base : module.base;
        const std::uint64_t requested_end = options.scan_size != 0
            ? (options.scan_size > UINT64_MAX - requested_base ? UINT64_MAX : requested_base + options.scan_size)
            : module_end;
        if (requested_end <= requested_base)
            return false;
        const std::uint64_t clipped_base = (std::max)(module.base, requested_base);
        const std::uint64_t clipped_end = (std::min)(module_end, requested_end);
        if (clipped_end <= clipped_base)
            return false;
        read_base = clipped_base;
        read_size = clipped_end - clipped_base;
    }
    return read_size >= 16;
}

std::uint64_t local_image_size(HMODULE module)
{
    if (!module)
        return 0;
    const auto base = reinterpret_cast<const std::uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 0x100000)
        return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    return nt->OptionalHeader.SizeOfImage;
}

bool image_range_available(std::uint64_t image_size, std::uint32_t rva, std::uint64_t bytes)
{
    return rva <= image_size && bytes <= image_size - rva;
}

bool image_export_name_equals(const std::uint8_t* image, std::uint64_t image_size, std::uint32_t rva, const char* expected)
{
    if (!image || !expected || !image_range_available(image_size, rva, 1))
        return false;
    std::uint64_t offset = rva;
    for (std::size_t i = 0; expected[i] != '\0'; ++i, ++offset) {
        if (offset >= image_size)
            return false;
        if (image[offset] != static_cast<std::uint8_t>(expected[i]))
            return false;
    }
    return offset < image_size && image[offset] == 0;
}

export_rva_lookup_result_t resolve_export_rva_from_mapped_image(const std::uint8_t* image,
                                                                std::uint64_t image_size,
                                                                const char* export_name,
                                                                const char* source)
{
    export_rva_lookup_result_t result;
    result.source = source ? source : "mapped_image";
    const ULONGLONG t0 = GetTickCount64();
    if (!image || image_size < sizeof(IMAGE_DOS_HEADER) || !export_name || !*export_name) {
        result.reason = "invalid_export_image_input";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    const std::uint64_t nt_offset = dos->e_lfanew > 0 ? static_cast<std::uint64_t>(dos->e_lfanew) : 0;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || nt_offset == 0 || nt_offset > image_size || image_size - nt_offset < sizeof(IMAGE_NT_HEADERS)) {
        result.reason = "invalid_dos_or_nt_header";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + nt_offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        result.reason = "invalid_nt_signature";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    result.module_size = nt->OptionalHeader.SizeOfImage;
    if (nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        result.reason = "export_directory_index_missing";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const IMAGE_DATA_DIRECTORY& export_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir_entry.VirtualAddress == 0 || export_dir_entry.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        result.reason = "export_directory_missing";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    if (!image_range_available(image_size, export_dir_entry.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY))) {
        result.reason = "export_directory_out_of_range";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(image + export_dir_entry.VirtualAddress);
    if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
        result.reason = "export_name_table_empty";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const std::uint64_t names_bytes = static_cast<std::uint64_t>(exports->NumberOfNames) * sizeof(DWORD);
    const std::uint64_t ordinals_bytes = static_cast<std::uint64_t>(exports->NumberOfNames) * sizeof(WORD);
    const std::uint64_t functions_bytes = static_cast<std::uint64_t>(exports->NumberOfFunctions) * sizeof(DWORD);
    if (!image_range_available(image_size, exports->AddressOfNames, names_bytes) ||
        !image_range_available(image_size, exports->AddressOfNameOrdinals, ordinals_bytes) ||
        !image_range_available(image_size, exports->AddressOfFunctions, functions_bytes)) {
        result.reason = "export_tables_out_of_range";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const auto* names = reinterpret_cast<const DWORD*>(image + exports->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const WORD*>(image + exports->AddressOfNameOrdinals);
    const auto* functions = reinterpret_cast<const DWORD*>(image + exports->AddressOfFunctions);
    const std::uint64_t export_start = export_dir_entry.VirtualAddress;
    const std::uint64_t export_end = export_start + export_dir_entry.Size;
    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        if (!image_export_name_equals(image, image_size, names[i], export_name))
            continue;
        const WORD ordinal_index = ordinals[i];
        if (ordinal_index >= exports->NumberOfFunctions) {
            result.reason = "export_ordinal_out_of_range";
            result.elapsed_ms = GetTickCount64() - t0;
            return result;
        }
        const DWORD function_rva = functions[ordinal_index];
        if (function_rva >= export_start && function_rva < export_end) {
            result.forwarded = true;
            result.reason = "forwarded_export";
            result.elapsed_ms = GetTickCount64() - t0;
            return result;
        }
        if (function_rva == 0 || !image_range_available(image_size, function_rva, 1)) {
            result.reason = "export_rva_out_of_range";
            result.elapsed_ms = GetTickCount64() - t0;
            return result;
        }
        result.ok = true;
        result.rva = function_rva;
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    result.reason = "export_missing";
    result.elapsed_ms = GetTickCount64() - t0;
    return result;
}

export_rva_lookup_result_t resolve_loaded_module_export_rva(HMODULE module, const char* export_name)
{
    export_rva_lookup_result_t result;
    result.source = "local_loaded_image";
    const ULONGLONG t0 = GetTickCount64();
    const std::uint64_t size = local_image_size(module);
    result.module_size = size;
    if (!module || size == 0)
        result.reason = "local_module_image_unavailable";
    else
        result = resolve_export_rva_from_mapped_image(reinterpret_cast<const std::uint8_t*>(module), size, export_name, "local_loaded_image");
    result.elapsed_ms = GetTickCount64() - t0;
    return result;
}

export_rva_lookup_result_t resolve_remote_module_export_rva(std::uint32_t pid,
                                                            const driver_bridge::module_info_t& module,
                                                            const char* export_name,
                                                            scan_deadline_t& deadline)
{
    export_rva_lookup_result_t result;
    result.source = "remote_mapped_image";
    const ULONGLONG t0 = GetTickCount64();
    if (module.base == 0 || module.size < sizeof(IMAGE_DOS_HEADER)) {
        result.reason = "remote_module_image_unavailable";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const std::uint64_t reserve = socket_resolution_app_scan_reserve_ms(deadline);
    const std::uint64_t remaining_before = deadline.remaining_ms();
    if (deadline.expired("remote_export_before_read")) {
        result.reason = "deadline_before_remote_export_read";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    if (remaining_before <= reserve + 50) {
        result.reason = "remote_export_read_skipped_deadline_reserve";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    const std::size_t to_read = static_cast<std::size_t>((std::min<std::uint64_t>)(module.size, 16777216));
    std::vector<std::uint8_t> bytes;
    diag::log_tagged_fmt("net_proto",
        "socket_export_remote_read_begin pid=%u module=%s base=%s size=%llu export=%s read_bytes=%zu remaining_ms=%llu elapsed_ms=%llu",
        pid,
        module.name.c_str(),
        fmt_addr(module.base).c_str(),
        static_cast<unsigned long long>(module.size),
        export_name ? export_name : "",
        to_read,
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    const ULONGLONG read_t0 = GetTickCount64();
    const bool read_ok = driver_bridge::read_memory_for(pid, module.base, to_read, bytes);
    result.remote_read_elapsed_ms = GetTickCount64() - read_t0;
    result.remote_read_bytes = bytes.size();
    result.gle = GetLastError();
    diag::log_tagged_fmt("net_proto",
        "socket_export_remote_read_done pid=%u module=%s export=%s ok=%d bytes=%zu gle=%lu read_elapsed_ms=%llu remaining_ms=%llu elapsed_ms=%llu",
        pid,
        module.name.c_str(),
        export_name ? export_name : "",
        read_ok ? 1 : 0,
        bytes.size(),
        result.gle,
        static_cast<unsigned long long>(result.remote_read_elapsed_ms),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    if (!read_ok || bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        result.reason = read_ok ? "remote_export_read_too_small" : "remote_export_read_failed";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    if (deadline.expired("remote_export_after_read")) {
        result.reason = "deadline_after_remote_export_read";
        result.elapsed_ms = GetTickCount64() - t0;
        return result;
    }
    export_rva_lookup_result_t parsed = resolve_export_rva_from_mapped_image(bytes.data(), bytes.size(), export_name, "remote_mapped_image");
    parsed.remote_read_elapsed_ms = result.remote_read_elapsed_ms;
    parsed.remote_read_bytes = result.remote_read_bytes;
    parsed.gle = result.gle;
    parsed.elapsed_ms = GetTickCount64() - t0;
    return parsed;
}

std::uint64_t resolve_local_export_rva(const std::string& lower_module_name,
                                       const char* export_name,
                                       const driver_bridge::module_info_t& remote_module,
                                       std::uint32_t pid,
                                       scan_deadline_t& deadline,
                                       nlohmann::json& diag)
{
    const ULONGLONG started = GetTickCount64();
    diag = nlohmann::json::object();
    diag["export"] = export_name ? export_name : "";
    diag["source"] = "socket_export_rva";
    diag["cache_hit"] = false;
    diag["deadline_remaining_ms_entry"] = deadline.remaining_ms();
    const wchar_t* dll = socket_module_dll_name(lower_module_name);
    const char* dll_label = socket_module_dll_label(lower_module_name);
    if (!dll) {
        diag["ok"] = false;
        diag["reason"] = "not_a_known_socket_module";
        return 0;
    }
    diag["dll"] = dll_label;
    diag["remote_module"] = remote_module.name;
    diag["remote_base"] = fmt_addr(remote_module.base);
    diag["remote_size"] = remote_module.size;
    diag["remote_path"] = remote_module.path;
    const std::string cache_key = local_export_cache_key(lower_module_name, export_name) + "@" + lower_copy(remote_module.path) + "#" + std::to_string(remote_module.size);
    {
        std::lock_guard<std::mutex> lock(local_export_cache_mutex());
        auto it = local_export_cache().find(cache_key);
        if (it != local_export_cache().end()) {
            apply_local_export_cache_entry(diag, it->second);
            diag["elapsed_ms"] = GetTickCount64() - started;
            diag["deadline_remaining_ms_exit"] = deadline.remaining_ms();
            diag["source"] = "local_rva_cache";
            diag::log_tagged_fmt("net_proto",
                "socket_export_local_cache_hit pid=%u module=%s dll=%s export=%s ok=%d rva=%s reason=%s remaining_ms=%llu elapsed_ms=%llu",
                pid,
                lower_module_name.c_str(),
                dll_label,
                export_name ? export_name : "",
                it->second.ok ? 1 : 0,
                it->second.rva ? fmt_addr(it->second.rva).c_str() : "0x0",
                it->second.reason.c_str(),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(GetTickCount64() - started));
            return it->second.rva;
        }
    }

    if (deadline.expired("local_export_before_getmodule")) {
        diag["ok"] = false;
        diag["reason"] = "deadline_before_getmodule";
        diag["deadline_hit"] = true;
        return 0;
    }

    diag::log_tagged_fmt("net_proto",
        "socket_export_getmodule_begin pid=%u module=%s dll=%s export=%s remaining_ms=%llu elapsed_ms=%llu",
        pid,
        lower_module_name.c_str(),
        dll_label,
        export_name ? export_name : "",
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(GetTickCount64() - started));
    const local_module_lookup_result_t getmodule = local_get_module_handle_w_seh(dll);
    HMODULE module = getmodule.module;
    diag["getmodule_gle"] = getmodule.gle;
    diag["getmodule_seh"] = getmodule.seh;
    diag["getmodule_elapsed_ms"] = getmodule.elapsed_ms;
    diag["getmodule_handle"] = fmt_addr(reinterpret_cast<std::uint64_t>(getmodule.module));
    diag::log_tagged_fmt("net_proto",
        "socket_export_getmodule_done pid=%u module=%s dll=%s export=%s handle=%p gle=%lu seh=0x%08lX phase_elapsed_ms=%llu remaining_ms=%llu elapsed_ms=%llu",
        pid,
        lower_module_name.c_str(),
        dll_label,
        export_name ? export_name : "",
        getmodule.module,
        getmodule.gle,
        getmodule.seh,
        static_cast<unsigned long long>(getmodule.elapsed_ms),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(GetTickCount64() - started));

    auto cache_success = [&](const export_rva_lookup_result_t& parsed, HMODULE cached_module, bool module_loaded) {
        local_export_cache_entry_t entry;
        entry.ok = parsed.ok;
        entry.module_loaded = module_loaded;
        entry.rva = parsed.rva;
        entry.module_size = parsed.module_size;
        entry.remote_read_bytes = parsed.remote_read_bytes;
        entry.module = cached_module;
        entry.source = parsed.source;
        entry.getmodule_gle = getmodule.gle;
        entry.remote_read_gle = parsed.gle;
        entry.getmodule_seh = getmodule.seh;
        entry.parse_seh = parsed.seh;
        entry.getmodule_elapsed_ms = getmodule.elapsed_ms;
        entry.remote_read_elapsed_ms = parsed.remote_read_elapsed_ms;
        entry.parse_elapsed_ms = parsed.elapsed_ms;
        entry.reason = parsed.reason;
        std::lock_guard<std::mutex> lock(local_export_cache_mutex());
        local_export_cache()[cache_key] = entry;
    };

    if (module) {
        if (deadline.expired("local_export_before_parse_loaded")) {
            diag["ok"] = false;
            diag["reason"] = "deadline_before_local_export_parse";
            diag["deadline_hit"] = true;
            diag["elapsed_ms"] = GetTickCount64() - started;
            diag["deadline_remaining_ms_exit"] = deadline.remaining_ms();
            return 0;
        }
        diag::log_tagged_fmt("net_proto",
            "socket_export_loaded_parse_begin pid=%u module=%s dll=%s export=%s handle=%p remaining_ms=%llu elapsed_ms=%llu",
            pid,
            lower_module_name.c_str(),
            dll_label,
            export_name ? export_name : "",
            module,
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(GetTickCount64() - started));
        export_rva_lookup_result_t parsed = resolve_loaded_module_export_rva(module, export_name);
        diag["local_loaded"] = nlohmann::json{
            {"ok", parsed.ok},
            {"source", parsed.source},
            {"rva", parsed.rva ? nlohmann::json(fmt_addr(parsed.rva)) : nlohmann::json(nullptr)},
            {"module_size", parsed.module_size},
            {"forwarded", parsed.forwarded},
            {"reason", parsed.reason},
            {"seh", static_cast<unsigned long>(parsed.seh)},
            {"elapsed_ms", parsed.elapsed_ms}
        };
        diag::log_tagged_fmt("net_proto",
            "socket_export_loaded_parse_done pid=%u module=%s dll=%s export=%s ok=%d rva=%s reason=%s forwarded=%d parse_elapsed_ms=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            lower_module_name.c_str(),
            dll_label,
            export_name ? export_name : "",
            parsed.ok ? 1 : 0,
            parsed.rva ? fmt_addr(parsed.rva).c_str() : "0x0",
            parsed.reason.c_str(),
            parsed.forwarded ? 1 : 0,
            static_cast<unsigned long long>(parsed.elapsed_ms),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(GetTickCount64() - started));
        if (parsed.ok) {
            cache_success(parsed, module, true);
            diag["ok"] = true;
            diag["module_loaded"] = true;
            diag["module_size"] = parsed.module_size;
            diag["resolution_source"] = parsed.source;
            diag["rva"] = fmt_addr(parsed.rva);
            diag["elapsed_ms"] = GetTickCount64() - started;
            diag["deadline_remaining_ms_exit"] = deadline.remaining_ms();
            return parsed.rva;
        }
    } else {
        diag["local_loaded"] = nlohmann::json{
            {"ok", false},
            {"source", "local_loaded_image"},
            {"reason", "local_module_not_loaded"}
        };
        diag::log_tagged_fmt("net_proto",
            "socket_export_local_module_absent pid=%u module=%s dll=%s export=%s remaining_ms=%llu elapsed_ms=%llu",
            pid,
            lower_module_name.c_str(),
            dll_label,
            export_name ? export_name : "",
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(GetTickCount64() - started));
    }

    if (!deadline.expired("remote_export_parse")) {
        export_rva_lookup_result_t remote = resolve_remote_module_export_rva(pid, remote_module, export_name, deadline);
        diag["remote_mapped"] = nlohmann::json{
            {"ok", remote.ok},
            {"source", remote.source},
            {"rva", remote.rva ? nlohmann::json(fmt_addr(remote.rva)) : nlohmann::json(nullptr)},
            {"module_size", remote.module_size},
            {"remote_read_bytes", remote.remote_read_bytes},
            {"remote_read_gle", static_cast<unsigned long>(remote.gle)},
            {"remote_read_elapsed_ms", remote.remote_read_elapsed_ms},
            {"forwarded", remote.forwarded},
            {"reason", remote.reason},
            {"seh", static_cast<unsigned long>(remote.seh)},
            {"elapsed_ms", remote.elapsed_ms}
        };
        if (remote.ok) {
            cache_success(remote, module, module != nullptr);
            diag["ok"] = true;
            diag["module_loaded"] = module != nullptr;
            diag["module_size"] = remote.module_size;
            diag["remote_read_bytes"] = remote.remote_read_bytes;
            diag["remote_read_elapsed_ms"] = remote.remote_read_elapsed_ms;
            diag["resolution_source"] = remote.source;
            diag["rva"] = fmt_addr(remote.rva);
            diag["elapsed_ms"] = GetTickCount64() - started;
            diag["deadline_remaining_ms_exit"] = deadline.remaining_ms();
            diag::log_tagged_fmt("net_proto",
                "socket_export_local_done pid=%u module=%s dll=%s export=%s ok=1 rva=%s source=%s remaining_ms=%llu elapsed_ms=%llu",
                pid,
                lower_module_name.c_str(),
                dll_label,
                export_name ? export_name : "",
                fmt_addr(remote.rva).c_str(),
                remote.source.c_str(),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(GetTickCount64() - started));
            return remote.rva;
        }
    } else {
        diag["remote_mapped"] = nlohmann::json{
            {"ok", false},
            {"source", "remote_mapped_image"},
            {"reason", "deadline_before_remote_export_parse"}
        };
    }

    const std::string local_reason = diag.contains("local_loaded") && diag["local_loaded"].is_object()
        ? diag["local_loaded"].value("reason", std::string())
        : std::string();
    const std::string remote_reason = diag.contains("remote_mapped") && diag["remote_mapped"].is_object()
        ? diag["remote_mapped"].value("reason", std::string())
        : std::string();
    diag["ok"] = false;
    diag["module_loaded"] = module != nullptr;
    diag["deadline_hit"] = deadline.hit;
    diag["reason"] = deadline.hit ? "deadline_during_socket_export_resolution" : (!remote_reason.empty() ? remote_reason : (!local_reason.empty() ? local_reason : "socket_export_rva_unresolved"));
    diag["elapsed_ms"] = GetTickCount64() - started;
    diag["deadline_remaining_ms_exit"] = deadline.remaining_ms();
    diag::log_tagged_fmt("net_proto",
        "socket_export_local_done pid=%u module=%s dll=%s export=%s ok=0 rva=0x0 reason=%s module_loaded=%d deadline_hit=%d remaining_ms=%llu elapsed_ms=%llu",
        pid,
        lower_module_name.c_str(),
        dll_label,
        export_name ? export_name : "",
        diag.value("reason", std::string()).c_str(),
        module ? 1 : 0,
        deadline.hit ? 1 : 0,
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(GetTickCount64() - started));
    return 0;
}

std::vector<api_target_t> resolve_socket_apis(const std::vector<driver_bridge::module_info_t>& modules,
                                              std::uint32_t pid,
                                              scan_deadline_t& deadline,
                                              nlohmann::json& diagnostics)
{
    static const struct {
        const char* name;
        const char* direction;
    } names[] = {
        {"send", "send"},
        {"WSASend", "send"},
        {"sendto", "send"},
        {"recv", "recv"},
        {"WSARecv", "recv"},
        {"recvfrom", "recv"}
    };

    std::vector<api_target_t> apis;
    diagnostics = nlohmann::json::object();
    diagnostics["socket_modules"] = nlohmann::json::array();
    diagnostics["export_resolution"] = nlohmann::json::array();
    diagnostics["ordered_socket_modules"] = nlohmann::json::array();
    diagnostics["local_rva_hits"] = 0;
    diagnostics["local_rva_cache_hits"] = 0;
    diagnostics["local_loaded_rva_hits"] = 0;
    diagnostics["remote_mapped_rva_hits"] = 0;
    diagnostics["remote_fallback_attempts"] = 0;
    diagnostics["remote_fallback_hits"] = 0;
    diagnostics["remote_fallback_skips"] = 0;
    diagnostics["app_scan_reserve_ms"] = socket_resolution_app_scan_reserve_ms(deadline);
    diag::log_tagged_fmt("net_proto",
        "resolve_socket_apis_begin pid=%u module_count=%zu timeout_ms=%u remaining_ms=%llu elapsed_ms=%llu",
        pid,
        modules.size(),
        deadline.timeout_ms,
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    std::vector<const driver_bridge::module_info_t*> socket_modules;
    socket_modules.reserve(4);
    for (const auto& module : modules) {
        const std::string lower_name = lower_copy(module.name);
        if (socket_module_kind(lower_name) != socket_module_kind_t::none)
            socket_modules.push_back(&module);
    }
    diag::log_tagged_fmt("net_proto",
        "resolve_socket_apis_socket_modules pid=%u socket_module_count=%zu remaining_ms=%llu elapsed_ms=%llu",
        pid,
        socket_modules.size(),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    std::stable_sort(socket_modules.begin(), socket_modules.end(),
        [](const driver_bridge::module_info_t* a, const driver_bridge::module_info_t* b) {
            const socket_module_kind_t ak = socket_module_kind(lower_copy(a ? a->name : std::string()));
            const socket_module_kind_t bk = socket_module_kind(lower_copy(b ? b->name : std::string()));
            const int ar = socket_module_rank(ak);
            const int br = socket_module_rank(bk);
            if (ar != br)
                return ar < br;
            const std::string an = lower_copy(a ? a->name : std::string());
            const std::string bn = lower_copy(b ? b->name : std::string());
            if (an != bn)
                return an < bn;
            return (a ? a->base : 0) < (b ? b->base : 0);
        });
    for (const auto* module_ptr : socket_modules) {
        if (deadline.expired("resolve_socket_exports_module")) {
            diag::log_tagged_fmt("net_proto",
                "resolve_socket_apis_deadline pid=%u stage=resolve_socket_exports_module apis=%zu remaining_ms=%llu elapsed_ms=%llu",
                pid,
                apis.size(),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            break;
        }
        if (!module_ptr)
            continue;
        const auto& module = *module_ptr;
        const std::string lower_name = lower_copy(module.name);
        const socket_module_kind_t kind = socket_module_kind(lower_name);
        if (diagnostics["ordered_socket_modules"].size() < 16)
            diagnostics["ordered_socket_modules"].push_back(nlohmann::json{{"name", module.name}, {"kind", socket_module_kind_name(kind)}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}, {"rank", socket_module_rank(kind)}});
        if (diagnostics["socket_modules"].size() < 8)
            diagnostics["socket_modules"].push_back(nlohmann::json{{"name", module.name}, {"kind", socket_module_kind_name(kind)}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}});
        diag::log_tagged_fmt("net_proto",
            "resolve_socket_module_begin pid=%u module=%s kind=%s base=%s size=%llu exports=%zu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            socket_module_kind_name(kind),
            fmt_addr(module.base).c_str(),
            static_cast<unsigned long long>(module.size),
            sizeof(names) / sizeof(names[0]),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        for (const auto& n : names) {
            if (deadline.expired("resolve_socket_exports_export")) {
                diag::log_tagged_fmt("net_proto",
                    "resolve_socket_export_deadline pid=%u module=%s export=%s apis=%zu remaining_ms=%llu elapsed_ms=%llu",
                    pid,
                    module.name.c_str(),
                    n.name,
                    apis.size(),
                    static_cast<unsigned long long>(deadline.remaining_ms()),
                    static_cast<unsigned long long>(deadline.elapsed_ms()));
                break;
            }
            nlohmann::json rdiag;
            rdiag["module"] = module.name;
            rdiag["module_kind"] = socket_module_kind_name(kind);
            rdiag["module_base"] = fmt_addr(module.base);
            rdiag["export"] = n.name;
            rdiag["deadline_remaining_ms"] = deadline.remaining_ms();
            diag::log_tagged_fmt("net_proto",
                "resolve_socket_export_begin pid=%u module=%s kind=%s export=%s remaining_ms=%llu elapsed_ms=%llu",
                pid,
                module.name.c_str(),
                socket_module_kind_name(kind),
                n.name,
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            if (!socket_module_exports_requested_api(kind, n.name)) {
                rdiag["ok"] = false;
                rdiag["resolution_source"] = "skipped";
                rdiag["skip_reason"] = "module_does_not_export_requested_socket_api";
                if (diagnostics["export_resolution"].size() < 32)
                    diagnostics["export_resolution"].push_back(std::move(rdiag));
                diag::log_tagged_fmt("net_proto",
                    "resolve_socket_export_skip pid=%u module=%s export=%s reason=module_does_not_export_requested_socket_api remaining_ms=%llu elapsed_ms=%llu",
                    pid,
                    module.name.c_str(),
                    n.name,
                    static_cast<unsigned long long>(deadline.remaining_ms()),
                    static_cast<unsigned long long>(deadline.elapsed_ms()));
                continue;
            }
            const std::uint64_t rva = resolve_local_export_rva(lower_name, n.name, module, pid, deadline, rdiag);
            if (rdiag.value("cache_hit", false))
                diagnostics["local_rva_cache_hits"] = diagnostics.value("local_rva_cache_hits", 0) + 1;
            std::uint64_t va = 0;
            if (rva != 0 && (module.size == 0 || rva < module.size)) {
                const std::string rva_source = rdiag.value("resolution_source", std::string("socket_export_rva"));
                va = module.base + rva;
                rdiag["remote_va"] = fmt_addr(va);
                rdiag["resolution_source"] = rva_source;
                rdiag["va_resolution_source"] = "rva_plus_remote_module_base";
                diagnostics["local_rva_hits"] = diagnostics.value("local_rva_hits", 0) + 1;
                if (rva_source == "local_loaded_image")
                    diagnostics["local_loaded_rva_hits"] = diagnostics.value("local_loaded_rva_hits", 0) + 1;
                if (rva_source == "remote_mapped_image")
                    diagnostics["remote_mapped_rva_hits"] = diagnostics.value("remote_mapped_rva_hits", 0) + 1;
            } else {
                if (rva != 0)
                    rdiag["reason"] = "local_rva_outside_remote_module_size";
                const std::string local_reason = rdiag.value("reason", std::string());
                const std::uint64_t remaining_before = deadline.remaining_ms();
                const std::uint64_t reserve = socket_resolution_app_scan_reserve_ms(deadline);
                const bool export_absent = local_reason == "local_export_missing" || local_reason == "export_missing";
                if (export_absent) {
                    rdiag["remote_fallback_skipped"] = true;
                    rdiag["remote_fallback_skip_reason"] = "local_export_absent";
                    rdiag["resolution_source"] = "local_absence";
                    diagnostics["remote_fallback_skips"] = diagnostics.value("remote_fallback_skips", 0) + 1;
                    diag::log_tagged_fmt("net_proto",
                        "socket_export_fallback_skip pid=%u module=%s export=%s reason=local_export_absent remaining_ms=%llu elapsed_ms=%llu",
                        pid,
                        module.name.c_str(),
                        n.name,
                        static_cast<unsigned long long>(deadline.remaining_ms()),
                        static_cast<unsigned long long>(deadline.elapsed_ms()));
                } else if (remaining_before > reserve + 75) {
                    diagnostics["remote_fallback_attempts"] = diagnostics.value("remote_fallback_attempts", 0) + 1;
                    const ULONGLONG t0 = GetTickCount64();
                    diag::log_tagged_fmt("net_proto",
                        "socket_export_fallback_begin pid=%u module=%s export=%s base=%s remaining_before=%llu reserve_ms=%llu elapsed_ms=%llu",
                        pid,
                        module.name.c_str(),
                        n.name,
                        fmt_addr(module.base).c_str(),
                        static_cast<unsigned long long>(remaining_before),
                        static_cast<unsigned long long>(reserve),
                        static_cast<unsigned long long>(deadline.elapsed_ms()));
                    va = driver_bridge::resolve_export_for(pid, module.base, n.name);
                    const ULONGLONG fallback_elapsed = GetTickCount64() - t0;
                    const std::uint64_t remaining_after = deadline.remaining_ms();
                    const std::string module_base = fmt_addr(module.base);
                    rdiag["remote_fallback_elapsed_ms"] = fallback_elapsed;
                    rdiag["deadline_remaining_ms_before_fallback"] = remaining_before;
                    rdiag["deadline_remaining_ms_after_fallback"] = remaining_after;
                    rdiag["remote_fallback_va"] = va ? nlohmann::json(fmt_addr(va)) : nlohmann::json(nullptr);
                    rdiag["resolution_source"] = va ? "driver_bridge_pid_bound" : "driver_bridge_pid_bound_miss";
                    diag::log_tagged_fmt("net_proto",
                        "socket_export_fallback pid=%u module=%s export=%s base=%s hit=%d elapsed_ms=%llu remaining_before=%llu remaining_after=%llu reserve_ms=%llu",
                        pid,
                        module.name.c_str(),
                        n.name,
                        module_base.c_str(),
                        va ? 1 : 0,
                        static_cast<unsigned long long>(fallback_elapsed),
                        static_cast<unsigned long long>(remaining_before),
                        static_cast<unsigned long long>(remaining_after),
                        static_cast<unsigned long long>(reserve));
                    if (va)
                        diagnostics["remote_fallback_hits"] = diagnostics.value("remote_fallback_hits", 0) + 1;
                } else {
                    rdiag["remote_fallback_skipped"] = true;
                    rdiag["remote_fallback_skip_reason"] = "deadline_remaining_too_small";
                    rdiag["deadline_remaining_ms_before_fallback"] = remaining_before;
                    rdiag["app_scan_reserve_ms"] = reserve;
                    rdiag["resolution_source"] = "skipped";
                    diagnostics["remote_fallback_skips"] = diagnostics.value("remote_fallback_skips", 0) + 1;
                    diag::log_tagged_fmt("net_proto",
                        "socket_export_fallback_skip pid=%u module=%s export=%s reason=deadline_remaining_too_small remaining_before=%llu reserve_ms=%llu elapsed_ms=%llu",
                        pid,
                        module.name.c_str(),
                        n.name,
                        static_cast<unsigned long long>(remaining_before),
                        static_cast<unsigned long long>(reserve),
                        static_cast<unsigned long long>(deadline.elapsed_ms()));
                }
            }
            rdiag["module"] = module.name;
            rdiag["module_kind"] = socket_module_kind_name(kind);
            rdiag["module_base"] = fmt_addr(module.base);
            rdiag["deadline_hit"] = deadline.hit;
            rdiag["deadline_remaining_ms"] = deadline.remaining_ms();
            if (diagnostics["export_resolution"].size() < 32)
                diagnostics["export_resolution"].push_back(std::move(rdiag));
            diag::log_tagged_fmt("net_proto",
                "resolve_socket_export_done pid=%u module=%s export=%s va=%s local_rva=%s apis=%zu deadline_hit=%d remaining_ms=%llu elapsed_ms=%llu",
                pid,
                module.name.c_str(),
                n.name,
                va ? fmt_addr(va).c_str() : "0x0",
                rva ? fmt_addr(rva).c_str() : "0x0",
                apis.size(),
                deadline.hit ? 1 : 0,
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            if (va == 0)
                continue;
            apis.push_back({n.name, n.direction, va});
        }
        diag::log_tagged_fmt("net_proto",
            "resolve_socket_module_done pid=%u module=%s apis=%zu deadline_hit=%d remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            apis.size(),
            deadline.hit ? 1 : 0,
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
    }
    diagnostics["api_count"] = apis.size();
    diagnostics["deadline_hit"] = deadline.hit;
    diagnostics["stage"] = deadline.stage;
    diagnostics["deadline_remaining_ms"] = deadline.remaining_ms();
    diagnostics["elapsed_ms"] = deadline.elapsed_ms();
    if (apis.empty()) {
        diagnostics["dependency_unavailable"] = true;
        if (deadline.hit)
            diagnostics["root_cause"] = "socket_export_resolution_deadline";
        else if (socket_modules.empty())
            diagnostics["root_cause"] = "socket_runtime_module_not_loaded_in_target";
        else
            diagnostics["root_cause"] = "socket_exports_unresolved";
    } else {
        diagnostics["dependency_unavailable"] = false;
        diagnostics["root_cause"] = "socket_exports_resolved";
    }
    diag::log_tagged_fmt("net_proto",
        "resolve_socket_apis_done pid=%u api_count=%zu deadline_hit=%d stage=%s root=%s remaining_ms=%llu elapsed_ms=%llu",
        pid,
        apis.size(),
        deadline.hit ? 1 : 0,
        deadline.stage.c_str(),
        diagnostics["root_cause"].get<std::string>().c_str(),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    return apis;
}

const api_target_t* find_api_by_address(const std::vector<api_target_t>& apis, std::uint64_t target)
{
    for (const auto& api : apis)
        if (api.address == target)
            return &api;
    return nullptr;
}

std::uint64_t find_probable_function_start(const std::vector<std::uint8_t>& bytes,
                                           std::size_t call_off,
                                           std::uint64_t base)
{
    const std::size_t lo = call_off > 512 ? call_off - 512 : 0;
    std::size_t best = lo;
    for (std::size_t i = call_off; i-- > lo; ) {
        if (bytes[i] == 0xcc && i + 1 < call_off) {
            best = i + 1;
            break;
        }
        if (i + 4 < bytes.size()) {
            const bool classic = bytes[i] == 0x55 && bytes[i + 1] == 0x48 &&
                (bytes[i + 2] == 0x8b || bytes[i + 2] == 0x89);
            const bool unwind = (bytes[i] == 0x40 || bytes[i] == 0x48 || bytes[i] == 0x4c) &&
                i + 3 < bytes.size() && (bytes[i + 1] == 0x53 || bytes[i + 1] == 0x55 || bytes[i + 1] == 0x57);
            const bool stack = bytes[i] == 0x48 && (bytes[i + 1] == 0x83 || bytes[i + 1] == 0x81) &&
                i + 3 < bytes.size() && bytes[i + 2] == 0xec;
            if (classic || unwind || stack) {
                best = i;
                break;
            }
        }
    }
    return base + best;
}

std::uint64_t nearest_internal_call(const std::vector<std::uint8_t>& bytes,
                                    std::size_t call_off,
                                    std::uint64_t base,
                                    const std::set<std::uint64_t>& excluded_targets,
                                    bool forward)
{
    if (bytes.size() < 5)
        return 0;
    const std::size_t window = 160;
    if (forward) {
        const std::size_t end = (std::min)(bytes.size() - 5, call_off + window);
        for (std::size_t i = call_off + 5; i <= end; ++i) {
            if (bytes[i] != 0xe8)
                continue;
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
            const std::uint64_t target = rel32_target(base + i + 5, rel);
            if (excluded_targets.find(target) == excluded_targets.end())
                return target;
        }
    } else {
        const std::size_t start = call_off > window ? call_off - window : 0;
        for (std::size_t i = call_off; i-- > start; ) {
            if (bytes[i] != 0xe8 || i + 5 > bytes.size())
                continue;
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
            const std::uint64_t target = rel32_target(base + i + 5, rel);
            if (excluded_targets.find(target) == excluded_targets.end())
                return target;
        }
    }
    return 0;
}

bool va_in_scan(std::uint64_t va, std::uint64_t base, std::size_t size)
{
    const std::uint64_t span = static_cast<std::uint64_t>(size);
    if (span > UINT64_MAX - base)
        return va >= base;
    return va >= base && va < base + span;
}

bool is_ret_or_trap(std::uint8_t op)
{
    return op == 0xc3 || op == 0xc2 || op == 0xcc;
}

bool is_branch_opcode(const std::vector<std::uint8_t>& bytes, std::size_t off)
{
    if (off >= bytes.size())
        return false;
    const std::uint8_t op = bytes[off];
    if (op == 0xe9 || op == 0xeb || op == 0xff || (op >= 0x70 && op <= 0x7f) || is_ret_or_trap(op))
        return true;
    return op == 0x0f && off + 1 < bytes.size() && bytes[off + 1] >= 0x80 && bytes[off + 1] <= 0x8f;
}

std::size_t find_probable_function_end(const std::vector<std::uint8_t>& bytes,
                                       std::size_t call_off,
                                       std::size_t function_start)
{
    const std::size_t max_end = (std::min)(bytes.size(), (std::max)(call_off + 6, function_start) + std::size_t(8192));
    for (std::size_t i = call_off + 5; i < max_end; ++i) {
        if (is_ret_or_trap(bytes[i])) {
            std::size_t end = i + 1;
            while (end < bytes.size() && bytes[end] == 0xcc && end - i < 32)
                ++end;
            return end;
        }
        if (i + 4 < max_end) {
            const bool prologue = bytes[i] == 0x40 && (bytes[i + 1] == 0x53 || bytes[i + 1] == 0x55 || bytes[i + 1] == 0x57);
            if (prologue && i > call_off + 16)
                return i;
        }
    }
    return max_end;
}

std::size_t find_basic_block_start(const std::vector<std::uint8_t>& bytes,
                                   std::size_t function_start,
                                   std::size_t call_off)
{
    std::size_t best = function_start;
    const std::size_t lo = call_off > 256 ? call_off - 256 : function_start;
    for (std::size_t i = call_off; i-- > lo; ) {
        if (is_branch_opcode(bytes, i)) {
            best = (std::min)(call_off, i + 1);
            break;
        }
    }
    return (std::max)(best, function_start);
}

std::size_t find_basic_block_end(const std::vector<std::uint8_t>& bytes,
                                 std::size_t call_off,
                                 std::size_t function_end)
{
    const std::size_t hi = (std::min)(function_end, call_off + std::size_t(256));
    for (std::size_t i = call_off + 5; i < hi; ++i) {
        if (is_branch_opcode(bytes, i))
            return i + 1;
    }
    return hi;
}

std::vector<internal_call_t> collect_internal_calls(const std::vector<std::uint8_t>& bytes,
                                                    std::size_t start,
                                                    std::size_t end,
                                                    std::uint64_t base,
                                                    const std::set<std::uint64_t>& excluded_targets)
{
    std::vector<internal_call_t> calls;
    end = (std::min)(end, bytes.size());
    for (std::size_t i = start; i + 5 <= end; ++i) {
        if (bytes[i] != 0xe8)
            continue;
        std::int32_t rel = 0;
        std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
        const std::uint64_t target = rel32_target(base + i + 5, rel);
        if (excluded_targets.find(target) != excluded_targets.end())
            continue;
        if (!va_in_scan(target, base, bytes.size()))
            continue;
        internal_call_t c;
        c.call_va = base + i;
        c.target_va = target;
        c.offset = i;
        calls.push_back(c);
    }
    return calls;
}

bool window_has_bytes(const std::vector<std::uint8_t>& bytes,
                      std::size_t start,
                      std::size_t end,
                      const std::vector<std::uint8_t>& pattern)
{
    if (pattern.empty())
        return false;
    end = (std::min)(end, bytes.size());
    for (std::size_t i = start; i + pattern.size() <= end; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (bytes[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

nlohmann::json calls_to_json(const std::vector<internal_call_t>& calls,
                             std::size_t call_off,
                             std::size_t max_items)
{
    nlohmann::json out = nlohmann::json::array();
    for (const auto& c : calls) {
        if (out.size() >= max_items)
            break;
        nlohmann::json item;
        item["call_va"] = fmt_addr(c.call_va);
        item["target_va"] = fmt_addr(c.target_va);
        item["distance_bytes"] = c.offset > call_off ? c.offset - call_off : call_off - c.offset;
        item["relation"] = c.offset < call_off ? "upstream" : "downstream";
        out.push_back(std::move(item));
    }
    return out;
}

std::pair<std::size_t, std::size_t> target_function_bounds(const std::vector<std::uint8_t>& bytes,
                                                           std::uint64_t base,
                                                           std::uint64_t target_va)
{
    if (!va_in_scan(target_va, base, bytes.size()))
        return {0, 0};
    const std::size_t target_off = static_cast<std::size_t>(target_va - base);
    const std::size_t end = find_probable_function_end(bytes, target_off, target_off);
    return {target_off, end};
}

std::size_t count_byte_pattern(const std::vector<std::uint8_t>& bytes,
                               std::size_t start,
                               std::size_t end,
                               const std::vector<std::uint8_t>& pattern)
{
    if (pattern.empty())
        return 0;
    std::size_t count = 0;
    end = (std::min)(end, bytes.size());
    for (std::size_t i = start; i + pattern.size() <= end; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size(); ++j) {
            if (bytes[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match)
            ++count;
    }
    return count;
}

std::size_t count_store_like_ops(const std::vector<std::uint8_t>& bytes,
                                 std::size_t start,
                                 std::size_t end)
{
    std::size_t count = 0;
    end = (std::min)(end, bytes.size());
    for (std::size_t i = start; i < end; ++i) {
        const std::uint8_t op = bytes[i];
        if (op == 0x88 || op == 0x89 || op == 0xc6 || op == 0xc7)
            ++count;
        if (i + 2 < end && (op == 0x66 || op == 0x44 || op == 0x48) && (bytes[i + 1] == 0x89 || bytes[i + 1] == 0x88))
            ++count;
    }
    return count;
}

std::size_t count_compare_like_ops(const std::vector<std::uint8_t>& bytes,
                                   std::size_t start,
                                   std::size_t end)
{
    std::size_t count = 0;
    end = (std::min)(end, bytes.size());
    for (std::size_t i = start; i < end; ++i) {
        const std::uint8_t op = bytes[i];
        if (op == 0x38 || op == 0x39 || op == 0x3a || op == 0x3b || op == 0x3c || op == 0x3d || op == 0x80 || op == 0x81 || op == 0x83 || op == 0x84 || op == 0x85)
            ++count;
    }
    return count;
}

nlohmann::json nested_calls_to_json(const std::vector<std::uint8_t>& bytes,
                                    std::uint64_t base,
                                    std::uint64_t target_va,
                                    const std::set<std::uint64_t>& excluded_targets)
{
    nlohmann::json out = nlohmann::json::array();
    const auto bounds = target_function_bounds(bytes, base, target_va);
    if (bounds.first == bounds.second)
        return out;
    const auto nested = collect_internal_calls(bytes, bounds.first, bounds.second, base, excluded_targets);
    for (const auto& c : nested) {
        if (out.size() >= 6)
            break;
        out.push_back(nlohmann::json{{"call_va", fmt_addr(c.call_va)}, {"target_va", fmt_addr(c.target_va)}});
    }
    return out;
}

scored_call_t score_internal_call_candidate(const std::vector<std::uint8_t>& bytes,
                                            std::uint64_t base,
                                            const internal_call_t& call,
                                            std::size_t api_call_off,
                                            std::size_t block_start,
                                            std::size_t block_end,
                                            bool serializer,
                                            const std::set<std::uint64_t>& excluded_targets)
{
    scored_call_t scored;
    scored.call = call;
    const std::size_t distance = call.offset > api_call_off ? call.offset - api_call_off : api_call_off - call.offset;
    scored.score = serializer ? 0.48 : 0.46;
    scored.evidence.push_back(serializer ? "candidate_precedes_send_api" : "candidate_follows_recv_api");
    scored.evidence.push_back("distance_bytes=" + std::to_string(distance));
    if (call.offset >= block_start && call.offset < block_end) {
        scored.score += 0.09;
        scored.evidence.push_back("same_basic_block");
    }
    if (distance <= 64) {
        scored.score += 0.08;
        scored.evidence.push_back("near_api_callsite");
    } else if (distance <= 192) {
        scored.score += 0.04;
        scored.evidence.push_back("same_function_near_api_callsite");
    }

    const std::size_t lo = serializer ? (std::min)(call.offset + std::size_t(5), api_call_off) : api_call_off + 5;
    const std::size_t hi = serializer ? api_call_off : call.offset;
    if (serializer) {
        if (window_has_bytes(bytes, lo, hi, {0x48, 0x8b, 0xd0}) || window_has_bytes(bytes, lo, hi, {0x48, 0x89, 0xc2}) ||
            window_has_bytes(bytes, lo, hi, {0x4c, 0x8b, 0xc0}) || window_has_bytes(bytes, lo, hi, {0x49, 0x89, 0xc0})) {
            scored.score += 0.09;
            scored.evidence.push_back("return_value_or_buffer_register_forwarded");
        }
        if (window_has_bytes(bytes, lo, hi, {0x48, 0x8d}) || window_has_bytes(bytes, lo, hi, {0x4c, 0x8d})) {
            scored.score += 0.04;
            scored.evidence.push_back("buffer_address_materialized");
        }
    } else {
        if (window_has_bytes(bytes, lo, hi, {0x85, 0xc0}) || window_has_bytes(bytes, lo, hi, {0x83, 0xf8}) || window_has_bytes(bytes, lo, hi, {0x3d})) {
            scored.score += 0.09;
            scored.evidence.push_back("recv_result_checked_before_candidate");
        }
        if (window_has_bytes(bytes, lo, hi, {0x48, 0x8d}) || window_has_bytes(bytes, lo, hi, {0x48, 0x8b}) || window_has_bytes(bytes, lo, hi, {0x4c, 0x8d})) {
            scored.score += 0.04;
            scored.evidence.push_back("receive_buffer_forwarded_to_candidate");
        }
    }

    const auto bounds = target_function_bounds(bytes, base, call.target_va);
    if (bounds.first != bounds.second) {
        const std::size_t stores = count_store_like_ops(bytes, bounds.first, bounds.second);
        const std::size_t compares = count_compare_like_ops(bytes, bounds.first, bounds.second);
        const std::size_t nested_count = collect_internal_calls(bytes, bounds.first, bounds.second, base, excluded_targets).size();
        if (serializer && stores >= 3) {
            scored.score += 0.07;
            scored.evidence.push_back("candidate_body_has_multiple_store_ops");
        }
        if (!serializer && compares >= 3) {
            scored.score += 0.07;
            scored.evidence.push_back("candidate_body_has_multiple_compare_ops");
        }
        if (count_byte_pattern(bytes, bounds.first, bounds.second, {0x0f, 0xb6}) != 0 || count_byte_pattern(bytes, bounds.first, bounds.second, {0x0f, 0xb7}) != 0) {
            scored.score += 0.03;
            scored.evidence.push_back(serializer ? "candidate_body_byte_word_materialization" : "candidate_body_byte_word_parse");
        }
        if (nested_count != 0) {
            scored.score += 0.02;
            scored.evidence.push_back("candidate_body_has_nested_calls=" + std::to_string(nested_count));
            scored.nested_calls = nested_calls_to_json(bytes, base, call.target_va, excluded_targets);
        }
        scored.evidence.push_back("candidate_body_range=" + fmt_addr(base + bounds.first) + "-" + fmt_addr(base + bounds.second));
    }
    scored.score = (std::min)(0.93, scored.score);
    return scored;
}

nlohmann::json scored_calls_to_json(const std::vector<scored_call_t>& calls,
                                    std::size_t max_items)
{
    nlohmann::json out = nlohmann::json::array();
    for (const auto& c : calls) {
        if (out.size() >= max_items)
            break;
        nlohmann::json item;
        item["call_va"] = fmt_addr(c.call.call_va);
        item["target_va"] = fmt_addr(c.call.target_va);
        item["score"] = c.score;
        item["evidence"] = c.evidence;
        item["nested_calls"] = c.nested_calls;
        out.push_back(std::move(item));
    }
    return out;
}

int register_call_id(const std::vector<std::uint8_t>& bytes, std::size_t off, std::size_t& call_size)
{
    call_size = 0;
    if (off + 2 <= bytes.size() && bytes[off] == 0xff && bytes[off + 1] >= 0xd0 && bytes[off + 1] <= 0xd7) {
        call_size = 2;
        return bytes[off + 1] - 0xd0;
    }
    if (off + 3 <= bytes.size() && bytes[off] == 0x41 && bytes[off + 1] == 0xff && bytes[off + 2] >= 0xd0 && bytes[off + 2] <= 0xd7) {
        call_size = 3;
        return 8 + bytes[off + 2] - 0xd0;
    }
    return -1;
}

const api_target_t* resolve_recent_register_import_call(const std::vector<std::uint8_t>& bytes,
                                                        std::size_t call_off,
                                                        std::uint64_t base,
                                                        const std::map<std::uint64_t, const api_target_t*>& import_slots,
                                                        std::uint64_t& slot_va,
                                                        std::uint64_t& load_va)
{
    std::size_t call_size = 0;
    const int reg = register_call_id(bytes, call_off, call_size);
    if (reg < 0)
        return nullptr;
    (void)call_size;
    const std::size_t start = call_off > 48 ? call_off - 48 : 0;
    for (std::size_t j = call_off; j-- > start; ) {
        if (j + 7 > bytes.size())
            continue;
        const std::uint8_t rex = bytes[j];
        if ((rex != 0x48 && rex != 0x4c) || bytes[j + 1] != 0x8b)
            continue;
        const std::uint8_t modrm = bytes[j + 2];
        if ((modrm & 0xc7) != 0x05)
            continue;
        const int loaded_reg = ((modrm >> 3) & 0x7) + (rex == 0x4c ? 8 : 0);
        if (loaded_reg != reg)
            continue;
        std::int32_t rel = 0;
        std::memcpy(&rel, bytes.data() + j + 3, sizeof(rel));
        const std::uint64_t candidate_slot = rel32_target(base + j + 7, rel);
        auto it = import_slots.find(candidate_slot);
        if (it != import_slots.end()) {
            slot_va = candidate_slot;
            load_va = base + j;
            return it->second;
        }
    }
    return nullptr;
}

callsite_context_t analyze_sendrecv_context(const std::vector<std::uint8_t>& bytes,
                                            std::uint64_t bytes_base,
                                            std::size_t call_off,
                                            const api_target_t& api,
                                            const std::set<std::uint64_t>& excluded_targets)
{
    callsite_context_t ctx;
    if (call_off >= bytes.size())
        return ctx;
    const std::uint64_t function_start_va = find_probable_function_start(bytes, call_off, bytes_base);
    std::size_t function_start = function_start_va >= bytes_base && function_start_va < bytes_base + bytes.size()
        ? static_cast<std::size_t>(function_start_va - bytes_base)
        : (call_off > 512 ? call_off - 512 : 0);
    const std::size_t function_end = find_probable_function_end(bytes, call_off, function_start);
    const std::size_t block_start = find_basic_block_start(bytes, function_start, call_off);
    const std::size_t block_end = find_basic_block_end(bytes, call_off, function_end);
    ctx.function_start = bytes_base + function_start;
    ctx.function_end = bytes_base + function_end;
    ctx.basic_block_start = bytes_base + block_start;
    ctx.basic_block_end = bytes_base + block_end;

    auto upstream = collect_internal_calls(bytes, function_start, call_off, bytes_base, excluded_targets);
    auto downstream = collect_internal_calls(bytes, call_off + 5, function_end, bytes_base, excluded_targets);
    std::sort(upstream.begin(), upstream.end(), [call_off](const internal_call_t& a, const internal_call_t& b) {
        const std::size_t da = a.offset > call_off ? a.offset - call_off : call_off - a.offset;
        const std::size_t db = b.offset > call_off ? b.offset - call_off : call_off - b.offset;
        return da < db;
    });
    std::sort(downstream.begin(), downstream.end(), [call_off](const internal_call_t& a, const internal_call_t& b) {
        const std::size_t da = a.offset > call_off ? a.offset - call_off : call_off - a.offset;
        const std::size_t db = b.offset > call_off ? b.offset - call_off : call_off - b.offset;
        return da < db;
    });
    ctx.upstream_calls = calls_to_json(upstream, call_off, 8);
    ctx.downstream_calls = calls_to_json(downstream, call_off, 8);
    ctx.evidence.push_back("same_function_cfg_window");
    ctx.evidence.push_back("function_start=" + fmt_addr(ctx.function_start));
    ctx.evidence.push_back("basic_block=" + fmt_addr(ctx.basic_block_start) + "-" + fmt_addr(ctx.basic_block_end));

    if (api.direction == "send" && !upstream.empty()) {
        std::vector<scored_call_t> scored;
        for (const auto& c : upstream)
            scored.push_back(score_internal_call_candidate(bytes, bytes_base, c, call_off, block_start, block_end, true, excluded_targets));
        std::sort(scored.begin(), scored.end(), [](const scored_call_t& a, const scored_call_t& b) {
            if (std::fabs(a.score - b.score) > 0.0001)
                return a.score > b.score;
            return a.call.offset > b.call.offset;
        });
        const auto& best = scored.front();
        ctx.serializer_candidate = best.call.target_va;
        ctx.candidate_confidence = best.score;
        ctx.upstream_calls = scored_calls_to_json(scored, 8);
        ctx.evidence.push_back("ranked_upstream_serializer_walk");
        for (const auto& item : best.evidence)
            ctx.evidence.push_back(item);
        ctx.evidence.push_back("upstream_serializer_candidate=" + fmt_addr(best.call.target_va));
    } else if (api.direction == "recv" && !downstream.empty()) {
        std::vector<scored_call_t> scored;
        for (const auto& c : downstream)
            scored.push_back(score_internal_call_candidate(bytes, bytes_base, c, call_off, block_start, block_end, false, excluded_targets));
        std::sort(scored.begin(), scored.end(), [](const scored_call_t& a, const scored_call_t& b) {
            if (std::fabs(a.score - b.score) > 0.0001)
                return a.score > b.score;
            return a.call.offset < b.call.offset;
        });
        const auto& best = scored.front();
        ctx.deserializer_candidate = best.call.target_va;
        ctx.candidate_confidence = best.score;
        ctx.downstream_calls = scored_calls_to_json(scored, 8);
        ctx.evidence.push_back("ranked_downstream_deserializer_walk");
        for (const auto& item : best.evidence)
            ctx.evidence.push_back(item);
        ctx.evidence.push_back("downstream_deserializer_candidate=" + fmt_addr(best.call.target_va));
    } else {
        ctx.candidate_confidence = 0.38;
        ctx.evidence.push_back(api.direction == "send" ? "no_upstream_internal_serializer_call_in_window" : "no_downstream_internal_deserializer_call_in_window");
    }
    return ctx;
}

void add_sendrecv_result(nlohmann::json& results,
                         std::set<std::uint64_t>& seen_callsites,
                         const driver_bridge::module_info_t& module,
                         const std::vector<std::uint8_t>& bytes,
                         std::uint64_t bytes_base,
                         const api_target_t& api,
                         std::uint64_t callsite,
                         std::uint64_t handler,
                         std::uint64_t adjacent,
                         bool iat_indirect,
                         const std::set<std::uint64_t>& excluded_targets,
                         std::uint32_t max_results)
{
    if (results.size() >= max_results || !seen_callsites.insert(callsite).second)
        return;

    if (callsite < bytes_base)
        return;
    const std::size_t call_off = static_cast<std::size_t>(callsite - bytes_base);
    if (call_off >= bytes.size())
        return;
    callsite_context_t ctx = analyze_sendrecv_context(bytes, bytes_base, call_off, api, excluded_targets);
    if (adjacent != 0 && api.direction == "send" && ctx.serializer_candidate == 0) {
        ctx.serializer_candidate = adjacent;
        ctx.candidate_confidence = (std::max)(ctx.candidate_confidence, 0.54);
        ctx.evidence.push_back("explicit_adjacent_serializer_candidate");
    } else if (adjacent != 0 && api.direction == "recv" && ctx.deserializer_candidate == 0) {
        ctx.deserializer_candidate = adjacent;
        ctx.candidate_confidence = (std::max)(ctx.candidate_confidence, 0.54);
        ctx.evidence.push_back("explicit_adjacent_deserializer_candidate");
    } else if (api.direction == "send" && ctx.serializer_candidate == 0) {
        const std::uint64_t fallback = nearest_internal_call(bytes, call_off, bytes_base, excluded_targets, false);
        if (fallback != 0 && va_in_scan(fallback, bytes_base, bytes.size())) {
            ctx.serializer_candidate = fallback;
            ctx.candidate_confidence = (std::max)(ctx.candidate_confidence, 0.46);
            ctx.evidence.push_back("low_confidence_nearest_call_fallback");
        }
    } else if (api.direction == "recv" && ctx.deserializer_candidate == 0) {
        const std::uint64_t fallback = nearest_internal_call(bytes, call_off, bytes_base, excluded_targets, true);
        if (fallback != 0 && va_in_scan(fallback, bytes_base, bytes.size())) {
            ctx.deserializer_candidate = fallback;
            ctx.candidate_confidence = (std::max)(ctx.candidate_confidence, 0.46);
            ctx.evidence.push_back("low_confidence_nearest_call_fallback");
        }
    }

    nlohmann::json r;
    r["direction"] = api.direction;
    r["api"] = api.name;
    r["api_call_va"] = fmt_addr(callsite);
    r["api_target_va"] = fmt_addr(api.address);
    r["handler_va"] = fmt_addr(handler);
    r["module"] = module.name;
    r["serializer_va"] = nullptr;
    r["deserializer_va"] = nullptr;
    if (api.direction == "send" && ctx.serializer_candidate != 0)
        r["serializer_va"] = fmt_addr(ctx.serializer_candidate);
    else if (api.direction == "recv" && ctx.deserializer_candidate != 0)
        r["deserializer_va"] = fmt_addr(ctx.deserializer_candidate);
    nlohmann::json handler_range;
    handler_range["start"] = fmt_addr(ctx.function_start ? ctx.function_start : handler);
    handler_range["end"] = ctx.function_end ? nlohmann::json(fmt_addr(ctx.function_end)) : nlohmann::json(nullptr);
    handler_range["basic_block_start"] = ctx.basic_block_start ? nlohmann::json(fmt_addr(ctx.basic_block_start)) : nlohmann::json(nullptr);
    handler_range["basic_block_end"] = ctx.basic_block_end ? nlohmann::json(fmt_addr(ctx.basic_block_end)) : nlohmann::json(nullptr);
    r["handler_range"] = std::move(handler_range);
    r["upstream_calls"] = ctx.upstream_calls;
    r["downstream_calls"] = ctx.downstream_calls;
    r["serializer_candidate"] = {
        {"va", ctx.serializer_candidate ? nlohmann::json(fmt_addr(ctx.serializer_candidate)) : nlohmann::json(nullptr)},
        {"confidence", api.direction == "send" ? ctx.candidate_confidence : 0.0},
        {"method", "same_function_cfg_window"}
    };
    r["deserializer_candidate"] = {
        {"va", ctx.deserializer_candidate ? nlohmann::json(fmt_addr(ctx.deserializer_candidate)) : nlohmann::json(nullptr)},
        {"confidence", api.direction == "recv" ? ctx.candidate_confidence : 0.0},
        {"method", "same_function_cfg_window"}
    };
    r["confidence"] = (std::min)(0.94, (iat_indirect ? 0.72 : 0.66) + (ctx.candidate_confidence >= 0.6 ? 0.12 : 0.0));
    nlohmann::json evidence = nlohmann::json::array({
        iat_indirect ? "call_indirect_through_import_slot" : "direct_relative_call_or_import_thunk",
        "handler_start_heuristic=" + fmt_addr(handler)
    });
    if (ctx.evidence.is_array()) {
        for (const auto& item : ctx.evidence)
            evidence.push_back(item);
    }
    r["evidence"] = std::move(evidence);
    results.push_back(std::move(r));
}

std::string endpoint_key(const driver_bridge::captured_packet_t& p)
{
    const std::string a = format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
    const std::string b = format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
    return a < b ? a + "<->" + b : b + "<->" + a;
}

std::string packet_src(const driver_bridge::captured_packet_t& p)
{
    if (p.direction == 0)
        return format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
    return format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
}

std::string packet_dst(const driver_bridge::captured_packet_t& p)
{
    if (p.direction == 0)
        return format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
    return format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
}

udp_fragment_info_t choose_fragment_info(const udp_fragment_info_t& current,
                                         const udp_fragment_info_t& candidate)
{
    if (!candidate.valid)
        return current;
    if (!current.valid || candidate.confidence > current.confidence)
        return candidate;
    return current;
}

udp_fragment_info_t parse_udp_fragment_header(const std::vector<std::uint8_t>& data)
{
    udp_fragment_info_t best;
    auto consider = [&](std::size_t header_size, bool has_ack, bool big, const char* scheme) {
        if (data.size() < header_size)
            return;
        const std::uint64_t seq = big ? be32(data.data()) : le32(data.data());
        const std::uint64_t ack = has_ack ? (big ? be32(data.data() + 4) : le32(data.data() + 4)) : 0;
        const std::size_t base = has_ack ? 8 : 4;
        const std::uint32_t frag_id = big ? be16(data.data() + base) : le16(data.data() + base);
        const std::uint32_t frag_index = big ? be16(data.data() + base + 2) : le16(data.data() + base + 2);
        const std::uint32_t frag_count = big ? be16(data.data() + base + 4) : le16(data.data() + base + 4);
        const std::uint32_t declared = big ? be16(data.data() + base + 6) : le16(data.data() + base + 6);
        const std::size_t available = data.size() - header_size;
        if (frag_count < 2 || frag_count > 1024 || frag_index >= frag_count || declared == 0 || declared > available)
            return;
        udp_fragment_info_t c;
        c.valid = true;
        c.header_size = header_size;
        c.sequence = seq;
        c.ack = ack;
        c.fragment_id = frag_id;
        c.fragment_index = frag_index;
        c.fragment_count = frag_count;
        c.fragment_offset = frag_index * declared;
        c.declared_payload_size = declared;
        c.logical_size = 0;
        c.scheme = scheme;
        c.confidence = 0.78;
        if (declared == available)
            c.confidence += 0.08;
        if (seq != 0 || ack != 0)
            c.confidence += 0.04;
        c.evidence = nlohmann::json::array({
            has_ack ? "sequence_ack_fragment_header" : "sequence_fragment_header",
            big ? "big_endian_header" : "little_endian_header",
            "fragment_index=" + std::to_string(frag_index),
            "fragment_count=" + std::to_string(frag_count)
        });
        best = choose_fragment_info(best, c);
    };
    consider(16, true, true, "seq_ack_frag16be");
    consider(16, true, false, "seq_ack_frag16le");
    consider(12, false, true, "seq_frag12be");
    consider(12, false, false, "seq_frag12le");

    if (data.size() >= 28) {
        const std::uint8_t command_id = data[4] & 0x0f;
        if (command_id == 8 || command_id == 12) {
            const std::uint32_t count = be32(data.data() + 12);
            const std::uint32_t index = be32(data.data() + 16);
            const std::uint32_t total_length = be32(data.data() + 20);
            const std::uint32_t fragment_offset = be32(data.data() + 24);
            if (count >= 2 && count <= 4096 && index < count && total_length >= data.size() - 28 && fragment_offset < total_length) {
                udp_fragment_info_t c;
                c.valid = true;
                c.header_size = 28;
                c.sequence = be16(data.data() + 6);
                c.ack = be16(data.data() + 2);
                c.fragment_id = static_cast<std::uint32_t>(c.sequence & 0xffffffffu);
                c.fragment_index = index;
                c.fragment_count = count;
                c.fragment_offset = fragment_offset;
                c.declared_payload_size = static_cast<std::uint32_t>(data.size() - 28);
                c.logical_size = total_length;
                c.scheme = "enet_send_fragment";
                c.confidence = 0.86;
                c.evidence = nlohmann::json::array({
                    "enet_fragment_command",
                    "fragment_offset=" + std::to_string(fragment_offset),
                    "fragment_count=" + std::to_string(count)
                });
                best = choose_fragment_info(best, c);
            }
        }
    }
    return best;
}

void fill_udp_message_endpoints(udp_message_t& m, const driver_bridge::captured_packet_t& p)
{
    m.local_port = p.local_port;
    m.remote_port = p.remote_port;
    m.address_family = p.address_family;
    std::memcpy(m.local_addr, p.local_addr, sizeof(m.local_addr));
    std::memcpy(m.remote_addr, p.remote_addr, sizeof(m.remote_addr));
    m.src = packet_src(p);
    m.dst = packet_dst(p);
    if (p.direction == 0) {
        m.src_ip = format_ip(p.remote_addr, p.address_family);
        m.src_port = p.remote_port;
        m.dst_ip = format_ip(p.local_addr, p.address_family);
        m.dst_port = p.local_port;
    } else {
        m.src_ip = format_ip(p.local_addr, p.address_family);
        m.src_port = p.local_port;
        m.dst_ip = format_ip(p.remote_addr, p.address_family);
        m.dst_port = p.remote_port;
    }
}

std::vector<udp_message_t> split_udp_messages(const driver_bridge::captured_packet_t& p)
{
    std::vector<udp_message_t> messages;
    const auto& data = p.payload;
    if (data.empty())
        return messages;

    auto make_message = [&](std::uint64_t seq, std::size_t off, std::size_t len, const std::string& scheme) {
        udp_message_t m;
        m.sequence = seq;
        m.payload.assign(data.begin() + static_cast<std::ptrdiff_t>(off),
                         data.begin() + static_cast<std::ptrdiff_t>(off + len));
        fill_udp_message_endpoints(m, p);
        m.scheme = scheme;
        messages.push_back(std::move(m));
    };

    const udp_fragment_info_t fragment = parse_udp_fragment_header(data);
    if (fragment.valid && fragment.header_size < data.size()) {
        udp_message_t m;
        m.sequence = fragment.sequence;
        m.ack = fragment.ack;
        m.fragment_id = fragment.fragment_id;
        m.fragment_index = fragment.fragment_index;
        m.fragment_count = fragment.fragment_count;
        m.fragment_offset = fragment.fragment_offset;
        m.logical_size = fragment.logical_size;
        m.reassembly_complete = false;
        m.reassembly_evidence = fragment.evidence;
        m.payload.assign(data.begin() + static_cast<std::ptrdiff_t>(fragment.header_size),
                         data.begin() + static_cast<std::ptrdiff_t>(fragment.header_size + (std::min<std::size_t>)(fragment.declared_payload_size, data.size() - fragment.header_size)));
        fill_udp_message_endpoints(m, p);
        m.scheme = fragment.scheme;
        messages.push_back(std::move(m));
        return messages;
    }

    bool split = false;
    if (data.size() >= 4) {
        for (bool little : {true, false}) {
            std::size_t off = 0;
            std::uint64_t seq = 0;
            std::vector<std::pair<std::size_t, std::size_t>> frames;
            while (off + 2 <= data.size() && frames.size() < 64) {
                const std::uint16_t len = little ? le16(data.data() + off) : be16(data.data() + off);
                if (len == 0 || len > 4096 || off + 2 + len > data.size())
                    break;
                frames.push_back({off + 2, len});
                off += 2 + len;
            }
            if (off == data.size() && frames.size() >= 1) {
                for (const auto& f : frames)
                    make_message(seq++, f.first, f.second, little ? "u16le_length_prefixed" : "u16be_length_prefixed");
                split = true;
                break;
            }
        }
    }
    if (split)
        return messages;

    std::uint64_t seq = 0;
    std::string scheme = "single_datagram";
    if (data.size() >= 8 && (data[4] & 0x0f) >= 1 && (data[4] & 0x0f) <= 12) {
        seq = be16(data.data() + 6);
        scheme = "enet_like_sequence";
    } else if (data.size() >= 4) {
        const std::uint32_t a = be32(data.data());
        const std::uint32_t b = le32(data.data());
        seq = (a < 0x01000000u) ? a : b;
        scheme = "u32_sequence_candidate";
    } else if (data.size() >= 2) {
        seq = be16(data.data());
        scheme = "u16_sequence_candidate";
    }
    make_message(seq, 0, data.size(), scheme);
    return messages;
}

std::string udp_fragment_group_key(const std::string& session_key, const udp_message_t& m)
{
    std::ostringstream os;
    os << session_key << "|" << m.src << ">" << m.dst << "|"
       << m.scheme << "|" << m.sequence << "|" << m.ack << "|"
       << m.fragment_id << "|" << m.fragment_count;
    return os.str();
}

void append_udp_message_limited(udp_session_t& session, udp_message_t&& message)
{
    if (session.messages.size() < 256)
        session.messages.push_back(std::move(message));
}

bool reassemble_fragment_group(const udp_fragment_group_t& group, udp_message_t& out)
{
    if (group.pieces.empty())
        return false;
    std::map<std::uint32_t, const udp_message_t*> by_index;
    std::uint32_t expected = group.pieces.front().fragment_count;
    if (expected < 2 || expected > 4096)
        return false;
    bool has_offset_evidence = false;
    std::uint32_t logical_size = 0;
    for (const auto& piece : group.pieces) {
        if (piece.fragment_count != expected || piece.fragment_index >= expected)
            return false;
        if (piece.logical_size != 0) {
            has_offset_evidence = true;
            logical_size = (std::max)(logical_size, piece.logical_size);
        }
        by_index[piece.fragment_index] = &piece;
    }
    if (by_index.size() != expected)
        return false;
    out = group.pieces.front();
    out.payload.clear();
    out.reassembly_evidence = nlohmann::json::array();
    out.reassembly_evidence.push_back("all_fragments_present");
    out.reassembly_evidence.push_back("fragment_count=" + std::to_string(expected));
    if (has_offset_evidence) {
        if (logical_size == 0 || logical_size > 1048576)
            return false;
        std::vector<std::uint8_t> assembled(logical_size);
        std::vector<bool> covered(logical_size, false);
        for (const auto& [index, piece] : by_index) {
            (void)index;
            const std::size_t off = piece->fragment_offset;
            if (off > assembled.size() || piece->payload.size() > assembled.size() - off)
                return false;
            for (std::size_t i = 0; i < piece->payload.size(); ++i) {
                if (covered[off + i])
                    return false;
                assembled[off + i] = piece->payload[i];
                covered[off + i] = true;
            }
        }
        for (bool b : covered)
            if (!b)
                return false;
        out.payload = std::move(assembled);
        out.logical_size = logical_size;
        out.reassembly_evidence.push_back("fragment_offsets_cover_declared_logical_size");
    } else {
        for (std::uint32_t i = 0; i < expected; ++i) {
            auto it = by_index.find(i);
            if (it == by_index.end())
                return false;
            out.payload.insert(out.payload.end(), it->second->payload.begin(), it->second->payload.end());
        }
        out.logical_size = static_cast<std::uint32_t>((std::min<std::size_t>)(out.payload.size(), std::numeric_limits<std::uint32_t>::max()));
        out.reassembly_evidence.push_back("fragment_index_order_reassembly");
    }
    out.reassembled = true;
    out.reassembly_complete = true;
    out.fragment_index = 0;
    out.scheme += "_reassembled";
    return true;
}

nlohmann::json udp_message_to_json(const udp_message_t& message)
{
    nlohmann::json mj;
    mj["sequence"] = message.sequence;
    mj["ack"] = message.ack;
    mj["scheme"] = message.scheme;
    mj["src"] = message.src;
    mj["dst"] = message.dst;
    mj["src_ip"] = message.src_ip;
    mj["src_port"] = message.src_port;
    mj["dst_ip"] = message.dst_ip;
    mj["dst_port"] = message.dst_port;
    mj["local_ip"] = format_ip(message.local_addr, message.address_family);
    mj["local_port"] = message.local_port;
    mj["remote_ip"] = format_ip(message.remote_addr, message.address_family);
    mj["remote_port"] = message.remote_port;
    mj["payload_size"] = message.payload.size();
    mj["payload_hex"] = game_protocol::bytes_to_hex(message.payload, 128);
    mj["reassembled"] = message.reassembled;
    mj["reassembly_complete"] = message.reassembly_complete;
    if (message.fragment_count != 0) {
        mj["fragment_id"] = message.fragment_id;
        mj["fragment_index"] = message.fragment_index;
        mj["fragment_count"] = message.fragment_count;
        mj["fragment_offset"] = message.fragment_offset;
        mj["logical_size"] = message.logical_size;
        mj["reassembly_evidence"] = message.reassembly_evidence;
    }
    return mj;
}

std::uint64_t read_integer_field(const std::vector<std::uint8_t>& payload,
                                 std::size_t off,
                                 std::size_t size,
                                 bool big_endian)
{
    std::uint64_t value = 0;
    if (off >= payload.size())
        return 0;
    const std::size_t available = (std::min)(size, payload.size() - off);
    for (std::size_t i = 0; i < available; ++i) {
        const std::size_t index = big_endian ? i : available - 1 - i;
        value = (value << 8) | payload[off + index];
    }
    return value;
}

void write_integer_field(std::vector<std::uint8_t>& payload,
                         std::size_t off,
                         std::size_t size,
                         bool big_endian,
                         std::uint64_t value)
{
    for (std::size_t i = 0; i < size && off + i < payload.size(); ++i) {
        const std::size_t shift_index = big_endian ? size - 1 - i : i;
        payload[off + i] = static_cast<std::uint8_t>((value >> (shift_index * 8)) & 0xffu);
    }
}

std::uint64_t integer_mask(std::size_t size)
{
    if (size >= 8)
        return std::numeric_limits<std::uint64_t>::max();
    return (1ULL << (size * 8)) - 1ULL;
}

bool uniform_field_bytes(const std::vector<std::uint8_t>& payload, std::size_t off, std::size_t size, std::uint8_t value)
{
    if (off + size > payload.size())
        return false;
    for (std::size_t i = 0; i < size; ++i)
        if (payload[off + i] != value)
            return false;
    return true;
}

bool printable_ascii_field(const std::vector<std::uint8_t>& payload, std::size_t off, std::size_t size)
{
    if (size < 2 || off + size > payload.size())
        return false;
    for (std::size_t i = 0; i < size; ++i) {
        const std::uint8_t c = payload[off + i];
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    return true;
}

void add_numeric_candidate(std::vector<numeric_field_candidate_t>& out,
                           const numeric_field_candidate_t& candidate)
{
    if (candidate.offset + candidate.size == 0)
        return;
    for (auto& existing : out) {
        if (existing.offset == candidate.offset && existing.size == candidate.size && existing.big_endian == candidate.big_endian) {
            if (candidate.confidence > existing.confidence)
                existing = candidate;
            return;
        }
    }
    out.push_back(candidate);
}

std::vector<numeric_field_candidate_t> numeric_field_candidates(const udp_session_t& session,
                                                               const udp_message_t& message)
{
    std::vector<numeric_field_candidate_t> out;
    const auto& payload = message.payload;
    const std::size_t limit = (std::min)(payload.size(), std::size_t(512));
    static const std::size_t sizes[] = {1, 2, 4, 8};
    for (std::size_t off = 0; off < limit && out.size() < 128; ++off) {
        for (std::size_t size : sizes) {
            if (off + size > limit)
                continue;
            if (uniform_field_bytes(payload, off, size, 0x00) || uniform_field_bytes(payload, off, size, 0xff))
                continue;
            if (printable_ascii_field(payload, off, size))
                continue;
            const bool endian_modes[] = {false, true};
            for (bool big : endian_modes) {
                if (size == 1 && big)
                    continue;
                const std::uint64_t value = read_integer_field(payload, off, size, big);
                if (value == 0 || value == integer_mask(size))
                    continue;
                numeric_field_candidate_t c;
                c.offset = off;
                c.size = size;
                c.big_endian = big;
                c.value = value;
                c.type = "integer";
                c.confidence = 0.34;
                c.evidence.push_back(big ? "big_endian_interpretation" : "little_endian_interpretation");
                if (off % size == 0) {
                    c.confidence += 0.08;
                    c.evidence.push_back("natural_alignment");
                }
                if (off <= 16) {
                    c.confidence += 0.04;
                    c.evidence.push_back("protocol_header_region");
                }
                const std::size_t remaining_after_field = payload.size() > off + size ? payload.size() - off - size : 0;
                if ((size == 2 || size == 4) && (value == payload.size() || value == remaining_after_field || value == payload.size() - off)) {
                    c.type = "length";
                    c.confidence += 0.24;
                    c.evidence.push_back("matches_payload_or_remaining_length");
                }
                if (message.fragment_count >= 2 && (value == message.fragment_index || value == message.fragment_count || value == message.fragment_offset || value == message.logical_size)) {
                    c.type = "fragment_metadata";
                    c.confidence += 0.18;
                    c.evidence.push_back("matches_reassembly_metadata");
                }
                std::vector<std::uint64_t> peer_values;
                for (const auto& peer : session.messages) {
                    if (&peer == &message || peer.payload.size() < off + size)
                        continue;
                    if (peer.payload.size() != payload.size() && c.type != "length")
                        continue;
                    const std::uint64_t peer_value = read_integer_field(peer.payload, off, size, big);
                    if (peer_value != 0 && peer_value != integer_mask(size))
                        peer_values.push_back(peer_value);
                }
                if (!peer_values.empty()) {
                    std::set<std::uint64_t> distinct(peer_values.begin(), peer_values.end());
                    distinct.insert(value);
                    if (distinct.size() > 1) {
                        c.confidence += 0.12;
                        c.evidence.push_back("varies_across_session_messages");
                        bool monotonic = true;
                        std::uint64_t prev = value;
                        for (std::uint64_t peer_value : peer_values) {
                            if (peer_value < prev) {
                                monotonic = false;
                                break;
                            }
                            prev = peer_value;
                        }
                        if (monotonic) {
                            c.type = c.type == "integer" ? "counter_or_sequence" : c.type;
                            c.confidence += 0.07;
                            c.evidence.push_back("nondecreasing_across_session_messages");
                        }
                    }
                }
                if (value <= 0xffff && c.type == "integer") {
                    c.type = "small_integer";
                    c.confidence += 0.03;
                }
                if (c.confidence >= 0.45)
                    add_numeric_candidate(out, c);
            }
        }
    }
    std::sort(out.begin(), out.end(), [](const numeric_field_candidate_t& a, const numeric_field_candidate_t& b) {
        if (std::fabs(a.confidence - b.confidence) > 0.0001)
            return a.confidence > b.confidence;
        if (a.offset != b.offset)
            return a.offset < b.offset;
        return a.size > b.size;
    });
    if (out.size() > 80)
        out.resize(80);
    if (out.empty() && !payload.empty()) {
        numeric_field_candidate_t c;
        c.offset = 0;
        c.size = 1;
        c.big_endian = false;
        c.value = payload[0];
        c.type = "single_byte_fallback";
        c.confidence = 0.28;
        c.evidence = nlohmann::json::array({"no_structured_numeric_field_detected", "fallback_first_byte"});
        out.push_back(std::move(c));
    }
    return out;
}

nlohmann::json numeric_field_to_json(const numeric_field_candidate_t& field)
{
    nlohmann::json f;
    f["offset"] = field.offset;
    f["size"] = field.size;
    f["endian"] = field.big_endian ? "big" : "little";
    f["value"] = field.value;
    f["type"] = field.type;
    f["confidence"] = field.confidence;
    f["evidence"] = field.evidence;
    return f;
}

std::vector<std::uint64_t> boundary_values_for_size(std::size_t size)
{
    std::vector<std::uint64_t> values = {0ULL, 1ULL};
    if (size >= 1) {
        values.push_back(0x7fULL);
        values.push_back(0x80ULL);
        values.push_back(0xffULL);
    }
    if (size >= 2) {
        values.push_back(0x100ULL);
        values.push_back(0x7fffULL);
        values.push_back(0x8000ULL);
        values.push_back(0xffffULL);
    }
    if (size >= 4) {
        values.push_back(0x10000ULL);
        values.push_back(0x7fffffffULL);
        values.push_back(0x80000000ULL);
        values.push_back(0xffffffffULL);
    }
    if (size >= 8) {
        values.push_back(0x100000000ULL);
        values.push_back(0x7fffffffffffffffULL);
        values.push_back(0x8000000000000000ULL);
        values.push_back(std::numeric_limits<std::uint64_t>::max());
    }
    const std::uint64_t mask = integer_mask(size);
    for (auto& v : values)
        v &= mask;
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

std::uint64_t stable_payload_seed(const udp_session_t& session)
{
    std::uint64_t h = 1469598103934665603ULL;
    auto mix = [&](std::uint8_t b) {
        h ^= b;
        h *= 1099511628211ULL;
    };
    for (char c : session.id)
        mix(static_cast<std::uint8_t>(c));
    for (const auto& message : session.messages) {
        for (std::uint8_t b : message.payload)
            mix(b);
    }
    return h;
}

std::vector<mutation_payload_t> make_mutations(const udp_session_t& session,
                                               const std::string& strategy,
                                               std::uint32_t max_mutations,
                                               std::uint32_t payload_cap,
                                               nlohmann::json& field_inventory)
{
    std::vector<mutation_payload_t> out;
    std::set<std::vector<std::uint8_t>> seen;
    std::uint64_t lcg = 0xA1DA5EED12345678ULL ^ stable_payload_seed(session);
    field_inventory = nlohmann::json::array();

    std::size_t message_index = 0;
    for (const auto& message : session.messages) {
        if (out.size() >= max_mutations)
            break;
        if (message.payload.empty() || message.payload.size() > payload_cap) {
            ++message_index;
            continue;
        }

        auto fields = numeric_field_candidates(session, message);
        nlohmann::json message_fields;
        message_fields["message_index"] = message_index;
        message_fields["scheme"] = message.scheme;
        message_fields["payload_size"] = message.payload.size();
        message_fields["field_count"] = fields.size();
        message_fields["fields"] = nlohmann::json::array();
        for (const auto& field : fields) {
            if (message_fields["fields"].size() >= 24)
                break;
            message_fields["fields"].push_back(numeric_field_to_json(field));
        }
        if (field_inventory.size() < 32)
            field_inventory.push_back(std::move(message_fields));

        if (strategy == "bitflip") {
            for (const auto& field : fields) {
                for (std::size_t byte_index : {std::size_t(0), field.size - 1}) {
                    if (out.size() >= max_mutations)
                        break;
                    auto m = message.payload;
                    const std::size_t byte_off = field.offset + byte_index;
                    if (byte_off >= m.size())
                        continue;
                    const std::uint8_t bit = byte_index == 0 ? std::uint8_t(0x01) : std::uint8_t(0x80);
                    m[byte_off] ^= bit;
                    if (seen.insert(m).second) {
                        mutation_payload_t mp;
                        mp.payload = std::move(m);
                        mp.source_message_index = message_index;
                        mp.field_offset = field.offset;
                        mp.field_size = field.size;
                        mp.big_endian = field.big_endian;
                        mp.original_value = field.value;
                        mp.mutated_value = read_integer_field(mp.payload, field.offset, field.size, field.big_endian);
                        mp.strategy = strategy;
                        mp.evidence = nlohmann::json::array({"bitflip_numeric_field", numeric_field_to_json(field)});
                        out.push_back(std::move(mp));
                    }
                }
            }
        } else if (strategy == "random") {
            for (const auto& field : fields) {
                if (out.size() >= max_mutations)
                    break;
                lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
                auto m = message.payload;
                const std::uint64_t value = lcg & integer_mask(field.size);
                write_integer_field(m, field.offset, field.size, field.big_endian, value);
                if (seen.insert(m).second) {
                    mutation_payload_t mp;
                    mp.payload = std::move(m);
                    mp.source_message_index = message_index;
                    mp.field_offset = field.offset;
                    mp.field_size = field.size;
                    mp.big_endian = field.big_endian;
                    mp.original_value = field.value;
                    mp.mutated_value = value;
                    mp.strategy = strategy;
                    mp.evidence = nlohmann::json::array({"deterministic_lcg_numeric_field", numeric_field_to_json(field)});
                    out.push_back(std::move(mp));
                }
            }
        } else {
            for (const auto& field : fields) {
                for (std::uint64_t value : boundary_values_for_size(field.size)) {
                    if (out.size() >= max_mutations)
                        break;
                    if (value == field.value)
                        continue;
                    auto m = message.payload;
                    write_integer_field(m, field.offset, field.size, field.big_endian, value);
                    if (seen.insert(m).second) {
                        mutation_payload_t mp;
                        mp.payload = std::move(m);
                        mp.source_message_index = message_index;
                        mp.field_offset = field.offset;
                        mp.field_size = field.size;
                        mp.big_endian = field.big_endian;
                        mp.original_value = field.value;
                        mp.mutated_value = value;
                        mp.strategy = strategy;
                        mp.evidence = nlohmann::json::array({"boundary_numeric_field", numeric_field_to_json(field)});
                        out.push_back(std::move(mp));
                    }
                }
            }
        }
        ++message_index;
    }
    return out;
}

bool valid_mutation_strategy(const std::string& strategy)
{
    return strategy == "boundary" || strategy == "random" || strategy == "bitflip";
}

bool same_ipv4(const std::uint8_t* a, const std::uint8_t* b)
{
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

nlohmann::json payload_diff_summary(const std::vector<std::uint8_t>& reference,
                                    const std::vector<std::uint8_t>& observed,
                                    const std::string& label)
{
    const std::size_t compared = (std::min)((std::min)(reference.size(), observed.size()), std::size_t(512));
    std::size_t changed = 0;
    std::size_t first_diff = std::numeric_limits<std::size_t>::max();
    for (std::size_t i = 0; i < compared; ++i) {
        if (reference[i] != observed[i]) {
            if (first_diff == std::numeric_limits<std::size_t>::max())
                first_diff = i;
            ++changed;
        }
    }
    if (reference.size() != observed.size() && first_diff == std::numeric_limits<std::size_t>::max())
        first_diff = compared;
    nlohmann::json diff;
    diff["reference"] = label;
    diff["reference_size"] = reference.size();
    diff["observed_size"] = observed.size();
    diff["compared_prefix_bytes"] = compared;
    diff["changed_prefix_bytes"] = changed;
    diff["size_delta"] = static_cast<std::int64_t>(observed.size()) - static_cast<std::int64_t>(reference.size());
    diff["first_diff_offset"] = first_diff == std::numeric_limits<std::size_t>::max() ? nlohmann::json(nullptr) : nlohmann::json(first_diff);
    return diff;
}

nlohmann::json best_payload_diff(const std::vector<std::uint8_t>& observed,
                                 const udp_session_t& session,
                                 const std::vector<mutation_payload_t>& mutations,
                                 const std::string& set_name)
{
    bool found = false;
    nlohmann::json best;
    std::uint64_t best_score = std::numeric_limits<std::uint64_t>::max();
    if (set_name == "original") {
        for (std::size_t i = 0; i < session.messages.size() && i < 128; ++i) {
            const auto diff = payload_diff_summary(session.messages[i].payload, observed, "original_message_" + std::to_string(i));
            const std::int64_t delta = diff.value("size_delta", 0ll);
            const std::uint64_t score = diff.value("changed_prefix_bytes", 0ull) +
                static_cast<std::uint64_t>(delta < 0 ? -delta : delta);
            if (!found || score < best_score) {
                found = true;
                best_score = score;
                best = diff;
            }
        }
    } else {
        for (std::size_t i = 0; i < mutations.size() && i < 128; ++i) {
            const auto diff = payload_diff_summary(mutations[i].payload, observed, "mutation_" + std::to_string(i));
            const std::int64_t delta = diff.value("size_delta", 0ll);
            const std::uint64_t score = diff.value("changed_prefix_bytes", 0ull) +
                static_cast<std::uint64_t>(delta < 0 ? -delta : delta);
            if (!found || score < best_score) {
                found = true;
                best_score = score;
                best = diff;
            }
        }
    }
    if (!found)
        return nlohmann::json(nullptr);
    best["score"] = best_score;
    return best;
}

bool payload_seen_in_mutations(const std::vector<std::uint8_t>& payload,
                               const std::vector<mutation_payload_t>& mutations)
{
    for (const auto& m : mutations)
        if (m.payload == payload)
            return true;
    return false;
}

nlohmann::json classify_response_packet(const driver_bridge::captured_packet_t& p,
                                        const std::uint8_t* target_addr,
                                        std::uint32_t target_port,
                                        std::uint32_t source_port,
                                        const udp_session_t& session,
                                        const std::vector<mutation_payload_t>& mutations,
                                        bool& interesting)
{
    const bool remote_is_target = p.address_family == 2 && same_ipv4(p.remote_addr, target_addr) && p.remote_port == target_port;
    const bool local_is_target = p.address_family == 2 && same_ipv4(p.local_addr, target_addr) && p.local_port == target_port;
    const bool inbound_from_target = p.direction == 0 && remote_is_target && (source_port == 0 || p.local_port == source_port);
    const bool outbound_to_target = p.direction != 0 && remote_is_target && (source_port == 0 || p.local_port == source_port);
    const bool target_local_response = p.direction == 0 && local_is_target;
    const bool echoed_mutation = payload_seen_in_mutations(p.payload, mutations);

    nlohmann::json r;
    r["pid"] = p.pid;
    r["direction"] = p.direction == 0 ? "inbound" : "outbound";
    r["src"] = packet_src(p);
    r["dst"] = packet_dst(p);
    if (p.direction == 0) {
        r["src_ip"] = format_ip(p.remote_addr, p.address_family);
        r["src_port"] = p.remote_port;
        r["dst_ip"] = format_ip(p.local_addr, p.address_family);
        r["dst_port"] = p.local_port;
    } else {
        r["src_ip"] = format_ip(p.local_addr, p.address_family);
        r["src_port"] = p.local_port;
        r["dst_ip"] = format_ip(p.remote_addr, p.address_family);
        r["dst_port"] = p.remote_port;
    }
    r["local"] = format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
    r["remote"] = format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
    r["payload_size"] = p.payload.size();
    r["hex_preview"] = game_protocol::bytes_to_hex(p.payload, 96);
    r["diff_vs_original"] = best_payload_diff(p.payload, session, mutations, "original");
    r["diff_vs_mutation"] = best_payload_diff(p.payload, session, mutations, "mutation");

    interesting = false;
    if (inbound_from_target && !echoed_mutation) {
        r["classification"] = "response_from_target";
        r["interesting_reason"] = "inbound_payload_from_target_differs_from_sent_mutations";
        interesting = true;
    } else if (inbound_from_target && echoed_mutation) {
        r["classification"] = "echoed_mutation_from_target";
        r["interesting_reason"] = "target_echoed_mutated_payload";
        interesting = true;
    } else if (outbound_to_target) {
        r["classification"] = echoed_mutation ? "outbound_replay_observed" : "outbound_udp_to_target";
        r["interesting_reason"] = echoed_mutation ? "driver_capture_observed_successful_replay_send" : "outbound_context_packet_to_target";
        interesting = echoed_mutation;
    } else if (target_local_response) {
        r["classification"] = "target_local_inbound_context";
        r["interesting_reason"] = "capture_endpoint_matches_target_local_port";
        interesting = !p.payload.empty();
    } else {
        r["classification"] = "unrelated_udp_capture_context";
        r["interesting_reason"] = nullptr;
    }
    r["interesting"] = interesting;
    return r;
}

bool driver_reg_index_checked(const std::string& reg, std::uint32_t& out)
{
    const std::string r = lower_copy(reg);
    if (r == "rax") { out = 0; return true; }
    if (r == "rcx") { out = 1; return true; }
    if (r == "rdx") { out = 2; return true; }
    if (r == "rbx") { out = 3; return true; }
    if (r == "rsp") { out = 4; return true; }
    if (r == "rbp") { out = 5; return true; }
    if (r == "rsi") { out = 6; return true; }
    if (r == "rdi") { out = 7; return true; }
    if (r == "r8") { out = 8; return true; }
    if (r == "r9") { out = 9; return true; }
    return false;
}

nlohmann::json output_byte_provenance(const std::vector<serializer_sample_t>& samples,
                                      std::size_t start,
                                      std::size_t size)
{
    nlohmann::json p;
    p["kind"] = "serializer_output_bytes";
    p["source_va_resolved"] = false;
    p["source_va_status"] = "not_available_from_capture_backend";
    p["byte_range"] = {{"offset", start}, {"size", size}};
    p["captures"] = nlohmann::json::array();
    std::set<std::string> unique_values;
    std::set<std::uint64_t> threads;
    std::set<std::uint64_t> rips;
    for (std::size_t i = 0; i < samples.size() && i < 16; ++i) {
        const auto& sample = samples[i];
        if (start >= sample.buffer.size())
            continue;
        const std::size_t n = (std::min)(size, sample.buffer.size() - start);
        const std::string hex = game_protocol::bytes_to_hex(sample.buffer.data() + start, n, 64);
        unique_values.insert(hex);
        if (sample.thread_id != 0)
            threads.insert(sample.thread_id);
        if (sample.rip != 0)
            rips.insert(sample.rip);
        nlohmann::json c;
        c["index"] = i;
        c["timestamp"] = sample.timestamp;
        c["thread_id"] = sample.thread_id;
        c["rip"] = sample.rip ? nlohmann::json(fmt_addr(sample.rip)) : nlohmann::json(nullptr);
        c["function"] = sample.function_name;
        c["backend"] = sample.backend;
        c["module"] = sample.module_name;
        c["module_offset"] = sample.module_offset ? nlohmann::json(fmt_addr(sample.module_offset)) : nlohmann::json(nullptr);
        c["bytes_observed"] = n;
        c["hex"] = hex;
        p["captures"].push_back(std::move(c));
    }
    p["capture_count"] = p["captures"].size();
    p["unique_value_count"] = unique_values.size();
    p["thread_count"] = threads.size();
    p["rip_count"] = rips.size();
    p["stable_across_captures"] = unique_values.size() <= 1 && p["capture_count"].get<std::size_t>() > 1;
    return p;
}

nlohmann::json captures_to_fields(const std::vector<serializer_sample_t>& samples)
{
    nlohmann::json fields = nlohmann::json::array();
    if (samples.empty())
        return fields;

    const auto& first = samples.front().buffer;
    nlohmann::json heuristic = game_protocol::decode_payload_heuristic(first, "serializer_buffer");
    if (heuristic.contains("fields") && heuristic["fields"].is_array()) {
        for (const auto& f : heuristic["fields"]) {
            if (fields.size() >= 64)
                break;
            nlohmann::json out;
            const std::size_t offset = f.value("offset", 0u);
            const std::size_t size = f.value("size", 0u);
            out["buffer_offset"] = offset;
            out["size"] = size;
            out["source_va_resolved"] = false;
            out["source_va_status"] = "not_available_from_capture_backend";
            out["source_type"] = "serializer_output_payload_heuristic";
            out["field_type_guess"] = f.value("type_guess", "unknown");
            out["confidence"] = f.value("confidence", 0.0);
            out["value_examples"] = f.value("sample_values", nlohmann::json::array());
            nlohmann::json evidence = f.contains("evidence") && f["evidence"].is_array() ? f["evidence"] : nlohmann::json::array();
            evidence.push_back("output_byte_provenance_recorded");
            out["evidence"] = std::move(evidence);
            out["output_byte_provenance"] = output_byte_provenance(samples, offset, size);
            fields.push_back(std::move(out));
        }
    }

    if (samples.size() >= 2) {
        const std::size_t limit = (std::min)(first.size(), std::size_t(512));
        std::size_t off = 0;
        while (off < limit && fields.size() < 96) {
            bool varies = false;
            for (std::size_t i = 1; i < samples.size(); ++i) {
                if (off >= samples[i].buffer.size())
                    continue;
                if (samples[i].buffer[off] != first[off]) {
                    varies = true;
                    break;
                }
            }
            if (!varies) {
                ++off;
                continue;
            }
            const std::size_t start = off;
            while (off < limit) {
                bool v = false;
                for (std::size_t i = 1; i < samples.size(); ++i) {
                    if (off < samples[i].buffer.size() && samples[i].buffer[off] != first[off]) {
                        v = true;
                        break;
                    }
                }
                if (!v)
                    break;
                ++off;
            }
            nlohmann::json examples = nlohmann::json::array();
            for (std::size_t i = 0; i < samples.size() && i < 4; ++i) {
                const std::size_t n = (std::min)(off - start, samples[i].buffer.size() > start ? samples[i].buffer.size() - start : std::size_t(0));
                examples.push_back(n == 0 ? std::string() : game_protocol::bytes_to_hex(samples[i].buffer.data() + start, n, 32));
            }
            nlohmann::json f;
            f["buffer_offset"] = start;
            f["size"] = off - start;
            f["source_va_resolved"] = false;
            f["source_va_status"] = "not_available_from_capture_backend";
            f["source_type"] = "serializer_output_byte_variance";
            f["field_type_guess"] = "variable_bytes";
            f["confidence"] = 0.56;
            f["value_examples"] = std::move(examples);
            f["evidence"] = nlohmann::json::array({"field_bytes_varied_across_captures", "output_byte_provenance_recorded"});
            f["output_byte_provenance"] = output_byte_provenance(samples, start, off - start);
            fields.push_back(std::move(f));
        }
    }

    return fields;
}

}

bool find_sendrecv_handlers(const sendrecv_scan_options_t& input,
                            nlohmann::json& out,
                            std::string& error)
{
    out = nlohmann::json::object();
    error.clear();
    std::uint32_t pid = 0;
    if (!ensure_process_context(input.process_id, pid, error)) {
        const std::string lower_error = lower_copy(error);
        std::string root_cause = "process_context_unavailable";
        if (lower_error.find("process_id is required") != std::string::npos)
            root_cause = "missing_target_process";
        else if (lower_error.find("driver bridge") != std::string::npos)
            root_cause = "driver_bridge_not_connected";
        else if (lower_error.find("openprocess failed") != std::string::npos)
            root_cause = "target_process_open_failed";
        out["dependency_unavailable"] = true;
        out["root_cause"] = root_cause;
        out["requested_process_id"] = input.process_id;
        out["attached_pid"] = driver_bridge::attached_pid();
        out["using_kernel_driver"] = driver_bridge::using_kernel_driver();
        out["attached_pids"] = driver_bridge::attached_pids();
        out["results"] = nlohmann::json::array();
        out["result_count"] = 0;
        out["count"] = 0;
        out["deadline_hit"] = false;
        out["elapsed_ms"] = 0;
        out["scanned_modules"] = nlohmann::json::array();
        out["scanned_module_count"] = 0;
        out["scanned_bytes"] = 0;
        out["stage"] = "dependency_check";
        out["limitations"] = nlohmann::json::array({"send/recv scan requires a live target process and connected driver bridge"});
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv dependency_failed requested_pid=%u attached_pid=%u using_driver=%d root=%s error=%s",
            input.process_id,
            driver_bridge::attached_pid(),
            driver_bridge::using_kernel_driver() ? 1 : 0,
            root_cause.c_str(),
            error.c_str());
        return false;
    }

    sendrecv_scan_options_t options = input;
    if (options.max_results == 0)
        options.max_results = 64;
    if (options.max_results > 128)
        options.max_results = 128;
    if (options.max_modules == 0)
        options.max_modules = 32;
    if (options.max_modules > 128)
        options.max_modules = 128;
    if (options.max_scan_bytes == 0)
        options.max_scan_bytes = 67108864;
    if (options.max_scan_bytes > 134217728)
        options.max_scan_bytes = 134217728;
    if (options.timeout_ms == 0)
        options.timeout_ms = 3500;
    if (options.timeout_ms < 250)
        options.timeout_ms = 250;
    if (options.timeout_ms > 30000)
        options.timeout_ms = 30000;

    scan_deadline_t deadline(options.timeout_ms);
    const ULONGLONG find_t0 = GetTickCount64();
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv begin pid=%u max_results=%u max_modules=%u max_scan_bytes=%llu timeout_ms=%u module_name=%s module_base=0x%llX scan_base=0x%llX scan_size=0x%llX",
        pid,
        options.max_results,
        options.max_modules,
        static_cast<unsigned long long>(options.max_scan_bytes),
        options.timeout_ms,
        options.module_name.empty() ? "<empty>" : options.module_name.c_str(),
        static_cast<unsigned long long>(options.module_base),
        static_cast<unsigned long long>(options.scan_base),
        static_cast<unsigned long long>(options.scan_size));
    deadline.stage = "enumerate_modules";
    const ULONGLONG enumerate_t0 = GetTickCount64();
    std::vector<driver_bridge::module_info_t> modules;
    if (!deadline.expired("before_enumerate_modules"))
        modules = driver_bridge::enumerate_modules_for(pid);
    const std::uint64_t enumerate_elapsed_ms = GetTickCount64() - enumerate_t0;
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv enumerate_modules_done pid=%u module_count=%zu deadline_hit=%d enumerate_elapsed_ms=%llu remaining_ms=%llu elapsed_ms=%llu",
        pid,
        modules.size(),
        deadline.hit ? 1 : 0,
        static_cast<unsigned long long>(enumerate_elapsed_ms),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    const ULONGLONG target_selection_t0 = GetTickCount64();
    nlohmann::json target_selection = nlohmann::json::object();
    std::vector<driver_bridge::module_info_t> scan_modules = prioritize_sendrecv_scan_modules(modules, options, target_selection);
    const std::uint64_t target_selection_elapsed_ms = GetTickCount64() - target_selection_t0;
    target_selection["elapsed_ms"] = target_selection_elapsed_ms;
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv target_module_selection pid=%u input_modules=%zu ordered_modules=%zu matched=%zu filter_present=%d target_prioritized=%d elapsed_ms=%llu remaining_ms=%llu total_elapsed_ms=%llu",
        pid,
        modules.size(),
        scan_modules.size(),
        target_selection.value("matched_count", static_cast<std::size_t>(0)),
        target_selection.value("filter_present", false) ? 1 : 0,
        target_selection.value("target_prioritized", false) ? 1 : 0,
        static_cast<unsigned long long>(target_selection_elapsed_ms),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    nlohmann::json socket_resolution = nlohmann::json::object();
    socket_resolution["enumerated_module_count"] = modules.size();
    socket_resolution["scan_ordered_module_count"] = scan_modules.size();
    socket_resolution["deadline_remaining_ms_after_enumeration"] = deadline.remaining_ms();
    socket_resolution["elapsed_ms_after_enumeration"] = deadline.elapsed_ms();
    if (!deadline.expired("resolve_socket_exports"))
        socket_resolution["module_count"] = modules.size();
    const std::uint64_t target_scan_reserve_ms = sendrecv_target_scan_reserve_ms(options.timeout_ms);
    const std::uint64_t resolve_remaining_ms = deadline.remaining_ms();
    const std::uint32_t resolve_budget_ms = socket_resolution_budget_ms(options.timeout_ms, resolve_remaining_ms, target_scan_reserve_ms);
    socket_resolution["target_scan_reserve_ms"] = target_scan_reserve_ms;
    socket_resolution["dependency_budget_ms"] = resolve_budget_ms;
    socket_resolution["parent_deadline_remaining_ms_before_resolution"] = resolve_remaining_ms;
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv resolve_socket_exports_begin pid=%u module_count=%zu dependency_budget_ms=%u target_scan_reserve_ms=%llu parent_deadline_hit=%d parent_remaining_ms=%llu elapsed_ms=%llu",
        pid,
        modules.size(),
        resolve_budget_ms,
        static_cast<unsigned long long>(target_scan_reserve_ms),
        deadline.hit ? 1 : 0,
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    scan_deadline_t resolve_deadline(resolve_budget_ms);
    const ULONGLONG socket_resolution_t0 = GetTickCount64();
    const auto apis = deadline.hit ? std::vector<api_target_t>() : resolve_socket_apis(modules, pid, resolve_deadline, socket_resolution);
    const std::uint64_t socket_resolution_elapsed_ms = GetTickCount64() - socket_resolution_t0;
    if (resolve_deadline.cancelled)
        deadline.expired("resolve_socket_exports_cancelled");
    else
        deadline.expired("after_resolve_socket_exports");
    const bool dependency_deadline_hit = resolve_deadline.hit && !resolve_deadline.cancelled;
    const bool dependency_cancelled = resolve_deadline.cancelled;
    socket_resolution["enumerated_module_count"] = modules.size();
    socket_resolution["scan_ordered_module_count"] = scan_modules.size();
    socket_resolution["target_scan_reserve_ms"] = target_scan_reserve_ms;
    socket_resolution["dependency_budget_ms"] = resolve_budget_ms;
    socket_resolution["parent_deadline_remaining_ms_before_resolution"] = resolve_remaining_ms;
    socket_resolution["dependency_deadline_hit"] = dependency_deadline_hit;
    socket_resolution["dependency_cancelled"] = dependency_cancelled;
    socket_resolution["dependency_stage"] = resolve_deadline.stage;
    socket_resolution["dependency_elapsed_ms"] = resolve_deadline.elapsed_ms();
    socket_resolution["dependency_remaining_ms"] = resolve_deadline.remaining_ms();
    socket_resolution["socket_resolution_elapsed_ms"] = socket_resolution_elapsed_ms;
    socket_resolution["parent_deadline_hit_after_resolution"] = deadline.hit;
    socket_resolution["parent_deadline_remaining_ms_after_resolution"] = deadline.remaining_ms();
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv resolve_socket_exports_done pid=%u api_count=%zu dependency_deadline_hit=%d dependency_cancelled=%d dependency_stage=%s dependency_elapsed_ms=%llu parent_deadline_hit=%d parent_stage=%s parent_remaining_ms=%llu elapsed_ms=%llu",
        pid,
        apis.size(),
        dependency_deadline_hit ? 1 : 0,
        dependency_cancelled ? 1 : 0,
        resolve_deadline.stage.c_str(),
        static_cast<unsigned long long>(socket_resolution_elapsed_ms),
        deadline.hit ? 1 : 0,
        deadline.stage.c_str(),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    if (apis.empty()) {
        const std::string root_cause = deadline.cancelled
            ? std::string("cancelled")
            : socket_resolution.value("root_cause", dependency_deadline_hit ? std::string("socket_export_resolution_deadline") : (deadline.hit ? std::string("socket_export_resolution_deadline") : std::string("socket_exports_unresolved")));
        const bool effective_deadline_hit = (deadline.hit || dependency_deadline_hit) && !deadline.cancelled && !dependency_cancelled;
        const nlohmann::json phase_timings = nlohmann::json{
            {"enumerate_modules_ms", enumerate_elapsed_ms},
            {"target_module_selection_ms", target_selection_elapsed_ms},
            {"socket_export_resolution_ms", socket_resolution_elapsed_ms},
            {"module_read_ms", 0},
            {"import_scan_ms", 0},
            {"thunk_scan_ms", 0},
            {"callsite_scan_ms", 0},
            {"total_wall_ms", static_cast<std::uint64_t>(GetTickCount64() - find_t0)}
        };
        out["process_id"] = pid;
        out["dependency_unavailable"] = true;
        out["root_cause"] = root_cause;
        out["results"] = nlohmann::json::array();
        out["result_count"] = 0;
        out["count"] = 0;
        out["deadline_hit"] = effective_deadline_hit;
        out["cancelled"] = deadline.cancelled || dependency_cancelled;
        out["elapsed_ms"] = deadline.elapsed_ms();
        out["deadline_remaining_ms"] = deadline.remaining_ms();
        out["timeout_ms"] = options.timeout_ms;
        out["scanned_modules"] = nlohmann::json::array();
        out["app_modules_scanned"] = nlohmann::json::array();
        out["scanned_module_count"] = 0;
        out["scanned_bytes"] = 0;
        out["candidate_hit_count"] = 0;
        out["stage"] = deadline.stage;
        out["deadline_stage"] = deadline.stage;
        out["socket_api_count"] = 0;
        out["dependency_result"] = nlohmann::json{
            {"ok", false},
            {"root_cause", root_cause},
            {"deadline_hit", effective_deadline_hit},
            {"dependency_deadline_hit", dependency_deadline_hit},
            {"cancelled", deadline.cancelled || dependency_cancelled},
            {"stage", dependency_deadline_hit ? resolve_deadline.stage : deadline.stage},
            {"dependency_stage", resolve_deadline.stage},
            {"dependency_budget_ms", resolve_budget_ms},
            {"target_scan_reserve_ms", target_scan_reserve_ms},
            {"deadline_remaining_ms", deadline.remaining_ms()},
            {"elapsed_ms", deadline.elapsed_ms()}
        };
        out["diagnostics"] = nlohmann::json{
            {"socket_resolution", socket_resolution},
            {"target_selection", target_selection},
            {"phase_timings", phase_timings},
            {"app_modules_scanned", nlohmann::json::array()},
            {"scanned_bytes", 0},
            {"candidate_hit_count", 0},
            {"deadline_stage", deadline.stage},
            {"deadline_remaining_ms", deadline.remaining_ms()},
            {"cancelled", deadline.cancelled || dependency_cancelled}
        };
        out["evidence"] = nlohmann::json::array({"socket API exports not resolved from loaded-module or remote-module export tables"});
        out["limitations"] = nlohmann::json::array({
            "socket API export resolution stopped before scanning application modules",
            "no send/recv callsite results are fabricated when socket exports are unavailable"
        });
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv timing pid=%u enumerate_ms=%llu target_selection_ms=%llu socket_resolution_ms=%llu module_read_ms=0 import_scan_ms=0 thunk_scan_ms=0 callsite_scan_ms=0 total_wall_ms=%llu dependency_unavailable=1 root=%s deadline_hit=%d cancelled=%d stage=%s",
            pid,
            static_cast<unsigned long long>(enumerate_elapsed_ms),
            static_cast<unsigned long long>(target_selection_elapsed_ms),
            static_cast<unsigned long long>(socket_resolution_elapsed_ms),
            static_cast<unsigned long long>(phase_timings["total_wall_ms"].get<std::uint64_t>()),
            root_cause.c_str(),
            effective_deadline_hit ? 1 : 0,
            (deadline.cancelled || dependency_cancelled) ? 1 : 0,
            deadline.stage.c_str());
        return true;
    }

    std::map<std::uint64_t, const api_target_t*> api_by_address;
    std::set<std::uint64_t> excluded_targets;
    for (const auto& api : apis) {
        api_by_address[api.address] = &api;
        excluded_targets.insert(api.address);
    }

    nlohmann::json results = nlohmann::json::array();
    nlohmann::json scanned_modules = nlohmann::json::array();
    nlohmann::json module_diagnostics = nlohmann::json::array();
    nlohmann::json app_module_skips = nlohmann::json::array();
    nlohmann::json app_module_skip_histogram = nlohmann::json::object();
    std::set<std::uint64_t> seen_callsites;
    std::uint64_t scanned_bytes = 0;
    std::uint64_t candidate_hits = 0;
    std::uint64_t module_read_elapsed_total_ms = 0;
    std::uint64_t import_scan_elapsed_total_ms = 0;
    std::uint64_t thunk_scan_elapsed_total_ms = 0;
    std::uint64_t callsite_scan_elapsed_total_ms = 0;
    std::uint32_t scanned_count = 0;
    std::string stop_reason;
    bool stopped = false;
    auto stop_scan = [&](const char* reason, const char* stage) {
        stopped = true;
        if (reason && stop_reason.empty())
            stop_reason = reason;
        deadline.expired(stage);
    };

    for (const auto& module : scan_modules) {
        if (deadline.expired("module_loop")) {
            diag::log_tagged_fmt("net_proto",
                "find_sendrecv module_loop_deadline pid=%u scanned_modules=%u scanned_bytes=%llu remaining_ms=%llu elapsed_ms=%llu",
                pid,
                scanned_count,
                static_cast<unsigned long long>(scanned_bytes),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            stop_scan("deadline_before_module", "module_loop");
            break;
        }
        if (!module_matches_scan_target(module, options)) {
            increment_json_counter(app_module_skip_histogram, "target_filter_mismatch");
            if (app_module_skips.size() < 32)
                app_module_skips.push_back(nlohmann::json{{"name", module.name}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}, {"skip_reason", "target_filter_mismatch"}});
            continue;
        }
        if (results.size() >= options.max_results) {
            stop_reason = "max_results_reached";
            diag::log_tagged_fmt("net_proto",
                "find_sendrecv stop pid=%u reason=max_results_reached results=%zu scanned_modules=%u scanned_bytes=%llu remaining_ms=%llu elapsed_ms=%llu",
                pid,
                results.size(),
                scanned_count,
                static_cast<unsigned long long>(scanned_bytes),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            break;
        }
        if (scanned_count >= options.max_modules || scanned_bytes >= options.max_scan_bytes) {
            stop_reason = scanned_count >= options.max_modules ? "max_modules_reached" : "max_scan_bytes_reached";
            diag::log_tagged_fmt("net_proto",
                "find_sendrecv stop pid=%u reason=%s results=%zu scanned_modules=%u scanned_bytes=%llu remaining_ms=%llu elapsed_ms=%llu",
                pid,
                stop_reason.c_str(),
                results.size(),
                scanned_count,
                static_cast<unsigned long long>(scanned_bytes),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            break;
        }
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv module_consider pid=%u name=%s base=%s size=%llu path=%s scanned_modules=%u scanned_bytes=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            fmt_addr(module.base).c_str(),
            static_cast<unsigned long long>(module.size),
            module.path.c_str(),
            scanned_count,
            static_cast<unsigned long long>(scanned_bytes),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        std::string module_skip = scan_module_skip_reason(module);
        if (module.base == 0)
            module_skip = "zero_module_base";
        else if (module.size < 16)
            module_skip = "module_too_small";
        if (!module_skip.empty()) {
            increment_json_counter(app_module_skip_histogram, module_skip);
            if (app_module_skips.size() < 32)
                app_module_skips.push_back(nlohmann::json{{"name", module.name}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}, {"skip_reason", module_skip}});
            diag::log_tagged_fmt("net_proto",
                "find_sendrecv module_skip pid=%u name=%s base=%s size=%llu reason=%s remaining_ms=%llu elapsed_ms=%llu",
                pid,
                module.name.c_str(),
                fmt_addr(module.base).c_str(),
                static_cast<unsigned long long>(module.size),
                module_skip.c_str(),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            continue;
        }

        std::uint64_t read_base = 0;
        std::uint64_t read_span = 0;
        if (!compute_scan_window(module, options, read_base, read_span)) {
            increment_json_counter(app_module_skip_histogram, "scan_window_empty");
            if (app_module_skips.size() < 32)
                app_module_skips.push_back(nlohmann::json{{"name", module.name}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}, {"skip_reason", "scan_window_empty"}});
            continue;
        }
        const std::uint64_t remaining = options.max_scan_bytes - scanned_bytes;
        const std::size_t to_read = static_cast<std::size_t>((std::min<std::uint64_t>)(read_span, (std::min<std::uint64_t>)(remaining, 16777216)));
        std::vector<std::uint8_t> bytes;
        nlohmann::json module_diag;
        module_diag["name"] = module.name;
        module_diag["base"] = fmt_addr(module.base);
        module_diag["size"] = module.size;
        module_diag["path"] = module.path;
        module_diag["read_base"] = fmt_addr(read_base);
        module_diag["read_span"] = read_span;
        module_diag["requested_read_bytes"] = to_read;
        module_diag["scan_index"] = scanned_count;
        deadline.stage = "module_read";
        module_diag["deadline_remaining_ms_before_read"] = deadline.remaining_ms();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv module_read_begin pid=%u name=%s module_base=%s read_base=%s request_bytes=%zu scanned_bytes=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            fmt_addr(module.base).c_str(),
            fmt_addr(read_base).c_str(),
            to_read,
            static_cast<unsigned long long>(scanned_bytes),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        const ULONGLONG read_t0 = GetTickCount64();
        const bool read_ok = !deadline.expired("before_module_read") && driver_bridge::read_memory_for(pid, read_base, to_read, bytes);
        module_diag["read_ok"] = read_ok;
        module_diag["read_elapsed_ms"] = GetTickCount64() - read_t0;
        module_read_elapsed_total_ms += module_diag["read_elapsed_ms"].get<std::uint64_t>();
        module_diag["bytes_read"] = bytes.size();
        module_diag["deadline_remaining_ms_after_read"] = deadline.remaining_ms();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv module_read_done pid=%u name=%s module_base=%s read_base=%s ok=%d requested_bytes=%zu bytes_read=%zu read_elapsed_ms=%llu scanned_bytes_before=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            fmt_addr(module.base).c_str(),
            fmt_addr(read_base).c_str(),
            read_ok ? 1 : 0,
            to_read,
            bytes.size(),
            static_cast<unsigned long long>(module_diag["read_elapsed_ms"].get<std::uint64_t>()),
            static_cast<unsigned long long>(scanned_bytes),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        if (!read_ok || bytes.size() < 16) {
            module_diag["rejection_reason"] = read_ok ? "read_too_small" : "read_failed";
            diag::log_tagged_fmt("net_proto",
                "find_sendrecv module_read_reject pid=%u name=%s reason=%s bytes_read=%zu deadline_hit=%d remaining_ms=%llu elapsed_ms=%llu",
                pid,
                module.name.c_str(),
                module_diag["rejection_reason"].get<std::string>().c_str(),
                bytes.size(),
                deadline.hit ? 1 : 0,
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            if (deadline.expired("after_module_read")) {
                diag::log_tagged_fmt("net_proto",
                    "find_sendrecv deadline_after_module_read pid=%u name=%s remaining_ms=%llu elapsed_ms=%llu",
                    pid,
                    module.name.c_str(),
                    static_cast<unsigned long long>(deadline.remaining_ms()),
                    static_cast<unsigned long long>(deadline.elapsed_ms()));
                stop_scan("deadline_after_module_read", "after_module_read");
                break;
            }
            continue;
        }
        if (deadline.expired("after_module_read")) {
            module_diag["deadline_hit_after_read"] = true;
            diag::log_tagged_fmt("net_proto",
                "find_sendrecv deadline_after_module_read pid=%u name=%s bytes_read=%zu remaining_ms=%llu elapsed_ms=%llu",
                pid,
                module.name.c_str(),
                bytes.size(),
                static_cast<unsigned long long>(deadline.remaining_ms()),
                static_cast<unsigned long long>(deadline.elapsed_ms()));
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            stop_scan("deadline_after_module_read", "after_module_read");
            break;
        }

        ++scanned_count;
        scanned_bytes += bytes.size();
        scanned_modules.push_back(module.name);

        std::map<std::uint64_t, const api_target_t*> import_slots;
        std::uint64_t module_candidate_hits = 0;
        const ULONGLONG import_slots_t0 = GetTickCount64();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv scan_import_slots_begin pid=%u name=%s bytes=%zu api_targets=%zu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            bytes.size(),
            apis.size(),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        for (std::size_t i = 0; i + 8 <= bytes.size(); i += 1) {
            if ((i & 0x0fffu) == 0 && deadline.expired("scan_import_slots")) {
                diag::log_tagged_fmt("net_proto",
                    "find_sendrecv scan_import_slots_deadline pid=%u name=%s offset=%zu import_slots=%zu remaining_ms=%llu elapsed_ms=%llu",
                    pid,
                    module.name.c_str(),
                    i,
                    import_slots.size(),
                    static_cast<unsigned long long>(deadline.remaining_ms()),
                    static_cast<unsigned long long>(deadline.elapsed_ms()));
                stop_scan("deadline_import_slot_scan", "scan_import_slots");
                break;
            }
            const std::uint64_t ptr = le64(bytes.data() + i);
            auto it = api_by_address.find(ptr);
            if (it != api_by_address.end())
                import_slots[read_base + i] = it->second;
        }
        module_diag["import_slot_count"] = import_slots.size();
        module_diag["import_slot_scan_elapsed_ms"] = GetTickCount64() - import_slots_t0;
        import_scan_elapsed_total_ms += module_diag["import_slot_scan_elapsed_ms"].get<std::uint64_t>();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv scan_import_slots_done pid=%u name=%s import_slots=%zu stopped=%d scan_elapsed_ms=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            import_slots.size(),
            stopped ? 1 : 0,
            static_cast<unsigned long long>(module_diag["import_slot_scan_elapsed_ms"].get<std::uint64_t>()),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        if (stopped) {
            module_diag["stop_reason"] = stop_reason;
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            break;
        }

        std::map<std::uint64_t, const api_target_t*> thunks;
        const ULONGLONG thunks_t0 = GetTickCount64();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv scan_import_thunks_begin pid=%u name=%s bytes=%zu import_slots=%zu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            bytes.size(),
            import_slots.size(),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        for (std::size_t i = 0; i + 6 <= bytes.size(); ++i) {
            if ((i & 0x0fffu) == 0 && deadline.expired("scan_import_thunks")) {
                diag::log_tagged_fmt("net_proto",
                    "find_sendrecv scan_import_thunks_deadline pid=%u name=%s offset=%zu thunks=%zu remaining_ms=%llu elapsed_ms=%llu",
                    pid,
                    module.name.c_str(),
                    i,
                    thunks.size(),
                    static_cast<unsigned long long>(deadline.remaining_ms()),
                    static_cast<unsigned long long>(deadline.elapsed_ms()));
                stop_scan("deadline_import_thunk_scan", "scan_import_thunks");
                break;
            }
            if (bytes[i] != 0xff || bytes[i + 1] != 0x25)
                continue;
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes.data() + i + 2, sizeof(rel));
            const std::uint64_t slot = rel32_target(read_base + i + 6, rel);
            auto sit = import_slots.find(slot);
            if (sit != import_slots.end())
                thunks[read_base + i] = sit->second;
        }
        for (const auto& t : thunks)
            excluded_targets.insert(t.first);
        module_diag["import_thunk_count"] = thunks.size();
        module_diag["import_thunk_scan_elapsed_ms"] = GetTickCount64() - thunks_t0;
        thunk_scan_elapsed_total_ms += module_diag["import_thunk_scan_elapsed_ms"].get<std::uint64_t>();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv scan_import_thunks_done pid=%u name=%s thunks=%zu stopped=%d scan_elapsed_ms=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            thunks.size(),
            stopped ? 1 : 0,
            static_cast<unsigned long long>(module_diag["import_thunk_scan_elapsed_ms"].get<std::uint64_t>()),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        if (stopped) {
            module_diag["stop_reason"] = stop_reason;
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            break;
        }

        const ULONGLONG callsites_t0 = GetTickCount64();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv scan_callsites_begin pid=%u name=%s bytes=%zu import_slots=%zu thunks=%zu results=%zu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            bytes.size(),
            import_slots.size(),
            thunks.size(),
            results.size(),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        for (std::size_t i = 0; i + 6 <= bytes.size() && results.size() < options.max_results; ++i) {
            if ((i & 0x0fffu) == 0 && deadline.expired("scan_callsites")) {
                diag::log_tagged_fmt("net_proto",
                    "find_sendrecv scan_callsites_deadline pid=%u name=%s offset=%zu results=%zu candidate_hits=%llu remaining_ms=%llu elapsed_ms=%llu",
                    pid,
                    module.name.c_str(),
                    i,
                    results.size(),
                    static_cast<unsigned long long>(candidate_hits),
                    static_cast<unsigned long long>(deadline.remaining_ms()),
                    static_cast<unsigned long long>(deadline.elapsed_ms()));
                stop_scan("deadline_callsite_scan", "scan_callsites");
                break;
            }
            const api_target_t* api = nullptr;
            bool iat = false;
            bool register_indirect_import = false;
            std::uint64_t callsite = read_base + i;

            if (bytes[i] == 0xe8 && i + 5 <= bytes.size()) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
                const std::uint64_t target = rel32_target(read_base + i + 5, rel);
                if (auto ait = api_by_address.find(target); ait != api_by_address.end())
                    api = ait->second;
                else if (auto tit = thunks.find(target); tit != thunks.end()) {
                    api = tit->second;
                    iat = true;
                }
            } else if (bytes[i] == 0xff && bytes[i + 1] == 0x15) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes.data() + i + 2, sizeof(rel));
                const std::uint64_t slot = rel32_target(read_base + i + 6, rel);
                if (auto sit = import_slots.find(slot); sit != import_slots.end()) {
                    api = sit->second;
                    iat = true;
                }
            } else {
                std::uint64_t register_slot = 0;
                std::uint64_t register_load = 0;
                if (const api_target_t* reg_api = resolve_recent_register_import_call(bytes, i, read_base, import_slots, register_slot, register_load)) {
                    api = reg_api;
                    iat = true;
                    register_indirect_import = true;
                    module_diag["register_indirect_import_hits"] = module_diag.value("register_indirect_import_hits", 0u) + 1;
                    if (!module_diag.contains("register_indirect_import_samples"))
                        module_diag["register_indirect_import_samples"] = nlohmann::json::array();
                    if (module_diag["register_indirect_import_samples"].size() < 8)
                        module_diag["register_indirect_import_samples"].push_back(nlohmann::json{{"call_va", fmt_addr(callsite)}, {"load_va", fmt_addr(register_load)}, {"slot_va", fmt_addr(register_slot)}, {"api", reg_api->name}});
                }
            }

            if (!api)
                continue;
            ++candidate_hits;
            ++module_candidate_hits;
            const std::uint64_t handler = find_probable_function_start(bytes, i, read_base);
            const std::size_t result_count_before = results.size();
            add_sendrecv_result(results, seen_callsites, module, bytes, read_base, *api, callsite, handler, 0, iat, excluded_targets, options.max_results);
            if (register_indirect_import && results.size() > result_count_before)
                results.back()["callsite_resolution"] = "register_indirect_import_slot_load";
        }
        module_diag["callsite_scan_elapsed_ms"] = GetTickCount64() - callsites_t0;
        callsite_scan_elapsed_total_ms += module_diag["callsite_scan_elapsed_ms"].get<std::uint64_t>();
        module_diag["candidate_hit_count"] = module_candidate_hits;
        module_diag["results_after_module"] = results.size();
        module_diag["deadline_hit"] = deadline.hit;
        module_diag["deadline_remaining_ms_after_scan"] = deadline.remaining_ms();
        module_diag["elapsed_ms"] = deadline.elapsed_ms();
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv scan_callsites_done pid=%u name=%s module_candidate_hits=%llu total_candidate_hits=%llu results=%zu stopped=%d scan_elapsed_ms=%llu scanned_bytes_total=%llu remaining_ms=%llu elapsed_ms=%llu",
            pid,
            module.name.c_str(),
            static_cast<unsigned long long>(module_candidate_hits),
            static_cast<unsigned long long>(candidate_hits),
            results.size(),
            stopped ? 1 : 0,
            static_cast<unsigned long long>(module_diag["callsite_scan_elapsed_ms"].get<std::uint64_t>()),
            static_cast<unsigned long long>(scanned_bytes),
            static_cast<unsigned long long>(deadline.remaining_ms()),
            static_cast<unsigned long long>(deadline.elapsed_ms()));
        if (module_diagnostics.size() < 32)
            module_diagnostics.push_back(std::move(module_diag));
        if (stopped)
            break;
    }

    out["process_id"] = pid;
    out["dependency_unavailable"] = false;
    out["root_cause"] = deadline.cancelled ? std::string("cancelled") : (deadline.hit ? std::string("scan_deadline") : (stop_reason.empty() ? std::string("complete") : stop_reason));
    out["results"] = std::move(results);
    out["result_count"] = out["results"].size();
    out["count"] = out["result_count"];
    out["deadline_hit"] = deadline.hit && !deadline.cancelled;
    out["cancelled"] = deadline.cancelled;
    out["elapsed_ms"] = deadline.elapsed_ms();
    out["deadline_remaining_ms"] = deadline.remaining_ms();
    out["timeout_ms"] = options.timeout_ms;
    out["scanned_modules"] = std::move(scanned_modules);
    out["app_modules_scanned"] = out["scanned_modules"];
    out["scanned_module_count"] = scanned_count;
    out["scanned_bytes"] = scanned_bytes;
    out["candidate_hit_count"] = candidate_hits;
    out["socket_api_count"] = apis.size();
    out["stage"] = deadline.hit ? deadline.stage : (stop_reason.empty() ? "complete" : stop_reason);
    out["deadline_stage"] = deadline.stage;
    const nlohmann::json phase_timings = nlohmann::json{
        {"enumerate_modules_ms", enumerate_elapsed_ms},
        {"target_module_selection_ms", target_selection_elapsed_ms},
        {"socket_export_resolution_ms", socket_resolution_elapsed_ms},
        {"module_read_ms", module_read_elapsed_total_ms},
        {"import_scan_ms", import_scan_elapsed_total_ms},
        {"thunk_scan_ms", thunk_scan_elapsed_total_ms},
        {"callsite_scan_ms", callsite_scan_elapsed_total_ms},
        {"total_wall_ms", static_cast<std::uint64_t>(GetTickCount64() - find_t0)}
    };
    out["diagnostics"] = nlohmann::json{
        {"socket_resolution", socket_resolution},
        {"target_selection", target_selection},
        {"phase_timings", phase_timings},
        {"module_diagnostics", module_diagnostics},
        {"app_module_skips", app_module_skips},
        {"app_module_skip_histogram", app_module_skip_histogram},
        {"stop_reason", stop_reason.empty() ? "complete" : stop_reason},
        {"seen_callsite_count", seen_callsites.size()},
        {"candidate_hit_count", candidate_hits},
        {"app_modules_scanned", out["app_modules_scanned"]},
        {"scanned_bytes", scanned_bytes},
        {"deadline_stage", deadline.stage},
        {"deadline_remaining_ms", deadline.remaining_ms()},
        {"cancelled", deadline.cancelled},
        {"module_filter", options.module_name},
        {"module_base_filter", options.module_base == 0 ? nlohmann::json(nullptr) : nlohmann::json(fmt_addr(options.module_base))},
        {"scan_base", options.scan_base == 0 ? nlohmann::json(nullptr) : nlohmann::json(fmt_addr(options.scan_base))},
        {"scan_size", options.scan_size}
    };
    out["limitations"] = nlohmann::json::array({
        "direct relative, import thunk, IAT indirect, and recent register-loaded IAT calls are detected; custom syscall wrappers may require manual follow-up",
        "serializer and deserializer addresses are ranked same-function call graph candidates unless net_proto_trace_serializer confirms runtime buffer writes",
        "system modules are skipped to focus on application handlers",
        "bounded deadline returns partial diagnostics without inventing send/recv handlers"
    });
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv done pid=%u results=%u apis=%zu scanned_modules=%u scanned_bytes=%llu candidate_hits=%llu deadline_hit=%d cancelled=%d elapsed_ms=%llu stage=%s stop=%s",
        pid,
        static_cast<unsigned>(out["result_count"].get<std::size_t>()),
        apis.size(),
        scanned_count,
        static_cast<unsigned long long>(scanned_bytes),
        static_cast<unsigned long long>(candidate_hits),
        (deadline.hit && !deadline.cancelled) ? 1 : 0,
        deadline.cancelled ? 1 : 0,
        static_cast<unsigned long long>(deadline.elapsed_ms()),
        out["stage"].get<std::string>().c_str(),
        stop_reason.empty() ? "complete" : stop_reason.c_str());
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv timing pid=%u enumerate_ms=%llu target_selection_ms=%llu socket_resolution_ms=%llu module_read_ms=%llu import_scan_ms=%llu thunk_scan_ms=%llu callsite_scan_ms=%llu total_wall_ms=%llu dependency_deadline_hit=%d parent_deadline_hit=%d stage=%s stop=%s",
        pid,
        static_cast<unsigned long long>(enumerate_elapsed_ms),
        static_cast<unsigned long long>(target_selection_elapsed_ms),
        static_cast<unsigned long long>(socket_resolution_elapsed_ms),
        static_cast<unsigned long long>(module_read_elapsed_total_ms),
        static_cast<unsigned long long>(import_scan_elapsed_total_ms),
        static_cast<unsigned long long>(thunk_scan_elapsed_total_ms),
        static_cast<unsigned long long>(callsite_scan_elapsed_total_ms),
        static_cast<unsigned long long>(phase_timings["total_wall_ms"].get<std::uint64_t>()),
        dependency_deadline_hit ? 1 : 0,
        (deadline.hit && !deadline.cancelled) ? 1 : 0,
        out["stage"].get<std::string>().c_str(),
        stop_reason.empty() ? "complete" : stop_reason.c_str());
    return true;
}

bool trace_serializer(const serializer_trace_options_t& input,
                      nlohmann::json& out,
                      std::string& error)
{
    const std::uint64_t started = static_cast<std::uint64_t>(GetTickCount64());
    out = nlohmann::json::object();
    error.clear();
    if (input.serializer_va == 0) {
        error = "serializer_va is required";
        return false;
    }
    const std::uint32_t active_pid_entry = driver_bridge::attached_pid();
    const nlohmann::json dynamic_ioctl_entry = dynamic_ioctl_state_json();
    std::uint32_t pid = 0;
    if (!ensure_process_context(input.process_id, pid, error)) {
        out["process_id"] = input.process_id;
        out["requested_pid"] = input.process_id;
        out["active_pid_entry"] = active_pid_entry;
        out["active_pid_after_context"] = driver_bridge::attached_pid();
        out["serializer_va"] = fmt_addr(input.serializer_va);
        out["backend"] = "driver_sniff_net_buffers";
        out["kernel_only_capture"] = true;
        out["driver_sniff_attempted"] = false;
        out["driver_sniff_started"] = false;
        out["driver_status"] = driver_bridge::status();
        out["driver_last_error"] = driver_bridge::last_error();
        out["dynamic_ioctl_entry"] = dynamic_ioctl_entry;
        out["dynamic_ioctl_after_context"] = dynamic_ioctl_state_json();
        out["functional_success"] = false;
        out["zero_capture_reason"] = "process context unavailable before kernel serializer backend start";
        diag::log_tagged_fmt("net_proto",
            "trace_serializer context_failed requested_pid=%u active_entry=%u active_after=%u serializer=0x%llX error=%s status=%s last_error=%s",
            input.process_id,
            active_pid_entry,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(input.serializer_va),
            error.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str());
        return false;
    }
    const std::uint32_t active_pid_after_context = driver_bridge::attached_pid();

    serializer_trace_options_t options = input;
    if (options.max_captures == 0)
        options.max_captures = 16;
    if (options.max_captures > 32)
        options.max_captures = 32;
    if (options.sample_ms == 0)
        options.sample_ms = 2000;
    if (options.sample_ms > 10000)
        options.sample_ms = 10000;

    std::uint32_t driver_buf_reg = 0;
    std::uint32_t driver_size_reg = 0;
    if (!driver_reg_index_checked(options.buffer_reg, driver_buf_reg)) {
        error = "invalid buffer_reg '" + options.buffer_reg + "'";
        out["negative_contract"] = true;
        out["invalid_register"] = options.buffer_reg;
        out["buffer_reg"] = options.buffer_reg;
        out["size_reg"] = options.size_reg;
        diag::log_tagged_fmt("net_proto", "trace_serializer invalid_buffer_reg=%s", options.buffer_reg.c_str());
        return false;
    }
    if (!driver_reg_index_checked(options.size_reg, driver_size_reg)) {
        error = "invalid size_reg '" + options.size_reg + "'";
        out["negative_contract"] = true;
        out["invalid_register"] = options.size_reg;
        out["buffer_reg"] = options.buffer_reg;
        out["size_reg"] = options.size_reg;
        diag::log_tagged_fmt("net_proto", "trace_serializer invalid_size_reg=%s", options.size_reg.c_str());
        return false;
    }
    if (lower_copy(options.buffer_reg) == lower_copy(options.size_reg)) {
        error = "buffer_reg and size_reg must be different registers";
        out["negative_contract"] = true;
        out["buffer_reg"] = options.buffer_reg;
        out["size_reg"] = options.size_reg;
        diag::log_tagged_fmt("net_proto", "trace_serializer invalid_register_pair reg=%s", options.buffer_reg.c_str());
        return false;
    }
    std::vector<serializer_sample_t> samples;
    nlohmann::json captures = nlohmann::json::array();
    std::string backend = "driver_sniff_net_buffers";
    bool driver_sniff_attempted = true;
    bool driver_sniff_started = false;
    bool driver_sniff_active_after_get = false;
    driver_bridge::memory_region_t serializer_region{};
    SetLastError(ERROR_SUCCESS);
    const bool serializer_region_ok = driver_bridge::query_memory_for(pid, options.serializer_va, serializer_region);
    const DWORD serializer_region_gle = serializer_region_ok ? ERROR_SUCCESS : GetLastError();
    const std::string serializer_region_error = driver_bridge::last_error();
    const nlohmann::json serializer_region_payload = memory_region_json(serializer_region_ok, serializer_region, serializer_region_gle, serializer_region_error);
    const std::uint32_t active_pid_before_start = driver_bridge::attached_pid();
    const nlohmann::json dynamic_ioctl_before_start = dynamic_ioctl_state_json();

    diag::log_tagged_fmt("net_proto",
        "trace_serializer begin pid=%u requested_pid=%u active_entry=%u active_after_context=%u active_before_start=%u serializer=0x%llX region_ok=%d region_base=%s region_size=%llu region_protect=0x%X buffer_reg=%s size_reg=%s driver_buf=%u driver_size=%u tid=%u sample_ms=%u max_captures=%u dyn_ready=%d dyn_ioctl_seed_hash=0x%08X backend=driver_sniff_net_buffers",
        pid,
        input.process_id,
        active_pid_entry,
        active_pid_after_context,
        active_pid_before_start,
        static_cast<unsigned long long>(options.serializer_va),
        serializer_region_ok ? 1 : 0,
        serializer_region_ok ? fmt_addr(serializer_region.base).c_str() : "<none>",
        static_cast<unsigned long long>(serializer_region_ok ? serializer_region.size : 0),
        serializer_region_ok ? serializer_region.protect : 0,
        options.buffer_reg.c_str(),
        options.size_reg.c_str(),
        driver_buf_reg,
        driver_size_reg,
        options.tid,
        options.sample_ms,
        options.max_captures,
        dynamic_ioctl_before_start.value("ready", false) ? 1 : 0,
        dynamic_ioctl_before_start.value("ioctl_seed_hash", 0u));

    const std::uint64_t start_call_ms = static_cast<std::uint64_t>(GetTickCount64());
    SetLastError(ERROR_SUCCESS);
    if (!driver_bridge::sniff_net_buffers_start(options.serializer_va,
            driver_buf_reg,
            driver_size_reg,
            options.max_captures,
            options.tid,
            0)) {
        const DWORD start_gle = GetLastError();
        const std::uint64_t start_elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_call_ms;
        error = driver_bridge::last_error().empty() ? "failed to start kernel serializer buffer sniffing" : driver_bridge::last_error();
        out["process_id"] = pid;
        out["requested_pid"] = input.process_id;
        out["serializer_va"] = fmt_addr(options.serializer_va);
        out["buffer_reg"] = options.buffer_reg;
        out["size_reg"] = options.size_reg;
        out["driver_buf_reg"] = driver_buf_reg;
        out["driver_size_reg"] = driver_size_reg;
        out["tid"] = options.tid;
        out["backend"] = backend;
        out["kernel_only_capture"] = true;
        out["driver_sniff_attempted"] = driver_sniff_attempted;
        out["driver_sniff_started"] = driver_sniff_started;
        out["driver_sniff_start_elapsed_ms"] = start_elapsed_ms;
        out["driver_sniff_start_gle"] = static_cast<unsigned long>(start_gle);
        out["driver_error"] = error;
        out["driver_status"] = driver_bridge::status();
        out["driver_last_error"] = driver_bridge::last_error();
        out["active_pid_entry"] = active_pid_entry;
        out["active_pid_after_context"] = active_pid_after_context;
        out["active_pid_before_start"] = active_pid_before_start;
        out["active_pid_after_start"] = driver_bridge::attached_pid();
        out["serializer_region"] = serializer_region_payload;
        out["dynamic_ioctl_entry"] = dynamic_ioctl_entry;
        out["dynamic_ioctl_after_context"] = dynamic_ioctl_state_json();
        out["dynamic_ioctl_before_start"] = dynamic_ioctl_before_start;
        out["dynamic_ioctl_after_start"] = dynamic_ioctl_state_json();
        out["functional_success"] = false;
        out["zero_capture_reason"] = "kernel serializer buffer sniffing did not start";
        diag::log_tagged_fmt("net_proto",
            "trace_serializer start_failed pid=%u active_before_start=%u active_after_start=%u serializer=0x%llX gle=%lu elapsed_ms=%llu error=%s status=%s last_error=%s region_ok=%d dyn_ready=%d",
            pid,
            active_pid_before_start,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(options.serializer_va),
            static_cast<unsigned long>(start_gle),
            static_cast<unsigned long long>(start_elapsed_ms),
            error.c_str(),
            driver_bridge::status().c_str(),
            driver_bridge::last_error().c_str(),
            serializer_region_ok ? 1 : 0,
            dynamic_ioctl_state_json().value("ready", false) ? 1 : 0);
        return false;
    }
    driver_sniff_started = true;
    const DWORD start_gle = GetLastError();
    const std::uint64_t start_elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - start_call_ms;
    const std::uint32_t active_pid_after_start = driver_bridge::attached_pid();
    const nlohmann::json dynamic_ioctl_after_start = dynamic_ioctl_state_json();
    bool sample_cancelled = false;
    bool sample_deadline_expired = false;
    const std::uint64_t sample_started_ms = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t sample_deadline_ms = sample_started_ms > std::numeric_limits<std::uint64_t>::max() - options.sample_ms
        ? std::numeric_limits<std::uint64_t>::max()
        : sample_started_ms + options.sample_ms;
    while (static_cast<std::uint64_t>(GetTickCount64()) < sample_deadline_ms) {
        if (mcp_standalone::current_call_cancelled()) {
            sample_cancelled = true;
            break;
        }
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        if (call_deadline != 0 && now >= call_deadline) {
            sample_deadline_expired = true;
            break;
        }
        std::uint64_t slice = std::min<std::uint64_t>(50, sample_deadline_ms > now ? sample_deadline_ms - now : 0);
        if (call_deadline != 0 && call_deadline > now)
            slice = std::min<std::uint64_t>(slice, call_deadline - now);
        if (slice == 0) {
            sample_deadline_expired = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(slice));
    }
    const std::uint64_t sample_elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - sample_started_ms;
    bool active = false;
    auto caps = driver_bridge::sniff_net_buffers_get(active);
    const std::uint64_t stop_started_ms = static_cast<std::uint64_t>(GetTickCount64());
    driver_bridge::sniff_net_buffers_stop();
    const std::uint64_t stop_elapsed_ms = static_cast<std::uint64_t>(GetTickCount64()) - stop_started_ms;
    driver_sniff_active_after_get = active;
    diag::log_tagged_fmt("net_proto",
        "trace_serializer driver_sniff_done captures=%zu active_after_get=%d active_after_stop=%u start_gle=%lu start_elapsed_ms=%llu sample_ms=%u sample_elapsed_ms=%llu sample_cancelled=%d sample_deadline=%d stop_elapsed_ms=%llu driver_error=%s",
        caps.size(),
        active ? 1 : 0,
        driver_bridge::attached_pid(),
        static_cast<unsigned long>(start_gle),
        static_cast<unsigned long long>(start_elapsed_ms),
        options.sample_ms,
        static_cast<unsigned long long>(sample_elapsed_ms),
        sample_cancelled ? 1 : 0,
        sample_deadline_expired ? 1 : 0,
        static_cast<unsigned long long>(stop_elapsed_ms),
        driver_bridge::last_error().c_str());
    for (const auto& cap : caps) {
        serializer_sample_t sample;
        sample.buffer = cap.buffer;
        sample.timestamp = cap.timestamp;
        sample.thread_id = cap.thread_id;
        sample.backend = "driver_sniff_net_buffers";
        samples.push_back(std::move(sample));
        nlohmann::json c;
        c["timestamp"] = cap.timestamp;
        c["thread_id"] = cap.thread_id;
        c["size"] = cap.buffer.size();
        c["hex_preview"] = game_protocol::bytes_to_hex(cap.buffer, 128);
        c["output_byte_origin"] = "driver_sniffed_serializer_buffer";
        c["source_va_resolved"] = false;
        c["source_va_status"] = "not_available_from_driver_sniff";
        c["register_provenance"] = nlohmann::json{{"buffer_reg", options.buffer_reg}, {"size_reg", options.size_reg}, {"capture_rip", nullptr}};
        captures.push_back(std::move(c));
    }
    out["driver_sniff_active_after_get"] = driver_sniff_active_after_get;

    out["process_id"] = pid;
    out["requested_pid"] = input.process_id;
    out["serializer_va"] = fmt_addr(options.serializer_va);
    out["buffer_reg"] = options.buffer_reg;
    out["size_reg"] = options.size_reg;
    out["driver_buf_reg"] = driver_buf_reg;
    out["driver_size_reg"] = driver_size_reg;
    out["tid"] = options.tid;
    out["backend"] = backend;
    out["trace_method"] = "output_buffer_sampling";
    out["source_resolution"] = "capture backends provide output-buffer byte provenance, thread, timestamp, and hook RIP when available; memory source addresses require a taint backend and are not claimed here";
    out["source_va_resolved"] = false;
    out["provenance_kind"] = "output_byte_capture";
    out["register_trace_method"] = "driver_debug_register_buffer_sniff";
    out["kernel_only_capture"] = true;
    out["taint_backend_status"] = "no live source-memory taint backend is exposed by these capture APIs; output bytes are tied to bounded register-derived buffer captures only";
    out["sample_ms"] = options.sample_ms;
    out["elapsed_ms"] = static_cast<std::uint64_t>(GetTickCount64()) - started;
    out["capture_window_ms"] = options.sample_ms;
    out["sample_elapsed_ms"] = sample_elapsed_ms;
    out["sample_cancelled"] = sample_cancelled;
    out["sample_deadline_expired"] = sample_deadline_expired;
    out["capture_count"] = captures.size();
    out["observed_capture_count"] = captures.size();
    out["saw_serializer_output"] = !samples.empty();
    out["stimulus_observed"] = !samples.empty();
    out["functional_success"] = !samples.empty();
    out["user_mode_hook_attempted"] = false;
    out["user_mode_hook_disabled_reason"] = "kernel_only_stealth_policy";
    out["driver_sniff_attempted"] = driver_sniff_attempted;
    out["driver_sniff_started"] = driver_sniff_started;
    out["driver_sniff_start_elapsed_ms"] = start_elapsed_ms;
    out["driver_sniff_start_gle"] = static_cast<unsigned long>(start_gle);
    out["driver_sniff_stop_elapsed_ms"] = stop_elapsed_ms;
    out["driver_sniff_active_after_get"] = driver_sniff_active_after_get;
    out["active_pid_entry"] = active_pid_entry;
    out["active_pid_after_context"] = active_pid_after_context;
    out["active_pid_before_start"] = active_pid_before_start;
    out["active_pid_after_start"] = active_pid_after_start;
    out["active_pid_after_stop"] = driver_bridge::attached_pid();
    out["serializer_region"] = serializer_region_payload;
    out["dynamic_ioctl_entry"] = dynamic_ioctl_entry;
    out["dynamic_ioctl_after_context"] = dynamic_ioctl_state_json();
    out["dynamic_ioctl_before_start"] = dynamic_ioctl_before_start;
    out["dynamic_ioctl_after_start"] = dynamic_ioctl_after_start;
    out["driver_status"] = driver_bridge::status();
    out["driver_last_error"] = driver_bridge::last_error();
    if (samples.empty())
        out["zero_capture_reason"] = "kernel serializer buffer sniffing completed without observing serializer output";
    out["captures"] = std::move(captures);
    out["fields"] = captures_to_fields(samples);
    out["field_count"] = out["fields"].size();
    out["confidence"] = samples.empty() ? 0.18 : (std::min)(0.78, 0.42 + 0.06 * static_cast<double>((std::min)(samples.size(), std::size_t(6))));
    out["evidence"] = samples.empty()
        ? nlohmann::json::array({"no serializer breakpoint hits observed during bounded sample"})
        : nlohmann::json::array({"captured serializer output buffers", "field offsets are inferred from payload bytes and sample variance", "output_byte_provenance recorded per field", "source addresses are not claimed without taint provenance"});
    diag::log_tagged_fmt("net_proto",
        "trace_serializer done backend=%s captures=%u fields=%u confidence=%.3f elapsed_ms=%llu functional_success=%d",
        backend.c_str(),
        out.value("capture_count", 0u),
        out.value("field_count", 0u),
        out.value("confidence", 0.0),
        static_cast<unsigned long long>(out.value("elapsed_ms", 0ull)),
        out.value("functional_success", false) ? 1 : 0);
    return true;
}

bool reassemble_udp_sessions(const udp_reassemble_options_t& input,
                             nlohmann::json& out,
                             std::string& error)
{
    out = nlohmann::json::object();
    error.clear();

    udp_reassemble_options_t options = input;
    if (options.capture_ms == 0)
        options.capture_ms = 10000;
    if (options.capture_ms > 15000)
        options.capture_ms = 15000;
    if (options.max_packets == 0)
        options.max_packets = 256;
    if (options.max_packets > 512)
        options.max_packets = 512;
    if (options.max_payload == 0)
        options.max_payload = 1500;
    if (options.max_payload > 4096)
        options.max_payload = 4096;

    std::string backend = "driver_capture";
    std::vector<driver_bridge::captured_packet_t> packets;
    if (!options.fixture_payloads.empty()) {
        backend = "provided_payload";
        for (const auto& payload : options.fixture_payloads) {
            if (payload.empty())
                continue;
            driver_bridge::captured_packet_t p{};
            p.pid = options.pid;
            p.protocol = 17;
            p.direction = 1;
            p.address_family = 2;
            p.local_addr[0] = 127;
            p.local_addr[3] = 1;
            p.remote_addr[0] = 127;
            p.remote_addr[3] = 1;
            p.local_port = 41000;
            p.remote_port = 42000;
            p.payload = payload;
            p.payload_size = static_cast<std::uint32_t>(p.payload.size());
            packets.push_back(std::move(p));
        }
        diag::log_tagged_fmt("net_proto",
            "udp_reassemble provided_payload payloads=%zu packets=%zu pid=%u max_payload=%u",
            options.fixture_payloads.size(),
            packets.size(),
            options.pid,
            options.max_payload);
    } else {
        if (!driver_bridge::using_kernel_driver()) {
            error = "driver bridge is not connected";
            return false;
        }

        diag::log_tagged_fmt("net_proto",
            "udp_reassemble capture_begin pid=%u capture_ms=%u max_packets=%u max_payload=%u",
            options.pid,
            options.capture_ms,
            options.max_packets,
            options.max_payload);
        if (!driver_bridge::start_capture(options.pid, 0, 17, nullptr, options.max_payload)) {
            error = driver_bridge::last_error().empty() ? "failed to start UDP capture" : driver_bridge::last_error();
            diag::log_tagged_fmt("net_proto",
                "udp_reassemble capture_start_failed pid=%u error=%s",
                options.pid,
                error.c_str());
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(options.capture_ms));
        packets = driver_bridge::get_captured_packets(options.max_packets);
        driver_bridge::stop_capture();
        diag::log_tagged_fmt("net_proto",
            "udp_reassemble capture_done pid=%u packets=%zu driver_error=%s",
            options.pid,
            packets.size(),
            driver_bridge::last_error().c_str());
    }

    std::map<std::string, udp_session_t> grouped;
    std::map<std::string, udp_fragment_group_t> fragment_groups;
    for (const auto& p : packets) {
        if (p.protocol != 17)
            continue;
        if (options.pid != 0 && p.pid != options.pid)
            continue;
        const std::string key = endpoint_key(p);
        auto& session = grouped[key];
        session.key = key;
        auto messages = split_udp_messages(p);
        for (auto& m : messages) {
            if (m.fragment_count >= 2 && !m.reassembly_complete) {
                const std::string group_key = udp_fragment_group_key(key, m);
                auto& group = fragment_groups[group_key];
                group.session_key = key;
                if (group.pieces.size() < 4096)
                    group.pieces.push_back(std::move(m));
            } else {
                append_udp_message_limited(session, std::move(m));
            }
        }
    }

    std::uint32_t reassembled_group_count = 0;
    std::uint32_t incomplete_fragment_group_count = 0;
    for (auto& [group_key, group] : fragment_groups) {
        (void)group_key;
        auto& session = grouped[group.session_key];
        session.key = group.session_key;
        udp_message_t reassembled;
        if (reassemble_fragment_group(group, reassembled)) {
            append_udp_message_limited(session, std::move(reassembled));
            ++reassembled_group_count;
        } else {
            ++incomplete_fragment_group_count;
            for (auto& piece : group.pieces) {
                piece.reassembly_complete = false;
                piece.reassembled = false;
                if (!piece.reassembly_evidence.is_array())
                    piece.reassembly_evidence = nlohmann::json::array();
                piece.reassembly_evidence.push_back("fragment_group_incomplete_or_overlapping");
                append_udp_message_limited(session, std::move(piece));
            }
        }
    }

    nlohmann::json sessions_json = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(udp_mutex());
        auto& store = udp_sessions();
        for (auto& [key, session] : grouped) {
            session.id = make_session_id("udp");
            session.created_ms = static_cast<std::uint64_t>(GetTickCount64());
            while (store.size() >= 16)
                store.erase(store.begin());

            nlohmann::json sj;
            sj["session_id"] = session.id;
            sj["key"] = key;
            sj["message_count"] = session.messages.size();
            std::uint32_t reassembled_messages = 0;
            std::uint32_t incomplete_fragments = 0;
            for (const auto& message : session.messages) {
                if (message.reassembled)
                    ++reassembled_messages;
                if (message.fragment_count >= 2 && !message.reassembly_complete)
                    ++incomplete_fragments;
            }
            sj["reassembled_message_count"] = reassembled_messages;
            sj["incomplete_fragment_count"] = incomplete_fragments;
            sj["confidence"] = reassembled_messages != 0 ? 0.82 : (session.messages.size() >= 2 ? 0.62 : 0.36);
            sj["evidence"] = nlohmann::json::array();
            nlohmann::json messages_json = nlohmann::json::array();
            std::set<std::string> schemes;
            for (const auto& message : session.messages) {
                schemes.insert(message.scheme);
                if (messages_json.size() >= 32)
                    continue;
                messages_json.push_back(udp_message_to_json(message));
            }
            for (const auto& scheme : schemes)
                sj["evidence"].push_back(scheme);
            if (reassembled_messages != 0)
                sj["evidence"].push_back("complete_multi_datagram_reassembly");
            if (incomplete_fragments != 0)
                sj["evidence"].push_back("incomplete_fragment_groups_retained");
            sj["messages"] = std::move(messages_json);

            sessions_json.push_back(std::move(sj));
            store[session.id] = std::move(session);
        }
    }

    diag::log_tagged_fmt("net_proto",
        "udp_reassemble grouping backend=%s packets=%zu groups=%zu sessions=%zu pid=%u",
        backend.c_str(),
        packets.size(),
        grouped.size(),
        sessions_json.size(),
        options.pid);
    out["capture_ms"] = options.capture_ms;
    out["backend"] = backend;
    out["capture_performed"] = backend == "driver_capture";
    out["deterministic_input"] = backend == "provided_payload";
    out["filter_pid"] = options.pid;
    out["filter_protocol"] = "udp";
    out["max_packets"] = options.max_packets;
    out["max_payload"] = options.max_payload;
    out["packet_count"] = packets.size();
    out["fragment_group_count"] = fragment_groups.size();
    out["reassembled_group_count"] = reassembled_group_count;
    out["incomplete_fragment_group_count"] = incomplete_fragment_group_count;
    out["sessions"] = std::move(sessions_json);
    out["session_count"] = out["sessions"].size();
    out["produces_recorded_sessions"] = true;
    out["replay_tool"] = "net_replay_mutate";
    out["limitations"] = nlohmann::json::array({
        "fragment reassembly is heuristic and recognizes length-prefixed and ENet-like sequence patterns",
        "logical sessions are grouped by endpoint tuple, not application authentication state"
    });
    return true;
}

bool replay_mutate(const replay_mutate_options_t& input,
                   nlohmann::json& out,
                   std::string& error)
{
    out = nlohmann::json::object();
    error.clear();
    if (!input.allow_unsafe || !input.confirm_unsafe) {
        error = "mutation replay requires allow_unsafe=true and confirm_unsafe=true";
        out = replay_mutate_error_data(input, "unsafe_confirmation_required", "unsafe_confirmation", error.c_str());
        return false;
    }
    if (input.session_id.empty()) {
        error = "session_id is required";
        out = replay_mutate_error_data(input, "session_id_required", "session_lookup", error.c_str());
        return false;
    }
    if (input.target_ip.empty() || input.target_port == 0 || input.target_port > 65535) {
        error = "target_ip and valid target_port are required";
        out = replay_mutate_error_data(input, "target_required", "target_validation", error.c_str());
        return false;
    }

    std::uint8_t target_addr[16] = {};
    if (!parse_ipv4(input.target_ip, target_addr)) {
        error = "target_ip must be an IPv4 literal";
        out = replay_mutate_error_data(input, "target_ip_invalid", "target_validation", error.c_str());
        return false;
    }
    if (is_blocked_target(target_addr)) {
        error = "target_ip is multicast, broadcast, unspecified, or link-local";
        out = replay_mutate_error_data(input, "target_ip_blocked", "target_validation", error.c_str());
        return false;
    }
    if (!is_loopback(target_addr, 2) && !input.allow_non_loopback) {
        error = "non-loopback mutation replay requires allow_non_loopback=true";
        out = replay_mutate_error_data(input, "non_loopback_requires_allow", "non_loopback", error.c_str());
        return false;
    }

    replay_mutate_options_t options = input;
    if (options.max_mutations == 0)
        options.max_mutations = 64;
    if (options.max_mutations > 256)
        options.max_mutations = 256;
    if (options.payload_cap == 0)
        options.payload_cap = 1024;
    if (options.payload_cap > 4096)
        options.payload_cap = 4096;
    if (options.response_wait_ms > 5000)
        options.response_wait_ms = 5000;
    options.mutation_strategy = lower_copy(options.mutation_strategy);
    if (options.mutation_strategy.empty())
        options.mutation_strategy = "boundary";
    if (!valid_mutation_strategy(options.mutation_strategy)) {
        error = "mutation_strategy must be one of boundary, random, or bitflip";
        out = replay_mutate_error_data(input, "invalid_mutation_strategy", "strategy_validation", error.c_str());
        return false;
    }

    udp_session_t session;
    bool found_session = false;
    {
        std::lock_guard<std::mutex> lock(udp_mutex());
        auto it = udp_sessions().find(options.session_id);
        if (it != udp_sessions().end()) {
            session = it->second;
            found_session = true;
        }
    }
    if (!found_session) {
        error = "session_id not found";
        out = replay_mutate_error_data(input, "session_id_not_found", "session_lookup", error.c_str());
        return false;
    }

    if (!driver_bridge::using_kernel_driver()) {
        error = "driver bridge is not connected";
        out = replay_mutate_error_data(input, "driver_bridge_not_connected", "driver_bridge", error.c_str());
        return false;
    }

    nlohmann::json numeric_field_inventory;
    auto mutations = make_mutations(session, options.mutation_strategy, options.max_mutations, options.payload_cap, numeric_field_inventory);
    if (mutations.empty()) {
        error = "no mutations generated within payload cap";
        out = replay_mutate_error_data(input, "no_mutations_generated", "mutation_generation", error.c_str());
        return false;
    }

    std::uint8_t src_addr[16] = {127, 0, 0, 1};
    std::uint32_t src_port = options.source_port;
    if (src_port == 0 && !session.messages.empty())
        src_port = session.messages.front().local_port ? session.messages.front().local_port : 49001;
    if (src_port == 0)
        src_port = 49001;

    bool capture_started = driver_bridge::start_capture(0, options.target_port, 17, nullptr, options.payload_cap);
    std::uint32_t sent = 0;
    nlohmann::json sent_json = nlohmann::json::array();

    std::size_t mutation_index = 0;
    for (const auto& mutation : mutations) {
        const bool ok = driver_bridge::inject_packet(1, 17, 2, src_port, options.target_port,
            src_addr, target_addr, mutation.payload.data(), static_cast<std::uint32_t>(mutation.payload.size()));
        if (ok)
            ++sent;
        if (sent_json.size() < 32) {
            nlohmann::json sj;
            sj["mutation_index"] = mutation_index;
            sj["ok"] = ok;
            sj["payload_size"] = mutation.payload.size();
            sj["hex_preview"] = game_protocol::bytes_to_hex(mutation.payload, 96);
            sj["strategy"] = mutation.strategy;
            sj["source_message_index"] = mutation.source_message_index;
            sj["field_offset"] = mutation.field_offset;
            sj["field_size"] = mutation.field_size;
            sj["endian"] = mutation.big_endian ? "big" : "little";
            sj["original_value"] = mutation.original_value;
            sj["mutated_value"] = mutation.mutated_value;
            sj["evidence"] = mutation.evidence;
            sent_json.push_back(std::move(sj));
        }
        ++mutation_index;
    }

    if (options.response_wait_ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(options.response_wait_ms));

    nlohmann::json responses = nlohmann::json::array();
    nlohmann::json captured_responses = nlohmann::json::array();
    std::uint32_t captured_response_count = 0;
    if (capture_started) {
        auto packets = driver_bridge::get_captured_packets(64);
        driver_bridge::stop_capture();
        for (const auto& p : packets) {
            if (p.protocol != 17)
                continue;
            bool interesting = false;
            nlohmann::json r = classify_response_packet(p, target_addr, options.target_port, src_port, session, mutations, interesting);
            ++captured_response_count;
            if (captured_responses.size() < 64)
                captured_responses.push_back(r);
            if (interesting && responses.size() < 32)
                responses.push_back(std::move(r));
        }
    }

    out["session_id"] = options.session_id;
    out["replay_requires_existing_session"] = true;
    out["record_operation"] = "net_udp_session_reassemble";
    out["recorded_message_count"] = session.messages.size();
    out["target"] = options.target_ip + ":" + std::to_string(options.target_port);
    out["mutation_strategy"] = options.mutation_strategy;
    out["allowed_mutation_strategies"] = nlohmann::json::array({"boundary", "random", "bitflip"});
    out["max_mutations"] = options.max_mutations;
    out["payload_cap"] = options.payload_cap;
    out["numeric_field_inventory"] = std::move(numeric_field_inventory);
    out["mutations_generated"] = mutations.size();
    out["mutations_sent"] = sent;
    out["sent_preview"] = std::move(sent_json);
    out["response_capture_started"] = capture_started;
    out["captured_response_count"] = captured_response_count;
    out["captured_responses"] = std::move(captured_responses);
    out["interesting_response_count"] = responses.size();
    out["interesting_responses"] = std::move(responses);
    out["replay_evidence"] = nlohmann::json::array({
        capture_started ? "response_capture_started" : "response_capture_start_failed",
        sent != 0 ? "at_least_one_mutation_sent" : "no_mutations_sent",
        captured_response_count != 0 ? "udp_packets_observed_after_replay" : "no_udp_packets_observed_after_replay"
    });
    out["replay_successful"] = sent != 0;
    out["response_observed"] = captured_response_count != 0;
    out["limitations"] = nlohmann::json::array({
        "mutations are generated from inferred numeric fields and may not preserve checksums or encryption",
        "interesting responses are classified from bounded UDP packet capture and payload diffs, not proof of server-side state changes",
        "loopback is enforced unless allow_non_loopback is explicitly set"
    });
    return true;
}

}
