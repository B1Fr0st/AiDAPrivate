#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "net_proto_analysis.hpp"

#include "game_protocol.hpp"
#include "pre_encrypt_hook.hpp"
#include "standalone_driver.hpp"
#include "../mcp/mcp_standalone.hpp"
#include "helpers/diag_log.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    std::vector<std::uint8_t> payload;
    std::uint32_t local_port = 0;
    std::uint32_t remote_port = 0;
    std::uint32_t address_family = 2;
    std::uint8_t local_addr[16] = {};
    std::uint8_t remote_addr[16] = {};
    std::string scheme;
};

struct udp_session_t {
    std::string id;
    std::string key;
    std::uint64_t created_ms = 0;
    std::vector<udp_message_t> messages;
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

std::uint64_t socket_resolution_app_scan_reserve_ms(const scan_deadline_t& deadline)
{
    return (std::max<std::uint64_t>)(100, (std::min<std::uint64_t>)(750, deadline.timeout_ms / 4));
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
    std::uint64_t neighbor = adjacent;
    if (neighbor == 0)
        neighbor = nearest_internal_call(bytes, call_off, bytes_base, excluded_targets, api.direction == "recv");

    nlohmann::json r;
    r["direction"] = api.direction;
    r["api"] = api.name;
    r["api_call_va"] = fmt_addr(callsite);
    r["api_target_va"] = fmt_addr(api.address);
    r["handler_va"] = fmt_addr(handler);
    r["module"] = module.name;
    r["serializer_va"] = nullptr;
    r["deserializer_va"] = nullptr;
    if (api.direction == "send")
        r["serializer_va"] = neighbor ? fmt_addr(neighbor) : fmt_addr(handler);
    else
        r["deserializer_va"] = neighbor ? fmt_addr(neighbor) : fmt_addr(handler);
    r["confidence"] = iat_indirect ? 0.78 : 0.7;
    r["evidence"] = nlohmann::json::array({
        iat_indirect ? "call_indirect_through_import_slot" : "direct_relative_call_or_import_thunk",
        "handler_start_heuristic=" + fmt_addr(handler)
    });
    results.push_back(std::move(r));
}

std::string endpoint_key(const driver_bridge::captured_packet_t& p)
{
    const std::string a = format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
    const std::string b = format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
    return a < b ? a + "<->" + b : b + "<->" + a;
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
        m.local_port = p.local_port;
        m.remote_port = p.remote_port;
        m.address_family = p.address_family;
        std::memcpy(m.local_addr, p.local_addr, sizeof(m.local_addr));
        std::memcpy(m.remote_addr, p.remote_addr, sizeof(m.remote_addr));
        m.scheme = scheme;
        messages.push_back(std::move(m));
    };

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

std::vector<std::pair<std::size_t, std::size_t>> numeric_offsets(const std::vector<std::uint8_t>& payload)
{
    std::vector<std::pair<std::size_t, std::size_t>> out;
    const std::size_t limit = (std::min)(payload.size(), std::size_t(512));
    for (std::size_t off = 0; off + 4 <= limit && out.size() < 48; off += 4) {
        const std::uint32_t v = le32(payload.data() + off);
        if (v != 0 && v != 0xffffffffu)
            out.push_back({off, 4});
    }
    for (std::size_t off = 0; off + 2 <= limit && out.size() < 64; off += 2) {
        const std::uint16_t v = le16(payload.data() + off);
        if (v != 0 && v != 0xffffu)
            out.push_back({off, 2});
    }
    if (out.empty() && !payload.empty())
        out.push_back({0, 1});
    return out;
}

void write_le(std::vector<std::uint8_t>& payload, std::size_t off, std::size_t size, std::uint64_t value)
{
    for (std::size_t i = 0; i < size && off + i < payload.size(); ++i)
        payload[off + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu);
}

std::vector<std::vector<std::uint8_t>> make_mutations(const udp_session_t& session,
                                                      const std::string& strategy,
                                                      std::uint32_t max_mutations,
                                                      std::uint32_t payload_cap)
{
    std::vector<std::vector<std::uint8_t>> out;
    std::set<std::vector<std::uint8_t>> seen;
    std::uint64_t lcg = 0xA1DA5EED12345678ULL ^ static_cast<std::uint64_t>(GetTickCount64());

    for (const auto& message : session.messages) {
        if (out.size() >= max_mutations)
            break;
        if (message.payload.empty() || message.payload.size() > payload_cap)
            continue;

        auto offsets = numeric_offsets(message.payload);
        if (strategy == "bitflip") {
            for (const auto& [off, size] : offsets) {
                for (std::uint8_t bit : {std::uint8_t(0x01), std::uint8_t(0x80)}) {
                    if (out.size() >= max_mutations)
                        break;
                    auto m = message.payload;
                    if (off < m.size())
                        m[off] ^= bit;
                    if (seen.insert(m).second)
                        out.push_back(std::move(m));
                }
            }
        } else if (strategy == "random") {
            for (const auto& [off, size] : offsets) {
                if (out.size() >= max_mutations)
                    break;
                lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
                auto m = message.payload;
                write_le(m, off, size, lcg);
                if (seen.insert(m).second)
                    out.push_back(std::move(m));
            }
        } else {
            static const std::uint64_t values[] = {
                0ULL, 1ULL, 0x7fULL, 0x80ULL, 0xffULL, 0x100ULL,
                0x7fffULL, 0x8000ULL, 0xffffULL, 0x10000ULL,
                0x7fffffffULL, 0x80000000ULL, 0xffffffffULL
            };
            for (const auto& [off, size] : offsets) {
                for (std::uint64_t value : values) {
                    if (out.size() >= max_mutations)
                        break;
                    auto m = message.payload;
                    write_le(m, off, size, value);
                    if (seen.insert(m).second)
                        out.push_back(std::move(m));
                }
            }
        }
    }
    return out;
}

int pre_encrypt_arg_index(const std::string& reg)
{
    const std::string r = lower_copy(reg);
    if (r == "rcx")
        return 0;
    if (r == "rdx")
        return 1;
    if (r == "r8")
        return 2;
    if (r == "r9")
        return 3;
    return -1;
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

nlohmann::json captures_to_fields(const std::vector<std::vector<std::uint8_t>>& samples)
{
    nlohmann::json fields = nlohmann::json::array();
    if (samples.empty())
        return fields;

    const auto& first = samples.front();
    nlohmann::json heuristic = game_protocol::decode_payload_heuristic(first, "serializer_buffer");
    if (heuristic.contains("fields") && heuristic["fields"].is_array()) {
        for (const auto& f : heuristic["fields"]) {
            if (fields.size() >= 64)
                break;
            nlohmann::json out;
            out["buffer_offset"] = f.value("offset", 0);
            out["size"] = f.value("size", 0);
            out["source_va"] = nullptr;
            out["source_type"] = "serializer_output_payload_heuristic";
            out["field_type_guess"] = f.value("type_guess", "unknown");
            out["confidence"] = f.value("confidence", 0.0);
            out["value_examples"] = f.value("sample_values", nlohmann::json::array());
            nlohmann::json evidence = f.contains("evidence") && f["evidence"].is_array() ? f["evidence"] : nlohmann::json::array();
            evidence.push_back("source_va_not_resolved_by_output_sampling");
            out["evidence"] = std::move(evidence);
            fields.push_back(std::move(out));
        }
    }

    if (samples.size() >= 2) {
        const std::size_t limit = (std::min)(first.size(), std::size_t(512));
        std::size_t off = 0;
        while (off < limit && fields.size() < 96) {
            bool varies = false;
            for (std::size_t i = 1; i < samples.size(); ++i) {
                if (off >= samples[i].size())
                    continue;
                if (samples[i][off] != first[off]) {
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
                    if (off < samples[i].size() && samples[i][off] != first[off]) {
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
                const std::size_t n = (std::min)(off - start, samples[i].size() > start ? samples[i].size() - start : std::size_t(0));
                examples.push_back(n == 0 ? std::string() : game_protocol::bytes_to_hex(samples[i].data() + start, n, 32));
            }
            nlohmann::json f;
            f["buffer_offset"] = start;
            f["size"] = off - start;
            f["source_va"] = nullptr;
            f["source_type"] = "serializer_output_byte_variance";
            f["field_type_guess"] = "variable_bytes";
            f["confidence"] = 0.56;
            f["value_examples"] = std::move(examples);
            f["evidence"] = nlohmann::json::array({"field_bytes_varied_across_captures", "source_va_not_resolved_by_output_sampling"});
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
    std::vector<driver_bridge::module_info_t> modules;
    if (!deadline.expired("before_enumerate_modules"))
        modules = driver_bridge::enumerate_modules_for(pid);
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv enumerate_modules_done pid=%u module_count=%zu deadline_hit=%d remaining_ms=%llu elapsed_ms=%llu",
        pid,
        modules.size(),
        deadline.hit ? 1 : 0,
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    nlohmann::json socket_resolution = nlohmann::json::object();
    socket_resolution["enumerated_module_count"] = modules.size();
    socket_resolution["deadline_remaining_ms_after_enumeration"] = deadline.remaining_ms();
    socket_resolution["elapsed_ms_after_enumeration"] = deadline.elapsed_ms();
    if (!deadline.expired("resolve_socket_exports"))
        socket_resolution["module_count"] = modules.size();
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv resolve_socket_exports_begin pid=%u module_count=%zu deadline_hit=%d remaining_ms=%llu elapsed_ms=%llu",
        pid,
        modules.size(),
        deadline.hit ? 1 : 0,
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    const auto apis = deadline.hit ? std::vector<api_target_t>() : resolve_socket_apis(modules, pid, deadline, socket_resolution);
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv resolve_socket_exports_done pid=%u api_count=%zu deadline_hit=%d stage=%s remaining_ms=%llu elapsed_ms=%llu",
        pid,
        apis.size(),
        deadline.hit ? 1 : 0,
        deadline.stage.c_str(),
        static_cast<unsigned long long>(deadline.remaining_ms()),
        static_cast<unsigned long long>(deadline.elapsed_ms()));
    if (apis.empty()) {
        const std::string root_cause = deadline.cancelled
            ? std::string("cancelled")
            : socket_resolution.value("root_cause", deadline.hit ? std::string("socket_export_resolution_deadline") : std::string("socket_exports_unresolved"));
        out["process_id"] = pid;
        out["dependency_unavailable"] = true;
        out["root_cause"] = root_cause;
        out["results"] = nlohmann::json::array();
        out["result_count"] = 0;
        out["count"] = 0;
        out["deadline_hit"] = deadline.hit && !deadline.cancelled;
        out["cancelled"] = deadline.cancelled;
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
            {"deadline_hit", deadline.hit && !deadline.cancelled},
            {"cancelled", deadline.cancelled},
            {"stage", deadline.stage},
            {"deadline_remaining_ms", deadline.remaining_ms()},
            {"elapsed_ms", deadline.elapsed_ms()}
        };
        out["diagnostics"] = nlohmann::json{
            {"socket_resolution", socket_resolution},
            {"app_modules_scanned", nlohmann::json::array()},
            {"scanned_bytes", 0},
            {"candidate_hit_count", 0},
            {"deadline_stage", deadline.stage},
            {"deadline_remaining_ms", deadline.remaining_ms()},
            {"cancelled", deadline.cancelled}
        };
        out["evidence"] = nlohmann::json::array({"socket API exports not resolved from loaded-module or remote-module export tables"});
        out["limitations"] = nlohmann::json::array({
            "socket API export resolution stopped before scanning application modules",
            "no send/recv callsite results are fabricated when socket exports are unavailable"
        });
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv done pid=%u results=0 apis=0 scanned_modules=0 scanned_bytes=0 dependency_unavailable=1 root=%s deadline_hit=%d cancelled=%d elapsed_ms=%llu stage=%s",
            pid,
            root_cause.c_str(),
            (deadline.hit && !deadline.cancelled) ? 1 : 0,
            deadline.cancelled ? 1 : 0,
            static_cast<unsigned long long>(deadline.elapsed_ms()),
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
    std::uint32_t scanned_count = 0;
    std::string stop_reason;
    bool stopped = false;
    auto stop_scan = [&](const char* reason, const char* stage) {
        stopped = true;
        if (reason && stop_reason.empty())
            stop_reason = reason;
        deadline.expired(stage);
    };

    for (const auto& module : modules) {
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
            std::uint64_t callsite = read_base + i;

            if (bytes[i] == 0xe8 && i + 5 <= bytes.size()) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
                const std::uint64_t target = rel32_target(read_base + i + 5, rel);
                if (auto ait = api_by_address.find(target); ait != api_by_address.end())
                    api = ait->second;
                else if (auto tit = thunks.find(target); tit != thunks.end())
                    api = tit->second;
            } else if (bytes[i] == 0xff && bytes[i + 1] == 0x15) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes.data() + i + 2, sizeof(rel));
                const std::uint64_t slot = rel32_target(read_base + i + 6, rel);
                if (auto sit = import_slots.find(slot); sit != import_slots.end()) {
                    api = sit->second;
                    iat = true;
                }
            }

            if (!api)
                continue;
            ++candidate_hits;
            ++module_candidate_hits;
            const std::uint64_t handler = find_probable_function_start(bytes, i, read_base);
            add_sendrecv_result(results, seen_callsites, module, bytes, read_base, *api, callsite, handler, 0, iat, excluded_targets, options.max_results);
        }
        module_diag["callsite_scan_elapsed_ms"] = GetTickCount64() - callsites_t0;
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
    out["diagnostics"] = nlohmann::json{
        {"socket_resolution", socket_resolution},
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
        "IAT and direct relative calls are detected; custom syscall wrappers may require manual follow-up",
        "serializer and deserializer addresses are nearest-call heuristics unless a dedicated trace confirms writes",
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
    std::uint32_t pid = 0;
    if (!ensure_process_context(input.process_id, pid, error))
        return false;

    serializer_trace_options_t options = input;
    if (options.max_captures == 0)
        options.max_captures = 16;
    if (options.max_captures > 32)
        options.max_captures = 32;
    if (options.sample_ms == 0)
        options.sample_ms = 2000;
    if (options.sample_ms > 10000)
        options.sample_ms = 10000;

    const int buf_arg = pre_encrypt_arg_index(options.buffer_reg);
    const int size_arg = pre_encrypt_arg_index(options.size_reg);
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
    std::vector<std::vector<std::uint8_t>> samples;
    nlohmann::json captures = nlohmann::json::array();
    std::string backend = "pre_encrypt_hook";
    bool pre_encrypt_attempted = buf_arg >= 0 && size_arg >= 0;
    bool pre_encrypt_hook_installed = false;
    bool pre_encrypt_polling_started = false;
    bool pre_encrypt_started = false;
    std::uint32_t pre_encrypt_unhook_removed = 0;
    DWORD pre_encrypt_debugger_error = ERROR_SUCCESS;
    std::string pre_encrypt_fallback_reason;
    bool driver_sniff_attempted = false;
    bool driver_sniff_started = false;
    bool driver_sniff_active_after_get = false;

    diag::log_tagged_fmt("net_proto",
        "trace_serializer begin pid=%u serializer=0x%llX buffer_reg=%s size_reg=%s pre_buf=%d pre_size=%d driver_buf=%u driver_size=%u sample_ms=%u max_captures=%u",
        pid,
        static_cast<unsigned long long>(options.serializer_va),
        options.buffer_reg.c_str(),
        options.size_reg.c_str(),
        buf_arg,
        size_arg,
        driver_buf_reg,
        driver_size_reg,
        options.sample_ms,
        options.max_captures);

    if (buf_arg >= 0 && size_arg >= 0) {
        pre_encrypt_hook_installed = pre_encrypt_hook::hook_address(options.serializer_va, "net_proto_serializer",
            static_cast<std::uint32_t>(buf_arg),
            static_cast<std::uint32_t>(size_arg));
        if (pre_encrypt_hook_installed)
            pre_encrypt_polling_started = pre_encrypt_hook::start_polling();
        pre_encrypt_debugger_error = pre_encrypt_hook::g_state.debugger_error.load();
        if (!pre_encrypt_hook_installed)
            pre_encrypt_fallback_reason = "pre_encrypt_hook_install_failed";
        else if (!pre_encrypt_polling_started)
            pre_encrypt_fallback_reason = "pre_encrypt_polling_start_failed";
        diag::log_tagged_fmt("net_proto",
            "trace_serializer pre_encrypt_setup attempted=1 installed=%d polling_started=%d debugger_error=%lu fallback_reason=%s",
            pre_encrypt_hook_installed ? 1 : 0,
            pre_encrypt_polling_started ? 1 : 0,
            static_cast<unsigned long>(pre_encrypt_debugger_error),
            pre_encrypt_fallback_reason.empty() ? "<none>" : pre_encrypt_fallback_reason.c_str());
    }

    if (pre_encrypt_hook_installed && pre_encrypt_polling_started) {
        pre_encrypt_started = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(options.sample_ms));
        auto caps = pre_encrypt_hook::get_captures(options.max_captures);
        pre_encrypt_unhook_removed = pre_encrypt_hook::unhook_all();
        diag::log_tagged_fmt("net_proto",
            "trace_serializer pre_encrypt_done installed=%d polling_started=%d captures=%zu sample_ms=%u unhook_removed=%u debugger_error=%lu",
            pre_encrypt_hook_installed ? 1 : 0,
            pre_encrypt_polling_started ? 1 : 0,
            caps.size(),
            options.sample_ms,
            pre_encrypt_unhook_removed,
            static_cast<unsigned long>(pre_encrypt_debugger_error));
        for (const auto& cap : caps) {
            samples.push_back(cap.buffer);
            nlohmann::json c;
            c["timestamp"] = cap.timestamp;
            c["thread_id"] = cap.tid;
            c["rip"] = fmt_addr(cap.rip);
            c["function"] = cap.function_name;
            c["size"] = cap.buffer.size();
            c["hex_preview"] = game_protocol::bytes_to_hex(cap.buffer, 128);
            captures.push_back(std::move(c));
        }
    } else {
        pre_encrypt_unhook_removed = pre_encrypt_hook::unhook_all();
        backend = "driver_sniff_net_buffers";
        driver_sniff_attempted = true;
        diag::log_tagged_fmt("net_proto",
            "trace_serializer driver_fallback pre_attempted=%d installed=%d polling_started=%d unhook_removed=%u debugger_error=%lu reason=%s",
            pre_encrypt_attempted ? 1 : 0,
            pre_encrypt_hook_installed ? 1 : 0,
            pre_encrypt_polling_started ? 1 : 0,
            pre_encrypt_unhook_removed,
            static_cast<unsigned long>(pre_encrypt_debugger_error),
            pre_encrypt_fallback_reason.empty() ? "<none>" : pre_encrypt_fallback_reason.c_str());
        if (!driver_bridge::sniff_net_buffers_start(options.serializer_va,
                driver_buf_reg,
                driver_size_reg,
                options.max_captures,
                options.tid,
                0)) {
            error = driver_bridge::last_error().empty() ? "failed to start serializer trace" : driver_bridge::last_error();
            out["process_id"] = pid;
            out["serializer_va"] = fmt_addr(options.serializer_va);
            out["buffer_reg"] = options.buffer_reg;
            out["size_reg"] = options.size_reg;
            out["backend"] = backend;
            out["pre_encrypt_attempted"] = pre_encrypt_attempted;
            out["pre_encrypt_hook_installed"] = pre_encrypt_hook_installed;
            out["pre_encrypt_polling_started"] = pre_encrypt_polling_started;
            out["pre_encrypt_started"] = pre_encrypt_started;
            out["pre_encrypt_unhook_removed"] = pre_encrypt_unhook_removed;
            out["pre_encrypt_debugger_error"] = static_cast<unsigned long>(pre_encrypt_debugger_error);
            out["pre_encrypt_fallback_reason"] = pre_encrypt_fallback_reason;
            out["driver_sniff_attempted"] = driver_sniff_attempted;
            out["driver_sniff_started"] = driver_sniff_started;
            out["driver_error"] = error;
            out["functional_success"] = false;
            out["zero_capture_reason"] = "driver serializer buffer sniffing did not start after pre-encrypt hook fallback";
            return false;
        }
        driver_sniff_started = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(options.sample_ms));
        bool active = false;
        auto caps = driver_bridge::sniff_net_buffers_get(active);
        driver_bridge::sniff_net_buffers_stop();
        driver_sniff_active_after_get = active;
        diag::log_tagged_fmt("net_proto",
            "trace_serializer driver_sniff_done captures=%zu active_after_get=%d sample_ms=%u driver_error=%s",
            caps.size(),
            active ? 1 : 0,
            options.sample_ms,
            driver_bridge::last_error().c_str());
        for (const auto& cap : caps) {
            samples.push_back(cap.buffer);
            nlohmann::json c;
            c["timestamp"] = cap.timestamp;
            c["thread_id"] = cap.thread_id;
            c["size"] = cap.buffer.size();
            c["hex_preview"] = game_protocol::bytes_to_hex(cap.buffer, 128);
            captures.push_back(std::move(c));
        }
        out["driver_sniff_active_after_get"] = driver_sniff_active_after_get;
    }

    out["process_id"] = pid;
    out["serializer_va"] = fmt_addr(options.serializer_va);
    out["buffer_reg"] = options.buffer_reg;
    out["size_reg"] = options.size_reg;
    out["backend"] = backend;
    out["trace_method"] = "output_buffer_sampling";
    out["source_resolution"] = "source_va is null unless a capture backend reports a concrete source address; current fields are inferred from serializer output bytes";
    out["sample_ms"] = options.sample_ms;
    out["elapsed_ms"] = static_cast<std::uint64_t>(GetTickCount64()) - started;
    out["capture_window_ms"] = options.sample_ms;
    out["capture_count"] = captures.size();
    out["observed_capture_count"] = captures.size();
    out["saw_serializer_output"] = !samples.empty();
    out["stimulus_observed"] = !samples.empty();
    out["functional_success"] = !samples.empty();
    out["pre_encrypt_attempted"] = pre_encrypt_attempted;
    out["pre_encrypt_hook_installed"] = pre_encrypt_hook_installed;
    out["pre_encrypt_polling_started"] = pre_encrypt_polling_started;
    out["pre_encrypt_started"] = pre_encrypt_started;
    out["pre_encrypt_unhook_removed"] = pre_encrypt_unhook_removed;
    out["pre_encrypt_debugger_error"] = static_cast<unsigned long>(pre_encrypt_debugger_error);
    out["pre_encrypt_fallback_reason"] = pre_encrypt_fallback_reason;
    out["driver_sniff_attempted"] = driver_sniff_attempted;
    out["driver_sniff_started"] = driver_sniff_started;
    out["driver_sniff_active_after_get"] = driver_sniff_active_after_get;
    if (samples.empty())
        out["zero_capture_reason"] = backend == "pre_encrypt_hook"
            ? "pre-encrypt hook sampling completed without observing serializer output"
            : "driver serializer buffer sniffing completed without observing serializer output";
    out["captures"] = std::move(captures);
    out["fields"] = captures_to_fields(samples);
    out["field_count"] = out["fields"].size();
    out["confidence"] = samples.empty() ? 0.18 : (std::min)(0.78, 0.42 + 0.06 * static_cast<double>((std::min)(samples.size(), std::size_t(6))));
    out["evidence"] = samples.empty()
        ? nlohmann::json::array({"no serializer breakpoint hits observed during bounded sample"})
        : nlohmann::json::array({"captured serializer output buffers", "field offsets are inferred from payload bytes and sample variance", "source addresses are not claimed without taint provenance"});
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
        std::uint32_t index = 0;
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
            p.local_port = 41000 + index;
            p.remote_port = 42000 + index;
            p.payload = payload;
            p.payload_size = static_cast<std::uint32_t>(p.payload.size());
            packets.push_back(std::move(p));
            ++index;
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
            if (session.messages.size() < 256)
                session.messages.push_back(std::move(m));
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
            sj["confidence"] = session.messages.size() >= 2 ? 0.62 : 0.36;
            sj["evidence"] = nlohmann::json::array();
            nlohmann::json messages_json = nlohmann::json::array();
            std::set<std::string> schemes;
            for (const auto& message : session.messages) {
                schemes.insert(message.scheme);
                if (messages_json.size() >= 32)
                    continue;
                nlohmann::json mj;
                mj["sequence"] = message.sequence;
                mj["scheme"] = message.scheme;
                mj["payload_size"] = message.payload.size();
                mj["payload_hex"] = game_protocol::bytes_to_hex(message.payload, 128);
                messages_json.push_back(std::move(mj));
            }
            for (const auto& scheme : schemes)
                sj["evidence"].push_back(scheme);
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

    auto mutations = make_mutations(session, lower_copy(options.mutation_strategy), options.max_mutations, options.payload_cap);
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

    for (const auto& payload : mutations) {
        const bool ok = driver_bridge::inject_packet(1, 17, 2, src_port, options.target_port,
            src_addr, target_addr, payload.data(), static_cast<std::uint32_t>(payload.size()));
        if (ok)
            ++sent;
        if (sent_json.size() < 32) {
            nlohmann::json sj;
            sj["ok"] = ok;
            sj["payload_size"] = payload.size();
            sj["hex_preview"] = game_protocol::bytes_to_hex(payload, 96);
            sent_json.push_back(std::move(sj));
        }
    }

    if (options.response_wait_ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(options.response_wait_ms));

    nlohmann::json responses = nlohmann::json::array();
    if (capture_started) {
        auto packets = driver_bridge::get_captured_packets(64);
        driver_bridge::stop_capture();
        for (const auto& p : packets) {
            if (responses.size() >= 32)
                break;
            if (p.protocol != 17)
                continue;
            nlohmann::json r;
            r["pid"] = p.pid;
            r["direction"] = p.direction == 0 ? "inbound" : "outbound";
            r["local"] = format_ip(p.local_addr, p.address_family) + ":" + std::to_string(p.local_port);
            r["remote"] = format_ip(p.remote_addr, p.address_family) + ":" + std::to_string(p.remote_port);
            r["payload_size"] = p.payload.size();
            r["hex_preview"] = game_protocol::bytes_to_hex(p.payload, 96);
            responses.push_back(std::move(r));
        }
    }

    out["session_id"] = options.session_id;
    out["replay_requires_existing_session"] = true;
    out["record_operation"] = "net_udp_session_reassemble";
    out["recorded_message_count"] = session.messages.size();
    out["target"] = options.target_ip + ":" + std::to_string(options.target_port);
    out["mutation_strategy"] = options.mutation_strategy;
    out["max_mutations"] = options.max_mutations;
    out["payload_cap"] = options.payload_cap;
    out["mutations_generated"] = mutations.size();
    out["mutations_sent"] = sent;
    out["sent_preview"] = std::move(sent_json);
    out["response_capture_started"] = capture_started;
    out["interesting_responses"] = std::move(responses);
    out["limitations"] = nlohmann::json::array({
        "mutations are generated from inferred numeric fields and may not preserve checksums or encryption",
        "responses are bounded packet previews, not proof of server-side state changes",
        "loopback is enforced unless allow_non_loopback is explicitly set"
    });
    return true;
}

}
