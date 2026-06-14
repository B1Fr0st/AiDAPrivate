#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "net_proto_analysis.hpp"

#include "game_protocol.hpp"
#include "pre_encrypt_hook.hpp"
#include "standalone_driver.hpp"
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
#include <thread>
#include <vector>

namespace net_proto_analysis {
namespace {

struct api_target_t {
    std::string name;
    std::string direction;
    std::uint64_t address = 0;
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
        if (std::chrono::steady_clock::now() < deadline)
            return false;
        hit = true;
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

std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
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

bool is_socket_module(const std::string& lower_name)
{
    return lower_name.find("ws2_32") != std::string::npos ||
           lower_name.find("mswsock") != std::string::npos ||
           lower_name.find("wsock32") != std::string::npos;
}

const wchar_t* socket_module_dll_name(const std::string& lower_name)
{
    if (lower_name.find("ws2_32") != std::string::npos)
        return L"ws2_32.dll";
    if (lower_name.find("mswsock") != std::string::npos)
        return L"mswsock.dll";
    if (lower_name.find("wsock32") != std::string::npos)
        return L"wsock32.dll";
    return nullptr;
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

std::uint64_t resolve_local_export_rva(const std::string& lower_module_name,
                                       const char* export_name,
                                       nlohmann::json& diag)
{
    diag = nlohmann::json::object();
    diag["export"] = export_name ? export_name : "";
    diag["source"] = "local_rva";
    const wchar_t* dll = socket_module_dll_name(lower_module_name);
    if (!dll) {
        diag["ok"] = false;
        diag["reason"] = "not_a_known_socket_module";
        return 0;
    }
    HMODULE module = GetModuleHandleW(dll);
    bool loaded_for_lookup = false;
    if (!module) {
        module = LoadLibraryExW(dll, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32 | DONT_RESOLVE_DLL_REFERENCES);
        loaded_for_lookup = module != nullptr;
    }
    if (!module) {
        diag["ok"] = false;
        diag["reason"] = "local_module_unavailable";
        diag["gle"] = GetLastError();
        return 0;
    }
    const auto base = reinterpret_cast<std::uint64_t>(module);
    const std::uint64_t size = local_image_size(module);
    FARPROC proc = export_name ? GetProcAddress(module, export_name) : nullptr;
    std::uint64_t rva = 0;
    if (proc && size) {
        const std::uint64_t addr = reinterpret_cast<std::uint64_t>(proc);
        if (addr >= base && addr < base + size)
            rva = addr - base;
    }
    diag["ok"] = rva != 0;
    diag["module_size"] = size;
    diag["loaded_for_lookup"] = loaded_for_lookup;
    if (rva)
        diag["rva"] = fmt_addr(rva);
    else
        diag["reason"] = proc ? "local_export_forwarded_or_outside_module" : "local_export_missing";
    if (loaded_for_lookup)
        FreeLibrary(module);
    return rva;
}

bool skip_scan_module(const driver_bridge::module_info_t& module)
{
    const std::string name = lower_copy(module.name);
    const std::string path = lower_copy(module.path);
    if (is_socket_module(name))
        return true;
    if (name == "ntdll.dll" || name == "kernel32.dll" || name == "kernelbase.dll" ||
        name == "ucrtbase.dll" || name == "vcruntime140.dll")
        return true;
    if (path.find("\\windows\\system32\\") != std::string::npos ||
        path.find("\\windows\\syswow64\\") != std::string::npos)
        return true;
    return false;
}

std::vector<api_target_t> resolve_socket_apis(const std::vector<driver_bridge::module_info_t>& modules,
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
    diagnostics["local_rva_hits"] = 0;
    diagnostics["remote_fallback_attempts"] = 0;
    diagnostics["remote_fallback_hits"] = 0;
    for (const auto& module : modules) {
        if (deadline.expired("resolve_socket_exports_module"))
            break;
        const std::string lower_name = lower_copy(module.name);
        if (!is_socket_module(lower_name))
            continue;
        if (diagnostics["socket_modules"].size() < 8)
            diagnostics["socket_modules"].push_back(nlohmann::json{{"name", module.name}, {"base", fmt_addr(module.base)}, {"size", module.size}, {"path", module.path}});
        for (const auto& n : names) {
            if (deadline.expired("resolve_socket_exports_export"))
                break;
            nlohmann::json rdiag;
            const std::uint64_t rva = resolve_local_export_rva(lower_name, n.name, rdiag);
            std::uint64_t va = 0;
            if (rva != 0 && (module.size == 0 || rva < module.size)) {
                va = module.base + rva;
                rdiag["remote_va"] = fmt_addr(va);
                diagnostics["local_rva_hits"] = diagnostics.value("local_rva_hits", 0) + 1;
            } else {
                if (rva != 0)
                    rdiag["reason"] = "local_rva_outside_remote_module_size";
                if (deadline.remaining_ms() > 100) {
                    diagnostics["remote_fallback_attempts"] = diagnostics.value("remote_fallback_attempts", 0) + 1;
                    const ULONGLONG t0 = GetTickCount64();
                    va = driver_bridge::resolve_export(module.base, n.name);
                    rdiag["remote_fallback_elapsed_ms"] = GetTickCount64() - t0;
                    rdiag["remote_fallback_va"] = va ? nlohmann::json(fmt_addr(va)) : nlohmann::json(nullptr);
                    if (va)
                        diagnostics["remote_fallback_hits"] = diagnostics.value("remote_fallback_hits", 0) + 1;
                } else {
                    rdiag["remote_fallback_skipped"] = true;
                    rdiag["remote_fallback_skip_reason"] = "deadline_remaining_too_small";
                }
            }
            rdiag["module"] = module.name;
            rdiag["module_base"] = fmt_addr(module.base);
            rdiag["deadline_hit"] = deadline.hit;
            if (diagnostics["export_resolution"].size() < 32)
                diagnostics["export_resolution"].push_back(std::move(rdiag));
            if (va == 0)
                continue;
            apis.push_back({n.name, n.direction, va});
        }
    }
    diagnostics["api_count"] = apis.size();
    diagnostics["deadline_hit"] = deadline.hit;
    diagnostics["stage"] = deadline.stage;
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

    const std::size_t call_off = static_cast<std::size_t>(callsite - module.base);
    std::uint64_t neighbor = adjacent;
    if (neighbor == 0)
        neighbor = nearest_internal_call(bytes, call_off, module.base, excluded_targets, api.direction == "recv");

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
        "find_sendrecv begin pid=%u max_results=%u max_modules=%u max_scan_bytes=%llu timeout_ms=%u",
        pid,
        options.max_results,
        options.max_modules,
        static_cast<unsigned long long>(options.max_scan_bytes),
        options.timeout_ms);
    deadline.stage = "enumerate_modules";
    auto modules = driver_bridge::enumerate_modules_for(pid);
    nlohmann::json socket_resolution = nlohmann::json::object();
    if (!deadline.expired("resolve_socket_exports"))
        socket_resolution["module_count"] = modules.size();
    const auto apis = deadline.hit ? std::vector<api_target_t>() : resolve_socket_apis(modules, deadline, socket_resolution);
    if (apis.empty()) {
        out["process_id"] = pid;
        out["results"] = nlohmann::json::array();
        out["result_count"] = 0;
        out["count"] = 0;
        out["deadline_hit"] = deadline.hit;
        out["elapsed_ms"] = deadline.elapsed_ms();
        out["timeout_ms"] = options.timeout_ms;
        out["scanned_modules"] = nlohmann::json::array();
        out["scanned_module_count"] = 0;
        out["scanned_bytes"] = 0;
        out["stage"] = deadline.stage;
        out["socket_api_count"] = 0;
        out["diagnostics"] = nlohmann::json{{"socket_resolution", socket_resolution}};
        out["evidence"] = nlohmann::json::array({"socket API exports not resolved in loaded modules"});
        out["limitations"] = nlohmann::json::array({
            "socket API export resolution stopped before scanning application modules",
            "no send/recv callsite results are fabricated when socket exports are unavailable"
        });
        diag::log_tagged_fmt("net_proto",
            "find_sendrecv done pid=%u results=0 apis=0 scanned_modules=0 scanned_bytes=0 deadline_hit=%d elapsed_ms=%llu stage=%s",
            pid,
            deadline.hit ? 1 : 0,
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
    std::set<std::uint64_t> seen_callsites;
    std::uint64_t scanned_bytes = 0;
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
            stop_scan("deadline_before_module", "module_loop");
            break;
        }
        if (results.size() >= options.max_results)
            break;
        if (scanned_count >= options.max_modules || scanned_bytes >= options.max_scan_bytes) {
            stop_reason = scanned_count >= options.max_modules ? "max_modules_reached" : "max_scan_bytes_reached";
            break;
        }
        if (skip_scan_module(module) || module.base == 0 || module.size < 16)
            continue;

        const std::uint64_t remaining = options.max_scan_bytes - scanned_bytes;
        const std::size_t to_read = static_cast<std::size_t>((std::min<std::uint64_t>)(module.size, (std::min<std::uint64_t>)(remaining, 16777216)));
        std::vector<std::uint8_t> bytes;
        nlohmann::json module_diag;
        module_diag["name"] = module.name;
        module_diag["base"] = fmt_addr(module.base);
        module_diag["size"] = module.size;
        module_diag["path"] = module.path;
        module_diag["requested_read_bytes"] = to_read;
        deadline.stage = "module_read";
        const ULONGLONG read_t0 = GetTickCount64();
        const bool read_ok = driver_bridge::read_memory_for(pid, module.base, to_read, bytes);
        module_diag["read_ok"] = read_ok;
        module_diag["read_elapsed_ms"] = GetTickCount64() - read_t0;
        module_diag["bytes_read"] = bytes.size();
        if (!read_ok || bytes.size() < 16) {
            module_diag["rejection_reason"] = read_ok ? "read_too_small" : "read_failed";
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            if (deadline.expired("after_module_read")) {
                stop_scan("deadline_after_module_read", "after_module_read");
                break;
            }
            continue;
        }
        if (deadline.expired("after_module_read")) {
            module_diag["deadline_hit_after_read"] = true;
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            stop_scan("deadline_after_module_read", "after_module_read");
            break;
        }

        ++scanned_count;
        scanned_bytes += bytes.size();
        scanned_modules.push_back(module.name);

        std::map<std::uint64_t, const api_target_t*> import_slots;
        for (std::size_t i = 0; i + 8 <= bytes.size(); i += 1) {
            if ((i & 0x3fffu) == 0 && deadline.expired("scan_import_slots")) {
                stop_scan("deadline_import_slot_scan", "scan_import_slots");
                break;
            }
            const std::uint64_t ptr = le64(bytes.data() + i);
            auto it = api_by_address.find(ptr);
            if (it != api_by_address.end())
                import_slots[module.base + i] = it->second;
        }
        module_diag["import_slot_count"] = import_slots.size();
        if (stopped) {
            module_diag["stop_reason"] = stop_reason;
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            break;
        }

        std::map<std::uint64_t, const api_target_t*> thunks;
        for (std::size_t i = 0; i + 6 <= bytes.size(); ++i) {
            if ((i & 0x3fffu) == 0 && deadline.expired("scan_import_thunks")) {
                stop_scan("deadline_import_thunk_scan", "scan_import_thunks");
                break;
            }
            if (bytes[i] != 0xff || bytes[i + 1] != 0x25)
                continue;
            std::int32_t rel = 0;
            std::memcpy(&rel, bytes.data() + i + 2, sizeof(rel));
            const std::uint64_t slot = rel32_target(module.base + i + 6, rel);
            auto sit = import_slots.find(slot);
            if (sit != import_slots.end())
                thunks[module.base + i] = sit->second;
        }
        for (const auto& t : thunks)
            excluded_targets.insert(t.first);
        module_diag["import_thunk_count"] = thunks.size();
        if (stopped) {
            module_diag["stop_reason"] = stop_reason;
            if (module_diagnostics.size() < 32)
                module_diagnostics.push_back(std::move(module_diag));
            break;
        }

        for (std::size_t i = 0; i + 6 <= bytes.size() && results.size() < options.max_results; ++i) {
            if ((i & 0x3fffu) == 0 && deadline.expired("scan_callsites")) {
                stop_scan("deadline_callsite_scan", "scan_callsites");
                break;
            }
            const api_target_t* api = nullptr;
            bool iat = false;
            std::uint64_t callsite = module.base + i;

            if (bytes[i] == 0xe8 && i + 5 <= bytes.size()) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes.data() + i + 1, sizeof(rel));
                const std::uint64_t target = rel32_target(module.base + i + 5, rel);
                if (auto ait = api_by_address.find(target); ait != api_by_address.end())
                    api = ait->second;
                else if (auto tit = thunks.find(target); tit != thunks.end())
                    api = tit->second;
            } else if (bytes[i] == 0xff && bytes[i + 1] == 0x15) {
                std::int32_t rel = 0;
                std::memcpy(&rel, bytes.data() + i + 2, sizeof(rel));
                const std::uint64_t slot = rel32_target(module.base + i + 6, rel);
                if (auto sit = import_slots.find(slot); sit != import_slots.end()) {
                    api = sit->second;
                    iat = true;
                }
            }

            if (!api)
                continue;
            const std::uint64_t handler = find_probable_function_start(bytes, i, module.base);
            add_sendrecv_result(results, seen_callsites, module, bytes, *api, callsite, handler, 0, iat, excluded_targets, options.max_results);
        }
        module_diag["results_after_module"] = results.size();
        module_diag["deadline_hit"] = deadline.hit;
        module_diag["elapsed_ms"] = deadline.elapsed_ms();
        if (module_diagnostics.size() < 32)
            module_diagnostics.push_back(std::move(module_diag));
        if (stopped)
            break;
    }

    out["process_id"] = pid;
    out["results"] = std::move(results);
    out["result_count"] = out["results"].size();
    out["count"] = out["result_count"];
    out["deadline_hit"] = deadline.hit;
    out["elapsed_ms"] = deadline.elapsed_ms();
    out["timeout_ms"] = options.timeout_ms;
    out["scanned_modules"] = std::move(scanned_modules);
    out["scanned_module_count"] = scanned_count;
    out["scanned_bytes"] = scanned_bytes;
    out["socket_api_count"] = apis.size();
    out["stage"] = deadline.hit ? deadline.stage : (stop_reason.empty() ? "complete" : stop_reason);
    out["diagnostics"] = nlohmann::json{
        {"socket_resolution", socket_resolution},
        {"module_diagnostics", module_diagnostics},
        {"stop_reason", stop_reason.empty() ? "complete" : stop_reason},
        {"seen_callsite_count", seen_callsites.size()}
    };
    out["limitations"] = nlohmann::json::array({
        "IAT and direct relative calls are detected; custom syscall wrappers may require manual follow-up",
        "serializer and deserializer addresses are nearest-call heuristics unless a dedicated trace confirms writes",
        "system modules are skipped to focus on application handlers",
        "bounded deadline returns partial diagnostics without inventing send/recv handlers"
    });
    diag::log_tagged_fmt("net_proto",
        "find_sendrecv done pid=%u results=%u apis=%zu scanned_modules=%u scanned_bytes=%llu deadline_hit=%d elapsed_ms=%llu stage=%s stop=%s",
        pid,
        static_cast<unsigned>(out["result_count"].get<std::size_t>()),
        apis.size(),
        scanned_count,
        static_cast<unsigned long long>(scanned_bytes),
        deadline.hit ? 1 : 0,
        static_cast<unsigned long long>(deadline.elapsed_ms()),
        out["stage"].get<std::string>().c_str(),
        stop_reason.empty() ? "complete" : stop_reason.c_str());
    return true;
}

bool trace_serializer(const serializer_trace_options_t& input,
                      nlohmann::json& out,
                      std::string& error)
{
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

    if (buf_arg >= 0 && size_arg >= 0 &&
        pre_encrypt_hook::hook_address(options.serializer_va, "net_proto_serializer",
                                       static_cast<std::uint32_t>(buf_arg),
                                       static_cast<std::uint32_t>(size_arg)) &&
        pre_encrypt_hook::start_polling()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(options.sample_ms));
        auto caps = pre_encrypt_hook::get_captures(options.max_captures);
        pre_encrypt_hook::unhook_all();
        diag::log_tagged_fmt("net_proto",
            "trace_serializer pre_encrypt_done captures=%zu sample_ms=%u",
            caps.size(),
            options.sample_ms);
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
        pre_encrypt_hook::unhook_all();
        backend = "driver_sniff_net_buffers";
        if (!driver_bridge::sniff_net_buffers_start(options.serializer_va,
                driver_buf_reg,
                driver_size_reg,
                options.max_captures,
                options.tid,
                0)) {
            error = driver_bridge::last_error().empty() ? "failed to start serializer trace" : driver_bridge::last_error();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(options.sample_ms));
        bool active = false;
        auto caps = driver_bridge::sniff_net_buffers_get(active);
        driver_bridge::sniff_net_buffers_stop();
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
        out["driver_sniff_active_after_get"] = active;
    }

    out["process_id"] = pid;
    out["serializer_va"] = fmt_addr(options.serializer_va);
    out["buffer_reg"] = options.buffer_reg;
    out["size_reg"] = options.size_reg;
    out["backend"] = backend;
    out["trace_method"] = "output_buffer_sampling";
    out["source_resolution"] = "source_va is null unless a capture backend reports a concrete source address; current fields are inferred from serializer output bytes";
    out["sample_ms"] = options.sample_ms;
    out["capture_count"] = captures.size();
    out["captures"] = std::move(captures);
    out["fields"] = captures_to_fields(samples);
    out["field_count"] = out["fields"].size();
    out["confidence"] = samples.empty() ? 0.18 : (std::min)(0.78, 0.42 + 0.06 * static_cast<double>((std::min)(samples.size(), std::size_t(6))));
    out["evidence"] = samples.empty()
        ? nlohmann::json::array({"no serializer breakpoint hits observed during bounded sample"})
        : nlohmann::json::array({"captured serializer output buffers", "field offsets are inferred from payload bytes and sample variance", "source addresses are not claimed without taint provenance"});
    diag::log_tagged_fmt("net_proto",
        "trace_serializer done backend=%s captures=%u fields=%u confidence=%.3f",
        backend.c_str(),
        out.value("capture_count", 0u),
        out.value("field_count", 0u),
        out.value("confidence", 0.0));
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
    if (input.target_ip.empty() || input.target_port == 0 || input.target_port > 65535) {
        error = "target_ip and valid target_port are required";
        return false;
    }

    std::uint8_t target_addr[16] = {};
    if (!parse_ipv4(input.target_ip, target_addr)) {
        error = "target_ip must be an IPv4 literal";
        return false;
    }
    if (is_blocked_target(target_addr)) {
        error = "target_ip is multicast, broadcast, unspecified, or link-local";
        return false;
    }
    if (!is_loopback(target_addr, 2) && !input.allow_non_loopback) {
        error = "non-loopback mutation replay requires allow_non_loopback=true";
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
    {
        std::lock_guard<std::mutex> lock(udp_mutex());
        auto it = udp_sessions().find(options.session_id);
        if (it == udp_sessions().end()) {
            error = "session_id not found";
            return false;
        }
        session = it->second;
    }

    auto mutations = make_mutations(session, lower_copy(options.mutation_strategy), options.max_mutations, options.payload_cap);
    if (mutations.empty()) {
        error = "no mutations generated within payload cap";
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
