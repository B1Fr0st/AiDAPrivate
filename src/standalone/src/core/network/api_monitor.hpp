#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "standalone_driver.hpp"
#include "../infra/work_queue.hpp"
#include "helpers/diag_log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace api_monitor {

enum class api_kind_t : uint32_t {
    generic = 0,
    send_linear,
    wsa_send,
    send_to,
    wsa_send_to,
    recv_linear,
    wsa_recv,
    recv_from,
    wsa_recv_from,
    connect_call,
    device_io_control,
    nt_device_io_control,
    write_file,
    read_file,
    encrypt_message,
    custom_linear
};

struct api_request_t {
    std::string original;
    std::string module_name;
    std::string function_name;
    api_kind_t kind = api_kind_t::generic;
    int buffer_reg = -1;
    int size_reg = -1;
};

struct api_target_t {
    api_request_t request;
    uint64_t address = 0;
    std::string resolved_module;
    uint64_t module_base = 0;
    uint64_t module_offset = 0;
    uint32_t bp_index = 0;
    bool active = false;
    std::vector<uint32_t> armed_tids;
};

struct register_snapshot_t {
    uint64_t rax = 0;
    uint64_t rbx = 0;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uint64_t rsi = 0;
    uint64_t rdi = 0;
    uint64_t rbp = 0;
    uint64_t rsp = 0;
    uint64_t r8 = 0;
    uint64_t r9 = 0;
    uint64_t r10 = 0;
    uint64_t r11 = 0;
    uint64_t r12 = 0;
    uint64_t r13 = 0;
    uint64_t r14 = 0;
    uint64_t r15 = 0;
    uint64_t rip = 0;
    uint64_t rflags = 0;
};

struct buffer_capture_t {
    std::string kind;
    std::string direction;
    uint64_t address = 0;
    uint64_t requested_size = 0;
    uint64_t captured_size = 0;
    bool truncated = false;
    bool readable = false;
    std::vector<uint8_t> bytes;
};

struct frame_t {
    uint64_t address = 0;
    std::string module_name;
    uint64_t module_offset = 0;
};

struct api_event_t {
    uint64_t sequence = 0;
    uint64_t timestamp_ms = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    std::string api;
    uint64_t api_address = 0;
    std::string api_module;
    uint64_t api_module_offset = 0;
    uint64_t return_address = 0;
    uint64_t callsite_address = 0;
    std::string caller_module;
    uint64_t caller_module_offset = 0;
    register_snapshot_t regs;
    nlohmann::json metadata = nlohmann::json::object();
    std::vector<buffer_capture_t> buffers;
    std::vector<frame_t> callstack;
};

struct socket_cache_t {
    uint64_t timestamp_ms = 0;
    std::vector<driver_bridge::socket_info_t> sockets;
};

struct state_t {
    std::mutex mutex;
    std::vector<api_request_t> requested;
    std::vector<api_target_t> targets;
    std::vector<driver_bridge::module_info_t> modules;
    std::deque<api_event_t> events;
    socket_cache_t socket_cache;
    std::atomic<bool> active{false};
    std::atomic<bool> polling{false};
    std::atomic<bool> debug_attached{false};
    std::atomic<bool> debug_loop_running{false};
    std::atomic<bool> cleanup_running{false};
    std::atomic<DWORD> debugger_error{0};
    std::atomic<uint64_t> total_hits{0};
    std::atomic<uint64_t> cleanup_attempts{0};
    std::atomic<uint64_t> cleanup_last_elapsed_ms{0};
    std::atomic<uint32_t> cleanup_last_requests{0};
    std::atomic<uint32_t> cleanup_last_succeeded{0};
    std::atomic<uint32_t> cleanup_last_failed{0};
    uint32_t pid = 0;
    bool capture_buffer = true;
    bool log_callstack = false;
    uint32_t max_capture_bytes = 256;
    size_t max_events = 4096;
    uint64_t next_sequence = 1;
};

inline state_t g_state;

inline std::string trim(std::string text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

inline std::string to_lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

inline std::string basename_of(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

inline std::string strip_extension(std::string name) {
    const size_t dot = name.find_last_of('.');
    if (dot != std::string::npos)
        name.resize(dot);
    return name;
}

inline std::string hex_addr(uint64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

inline bool parse_u64(const std::string& text, uint64_t& out) {
    char* end = nullptr;
    errno = 0;
    unsigned long long value = std::strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str() || *end != '\0')
        return false;
    out = static_cast<uint64_t>(value);
    return true;
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0)
            os << ' ';
        os << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return os.str();
}

inline bool module_name_matches(const driver_bridge::module_info_t& module, const std::string& requested) {
    if (requested.empty())
        return true;
    const std::string want = to_lower(strip_extension(basename_of(requested)));
    const std::string have_name = to_lower(strip_extension(basename_of(module.name)));
    const std::string have_path = to_lower(strip_extension(basename_of(module.path)));
    return have_name == want || have_path == want;
}

inline api_kind_t infer_kind(const std::string& function_name) {
    const std::string name = to_lower(function_name);
    if (name == "send")
        return api_kind_t::send_linear;
    if (name == "wsasend")
        return api_kind_t::wsa_send;
    if (name == "sendto")
        return api_kind_t::send_to;
    if (name == "wsasendto")
        return api_kind_t::wsa_send_to;
    if (name == "recv")
        return api_kind_t::recv_linear;
    if (name == "wsarecv")
        return api_kind_t::wsa_recv;
    if (name == "recvfrom")
        return api_kind_t::recv_from;
    if (name == "wsarecvfrom")
        return api_kind_t::wsa_recv_from;
    if (name == "connect" || name == "wsaconnect")
        return api_kind_t::connect_call;
    if (name == "deviceiocontrol")
        return api_kind_t::device_io_control;
    if (name == "ntdeviceiocontrolfile" || name == "zwdeviceiocontrolfile")
        return api_kind_t::nt_device_io_control;
    if (name == "writefile" || name == "writefileex")
        return api_kind_t::write_file;
    if (name == "readfile" || name == "readfileex")
        return api_kind_t::read_file;
    if (name == "encryptmessage")
        return api_kind_t::encrypt_message;
    if (name == "ssl_write" || name == "pr_write" || name == "sslencryptpacket")
        return api_kind_t::custom_linear;
    return api_kind_t::generic;
}

inline const char* kind_name(api_kind_t kind) {
    switch (kind) {
    case api_kind_t::send_linear: return "send";
    case api_kind_t::wsa_send: return "wsasend";
    case api_kind_t::send_to: return "sendto";
    case api_kind_t::wsa_send_to: return "wsasendto";
    case api_kind_t::recv_linear: return "recv";
    case api_kind_t::wsa_recv: return "wsarecv";
    case api_kind_t::recv_from: return "recvfrom";
    case api_kind_t::wsa_recv_from: return "wsarecvfrom";
    case api_kind_t::connect_call: return "connect";
    case api_kind_t::device_io_control: return "deviceiocontrol";
    case api_kind_t::nt_device_io_control: return "ntdeviceiocontrolfile";
    case api_kind_t::write_file: return "writefile";
    case api_kind_t::read_file: return "readfile";
    case api_kind_t::encrypt_message: return "encryptmessage";
    case api_kind_t::custom_linear: return "linear";
    default: return "generic";
    }
}

inline uint64_t register_value(const CONTEXT& ctx, int index) {
    switch (index) {
    case 0: return static_cast<uint64_t>(ctx.Rcx);
    case 1: return static_cast<uint64_t>(ctx.Rdx);
    case 2: return static_cast<uint64_t>(ctx.R8);
    case 3: return static_cast<uint64_t>(ctx.R9);
    default: return 0;
    }
}

inline register_snapshot_t snapshot_registers(const CONTEXT& ctx) {
    register_snapshot_t r;
    r.rax = static_cast<uint64_t>(ctx.Rax);
    r.rbx = static_cast<uint64_t>(ctx.Rbx);
    r.rcx = static_cast<uint64_t>(ctx.Rcx);
    r.rdx = static_cast<uint64_t>(ctx.Rdx);
    r.rsi = static_cast<uint64_t>(ctx.Rsi);
    r.rdi = static_cast<uint64_t>(ctx.Rdi);
    r.rbp = static_cast<uint64_t>(ctx.Rbp);
    r.rsp = static_cast<uint64_t>(ctx.Rsp);
    r.r8 = static_cast<uint64_t>(ctx.R8);
    r.r9 = static_cast<uint64_t>(ctx.R9);
    r.r10 = static_cast<uint64_t>(ctx.R10);
    r.r11 = static_cast<uint64_t>(ctx.R11);
    r.r12 = static_cast<uint64_t>(ctx.R12);
    r.r13 = static_cast<uint64_t>(ctx.R13);
    r.r14 = static_cast<uint64_t>(ctx.R14);
    r.r15 = static_cast<uint64_t>(ctx.R15);
    r.rip = static_cast<uint64_t>(ctx.Rip);
    r.rflags = static_cast<uint64_t>(ctx.EFlags);
    return r;
}

inline bool read_target(uint32_t pid, uint64_t address, size_t size, std::vector<uint8_t>& out) {
    out.clear();
    if (pid == 0 || address == 0 || size == 0)
        return false;
    if (!driver_bridge::read_memory_for(pid, address, size, out))
        return false;
    if (out.size() > size)
        out.resize(size);
    return !out.empty();
}

template <typename T>
inline bool read_target_value(uint32_t pid, uint64_t address, T& out) {
    std::vector<uint8_t> raw;
    if (!read_target(pid, address, sizeof(T), raw) || raw.size() < sizeof(T))
        return false;
    std::memcpy(&out, raw.data(), sizeof(T));
    return true;
}

inline uint64_t stack_arg64(uint32_t pid, uint64_t rsp, uint32_t arg_index) {
    uint64_t value = 0;
    const uint64_t address = rsp + 0x28 + static_cast<uint64_t>(arg_index) * 8;
    read_target_value(pid, address, value);
    return value;
}

inline uint64_t bounded_size(uint64_t requested, uint32_t max_capture_bytes) {
    if (requested == 0)
        return 0;
    if (requested > max_capture_bytes)
        return max_capture_bytes;
    return requested;
}

inline void append_buffer_capture(std::vector<buffer_capture_t>& buffers,
                                  uint32_t pid,
                                  const std::string& kind,
                                  const std::string& direction,
                                  uint64_t address,
                                  uint64_t requested_size,
                                  uint32_t max_capture_bytes,
                                  bool capture_bytes) {
    buffer_capture_t b;
    b.kind = kind;
    b.direction = direction;
    b.address = address;
    b.requested_size = requested_size;
    b.truncated = requested_size > max_capture_bytes;
    if (capture_bytes && address != 0 && requested_size != 0) {
        const uint64_t take = bounded_size(requested_size, max_capture_bytes);
        std::vector<uint8_t> raw;
        if (read_target(pid, address, static_cast<size_t>(take), raw)) {
            b.bytes = std::move(raw);
            b.captured_size = static_cast<uint64_t>(b.bytes.size());
            b.readable = true;
        }
    }
    buffers.push_back(std::move(b));
}

inline void capture_linear_buffer(std::vector<buffer_capture_t>& buffers,
                                  uint32_t pid,
                                  const std::string& direction,
                                  uint64_t address,
                                  uint64_t size,
                                  uint32_t max_capture_bytes,
                                  bool capture_bytes) {
    append_buffer_capture(buffers, pid, "linear", direction, address, size, max_capture_bytes, capture_bytes);
}

inline void capture_wsabufs(std::vector<buffer_capture_t>& buffers,
                            uint32_t pid,
                            uint64_t array_address,
                            uint64_t count,
                            const std::string& direction,
                            uint32_t max_capture_bytes,
                            bool capture_bytes,
                            nlohmann::json& metadata) {
    struct remote_wsabuf_t {
        uint32_t len;
        uint32_t pad;
        uint64_t buf;
    };

    metadata["wsabuf_array"] = hex_addr(array_address);
    metadata["wsabuf_count_requested"] = count;
    if (array_address == 0 || count == 0)
        return;
    if (count > 16)
        count = 16;
    metadata["wsabuf_count_parsed"] = count;

    std::vector<uint8_t> raw;
    if (!read_target(pid, array_address, static_cast<size_t>(count) * sizeof(remote_wsabuf_t), raw))
        return;

    const size_t parsed = raw.size() / sizeof(remote_wsabuf_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_wsabuf_t entry{};
        std::memcpy(&entry, raw.data() + i * sizeof(remote_wsabuf_t), sizeof(entry));
        append_buffer_capture(buffers, pid, "wsabuf", direction, entry.buf, entry.len, max_capture_bytes, capture_bytes);
    }
}

inline void capture_sec_buffers(std::vector<buffer_capture_t>& buffers,
                                uint32_t pid,
                                uint64_t desc_address,
                                uint32_t max_capture_bytes,
                                bool capture_bytes,
                                nlohmann::json& metadata) {
    struct remote_sec_buffer_desc_t {
        uint32_t ulVersion;
        uint32_t cBuffers;
        uint64_t pBuffers;
    };
    struct remote_sec_buffer_t {
        uint32_t cbBuffer;
        uint32_t BufferType;
        uint64_t pvBuffer;
    };

    metadata["sec_buffer_desc"] = hex_addr(desc_address);
    if (desc_address == 0)
        return;

    remote_sec_buffer_desc_t desc{};
    if (!read_target_value(pid, desc_address, desc))
        return;
    metadata["sec_buffer_count_requested"] = desc.cBuffers;
    if (desc.cBuffers == 0 || desc.pBuffers == 0)
        return;
    if (desc.cBuffers > 16)
        desc.cBuffers = 16;
    metadata["sec_buffer_array"] = hex_addr(desc.pBuffers);
    metadata["sec_buffer_count_parsed"] = desc.cBuffers;

    std::vector<uint8_t> raw;
    if (!read_target(pid, desc.pBuffers, static_cast<size_t>(desc.cBuffers) * sizeof(remote_sec_buffer_t), raw))
        return;
    const size_t parsed = raw.size() / sizeof(remote_sec_buffer_t);
    for (size_t i = 0; i < parsed; ++i) {
        remote_sec_buffer_t entry{};
        std::memcpy(&entry, raw.data() + i * sizeof(remote_sec_buffer_t), sizeof(entry));
        if ((entry.BufferType & 0xFFFFu) != 1u)
            continue;
        append_buffer_capture(buffers, pid, "sec_buffer", "outbound", entry.pvBuffer, entry.cbBuffer,
                              max_capture_bytes, capture_bytes);
    }
}

inline uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline std::string format_ipv4(const uint8_t* p) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>(p[0]),
                  static_cast<unsigned>(p[1]),
                  static_cast<unsigned>(p[2]),
                  static_cast<unsigned>(p[3]));
    return buf;
}

inline std::string format_ipv6(const uint8_t* p) {
    char buf[64];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                  p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    return buf;
}

inline bool parse_sockaddr(uint32_t pid, uint64_t address, uint64_t length, nlohmann::json& out) {
    if (address == 0 || length < 4)
        return false;
    if (length > 64)
        length = 64;
    std::vector<uint8_t> raw;
    if (!read_target(pid, address, static_cast<size_t>(length), raw) || raw.size() < 4)
        return false;
    const uint16_t family = static_cast<uint16_t>(raw[0] | (raw[1] << 8));
    out["sockaddr"] = hex_addr(address);
    out["family"] = family;
    if (family == 2 && raw.size() >= 8) {
        out["family_name"] = "AF_INET";
        out["port"] = read_be16(raw.data() + 2);
        out["address"] = format_ipv4(raw.data() + 4);
        return true;
    }
    if (family == 23 && raw.size() >= 24) {
        out["family_name"] = "AF_INET6";
        out["port"] = read_be16(raw.data() + 2);
        out["address"] = format_ipv6(raw.data() + 8);
        return true;
    }
    return true;
}

inline bool lookup_socket(uint32_t pid, uint64_t socket_handle, driver_bridge::socket_info_t& out) {
    if (socket_handle == 0)
        return false;
    const uint64_t now = GetTickCount64();
    std::vector<driver_bridge::socket_info_t> sockets;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        if (g_state.socket_cache.timestamp_ms != 0 &&
            now - g_state.socket_cache.timestamp_ms < 1000) {
            sockets = g_state.socket_cache.sockets;
        }
    }
    if (sockets.empty()) {
        sockets = driver_bridge::get_socket_handles(pid);
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.socket_cache.timestamp_ms = now;
        g_state.socket_cache.sockets = sockets;
    }
    for (const auto& s : sockets) {
        if (s.handle_value == socket_handle) {
            out = s;
            return true;
        }
    }
    return false;
}

inline nlohmann::json socket_to_json(const driver_bridge::socket_info_t& s) {
    nlohmann::json j;
    j["handle"] = hex_addr(s.handle_value);
    j["afd_endpoint"] = hex_addr(s.afd_endpoint_addr);
    j["pid"] = s.pid;
    j["protocol"] = s.protocol == 6 ? "TCP" : (s.protocol == 17 ? "UDP" : std::to_string(s.protocol));
    j["state"] = s.state;
    j["local_port"] = s.local_port;
    j["remote_port"] = s.remote_port;
    j["address_family"] = s.address_family;
    if (s.address_family == 23) {
        j["local_address"] = format_ipv6(s.local_addr);
        j["remote_address"] = format_ipv6(s.remote_addr);
    } else {
        j["local_address"] = format_ipv4(s.local_addr);
        j["remote_address"] = format_ipv4(s.remote_addr);
    }
    return j;
}

inline void add_socket_metadata(uint32_t pid, uint64_t socket_handle, nlohmann::json& metadata) {
    metadata["socket_handle"] = hex_addr(socket_handle);
    driver_bridge::socket_info_t sock{};
    if (lookup_socket(pid, socket_handle, sock))
        metadata["socket"] = socket_to_json(sock);
}

inline nlohmann::json ioctl_to_json(uint32_t code) {
    nlohmann::json j;
    j["code"] = hex_addr(code);
    j["device_type"] = static_cast<uint32_t>((code >> 16) & 0xFFFFu);
    j["access"] = static_cast<uint32_t>((code >> 14) & 0x3u);
    j["function"] = static_cast<uint32_t>((code >> 2) & 0xFFFu);
    j["method"] = static_cast<uint32_t>(code & 0x3u);
    return j;
}

inline bool address_in_modules(uint64_t address,
                               const std::vector<driver_bridge::module_info_t>& modules,
                               std::string& module_name,
                               uint64_t& module_offset) {
    for (const auto& m : modules) {
        if (address >= m.base && address < m.base + m.size) {
            module_name = !m.name.empty() ? m.name : basename_of(m.path);
            module_offset = address - m.base;
            return true;
        }
    }
    module_name.clear();
    module_offset = 0;
    return false;
}

inline bool is_code_address(uint64_t address, const std::vector<driver_bridge::module_info_t>& modules) {
    if (address < 0x10000)
        return false;
    std::string name;
    uint64_t offset = 0;
    return address_in_modules(address, modules, name, offset);
}

inline uint64_t read_return_address(uint32_t pid, uint64_t rsp) {
    uint64_t value = 0;
    read_target_value(pid, rsp, value);
    return value;
}

inline uint64_t find_callsite(uint32_t pid, uint64_t return_address) {
    if (return_address < 16)
        return 0;
    std::vector<uint8_t> raw;
    if (!read_target(pid, return_address - 8, 8, raw) || raw.size() < 8)
        return 0;
    if (raw[3] == 0xE8)
        return return_address - 5;
    if (raw[6] == 0xFF && ((raw[7] >> 3) & 7) == 2)
        return return_address - 2;
    if ((raw[5] & 0xF0) == 0x40 && raw[6] == 0xFF && ((raw[7] >> 3) & 7) == 2)
        return return_address - 3;
    if (raw[2] == 0xFF && ((raw[3] >> 3) & 7) == 2)
        return return_address - 6;
    if ((raw[1] & 0xF0) == 0x40 && raw[2] == 0xFF && ((raw[3] >> 3) & 7) == 2)
        return return_address - 7;
    return 0;
}

inline std::vector<frame_t> capture_callstack(uint32_t pid,
                                              const CONTEXT& ctx,
                                              uint64_t return_address,
                                              const std::vector<driver_bridge::module_info_t>& modules) {
    std::vector<frame_t> frames;
    auto add_frame = [&](uint64_t address) {
        if (!is_code_address(address, modules))
            return;
        for (const auto& existing : frames) {
            if (existing.address == address)
                return;
        }
        frame_t f;
        f.address = address;
        address_in_modules(address, modules, f.module_name, f.module_offset);
        frames.push_back(std::move(f));
    };

    add_frame(static_cast<uint64_t>(ctx.Rip));
    add_frame(return_address);

    uint64_t rbp = static_cast<uint64_t>(ctx.Rbp);
    for (int i = 0; i < 24 && rbp >= 0x10000; ++i) {
        uint64_t next_rbp = 0;
        uint64_t ret = 0;
        if (!read_target_value(pid, rbp, next_rbp) || !read_target_value(pid, rbp + 8, ret))
            break;
        add_frame(ret);
        if (next_rbp <= rbp)
            break;
        rbp = next_rbp;
    }

    if (frames.size() < 4) {
        std::vector<uint8_t> stack;
        if (read_target(pid, static_cast<uint64_t>(ctx.Rsp), 0x200, stack)) {
            const size_t aligned = stack.size() & ~static_cast<size_t>(7);
            for (size_t off = 0; off < aligned && frames.size() < 24; off += 8) {
                uint64_t candidate = 0;
                std::memcpy(&candidate, stack.data() + off, sizeof(candidate));
                add_frame(candidate);
            }
        }
    }
    return frames;
}

inline bool local_export_rva_fallback(const std::string& module_name,
                                      const std::string& function_name,
                                      const std::vector<driver_bridge::module_info_t>& target_modules,
                                      uint64_t& out_address,
                                      std::string& out_module) {
    if (module_name.empty())
        return false;
    HMODULE local_module = GetModuleHandleA(module_name.c_str());
    if (!local_module && module_name.find('.') == std::string::npos) {
        std::string with_ext = module_name + ".dll";
        local_module = GetModuleHandleA(with_ext.c_str());
    }
    if (!local_module)
        return false;
    FARPROC proc = GetProcAddress(local_module, function_name.c_str());
    if (!proc)
        return false;
    HMODULE owner = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(proc), &owner) || !owner)
        return false;
    char owner_path[MAX_PATH] = {};
    GetModuleFileNameA(owner, owner_path, MAX_PATH);
    const std::string owner_base = basename_of(owner_path);
    const uint64_t rva = reinterpret_cast<uint64_t>(proc) - reinterpret_cast<uint64_t>(owner);
    for (const auto& m : target_modules) {
        if (!module_name_matches(m, owner_base))
            continue;
        out_address = m.base + rva;
        out_module = !m.name.empty() ? m.name : owner_base;
        return true;
    }
    return false;
}

inline bool with_active_pid(uint32_t pid, const std::function<bool()>& fn) {
    const uint32_t previous = driver_bridge::attached_pid();
    bool changed = false;
    if (pid != 0 && previous != pid) {
        if (!driver_bridge::set_active_pid(pid))
            return false;
        changed = true;
    }
    const bool ok = fn();
    if (changed) {
        if (previous != 0)
            driver_bridge::set_active_pid(previous);
        else
            driver_bridge::clear_active_pid();
    }
    return ok;
}

inline bool resolve_request(uint32_t pid,
                            const api_request_t& request,
                            const std::vector<driver_bridge::module_info_t>& modules,
                            api_target_t& out) {
    uint64_t manual_address = 0;
    if (parse_u64(request.original, manual_address) && manual_address != 0) {
        out.request = request;
        out.address = manual_address;
        out.resolved_module.clear();
        out.module_base = 0;
        out.module_offset = 0;
        out.active = true;
        return true;
    }

    bool resolved = false;
    uint64_t address = 0;
    std::string module_name;
    with_active_pid(pid, [&]() -> bool {
        for (const auto& m : modules) {
            if (!module_name_matches(m, request.module_name))
                continue;
            const uint64_t candidate = driver_bridge::resolve_export(m.base, request.function_name.c_str());
            if (candidate == 0)
                continue;
            address = candidate;
            module_name = !m.name.empty() ? m.name : basename_of(m.path);
            resolved = true;
            return true;
        }
        return true;
    });

    if (!resolved && !request.module_name.empty())
        resolved = local_export_rva_fallback(request.module_name, request.function_name, modules, address, module_name);

    if (!resolved)
        return false;

    out.request = request;
    out.address = address;
    out.resolved_module = module_name;
    out.active = true;
    for (const auto& m : modules) {
        if (address >= m.base && address < m.base + m.size) {
            out.module_base = m.base;
            out.module_offset = address - m.base;
            if (out.resolved_module.empty())
                out.resolved_module = !m.name.empty() ? m.name : basename_of(m.path);
            break;
        }
    }
    return true;
}

inline api_request_t parse_api_string(const std::string& text) {
    api_request_t request;
    request.original = trim(text);
    std::string spec = request.original;
    const size_t bang = spec.find('!');
    if (bang != std::string::npos) {
        request.module_name = trim(spec.substr(0, bang));
        request.function_name = trim(spec.substr(bang + 1));
    } else {
        uint64_t addr = 0;
        if (parse_u64(spec, addr)) {
            request.function_name = spec;
        } else {
            request.function_name = trim(spec);
        }
    }
    request.kind = infer_kind(request.function_name);
    if (request.kind == api_kind_t::custom_linear) {
        request.buffer_reg = 1;
        request.size_reg = 2;
    }
    return request;
}

inline api_kind_t parse_kind_override(const std::string& text, api_kind_t fallback) {
    const std::string v = to_lower(text);
    if (v == "linear")
        return api_kind_t::custom_linear;
    if (v == "wsabuf" || v == "wsabuf_array")
        return api_kind_t::wsa_send;
    if (v == "sec_buffer" || v == "secbuffer" || v == "sec_buffer_desc")
        return api_kind_t::encrypt_message;
    return fallback;
}

inline bool parse_request_json(const nlohmann::json& value, api_request_t& out, std::string& error) {
    if (value.is_string()) {
        out = parse_api_string(value.get<std::string>());
        if (out.original.empty()) {
            error = "empty api entry";
            return false;
        }
        return true;
    }
    if (!value.is_object()) {
        error = "api entries must be strings or objects";
        return false;
    }
    const std::string api = value.value("api", value.value("name", std::string{}));
    if (api.empty()) {
        error = "api object requires api";
        return false;
    }
    out = parse_api_string(api);
    if (value.contains("buffer_reg") && value["buffer_reg"].is_number_integer())
        out.buffer_reg = value["buffer_reg"].get<int>();
    if (value.contains("size_reg") && value["size_reg"].is_number_integer())
        out.size_reg = value["size_reg"].get<int>();
    if (value.contains("buffer_kind") && value["buffer_kind"].is_string())
        out.kind = parse_kind_override(value["buffer_kind"].get<std::string>(), out.kind);
    return true;
}

inline bool process_exists(uint32_t pid) {
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

inline bool target_is_x64(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return false;

    using is_wow64_process2_t = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    auto fn = kernel32 ? reinterpret_cast<is_wow64_process2_t>(GetProcAddress(kernel32, "IsWow64Process2")) : nullptr;
    if (fn) {
        USHORT process_machine = 0;
        USHORT native_machine = 0;
        const BOOL ok = fn(h, &process_machine, &native_machine);
        CloseHandle(h);
        if (!ok)
            return false;
        return process_machine == IMAGE_FILE_MACHINE_UNKNOWN && native_machine == IMAGE_FILE_MACHINE_AMD64;
    }

    BOOL wow64 = FALSE;
    const BOOL ok = IsWow64Process(h, &wow64);
    CloseHandle(h);
    return ok && !wow64;
}

inline bool ensure_driver_attached(uint32_t pid, std::string& error) {
    if (!driver_bridge::using_kernel_driver()) {
        error = "Driver bridge is not connected. Attach with sessions_manage action=attach_pid first.";
        return false;
    }
    if (driver_bridge::attached_pid() == pid)
        return true;
    const auto attached = driver_bridge::attached_pids();
    for (uint32_t attached_pid : attached) {
        if (attached_pid == pid) {
            if (!driver_bridge::set_active_pid(pid)) {
                error = "Failed to select attached PID " + std::to_string(pid);
                return false;
            }
            return true;
        }
    }
    if (!driver_bridge::attach(pid)) {
        error = "Failed to attach PID " + std::to_string(pid) + " through driver bridge.";
        return false;
    }
    return true;
}

inline bool enable_debug_privilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const bool ok = GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

inline std::vector<api_target_t> targets_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    std::vector<api_target_t> result;
    for (const auto& target : g_state.targets) {
        if (target.active)
            result.push_back(target);
    }
    return result;
}

inline bool find_target_for_hit(uint64_t rip, uint64_t exception_address, api_target_t& out) {
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        if (target.address == rip || target.address == exception_address) {
            out = target;
            return true;
        }
    }
    return false;
}

inline uint32_t pid_snapshot() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.pid;
}

inline void mark_thread_armed(uint64_t address, uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        if (target.address != address)
            continue;
        if (std::find(target.armed_tids.begin(), target.armed_tids.end(), tid) == target.armed_tids.end())
            target.armed_tids.push_back(tid);
        return;
    }
}

inline void remove_thread_armed(uint32_t tid) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    for (auto& target : g_state.targets) {
        auto& tids = target.armed_tids;
        tids.erase(std::remove(tids.begin(), tids.end(), tid), tids.end());
    }
}

inline bool arm_breakpoints_for_thread(uint32_t tid) {
    if (tid == 0 || !driver_bridge::using_kernel_driver())
        return false;
    bool armed = false;
    auto targets = targets_snapshot();
    for (const auto& target : targets) {
        if (driver_bridge::set_hardware_breakpoint(tid, static_cast<int>(target.bp_index), target.address, 0, 0)) {
            mark_thread_armed(target.address, tid);
            armed = true;
            diag::log_tagged_fmt("api_monitor",
                "arm_thread tid=%u slot=%u api=%s addr=%s ok=1",
                tid,
                target.bp_index,
                target.request.original.c_str(),
                hex_addr(target.address).c_str());
        } else {
            diag::log_tagged_fmt("api_monitor",
                "arm_thread tid=%u slot=%u api=%s addr=%s ok=0 gle=%lu",
                tid,
                target.bp_index,
                target.request.original.c_str(),
                hex_addr(target.address).c_str(),
                GetLastError());
        }
    }
    return armed;
}

inline uint32_t arm_existing_threads() {
    const uint32_t pid = pid_snapshot();
    if (pid == 0)
        return 0;
    const auto threads = driver_bridge::enumerate_threads_for(pid);
    diag::log_tagged_fmt("api_monitor",
        "arm_existing_threads pid=%u thread_count=%llu",
        pid,
        static_cast<unsigned long long>(threads.size()));
    uint32_t armed = 0;
    for (const auto& thread : threads) {
        if (thread.owner_pid == pid && arm_breakpoints_for_thread(thread.tid))
            ++armed;
    }
    diag::log_tagged_fmt("api_monitor",
        "arm_existing_threads_done pid=%u armed_threads=%u",
        pid,
        armed);
    return armed;
}

struct clear_result_t {
    DWORD gle = ERROR_SUCCESS;
    DWORD suspend_prev = static_cast<DWORD>(-1);
    DWORD resume_prev = static_cast<DWORD>(-1);
    uint64_t before_dr7 = 0;
    uint64_t after_dr7 = 0;
    uint64_t elapsed_ms = 0;
};

inline bool clear_hardware_breakpoint_usermode(uint32_t tid, uint32_t slot, clear_result_t& result) {
    const uint64_t start = GetTickCount64();
    auto finish = [&result, start](DWORD gle, bool ok) {
        result.gle = gle;
        result.elapsed_ms = GetTickCount64() - start;
        SetLastError(gle);
        return ok;
    };

    if (tid == 0 || slot > 3)
        return finish(ERROR_INVALID_PARAMETER, false);
    if (tid == GetCurrentThreadId())
        return finish(ERROR_INVALID_PARAMETER, false);

    HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                                      FALSE,
                                      static_cast<DWORD>(tid));
    if (!thread_handle)
        return finish(GetLastError(), false);

    result.suspend_prev = SuspendThread(thread_handle);
    if (result.suspend_prev == static_cast<DWORD>(-1)) {
        const DWORD gle = GetLastError();
        CloseHandle(thread_handle);
        return finish(gle, false);
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
    const BOOL got_context = GetThreadContext(thread_handle, &ctx);
    DWORD gle = got_context ? ERROR_SUCCESS : GetLastError();
    BOOL set_context = FALSE;
    if (got_context) {
        result.before_dr7 = static_cast<uint64_t>(ctx.Dr7);
        switch (slot) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
        default: break;
        }
        uint64_t dr7 = static_cast<uint64_t>(ctx.Dr7);
        constexpr uint64_t kDr7UserMask = 0xFFFF0355ULL;
        constexpr uint64_t kDr7GlobalEnableMask = 0xAAULL;
        dr7 &= kDr7UserMask;
        dr7 &= ~kDr7GlobalEnableMask;
        dr7 &= ~(3ULL << (slot * 2));
        dr7 &= ~(3ULL << (16 + slot * 4));
        dr7 &= ~(3ULL << (18 + slot * 4));
        ctx.Dr6 = 0;
        ctx.Dr7 = static_cast<DWORD64>(dr7);
        result.after_dr7 = dr7;
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;
        set_context = SetThreadContext(thread_handle, &ctx);
        gle = set_context ? ERROR_SUCCESS : GetLastError();
    }

    result.resume_prev = ResumeThread(thread_handle);
    const DWORD resume_gle = result.resume_prev == static_cast<DWORD>(-1) ? GetLastError() : ERROR_SUCCESS;
    CloseHandle(thread_handle);
    if (!got_context || !set_context)
        return finish(gle, false);
    if (resume_gle != ERROR_SUCCESS)
        return finish(resume_gle, false);
    return finish(ERROR_SUCCESS, true);
}

inline void clear_armed_breakpoints(const char* source) {
    struct clear_request_t {
        uint32_t tid;
        uint32_t slot;
    };
    const char* origin = source && *source ? source : "unknown";
    if (g_state.cleanup_running.exchange(true)) {
        diag::log_tagged_fmt("api_monitor",
            "clear_armed_breakpoints_busy source=%s",
            origin);
        return;
    }

    const uint64_t cleanup_start = GetTickCount64();
    g_state.cleanup_attempts.fetch_add(1, std::memory_order_relaxed);
    std::vector<clear_request_t> requests;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& target : g_state.targets) {
            for (uint32_t tid : target.armed_tids)
                requests.push_back({tid, target.bp_index});
            target.armed_tids.clear();
        }
    }
    g_state.cleanup_last_requests.store(static_cast<uint32_t>(requests.size()), std::memory_order_relaxed);
    diag::log_tagged_fmt("api_monitor",
        "clear_armed_breakpoints source=%s requests=%llu kernel=%d attached=%d",
        origin,
        static_cast<unsigned long long>(requests.size()),
        driver_bridge::using_kernel_driver() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);
    uint32_t succeeded = 0;
    uint32_t failed = 0;
    uint32_t index = 0;
    for (const auto& req : requests) {
        ++index;
        diag::log_tagged_fmt("api_monitor",
            "clear_breakpoint_begin source=%s index=%u total=%llu tid=%u slot=%u",
            origin,
            index,
            static_cast<unsigned long long>(requests.size()),
            req.tid,
            req.slot);
        clear_result_t clear_result;
        const bool ok = clear_hardware_breakpoint_usermode(req.tid, req.slot, clear_result);
        if (ok)
            ++succeeded;
        else
            ++failed;
        diag::log_tagged_fmt("api_monitor",
            "clear_breakpoint_end source=%s index=%u total=%llu tid=%u slot=%u ok=%d gle=%lu before_dr7=0x%llX after_dr7=0x%llX suspend_prev=%lu resume_prev=%lu elapsed_ms=%llu",
            origin,
            index,
            static_cast<unsigned long long>(requests.size()),
            req.tid,
            req.slot,
            ok ? 1 : 0,
            clear_result.gle,
            static_cast<unsigned long long>(clear_result.before_dr7),
            static_cast<unsigned long long>(clear_result.after_dr7),
            clear_result.suspend_prev,
            clear_result.resume_prev,
            static_cast<unsigned long long>(clear_result.elapsed_ms));
    }
    const uint64_t elapsed = GetTickCount64() - cleanup_start;
    g_state.cleanup_last_succeeded.store(succeeded, std::memory_order_relaxed);
    g_state.cleanup_last_failed.store(failed, std::memory_order_relaxed);
    g_state.cleanup_last_elapsed_ms.store(elapsed, std::memory_order_relaxed);
    g_state.cleanup_running.store(false);
    diag::log_tagged_fmt("api_monitor",
        "clear_armed_breakpoints_done source=%s requests=%llu succeeded=%u failed=%u elapsed_ms=%llu",
        origin,
        static_cast<unsigned long long>(requests.size()),
        succeeded,
        failed,
        static_cast<unsigned long long>(elapsed));
}

inline void update_module_cache(uint32_t pid) {
    auto modules = driver_bridge::enumerate_modules_for(pid);
    if (modules.empty())
        return;
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.modules = std::move(modules);
}

inline void capture_known_arguments(uint32_t pid,
                                    const CONTEXT& ctx,
                                    const api_target_t& target,
                                    api_event_t& event,
                                    bool capture_bytes,
                                    uint32_t max_capture_bytes) {
    const api_kind_t kind = target.request.kind;
    event.metadata["kind"] = kind_name(kind);

    if (kind == api_kind_t::send_linear || kind == api_kind_t::custom_linear) {
        const uint64_t socket_handle = register_value(ctx, 0);
        if (kind == api_kind_t::send_linear)
            add_socket_metadata(pid, socket_handle, event.metadata);
        capture_linear_buffer(event.buffers, pid, "outbound", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, capture_bytes);
        event.metadata["flags"] = hex_addr(register_value(ctx, 3));
        return;
    }

    if (kind == api_kind_t::wsa_send) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_wsabufs(event.buffers, pid, register_value(ctx, 1), register_value(ctx, 2), "outbound",
                        max_capture_bytes, capture_bytes, event.metadata);
        event.metadata["bytes_sent_ptr"] = hex_addr(register_value(ctx, 3));
        return;
    }

    if (kind == api_kind_t::send_to) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_linear_buffer(event.buffers, pid, "outbound", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, capture_bytes);
        event.metadata["flags"] = hex_addr(register_value(ctx, 3));
        nlohmann::json endpoint;
        if (parse_sockaddr(pid, stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 0),
                           stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 1), endpoint))
            event.metadata["target_endpoint"] = endpoint;
        return;
    }

    if (kind == api_kind_t::wsa_send_to) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_wsabufs(event.buffers, pid, register_value(ctx, 1), register_value(ctx, 2), "outbound",
                        max_capture_bytes, capture_bytes, event.metadata);
        event.metadata["bytes_sent_ptr"] = hex_addr(register_value(ctx, 3));
        event.metadata["flags"] = hex_addr(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 0));
        nlohmann::json endpoint;
        if (parse_sockaddr(pid, stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 1),
                           stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 2), endpoint))
            event.metadata["target_endpoint"] = endpoint;
        return;
    }

    if (kind == api_kind_t::recv_linear || kind == api_kind_t::recv_from) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_linear_buffer(event.buffers, pid, "inbound_destination", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, false);
        event.metadata["capture_phase"] = "entry";
        event.metadata["buffer_contents"] = "not_captured_before_api_return";
        return;
    }

    if (kind == api_kind_t::wsa_recv || kind == api_kind_t::wsa_recv_from) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        capture_wsabufs(event.buffers, pid, register_value(ctx, 1), register_value(ctx, 2), "inbound_destination",
                        max_capture_bytes, false, event.metadata);
        event.metadata["capture_phase"] = "entry";
        event.metadata["buffer_contents"] = "not_captured_before_api_return";
        return;
    }

    if (kind == api_kind_t::connect_call) {
        add_socket_metadata(pid, register_value(ctx, 0), event.metadata);
        nlohmann::json endpoint;
        if (parse_sockaddr(pid, register_value(ctx, 1), register_value(ctx, 2), endpoint))
            event.metadata["target_endpoint"] = endpoint;
        return;
    }

    if (kind == api_kind_t::device_io_control) {
        const uint32_t ioctl = static_cast<uint32_t>(register_value(ctx, 1));
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["ioctl"] = ioctl_to_json(ioctl);
        capture_linear_buffer(event.buffers, pid, "ioctl_input", register_value(ctx, 2), register_value(ctx, 3),
                              max_capture_bytes, capture_bytes);
        event.metadata["out_buffer"] = hex_addr(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 0));
        event.metadata["out_buffer_size"] = stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 1);
        event.metadata["bytes_returned_ptr"] = hex_addr(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 2));
        event.metadata["overlapped_ptr"] = hex_addr(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 3));
        return;
    }

    if (kind == api_kind_t::nt_device_io_control) {
        const uint32_t ioctl = static_cast<uint32_t>(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 1));
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["event_handle"] = hex_addr(register_value(ctx, 1));
        event.metadata["apc_routine"] = hex_addr(register_value(ctx, 2));
        event.metadata["apc_context"] = hex_addr(register_value(ctx, 3));
        event.metadata["io_status_block"] = hex_addr(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 0));
        event.metadata["ioctl"] = ioctl_to_json(ioctl);
        capture_linear_buffer(event.buffers, pid, "ioctl_input", stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 2),
                              stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 3), max_capture_bytes, capture_bytes);
        event.metadata["out_buffer"] = hex_addr(stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 4));
        event.metadata["out_buffer_size"] = stack_arg64(pid, static_cast<uint64_t>(ctx.Rsp), 5);
        return;
    }

    if (kind == api_kind_t::write_file) {
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["bytes_transferred_ptr"] = hex_addr(register_value(ctx, 3));
        capture_linear_buffer(event.buffers, pid, "write", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, capture_bytes);
        return;
    }

    if (kind == api_kind_t::read_file) {
        event.metadata["handle"] = hex_addr(register_value(ctx, 0));
        event.metadata["bytes_transferred_ptr"] = hex_addr(register_value(ctx, 3));
        capture_linear_buffer(event.buffers, pid, "read_destination", register_value(ctx, 1), register_value(ctx, 2),
                              max_capture_bytes, false);
        event.metadata["capture_phase"] = "entry";
        event.metadata["buffer_contents"] = "not_captured_before_api_return";
        return;
    }

    if (kind == api_kind_t::encrypt_message) {
        event.metadata["credential_or_context"] = hex_addr(register_value(ctx, 0));
        event.metadata["quality_of_protection"] = hex_addr(register_value(ctx, 1));
        event.metadata["message_seq_no"] = hex_addr(register_value(ctx, 3));
        capture_sec_buffers(event.buffers, pid, register_value(ctx, 2), max_capture_bytes, capture_bytes, event.metadata);
        return;
    }

    if (target.request.buffer_reg >= 0 && target.request.size_reg >= 0) {
        capture_linear_buffer(event.buffers, pid, "custom", register_value(ctx, target.request.buffer_reg),
                              register_value(ctx, target.request.size_reg), max_capture_bytes, capture_bytes);
    }
}

inline void record_event(uint32_t pid, uint32_t tid, const CONTEXT& ctx, const api_target_t& target) {
    bool capture_bytes = true;
    bool log_callstack = false;
    uint32_t max_capture_bytes = 256;
    std::vector<driver_bridge::module_info_t> modules;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        capture_bytes = g_state.capture_buffer;
        log_callstack = g_state.log_callstack;
        max_capture_bytes = g_state.max_capture_bytes;
        modules = g_state.modules;
    }

    api_event_t event;
    event.pid = pid;
    event.tid = tid;
    event.timestamp_ms = GetTickCount64();
    event.api = target.request.original.empty() ? target.request.function_name : target.request.original;
    event.api_address = target.address;
    event.api_module = target.resolved_module;
    event.api_module_offset = target.module_offset;
    event.regs = snapshot_registers(ctx);
    event.return_address = read_return_address(pid, static_cast<uint64_t>(ctx.Rsp));
    event.callsite_address = find_callsite(pid, event.return_address);
    address_in_modules(event.return_address, modules, event.caller_module, event.caller_module_offset);
    event.metadata["api_function"] = target.request.function_name;
    event.metadata["api_module"] = target.resolved_module;

    capture_known_arguments(pid, ctx, target, event, capture_bytes, max_capture_bytes);
    if (log_callstack)
        event.callstack = capture_callstack(pid, ctx, event.return_address, modules);

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        event.sequence = g_state.next_sequence++;
        g_state.events.push_back(std::move(event));
        while (g_state.events.size() > g_state.max_events)
            g_state.events.pop_front();
        g_state.total_hits.fetch_add(1, std::memory_order_relaxed);
    }
}

inline bool capture_breakpoint_hit(const DEBUG_EVENT& evt) {
    HANDLE thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, evt.dwThreadId);
    if (!thread_handle)
        return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    const BOOL got_context = GetThreadContext(thread_handle, &ctx);
    if (!got_context) {
        CloseHandle(thread_handle);
        return false;
    }

    const uint64_t exception_address = reinterpret_cast<uint64_t>(evt.u.Exception.ExceptionRecord.ExceptionAddress);
    api_target_t target;
    if (!find_target_for_hit(static_cast<uint64_t>(ctx.Rip), exception_address, target)) {
        CloseHandle(thread_handle);
        return false;
    }

    record_event(evt.dwProcessId, evt.dwThreadId, ctx, target);
    ctx.EFlags |= 0x10000;
    SetThreadContext(thread_handle, &ctx);
    CloseHandle(thread_handle);
    return true;
}

inline void close_debug_event_handles(const DEBUG_EVENT& evt) {
    switch (evt.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:
        if (evt.u.CreateProcessInfo.hFile)
            CloseHandle(evt.u.CreateProcessInfo.hFile);
        if (evt.u.CreateProcessInfo.hThread)
            CloseHandle(evt.u.CreateProcessInfo.hThread);
        if (evt.u.CreateProcessInfo.hProcess)
            CloseHandle(evt.u.CreateProcessInfo.hProcess);
        break;
    case CREATE_THREAD_DEBUG_EVENT:
        if (evt.u.CreateThread.hThread)
            CloseHandle(evt.u.CreateThread.hThread);
        break;
    case LOAD_DLL_DEBUG_EVENT:
        if (evt.u.LoadDll.hFile)
            CloseHandle(evt.u.LoadDll.hFile);
        break;
    default:
        break;
    }
}

inline void debug_event_loop() {
    const uint32_t pid = pid_snapshot();
    diag::log_tagged_fmt("api_monitor",
        "debug_loop_enter pid=%u host_tid=%lu kernel=%d",
        pid,
        GetCurrentThreadId(),
        driver_bridge::using_kernel_driver() ? 1 : 0);
    if (pid == 0 || !driver_bridge::using_kernel_driver()) {
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.active.store(false);
        g_state.debugger_error.store(ERROR_INVALID_PARAMETER);
        diag::log_tagged_fmt("api_monitor",
            "debug_loop_invalid pid=%u kernel=%d",
            pid,
            driver_bridge::using_kernel_driver() ? 1 : 0);
        return;
    }

    enable_debug_privilege();
    diag::log_tagged_fmt("api_monitor", "debug_attach_begin pid=%u", pid);
    if (!DebugActiveProcess(pid)) {
        const DWORD gle = GetLastError();
        g_state.debugger_error.store(gle);
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        g_state.active.store(false);
        diag::log_tagged_fmt("api_monitor",
            "debug_attach_failed pid=%u gle=%lu",
            pid,
            gle);
        return;
    }

    DebugSetProcessKillOnExit(FALSE);
    g_state.debug_attached.store(true);
    g_state.debugger_error.store(0);
    update_module_cache(pid);
    const uint32_t initial_armed = arm_existing_threads();
    diag::log_tagged_fmt("api_monitor",
        "debug_attach_ok pid=%u initial_armed=%u",
        pid,
        initial_armed);

    bool initial_break_pending = true;
    uint64_t event_count = 0;
    while (g_state.polling.load()) {
        DEBUG_EVENT evt{};
        if (!WaitForDebugEvent(&evt, 100))
            continue;

        ++event_count;
        DWORD continue_status = DBG_CONTINUE;
        if (evt.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const DWORD code = evt.u.Exception.ExceptionRecord.ExceptionCode;
            if (event_count <= 32 || code == EXCEPTION_SINGLE_STEP) {
                diag::log_tagged_fmt("api_monitor",
                    "debug_event_exception pid=%lu tid=%lu code=0x%08lX first=%lu addr=%p count=%llu",
                    evt.dwProcessId,
                    evt.dwThreadId,
                    code,
                    evt.u.Exception.dwFirstChance,
                    evt.u.Exception.ExceptionRecord.ExceptionAddress,
                    static_cast<unsigned long long>(event_count));
            }
            if (code == EXCEPTION_SINGLE_STEP) {
                if (!capture_breakpoint_hit(evt))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
            } else if (code == EXCEPTION_BREAKPOINT && evt.u.Exception.dwFirstChance != 0 && initial_break_pending) {
                initial_break_pending = false;
                continue_status = DBG_CONTINUE;
            } else {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
        } else if (evt.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            diag::log_tagged_fmt("api_monitor",
                "debug_event_create_thread pid=%lu tid=%lu",
                evt.dwProcessId,
                evt.dwThreadId);
            arm_breakpoints_for_thread(evt.dwThreadId);
        } else if (evt.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
            diag::log_tagged_fmt("api_monitor",
                "debug_event_exit_thread pid=%lu tid=%lu",
                evt.dwProcessId,
                evt.dwThreadId);
            remove_thread_armed(evt.dwThreadId);
        } else if (evt.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT || evt.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
            diag::log_tagged_fmt("api_monitor",
                "debug_event_module pid=%lu tid=%lu code=%lu",
                evt.dwProcessId,
                evt.dwThreadId,
                evt.dwDebugEventCode);
            update_module_cache(pid);
        } else if (evt.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            diag::log_tagged_fmt("api_monitor",
                "debug_event_exit_process pid=%lu tid=%lu",
                evt.dwProcessId,
                evt.dwThreadId);
            g_state.active.store(false);
            g_state.polling.store(false);
        }

        close_debug_event_handles(evt);
        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status);
    }

    clear_armed_breakpoints("debug_loop");
    if (g_state.debug_attached.exchange(false)) {
        const BOOL stopped = DebugActiveProcessStop(pid);
        diag::log_tagged_fmt("api_monitor",
            "debug_detach pid=%u ok=%d gle=%lu events=%llu",
            pid,
            stopped ? 1 : 0,
            GetLastError(),
            static_cast<unsigned long long>(event_count));
    }
    g_state.debug_loop_running.store(false);
    diag::log_tagged_fmt("api_monitor",
        "debug_loop_exit pid=%u events=%llu",
        pid,
        static_cast<unsigned long long>(event_count));
}

inline void stop() {
    diag::log_tagged_fmt("api_monitor",
        "stop_enter active=%d polling=%d debug_loop=%d attached=%d pid=%u",
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        pid_snapshot());
    const uint64_t stop_start = GetTickCount64();
    const uint32_t pid = pid_snapshot();
    g_state.polling.store(false);
    int waited = 0;
    for (; waited < 60 && g_state.debug_loop_running.load(); ++waited)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    diag::log_tagged_fmt("api_monitor",
        "stop_wait_done pid=%u waited_ms=%llu iterations=%d debug_loop=%d attached=%d",
        pid,
        static_cast<unsigned long long>(GetTickCount64() - stop_start),
        waited,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0);
    if (pid != 0 && g_state.debug_loop_running.load() && g_state.debug_attached.exchange(false)) {
        const BOOL stopped = DebugActiveProcessStop(pid);
        diag::log_tagged_fmt("api_monitor",
            "stop_detach_slow_debug_loop pid=%u ok=%d gle=%lu waited_ms=%llu",
            pid,
            stopped ? 1 : 0,
            GetLastError(),
            static_cast<unsigned long long>(GetTickCount64() - stop_start));
    } else if (pid == 0 && g_state.debug_loop_running.load() && g_state.debug_attached.load()) {
        diag::log_tagged_fmt("api_monitor",
            "stop_detach_slow_debug_loop_skipped pid=0 waited_ms=%llu",
            static_cast<unsigned long long>(GetTickCount64() - stop_start));
    }
    clear_armed_breakpoints("stop");
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto& target : g_state.targets)
            target.active = false;
        g_state.targets.clear();
        g_state.requested.clear();
        g_state.modules.clear();
        g_state.socket_cache = {};
        g_state.pid = 0;
    }
    g_state.active.store(false);
    diag::log_tagged_fmt("api_monitor",
        "stop_exit active=%d polling=%d debug_loop=%d attached=%d elapsed_ms=%llu cleanup_requests=%u cleanup_ok=%u cleanup_failed=%u",
        g_state.active.load() ? 1 : 0,
        g_state.polling.load() ? 1 : 0,
        g_state.debug_loop_running.load() ? 1 : 0,
        g_state.debug_attached.load() ? 1 : 0,
        static_cast<unsigned long long>(GetTickCount64() - stop_start),
        g_state.cleanup_last_requests.load(std::memory_order_relaxed),
        g_state.cleanup_last_succeeded.load(std::memory_order_relaxed),
        g_state.cleanup_last_failed.load(std::memory_order_relaxed));
}

inline bool start_polling(std::string& error) {
    if (!g_state.active.load()) {
        error = "No active API monitor targets.";
        return false;
    }
    if (g_state.debug_loop_running.exchange(true)) {
        if (g_state.debug_attached.load()) {
            arm_existing_threads();
            return true;
        }
        error = "API monitor debug loop is already starting.";
        return false;
    }

    g_state.polling.store(true);
    bool posted = false;
    try {
        posted = work_queue::post([]() { debug_event_loop(); });
    } catch (...) {
        posted = false;
    }
    if (!posted) {
        g_state.polling.store(false);
        g_state.debug_loop_running.store(false);
        error = "Failed to schedule API monitor worker on work queue.";
        diag::log_tagged_fmt("api_monitor",
            "start_polling_post_failed");
        return false;
    }
    diag::log_tagged_fmt("api_monitor", "start_polling_worker_posted");

    for (int i = 0; i < 60; ++i) {
        if (g_state.debug_attached.load())
            return true;
        if (!g_state.debug_loop_running.load()) {
            error = "DebugActiveProcess failed, error=" + std::to_string(static_cast<unsigned long>(g_state.debugger_error.load()));
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    if (g_state.debug_attached.load())
        return true;
    error = "Timed out waiting for API monitor debug attach.";
    return false;
}

inline bool start(uint32_t requested_pid,
                  const std::vector<api_request_t>& apis,
                  bool log_callstack,
                  bool capture_buffer,
                  uint32_t max_capture_bytes,
                  size_t max_events,
                  nlohmann::json& summary,
                  std::string& error) {
    if (apis.empty()) {
        error = "apis must contain at least one API name.";
        return false;
    }
    if (apis.size() > 4) {
        error = "api_monitor_start supports up to 4 APIs per session because it uses DR0-DR3 hardware execute breakpoints.";
        return false;
    }

    stop();

    uint32_t pid = requested_pid;
    if (pid == 0)
        pid = driver_bridge::attached_pid();
    if (pid == 0) {
        error = "Missing pid and no driver target is attached.";
        return false;
    }
    if (pid == GetCurrentProcessId()) {
        error = "Refusing to debug the AiDA process itself.";
        return false;
    }
    if (!process_exists(pid)) {
        error = "Target PID " + std::to_string(pid) + " is not running.";
        return false;
    }
    if (!target_is_x64(pid)) {
        error = "API monitor requires a native x64 target process.";
        return false;
    }
    if (!ensure_driver_attached(pid, error))
        return false;

    auto modules = driver_bridge::enumerate_modules_for(pid);
    if (modules.empty()) {
        error = "Failed to enumerate modules for PID " + std::to_string(pid) + ".";
        return false;
    }

    std::vector<api_target_t> targets;
    nlohmann::json resolved = nlohmann::json::array();
    nlohmann::json unresolved = nlohmann::json::array();
    uint32_t slot = 0;
    for (const auto& request : apis) {
        api_target_t target;
        if (resolve_request(pid, request, modules, target)) {
            target.bp_index = slot++;
            targets.push_back(target);
            nlohmann::json item;
            item["api"] = request.original;
            item["address"] = hex_addr(target.address);
            item["module"] = target.resolved_module;
            item["module_offset"] = hex_addr(target.module_offset);
            item["bp_slot"] = target.bp_index;
            item["kind"] = kind_name(target.request.kind);
            resolved.push_back(item);
        } else {
            unresolved.push_back(request.original);
        }
    }

    if (targets.empty()) {
        error = "No requested APIs resolved in the target process.";
        summary["unresolved"] = unresolved;
        return false;
    }

    if (max_capture_bytes == 0)
        max_capture_bytes = 256;
    if (max_capture_bytes > 2048)
        max_capture_bytes = 2048;
    if (max_events < 64)
        max_events = 64;
    if (max_events > 16384)
        max_events = 16384;

    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.pid = pid;
        g_state.requested = apis;
        g_state.targets = std::move(targets);
        g_state.modules = std::move(modules);
        g_state.events.clear();
        g_state.socket_cache = {};
        g_state.capture_buffer = capture_buffer;
        g_state.log_callstack = log_callstack;
        g_state.max_capture_bytes = max_capture_bytes;
        g_state.max_events = max_events;
        g_state.next_sequence = 1;
    }
    g_state.total_hits.store(0, std::memory_order_relaxed);
    g_state.debugger_error.store(0);
    g_state.active.store(true);

    if (!start_polling(error)) {
        stop();
        return false;
    }

    uint32_t armed_thread_breakpoints = 0;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (const auto& target : g_state.targets)
            armed_thread_breakpoints += static_cast<uint32_t>(target.armed_tids.size());
    }

    summary["pid"] = pid;
    summary["backend"] = "hardware_breakpoint_debug_events";
    summary["capture_buffer"] = capture_buffer;
    summary["log_callstack"] = log_callstack;
    summary["max_capture_bytes"] = max_capture_bytes;
    summary["max_events"] = max_events;
    summary["resolved"] = resolved;
    summary["unresolved"] = unresolved;
    summary["armed_thread_breakpoints"] = armed_thread_breakpoints;
    summary["active"] = true;
    return true;
}

inline nlohmann::json registers_to_json(const register_snapshot_t& r) {
    nlohmann::json j;
    j["rax"] = hex_addr(r.rax);
    j["rbx"] = hex_addr(r.rbx);
    j["rcx"] = hex_addr(r.rcx);
    j["rdx"] = hex_addr(r.rdx);
    j["rsi"] = hex_addr(r.rsi);
    j["rdi"] = hex_addr(r.rdi);
    j["rbp"] = hex_addr(r.rbp);
    j["rsp"] = hex_addr(r.rsp);
    j["r8"] = hex_addr(r.r8);
    j["r9"] = hex_addr(r.r9);
    j["r10"] = hex_addr(r.r10);
    j["r11"] = hex_addr(r.r11);
    j["r12"] = hex_addr(r.r12);
    j["r13"] = hex_addr(r.r13);
    j["r14"] = hex_addr(r.r14);
    j["r15"] = hex_addr(r.r15);
    j["rip"] = hex_addr(r.rip);
    j["rflags"] = hex_addr(r.rflags);
    return j;
}

inline nlohmann::json buffer_to_json(const buffer_capture_t& b) {
    nlohmann::json j;
    j["kind"] = b.kind;
    j["direction"] = b.direction;
    j["address"] = hex_addr(b.address);
    j["requested_size"] = b.requested_size;
    j["captured_size"] = b.captured_size;
    j["truncated"] = b.truncated;
    j["readable"] = b.readable;
    if (!b.bytes.empty())
        j["hex"] = bytes_to_hex(b.bytes);
    return j;
}

inline nlohmann::json frame_to_json(const frame_t& f) {
    nlohmann::json j;
    j["address"] = hex_addr(f.address);
    j["module"] = f.module_name;
    j["module_offset"] = hex_addr(f.module_offset);
    return j;
}

inline nlohmann::json event_to_json(const api_event_t& event) {
    nlohmann::json j;
    j["sequence"] = event.sequence;
    j["timestamp_ms"] = event.timestamp_ms;
    j["pid"] = event.pid;
    j["tid"] = event.tid;
    j["api"] = event.api;
    j["api_address"] = hex_addr(event.api_address);
    j["api_module"] = event.api_module;
    j["api_module_offset"] = hex_addr(event.api_module_offset);
    if (event.return_address != 0)
        j["return_address"] = hex_addr(event.return_address);
    if (event.callsite_address != 0)
        j["caller_address"] = hex_addr(event.callsite_address);
    if (!event.caller_module.empty()) {
        j["caller_module"] = event.caller_module;
        j["caller_module_offset"] = hex_addr(event.caller_module_offset);
    }
    j["registers"] = registers_to_json(event.regs);
    j["metadata"] = event.metadata;

    nlohmann::json buffers = nlohmann::json::array();
    for (const auto& b : event.buffers)
        buffers.push_back(buffer_to_json(b));
    j["buffers"] = buffers;

    if (!event.callstack.empty()) {
        nlohmann::json frames = nlohmann::json::array();
        for (const auto& f : event.callstack)
            frames.push_back(frame_to_json(f));
        j["callstack"] = frames;
    }
    return j;
}

inline nlohmann::json status_json() {
    nlohmann::json j;
    uint32_t armed = 0;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        j["pid"] = g_state.pid;
        j["target_count"] = static_cast<int>(g_state.targets.size());
        j["event_count"] = static_cast<int>(g_state.events.size());
        for (const auto& target : g_state.targets)
            armed += static_cast<uint32_t>(target.armed_tids.size());
    }
    j["active"] = g_state.active.load();
    j["debug_attached"] = g_state.debug_attached.load();
    j["debug_loop_running"] = g_state.debug_loop_running.load();
    j["cleanup_running"] = g_state.cleanup_running.load();
    j["debugger_error"] = static_cast<unsigned long>(g_state.debugger_error.load());
    j["total_hits"] = g_state.total_hits.load(std::memory_order_relaxed);
    j["armed_thread_breakpoints"] = armed;
    j["cleanup_attempts"] = g_state.cleanup_attempts.load(std::memory_order_relaxed);
    j["cleanup_last_elapsed_ms"] = g_state.cleanup_last_elapsed_ms.load(std::memory_order_relaxed);
    j["cleanup_last_requests"] = g_state.cleanup_last_requests.load(std::memory_order_relaxed);
    j["cleanup_last_succeeded"] = g_state.cleanup_last_succeeded.load(std::memory_order_relaxed);
    j["cleanup_last_failed"] = g_state.cleanup_last_failed.load(std::memory_order_relaxed);
    return j;
}

inline nlohmann::json results(size_t limit,
                              const std::string& filter_api,
                              bool clear_after,
                              bool stop_after) {
    if (limit == 0)
        limit = 64;
    if (limit > 512)
        limit = 512;

    const std::string filter = to_lower(filter_api);
    std::vector<api_event_t> selected;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        for (auto it = g_state.events.rbegin(); it != g_state.events.rend() && selected.size() < limit; ++it) {
            if (!filter.empty() && to_lower(it->api).find(filter) == std::string::npos)
                continue;
            selected.push_back(*it);
        }
        std::reverse(selected.begin(), selected.end());
        if (clear_after)
            g_state.events.clear();
    }

    nlohmann::json arr = nlohmann::json::array();
    for (const auto& event : selected)
        arr.push_back(event_to_json(event));

    if (stop_after)
        stop();

    nlohmann::json out;
    out["events"] = arr;
    out["count"] = static_cast<int>(arr.size());
    out["status"] = status_json();
    out["stopped"] = stop_after;
    return out;
}

inline void clear_events() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.events.clear();
}

}
