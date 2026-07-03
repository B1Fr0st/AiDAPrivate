#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "standalone_compat.hpp"
#include "standalone_driver.hpp"
#include "comm.h"
#include "emulation_engine.hpp"
#include "../debugger/page_guard_engine.hpp"
#include "../analysis/code_patcher.hpp"
#include "../disasm/zydis_disasm.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace protected_re {

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

namespace detail {

struct target_module_t {
    std::uint32_t pid = 0;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string name;
    std::string path;
    bool kernel = false;
};

struct mapped_section_t {
    std::string name;
    std::uint64_t va = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_pointer = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;
};

struct pe_layout_t {
    std::uint64_t base = 0;
    std::uint64_t entry = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t import_rva = 0;
    std::uint32_t import_size = 0;
    std::vector<mapped_section_t> sections;
    bool is_64 = true;
};

inline std::string lower_ascii(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline std::string trim_ascii(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.pop_back();
    return s;
}

inline bool contains_ci(const std::string& haystack, const std::string& needle)
{
    if (needle.empty())
        return true;
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

inline bool is_kernel_address(std::uint64_t address)
{
    return address >= 0xFFFF800000000000ULL;
}

inline std::optional<std::uint64_t> parse_u64_json(const json& value)
{
    if (value.is_number_unsigned())
        return value.get<std::uint64_t>();
    if (value.is_number_integer()) {
        const auto v = value.get<std::int64_t>();
        if (v < 0)
            return std::nullopt;
        return static_cast<std::uint64_t>(v);
    }
    if (value.is_string())
        return sa_parse_address(value.get<std::string>());
    if (value.is_object() && value.contains("value"))
        return parse_u64_json(value["value"]);
    return std::nullopt;
}

inline std::optional<std::uint64_t> parse_param_u64(const json& params, const char* key)
{
    if (!params.contains(key))
        return std::nullopt;
    return parse_u64_json(params[key]);
}

inline std::uint32_t requested_pid(const json& params)
{
    auto v = parse_param_u64(params, "process_id");
    if (!v)
        v = parse_param_u64(params, "pid");
    if (!v || *v == 0 || *v > 0xFFFFFFFFULL)
        return driver_bridge::attached_pid();
    return static_cast<std::uint32_t>(*v);
}

inline bool unsafe_confirmed(const json& params)
{
    return params.value("confirm_unsafe", false) ||
           params.value("allow_unsafe", false) ||
           params.value("unsafe", false);
}

inline json destructive_safe_contract_payload(const char* tool,
                                              const char* action,
                                              const json& params,
                                              const char* validation_code,
                                              const char* required_capability)
{
    json out;
    out["tool"] = tool ? tool : "";
    out["action"] = action ? action : "";
    out["validation_code"] = validation_code ? validation_code : "";
    out["required_capability"] = required_capability ? required_capability : "";
    out["safe_contract"] = "fail_closed_until_explicit_unsafe_confirmation_and_validated_inputs";
    out["mutation"] = "none";
    out["side_effects"] = "none";
    out["fail_closed"] = true;
    out["functional_success"] = false;
    out["confirm_unsafe_required"] = true;
    out["allow_unsafe_alias_accepted"] = true;
    out["allow_unsafe_required"] = false;
    out["confirm_unsafe_received"] = params.value("confirm_unsafe", false);
    out["allow_unsafe_received"] = params.value("allow_unsafe", false);
    out["unsafe_received"] = params.value("unsafe", false);
    out["unsafe_confirmed"] = unsafe_confirmed(params);
    out["security_guard_pass"] = true;
    out["device_open_attempted"] = false;
    out["process_id"] = requested_pid(params);
    out["driver_connected"] = driver_bridge::using_kernel_driver() && device && device->is_connected();
    out["diag_id"] = mcp_standalone::current_call_diag_id();
    out["deadline_ms"] = mcp_standalone::current_call_deadline_ms();
    out["cancelled"] = mcp_standalone::current_call_cancelled();
    return out;
}

inline tool_result_t require_driver()
{
    if (!driver_bridge::using_kernel_driver() || !device || !device->is_connected())
        return tool_result_t::error("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first.");
    return tool_result_t::ok(json{{"status", "ok"}});
}

inline std::recursive_mutex& active_pid_scope_mutex()
{
    static std::recursive_mutex m;
    return m;
}

struct active_pid_scope_t {
    std::uint32_t previous = 0;
    std::uint32_t requested = 0;
    bool changed = false;
    bool ok = false;
    std::unique_lock<std::recursive_mutex> lock;

    explicit active_pid_scope_t(std::uint32_t pid)
        : lock(active_pid_scope_mutex())
    {
        requested = pid != 0 ? pid : driver_bridge::attached_pid();
        previous = driver_bridge::attached_pid();
        if (requested == 0 || !driver_bridge::using_kernel_driver() || !device || !device->is_connected())
            return;
        if (previous != requested) {
            const auto attached = driver_bridge::attached_pids();
            bool known = false;
            for (const auto attached_pid : attached) {
                if (attached_pid == requested) {
                    known = true;
                    break;
                }
            }
            if (!known && !driver_bridge::attach_additional(requested))
                return;
            if (!driver_bridge::set_active_pid(requested))
                return;
            changed = true;
        }
        if (device->get_process_id() != requested)
            device->set_process_id(requested);
        if (device->get_dtb() == 0)
            device->solve_dtb();
        ok = device->get_dtb() != 0;
        if (!ok)
            diag::log_tagged_fmt("protected_re", "active_pid_scope_dtb_failed requested=%u previous=%u active=%u status=%s last_error=%s",
                requested, previous, driver_bridge::attached_pid(), driver_bridge::status().c_str(), driver_bridge::last_error().c_str());
    }

    ~active_pid_scope_t()
    {
        if (!changed)
            return;
        if (previous != 0)
            driver_bridge::set_active_pid(previous);
        else
            driver_bridge::clear_active_pid();
    }
};

inline json page_guard_install_failure_json()
{
    const auto f = page_guard_engine::g_pg_engine.last_install_failure();
    return json{
        {"reason", f.reason},
        {"detail", f.detail},
        {"driver_status", f.driver_status},
        {"driver_last_error", f.driver_last_error},
        {"pid", f.pid},
        {"win32_error", f.win32_error},
        {"region_state", f.region_state},
        {"region_protect", f.region_protect},
        {"region_type", f.region_type},
        {"attempted_protect", f.attempted_protect},
        {"requested_addr", sa_format_address(f.requested_addr)},
        {"requested_size", f.requested_size},
        {"guard_addr", sa_format_address(f.guard_addr)},
        {"guard_size", f.guard_size},
        {"region_base", sa_format_address(f.region_base)},
        {"region_size", f.region_size}
    };
}

inline std::string page_guard_access_kind(std::uint32_t access_type)
{
    switch (access_type) {
    case 0: return "read";
    case 1: return "write";
    case 8: return "execute";
    default: return "unknown";
    }
}

inline json page_guard_capture_json(const page_guard_engine::pg_capture_record_t& c)
{
    const auto& m = c.metadata;
    json out;
    out["fault_address"] = sa_format_address(m.fault_addr);
    out["rip"] = sa_format_address(m.rip);
    out["rax"] = sa_format_address(m.ctx_rax);
    out["rcx"] = sa_format_address(m.ctx_rcx);
    out["rdx"] = sa_format_address(m.ctx_rdx);
    out["exception_code"] = m.exception_code;
    out["access_type"] = m.access_type;
    out["access_kind"] = page_guard_access_kind(m.access_type);
    out["event_kind"] = out["access_kind"];
    out["timestamp_tsc"] = m.timestamp;
    page_guard_engine::serialize_payload_fields(out, c);
    return out;
}

inline json page_guard_sessions_json()
{
    json arr = json::array();
    for (const auto& s : page_guard_engine::g_pg_engine.list_sessions()) {
        arr.push_back(json{
            {"session_id", s.session_id},
            {"pid", s.pid},
            {"target_addr", sa_format_address(s.target_addr)},
            {"region_size", s.region_size},
            {"pending_captures", s.pending_captures}
        });
    }
    return arr;
}

inline bool read_target_memory(std::uint32_t pid, std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (address == 0 || size == 0)
        return false;
    if (size > 16u * 1024u * 1024u)
        size = 16u * 1024u * 1024u;
    if (is_kernel_address(address))
        return driver_bridge::read_kernel_memory(address, size, out);
    active_pid_scope_t scope(pid);
    if (!scope.ok) {
        diag::log_tagged_fmt("protected_re", "read_target_memory_scope_failed pid=%u addr=0x%llX size=%zu active=%u",
            pid, static_cast<unsigned long long>(address), size, driver_bridge::attached_pid());
        return false;
    }
    out.resize(size);
    const std::size_t got = device->read_raw(address, out.data(), size);
    if (got == 0) {
        out.clear();
        diag::log_tagged_fmt("protected_re", "read_target_memory_driver_failed pid=%u addr=0x%llX size=%zu active=%u dtb=0x%llX",
            scope.requested,
            static_cast<unsigned long long>(address),
            size,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(device->get_dtb()));
        return false;
    }
    out.resize(got);
    return true;
}

template <typename T>
inline bool read_target_value(std::uint32_t pid, std::uint64_t address, T& out)
{
    std::vector<std::uint8_t> bytes;
    if (!read_target_memory(pid, address, sizeof(T), bytes) || bytes.size() < sizeof(T))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(T));
    return true;
}

inline bool write_target_memory(std::uint32_t pid, std::uint64_t address, const std::vector<std::uint8_t>& bytes)
{
    if (address == 0 || bytes.empty() || is_kernel_address(address))
        return false;
    active_pid_scope_t scope(pid);
    if (!scope.ok) {
        diag::log_tagged_fmt("protected_re", "write_target_memory_scope_failed pid=%u addr=0x%llX size=%zu active=%u",
            pid, static_cast<unsigned long long>(address), bytes.size(), driver_bridge::attached_pid());
        return false;
    }
    const std::size_t written = device->write_raw(address, bytes.data(), bytes.size());
    if (written != bytes.size()) {
        diag::log_tagged_fmt("protected_re", "write_target_memory_driver_failed pid=%u addr=0x%llX size=%zu written=%zu active=%u dtb=0x%llX",
            scope.requested,
            static_cast<unsigned long long>(address),
            bytes.size(),
            written,
            driver_bridge::attached_pid(),
            static_cast<unsigned long long>(device->get_dtb()));
        return false;
    }
    return true;
}

inline std::vector<voyager::device_t::thread_info> enumerate_target_threads(std::uint32_t pid)
{
    active_pid_scope_t scope(pid);
    if (!scope.ok)
        return {};
    return device->enumerate_threads();
}

inline bool read_target_thread_context(std::uint32_t pid, std::uint32_t tid, voyager::device_t::thread_context& ctx)
{
    active_pid_scope_t scope(pid);
    if (!scope.ok || tid == 0)
        return false;
    return device->get_thread_context(tid, ctx);
}

inline bool set_target_hardware_breakpoint(std::uint32_t pid, std::uint32_t tid, int index, std::uint64_t address, int type, int size)
{
    active_pid_scope_t scope(pid);
    if (!scope.ok || tid == 0)
        return false;
    return device->set_hardware_breakpoint(tid, index, address, type, size);
}

inline bool clear_target_hardware_breakpoint(std::uint32_t pid, std::uint32_t tid, int index)
{
    active_pid_scope_t scope(pid);
    if (!scope.ok || tid == 0)
        return false;
    return device->clear_hardware_breakpoint(tid, index);
}

inline bool set_target_thread_context(std::uint32_t pid, std::uint32_t tid, const voyager::device_t::thread_context& ctx, std::uint64_t register_mask)
{
    active_pid_scope_t scope(pid);
    if (!scope.ok || tid == 0)
        return false;
    return device->set_thread_context(tid, ctx, register_mask);
}

inline const char* drv_gpr_name(std::uint16_t reg)
{
    switch (static_cast<ZydisRegister>(reg)) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH: return "rax";
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH: return "rbx";
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH: return "rcx";
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH: return "rdx";
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: case ZYDIS_REGISTER_SIL: return "rsi";
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: case ZYDIS_REGISTER_DIL: return "rdi";
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP: case ZYDIS_REGISTER_BPL: return "rbp";
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: case ZYDIS_REGISTER_SPL: return "rsp";
    case ZYDIS_REGISTER_R8: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B: return "r8";
    case ZYDIS_REGISTER_R9: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B: return "r9";
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return "r10";
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return "r11";
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return "r12";
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return "r13";
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return "r14";
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return "r15";
    default: return "";
    }
}

inline std::uint64_t context_dr_address(const voyager::device_t::thread_context& ctx, std::uint32_t slot)
{
    switch (slot) {
    case 0: return ctx.dr0;
    case 1: return ctx.dr1;
    case 2: return ctx.dr2;
    case 3: return ctx.dr3;
    default: return 0;
    }
}

inline json thread_context_register_json(const voyager::device_t::thread_context& ctx)
{
    return json{{"rip", sa_format_address(ctx.rip)},
                {"rsp", sa_format_address(ctx.rsp)},
                {"rax", sa_format_address(ctx.rax)},
                {"rbx", sa_format_address(ctx.rbx)},
                {"rcx", sa_format_address(ctx.rcx)},
                {"rdx", sa_format_address(ctx.rdx)},
                {"r8", sa_format_address(ctx.r8)},
                {"r9", sa_format_address(ctx.r9)},
                {"r10", sa_format_address(ctx.r10)},
                {"r11", sa_format_address(ctx.r11)},
                {"rflags", sa_format_address(ctx.rflags)},
                {"dr0", sa_format_address(ctx.dr0)},
                {"dr1", sa_format_address(ctx.dr1)},
                {"dr2", sa_format_address(ctx.dr2)},
                {"dr3", sa_format_address(ctx.dr3)},
                {"dr6", sa_format_address(ctx.dr6)},
                {"dr7", sa_format_address(ctx.dr7)}};
}

inline std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes, std::size_t limit = std::numeric_limits<std::size_t>::max())
{
    const std::size_t n = std::min(bytes.size(), limit);
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < n; ++i) {
        if (i)
            os << ' ';
        os << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    if (bytes.size() > n)
        os << " ...";
    return os.str();
}

inline std::vector<std::uint8_t> hex_to_bytes(std::string text)
{
    std::vector<std::uint8_t> out;
    std::string compact;
    compact.reserve(text.size());
    for (char c : text) {
        if (std::isxdigit(static_cast<unsigned char>(c)))
            compact.push_back(c);
    }
    if ((compact.size() & 1u) != 0)
        return {};
    out.reserve(compact.size() / 2);
    for (std::size_t i = 0; i + 1 < compact.size(); i += 2) {
        char pair[3] = { compact[i], compact[i + 1], 0 };
        out.push_back(static_cast<std::uint8_t>(std::strtoul(pair, nullptr, 16)));
    }
    return out;
}

inline bool hex_to_bytes_strict(const std::string& text, std::vector<std::uint8_t>& out, std::string& error)
{
    out.clear();
    error.clear();
    std::string compact;
    compact.reserve(text.size());
    bool token_start = true;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (std::isspace(c)) {
            token_start = true;
            continue;
        }
        if (token_start && c == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            ++i;
            token_start = false;
            continue;
        }
        if (!std::isxdigit(c)) {
            error = "input_buffer_hex contains invalid character at offset " + std::to_string(i);
            return false;
        }
        compact.push_back(static_cast<char>(c));
        token_start = false;
    }
    if ((compact.size() & 1u) != 0) {
        error = "input_buffer_hex must contain an even number of hex digits";
        return false;
    }
    out.reserve(compact.size() / 2);
    for (std::size_t i = 0; i + 1 < compact.size(); i += 2) {
        char pair[3] = { compact[i], compact[i + 1], 0 };
        char* end = nullptr;
        const unsigned long v = std::strtoul(pair, &end, 16);
        if (!end || *end != '\0') {
            error = "input_buffer_hex contains an invalid byte at offset " + std::to_string(i);
            out.clear();
            return false;
        }
        out.push_back(static_cast<std::uint8_t>(v & 0xFFu));
    }
    return true;
}

inline double entropy_of(const std::vector<std::uint8_t>& bytes)
{
    if (bytes.empty())
        return 0.0;
    std::array<std::uint64_t, 256> counts{};
    for (std::uint8_t b : bytes)
        ++counts[b];
    double e = 0.0;
    const double total = static_cast<double>(bytes.size());
    for (std::uint64_t c : counts) {
        if (c == 0)
            continue;
        const double p = static_cast<double>(c) / total;
        e -= p * std::log2(p);
    }
    return e;
}

inline bool executable_characteristics(std::uint32_t ch)
{
    return (ch & IMAGE_SCN_MEM_EXECUTE) != 0 || (ch & IMAGE_SCN_CNT_CODE) != 0;
}

inline bool executable_protect(std::uint32_t protect)
{
    const std::uint32_t p = protect & 0xFFu;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

inline std::string protection_name(std::uint32_t protect)
{
    switch (protect & 0xFFu) {
    case PAGE_NOACCESS: return "NOACCESS";
    case PAGE_READONLY: return "READONLY";
    case PAGE_READWRITE: return "READWRITE";
    case PAGE_WRITECOPY: return "WRITECOPY";
    case PAGE_EXECUTE: return "EXECUTE";
    case PAGE_EXECUTE_READ: return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
    default: return sa_format_address(protect);
    }
}

inline std::string section_name(const IMAGE_SECTION_HEADER& s)
{
    char buf[9] = {};
    std::memcpy(buf, s.Name, 8);
    return std::string(buf);
}

inline bool read_pe_layout(std::uint32_t pid, std::uint64_t base, pe_layout_t& out)
{
    out = {};
    if (base == 0)
        return false;
    IMAGE_DOS_HEADER dos{};
    if (!read_target_value(pid, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000)
        return false;
    DWORD sig = 0;
    if (!read_target_value(pid, base + static_cast<std::uint32_t>(dos.e_lfanew), sig) || sig != IMAGE_NT_SIGNATURE)
        return false;
    IMAGE_FILE_HEADER fh{};
    if (!read_target_value(pid, base + static_cast<std::uint32_t>(dos.e_lfanew) + 4, fh))
        return false;
    if (fh.NumberOfSections == 0 || fh.NumberOfSections > 96)
        return false;
    const std::uint64_t opt_va = base + static_cast<std::uint32_t>(dos.e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER);
    WORD magic = 0;
    if (!read_target_value(pid, opt_va, magic))
        return false;
    out.base = base;
    out.is_64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (out.is_64) {
        IMAGE_OPTIONAL_HEADER64 opt{};
        if (!read_target_value(pid, opt_va, opt))
            return false;
        out.entry = base + opt.AddressOfEntryPoint;
        out.size_of_image = opt.SizeOfImage;
        if (IMAGE_DIRECTORY_ENTRY_IMPORT < opt.NumberOfRvaAndSizes) {
            out.import_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            out.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    } else {
        IMAGE_OPTIONAL_HEADER32 opt{};
        if (!read_target_value(pid, opt_va, opt))
            return false;
        out.entry = base + opt.AddressOfEntryPoint;
        out.size_of_image = opt.SizeOfImage;
        if (IMAGE_DIRECTORY_ENTRY_IMPORT < opt.NumberOfRvaAndSizes) {
            out.import_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            out.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    }
    const std::uint64_t sec_va = opt_va + fh.SizeOfOptionalHeader;
    out.sections.reserve(fh.NumberOfSections);
    for (WORD i = 0; i < fh.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!read_target_value(pid, sec_va + static_cast<std::uint64_t>(i) * sizeof(sh), sh))
            break;
        mapped_section_t ms;
        ms.name = section_name(sh);
        ms.va = base + sh.VirtualAddress;
        ms.virtual_size = sh.Misc.VirtualSize;
        ms.raw_size = sh.SizeOfRawData;
        ms.raw_pointer = sh.PointerToRawData;
        ms.characteristics = sh.Characteristics;
        out.sections.push_back(std::move(ms));
    }
    return out.entry != 0 && !out.sections.empty();
}

template <typename T>
inline bool read_image_value(const std::vector<std::uint8_t>& image, std::uint64_t offset, T& out)
{
    if (offset > image.size() || image.size() - static_cast<std::size_t>(offset) < sizeof(T))
        return false;
    std::memcpy(&out, image.data() + static_cast<std::size_t>(offset), sizeof(T));
    return true;
}

inline bool read_pe_layout_from_image_bytes(const std::vector<std::uint8_t>& image, std::uint64_t base_override, pe_layout_t& out)
{
    out = {};
    if (image.size() < sizeof(IMAGE_DOS_HEADER))
        return false;
    IMAGE_DOS_HEADER dos{};
    if (!read_image_value(image, 0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (dos.e_lfanew <= 0 || static_cast<std::uint64_t>(dos.e_lfanew) > image.size() || image.size() - static_cast<std::size_t>(dos.e_lfanew) < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
        return false;
    DWORD sig = 0;
    if (!read_image_value(image, static_cast<std::uint64_t>(dos.e_lfanew), sig) || sig != IMAGE_NT_SIGNATURE)
        return false;
    IMAGE_FILE_HEADER fh{};
    if (!read_image_value(image, static_cast<std::uint64_t>(dos.e_lfanew) + 4, fh))
        return false;
    if (fh.NumberOfSections == 0 || fh.NumberOfSections > 96)
        return false;
    const std::uint64_t opt_off = static_cast<std::uint64_t>(dos.e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER);
    WORD magic = 0;
    if (!read_image_value(image, opt_off, magic))
        return false;
    out.is_64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (out.is_64) {
        IMAGE_OPTIONAL_HEADER64 opt{};
        if (!read_image_value(image, opt_off, opt))
            return false;
        out.base = base_override ? base_override : opt.ImageBase;
        out.entry = out.base + opt.AddressOfEntryPoint;
        out.size_of_image = opt.SizeOfImage;
        if (IMAGE_DIRECTORY_ENTRY_IMPORT < opt.NumberOfRvaAndSizes) {
            out.import_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            out.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    } else {
        IMAGE_OPTIONAL_HEADER32 opt{};
        if (!read_image_value(image, opt_off, opt))
            return false;
        out.base = base_override ? base_override : opt.ImageBase;
        out.entry = out.base + opt.AddressOfEntryPoint;
        out.size_of_image = opt.SizeOfImage;
        if (IMAGE_DIRECTORY_ENTRY_IMPORT < opt.NumberOfRvaAndSizes) {
            out.import_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            out.import_size = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    }
    const std::uint64_t sec_off = opt_off + fh.SizeOfOptionalHeader;
    if (sec_off > image.size() || image.size() - static_cast<std::size_t>(sec_off) < static_cast<std::size_t>(fh.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER))
        return false;
    out.sections.reserve(fh.NumberOfSections);
    for (WORD i = 0; i < fh.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!read_image_value(image, sec_off + static_cast<std::uint64_t>(i) * sizeof(sh), sh))
            return false;
        mapped_section_t ms;
        ms.name = section_name(sh);
        ms.va = out.base + sh.VirtualAddress;
        ms.virtual_size = sh.Misc.VirtualSize;
        ms.raw_size = sh.SizeOfRawData;
        ms.raw_pointer = sh.PointerToRawData;
        ms.characteristics = sh.Characteristics;
        out.sections.push_back(std::move(ms));
    }
    return out.base != 0 && out.entry != 0 && !out.sections.empty();
}

inline bool read_image_va_bytes(const std::vector<std::uint8_t>& image,
                                const pe_layout_t& pe,
                                std::uint64_t va,
                                std::size_t size,
                                std::vector<std::uint8_t>& out)
{
    out.clear();
    if (image.empty() || size == 0 || va < pe.base)
        return false;
    const std::uint64_t rva = va - pe.base;
    for (const auto& sec : pe.sections) {
        const std::uint64_t sec_rva = sec.va >= pe.base ? sec.va - pe.base : 0;
        const std::uint64_t sec_span = std::max<std::uint64_t>(sec.virtual_size, sec.raw_size);
        if (sec_span == 0 || rva < sec_rva || rva >= sec_rva + sec_span)
            continue;
        const std::uint64_t in_sec = rva - sec_rva;
        const std::uint64_t raw_off = static_cast<std::uint64_t>(sec.raw_pointer) + in_sec;
        if (raw_off >= image.size())
            return false;
        const std::size_t avail = static_cast<std::size_t>(std::min<std::uint64_t>(size, image.size() - static_cast<std::size_t>(raw_off)));
        out.assign(image.begin() + static_cast<std::ptrdiff_t>(raw_off), image.begin() + static_cast<std::ptrdiff_t>(raw_off + avail));
        return !out.empty();
    }
    if (rva < image.size()) {
        const std::size_t avail = static_cast<std::size_t>(std::min<std::uint64_t>(size, image.size() - static_cast<std::size_t>(rva)));
        out.assign(image.begin() + static_cast<std::ptrdiff_t>(rva), image.begin() + static_cast<std::ptrdiff_t>(rva + avail));
        return !out.empty();
    }
    return false;
}

inline std::vector<target_module_t> user_modules(std::uint32_t pid)
{
    std::vector<target_module_t> out;
    std::vector<driver_bridge::module_info_t> mods = pid != 0 ? driver_bridge::enumerate_modules_for(pid) : driver_bridge::enumerate_modules();
    for (const auto& m : mods) {
        target_module_t tm;
        tm.pid = pid;
        tm.base = m.base;
        tm.size = m.size;
        tm.name = m.name;
        tm.path = m.path;
        tm.kernel = false;
        out.push_back(std::move(tm));
    }
    return out;
}

struct sys_module_entry_t {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct sys_module_info_t {
    ULONG NumberOfModules;
    sys_module_entry_t Modules[1];
};

using NtQuerySystemInformation_fn = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);

inline std::vector<target_module_t> kernel_modules(std::string* error = nullptr)
{
    std::vector<target_module_t> out;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        if (error) *error = "ntdll.dll is not loaded";
        return out;
    }
    auto fn = reinterpret_cast<NtQuerySystemInformation_fn>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!fn) {
        if (error) *error = "NtQuerySystemInformation is unavailable";
        return out;
    }
    ULONG needed = 0;
    fn(11, nullptr, 0, &needed);
    if (needed == 0)
        needed = 512 * 1024;
    needed += 16384;
    std::vector<std::uint8_t> buf(needed);
    LONG status = fn(11, buf.data(), static_cast<ULONG>(buf.size()), &needed);
    if (status < 0) {
        if (error) *error = "NtQuerySystemInformation(SystemModuleInformation) failed with " + sa_format_address(static_cast<std::uint32_t>(status));
        return out;
    }
    if (buf.size() < sizeof(ULONG))
        return out;
    const auto* info = reinterpret_cast<const sys_module_info_t*>(buf.data());
    if (info->NumberOfModules > 4096)
        return out;
    for (ULONG i = 0; i < info->NumberOfModules; ++i) {
        const auto& m = info->Modules[i];
        const char* p = reinterpret_cast<const char*>(m.FullPathName);
        std::size_t len = 0;
        while (len < sizeof(m.FullPathName) && p[len] != '\0')
            ++len;
        std::string path(p, len);
        std::string name = path;
        if (m.OffsetToFileName < path.size())
            name = path.substr(m.OffsetToFileName);
        else {
            const std::size_t pos = path.find_last_of("\\/");
            if (pos != std::string::npos)
                name = path.substr(pos + 1);
        }
        target_module_t tm;
        tm.base = reinterpret_cast<std::uint64_t>(m.ImageBase);
        tm.size = m.ImageSize;
        tm.name = name;
        tm.path = path;
        tm.kernel = true;
        out.push_back(std::move(tm));
    }
    return out;
}

inline std::optional<target_module_t> select_module(const json& params, bool kernel, std::string* error)
{
    std::uint32_t pid = requested_pid(params);
    auto base = parse_param_u64(params, kernel ? "module_base" : "module_base");
    if (!base)
        base = parse_param_u64(params, "base");
    auto module_size = parse_param_u64(params, "module_size");
    if (!module_size)
        module_size = parse_param_u64(params, "image_size");
    if (!module_size)
        module_size = parse_param_u64(params, "range_size");
    std::string filter;
    for (const char* k : { "module_name", "module", "driver_name", "name" }) {
        if (params.contains(k) && params[k].is_string()) {
            filter = params[k].get<std::string>();
            break;
        }
    }
    std::string qerr;
    std::vector<target_module_t> mods = kernel ? kernel_modules(&qerr) : user_modules(pid);
    if (base) {
        for (const auto& m : mods) {
            if (m.base == *base)
                return m;
        }
        target_module_t tm;
        tm.pid = pid;
        tm.base = *base;
        tm.size = module_size.value_or(0);
        tm.name = "module@" + sa_format_address(*base);
        tm.kernel = kernel || is_kernel_address(*base);
        return tm;
    }
    if (mods.empty()) {
        if (error) *error = qerr.empty() ? "No modules are available" : qerr;
        return std::nullopt;
    }
    if (!filter.empty()) {
        for (const auto& m : mods) {
            if (contains_ci(m.name, filter) || contains_ci(m.path, filter))
                return m;
        }
        if (error) *error = "No module matched '" + filter + "'";
        return std::nullopt;
    }
    if (!kernel)
        return mods.front();
    json candidates = json::array();
    for (std::size_t i = 0; i < mods.size() && i < 16; ++i)
        candidates.push_back(json{{"name", mods[i].name}, {"base", sa_format_address(mods[i].base)}, {"size", mods[i].size}});
    if (error) *error = "Provide driver_name or module_base for kernel driver analysis. Candidate modules: " + candidates.dump();
    return std::nullopt;
}

inline std::vector<AsmInstr> disassemble_target(std::uint32_t pid, std::uint64_t address, std::uint32_t bytes, std::uint32_t max_insns)
{
    std::vector<AsmInstr> out;
    if (bytes == 0 || max_insns == 0)
        return out;
    bytes = std::min<std::uint32_t>(bytes, 1024u * 1024u);
    max_insns = std::min<std::uint32_t>(max_insns, 65536u);
#ifdef __NT__
    if (!is_kernel_address(address) && (pid == 0 || pid == driver_bridge::attached_pid())) {
        auto decoded = emulation::driver_disassemble_range(address, bytes, max_insns);
        out.reserve(decoded.size());
        for (const auto& d : decoded) {
            AsmInstr ins{};
            ins.addr = d.address;
            ins.len = static_cast<int>(d.length);
            std::snprintf(ins.mnem, sizeof(ins.mnem), "%s", d.mnemonic.c_str());
            std::snprintf(ins.ops, sizeof(ins.ops), "%s", d.operands_text.c_str());
            ins.is_branch = d.is_branch;
            ins.is_call = d.is_call;
            ins.is_ret = d.is_ret;
            ins.is_nop = d.is_nop;
            ins.is_priv = d.is_privileged;
            out.push_back(ins);
        }
        if (!out.empty())
            return out;
    }
#endif
    std::vector<std::uint8_t> mem;
    if (!read_target_memory(pid, address, bytes, mem) || mem.empty())
        return out;
    std::size_t off = 0;
    while (off < mem.size() && out.size() < max_insns) {
        const int avail = static_cast<int>(std::min<std::size_t>(15, mem.size() - off));
        AsmInstr ins = zydis_decode_one(mem.data() + off, avail, address + off);
        if (ins.len <= 0)
            ins.len = 1;
        out.push_back(ins);
        off += static_cast<std::size_t>(ins.len);
    }
    return out;
}

inline json instruction_to_json(const AsmInstr& ins)
{
    json j;
    j["address"] = sa_format_address(ins.addr);
    j["mnemonic"] = ins.mnem;
    j["operands"] = ins.ops;
    j["text"] = std::string(ins.mnem) + (std::strlen(ins.ops) ? " " + std::string(ins.ops) : "");
    j["length"] = ins.len;
    if (ins.branch_target)
        j["target"] = sa_format_address(ins.branch_target);
    if (ins.is_branch)
        j["is_branch"] = true;
    if (ins.is_call)
        j["is_call"] = true;
    if (ins.is_ret)
        j["is_ret"] = true;
    return j;
}

inline std::vector<std::string> split_operands(const char* ops)
{
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    for (const char* p = ops; p && *p; ++p) {
        if (*p == '[')
            ++depth;
        else if (*p == ']' && depth > 0)
            --depth;
        if (*p == ',' && depth == 0) {
            out.push_back(trim_ascii(cur));
            cur.clear();
        } else {
            cur.push_back(*p);
        }
    }
    if (!cur.empty())
        out.push_back(trim_ascii(cur));
    return out;
}

inline std::optional<std::uint64_t> parse_hex_in_text(const std::string& text)
{
    const std::size_t p = text.find("0x");
    if (p == std::string::npos)
        return std::nullopt;
    std::size_t e = p + 2;
    while (e < text.size() && std::isxdigit(static_cast<unsigned char>(text[e])))
        ++e;
    return sa_parse_address(text.substr(p, e - p));
}

inline std::string reg_from_operand(const std::string& op)
{
    std::string s = lower_ascii(op);
    for (const char* prefix : { "qword ptr ", "dword ptr ", "word ptr ", "byte ptr ", "ptr " }) {
        const std::string p(prefix);
        const std::size_t pos = s.find(p);
        if (pos != std::string::npos)
            s.erase(pos, p.size());
    }
    s = trim_ascii(s);
    static const std::array<const char*, 16> regs = {
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"
    };
    for (const char* r : regs) {
        if (s == r)
            return r;
    }
    static const std::array<std::pair<const char*, const char*>, 52> aliases = {{
        {"eax","rax"},{"ax","rax"},{"al","rax"},{"ah","rax"},
        {"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},{"bh","rbx"},
        {"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},{"ch","rcx"},
        {"edx","rdx"},{"dx","rdx"},{"dl","rdx"},{"dh","rdx"},
        {"esi","rsi"},{"si","rsi"},{"sil","rsi"},
        {"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},
        {"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
        {"r8d","r8"},{"r8w","r8"},{"r8b","r8"},
        {"r9d","r9"},{"r9w","r9"},{"r9b","r9"},
        {"r10d","r10"},{"r10w","r10"},{"r10b","r10"},
        {"r11d","r11"},{"r11w","r11"},{"r11b","r11"},
        {"r12d","r12"},{"r12w","r12"},{"r12b","r12"},
        {"r13d","r13"},{"r13w","r13"},{"r13b","r13"},
        {"r14d","r14"},{"r14w","r14"},{"r14b","r14"},
        {"r15d","r15"},{"r15w","r15"},{"r15b","r15"}
    }};
    for (const auto& alias : aliases) {
        if (s == alias.first)
            return alias.second;
    }
    return s;
}

inline bool operand_is_memory(const std::string& op)
{
    return op.find('[') != std::string::npos && op.find(']') != std::string::npos;
}

inline std::string classify_memory_direction(const AsmInstr& ins)
{
    auto ops = split_operands(ins.ops);
    if (ops.empty())
        return {};
    if (operand_is_memory(ops[0]))
        return "write";
    if (ops.size() > 1 && operand_is_memory(ops[1]))
        return "read";
    return {};
}

inline std::string mnemonic_of(const AsmInstr& ins)
{
    return lower_ascii(ins.mnem);
}

inline bool is_conditional_branch(const AsmInstr& ins)
{
    const std::string m = mnemonic_of(ins);
    return ins.is_branch && m != "jmp";
}

inline std::string estimate_algo_from_mnemonic(const std::string& mnemonic)
{
    if (mnemonic == "xor")
        return "xor";
    if (mnemonic == "add" || mnemonic == "sub")
        return "add";
    if (mnemonic == "rol" || mnemonic == "ror" || mnemonic == "shl" || mnemonic == "shr")
        return "rol";
    return "custom";
}

struct block_t {
    int id = 0;
    std::uint64_t start = 0;
    std::uint64_t end = 0;
    std::vector<AsmInstr> insns;
    std::vector<int> successors;
};

inline std::vector<block_t> build_blocks(const std::vector<AsmInstr>& insns)
{
    std::vector<block_t> blocks;
    if (insns.empty())
        return blocks;
    std::map<std::uint64_t, int> addr_to_index;
    std::set<std::uint64_t> leaders;
    leaders.insert(insns.front().addr);
    const std::uint64_t lo = insns.front().addr;
    const std::uint64_t hi = insns.back().addr + std::max<int>(insns.back().len, 1);
    for (const auto& ins : insns) {
        if ((ins.is_branch || ins.is_call) && ins.branch_target >= lo && ins.branch_target < hi)
            leaders.insert(ins.branch_target);
        if (ins.is_branch || ins.is_ret) {
            const std::uint64_t next = ins.addr + std::max<int>(ins.len, 1);
            if (next >= lo && next < hi)
                leaders.insert(next);
        }
    }
    int cur = -1;
    for (const auto& ins : insns) {
        if (leaders.count(ins.addr) || cur < 0) {
            block_t b;
            b.id = static_cast<int>(blocks.size());
            b.start = ins.addr;
            addr_to_index[b.start] = b.id;
            blocks.push_back(std::move(b));
            cur = blocks.back().id;
        }
        blocks[static_cast<std::size_t>(cur)].insns.push_back(ins);
        blocks[static_cast<std::size_t>(cur)].end = ins.addr + std::max<int>(ins.len, 1);
        if (ins.is_branch || ins.is_ret)
            cur = -1;
    }
    for (auto& b : blocks) {
        if (b.insns.empty())
            continue;
        const AsmInstr& last = b.insns.back();
        if (last.is_ret)
            continue;
        const std::string m = mnemonic_of(last);
        if (last.is_branch && last.branch_target != 0) {
            auto it = addr_to_index.find(last.branch_target);
            if (it != addr_to_index.end())
                b.successors.push_back(it->second);
            if (m != "jmp") {
                auto itf = addr_to_index.find(last.addr + std::max<int>(last.len, 1));
                if (itf != addr_to_index.end() && std::find(b.successors.begin(), b.successors.end(), itf->second) == b.successors.end())
                    b.successors.push_back(itf->second);
            }
        } else {
            auto itn = addr_to_index.find(last.addr + std::max<int>(last.len, 1));
            if (itn != addr_to_index.end())
                b.successors.push_back(itn->second);
        }
    }
    return blocks;
}

inline json blocks_to_json(const std::vector<block_t>& blocks, std::size_t insn_limit = 16)
{
    json arr = json::array();
    for (const auto& b : blocks) {
        json bj;
        bj["id"] = b.id;
        bj["start"] = sa_format_address(b.start);
        bj["end"] = sa_format_address(b.end);
        bj["successors"] = b.successors;
        json ij = json::array();
        for (std::size_t i = 0; i < b.insns.size() && i < insn_limit; ++i)
            ij.push_back(instruction_to_json(b.insns[i]));
        bj["instructions"] = std::move(ij);
        bj["instruction_count"] = b.insns.size();
        arr.push_back(std::move(bj));
    }
    return arr;
}

inline std::string cfg_to_dot(const std::vector<block_t>& blocks, const char* name)
{
    std::ostringstream os;
    os << "digraph " << (name ? name : "cfg") << " {\n";
    for (const auto& b : blocks)
        os << "  n" << b.id << " [label=\"B" << b.id << "\\n" << sa_format_address(b.start) << "\"];\n";
    for (const auto& b : blocks) {
        for (int s : b.successors)
            os << "  n" << b.id << " -> n" << s << ";\n";
    }
    os << "}\n";
    return os.str();
}

inline bool pointer_looks_executable(std::uint32_t pid, std::uint64_t ptr)
{
    if (ptr == 0)
        return false;
    if (is_kernel_address(ptr))
        return true;
    driver_bridge::memory_region_t r{};
    return driver_bridge::query_memory_for(pid, ptr, r) && executable_protect(r.protect);
}

inline double table_density(std::uint32_t pid, std::uint64_t table, std::uint32_t count, json* sample)
{
    if (table == 0 || count == 0)
        return 0.0;
    count = std::min<std::uint32_t>(count, 512);
    std::vector<std::uint8_t> bytes;
    if (!read_target_memory(pid, table, static_cast<std::size_t>(count) * sizeof(std::uint64_t), bytes) || bytes.size() < sizeof(std::uint64_t))
        return 0.0;
    std::uint32_t valid = 0;
    const std::uint32_t got = static_cast<std::uint32_t>(bytes.size() / sizeof(std::uint64_t));
    for (std::uint32_t i = 0; i < got; ++i) {
        std::uint64_t ptr = 0;
        std::memcpy(&ptr, bytes.data() + static_cast<std::size_t>(i) * sizeof(ptr), sizeof(ptr));
        if (pointer_looks_executable(pid, ptr)) {
            ++valid;
            if (sample && sample->size() < 16)
                sample->push_back(json{{"index", i}, {"handler_va", sa_format_address(ptr)}});
        }
    }
    return got ? static_cast<double>(valid) / static_cast<double>(got) : 0.0;
}

inline json vm_region_evidence(std::uint32_t pid, std::uint64_t va)
{
    if (va == 0)
        return json{{"queried", false}, {"reason", "zero_address"}};
    if (is_kernel_address(va))
        return json{{"queried", false}, {"reason", "kernel_address"}};
    driver_bridge::memory_region_t region{};
    if (!driver_bridge::query_memory_for(pid, va, region))
        return json{{"queried", false}, {"reason", "query_failed"}, {"status", driver_bridge::status()}, {"last_error", driver_bridge::last_error()}};
    return json{{"queried", true},
                {"base", sa_format_address(region.base)},
                {"size", region.size},
                {"state", sa_format_address(region.state)},
                {"protect", protection_name(region.protect)},
                {"protect_raw", sa_format_address(region.protect)},
                {"type", sa_format_address(region.type)},
                {"executable", executable_protect(region.protect)}};
}

inline std::uint64_t candidate_table_from_instruction(const AsmInstr& ins)
{
    if (!ins.has_mem_op || !ins.mem_op.has_disp)
        return 0;
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP))
        return ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)) + static_cast<std::uint64_t>(ins.mem_op.disp);
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE) && ins.mem_op.index_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE))
        return static_cast<std::uint64_t>(ins.mem_op.disp);
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE) && ins.mem_op.has_disp)
        return static_cast<std::uint64_t>(ins.mem_op.disp);
    return 0;
}

inline std::string zydis_reg_name(std::uint16_t reg)
{
    if (reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE))
        return {};
    const char* name = ZydisRegisterGetString(static_cast<ZydisRegister>(reg));
    return name ? lower_ascii(name) : std::string();
}

inline bool instruction_is_indirect_transfer(const AsmInstr& ins)
{
    const std::string m = mnemonic_of(ins);
    if (m != "jmp" && m != "call")
        return false;
    return ins.branch_target == 0 || operand_is_memory(ins.ops) || lower_ascii(ins.ops).find(" ptr ") != std::string::npos;
}

inline bool mnemonic_writes_flags(const std::string& m)
{
    static const std::unordered_set<std::string> flag_ops = {
        "add","adc","sub","sbb","cmp","test","xor","and","or","neg","inc","dec","shl","shr","sar","sal","rol","ror","imul","mul"
    };
    return flag_ops.count(m) != 0;
}

inline std::string condition_from_branch(const std::string& mnemonic)
{
    const std::string m = lower_ascii(mnemonic);
    if (m == "je" || m == "jz") return "ZF == 1";
    if (m == "jne" || m == "jnz") return "ZF == 0";
    if (m == "ja" || m == "jnbe") return "CF == 0 && ZF == 0";
    if (m == "jae" || m == "jnb" || m == "jnc") return "CF == 0";
    if (m == "jb" || m == "jc" || m == "jnae") return "CF == 1";
    if (m == "jbe" || m == "jna") return "CF == 1 || ZF == 1";
    if (m == "jg" || m == "jnle") return "ZF == 0 && SF == OF";
    if (m == "jge" || m == "jnl") return "SF == OF";
    if (m == "jl" || m == "jnge") return "SF != OF";
    if (m == "jle" || m == "jng") return "ZF == 1 || SF != OF";
    if (m == "js") return "SF == 1";
    if (m == "jns") return "SF == 0";
    if (m == "jo") return "OF == 1";
    if (m == "jno") return "OF == 0";
    if (m == "jp" || m == "jpe") return "PF == 1";
    if (m == "jnp" || m == "jpo") return "PF == 0";
    return {};
}

inline std::uint64_t trace_reg_value(const emulation::trace_entry_t& t, const std::string& reg)
{
    const std::string r = lower_ascii(reg);
    if (r == "rax" || r == "eax" || r == "ax" || r == "al") return t.rax;
    if (r == "rbx" || r == "ebx" || r == "bx" || r == "bl") return t.rbx;
    if (r == "rcx" || r == "ecx" || r == "cx" || r == "cl") return t.rcx;
    if (r == "rdx" || r == "edx" || r == "dx" || r == "dl") return t.rdx;
    if (r == "rsi" || r == "esi" || r == "si" || r == "sil") return t.rsi;
    if (r == "rdi" || r == "edi" || r == "di" || r == "dil") return t.rdi;
    if (r == "rbp" || r == "ebp" || r == "bp" || r == "bpl") return t.rbp;
    if (r == "rsp" || r == "esp" || r == "sp" || r == "spl") return t.rsp;
    if (r == "r8" || r == "r8d" || r == "r8w" || r == "r8b") return t.r8;
    if (r == "r9" || r == "r9d" || r == "r9w" || r == "r9b") return t.r9;
    if (r == "r10" || r == "r10d" || r == "r10w" || r == "r10b") return t.r10;
    if (r == "r11" || r == "r11d" || r == "r11w" || r == "r11b") return t.r11;
    if (r == "r12" || r == "r12d" || r == "r12w" || r == "r12b") return t.r12;
    if (r == "r13" || r == "r13d" || r == "r13w" || r == "r13b") return t.r13;
    if (r == "r14" || r == "r14d" || r == "r14w" || r == "r14b") return t.r14;
    if (r == "r15" || r == "r15d" || r == "r15w" || r == "r15b") return t.r15;
    if (r == "rip") return t.rip;
    if (r == "rflags" || r == "eflags") return t.rflags;
    return 0;
}

inline json trace_register_delta_json(const emulation::trace_entry_t& before, const emulation::trace_entry_t& after)
{
    json deltas = json::array();
    static const std::array<const char*, 17> regs = {
        "RAX","RBX","RCX","RDX","RSI","RDI","RBP","RSP","R8","R9","R10","R11","R12","R13","R14","R15","RFLAGS"
    };
    for (const char* reg : regs) {
        const std::uint64_t a = trace_reg_value(before, reg);
        const std::uint64_t b = trace_reg_value(after, reg);
        if (a != b)
            deltas.push_back(json{{"register", reg}, {"before", sa_format_address(a)}, {"after", sa_format_address(b)}});
    }
    return deltas;
}

inline std::set<std::uint64_t> trace_addresses_between(const std::vector<emulation::trace_entry_t>& trace, std::size_t begin, std::size_t end)
{
    std::set<std::uint64_t> addrs;
    if (trace.empty() || begin >= trace.size())
        return addrs;
    end = std::min<std::size_t>(end, trace.size() - 1);
    for (std::size_t i = begin; i <= end; ++i)
        addrs.insert(trace[i].address);
    return addrs;
}

inline json trace_reads_json(std::uint32_t pid, const std::vector<emulation::mem_read_t>& reads, const std::set<std::uint64_t>& insn_addrs, std::size_t limit)
{
    json out = json::array();
    for (const auto& r : reads) {
        if (!insn_addrs.count(r.insn_address))
            continue;
        json j{{"address", sa_format_address(r.address)}, {"size", r.size}, {"from_insn", sa_format_address(r.insn_address)}};
        if (r.size > 0 && r.size <= 8) {
            std::vector<std::uint8_t> bytes;
            if (read_target_memory(pid, r.address, static_cast<std::size_t>(r.size), bytes) && !bytes.empty()) {
                std::uint64_t value = 0;
                std::memcpy(&value, bytes.data(), std::min<std::size_t>(bytes.size(), sizeof(value)));
                j["value"] = sa_format_address(value);
                j["hex"] = bytes_to_hex(bytes, 16);
            }
        }
        out.push_back(std::move(j));
        if (out.size() >= limit)
            break;
    }
    return out;
}

inline json trace_writes_json(const std::vector<emulation::mem_write_t>& writes, const std::set<std::uint64_t>& insn_addrs, std::size_t limit)
{
    json out = json::array();
    for (const auto& w : writes) {
        if (!insn_addrs.count(w.insn_address))
            continue;
        out.push_back(json{{"address", sa_format_address(w.address)}, {"size", w.size}, {"from_insn", sa_format_address(w.insn_address)}, {"hex", bytes_to_hex(w.data, 16)}});
        if (out.size() >= limit)
            break;
    }
    return out;
}

struct vm_table_scan_result_t {
    bool read_ok = false;
    std::uint32_t entries_read = 0;
    std::uint32_t valid = 0;
    std::uint32_t nulls = 0;
    std::uint32_t entry_size = 8;
    double density = 0.0;
    json sample = json::array();
    std::vector<std::uint64_t> handlers;
};

inline vm_table_scan_result_t scan_vm_handler_table(std::uint32_t pid, std::uint64_t table, std::uint32_t count, std::uint32_t entry_size, bool relative, std::uint64_t image_base, std::size_t sample_limit)
{
    vm_table_scan_result_t result;
    result.entry_size = std::clamp<std::uint32_t>(entry_size, 1, 8);
    count = std::clamp<std::uint32_t>(count, 1, 4096);
    if (table == 0)
        return result;
    std::vector<std::uint8_t> bytes;
    result.read_ok = read_target_memory(pid, table, static_cast<std::size_t>(count) * result.entry_size, bytes);
    if (!result.read_ok || bytes.size() < result.entry_size)
        return result;
    result.entries_read = static_cast<std::uint32_t>(bytes.size() / result.entry_size);
    result.handlers.resize(result.entries_read);
    for (std::uint32_t i = 0; i < result.entries_read; ++i) {
        std::uint64_t raw = 0;
        std::memcpy(&raw, bytes.data() + static_cast<std::size_t>(i) * result.entry_size, result.entry_size);
        if (result.entry_size == 4)
            raw = static_cast<std::uint64_t>(static_cast<std::int32_t>(raw & 0xFFFFFFFFULL));
        std::uint64_t handler = relative ? image_base + raw : raw;
        result.handlers[i] = handler;
        if (handler == 0 || handler < 0x10000) {
            ++result.nulls;
            continue;
        }
        if (pointer_looks_executable(pid, handler)) {
            ++result.valid;
            if (result.sample.size() < sample_limit)
                result.sample.push_back(json{{"index", i}, {"raw_value", sa_format_address(raw)}, {"handler_va", sa_format_address(handler)}});
        }
    }
    result.density = result.entries_read ? static_cast<double>(result.valid) / static_cast<double>(result.entries_read) : 0.0;
    return result;
}

inline json register_score_array(const std::map<std::string, double>& scores, std::size_t limit)
{
    std::vector<std::pair<std::string, double>> items(scores.begin(), scores.end());
    std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) {
        if (a.second == b.second)
            return a.first < b.first;
        return a.second > b.second;
    });
    json out = json::array();
    for (const auto& item : items) {
        if (item.second <= 0.0)
            continue;
        out.push_back(json{{"register", item.first}, {"score", item.second}});
        if (out.size() >= limit)
            break;
    }
    return out;
}

inline json register_score_array_int(const std::map<std::string, int>& scores, std::size_t limit)
{
    std::map<std::string, double> converted;
    for (const auto& item : scores)
        converted[item.first] = static_cast<double>(item.second);
    return register_score_array(converted, limit);
}

inline std::string most_likely_vm_register(const std::vector<AsmInstr>& insns, const std::vector<const char*>& candidates)
{
    std::map<std::string, int> counts;
    for (const auto& ins : insns) {
        const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
        for (const char* c : candidates) {
            const std::string r(c);
            if (text.find(r) != std::string::npos)
                counts[r]++;
        }
    }
    std::string best = "unknown";
    int score = 0;
    for (const auto& it : counts) {
        if (it.second > score) {
            best = it.first;
            score = it.second;
        }
    }
    return best;
}

inline json classify_handler_static(std::uint32_t pid, std::uint64_t handler, std::uint32_t size, std::uint32_t num_inputs)
{
    size = std::clamp<std::uint32_t>(size, 1, 4096);
    const std::uint32_t read_size = std::clamp<std::uint32_t>(std::max<std::uint32_t>(size, 16), 16, 4096);
    auto insns = disassemble_target(pid, handler, size, 256);
    std::map<std::string, int> mcounts;
    std::map<std::string, int> written_reg_counts;
    std::map<std::string, int> read_reg_counts;
    bool branch = false;
    bool flags = false;
    bool mem_read = false;
    bool mem_write = false;
    bool self_zero = false;
    bool terminal_only = true;
    std::string primary_mnemonic;
    json evidence = json::array();
    for (const auto& ins : insns) {
        const std::string m = mnemonic_of(ins);
        ++mcounts[m];
        if (ins.is_branch || ins.is_call || ins.is_ret)
            branch = true;
        else
            terminal_only = false;
        if (mnemonic_writes_flags(m))
            flags = true;
        const std::string dir = classify_memory_direction(ins);
        if (dir == "read")
            mem_read = true;
        if (dir == "write")
            mem_write = true;
        auto ops = split_operands(ins.ops);
        if (!ops.empty() && !ins.is_branch && !ins.is_call && !ins.is_ret) {
            const std::string dst = reg_from_operand(ops[0]);
            if (!dst.empty())
                written_reg_counts[dst]++;
            for (std::size_t i = 1; i < ops.size(); ++i) {
                const std::string src = reg_from_operand(ops[i]);
                if (!src.empty())
                    read_reg_counts[src]++;
            }
            if (primary_mnemonic.empty())
                primary_mnemonic = m;
            if ((m == "xor" || m == "sub") && ops.size() >= 2 && lower_ascii(ops[0]) == lower_ascii(ops[1]))
                self_zero = true;
        }
    }
    auto count = [&](const char* m) { auto it = mcounts.find(m); return it == mcounts.end() ? 0 : it->second; };
    std::string semantic = "UNKNOWN";
    std::string normalized_semantic;
    double confidence = 0.25;
    if (self_zero && count("xor") > 0) { semantic = "XOR"; normalized_semantic = "CONST_ZERO"; confidence = 0.78; }
    else if (self_zero && count("sub") > 0) { semantic = "SUB"; normalized_semantic = "CONST_ZERO"; confidence = 0.76; }
    else if (mem_write && count("mov") > 0) { semantic = "STORE"; confidence = 0.7; }
    else if (mem_read && count("mov") > 0) { semantic = "LOAD"; confidence = 0.7; }
    else if (branch && (count("cmp") > 0 || count("test") > 0)) { semantic = "JCC"; confidence = 0.72; }
    else if (count("call") > 0) { semantic = "CALL"; confidence = 0.74; }
    else if (terminal_only && count("ret") > 0) { semantic = "RET"; confidence = 0.82; }
    else if (count("push") > count("pop")) { semantic = "PUSH"; confidence = 0.64; }
    else if (count("pop") > count("push")) { semantic = "POP"; confidence = 0.64; }
    else if (count("add") > 0 || count("adc") > 0 || count("lea") > 1) { semantic = "ADD"; confidence = 0.66; }
    else if (count("sub") > 0 || count("sbb") > 0) { semantic = "SUB"; confidence = 0.66; }
    else if (count("imul") > 0 || count("mul") > 0) { semantic = "MUL"; confidence = 0.7; }
    else if (count("xor") > 0) { semantic = "XOR"; confidence = 0.66; }
    else if (count("and") > 0) { semantic = "AND"; confidence = 0.66; }
    else if (count("or") > 0) { semantic = "OR"; confidence = 0.66; }
    else if (count("not") > 0) { semantic = "NOT"; confidence = 0.66; }
    else if (count("shl") > 0 || count("sal") > 0) { semantic = "SHL"; confidence = 0.66; }
    else if (count("shr") > 0 || count("sar") > 0) { semantic = "SHR"; confidence = 0.66; }
    else if (count("mov") > 0 || count("cmovz") > 0 || count("cmovnz") > 0) { semantic = "MOV"; confidence = 0.58; }

    if (!insns.empty()) {
        for (std::size_t i = 0; i < insns.size() && i < 16; ++i)
            evidence.push_back(instruction_to_json(insns[i]));
    }

    json roles;
    if (!insns.empty()) {
        for (const auto& ins : insns) {
            if (ins.is_branch || ins.is_call || ins.is_ret)
                continue;
            auto ops = split_operands(ins.ops);
            if (ops.size() >= 1 && !roles.contains("dst"))
                roles["dst"] = ops[0];
            if (ops.size() >= 2 && !roles.contains("src1"))
                roles["src1"] = ops[1];
            if (ops.size() >= 3 && !roles.contains("src2"))
                roles["src2"] = ops[2];
            if (roles.contains("dst") && roles.contains("src1"))
                break;
        }
    }

    json differential = json::array();
    json differential_summary;
    std::uint32_t successful_inputs = 0;
    std::uint32_t flags_changed_inputs = 0;
    std::uint64_t total_reads = 0;
    std::uint64_t total_writes = 0;
    std::set<std::uint64_t> unique_ends;
    std::set<std::string> changed_regs;
#ifdef __NT__
    if (!insns.empty() && num_inputs > 0) {
        std::vector<std::uint8_t> code;
        if (read_target_memory(pid, handler, read_size, code) && !code.empty()) {
            const std::uint32_t traces = std::min<std::uint32_t>(num_inputs, 8);
            for (std::uint32_t i = 0; i < traces; ++i) {
                emulation::process_snapshot_t snap;
                snap.success = true;
                snap.rip = handler;
                snap.rflags = 0x202;
                snap.rax = 0x1111000011110000ULL ^ (0x101010101010101ULL * (i + 1));
                snap.rbx = 0x2222000022220000ULL ^ (0x0101010101010101ULL * (i + 3));
                snap.rcx = 0x3333000033330000ULL ^ (0x1111111111111111ULL * (i + 5));
                snap.rdx = 0x4444000044440000ULL ^ (0x0102030405060708ULL * (i + 7));
                snap.rsi = 0x5555000055550000ULL + i * 0x101;
                snap.rdi = 0x6666000066660000ULL + i * 0x203;
                snap.r8 = 0x7777000077770000ULL + i * 0x307;
                snap.r9 = 0x8888000088880000ULL + i * 0x409;
                emulation::memory_snapshot_region_t code_region;
                code_region.base = handler & ~0xFFFULL;
                code_region.size = (static_cast<std::uint64_t>(code.size()) + 0xFFF + (handler & 0xFFFULL)) & ~0xFFFULL;
                code_region.data.resize(static_cast<std::size_t>(code_region.size));
                std::memcpy(code_region.data.data() + (handler - code_region.base), code.data(), code.size());
                snap.regions.push_back(std::move(code_region));
                emulation::memory_snapshot_region_t stack_region;
                stack_region.base = 0x7FF700000000ULL + static_cast<std::uint64_t>(i) * 0x20000ULL;
                stack_region.size = 0x20000;
                stack_region.data.resize(static_cast<std::size_t>(stack_region.size));
                snap.rsp = stack_region.base + stack_region.size - 0x1000;
                snap.regions.push_back(std::move(stack_region));
                emulation::emulation_config_t cfg;
                cfg.start_address = handler;
                cfg.max_instructions = 512;
                cfg.max_trace_entries = 32;
                cfg.record_mem_reads = true;
                cfg.record_mem_writes = true;
                cfg.record_registers = true;
                cfg.timeout_us = 1000000;
                auto r = emulation::emulate_from_snapshot(snap, cfg);
                if (r.success)
                    ++successful_inputs;
                unique_ends.insert(r.end_address);
                total_reads += r.mem_reads.size();
                total_writes += r.mem_writes.size();
                json regs = json::array();
                for (const auto& d : r.reg_deltas) {
                    changed_regs.insert(d.name);
                    if (d.name == "RFLAGS")
                        ++flags_changed_inputs;
                    regs.push_back(json{{"register", d.name}, {"before", sa_format_address(d.before)}, {"after", sa_format_address(d.after)}});
                }
                json reads = json::array();
                for (std::size_t ri = 0; ri < r.mem_reads.size() && ri < 8; ++ri)
                    reads.push_back(json{{"address", sa_format_address(r.mem_reads[ri].address)}, {"size", r.mem_reads[ri].size}, {"from_insn", sa_format_address(r.mem_reads[ri].insn_address)}});
                json writes = json::array();
                for (std::size_t wi = 0; wi < r.mem_writes.size() && wi < 8; ++wi)
                    writes.push_back(json{{"address", sa_format_address(r.mem_writes[wi].address)}, {"size", r.mem_writes[wi].size}, {"from_insn", sa_format_address(r.mem_writes[wi].insn_address)}, {"hex", bytes_to_hex(r.mem_writes[wi].data, 16)}});
                differential.push_back(json{{"input_index", i}, {"success", r.success}, {"error", r.error}, {"instructions", r.total_instructions}, {"end_address", sa_format_address(r.end_address)}, {"hit_ret", r.hit_ret}, {"reads", reads}, {"writes", writes}, {"register_deltas", regs}});
            }
            if (!differential.empty()) {
                confidence = std::min(0.95, confidence + 0.08 + (successful_inputs == traces ? 0.04 : 0.0));
                if (total_writes > 0 && semantic == "UNKNOWN") {
                    semantic = "STORE";
                    confidence = std::max(confidence, 0.66);
                } else if (total_reads > 0 && semantic == "UNKNOWN") {
                    semantic = "LOAD";
                    confidence = std::max(confidence, 0.62);
                }
                if (unique_ends.size() > 1 && branch) {
                    semantic = "JCC";
                    confidence = std::max(confidence, 0.78);
                }
                if (flags_changed_inputs > 0)
                    flags = true;
            }
        }
    }
#else
    (void)num_inputs;
#endif
    json changed = json::array();
    for (const auto& r : changed_regs)
        changed.push_back(r);
    json ends = json::array();
    for (const auto e : unique_ends)
        ends.push_back(sa_format_address(e));
    differential_summary["inputs_run"] = differential.size();
    differential_summary["successful_inputs"] = successful_inputs;
    differential_summary["unique_end_addresses"] = ends;
    differential_summary["changed_registers"] = changed;
    differential_summary["total_memory_reads"] = total_reads;
    differential_summary["total_memory_writes"] = total_writes;
    differential_summary["flags_changed_inputs"] = flags_changed_inputs;

    json out;
    out["handler_va"] = sa_format_address(handler);
    out["semantic"] = semantic;
    if (!normalized_semantic.empty())
        out["normalized_semantic"] = normalized_semantic;
    out["operand_roles"] = roles;
    out["affects_flags"] = flags;
    out["is_branch"] = branch;
    out["confidence"] = confidence;
    out["instruction_count"] = insns.size();
    out["evidence"] = evidence;
    out["static_features"] = json{{"primary_mnemonic", primary_mnemonic}, {"memory_read", mem_read}, {"memory_write", mem_write}, {"terminal_only", terminal_only}, {"self_zero", self_zero}, {"written_register_scores", register_score_array_int(written_reg_counts, 8)}, {"read_register_scores", register_score_array_int(read_reg_counts, 8)}};
    out["differential_summary"] = differential_summary;
    if (!differential.empty())
        out["differential_emulation"] = differential;
    return out;
}

inline std::string opcode_key_from_index(std::uint64_t index)
{
    char key[32] = {};
    std::snprintf(key, sizeof(key), "0x%02llX", static_cast<unsigned long long>(index));
    return std::string(key);
}

inline std::optional<std::uint64_t> parse_opcode_key(const std::string& opcode)
{
    std::string s = trim_ascii(opcode);
    if (s.empty() || s == "unknown" || s == "unresolved")
        return std::nullopt;
    if (s.size() > 1 && (s[0] == 'v' || s[0] == 'V'))
        s.erase(s.begin());
    return sa_parse_address(s);
}

inline const json& opcode_map_payload(const json& map)
{
    if (map.is_object() && map.contains("opcode_map") && map["opcode_map"].is_object())
        return map["opcode_map"];
    return map;
}

inline std::optional<std::uint64_t> json_field_address(const json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key))
        return std::nullopt;
    return parse_u64_json(obj[key]);
}

inline std::optional<std::uint64_t> opcode_entry_handler_va(const json& entry)
{
    if (!entry.is_object())
        return std::nullopt;
    if (auto v = json_field_address(entry, "handler_va"))
        return v;
    if (auto v = json_field_address(entry, "address"))
        return v;
    return std::nullopt;
}

inline const json* opcode_map_entry_by_opcode(const json& map_root, const std::string& opcode)
{
    const json& map = opcode_map_payload(map_root);
    if (!map.is_object())
        return nullptr;
    if (auto it = map.find(opcode); it != map.end() && it->is_object())
        return &(*it);
    const std::string lower = lower_ascii(opcode);
    if (auto it = map.find(lower); it != map.end() && it->is_object())
        return &(*it);
    if (auto numeric = parse_opcode_key(opcode)) {
        const std::string key = opcode_key_from_index(*numeric);
        if (auto it = map.find(key); it != map.end() && it->is_object())
            return &(*it);
        const std::string lower_key = lower_ascii(key);
        if (auto it = map.find(lower_key); it != map.end() && it->is_object())
            return &(*it);
    }
    return nullptr;
}

inline const json* opcode_map_entry_by_handler(const json& map_root, std::uint64_t handler)
{
    const json& map = opcode_map_payload(map_root);
    if (!map.is_object() || handler == 0)
        return nullptr;
    for (auto it = map.begin(); it != map.end(); ++it) {
        if (!it.value().is_object())
            continue;
        auto h = opcode_entry_handler_va(it.value());
        if (h && *h == handler)
            return &it.value();
    }
    return nullptr;
}

inline std::string opcode_key_by_handler(const json& map_root, std::uint64_t handler)
{
    const json& map = opcode_map_payload(map_root);
    if (!map.is_object() || handler == 0)
        return {};
    for (auto it = map.begin(); it != map.end(); ++it) {
        if (!it.value().is_object())
            continue;
        auto h = opcode_entry_handler_va(it.value());
        if (h && *h == handler) {
            if (it.value().contains("opcode") && it.value()["opcode"].is_string())
                return it.value()["opcode"].get<std::string>();
            return it.key();
        }
    }
    return {};
}

inline std::map<std::uint64_t, std::string> handler_opcode_lookup_from_params(std::uint32_t pid, const json& params)
{
    std::map<std::uint64_t, std::string> lookup;
    if (params.contains("opcode_map")) {
        const json& map = opcode_map_payload(params["opcode_map"]);
        if (map.is_object()) {
            for (auto it = map.begin(); it != map.end(); ++it) {
                if (!it.value().is_object())
                    continue;
                auto h = opcode_entry_handler_va(it.value());
                if (!h)
                    continue;
                std::string opcode = it.key();
                if (it.value().contains("opcode") && it.value()["opcode"].is_string())
                    opcode = it.value()["opcode"].get<std::string>();
                lookup[*h] = opcode;
            }
        }
    }
    auto table = parse_param_u64(params, "handler_table_va");
    if (table) {
        std::uint32_t count = static_cast<std::uint32_t>(parse_param_u64(params, "handler_count").value_or(256));
        count = std::clamp<std::uint32_t>(count, 1, 512);
        std::vector<std::uint8_t> bytes;
        if (read_target_memory(pid, *table, static_cast<std::size_t>(count) * sizeof(std::uint64_t), bytes)) {
            const std::uint32_t got = static_cast<std::uint32_t>(bytes.size() / sizeof(std::uint64_t));
            for (std::uint32_t i = 0; i < got; ++i) {
                std::uint64_t handler = 0;
                std::memcpy(&handler, bytes.data() + static_cast<std::size_t>(i) * sizeof(handler), sizeof(handler));
                if (pointer_looks_executable(pid, handler) && !lookup.count(handler))
                    lookup[handler] = opcode_key_from_index(i);
            }
        }
    }
    return lookup;
}

inline tool_result_t vm_identify(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto addr = parse_param_u64(params, "address");
    if (!addr)
        return tool_result_t::error("address is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t scan_size = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "size").value_or(0x4000)), 0x40, 0x20000);
    auto insns = disassemble_target(pid, *addr, scan_size, 8192);
    if (insns.empty())
        return tool_result_t::error("No code could be decoded at " + sa_format_address(*addr));
    std::uint64_t best_table = 0;
    double best_density = 0.0;
    json table_sample = json::array();
    json table_candidates = json::array();
    json dispatch_candidates = json::array();
    json bytecode_fetches = json::array();
    int indirect_dispatches = 0;
    int scaled_dispatches = 0;
    int bytecode_reads = 0;
    int vip_updates = 0;
    int arithmetic = 0;
    int stack_ops = 0;
    int rotate_ops = 0;
    int branch_ops = 0;
    std::uint64_t best_dispatch = 0;
    std::uint64_t bytecode_va = parse_param_u64(params, "bytecode_va").value_or(0);
    std::map<std::string, double> vip_scores;
    std::map<std::string, double> vsp_scores;
    json evidence = json::array();
    auto score_reg = [](std::map<std::string, double>& scores, const std::string& reg, double score) {
        if (!reg.empty() && reg != "rip" && reg != "rsp")
            scores[reg] += score;
    };
    const bool relative_table = params.value("relative", false);
    const std::uint64_t image_base = parse_param_u64(params, "image_base").value_or(0);
    const std::uint32_t entry_size = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(parse_param_u64(params, "entry_size").value_or(8), 1, 8));
    const std::uint32_t handler_count = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(parse_param_u64(params, "handler_count").value_or(256), 1, 4096));
    auto evaluate_table = [&](std::uint64_t cand, std::uint64_t dispatch_va, const char* source) {
        if (cand == 0)
            return;
        auto scan = scan_vm_handler_table(pid, cand, handler_count, entry_size, relative_table, image_base, 16);
        json tc{{"table_va", sa_format_address(cand)}, {"dispatch_va", sa_format_address(dispatch_va)}, {"source", source ? source : "unknown"}, {"read_ok", scan.read_ok}, {"entry_size", scan.entry_size}, {"entries_read", scan.entries_read}, {"valid_handlers", scan.valid}, {"null_entries", scan.nulls}, {"density", scan.density}, {"sample", scan.sample}};
        table_candidates.push_back(tc);
        if (scan.density > best_density) {
            best_density = scan.density;
            best_table = cand;
            table_sample = scan.sample;
            best_dispatch = dispatch_va;
        }
    };
    if (auto explicit_table = parse_param_u64(params, "handler_table_va"))
        evaluate_table(*explicit_table, *addr, "explicit_handler_table");
    for (std::size_t idx = 0; idx < insns.size(); ++idx) {
        const auto& ins = insns[idx];
        const std::string m = mnemonic_of(ins);
        if (ins.is_branch)
            ++branch_ops;
        if (m == "xor" || m == "add" || m == "sub" || m == "and" || m == "or")
            ++arithmetic;
        if (m == "rol" || m == "ror" || m == "shl" || m == "shr")
            ++rotate_ops;
        if (m == "push" || m == "pop" || m == "pushfq" || m == "popfq")
            ++stack_ops;
        auto ops = split_operands(ins.ops);
        if ((m == "inc" || m == "dec" || m == "add" || m == "sub" || m == "lea") && !ops.empty()) {
            const std::string dst = reg_from_operand(ops[0]);
            score_reg(vip_scores, dst, (m == "inc" || m == "add" || m == "lea") ? 1.8 : 0.8);
        }
        if (ins.has_mem_op) {
            const std::string base = zydis_reg_name(ins.mem_op.base_reg);
            const std::string index = zydis_reg_name(ins.mem_op.index_reg);
            const std::string dir = classify_memory_direction(ins);
            if (dir == "read" && (m == "movzx" || m == "movsx" || m == "movsxd" || m == "mov")) {
                ++bytecode_reads;
                score_reg(vip_scores, base, 3.0);
                score_reg(vip_scores, index, 2.0);
                std::uint64_t rip_va = 0;
                if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP))
                    rip_va = ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)) + static_cast<std::uint64_t>(ins.mem_op.disp);
                if (rip_va && bytecode_va == 0)
                    bytecode_va = rip_va;
                if (bytecode_fetches.size() < 32)
                    bytecode_fetches.push_back(json{{"va", sa_format_address(ins.addr)}, {"instruction", std::string(ins.mnem) + " " + ins.ops}, {"base_reg", base}, {"index_reg", index}, {"memory_va", rip_va ? sa_format_address(rip_va) : "dynamic"}, {"mem_size_bits", ins.mem_op.size}});
            }
            if (dir == "read" || dir == "write") {
                score_reg(vsp_scores, base, dir == "write" ? 1.6 : 1.0);
                score_reg(vsp_scores, index, 0.6);
            }
        }
        if (instruction_is_indirect_transfer(ins)) {
            ++indirect_dispatches;
            if (ins.has_mem_op && ins.mem_op.index_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE) && ins.mem_op.scale > 1)
                ++scaled_dispatches;
            std::uint64_t cand = candidate_table_from_instruction(ins);
            json dc = instruction_to_json(ins);
            dc["type"] = ins.has_mem_op && ins.mem_op.index_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE) && ins.mem_op.scale > 1 ? "scaled_table_dispatch" : "indirect_dispatch";
            dc["table_candidate"] = cand ? sa_format_address(cand) : "unknown";
            dc["index_reg"] = ins.has_mem_op ? zydis_reg_name(ins.mem_op.index_reg) : "";
            dc["base_reg"] = ins.has_mem_op ? zydis_reg_name(ins.mem_op.base_reg) : "";
            dc["scale"] = ins.has_mem_op ? ins.mem_op.scale : 0;
            dispatch_candidates.push_back(dc);
            if (evidence.size() < 64)
                evidence.push_back(instruction_to_json(ins));
            if (cand) {
                evaluate_table(cand, ins.addr, "indirect_dispatch_memory_operand");
            }
        }
        if ((m == "mov" || m == "lea") && ops.size() >= 2 && operand_is_memory(ops[1])) {
            const std::string dst = reg_from_operand(ops[0]);
            if (!dst.empty() && idx + 4 < insns.size()) {
                for (std::size_t j = idx + 1; j < insns.size() && j <= idx + 4; ++j) {
                    if (instruction_is_indirect_transfer(insns[j]) && lower_ascii(insns[j].ops).find(dst) != std::string::npos) {
                        ++vip_updates;
                        score_reg(vip_scores, dst, 2.5);
                    }
                }
            }
        }
    }
    double confidence = 0.15;
    if (indirect_dispatches > 0)
        confidence += 0.25;
    if (scaled_dispatches > 0)
        confidence += 0.18;
    if (best_density > 0.35)
        confidence += 0.35;
    if (bytecode_reads > 0)
        confidence += 0.12;
    if (vip_updates > 0)
        confidence += 0.08;
    if (arithmetic > 20)
        confidence += 0.1;
    if (rotate_ops > 4)
        confidence += 0.08;
    if (stack_ops > 8)
        confidence += 0.07;
    confidence = std::min(0.95, confidence);
    std::string name = confidence >= 0.65 ? "custom_vm" : "unknown";
    std::string version = "unknown";
    if (rotate_ops > 8 && stack_ops > 12) {
        name = "vmp_like";
        version = "2_or_3_family";
    } else if (branch_ops > 80 && best_density > 0.45) {
        name = "themida_or_code_virtualizer_like";
    }
    const json vip_rank = register_score_array(vip_scores, 8);
    const json vsp_rank = register_score_array(vsp_scores, 8);
    json out;
    out["name"] = name;
    out["version"] = version;
    out["confidence"] = confidence;
    out["dispatcher_va"] = best_dispatch ? sa_format_address(best_dispatch) : sa_format_address(*addr);
    out["dispatcher_candidates"] = dispatch_candidates;
    out["handler_table_va"] = best_table ? sa_format_address(best_table) : "unknown";
    out["handler_table_density"] = best_density;
    out["handler_table_sample"] = table_sample;
    out["handler_table_candidates"] = table_candidates;
    out["bytecode_va"] = bytecode_va ? sa_format_address(bytecode_va) : "unknown";
    out["bytecode_fetches"] = bytecode_fetches;
    out["vm_stack_reg"] = !vsp_rank.empty() ? vsp_rank[0].value("register", std::string("unknown")) : most_likely_vm_register(insns, {"rsp","rbp","rsi","rdi","rbx"});
    out["vip_reg"] = !vip_rank.empty() ? vip_rank[0].value("register", std::string("unknown")) : most_likely_vm_register(insns, {"rsi","rdi","rbx","rcx","rdx","r8","r9"});
    out["vip_candidates"] = vip_rank;
    out["vsp_candidates"] = vsp_rank;
    out["indirect_dispatches"] = indirect_dispatches;
    out["scaled_table_jumps"] = scaled_dispatches;
    out["memory_reads"] = bytecode_reads;
    out["dispatch_candidates"] = dispatch_candidates.size();
    out["dbg_style_evidence"] = json{{"indirect_jumps", indirect_dispatches}, {"scaled_table_jumps", scaled_dispatches}, {"memory_reads", bytecode_reads}, {"dispatch_candidates", dispatch_candidates.size()}};
    out["instruction_count"] = insns.size();
    out["evidence"] = evidence;
    return tool_result_t::ok("VM identification completed with evidence confidence " + std::to_string(confidence), out);
}

inline std::string infer_vm_semantic_from_trace_step(const json& step);
inline std::string condition_from_trace_step(const json& step);
inline std::optional<std::uint64_t> branch_target_from_trace_step(const json& step);

inline tool_result_t vm_trace_bytecode(const json& params)
{
    diag::log_tagged_fmt("protected_re", "vm_trace_bytecode handler_entry params=%s", params.dump().c_str());
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    if (mcp_standalone::current_call_cancelled())
        return tool_result_t::error("VM bytecode trace cancelled before parameter parsing");
    auto entry = parse_param_u64(params, "entry_va");
    if (!entry)
        entry = parse_param_u64(params, "address");
    if (!entry)
        return tool_result_t::error("entry_va is required");
    const std::uint32_t pid = requested_pid(params);
    bool allow_neutral_context = false;
    if (params.contains("allow_neutral_thread_context") && params["allow_neutral_thread_context"].is_boolean())
        allow_neutral_context = params["allow_neutral_thread_context"].get<bool>();
    if (params.contains("fixture_mode") && params["fixture_mode"].is_boolean() && params["fixture_mode"].get<bool>())
        allow_neutral_context = true;
    std::uint32_t tid = 0;
    if (auto t = parse_param_u64(params, "tid"))
        tid = static_cast<std::uint32_t>(*t);
    if (tid == 0 && !allow_neutral_context) {
        if (mcp_standalone::current_call_cancelled())
            return tool_result_t::error("VM bytecode trace cancelled before thread enumeration");
        diag::log_tagged_fmt("protected_re",
            "vm_trace_bytecode thread_enum_begin pid=%u active_pid=%u",
            pid,
            driver_bridge::attached_pid());
        auto threads = enumerate_target_threads(pid);
        diag::log_tagged_fmt("protected_re",
            "vm_trace_bytecode thread_enum_end pid=%u count=%zu",
            pid,
            threads.size());
        if (!threads.empty())
            tid = threads.front().tid;
    }
    if (pid == 0 || (tid == 0 && !allow_neutral_context))
        return tool_result_t::error("An attached process and a target thread are required for snapshot tracing");
    std::uint32_t max_steps = static_cast<std::uint32_t>(parse_param_u64(params, "max_steps").value_or(50000));
    max_steps = std::clamp<std::uint32_t>(max_steps, 1, 100000);
    const std::uint32_t return_limit = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "max_returned_steps").value_or(1024)), 1, 4096);
#ifdef __NT__
    const std::uint64_t trace_started_ms = static_cast<std::uint64_t>(GetTickCount64());
    const std::uint64_t tool_deadline_ms = mcp_standalone::current_call_deadline_ms();
    auto deadline_remaining_ms = [&]() -> std::uint64_t {
        if (tool_deadline_ms == 0)
            return 0;
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        return now < tool_deadline_ms ? tool_deadline_ms - now : 0;
    };
    auto trace_cancelled = [&](const char* phase) -> bool {
        const bool cancelled = mcp_standalone::current_call_cancelled();
        const std::uint64_t now = static_cast<std::uint64_t>(GetTickCount64());
        const bool expired = tool_deadline_ms != 0 && now >= tool_deadline_ms;
        if (cancelled || expired) {
            diag::log_tagged_fmt("protected_re",
                "vm_trace_bytecode deadline_cancel phase=%s diag_id=%s cancelled=%d expired=%d elapsed_ms=%llu deadline_ms=%llu remaining_ms=%llu",
                phase ? phase : "<null>",
                mcp_standalone::current_call_diag_id(),
                cancelled ? 1 : 0,
                expired ? 1 : 0,
                static_cast<unsigned long long>(now - trace_started_ms),
                static_cast<unsigned long long>(tool_deadline_ms),
                static_cast<unsigned long long>(deadline_remaining_ms()));
            return true;
        }
        return false;
    };
    auto cancelled_result = [&](const char* phase, const std::string& message) -> tool_result_t {
        json out;
        out["phase"] = phase ? phase : "";
        out["diag_id"] = mcp_standalone::current_call_diag_id();
        out["pid"] = pid;
        out["tid"] = tid;
        out["entry_va"] = sa_format_address(*entry);
        out["elapsed_ms"] = static_cast<std::uint64_t>(GetTickCount64()) - trace_started_ms;
        out["deadline_ms"] = tool_deadline_ms;
        out["deadline_remaining_ms"] = deadline_remaining_ms();
        out["cancelled"] = mcp_standalone::current_call_cancelled();
        return tool_result_t::error(message, out);
    };
    if (trace_cancelled("before_region_evidence"))
        return cancelled_result("before_region_evidence", "VM bytecode trace cancelled before region evidence");
    diag::log_tagged_fmt("protected_re",
        "vm_trace_bytecode region_evidence_begin pid=%u entry=0x%llX diag_id=%s deadline_remaining_ms=%llu",
        pid,
        static_cast<unsigned long long>(*entry),
        mcp_standalone::current_call_diag_id(),
        static_cast<unsigned long long>(deadline_remaining_ms()));
    const json entry_region = vm_region_evidence(pid, *entry);
    diag::log_tagged_fmt("protected_re",
        "vm_trace_bytecode region_evidence_end pid=%u entry=0x%llX elapsed_ms=%llu deadline_remaining_ms=%llu region=%s",
        pid,
        static_cast<unsigned long long>(*entry),
        static_cast<unsigned long long>(static_cast<std::uint64_t>(GetTickCount64()) - trace_started_ms),
        static_cast<unsigned long long>(deadline_remaining_ms()),
        entry_region.dump().c_str());
    if (trace_cancelled("after_region_evidence"))
        return cancelled_result("after_region_evidence", "VM bytecode trace cancelled after region evidence");
    const std::uint64_t snapshot_base = parse_param_u64(params, "snapshot_base").value_or(*entry & ~0xFFFULL);
    const std::uint64_t snapshot_size = std::clamp<std::uint64_t>(parse_param_u64(params, "snapshot_size").value_or(0x40000ULL), 0x1000ULL, 0x400000ULL);
    diag::log_tagged_fmt("protected_re",
        "vm_trace_bytecode entry pid=%u tid=%u neutral=%d entry=0x%llX snapshot_base=0x%llX snapshot_size=0x%llX active_pid=%u max_steps=%u return_limit=%u entry_region=%s bridge_status='%s' bridge_last_error='%s'",
        pid,
        tid,
        allow_neutral_context ? 1 : 0,
        static_cast<unsigned long long>(*entry),
        static_cast<unsigned long long>(snapshot_base),
        static_cast<unsigned long long>(snapshot_size),
        driver_bridge::attached_pid(),
        max_steps,
        return_limit,
        entry_region.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    emulation::emulation_config_t cfg;
    cfg.start_address = *entry;
    cfg.max_instructions = max_steps;
    cfg.max_trace_entries = max_steps;
    cfg.record_mem_reads = true;
    cfg.record_mem_writes = true;
    cfg.record_registers = true;
    cfg.analyze_effective_ops = true;
    cfg.timeout_us = std::min<std::uint64_t>(parse_param_u64(params, "timeout_us").value_or(15000000), 60000000);
    cfg.deadline_ms = static_cast<std::uint64_t>(GetTickCount64()) + std::max<std::uint64_t>(1000, cfg.timeout_us / 1000 + 1000);
    if (tool_deadline_ms != 0 && (cfg.deadline_ms == 0 || tool_deadline_ms < cfg.deadline_ms))
        cfg.deadline_ms = tool_deadline_ms;
    cfg.allow_neutral_thread_context = allow_neutral_context;
    cfg.max_invalid_page_maps = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(parse_param_u64(params, "max_invalid_page_maps").value_or(32), 0, 4096));
    if (trace_cancelled("before_snapshot_emulate"))
        return cancelled_result("before_snapshot_emulate", "VM bytecode trace cancelled before snapshot emulation");
    diag::log_tagged_fmt("protected_re",
        "vm_trace_bytecode snapshot_emulate_begin pid=%u tid=%u diag_id=%s deadline_ms=%llu timeout_us=%llu invalid_cap=%u deadline_remaining_ms=%llu",
        pid,
        tid,
        mcp_standalone::current_call_diag_id(),
        static_cast<unsigned long long>(cfg.deadline_ms),
        static_cast<unsigned long long>(cfg.timeout_us),
        cfg.max_invalid_page_maps,
        static_cast<unsigned long long>(deadline_remaining_ms()));
    auto r = emulation::driver_snapshot_and_emulate(pid, tid, cfg, snapshot_base, snapshot_size);
    diag::log_tagged_fmt("protected_re",
        "vm_trace_bytecode emulation_exit pid=%u tid=%u entry=0x%llX success=%d error='%s' total=%u trace=%zu reads=%zu writes=%zu reg_deltas=%zu hit_ret=%d hit_breakpoint=%d elapsed_ms=%llu deadline_remaining_ms=%llu",
        pid,
        tid,
        static_cast<unsigned long long>(*entry),
        r.success ? 1 : 0,
        r.error.c_str(),
        r.total_instructions,
        r.trace.size(),
        r.mem_reads.size(),
        r.mem_writes.size(),
        r.reg_deltas.size(),
        r.hit_ret ? 1 : 0,
        r.hit_breakpoint ? 1 : 0,
        static_cast<unsigned long long>(static_cast<std::uint64_t>(GetTickCount64()) - trace_started_ms),
        static_cast<unsigned long long>(deadline_remaining_ms()));
    if (trace_cancelled("after_snapshot_emulate")) {
        json out;
        out["entry_va"] = sa_format_address(*entry);
        out["pid"] = pid;
        out["tid"] = tid;
        out["success"] = false;
        out["error"] = r.error.empty() ? "deadline or cancellation after snapshot emulation" : r.error;
        out["emulated_instructions"] = r.total_instructions;
        out["trace_entries"] = r.trace.size();
        out["mem_reads"] = r.mem_reads.size();
        out["mem_writes"] = r.mem_writes.size();
        out["diag_id"] = mcp_standalone::current_call_diag_id();
        out["elapsed_ms"] = static_cast<std::uint64_t>(GetTickCount64()) - trace_started_ms;
        out["deadline_ms"] = tool_deadline_ms;
        out["deadline_remaining_ms"] = deadline_remaining_ms();
        out["cancelled"] = mcp_standalone::current_call_cancelled();
        return tool_result_t::error("VM bytecode trace cancelled after snapshot emulation", out);
    }
    const auto handler_lookup = handler_opcode_lookup_from_params(pid, params);
    const json opcode_map = params.contains("opcode_map") ? params["opcode_map"] : json::object();
    json steps = json::array();
    std::vector<std::size_t> dispatch_indices;
    for (std::size_t i = 0; i + 1 < r.trace.size(); ++i) {
        const auto& cur = r.trace[i];
        const auto& next = r.trace[i + 1];
        const std::string d = lower_ascii(cur.disasm);
        const bool transfer = (d.find("jmp") == 0 || d.find("call") == 0) && (d.find('[') != std::string::npos || next.address != cur.address + std::max<std::uint32_t>(cur.insn_size, 1));
        const bool next_known_handler = handler_lookup.find(next.address) != handler_lookup.end() || opcode_map_entry_by_handler(opcode_map, next.address) != nullptr;
        if (transfer || next_known_handler)
            dispatch_indices.push_back(i);
    }
    if (dispatch_indices.empty() && !r.trace.empty())
        dispatch_indices.push_back(0);
    const std::uint64_t bytecode_va = parse_param_u64(params, "bytecode_va").value_or(0);
    const std::uint64_t bytecode_size = parse_param_u64(params, "bytecode_size").value_or(0);
    auto read_opcode_from_side_effects = [&](const std::set<std::uint64_t>& insn_addrs) -> std::optional<std::uint64_t> {
        if (bytecode_va == 0)
            return std::nullopt;
        for (const auto& rd : r.mem_reads) {
            if (!insn_addrs.count(rd.insn_address) || rd.size == 0 || rd.size > 8)
                continue;
            if (rd.address < bytecode_va)
                continue;
            if (bytecode_size != 0 && rd.address + rd.size > bytecode_va + bytecode_size)
                continue;
            std::vector<std::uint8_t> bytes;
            if (!read_target_memory(pid, rd.address, static_cast<std::size_t>(rd.size), bytes) || bytes.empty())
                continue;
            std::uint64_t value = 0;
            std::memcpy(&value, bytes.data(), std::min<std::size_t>(bytes.size(), sizeof(value)));
            return value;
        }
        return std::nullopt;
    };
    for (std::size_t di = 0; di < dispatch_indices.size() && steps.size() < return_limit; ++di) {
        const std::size_t dispatch_index = dispatch_indices[di];
        const std::size_t handler_index = dispatch_index + 1 < r.trace.size() ? dispatch_index + 1 : dispatch_index;
        const std::size_t next_dispatch_index = di + 1 < dispatch_indices.size() ? dispatch_indices[di + 1] : r.trace.size();
        const std::size_t end_index = next_dispatch_index > handler_index ? std::min<std::size_t>(next_dispatch_index - 1, r.trace.size() - 1) : handler_index;
        const auto& cur = r.trace[dispatch_index];
        const auto& first = r.trace[handler_index];
        const auto& last = r.trace[end_index];
        const auto insn_addrs = trace_addresses_between(r.trace, handler_index, end_index);
        json side_effects;
        side_effects["reads"] = trace_reads_json(pid, r.mem_reads, insn_addrs, 16);
        side_effects["writes"] = trace_writes_json(r.mem_writes, insn_addrs, 16);
        side_effects["register_deltas"] = trace_register_delta_json(first, last);
        side_effects["flags_before"] = sa_format_address(first.rflags);
        side_effects["flags_after"] = sa_format_address(last.rflags);
        side_effects["flags_changed"] = first.rflags != last.rflags;
        json effective_ops = json::array();
        for (std::size_t ti = handler_index; ti <= end_index && ti < r.trace.size(); ++ti) {
            effective_ops.push_back(json{{"va", sa_format_address(r.trace[ti].address)}, {"disasm", r.trace[ti].disasm}});
            if (effective_ops.size() >= 32)
                break;
        }
        side_effects["native_ops"] = effective_ops;
        json st;
        st["step"] = steps.size();
        st["handler_va"] = sa_format_address(first.address);
        st["dispatch_va"] = sa_format_address(cur.address);
        st["dispatch_disasm"] = cur.disasm;
        st["native_start_va"] = sa_format_address(first.address);
        st["native_end_va"] = sa_format_address(last.address);
        st["native_instruction_count"] = end_index >= handler_index ? (end_index - handler_index + 1) : 1;
        st["side_effects"] = std::move(side_effects);
        bool flags_affected = first.rflags != last.rflags;
        for (std::size_t ti = handler_index; ti <= end_index && ti < r.trace.size(); ++ti) {
            const std::string text = lower_ascii(r.trace[ti].disasm);
            const std::string mnemonic = text.substr(0, text.find(' '));
            if (mnemonic_writes_flags(mnemonic)) {
                flags_affected = true;
                break;
            }
        }
        st["flags_affected"] = flags_affected;
        std::string opcode;
        std::string opcode_source = "unresolved";
        if (auto it = handler_lookup.find(first.address); it != handler_lookup.end()) {
            opcode = it->second;
            opcode_source = "handler_table_or_opcode_map";
        } else {
            opcode = opcode_key_by_handler(opcode_map, first.address);
            if (!opcode.empty())
                opcode_source = "opcode_map_handler_va";
        }
        if (opcode.empty()) {
            if (auto decoded = read_opcode_from_side_effects(insn_addrs)) {
                opcode = opcode_key_from_index(*decoded);
                opcode_source = "bytecode_memory_read";
                st["decoded_vopcode_value"] = sa_format_address(*decoded);
            }
        }
        if (opcode.empty()) {
            st["vopcode"] = "unresolved";
            st["vopcode_resolved"] = false;
            st["unresolved_reason"] = "handler address and bytecode read were not present in the supplied opcode map or handler table";
        } else {
            st["vopcode"] = opcode;
            st["vopcode_resolved"] = true;
            st["opcode_source"] = opcode_source;
            if (const json* entry_json = opcode_map_entry_by_opcode(opcode_map, opcode)) {
                st["semantic"] = entry_json->value("semantic", std::string("UNKNOWN"));
                st["handler_confidence"] = entry_json->value("confidence", 0.0);
                if (entry_json->contains("operand_roles"))
                    st["operand_roles"] = (*entry_json)["operand_roles"];
            } else if (const json* entry_json = opcode_map_entry_by_handler(opcode_map, first.address)) {
                st["semantic"] = entry_json->value("semantic", std::string("UNKNOWN"));
                st["handler_confidence"] = entry_json->value("confidence", 0.0);
                if (entry_json->contains("operand_roles"))
                    st["operand_roles"] = (*entry_json)["operand_roles"];
            }
        }
        const std::string inferred_semantic = infer_vm_semantic_from_trace_step(st);
        if (!inferred_semantic.empty() && inferred_semantic != "UNKNOWN") {
            st["inferred_semantic"] = inferred_semantic;
            if (!st.contains("semantic") || !st["semantic"].is_string() || st["semantic"].get<std::string>().empty() || st["semantic"].get<std::string>() == "UNKNOWN") {
                st["semantic"] = inferred_semantic;
                st["semantic_source"] = "trace_window_side_effects";
            }
        }
        if (st.value("semantic", std::string()) == "JCC") {
            const std::string cond = condition_from_trace_step(st);
            if (!cond.empty())
                st["condition"] = cond;
        }
        if (auto target_va = branch_target_from_trace_step(st))
            st["target_native_va"] = sa_format_address(*target_va);
        steps.push_back(std::move(st));
    }
    std::map<std::uint64_t, std::uint64_t> step_by_native_start;
    for (std::size_t i = 0; i < steps.size(); ++i) {
        if (auto h = parse_u64_json(steps[i].value("handler_va", json())))
            step_by_native_start[*h] = static_cast<std::uint64_t>(i);
        if (auto h = parse_u64_json(steps[i].value("native_start_va", json())))
            step_by_native_start[*h] = static_cast<std::uint64_t>(i);
    }
    for (auto& st : steps) {
        auto target = parse_u64_json(st.value("target_native_va", json()));
        if (!target)
            continue;
        auto it = step_by_native_start.find(*target);
        if (it != step_by_native_start.end()) {
            st["target_index"] = it->second;
            st["target_resolved"] = true;
        } else {
            st["target_resolved"] = false;
        }
    }
    json out;
    out["entry_va"] = sa_format_address(*entry);
    out["pid"] = pid;
    out["tid"] = tid;
    out["success"] = r.success;
    out["emulated_instructions"] = r.total_instructions;
    out["trace_entries"] = r.trace.size();
    out["returned_steps"] = steps.size();
    out["truncated"] = dispatch_indices.size() > return_limit;
    out["opcode_lookup_entries"] = handler_lookup.size();
    out["dispatch_windows"] = dispatch_indices.size();
    out["memory_reads_total"] = r.mem_reads.size();
    out["memory_writes_total"] = r.mem_writes.size();
    out["register_delta_total"] = r.reg_deltas.size();
    json global_deltas = json::array();
    for (const auto& d : r.reg_deltas)
        global_deltas.push_back(json{{"register", d.name}, {"before", sa_format_address(d.before)}, {"after", sa_format_address(d.after)}});
    out["register_deltas"] = global_deltas;
    json effective = json::array();
    for (const auto& op : r.effective_ops) {
        effective.push_back(op);
        if (effective.size() >= 128)
            break;
    }
    out["effective_operations"] = effective;
    out["steps"] = steps;
    if (!r.success)
        out["error"] = r.error;
    diag::log_tagged_fmt("protected_re",
        "vm_trace_bytecode handler_exit pid=%u tid=%u success=%d emulated=%u returned_steps=%zu cancelled=%d",
        pid,
        tid,
        r.success ? 1 : 0,
        r.total_instructions,
        steps.size(),
        mcp_standalone::current_call_cancelled() ? 1 : 0);
    return r.success ? tool_result_t::ok("VM bytecode trace completed", out) : tool_result_t::error("VM bytecode trace failed: " + r.error, out);
#else
    (void)pid;
    (void)tid;
    (void)return_limit;
    return tool_result_t::error("VM tracing requires the Windows emulation backend");
#endif
}

inline tool_result_t vm_classify_handler(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto handler = parse_param_u64(params, "handler_va");
    if (!handler)
        handler = parse_param_u64(params, "address");
    if (!handler)
        return tool_result_t::error("handler_va is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t size = static_cast<std::uint32_t>(parse_param_u64(params, "handler_size").value_or(512));
    const std::uint32_t inputs = static_cast<std::uint32_t>(parse_param_u64(params, "num_test_inputs").value_or(16));
    const json handler_region = vm_region_evidence(pid, *handler);
    diag::log_tagged_fmt("protected_re",
        "vm_classify_handler entry pid=%u handler=0x%llX size=%u inputs=%u active_pid=%u handler_region=%s bridge_status='%s' bridge_last_error='%s'",
        pid,
        static_cast<unsigned long long>(*handler),
        size,
        inputs,
        driver_bridge::attached_pid(),
        handler_region.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    json out = classify_handler_static(pid, *handler, size, inputs);
    diag::log_tagged_fmt("protected_re",
        "vm_classify_handler exit pid=%u handler=0x%llX semantic=%s confidence=%.4f instruction_count=%llu evidence_count=%llu",
        pid,
        static_cast<unsigned long long>(*handler),
        out.value("semantic", std::string("UNKNOWN")).c_str(),
        out.value("confidence", 0.0),
        static_cast<unsigned long long>(out.value("instruction_count", 0)),
        static_cast<unsigned long long>(out.contains("evidence") && out["evidence"].is_array() ? out["evidence"].size() : 0));
    return tool_result_t::ok("VM handler classified as " + out.value("semantic", std::string("UNKNOWN")), out);
}

inline tool_result_t vm_build_opcode_map(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto table = parse_param_u64(params, "handler_table_va");
    if (!table)
        return tool_result_t::error("handler_table_va is required");
    const std::uint32_t pid = requested_pid(params);
    std::uint32_t count = static_cast<std::uint32_t>(parse_param_u64(params, "handler_count").value_or(256));
    count = std::clamp<std::uint32_t>(count, 1, 4096);
    const std::uint32_t entry_size = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(parse_param_u64(params, "entry_size").value_or(8), 1, 8));
    const bool relative = params.value("relative", false);
    const std::uint64_t image_base = parse_param_u64(params, "image_base").value_or(0);
    const json table_region = vm_region_evidence(pid, *table);
    auto table_scan = scan_vm_handler_table(pid, *table, count, entry_size, relative, image_base, 32);
    diag::log_tagged_fmt("protected_re",
        "vm_build_opcode_map table_read pid=%u table=0x%llX count=%u read_ok=%d bytes=%zu active_pid=%u table_region=%s bridge_status='%s' bridge_last_error='%s'",
        pid,
        static_cast<unsigned long long>(*table),
        count,
        table_scan.read_ok ? 1 : 0,
        static_cast<std::size_t>(table_scan.entries_read) * static_cast<std::size_t>(table_scan.entry_size),
        driver_bridge::attached_pid(),
        table_region.dump().c_str(),
        driver_bridge::status().c_str(),
        driver_bridge::last_error().c_str());
    if (!table_scan.read_ok || table_scan.entries_read == 0)
        return tool_result_t::error("Could not read handler table at " + sa_format_address(*table));
    std::vector<std::uint8_t> bytecode;
    const std::uint64_t bytecode_va = parse_param_u64(params, "bytecode_va").value_or(0);
    const std::uint32_t opcode_width = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(parse_param_u64(params, "opcode_width").value_or(1), 1, 4));
    const std::uint32_t bytecode_count = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(parse_param_u64(params, "bytecode_count").value_or(count), 1, 4096));
    if (bytecode_va != 0)
        read_target_memory(pid, bytecode_va, static_cast<std::size_t>(bytecode_count) * opcode_width, bytecode);
    std::map<std::uint64_t, json> decoded_vopcode_offsets;
    if (!bytecode.empty()) {
        const std::size_t available = bytecode.size() / opcode_width;
        for (std::size_t i = 0; i < available; ++i) {
            std::uint64_t op = 0;
            std::memcpy(&op, bytecode.data() + i * opcode_width, opcode_width);
            if (op >= table_scan.handlers.size())
                continue;
            decoded_vopcode_offsets[op].push_back(json{{"bytecode_va", sa_format_address(bytecode_va + i * opcode_width)}, {"offset", i * opcode_width}});
            if (decoded_vopcode_offsets[op].size() >= 16)
                continue;
        }
    }
    json map = json::object();
    json decoded_map = json::object();
    std::uint32_t classified = 0;
    std::uint32_t unknown = 0;
    const std::uint32_t got = table_scan.entries_read;
    for (std::uint32_t i = 0; i < got; ++i) {
        const std::uint64_t handler = table_scan.handlers[static_cast<std::size_t>(i)];
        if (!pointer_looks_executable(pid, handler))
            continue;
        json cls = classify_handler_static(pid, handler, static_cast<std::uint32_t>(parse_param_u64(params, "handler_size").value_or(512)), static_cast<std::uint32_t>(parse_param_u64(params, "num_test_inputs").value_or(4)));
        const std::string sem = cls.value("semantic", std::string("UNKNOWN"));
        if (sem == "UNKNOWN")
            ++unknown;
        else
            ++classified;
        const std::string key = opcode_key_from_index(i);
        cls["opcode"] = key;
        cls["opcode_index"] = i;
        cls["vopcode"] = key;
        cls["vopcode_source"] = "handler_table_index";
        cls["handler_va"] = sa_format_address(handler);
        if (auto it = decoded_vopcode_offsets.find(i); it != decoded_vopcode_offsets.end()) {
            cls["decoded_from_bytecode"] = true;
            cls["bytecode_uses"] = it->second;
            cls["vopcode_source"] = "bytecode_stream_and_handler_table";
            decoded_map[key] = cls;
        } else {
            cls["decoded_from_bytecode"] = false;
        }
        map[key] = std::move(cls);
    }
    diag::log_tagged_fmt("protected_re",
        "vm_build_opcode_map exit pid=%u table=0x%llX requested=%u read=%u classified=%u unknown=%u map=%zu",
        pid,
        static_cast<unsigned long long>(*table),
        count,
        got,
        classified,
        unknown,
        map.size());
    json out;
    out["handler_table_va"] = sa_format_address(*table);
    out["handler_count_requested"] = count;
    out["handler_count_read"] = got;
    out["entry_size"] = entry_size;
    out["relative"] = relative;
    if (relative)
        out["image_base"] = sa_format_address(image_base);
    out["handler_table_density"] = table_scan.density;
    out["handler_table_sample"] = table_scan.sample;
    out["bytecode_va"] = bytecode_va ? sa_format_address(bytecode_va) : "unknown";
    out["opcode_width"] = opcode_width;
    out["bytecode_bytes_read"] = bytecode.size();
    out["decoded_opcode_map"] = decoded_map;
    out["decoded_opcode_count"] = decoded_map.size();
    out["opcode_map"] = std::move(map);
    out["classified_count"] = classified;
    out["unknown_count"] = unknown;
    out["confidence"] = got ? (static_cast<double>(classified) / static_cast<double>(got)) * std::max(0.25, table_scan.density) : 0.0;
    return tool_result_t::ok("VM opcode map classified " + std::to_string(classified) + " handlers", out);
}

inline std::string semantic_from_opcode_map(const json& map, const std::string& opcode)
{
    if (const json* entry = opcode_map_entry_by_opcode(map, opcode))
        return entry->value("semantic", std::string("UNKNOWN"));
    return "UNKNOWN";
}

inline std::string il_operand_name(const std::string& operand)
{
    const std::string trimmed = trim_ascii(operand);
    if (trimmed.empty())
        return {};
    if (operand_is_memory(trimmed))
        return "mem" + trimmed.substr(trimmed.find('['));
    const std::string reg = reg_from_operand(trimmed);
    if (!reg.empty() && reg.find(' ') == std::string::npos && reg.find('[') == std::string::npos && !std::isdigit(static_cast<unsigned char>(reg.front())))
        return "v_" + reg;
    return trimmed;
}

inline std::string il_operator_for_semantic(const std::string& semantic)
{
    const std::string s = lower_ascii(semantic);
    if (s == "xor") return "^";
    if (s == "add") return "+";
    if (s == "sub") return "-";
    if (s == "and") return "&";
    if (s == "or") return "|";
    if (s == "mul") return "*";
    if (s == "shl") return "<<";
    if (s == "shr") return ">>";
    return {};
}

inline std::string native_op_text(const json& op)
{
    if (op.is_string())
        return op.get<std::string>();
    if (op.is_object()) {
        if (op.contains("disasm") && op["disasm"].is_string())
            return op["disasm"].get<std::string>();
        if (op.contains("text") && op["text"].is_string())
            return op["text"].get<std::string>();
    }
    return {};
}

inline std::string mnemonic_from_disasm_text(const std::string& text)
{
    const std::string t = lower_ascii(trim_ascii(text));
    const std::size_t sp = t.find_first_of(" \t");
    return sp == std::string::npos ? t : t.substr(0, sp);
}

inline json native_ops_from_step(const json& step)
{
    if (step.is_object() && step.contains("side_effects") && step["side_effects"].is_object()) {
        const json& effects = step["side_effects"];
        if (effects.contains("native_ops") && effects["native_ops"].is_array())
            return effects["native_ops"];
    }
    return json::array();
}

inline std::string infer_vm_semantic_from_trace_step(const json& step)
{
    const json native_ops = native_ops_from_step(step);
    const json effects = step.is_object() && step.contains("side_effects") && step["side_effects"].is_object() ? step["side_effects"] : json::object();
    int add = 0, sub = 0, bit_xor = 0, bit_and = 0, bit_or = 0, shifts = 0, movs = 0;
    bool saw_ret = false;
    bool saw_call = false;
    bool saw_cond = false;
    bool saw_uncond = false;
    bool self_zero = false;
    for (const auto& op : native_ops) {
        const std::string text = native_op_text(op);
        const std::string m = mnemonic_from_disasm_text(text);
        if (m.empty())
            continue;
        if (m == "ret")
            saw_ret = true;
        else if (m == "call")
            saw_call = true;
        else if (condition_from_branch(m).size())
            saw_cond = true;
        else if (m == "jmp")
            saw_uncond = true;
        else if (m == "add" || m == "adc" || m == "lea")
            ++add;
        else if (m == "sub" || m == "sbb")
            ++sub;
        else if (m == "xor")
            ++bit_xor;
        else if (m == "and")
            ++bit_and;
        else if (m == "or")
            ++bit_or;
        else if (m == "shl" || m == "shr" || m == "sar" || m == "sal")
            ++shifts;
        else if (m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "cmovz" || m == "cmovnz")
            ++movs;
        const std::size_t sp = text.find_first_of(" \t");
        if (sp != std::string::npos) {
            auto ops = split_operands(text.substr(sp + 1).c_str());
            if ((m == "xor" || m == "sub") && ops.size() >= 2 && lower_ascii(ops[0]) == lower_ascii(ops[1]))
                self_zero = true;
        }
    }
    if (saw_ret)
        return "RET";
    if (saw_cond)
        return "JCC";
    if (saw_call)
        return "CALL";
    if (effects.contains("writes") && effects["writes"].is_array() && !effects["writes"].empty())
        return "STORE";
    if (effects.contains("reads") && effects["reads"].is_array() && !effects["reads"].empty())
        return "LOAD";
    if (self_zero && bit_xor > 0)
        return "XOR";
    if (self_zero && sub > 0)
        return "SUB";
    if (add > 0)
        return "ADD";
    if (sub > 0)
        return "SUB";
    if (bit_xor > 0)
        return "XOR";
    if (bit_and > 0)
        return "AND";
    if (bit_or > 0)
        return "OR";
    if (shifts > 0)
        return "SHL";
    if (movs > 0)
        return "MOV";
    return saw_uncond ? "JMP" : "UNKNOWN";
}

inline std::string condition_from_trace_step(const json& step)
{
    for (const auto& op : native_ops_from_step(step)) {
        const std::string m = mnemonic_from_disasm_text(native_op_text(op));
        const std::string cond = condition_from_branch(m);
        if (!cond.empty())
            return cond;
    }
    return {};
}

inline std::optional<std::uint64_t> branch_target_from_trace_step(const json& step)
{
    for (const auto& op : native_ops_from_step(step)) {
        const std::string text = native_op_text(op);
        const std::string m = mnemonic_from_disasm_text(text);
        if (m != "jmp" && m != "call" && condition_from_branch(m).empty())
            continue;
        if (text.find('[') != std::string::npos)
            continue;
        if (auto target = parse_hex_in_text(text))
            return target;
    }
    return std::nullopt;
}

inline tool_result_t vm_lift_to_il(const json& params)
{
    const json trace = params.contains("trace") ? params["trace"] : json::object();
    const json opcode_map = params.contains("opcode_map") ? params["opcode_map"] : json::object();
    if (!trace.is_object() && !trace.is_array())
        return tool_result_t::error("trace object or array is required");
    const bool optimize = params.value("optimize", true);
    const json& steps = trace.is_array() ? trace : (trace.contains("steps") ? trace["steps"] : trace);
    if (!steps.is_array())
        return tool_result_t::error("trace must contain a steps array");
    json il = json::array();
    std::uint64_t dead_assignments = 0;
    std::uint64_t folded = 0;
    std::uint64_t resolved_by_opcode = 0;
    std::uint64_t resolved_by_handler = 0;
    std::uint64_t unresolved = 0;
    json virtual_reg_map = json::object();
    json memory_accesses = json::array();
    auto note_vreg = [&](const std::string& operand) {
        const std::string v = il_operand_name(operand);
        if (v.rfind("v_", 0) == 0 && !virtual_reg_map.contains(v))
            virtual_reg_map[v] = json{{"source", operand}, {"width_bits", 64}};
        return v;
    };
    for (const auto& s : steps) {
        const std::string opcode = s.value("vopcode", std::string("unknown"));
        std::string semantic = s.value("semantic", std::string());
        const json* map_entry = nullptr;
        std::string resolution = "trace";
        if (semantic.empty() || semantic == "UNKNOWN" || semantic == "UNRESOLVED") {
            map_entry = opcode_map_entry_by_opcode(opcode_map, opcode);
            if (map_entry) {
                semantic = map_entry->value("semantic", std::string("UNKNOWN"));
                resolution = "opcode";
                ++resolved_by_opcode;
            }
        }
        auto handler_va = parse_u64_json(s.value("handler_va", json()));
        if ((!map_entry || semantic == "UNKNOWN" || semantic.empty()) && handler_va) {
            map_entry = opcode_map_entry_by_handler(opcode_map, *handler_va);
            if (map_entry) {
                semantic = map_entry->value("semantic", std::string("UNKNOWN"));
                resolution = "handler_va";
                ++resolved_by_handler;
            }
        }
        if (semantic.empty() || semantic == "UNKNOWN" || semantic == "UNRESOLVED") {
            const std::string inferred = infer_vm_semantic_from_trace_step(s);
            if (!inferred.empty() && inferred != "UNKNOWN") {
                semantic = inferred;
                resolution = "trace_window_side_effects";
            }
        }
        if (semantic.empty() || semantic == "UNKNOWN")
            semantic = "UNRESOLVED";
        json node;
        node["index"] = il.size();
        node["op"] = semantic;
        node["kind"] = "operation";
        node["opcode"] = opcode;
        node["handler_va"] = s.value("handler_va", std::string("unknown"));
        node["resolution"] = resolution;
        node["trace_step"] = s.value("step", static_cast<std::uint64_t>(il.size()));
        if (map_entry) {
            node["confidence"] = map_entry->value("confidence", 0.0);
            if (map_entry->contains("operand_roles")) {
                const json& roles = (*map_entry)["operand_roles"];
                if (roles.is_object()) {
                    if (roles.contains("dst") && roles["dst"].is_string()) {
                        node["dst"] = note_vreg(roles["dst"].get<std::string>());
                        node["native_dst"] = roles["dst"];
                    }
                    if (roles.contains("src1") && roles["src1"].is_string()) {
                        node["src1"] = note_vreg(roles["src1"].get<std::string>());
                        node["native_src1"] = roles["src1"];
                    }
                    if (roles.contains("src2") && roles["src2"].is_string()) {
                        node["src2"] = note_vreg(roles["src2"].get<std::string>());
                        node["native_src2"] = roles["src2"];
                    }
                }
            }
            if (map_entry->contains("evidence"))
                node["handler_evidence"] = (*map_entry)["evidence"];
        }
        if (!node.contains("dst") && s.contains("operand_roles") && s["operand_roles"].is_object()) {
            const json& roles = s["operand_roles"];
            if (roles.contains("dst") && roles["dst"].is_string())
                node["dst"] = note_vreg(roles["dst"].get<std::string>());
            if (roles.contains("src1") && roles["src1"].is_string())
                node["src1"] = note_vreg(roles["src1"].get<std::string>());
            if (roles.contains("src2") && roles["src2"].is_string())
                node["src2"] = note_vreg(roles["src2"].get<std::string>());
        }
        json effects = s.value("side_effects", json::object());
        if (!effects.is_object())
            effects = json::object({{"raw", effects}});
        if (effects.contains("reads") && effects["reads"].is_array()) {
            for (const auto& rd : effects["reads"]) {
                json ma = rd;
                ma["access"] = "read";
                ma["il_index"] = node["index"];
                memory_accesses.push_back(ma);
            }
        }
        if (effects.contains("writes") && effects["writes"].is_array()) {
            for (const auto& wr : effects["writes"]) {
                json ma = wr;
                ma["access"] = "write";
                ma["il_index"] = node["index"];
                memory_accesses.push_back(ma);
            }
        }
        if (semantic == "UNRESOLVED") {
            ++unresolved;
            effects["unresolved"] = true;
            effects["unresolved_reason"] = handler_va ? "no opcode-map entry matched handler_va" : "trace step did not include a parseable handler_va";
        }
        node["effects"] = std::move(effects);
        const std::string op_token = il_operator_for_semantic(semantic);
        if (!op_token.empty() && node.contains("dst") && node.contains("src1")) {
            node["kind"] = "assign";
            if (node.contains("src2"))
                node["expr"] = node["src1"].get<std::string>() + " " + op_token + " " + node["src2"].get<std::string>();
            else
                node["expr"] = node["dst"].get<std::string>() + " " + op_token + " " + node["src1"].get<std::string>();
        } else if (semantic == "MOV" && node.contains("dst") && node.contains("src1")) {
            node["kind"] = "assign";
            node["expr"] = node["src1"];
        } else if (semantic == "LOAD") {
            node["kind"] = "load";
        } else if (semantic == "STORE") {
            node["kind"] = "store";
        } else if (semantic == "JCC") {
            node["kind"] = "branch";
            node["condition"] = s.value("condition", std::string("vflags"));
        } else if (semantic == "RET") {
            node["kind"] = "return";
        } else if (semantic == "CALL") {
            node["kind"] = "call";
        }
        if (s.contains("native_start_va"))
            node["native_start_va"] = s["native_start_va"];
        if (s.contains("native_end_va"))
            node["native_end_va"] = s["native_end_va"];
        if (s.contains("target_native_va"))
            node["target_native_va"] = s["target_native_va"];
        if (s.contains("target_index") && s["target_index"].is_number())
            node["target_index"] = s["target_index"];
        if (s.contains("flags_affected"))
            node["flags_affected"] = s["flags_affected"];
        if (semantic == "JCC" || semantic == "RET" || semantic == "CALL")
            node["terminator"] = true;
        if (optimize && semantic == "MOV" && node.contains("src1") && node.contains("dst") && node["src1"] == node["dst"]) {
            ++dead_assignments;
            continue;
        }
        if (optimize && semantic == "XOR" && node.contains("src1") && node.contains("src2") && node["src1"] == node["src2"]) {
            node["op"] = "ASSIGN_CONST";
            node["kind"] = "assign";
            if (!node.contains("dst"))
                node["dst"] = node["src1"];
            node["expr"] = "0x0";
            node["value"] = "0x0";
            ++folded;
        }
        if (optimize && semantic == "SUB" && node.contains("src1") && node.contains("src2") && node["src1"] == node["src2"]) {
            node["op"] = "ASSIGN_CONST";
            node["kind"] = "assign";
            if (!node.contains("dst"))
                node["dst"] = node["src1"];
            node["expr"] = "0x0";
            node["value"] = "0x0";
            ++folded;
        }
        il.push_back(std::move(node));
    }
    json out;
    out["il_instructions"] = il;
    out["virtual_reg_map"] = virtual_reg_map;
    out["memory_accesses"] = memory_accesses;
    out["optimization_stats"] = json{{"enabled", optimize}, {"dead_assignments_removed", dead_assignments}, {"constant_folds", folded}, {"input_steps", steps.size()}, {"output_il", il.size()}, {"resolved_by_opcode", resolved_by_opcode}, {"resolved_by_handler_va", resolved_by_handler}, {"unresolved", unresolved}};
    return tool_result_t::ok("Lifted VM trace to IL", out);
}

inline tool_result_t vm_recover_cfg(const json& params)
{
    json il = params.contains("optimized_il") ? params["optimized_il"] : json::object();
    if (il.is_object() && il.contains("il_instructions"))
        il = il["il_instructions"];
    if (!il.is_array())
        return tool_result_t::error("optimized_il with il_instructions is required");
    std::set<int> leaders;
    leaders.insert(0);
    for (std::size_t i = 0; i < il.size(); ++i) {
        const auto& n = il[i];
        const std::string kind = n.value("kind", std::string());
        const std::string op = n.value("op", std::string());
        if (kind == "branch" || op == "JCC" || op == "RET" || op == "CALL" || n.value("terminator", false)) {
            if (i + 1 < il.size())
                leaders.insert(static_cast<int>(i + 1));
            if (n.contains("target_index") && n["target_index"].is_number_integer()) {
                const int target = n["target_index"].get<int>();
                if (target >= 0 && target < static_cast<int>(il.size()))
                    leaders.insert(target);
            }
        }
    }
    std::map<int, int> index_to_block;
    json nodes = json::array();
    std::vector<std::pair<int, int>> block_ranges;
    std::vector<int> sorted_leaders(leaders.begin(), leaders.end());
    std::sort(sorted_leaders.begin(), sorted_leaders.end());
    for (std::size_t bi = 0; bi < sorted_leaders.size(); ++bi) {
        const int start = sorted_leaders[bi];
        const int end = bi + 1 < sorted_leaders.size() ? sorted_leaders[bi + 1] - 1 : static_cast<int>(il.size()) - 1;
        if (start < 0 || start >= static_cast<int>(il.size()) || end < start)
            continue;
        const int id = static_cast<int>(block_ranges.size());
        block_ranges.push_back({start, end});
        for (int idx = start; idx <= end; ++idx)
            index_to_block[idx] = id;
    }
    std::vector<int> exits;
    json edges = json::array();
    for (std::size_t bi = 0; bi < block_ranges.size(); ++bi) {
        const int start = block_ranges[bi].first;
        const int end = block_ranges[bi].second;
        json node{{"id", static_cast<int>(bi)}, {"start_index", start}, {"end_index", end}, {"il_instructions", json::array()}, {"successors", json::array()}};
        for (int idx = start; idx <= end; ++idx)
            node["il_instructions"].push_back(il[static_cast<std::size_t>(idx)]);
        const json& last = il[static_cast<std::size_t>(end)];
        const std::string kind = last.value("kind", std::string());
        const std::string op = last.value("op", std::string());
        if (kind == "return" || op == "RET") {
            exits.push_back(static_cast<int>(bi));
        } else {
            auto add_successor = [&](int target_block, const char* type) {
                if (target_block < 0 || target_block >= static_cast<int>(block_ranges.size()))
                    return;
                bool present = false;
                for (const auto& existing : node["successors"]) {
                    if (existing.is_number_integer() && existing.get<int>() == target_block) {
                        present = true;
                        break;
                    }
                }
                if (!present)
                    node["successors"].push_back(target_block);
                edges.push_back(json{{"from", static_cast<int>(bi)}, {"to", target_block}, {"type", type ? type : "flow"}, {"from_il_index", end}});
            };
            if ((kind == "branch" || op == "JCC") && last.contains("target_index") && last["target_index"].is_number_integer()) {
                const int target = last["target_index"].get<int>();
                auto it = index_to_block.find(target);
                if (it != index_to_block.end())
                    add_successor(it->second, "taken");
                auto ft = index_to_block.find(end + 1);
                if (ft != index_to_block.end())
                    add_successor(ft->second, "fallthrough");
            } else if (kind == "branch" || op == "JCC") {
                auto ft = index_to_block.find(end + 1);
                if (ft != index_to_block.end())
                    add_successor(ft->second, "fallthrough_unresolved_target");
            } else if (kind == "call" || op == "CALL") {
                auto ft = index_to_block.find(end + 1);
                if (ft != index_to_block.end())
                    add_successor(ft->second, "return_continuation");
            } else {
                auto ft = index_to_block.find(end + 1);
                if (ft != index_to_block.end())
                    add_successor(ft->second, "fallthrough");
            }
        }
        nodes.push_back(std::move(node));
    }
    json out;
    out["nodes"] = nodes;
    out["edges"] = edges;
    out["entry_node"] = nodes.empty() ? -1 : 0;
    out["exit_nodes"] = exits;
    out["node_count"] = nodes.size();
    return tool_result_t::ok("Recovered VM IL CFG", out);
}

inline tool_result_t vm_emit_pseudocode(const json& params)
{
    if (!params.contains("cfg"))
        return tool_result_t::error("cfg is required");
    const json& cfg = params["cfg"];
    const std::string style = params.value("style", std::string("c"));
    const json nodes = cfg.contains("nodes") ? cfg["nodes"] : json::array();
    if (!nodes.is_array())
        return tool_result_t::error("cfg.nodes must be an array");
    std::ostringstream ps;
    std::set<std::string> unresolved;
    std::map<int, int> taken_targets;
    std::map<int, int> fallthrough_targets;
    const json edges = cfg.contains("edges") && cfg["edges"].is_array() ? cfg["edges"] : json::array();
    for (const auto& e : edges) {
        if (!e.is_object())
            continue;
        const int from = e.value("from", -1);
        const int to = e.value("to", -1);
        const std::string type = e.value("type", std::string());
        if (from < 0 || to < 0)
            continue;
        if (type == "taken")
            taken_targets[from] = to;
        else if (type.find("fallthrough") != std::string::npos || type == "return_continuation")
            fallthrough_targets[from] = to;
    }
    auto emit_statement = [&](const json& ins, int branch_target) -> std::string {
        const std::string kind = ins.value("kind", std::string());
        const std::string op = ins.value("op", std::string("UNKNOWN"));
        const std::string dst = ins.value("dst", std::string());
        const std::string expr = ins.value("expr", std::string());
        if (kind == "assign" && !dst.empty() && !expr.empty())
            return dst + " = " + expr + ";";
        if (kind == "load" && !dst.empty())
            return dst + " = vm_load();";
        if (kind == "store")
            return "vm_store();";
        if (kind == "branch") {
            const std::string target = branch_target >= 0 ? ("block_" + std::to_string(branch_target)) : std::string("unresolved_target");
            return "if (" + ins.value("condition", std::string("vflags")) + ") goto " + target + ";";
        }
        if (kind == "call")
            return "vm_call(" + ins.value("handler_va", std::string("unknown")) + ");";
        if (kind == "return")
            return "return;";
        if (op == "ASSIGN_CONST" && !dst.empty())
            return dst + " = " + ins.value("value", std::string("0x0")) + ";";
        if (op == "UNRESOLVED" || op == "UNKNOWN")
            return "vm_unresolved(" + ins.value("handler_va", std::string("unknown")) + ");";
        return lower_ascii(op) + "();";
    };
    if (style == "asm_comments") {
        for (const auto& n : nodes) {
            ps << "block_" << n.value("id", 0) << ":\n";
            for (const auto& ins : n.value("il_instructions", json::array()))
                ps << "  " << ins.value("handler_va", std::string()) << " " << emit_statement(ins, -1) << "\n";
        }
    } else {
        ps << "void recovered_vm_function(void) {\n";
        for (const auto& n : nodes) {
            const int block_id = n.value("id", 0);
            ps << "block_" << block_id << ":\n";
            bool ended_return = false;
            bool emitted_branch = false;
            for (const auto& ins : n.value("il_instructions", json::array())) {
                const std::string op = ins.value("op", std::string("UNKNOWN"));
                if (op == "UNKNOWN" || op == "UNRESOLVED")
                    unresolved.insert(ins.value("handler_va", std::string("unknown")));
                const bool is_branch = ins.value("kind", std::string()) == "branch";
                const int branch_target = is_branch && taken_targets.count(block_id) ? taken_targets[block_id] : -1;
                if (is_branch)
                    emitted_branch = true;
                if (ins.value("kind", std::string()) == "return")
                    ended_return = true;
                ps << "    " << emit_statement(ins, branch_target) << "\n";
            }
            if (n.contains("successors") && n["successors"].is_array() && !n["successors"].empty()) {
                if (n["successors"].size() == 1 && !ended_return)
                    ps << "    goto block_" << n["successors"][0].get<int>() << ";\n";
                else if (emitted_branch && fallthrough_targets.count(block_id))
                    ps << "    goto block_" << fallthrough_targets[block_id] << ";\n";
            }
        }
        ps << "}\n";
    }
    json ur = json::array();
    for (const auto& u : unresolved)
        ur.push_back(u);
    const double conf = nodes.empty() ? 0.0 : std::max(0.2, 1.0 - static_cast<double>(unresolved.size()) / static_cast<double>(std::max<std::size_t>(1, nodes.size())));
    json out;
    out["pseudocode"] = ps.str();
    out["confidence"] = conf;
    out["unresolved_handlers"] = ur;
    return tool_result_t::ok("VM pseudocode emitted", out);
}

inline std::optional<std::uint64_t> first_immediate_in_block(const block_t& b)
{
    for (const auto& ins : b.insns) {
        if (ins.has_imm)
            return ins.imm_unsigned;
        if (auto h = parse_hex_in_text(ins.ops))
            return h;
    }
    return std::nullopt;
}

inline std::string cff_state_operand_key(const std::string& operand)
{
    std::string s = lower_ascii(trim_ascii(operand));
    for (const char* prefix : { "qword ptr ", "dword ptr ", "word ptr ", "byte ptr ", "ptr " }) {
        const std::string p(prefix);
        const std::size_t pos = s.find(p);
        if (pos != std::string::npos)
            s.erase(pos, p.size());
    }
    s = trim_ascii(s);
    if (operand_is_memory(s))
        return s;
    return reg_from_operand(s);
}

inline std::optional<std::uint64_t> immediate_operand_value(const std::string& operand)
{
    std::string s = lower_ascii(trim_ascii(operand));
    if (auto v = sa_parse_address(s))
        return v;
    return parse_hex_in_text(s);
}

inline bool cff_operand_is_immediate(const std::string& operand)
{
    const std::string s = lower_ascii(trim_ascii(operand));
    if (s.empty())
        return false;
    if (s.front() == '-' || std::isdigit(static_cast<unsigned char>(s.front())))
        return true;
    return s.rfind("0x", 0) == 0;
}

inline std::string cff_state_key_from_compare(const std::vector<std::string>& ops)
{
    if (ops.size() < 2)
        return {};
    const bool lhs_imm = cff_operand_is_immediate(ops[0]);
    const bool rhs_imm = cff_operand_is_immediate(ops[1]);
    if (!lhs_imm)
        return cff_state_operand_key(ops[0]);
    if (!rhs_imm)
        return cff_state_operand_key(ops[1]);
    return {};
}

inline std::optional<std::uint64_t> cff_case_value_from_compare(const std::vector<std::string>& ops)
{
    if (ops.size() < 2)
        return std::nullopt;
    if (auto rhs = immediate_operand_value(ops[1]))
        return rhs;
    if (auto lhs = immediate_operand_value(ops[0]))
        return lhs;
    return std::nullopt;
}

inline json detect_flattening(std::uint32_t pid, std::uint64_t address, std::uint32_t size)
{
    auto insns = disassemble_target(pid, address, size, 8192);
    auto blocks = build_blocks(insns);
    int dispatcher = -1;
    std::size_t max_edges = 0;
    std::map<std::string, int> state_compare_counts;
    std::map<std::string, int> state_write_counts;
    std::map<std::string, json> state_samples;
    json transition_evidence = json::array();
    for (const auto& b : blocks) {
        if (b.successors.size() > max_edges) {
            max_edges = b.successors.size();
            dispatcher = b.id;
        }
        for (const auto& ins : b.insns) {
            const std::string m = mnemonic_of(ins);
            auto ops = split_operands(ins.ops);
            if ((m == "cmp" || m == "test") && ops.size() >= 2) {
                const std::string key = cff_state_key_from_compare(ops);
                if (!key.empty()) {
                    state_compare_counts[key]++;
                    if (!state_samples.count(key))
                        state_samples[key] = json{{"kind", operand_is_memory(key) ? "memory" : "register"}, {"operand", key}, {"first_compare_va", sa_format_address(ins.addr)}};
                }
            }
            if ((m == "mov" || m == "lea") && ops.size() >= 2) {
                const std::string key = cff_state_operand_key(ops[0]);
                if (!key.empty() && immediate_operand_value(ops[1])) {
                    state_write_counts[key]++;
                    if (!state_samples.count(key))
                        state_samples[key] = json{{"kind", operand_is_memory(ops[0]) ? "memory" : "register"}, {"operand", ops[0]}, {"first_write_va", sa_format_address(ins.addr)}};
                    if (transition_evidence.size() < 128)
                        transition_evidence.push_back(json{{"block_id", b.id}, {"write_va", sa_format_address(ins.addr)}, {"state_operand", ops[0]}, {"state_value", sa_format_address(*immediate_operand_value(ops[1]))}});
                }
            }
        }
    }
    std::string state_key;
    int state_score = 0;
    for (const auto& it : state_compare_counts) {
        const int score = it.second * 2 + state_write_counts[it.first];
        if (score > state_score) {
            state_score = score;
            state_key = it.first;
        }
    }
    if (state_key.empty()) {
        for (const auto& it : state_write_counts) {
            if (it.second > state_score) {
                state_score = it.second;
                state_key = it.first;
            }
        }
    }
    int dispatcher_state_compares = 0;
    int proven_transitions = 0;
    json state_cases = json::array();
    if (!state_key.empty()) {
        for (const auto& b : blocks) {
            for (const auto& ins : b.insns) {
                const std::string m = mnemonic_of(ins);
                auto ops = split_operands(ins.ops);
                if ((m == "cmp" || m == "test") && ops.size() >= 2 && cff_state_key_from_compare(ops) == state_key) {
                    if (b.id == dispatcher)
                        ++dispatcher_state_compares;
                    if (auto imm = cff_case_value_from_compare(ops)) {
                        state_cases.push_back(json{{"block_id", b.id}, {"compare_va", sa_format_address(ins.addr)}, {"state_value", sa_format_address(*imm)}});
                        if (state_cases.size() >= 128)
                            break;
                    }
                }
                if ((m == "mov" || m == "lea") && ops.size() >= 2 && cff_state_operand_key(ops[0]) == state_key && immediate_operand_value(ops[1]))
                    ++proven_transitions;
            }
        }
    }
    int back_to_dispatcher = 0;
    if (dispatcher >= 0) {
        for (const auto& b : blocks) {
            if (b.id == dispatcher)
                continue;
            if (std::find(b.successors.begin(), b.successors.end(), dispatcher) != b.successors.end())
                ++back_to_dispatcher;
        }
    }
    const double block_factor = blocks.size() >= 12 ? 0.25 : (blocks.size() >= 6 ? 0.12 : 0.0);
    const double edge_factor = max_edges >= 4 ? 0.3 : (max_edges >= 2 ? 0.12 : 0.0);
    const double state_factor = state_score >= 6 ? 0.25 : (state_score >= 3 ? 0.14 : 0.0);
    const double proof_factor = dispatcher_state_compares >= 2 && proven_transitions >= 2 ? 0.2 : (dispatcher_state_compares >= 1 && proven_transitions >= 1 ? 0.1 : 0.0);
    const double loop_factor = blocks.empty() ? 0.0 : std::min(0.2, static_cast<double>(back_to_dispatcher) / static_cast<double>(blocks.size()));
    const double confidence = std::min(0.95, block_factor + edge_factor + state_factor + proof_factor + loop_factor);
    json out;
    out["is_flattened"] = confidence >= 0.55;
    out["confidence"] = confidence;
    out["dispatcher_va"] = dispatcher >= 0 && dispatcher < static_cast<int>(blocks.size()) ? sa_format_address(blocks[static_cast<std::size_t>(dispatcher)].start) : "unknown";
    out["dispatcher_block_id"] = dispatcher;
    out["state_var_offset"] = !state_key.empty() && state_key.find('[') != std::string::npos ? state_key : "unknown";
    out["state_variable"] = !state_key.empty() ? state_key : "unknown";
    out["state_variable_evidence"] = !state_key.empty() && state_samples.count(state_key) ? state_samples[state_key] : json::object();
    out["dispatcher_state_compares"] = dispatcher_state_compares;
    out["proven_state_transitions"] = proven_transitions;
    out["state_cases"] = state_cases;
    out["transition_evidence"] = transition_evidence;
    out["dispatcher_proven"] = dispatcher >= 0 && dispatcher_state_compares > 0 && proven_transitions > 0;
    out["block_count"] = blocks.size();
    out["dispatcher_edges"] = max_edges;
    out["back_edges_to_dispatcher"] = back_to_dispatcher;
    out["blocks"] = blocks_to_json(blocks, 8);
    return out;
}

inline tool_result_t cff_detect(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto address = parse_param_u64(params, "address");
    if (!address)
        return tool_result_t::error("address is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t size = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "size").value_or(0x10000)), 0x100, 0x20000);
    json out = detect_flattening(pid, *address, size);
    return tool_result_t::ok(out.value("is_flattened", false) ? "Control-flow flattening indicators found" : "No strong control-flow flattening indicators found", out);
}

inline tool_result_t cff_recover_cfg(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto address = parse_param_u64(params, "address");
    if (!address)
        return tool_result_t::error("address is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t size = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "size").value_or(0x10000)), 0x100, 0x20000);
    const ULONGLONG started = GetTickCount64();
    auto capped_param = [&](const char* key, std::uint64_t fallback, std::uint64_t lo, std::uint64_t hi) -> std::uint64_t {
        return std::clamp<std::uint64_t>(parse_param_u64(params, key).value_or(fallback), lo, hi);
    };
    const std::uint32_t max_instructions = static_cast<std::uint32_t>(capped_param("max_instructions", 512, 32, 8192));
    const std::size_t max_blocks = static_cast<std::size_t>(capped_param("max_blocks", 64, 1, 1024));
    const std::size_t max_edges = static_cast<std::size_t>(capped_param("max_edges", 128, 1, 4096));
    const std::size_t max_il_per_block = static_cast<std::size_t>(capped_param("max_il_per_block", 8, 0, 64));
    const std::size_t max_serialized_instructions = static_cast<std::size_t>(capped_param("max_serialized_instructions", 128, 0, 4096));
    const std::size_t max_state_writes_per_block = static_cast<std::size_t>(capped_param("max_state_writes_per_block", 16, 0, 256));
    const std::uint64_t timeout_ms = capped_param("timeout_ms", 3000, 250, 60000);
    const std::uint64_t local_deadline = started > std::numeric_limits<std::uint64_t>::max() - timeout_ms ? std::numeric_limits<std::uint64_t>::max() : started + timeout_ms;
    const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
    bool cancelled = false;
    bool deadline_hit = false;
    bool result_truncated = false;
    std::string stop_phase;
    auto remaining_ms = [&]() -> std::uint64_t {
        const std::uint64_t now = GetTickCount64();
        std::uint64_t deadline = local_deadline;
        if (call_deadline != 0)
            deadline = std::min<std::uint64_t>(deadline, call_deadline);
        return deadline > now ? deadline - now : 0;
    };
    auto stop_requested = [&](const char* phase) -> bool {
        if (cancelled || deadline_hit)
            return true;
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            stop_phase = phase ? phase : "";
        }
        else
        {
            const std::uint64_t now = GetTickCount64();
            if (now >= local_deadline || (call_deadline != 0 && now >= call_deadline))
            {
                deadline_hit = true;
                stop_phase = phase ? phase : "";
            }
        }
        return cancelled || deadline_hit;
    };
    diag::log_tagged_fmt("protected_re",
                         "cff_recover_cfg enter pid=%u address=%s size=%u max_instructions=%u max_blocks=%zu max_edges=%zu timeout_ms=%llu",
                         pid,
                         sa_format_address(*address).c_str(),
                         size,
                         max_instructions,
                         max_blocks,
                         max_edges,
                         static_cast<unsigned long long>(timeout_ms));
    const ULONGLONG decode_started = GetTickCount64();
    auto insns = disassemble_target(pid, *address, size, max_instructions);
    const ULONGLONG decode_elapsed = GetTickCount64() - decode_started;
    if (insns.size() >= max_instructions)
        result_truncated = true;
    auto blocks = build_blocks(insns);
    const std::size_t total_block_count = blocks.size();
    const std::size_t block_limit = std::min<std::size_t>(blocks.size(), max_blocks);
    if (blocks.size() > block_limit)
        result_truncated = true;
    json detection = stop_requested("before_detection") ? json::object() : detect_flattening(pid, *address, size);
    if (detection.contains("blocks") && detection["blocks"].is_array() && detection["blocks"].size() > max_blocks)
    {
        json limited = json::array();
        for (std::size_t i = 0; i < detection["blocks"].size() && i < max_blocks; ++i)
            limited.push_back(detection["blocks"][i]);
        detection["blocks"] = std::move(limited);
        detection["blocks_truncated"] = true;
        detection["blocks_returned"] = detection["blocks"].size();
        result_truncated = true;
    }
    std::string state_key = params.value("state_var_hint", std::string());
    if (state_key.empty())
        state_key = detection.value("state_variable", std::string("unknown"));
    std::map<std::uint64_t, int> state_to_block;
    for (std::size_t bi = 0; bi < block_limit; ++bi) {
        if (stop_requested("state_index"))
            break;
        const auto& b = blocks[bi];
        for (const auto& ins : b.insns) {
            const std::string m = mnemonic_of(ins);
            auto ops = split_operands(ins.ops);
            if ((m == "cmp" || m == "test") && ops.size() >= 2 && cff_state_key_from_compare(ops) == state_key) {
                if (auto imm = cff_case_value_from_compare(ops))
                    state_to_block[*imm] = b.id;
            }
        }
    }
    json recovered = json::array();
    json recovered_edges = json::array();
    std::size_t serialized_instruction_count = 0;
    std::size_t edges_considered = 0;
    for (std::size_t bi = 0; bi < block_limit; ++bi) {
        if (stop_requested("block_recovery"))
            break;
        const auto& b = blocks[bi];
        json rb;
        rb["id"] = b.id;
        rb["start"] = sa_format_address(b.start);
        rb["end"] = sa_format_address(b.end);
        rb["instruction_count"] = b.insns.size();
        std::optional<std::uint64_t> state_in;
        json state_writes = json::array();
        for (const auto& ins : b.insns) {
            const std::string m = mnemonic_of(ins);
            auto ops = split_operands(ins.ops);
            if ((m == "cmp" || m == "test") && ops.size() >= 2 && cff_state_key_from_compare(ops) == state_key) {
                if (auto imm = cff_case_value_from_compare(ops))
                    state_in = imm;
            }
            if ((m == "mov" || m == "lea") && ops.size() >= 2 && cff_state_operand_key(ops[0]) == state_key) {
                if (auto imm = immediate_operand_value(ops[1]))
                {
                    if (state_writes.size() < max_state_writes_per_block)
                        state_writes.push_back(json{{"write_va", sa_format_address(ins.addr)}, {"state_out", sa_format_address(*imm)}});
                    else
                        result_truncated = true;
                }
            }
        }
        if (!state_in)
            state_in = first_immediate_in_block(b);
        rb["state_in"] = state_in ? sa_format_address(*state_in) : "unknown";
        rb["state_writes"] = state_writes;
        json outs = json::array();
        for (const auto& sw : state_writes) {
            auto v = parse_u64_json(sw.value("state_out", json()));
            if (v) {
                auto it = state_to_block.find(*v);
                if (it != state_to_block.end()) {
                    outs.push_back(sa_format_address(*v));
                    ++edges_considered;
                    if (recovered_edges.size() < max_edges)
                        recovered_edges.push_back(json{{"from", b.id}, {"to", it->second}, {"state_value", sa_format_address(*v)}, {"proof", "state_write_to_dispatcher_case"}});
                    else
                        result_truncated = true;
                }
            }
        }
        for (int sid : b.successors) {
            if (sid >= 0 && sid < static_cast<int>(block_limit)) {
                auto imm = first_immediate_in_block(blocks[static_cast<std::size_t>(sid)]);
                const std::string out_state = imm ? sa_format_address(*imm) : sa_format_address(blocks[static_cast<std::size_t>(sid)].start);
                bool present = false;
                for (const auto& existing : outs) {
                    if (existing.is_string() && existing.get<std::string>() == out_state) {
                        present = true;
                        break;
                    }
                }
                if (!present)
                    outs.push_back(out_state);
                ++edges_considered;
                if (recovered_edges.size() < max_edges)
                    recovered_edges.push_back(json{{"from", b.id}, {"to", sid}, {"state_value", out_state}, {"proof", "native_cfg_edge"}});
                else
                    result_truncated = true;
            }
        }
        rb["state_out"] = outs;
        json il = json::array();
        for (const auto& ins : b.insns)
        {
            if (il.size() >= max_il_per_block || serialized_instruction_count >= max_serialized_instructions)
            {
                result_truncated = true;
                break;
            }
            il.push_back(json{{"va", sa_format_address(ins.addr)}, {"op", ins.mnem}, {"operands", ins.ops}});
            ++serialized_instruction_count;
        }
        rb["il"] = il;
        rb["il_truncated"] = il.size() < b.insns.size();
        recovered.push_back(std::move(rb));
    }
    std::ostringstream ps;
    ps << "void recovered_flattened_function(void) {\n";
    if (state_key != "unknown")
        ps << "uint64_t state = load_state(\"" << state_key << "\");\n";
    for (std::size_t bi = 0; bi < block_limit; ++bi) {
        const auto& b = blocks[bi];
        ps << "block_" << b.id << ":\n";
        bool emitted = false;
        for (const auto& e : recovered_edges) {
            if (!e.is_object() || e.value("from", -1) != b.id)
                continue;
            ps << "    goto block_" << e.value("to", -1) << ";\n";
            emitted = true;
            break;
        }
        if (!emitted)
        {
            for (int sid : b.successors)
            {
                if (sid >= 0 && sid < static_cast<int>(block_limit))
                {
                    ps << "    goto block_" << sid << ";\n";
                    emitted = true;
                    break;
                }
            }
        }
    }
    ps << "}\n";
    std::ostringstream dot;
    dot << "digraph cff_recovered {\n";
    for (std::size_t bi = 0; bi < block_limit; ++bi)
    {
        const auto& b = blocks[bi];
        dot << "  n" << b.id << " [label=\"B" << b.id << "\\n" << sa_format_address(b.start) << "\"];\n";
    }
    for (const auto& e : recovered_edges)
    {
        if (!e.is_object())
            continue;
        dot << "  n" << e.value("from", -1) << " -> n" << e.value("to", -1) << ";\n";
    }
    dot << "}\n";
    json out;
    out["recovered_blocks"] = recovered;
    out["recovered_edges"] = recovered_edges;
    out["cfg_dot"] = dot.str();
    out["pseudocode"] = ps.str();
    out["detection"] = detection;
    out["confidence"] = detection.value("confidence", 0.0);
    out["state_variable"] = state_key;
    out["transition_count"] = recovered_edges.size();
    out["transition_count_total_considered"] = edges_considered;
    out["instruction_count_total_decoded"] = insns.size();
    out["serialized_instruction_count"] = serialized_instruction_count;
    out["block_count_total"] = total_block_count;
    out["block_count_returned"] = recovered.size();
    out["result_truncated"] = result_truncated;
    out["deadline_hit"] = deadline_hit;
    out["cancelled"] = cancelled;
    out["partial"] = result_truncated || deadline_hit || cancelled;
    out["stop_phase"] = stop_phase;
    out["timeout_ms"] = timeout_ms;
    out["deadline_remaining_ms"] = remaining_ms();
    out["elapsed_ms"] = GetTickCount64() - started;
    out["phase_timings"] = json{{"decode_elapsed_ms", decode_elapsed}};
    out["caps"] = json{{"max_instructions", max_instructions},
                       {"max_blocks", max_blocks},
                       {"max_edges", max_edges},
                       {"max_il_per_block", max_il_per_block},
                       {"max_serialized_instructions", max_serialized_instructions},
                       {"max_state_writes_per_block", max_state_writes_per_block}};
    diag::log_tagged_fmt("protected_re",
                         "cff_recover_cfg exit pid=%u blocks=%zu/%zu edges=%zu/%zu instructions=%zu truncated=%d deadline=%d cancelled=%d elapsed_ms=%llu",
                         pid,
                         recovered.size(),
                         total_block_count,
                         recovered_edges.size(),
                         edges_considered,
                         insns.size(),
                         result_truncated ? 1 : 0,
                         deadline_hit ? 1 : 0,
                         cancelled ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started));
    if (cancelled)
        return tool_result_t::error("CFF CFG recovery cancelled.", out);
    if (deadline_hit && recovered.empty())
        return tool_result_t::error("CFF CFG recovery deadline reached before any block was recovered.", out);
    return tool_result_t::ok("Recovered CFG from flattened control flow evidence", out);
}

inline bool z3_is_separator(wchar_t ch)
{
    return ch == L'\\' || ch == L'/';
}

inline constexpr DWORD kZ3PathChars = 32768;

inline bool z3_is_ascii_alpha(wchar_t ch)
{
    return (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
}

inline bool z3_is_drive_absolute(const std::wstring& path, std::size_t offset = 0)
{
    return path.size() >= offset + 3 && z3_is_ascii_alpha(path[offset]) && path[offset + 1] == L':' && z3_is_separator(path[offset + 2]);
}

inline bool z3_is_absolute_path(const std::wstring& path)
{
    if (z3_is_drive_absolute(path))
        return true;
    if (path.size() >= 8 && z3_is_separator(path[0]) && z3_is_separator(path[1]) && path[2] == L'?' && z3_is_separator(path[3])) {
        if (z3_is_drive_absolute(path, 4))
            return true;
        return path.size() >= 10 && path[4] == L'U' && path[5] == L'N' && path[6] == L'C' && z3_is_separator(path[7]) && !z3_is_separator(path[8]);
    }
    return path.size() >= 3 && z3_is_separator(path[0]) && z3_is_separator(path[1]) && !z3_is_separator(path[2]) && path[2] != L'?';
}

inline std::wstring z3_trim_trailing_separators(std::wstring path)
{
    while (path.size() > 1 && z3_is_separator(path.back())) {
        if (path.size() == 3 && z3_is_drive_absolute(path))
            break;
        if (path.size() == 7 && z3_is_separator(path[0]) && z3_is_separator(path[1]) && path[2] == L'?' && z3_is_separator(path[3]) && z3_is_drive_absolute(path, 4))
            break;
        path.pop_back();
    }
    return path;
}

inline std::wstring z3_normalize_absolute_dir(const std::wstring& raw)
{
    if (raw.empty() || !z3_is_absolute_path(raw))
        return {};
    const DWORD needed = GetFullPathNameW(raw.c_str(), 0, nullptr, nullptr);
    if (needed == 0 || needed > kZ3PathChars)
        return {};
    std::wstring full(needed, L'\0');
    const DWORD written = GetFullPathNameW(raw.c_str(), needed, full.data(), nullptr);
    if (written == 0 || written >= needed)
        return {};
    full.resize(written);
    if (!z3_is_absolute_path(full))
        return {};
    return z3_trim_trailing_separators(std::move(full));
}

inline std::wstring z3_join_path(std::wstring dir, const wchar_t* filename)
{
    dir = z3_trim_trailing_separators(std::move(dir));
    if (dir.empty())
        return {};
    if (!z3_is_separator(dir.back()))
        dir.push_back(L'\\');
    dir += filename;
    return dir;
}

inline bool z3_regular_file_exists(const std::wstring& path)
{
    if (path.empty())
        return false;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

inline std::wstring z3_executable_dir()
{
    std::array<wchar_t, kZ3PathChars> path{};
    const DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (len == 0 || len >= static_cast<DWORD>(path.size()))
        return {};
    std::wstring exe(path.data(), path.data() + len);
    const std::size_t slash = exe.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
        return {};
    return z3_trim_trailing_separators(exe.substr(0, slash));
}

inline std::wstring z3_module_path_w(HMODULE mod)
{
    std::array<wchar_t, kZ3PathChars> path{};
    const DWORD len = GetModuleFileNameW(mod, path.data(), static_cast<DWORD>(path.size()));
    if (len == 0 || len >= static_cast<DWORD>(path.size()))
        return {};
    return std::wstring(path.data(), path.data() + len);
}

inline std::string z3_wide_to_utf8(const std::wstring& value)
{
    if (value.empty())
        return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1)
        return {};
    std::string out(static_cast<std::size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, out.data(), needed, nullptr, nullptr);
    return out;
}

struct z3_load_candidate_t {
    const char* source = "";
    std::wstring path;
    bool eligible = false;
    bool exists = false;
    std::string reason;
};

inline z3_load_candidate_t z3_make_candidate(const char* source, const std::wstring& dir, const char* unavailable_reason)
{
    z3_load_candidate_t candidate;
    candidate.source = source;
    if (dir.empty()) {
        candidate.reason = unavailable_reason;
        return candidate;
    }
    candidate.path = z3_join_path(dir, L"libz3.dll");
    candidate.exists = z3_regular_file_exists(candidate.path);
    candidate.eligible = candidate.exists;
    candidate.reason = candidate.exists ? "ready" : "file_missing";
    return candidate;
}

inline std::vector<z3_load_candidate_t> z3_load_candidates()
{
    std::vector<z3_load_candidate_t> candidates;
    candidates.reserve(3);

    z3_load_candidate_t env_candidate;
    env_candidate.source = "AIDA_Z3_PRELOAD_DIR";
    std::array<wchar_t, kZ3PathChars> preload_dir{};
    const DWORD preload_cap = static_cast<DWORD>(preload_dir.size());
    const DWORD preload_len = GetEnvironmentVariableW(L"AIDA_Z3_PRELOAD_DIR", preload_dir.data(), preload_cap);
    if (preload_len == 0) {
        env_candidate.reason = "env_absent_or_empty";
    } else if (preload_len >= preload_cap) {
        env_candidate.reason = "env_too_long";
    } else {
        const std::wstring normalized = z3_normalize_absolute_dir(std::wstring(preload_dir.data(), preload_dir.data() + preload_len));
        if (normalized.empty()) {
            env_candidate.reason = "env_not_absolute_normalized_dir";
        } else {
            env_candidate = z3_make_candidate("AIDA_Z3_PRELOAD_DIR", normalized, "env_not_absolute_normalized_dir");
        }
    }
    candidates.push_back(std::move(env_candidate));

    const std::wstring exe_dir = z3_executable_dir();
    candidates.push_back(z3_make_candidate("exe_deps_z3", z3_join_path(z3_join_path(exe_dir, L"deps"), L"z3"), "exe_dir_unavailable"));
    candidates.push_back(z3_make_candidate("exe_dir_developer", exe_dir, "exe_dir_unavailable"));
    return candidates;
}

inline HMODULE z3_load_library_scoped(const std::wstring& path)
{
    return LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
}

inline HMODULE z3_module_handle(bool allow_load)
{
    HMODULE mod = GetModuleHandleW(L"libz3.dll");
    if (mod || !allow_load)
        return mod;
    for (const auto& candidate : z3_load_candidates()) {
        if (!candidate.eligible || !candidate.exists)
            continue;
        mod = z3_load_library_scoped(candidate.path);
        if (mod)
            return mod;
    }
    return nullptr;
}

inline const std::array<const char*, 22>& z3_required_exports()
{
    static const std::array<const char*, 22> names = {
        "Z3_mk_config",
        "Z3_del_config",
        "Z3_mk_context",
        "Z3_del_context",
        "Z3_mk_solver",
        "Z3_solver_inc_ref",
        "Z3_solver_dec_ref",
        "Z3_solver_assert",
        "Z3_solver_check",
        "Z3_mk_bv_sort",
        "Z3_mk_string_symbol",
        "Z3_mk_const",
        "Z3_mk_numeral",
        "Z3_mk_eq",
        "Z3_mk_not",
        "Z3_mk_bvadd",
        "Z3_mk_bvsub",
        "Z3_mk_bvmul",
        "Z3_mk_bvand",
        "Z3_mk_bvor",
        "Z3_mk_bvxor",
        "Z3_mk_bvshl"
    };
    return names;
}

struct z3_dynamic_api_t {
    using z3_ptr = void*;
    using mk_config_fn = z3_ptr (__cdecl*)();
    using del_config_fn = void (__cdecl*)(z3_ptr);
    using mk_context_fn = z3_ptr (__cdecl*)(z3_ptr);
    using del_context_fn = void (__cdecl*)(z3_ptr);
    using mk_solver_fn = z3_ptr (__cdecl*)(z3_ptr);
    using solver_ref_fn = void (__cdecl*)(z3_ptr, z3_ptr);
    using solver_assert_fn = void (__cdecl*)(z3_ptr, z3_ptr, z3_ptr);
    using solver_check_fn = int (__cdecl*)(z3_ptr, z3_ptr);
    using mk_bv_sort_fn = z3_ptr (__cdecl*)(z3_ptr, unsigned);
    using mk_string_symbol_fn = z3_ptr (__cdecl*)(z3_ptr, const char*);
    using mk_const_fn = z3_ptr (__cdecl*)(z3_ptr, z3_ptr, z3_ptr);
    using mk_numeral_fn = z3_ptr (__cdecl*)(z3_ptr, const char*, z3_ptr);
    using mk_unary_ast_fn = z3_ptr (__cdecl*)(z3_ptr, z3_ptr);
    using mk_binary_ast_fn = z3_ptr (__cdecl*)(z3_ptr, z3_ptr, z3_ptr);

    HMODULE module = nullptr;
    mk_config_fn mk_config = nullptr;
    del_config_fn del_config = nullptr;
    mk_context_fn mk_context = nullptr;
    del_context_fn del_context = nullptr;
    mk_solver_fn mk_solver = nullptr;
    solver_ref_fn solver_inc_ref = nullptr;
    solver_ref_fn solver_dec_ref = nullptr;
    solver_assert_fn solver_assert = nullptr;
    solver_check_fn solver_check = nullptr;
    mk_bv_sort_fn mk_bv_sort = nullptr;
    mk_string_symbol_fn mk_string_symbol = nullptr;
    mk_const_fn mk_const = nullptr;
    mk_numeral_fn mk_numeral = nullptr;
    mk_binary_ast_fn mk_eq = nullptr;
    mk_unary_ast_fn mk_not = nullptr;
    mk_binary_ast_fn mk_bvadd = nullptr;
    mk_binary_ast_fn mk_bvsub = nullptr;
    mk_binary_ast_fn mk_bvmul = nullptr;
    mk_binary_ast_fn mk_bvand = nullptr;
    mk_binary_ast_fn mk_bvor = nullptr;
    mk_binary_ast_fn mk_bvxor = nullptr;
    mk_binary_ast_fn mk_bvshl = nullptr;
    std::vector<std::string> missing_exports;

    bool load(bool allow_load)
    {
        missing_exports.clear();
        module = z3_module_handle(allow_load);
        if (!module)
            return false;
#define AIDA_Z3_LOAD(field, name) field = reinterpret_cast<decltype(field)>(GetProcAddress(module, name)); if (!field) missing_exports.emplace_back(name)
        AIDA_Z3_LOAD(mk_config, "Z3_mk_config");
        AIDA_Z3_LOAD(del_config, "Z3_del_config");
        AIDA_Z3_LOAD(mk_context, "Z3_mk_context");
        AIDA_Z3_LOAD(del_context, "Z3_del_context");
        AIDA_Z3_LOAD(mk_solver, "Z3_mk_solver");
        AIDA_Z3_LOAD(solver_inc_ref, "Z3_solver_inc_ref");
        AIDA_Z3_LOAD(solver_dec_ref, "Z3_solver_dec_ref");
        AIDA_Z3_LOAD(solver_assert, "Z3_solver_assert");
        AIDA_Z3_LOAD(solver_check, "Z3_solver_check");
        AIDA_Z3_LOAD(mk_bv_sort, "Z3_mk_bv_sort");
        AIDA_Z3_LOAD(mk_string_symbol, "Z3_mk_string_symbol");
        AIDA_Z3_LOAD(mk_const, "Z3_mk_const");
        AIDA_Z3_LOAD(mk_numeral, "Z3_mk_numeral");
        AIDA_Z3_LOAD(mk_eq, "Z3_mk_eq");
        AIDA_Z3_LOAD(mk_not, "Z3_mk_not");
        AIDA_Z3_LOAD(mk_bvadd, "Z3_mk_bvadd");
        AIDA_Z3_LOAD(mk_bvsub, "Z3_mk_bvsub");
        AIDA_Z3_LOAD(mk_bvmul, "Z3_mk_bvmul");
        AIDA_Z3_LOAD(mk_bvand, "Z3_mk_bvand");
        AIDA_Z3_LOAD(mk_bvor, "Z3_mk_bvor");
        AIDA_Z3_LOAD(mk_bvxor, "Z3_mk_bvxor");
        AIDA_Z3_LOAD(mk_bvshl, "Z3_mk_bvshl");
#undef AIDA_Z3_LOAD
        return missing_exports.empty();
    }
};

inline bool z3_prove_bv_add_xor_and_identity(json& proof)
{
    proof = json{{"identity", "bvadd_xor_and_carry"}, {"bit_width", 64}, {"solver_invoked", false}, {"z3_used", false}, {"proved", false}};
    z3_dynamic_api_t api;
    if (!api.load(true)) {
        proof["reason"] = "z3_backend_unavailable";
        proof["module_handle"] = api.module ? sa_format_address(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(api.module))) : "0x0";
        proof["missing_exports"] = api.missing_exports;
        return false;
    }
    proof["module_handle"] = sa_format_address(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(api.module)));
    auto cfg = api.mk_config();
    if (!cfg) {
        proof["reason"] = "mk_config_failed";
        return false;
    }
    auto ctx = api.mk_context(cfg);
    api.del_config(cfg);
    if (!ctx) {
        proof["reason"] = "mk_context_failed";
        return false;
    }
    auto solver = api.mk_solver(ctx);
    if (!solver) {
        api.del_context(ctx);
        proof["reason"] = "mk_solver_failed";
        return false;
    }
    api.solver_inc_ref(ctx, solver);
    auto cleanup = [&]() {
        api.solver_dec_ref(ctx, solver);
        api.del_context(ctx);
    };
    auto bv64 = api.mk_bv_sort(ctx, 64);
    auto x = api.mk_const(ctx, api.mk_string_symbol(ctx, "x"), bv64);
    auto y = api.mk_const(ctx, api.mk_string_symbol(ctx, "y"), bv64);
    auto one = api.mk_numeral(ctx, "1", bv64);
    if (!bv64 || !x || !y || !one) {
        cleanup();
        proof["reason"] = "ast_construction_failed";
        return false;
    }
    auto lhs = api.mk_bvadd(ctx, api.mk_bvxor(ctx, x, y), api.mk_bvshl(ctx, api.mk_bvand(ctx, x, y), one));
    auto rhs = api.mk_bvadd(ctx, x, y);
    auto neq = api.mk_not(ctx, api.mk_eq(ctx, lhs, rhs));
    if (!lhs || !rhs || !neq) {
        cleanup();
        proof["reason"] = "identity_ast_failed";
        return false;
    }
    api.solver_assert(ctx, solver, neq);
    proof["solver_invoked"] = true;
    proof["z3_used"] = true;
    const int result = api.solver_check(ctx, solver);
    proof["solver_result"] = result == -1 ? "unsat" : (result == 1 ? "sat" : "unknown");
    const bool proved = result == -1;
    proof["proved"] = proved;
    proof["proof_method"] = proved ? "z3_bv64_unsat_negated_equivalence" : "z3_bv64_solver_not_unsat";
    cleanup();
    return proved;
}

inline json z3_backend_state()
{
    json state;
    json candidate_checks = json::array();
    bool preload_env_present = false;
    bool preload_env_accepted = false;
    for (const auto& candidate : z3_load_candidates()) {
        if (std::strcmp(candidate.source, "AIDA_Z3_PRELOAD_DIR") == 0) {
            preload_env_present = candidate.reason != "env_absent_or_empty";
            preload_env_accepted = candidate.eligible;
        }
        candidate_checks.push_back(json{
            {"source", candidate.source},
            {"path", z3_wide_to_utf8(candidate.path)},
            {"eligible", candidate.eligible},
            {"exists", candidate.exists},
            {"reason", candidate.reason}
        });
    }
    state["load_candidates"] = candidate_checks;
    state["preload_env_present"] = preload_env_present;
    state["preload_env_accepted"] = preload_env_accepted;
    HMODULE mod = z3_module_handle(false);
    state["module_loaded"] = mod != nullptr;
    state["module_handle"] = mod ? sa_format_address(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mod))) : "0x0";
    if (mod) {
        state["module_path"] = z3_wide_to_utf8(z3_module_path_w(mod));
        json exports = json::object();
        json missing = json::array();
        for (const auto* name : z3_required_exports()) {
            const bool present = GetProcAddress(mod, name) != nullptr;
            exports[name] = present;
            if (!present)
                missing.push_back(name);
        }
        state["api_exports"] = exports;
        state["api_missing_exports"] = missing;
        state["api_missing_export_count"] = missing.size();
        state["api_required_export_count"] = z3_required_exports().size();
        state["api_available"] = missing.empty();
        state["api_mk_config"] = exports.value("Z3_mk_config", false);
        state["api_mk_context"] = exports.value("Z3_mk_context", false);
        state["api_mk_solver"] = exports.value("Z3_mk_solver", false);
        state["api_solver_check"] = exports.value("Z3_solver_check", false);
    } else {
        state["module_path"] = "";
        state["api_exports"] = json::object();
        state["api_missing_exports"] = json::array();
        state["api_missing_export_count"] = z3_required_exports().size();
        state["api_required_export_count"] = z3_required_exports().size();
        state["api_available"] = false;
    }
    return state;
}

inline tool_result_t mba_simplify(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto address = parse_param_u64(params, "address");
    if (!address)
        return tool_result_t::error("address is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t size = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "size").value_or(4096)), 16, 65536);
    const bool use_z3 = params.value("use_z3", false);
    const bool z3_explicit = params.contains("use_z3");
    json z3_state = z3_backend_state();
    auto insns = disassemble_target(pid, *address, size, 4096);
    json out = json::array();
    std::uint64_t deterministic_count = 0;
    std::uint64_t heuristic_count = 0;
    bool solver_required = false;
    bool solver_invoked = false;
    bool z3_used_any = false;
    json solver_proofs = json::array();
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        const std::string m = mnemonic_of(ins);
        auto ops = split_operands(ins.ops);
        if ((m == "xor" || m == "sub") && ops.size() >= 2 && lower_ascii(ops[0]) == lower_ascii(ops[1])) {
            ++deterministic_count;
            out.push_back(json{{"original_va", sa_format_address(ins.addr)}, {"original_expr", std::string(ins.mnem) + " " + ins.ops}, {"simplified_expr", ops[0] + " = 0"}, {"verified", true}, {"proof_method", "deterministic_register_identity"}, {"solver_required", false}, {"solver_invoked", false}, {"solver_selection_reason", "deterministic_identity"}, {"z3_used", false}});
        } else if (m == "shl" && ops.size() >= 2 && (ops[1] == "1" || ops[1] == "0x1")) {
            ++deterministic_count;
            out.push_back(json{{"original_va", sa_format_address(ins.addr)}, {"original_expr", std::string(ins.mnem) + " " + ins.ops}, {"simplified_expr", ops[0] + " = " + ops[0] + " * 2"}, {"verified", true}, {"proof_method", "deterministic_shift_identity"}, {"solver_required", false}, {"solver_invoked", false}, {"solver_selection_reason", "deterministic_identity"}, {"z3_used", false}});
        } else if (m == "not" && i + 1 < insns.size()) {
            const auto next_ops = split_operands(insns[i + 1].ops);
            if (mnemonic_of(insns[i + 1]) == "add" && next_ops.size() >= 2 && lower_ascii(next_ops[0]) == lower_ascii(ops.empty() ? "" : ops[0]) && (next_ops[1] == "1" || next_ops[1] == "0x1")) {
                ++deterministic_count;
                out.push_back(json{{"original_va", sa_format_address(ins.addr)}, {"original_expr", std::string("not/add ") + (ops.empty() ? "" : ops[0])}, {"simplified_expr", (ops.empty() ? std::string("x") : ops[0]) + " = -" + (ops.empty() ? std::string("x") : ops[0])}, {"verified", true}, {"proof_method", "deterministic_twos_complement_identity"}, {"solver_required", false}, {"solver_invoked", false}, {"solver_selection_reason", "deterministic_identity"}, {"z3_used", false}});
            }
        } else if ((m == "xor" || m == "and") && i + 2 < insns.size()) {
            const std::string m1 = mnemonic_of(insns[i + 1]);
            const std::string m2 = mnemonic_of(insns[i + 2]);
            if ((m == "xor" && m1 == "and" && (m2 == "lea" || m2 == "add")) || (m == "and" && m1 == "xor" && (m2 == "lea" || m2 == "add"))) {
                ++heuristic_count;
                solver_required = true;
                json proof = json{{"solver_invoked", false}, {"z3_used", false}, {"reason", "z3_not_requested"}};
                bool verified = false;
                if (use_z3) {
                    verified = z3_prove_bv_add_xor_and_identity(proof);
                    solver_invoked = solver_invoked || proof.value("solver_invoked", false);
                    z3_used_any = z3_used_any || proof.value("z3_used", false);
                    if (solver_proofs.size() < 16)
                        solver_proofs.push_back(proof);
                }
                const std::string reason = !use_z3 ? "z3_not_requested" : (proof.value("z3_used", false) ? (verified ? "z3_proved_bv64_identity" : "z3_solver_not_unsat") : proof.value("reason", std::string("z3_backend_unavailable")));
                out.push_back(json{{"original_va", sa_format_address(ins.addr)}, {"original_expr", "(x ^ y) + ((x & y) << 1)"}, {"simplified_expr", "x + y"}, {"verified", verified}, {"proof_method", verified ? "z3_bv64_unsat_negated_equivalence" : (use_z3 ? "z3_identity_proof_unavailable" : "unverified_mba_heuristic")}, {"solver_required", true}, {"solver_invoked", proof.value("solver_invoked", false)}, {"solver_selection_reason", reason}, {"z3_skip_reason", verified ? "" : reason}, {"z3_used", proof.value("z3_used", false)}, {"z3_proof", proof}});
            }
        }
    }
    if (use_z3 && solver_required)
        z3_state = z3_backend_state();
    const bool z3_api_available = z3_state.value("api_available", false);
    std::string selection_reason;
    std::string skip_reason;
    if (!use_z3) {
        selection_reason = "z3_not_requested";
        skip_reason = "z3_not_requested";
    } else if (!solver_required) {
        selection_reason = "deterministic_identities_do_not_require_solver";
        skip_reason = "solver_not_required_for_detected_identities";
    } else if (!z3_api_available) {
        selection_reason = z3_used_any ? "z3_loaded_for_dynamic_identity_proof" : "z3_backend_unavailable";
        skip_reason = z3_used_any ? "" : "z3_backend_unavailable";
    } else {
        selection_reason = z3_used_any ? "z3_loaded_for_dynamic_identity_proof" : "z3_backend_available_but_no_solver_candidate_invoked";
        skip_reason = z3_used_any ? "" : "z3_backend_available_but_no_solver_candidate_invoked";
    }
    const bool z3_requested = use_z3 && solver_required;
    diag::log_tagged_fmt("protected_re",
        "mba_simplify_backend pid=%u address=0x%llX size=%u z3_requested=%d z3_preference=%d z3_explicit=%d z3_module_loaded=%d z3_api_available=%d solver_required=%d solver_invoked=%d deterministic=%llu heuristic=%llu instructions=%zu reason=%s",
        pid,
        static_cast<unsigned long long>(*address),
        size,
        z3_requested ? 1 : 0,
        use_z3 ? 1 : 0,
        z3_explicit ? 1 : 0,
        z3_state.value("module_loaded", false) ? 1 : 0,
        z3_api_available ? 1 : 0,
        solver_required ? 1 : 0,
        solver_invoked ? 1 : 0,
        static_cast<unsigned long long>(deterministic_count),
        static_cast<unsigned long long>(heuristic_count),
        insns.size(),
        selection_reason.c_str());
    json result;
    result["simplifications"] = out;
    result["count"] = out.size();
    result["z3_requested"] = z3_requested;
    result["z3_preference_requested"] = use_z3;
    result["z3_request_explicit"] = z3_explicit;
    result["z3_used"] = z3_used_any;
    result["z3_backend"] = z3_state;
    result["solver_required"] = solver_required;
    result["solver_invoked"] = solver_invoked;
    result["solver_selection_reason"] = selection_reason;
    result["z3_skip_reason"] = skip_reason;
    result["solver_proofs"] = solver_proofs;
    result["expression_complexity"] = json{{"instructions_decoded", insns.size()}, {"deterministic_identity_count", deterministic_count}, {"heuristic_candidate_count", heuristic_count}, {"solver_candidate_count", heuristic_count}, {"scan_size", size}};
    result["proof_backend"] = solver_required ? "deterministic_local_identities_with_unverified_solver_candidates" : "deterministic_local_identities_only";
    result["confidence"] = out.empty() ? 0.0 : 0.65;
    return tool_result_t::ok("MBA simplification scan completed", result);
}

inline tool_result_t obf_detect_mba(const json& params)
{
    auto result = mba_simplify(params);
    if (result.data.is_object()) {
        result.data["alias_tool"] = "obf_detect_mba";
        result.data["canonical_tool"] = "mba_simplify";
        result.data["detection_kind"] = "mixed_boolean_arithmetic";
    }
    return result;
}

inline bool expression_text_valid(const std::string& expr)
{
    int depth = 0;
    bool saw_token = false;
    for (char c : expr) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalnum(u) || c == '_' || c == ' ' || c == '\t' || c == '+' || c == '-' || c == '*' || c == '&' || c == '|' || c == '^' || c == '~' || c == '(' || c == ')' || c == '<' || c == '>' || c == 'x' || c == 'X') {
            if (std::isalnum(u) || c == '_')
                saw_token = true;
            if (c == '(')
                ++depth;
            if (c == ')') {
                --depth;
                if (depth < 0)
                    return false;
            }
            continue;
        }
        return false;
    }
    return saw_token && depth == 0;
}

inline std::string strip_outer_expr(std::string s)
{
    s = trim_ascii(s);
    bool changed = true;
    while (changed && s.size() >= 2 && s.front() == '(' && s.back() == ')') {
        changed = false;
        int depth = 0;
        bool wraps = true;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '(')
                ++depth;
            else if (s[i] == ')')
                --depth;
            if (depth == 0 && i + 1 < s.size()) {
                wraps = false;
                break;
            }
        }
        if (wraps) {
            s = trim_ascii(s.substr(1, s.size() - 2));
            changed = true;
        }
    }
    return s;
}

inline bool split_top_level_expr(const std::string& expr, const std::string& op, std::string& lhs, std::string& rhs)
{
    int depth = 0;
    for (std::size_t i = 0; i + op.size() <= expr.size(); ++i) {
        const char c = expr[i];
        if (c == '(') {
            ++depth;
            continue;
        }
        if (c == ')') {
            --depth;
            continue;
        }
        if (depth == 0 && expr.compare(i, op.size(), op) == 0) {
            lhs = strip_outer_expr(expr.substr(0, i));
            rhs = strip_outer_expr(expr.substr(i + op.size()));
            return !lhs.empty() && !rhs.empty();
        }
    }
    return false;
}

inline bool same_expr_text(const std::string& a, const std::string& b)
{
    return lower_ascii(strip_outer_expr(a)) == lower_ascii(strip_outer_expr(b));
}

inline bool zero_expr_text(const std::string& s)
{
    const std::string t = lower_ascii(strip_outer_expr(s));
    return t == "0" || t == "0x0";
}

inline bool one_expr_text(const std::string& s)
{
    const std::string t = lower_ascii(strip_outer_expr(s));
    return t == "1" || t == "0x1";
}

inline tool_result_t obf_simplify_expr(const json& params)
{
    const std::string expr = params.value("expr", std::string());
    if (expr.empty())
        return tool_result_t::error("expr is required");
    if (expr.size() > 4096)
        return tool_result_t::error("expr is too large; max 4096 bytes");
    if (!expression_text_valid(expr))
        return tool_result_t::error("expr contains invalid characters or unbalanced parentheses", json{{"expr_valid", false}});
    const std::string normalized = strip_outer_expr(expr);
    std::string lhs;
    std::string rhs;
    std::string simplified = normalized;
    std::string proof = "no_deterministic_identity_matched";
    bool changed = false;
    bool verified = false;
    if (split_top_level_expr(normalized, "^", lhs, rhs) && same_expr_text(lhs, rhs)) {
        simplified = "0";
        proof = "xor_self_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "-", lhs, rhs) && same_expr_text(lhs, rhs)) {
        simplified = "0";
        proof = "sub_self_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "&", lhs, rhs) && (zero_expr_text(lhs) || zero_expr_text(rhs))) {
        simplified = "0";
        proof = "and_zero_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "|", lhs, rhs) && zero_expr_text(rhs)) {
        simplified = lhs;
        proof = "or_zero_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "|", lhs, rhs) && zero_expr_text(lhs)) {
        simplified = rhs;
        proof = "or_zero_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "+", lhs, rhs) && zero_expr_text(rhs)) {
        simplified = lhs;
        proof = "add_zero_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "+", lhs, rhs) && zero_expr_text(lhs)) {
        simplified = rhs;
        proof = "add_zero_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "*", lhs, rhs) && one_expr_text(rhs)) {
        simplified = lhs;
        proof = "mul_one_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "*", lhs, rhs) && one_expr_text(lhs)) {
        simplified = rhs;
        proof = "mul_one_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "<<", lhs, rhs) && one_expr_text(rhs)) {
        simplified = lhs + " * 2";
        proof = "shift_left_one_identity";
        changed = true;
        verified = true;
    } else if (split_top_level_expr(normalized, "+", lhs, rhs) && one_expr_text(rhs) && !lhs.empty() && lhs.front() == '~') {
        simplified = "-" + strip_outer_expr(lhs.substr(1));
        proof = "twos_complement_negation_identity";
        changed = true;
        verified = true;
    }
    json out;
    out["original_expr"] = expr;
    out["normalized_expr"] = normalized;
    out["simplified_expr"] = simplified;
    out["changed"] = changed;
    out["verified"] = verified;
    out["identity_match"] = verified;
    out["proof_method"] = proof;
    out["confidence"] = verified ? 1.0 : 0.35;
    out["tool"] = "obf_simplify_expr";
    out["input_bytes"] = expr.size();
    return tool_result_t::ok("Expression simplification completed", out);
}

inline std::string sanitize_symbol_component(std::string s)
{
    s = lower_ascii(trim_ascii(s));
    std::string out;
    out.reserve(s.size());
    bool last_underscore = false;
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalnum(u)) {
            out.push_back(static_cast<char>(u));
            last_underscore = false;
        } else if (!last_underscore) {
            out.push_back('_');
            last_underscore = true;
        }
    }
    while (!out.empty() && out.front() == '_')
        out.erase(out.begin());
    while (!out.empty() && out.back() == '_')
        out.pop_back();
    if (out.empty())
        out = "symbol";
    if (std::isdigit(static_cast<unsigned char>(out.front())))
        out.insert(out.begin(), '_');
    return out;
}

inline std::string rename_prefix_for_symbol(const json& sym)
{
    std::string basis;
    for (const char* k : { "role", "classification", "reason", "kind", "type", "name" }) {
        if (sym.contains(k) && sym[k].is_string()) {
            basis += " ";
            basis += sym[k].get<std::string>();
        }
    }
    const std::string b = lower_ascii(basis);
    if (b.find("decrypt") != std::string::npos)
        return "decryptor";
    if (b.find("vm") != std::string::npos || b.find("virtual") != std::string::npos)
        return "vm_handler";
    if (b.find("ioctl") != std::string::npos)
        return "ioctl_dispatch";
    if (b.find("opaque") != std::string::npos)
        return "opaque_predicate";
    if (b.find("pack") != std::string::npos || b.find("oep") != std::string::npos)
        return "packer";
    if (b.find("mba") != std::string::npos)
        return "mba_expr";
    return sanitize_symbol_component(basis);
}

inline tool_result_t obf_rename_symbols(const json& params)
{
    if (params.value("apply", false) || unsafe_confirmed(params))
        return tool_result_t::error("obf_rename_symbols is read-only in standalone protected RE mode; no symbol database mutation backend is exposed.", json{{"applied", false}, {"requested_apply", params.value("apply", false)}, {"mutation", "none"}, {"symbol_count", params.contains("symbols") && params["symbols"].is_array() ? params["symbols"].size() : 0}, {"security_contract", "fail_closed_no_symbol_mutation"}, {"safe_contract", "fail_closed_no_symbol_mutation"}});
    if (!params.contains("symbols") || !params["symbols"].is_array())
        return tool_result_t::error("symbols array is required");
    json renames = json::array();
    for (const auto& sym : params["symbols"]) {
        if (!sym.is_object())
            continue;
        auto va = parse_u64_json(sym.value("va", json()));
        if (!va)
            va = parse_u64_json(sym.value("address", json()));
        const std::string current = sym.value("name", std::string());
        const std::string prefix = sanitize_symbol_component(rename_prefix_for_symbol(sym));
        char suffix[32] = {};
        std::snprintf(suffix, sizeof(suffix), "%04llX", static_cast<unsigned long long>((va.value_or(0) >> 4) & 0xFFFFULL));
        renames.push_back(json{{"va", va ? sa_format_address(*va) : "unknown"}, {"old_name", current}, {"new_name", prefix + "_" + suffix}, {"applied", false}, {"confidence", va ? 0.72 : 0.45}, {"source", "protected_re_semantic_plan"}});
        if (renames.size() >= 256)
            break;
    }
    const std::size_t symbol_count = params["symbols"].is_array() ? params["symbols"].size() : 0;
    return tool_result_t::ok("Symbol rename plan generated without mutation", json{{"renames", renames}, {"count", renames.size()}, {"symbol_count", symbol_count}, {"renames_truncated", symbol_count > renames.size()}, {"applied", false}, {"mutation", "none"}, {"safe_contract", "read_only_rename_plan"}});
}

inline tool_result_t opaque_predicate_detect(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto address = parse_param_u64(params, "address");
    if (!address)
        return tool_result_t::error("address is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t size = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "size").value_or(32768)), 16, 0x20000);
    auto insns = disassemble_target(pid, *address, size, 8192);
    json preds = json::array();
    for (std::size_t i = 1; i < insns.size(); ++i) {
        const auto& br = insns[i];
        if (!is_conditional_branch(br))
            continue;
        const auto& prev = insns[i - 1];
        const std::string pm = mnemonic_of(prev);
        const std::string bm = mnemonic_of(br);
        auto ops = split_operands(prev.ops);
        std::optional<std::string> result;
        if ((pm == "cmp" || pm == "sub" || pm == "xor") && ops.size() >= 2 && lower_ascii(ops[0]) == lower_ascii(ops[1])) {
            if (bm == "je" || bm == "jz" || bm == "jbe" || bm == "jle")
                result = "always_true";
            else if (bm == "jne" || bm == "jnz" || bm == "ja" || bm == "jg")
                result = "always_false";
        }
        if (pm == "cmp" && ops.size() >= 2) {
            auto a = parse_hex_in_text(ops[0]);
            auto b = parse_hex_in_text(ops[1]);
            if (a && b && *a == *b) {
                if (bm == "je" || bm == "jz")
                    result = "always_true";
                else if (bm == "jne" || bm == "jnz")
                    result = "always_false";
            }
        }
        if (!result)
            continue;
        const std::uint64_t fallthrough = br.addr + static_cast<std::uint64_t>(std::max(br.len, 1));
        const bool true_branch_taken = *result == "always_true";
        const std::uint64_t dead = true_branch_taken ? fallthrough : br.branch_target;
        preds.push_back(json{{"va", sa_format_address(br.addr)}, {"condition_expr", std::string(prev.mnem) + " " + prev.ops}, {"result", *result}, {"dead_branch_va", sa_format_address(dead)}, {"taken_branch_va", sa_format_address(true_branch_taken ? br.branch_target : fallthrough)}, {"proof_method", "syntactic_identity"}, {"confidence", 0.9}, {"instruction_length", br.len}});
    }
    json out;
    out["predicates"] = preds;
    out["count"] = preds.size();
    return tool_result_t::ok("Opaque predicate detection completed", out);
}

inline std::optional<std::vector<std::uint8_t>> patch_bytes_for_predicate(std::uint32_t pid, const json& pred)
{
    auto va = parse_u64_json(pred.value("va", json()));
    if (!va)
        return std::nullopt;
    auto insns = disassemble_target(pid, *va, 16, 1);
    if (insns.empty())
        return std::nullopt;
    const AsmInstr& ins = insns.front();
    const int len = std::max(ins.len, 1);
    const std::string result = pred.value("result", std::string());
    if (result == "always_false")
        return std::vector<std::uint8_t>(static_cast<std::size_t>(len), 0x90);
    if (result != "always_true" || ins.branch_target == 0)
        return std::nullopt;
    std::vector<std::uint8_t> patch(static_cast<std::size_t>(len), 0x90);
    const std::int64_t rel8 = static_cast<std::int64_t>(ins.branch_target) - static_cast<std::int64_t>(*va + 2);
    if (len >= 2 && rel8 >= -128 && rel8 <= 127) {
        patch[0] = 0xEB;
        patch[1] = static_cast<std::uint8_t>(rel8 & 0xFF);
        return patch;
    }
    const std::int64_t rel32 = static_cast<std::int64_t>(ins.branch_target) - static_cast<std::int64_t>(*va + 5);
    if (len >= 5 && rel32 >= std::numeric_limits<std::int32_t>::min() && rel32 <= std::numeric_limits<std::int32_t>::max()) {
        patch[0] = 0xE9;
        const auto r = static_cast<std::int32_t>(rel32);
        std::memcpy(patch.data() + 1, &r, sizeof(r));
        return patch;
    }
    return std::nullopt;
}

inline tool_result_t opaque_predicate_patch(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    if (!unsafe_confirmed(params))
        return tool_result_t::error("opaque_predicate_patch mutates target code. Re-run with confirm_unsafe=true or allow_unsafe=true.",
            destructive_safe_contract_payload("opaque_predicate_patch", "patch", params, "confirm_unsafe_required", "code_patch_revalidation_and_explicit_user_confirmation"));
    if (!params.contains("predicates") || !params["predicates"].is_array())
    {
        json out = destructive_safe_contract_payload("opaque_predicate_patch", "patch", params, "predicates_array_required", "code_patch_revalidation_and_explicit_user_confirmation");
        out["confirm_unsafe_received"] = unsafe_confirmed(params);
        return tool_result_t::error("predicates array is required", out);
    }
    const std::uint32_t pid = requested_pid(params);
    active_pid_scope_t scope(pid);
    if (!scope.ok)
        return tool_result_t::error("Could not set active process for patching");
    json log = json::array();
    int patched = 0;
    for (const auto& pred : params["predicates"]) {
        auto va = parse_u64_json(pred.value("va", json()));
        if (!va)
            continue;
        const std::uint64_t verify_base = *va > 32 ? *va - 32 : *va;
        auto verified_scan = opaque_predicate_detect(json{{"address", sa_format_address(verify_base)}, {"size", 96}, {"process_id", pid}});
        bool still_proven = false;
        if (verified_scan.success && verified_scan.data.contains("predicates") && verified_scan.data["predicates"].is_array()) {
            for (const auto& p : verified_scan.data["predicates"]) {
                auto pva = parse_u64_json(p.value("va", json()));
                if (pva && *pva == *va && p.value("result", std::string()) == pred.value("result", std::string())) {
                    still_proven = true;
                    break;
                }
            }
        }
        if (!still_proven) {
            log.push_back(json{{"va", sa_format_address(*va)}, {"applied", false}, {"skipped", true}, {"reason", "predicate_not_reproven_before_patch"}, {"verification", verified_scan.data}});
            continue;
        }
        auto patch = patch_bytes_for_predicate(pid, pred);
        if (!patch) {
            log.push_back(json{{"va", sa_format_address(*va)}, {"applied", false}, {"skipped", true}, {"reason", "patch_bytes_unavailable_after_validation"}});
            continue;
        }
        std::vector<std::uint8_t> before;
        read_target_memory(pid, *va, patch->size(), before);
        const std::string desc = "opaque_predicate_patch " + pred.value("result", std::string("unknown"));
        const int idx = code_patcher::create_patch(*va, *patch, desc);
        bool ok = idx >= 0 && code_patcher::apply_patch(idx);
        std::vector<std::uint8_t> after;
        if (ok)
            read_target_memory(pid, *va, patch->size(), after);
        if (ok)
            ++patched;
        log.push_back(json{{"va", sa_format_address(*va)}, {"action", pred.value("result", std::string()) == "always_true" ? "replace_with_unconditional_jump" : "nop_conditional_jump"}, {"patch_index", idx}, {"applied", ok}, {"validation", "predicate_reproven_before_patch"}, {"original_bytes", bytes_to_hex(before)}, {"patch_bytes", bytes_to_hex(*patch)}, {"after_bytes", bytes_to_hex(after)}, {"after_matches_patch", ok && after == *patch}});
    }
    json out;
    out["patched_count"] = patched;
    out["patch_log"] = log;
    return patched ? tool_result_t::ok("Opaque predicate patches applied", out) : tool_result_t::error("No opaque predicates were patched", out);
}

inline tool_result_t bogus_block_remove(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto address = parse_param_u64(params, "address");
    if (!address)
        return tool_result_t::error("address is required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint32_t size = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "size").value_or(32768)), 16, 0x20000);
    auto insns = disassemble_target(pid, *address, size, 8192);
    auto blocks = build_blocks(insns);
    std::set<int> reachable;
    std::vector<int> work;
    if (!blocks.empty())
        work.push_back(0);
    while (!work.empty()) {
        int id = work.back();
        work.pop_back();
        if (!reachable.insert(id).second)
            continue;
        if (id < 0 || id >= static_cast<int>(blocks.size()))
            continue;
        for (int s : blocks[static_cast<std::size_t>(id)].successors)
            work.push_back(s);
    }
    json dead = json::array();
    for (const auto& b : blocks) {
        if (!reachable.count(b.id))
            dead.push_back(json{{"block_va", sa_format_address(b.start)}, {"size", b.end > b.start ? b.end - b.start : 0}, {"reason", "unreachable_from_entry"}});
    }
    json od = opaque_predicate_detect(json{{"address", sa_format_address(*address)}, {"size", size}, {"process_id", pid}}).data;
    if (od.contains("predicates")) {
        for (const auto& p : od["predicates"])
            dead.push_back(json{{"block_va", p.value("dead_branch_va", std::string("unknown"))}, {"size", 0}, {"reason", "opaque_guard"}, {"predicate_va", p.value("va", std::string("unknown"))}});
    }
    json out;
    out["blocks"] = dead;
    out["count"] = dead.size();
    out["note"] = "No target mutation was performed; returned blocks are candidates for annotation or later patching.";
    return tool_result_t::ok("Bogus block analysis completed", out);
}

inline std::string irp_name(std::uint32_t code)
{
    static const std::array<const char*, 28> names = {
        "IRP_MJ_CREATE","IRP_MJ_CREATE_NAMED_PIPE","IRP_MJ_CLOSE","IRP_MJ_READ",
        "IRP_MJ_WRITE","IRP_MJ_QUERY_INFORMATION","IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA","IRP_MJ_SET_EA","IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION","IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL","IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL","IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN","IRP_MJ_LOCK_CONTROL","IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT","IRP_MJ_QUERY_SECURITY","IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER","IRP_MJ_SYSTEM_CONTROL","IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA","IRP_MJ_SET_QUOTA","IRP_MJ_PNP"
    };
    return code < names.size() ? names[code] : "IRP_MJ_UNKNOWN";
}

inline json target_module_json(const target_module_t& mod)
{
    return json{{"name", mod.name},
                {"path", mod.path},
                {"base", sa_format_address(mod.base)},
                {"size", mod.size},
                {"end", sa_format_address(mod.base + mod.size)},
                {"kernel", mod.kernel}};
}

inline json mapped_section_json(const mapped_section_t& sec)
{
    return json{{"name", sec.name},
                {"va", sa_format_address(sec.va)},
                {"virtual_size", sec.virtual_size},
                {"raw_size", sec.raw_size},
                {"raw_pointer", sa_format_address(sec.raw_pointer)},
                {"characteristics", sa_format_address(sec.characteristics)},
                {"executable", executable_characteristics(sec.characteristics)}};
}

inline const mapped_section_t* section_for_absolute_va(const pe_layout_t& pe, std::uint64_t va)
{
    for (const auto& sec : pe.sections) {
        const std::uint64_t size = std::max<std::uint64_t>(sec.virtual_size, sec.raw_size);
        if (size && va >= sec.va && va < sec.va + size)
            return &sec;
    }
    return nullptr;
}

inline json section_evidence_for_va(const pe_layout_t& pe, std::uint64_t va)
{
    const mapped_section_t* sec = section_for_absolute_va(pe, va);
    if (!sec)
        return json{{"found", false}};
    json out = mapped_section_json(*sec);
    out["found"] = true;
    out["rva"] = va >= pe.base ? json(sa_format_address(va - pe.base)) : json(nullptr);
    out["offset"] = sa_format_address(va - sec->va);
    return out;
}

inline json memory_protection_evidence(std::uint32_t pid, std::uint64_t va)
{
    if (va == 0)
        return json{{"queried", false}, {"reason", "zero_address"}};
    if (is_kernel_address(va))
        return json{{"queried", false}, {"reason", "kernel_address_not_queryable_from_user_mode"}, {"protect", "unknown"}};
    driver_bridge::memory_region_t region{};
    if (!driver_bridge::query_memory_for(pid, va, region))
        return json{{"queried", false}, {"reason", "query_failed"}, {"protect", "unknown"}};
    return json{{"queried", true},
                {"base", sa_format_address(region.base)},
                {"size", region.size},
                {"state", sa_format_address(region.state)},
                {"protect", protection_name(region.protect)},
                {"protect_raw", sa_format_address(region.protect)},
                {"type", sa_format_address(region.type)},
                {"executable", executable_protect(region.protect)}};
}

inline bool module_is_ntoskrnl(const target_module_t& mod)
{
    const std::string name = lower_ascii(mod.name);
    const std::string path = lower_ascii(mod.path);
    return name.find("ntoskrnl") != std::string::npos || path.find("ntoskrnl") != std::string::npos;
}

inline void increment_json_counter(json& object, const std::string& key)
{
    std::uint64_t value = 0;
    if (object.is_object() && object.contains(key) && object[key].is_number_unsigned())
        value = object[key].get<std::uint64_t>();
    object[key] = value + 1;
}

inline bool ends_with_ascii(const std::string& value, const char* suffix)
{
    if (!suffix)
        return false;
    const std::string lower_value = lower_ascii(value);
    const std::string lower_suffix = lower_ascii(suffix);
    return lower_value.size() >= lower_suffix.size() &&
           lower_value.compare(lower_value.size() - lower_suffix.size(), lower_suffix.size(), lower_suffix) == 0;
}

inline std::string kernel_auto_select_skip_reason(const target_module_t& mod)
{
    const std::string name = lower_ascii(mod.name);
    const std::string path = lower_ascii(mod.path);
    if (mod.base == 0)
        return "zero_module_base";
    if (mod.size < 0x1000)
        return "module_too_small";
    if (module_is_ntoskrnl(mod))
        return "kernel_image_not_wdm_driver";
    if (!ends_with_ascii(name, ".sys") && !ends_with_ascii(path, ".sys"))
        return "support_kernel_image_not_sys_driver";
    if (name.find("win32k") == 0)
        return "win32k_graphics_kernel_image";
    if (path.find("\\system32\\") != std::string::npos &&
        path.find("\\system32\\drivers\\") == std::string::npos &&
        path.find("\\sysnative\\drivers\\") == std::string::npos)
        return "system32_support_sys_not_driver_directory";
    return {};
}

inline int kernel_auto_select_priority(const target_module_t& mod)
{
    const std::string name = lower_ascii(mod.name);
    const std::string path = lower_ascii(mod.path);
    int score = 1000;
    if (name.find("aida") != std::string::npos ||
        name.find("whoswho") != std::string::npos ||
        name.find("sentinel") != std::string::npos ||
        name.find("test") != std::string::npos)
        score -= 500;
    if (path.find("\\system32\\drivers\\") != std::string::npos || path.find("\\sysnative\\drivers\\") != std::string::npos)
        score -= 250;
    if (path.find("\\systemroot\\") == std::string::npos && path.find("\\windows\\") == std::string::npos)
        score -= 150;
    if (mod.size && mod.size <= 8ull * 1024ull * 1024ull)
        score -= 50;
    if (name.find("flt") != std::string::npos || name.find("kbd") != std::string::npos || name.find("mou") != std::string::npos)
        score -= 10;
    return score;
}

inline json handler_plausibility(std::uint32_t pid, const target_module_t& mod, const pe_layout_t& pe, std::uint64_t handler)
{
    json out;
    out["handler_va"] = handler ? json(sa_format_address(handler)) : json(nullptr);
    if (handler == 0) {
        out["plausible"] = false;
        out["reason"] = "unresolved_handler";
        return out;
    }
    const std::uint64_t module_end = mod.base + std::max<std::uint64_t>(mod.size, pe.size_of_image);
    const bool inside_module = handler >= mod.base && handler < module_end;
    out["inside_selected_module"] = inside_module;
    out["section"] = section_evidence_for_va(pe, handler);
    out["protection"] = memory_protection_evidence(pid, handler);
    if (!inside_module) {
        out["plausible"] = false;
        out["reason"] = "handler_outside_selected_driver_module";
        return out;
    }
    const mapped_section_t* sec = section_for_absolute_va(pe, handler);
    if (!sec) {
        out["plausible"] = false;
        out["reason"] = "handler_not_in_any_pe_section";
        return out;
    }
    if (!executable_characteristics(sec->characteristics)) {
        out["plausible"] = false;
        out["reason"] = "handler_section_not_executable";
        return out;
    }
    out["plausible"] = true;
    out["reason"] = "handler_inside_executable_driver_section";
    return out;
}

inline std::optional<std::uint64_t> resolve_last_register_value(const std::map<std::string, std::uint64_t>& regs, const std::string& reg)
{
    auto it = regs.find(lower_ascii(reg));
    if (it == regs.end())
        return std::nullopt;
    return it->second;
}

inline bool dispatch_assignment_less(const json& a, const json& b)
{
    const std::uint32_t ai = a.value("irp_code", 0u);
    const std::uint32_t bi = b.value("irp_code", 0u);
    if (ai != bi)
        return ai < bi;
    const std::string av = a.value("assignment_va", std::string());
    const std::string bv = b.value("assignment_va", std::string());
    if (av != bv)
        return av < bv;
    return a.value("handler_va", std::string()) < b.value("handler_va", std::string());
}

inline json dispatch_accepted_slots_json(const json& assignments)
{
    json slots = json::array();
    if (!assignments.is_array())
        return slots;
    for (const auto& a : assignments) {
        slots.push_back(json{{"irp_code", a.value("irp_code", 0u)},
                             {"irp_name", a.value("irp_name", std::string("IRP_MJ_UNKNOWN"))},
                             {"handler_va", a.value("handler_va", json(nullptr))},
                             {"assignment_va", a.value("assignment_va", json(nullptr))}});
    }
    return slots;
}

inline bool drv_add_signed_offset(std::uint64_t base, std::int64_t disp, std::uint64_t& out)
{
    if (disp >= 0) {
        const std::uint64_t udisp = static_cast<std::uint64_t>(disp);
        if (base > std::numeric_limits<std::uint64_t>::max() - udisp)
            return false;
        out = base + udisp;
        return true;
    }
    const std::uint64_t magnitude = static_cast<std::uint64_t>(-(disp + 1)) + 1;
    if (base < magnitude)
        return false;
    out = base - magnitude;
    return true;
}

inline json driver_object_assignment_evidence(const AsmInstr& ins,
                                             const std::map<std::string, std::uint64_t>& reg_values,
                                             std::int64_t disp)
{
    json ev;
    const std::string base_reg = drv_gpr_name(ins.mem_op.base_reg);
    const std::string index_reg = drv_gpr_name(ins.mem_op.index_reg);
    ev["memory_base_register"] = base_reg.empty() ? "none" : base_reg;
    ev["memory_index_register"] = index_reg.empty() ? "none" : index_reg;
    ev["memory_displacement"] = disp;
    ev["major_function_offset"] = sa_format_address(static_cast<std::uint64_t>(disp));
    ev["assignment_instruction"] = instruction_to_json(ins);
    ev["driver_object_source"] = base_reg == "rcx" ? "driver_entry_rcx_argument" : (base_reg.empty() ? "unresolved" : "tracked_register_or_alias");
    ev["dispatch_table_va_known"] = false;
    ev["dispatch_slot_va"] = nullptr;
    ev["driver_object_va"] = nullptr;
    if (!base_reg.empty()) {
        if (auto base = resolve_last_register_value(reg_values, base_reg)) {
            std::uint64_t slot_va = 0;
            if (drv_add_signed_offset(*base, disp, slot_va)) {
                ev["driver_object_va"] = sa_format_address(*base);
                ev["dispatch_slot_va"] = sa_format_address(slot_va);
                ev["dispatch_table_va"] = sa_format_address(*base + 0x70);
                ev["dispatch_table_va_known"] = true;
                ev["driver_object_source"] = "tracked_register_constant";
            }
        }
    }
    if (!ev.value("dispatch_table_va_known", false))
        ev["dispatch_table_va"] = "driver_object+0x70";
    return ev;
}

inline json apply_explicit_driver_object_to_assignments(json& assignments, std::uint64_t driver_object_va)
{
    json evidence;
    evidence["driver_object_va"] = sa_format_address(driver_object_va);
    evidence["dispatch_table_va"] = sa_format_address(driver_object_va + 0x70);
    evidence["source"] = "explicit_driver_object_va_parameter";
    evidence["slot_count_updated"] = 0;
    if (!assignments.is_array() || driver_object_va == 0)
        return evidence;
    std::size_t updated = 0;
    for (auto& a : assignments) {
        if (!a.is_object())
            continue;
        const std::uint32_t irp = a.value("irp_code", 0u);
        const std::uint64_t slot = driver_object_va + 0x70 + static_cast<std::uint64_t>(irp) * 8ull;
        a["driver_object_va"] = sa_format_address(driver_object_va);
        a["dispatch_table_va"] = sa_format_address(driver_object_va + 0x70);
        a["dispatch_slot_va"] = sa_format_address(slot);
        a["dispatch_table_va_source"] = "explicit_driver_object_va_parameter";
        ++updated;
    }
    evidence["slot_count_updated"] = updated;
    return evidence;
}

inline json driver_entry_evidence_json(std::uint32_t pid, const target_module_t& mod, const pe_layout_t& pe, const json& diagnostics)
{
    json ev;
    ev["driver_entry_va"] = sa_format_address(pe.entry);
    ev["driver_entry_rva"] = pe.entry >= pe.base ? json(sa_format_address(pe.entry - pe.base)) : json(nullptr);
    ev["entry_section"] = section_evidence_for_va(pe, pe.entry);
    ev["entry_protection"] = memory_protection_evidence(pid, pe.entry);
    ev["module"] = target_module_json(mod);
    ev["scan_window"] = diagnostics.value("scan_window", json::object());
    ev["instructions_decoded"] = diagnostics.value("instructions_decoded", 0);
    ev["accepted_assignment_count"] = diagnostics.value("accepted_assignment_count", 0);
    ev["candidate_count"] = diagnostics.value("candidate_count", 0);
    ev["accepted_slots"] = diagnostics.value("accepted_slots", json::array());
    return ev;
}

struct drv_dispatch_scan_limits_t {
    std::uint32_t timeout_ms = 5000;
    std::uint32_t max_entry_bytes = 0x8000;
    std::uint32_t max_entry_instructions = 4096;
    std::size_t max_candidates = 64;
    std::size_t max_breadcrumbs = 160;
};

struct drv_dispatch_scan_context_t {
    drv_dispatch_scan_limits_t limits;
    ULONGLONG started = GetTickCount64();
    bool deadline_hit = false;
    bool cancelled = false;
    bool stop_logged = false;
    std::string stage = "entry";
    json breadcrumbs = json::array();

    explicit drv_dispatch_scan_context_t(const drv_dispatch_scan_limits_t& in_limits)
        : limits(in_limits)
    {
    }

    ULONGLONG elapsed_ms() const
    {
        return GetTickCount64() - started;
    }

    bool should_stop(const char* next_stage)
    {
        if (next_stage)
            stage = next_stage;
        if (!cancelled && mcp_standalone::current_call_cancelled())
            cancelled = true;
        if (!deadline_hit && limits.timeout_ms != 0 && elapsed_ms() >= limits.timeout_ms)
            deadline_hit = true;
        if ((deadline_hit || cancelled) && !stop_logged) {
            stop_logged = true;
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch budget_exit stage=%s elapsed_ms=%llu timeout_ms=%u deadline_hit=%d cancelled=%d",
                stage.c_str(),
                static_cast<unsigned long long>(elapsed_ms()),
                limits.timeout_ms,
                deadline_hit ? 1 : 0,
                cancelled ? 1 : 0);
        }
        return deadline_hit || cancelled;
    }

    void record(const char* event, json data)
    {
        data["event"] = event ? event : "";
        data["stage"] = stage;
        data["elapsed_ms"] = elapsed_ms();
        data["deadline_hit"] = deadline_hit;
        data["cancelled"] = cancelled;
        if (breadcrumbs.size() < limits.max_breadcrumbs)
            breadcrumbs.push_back(std::move(data));
    }

    json status() const
    {
        return json{{"timeout_ms", limits.timeout_ms},
                    {"elapsed_ms", elapsed_ms()},
                    {"deadline_hit", deadline_hit},
                    {"cancelled", cancelled},
                    {"stage", stage},
                    {"max_entry_bytes", limits.max_entry_bytes},
                    {"max_entry_instructions", limits.max_entry_instructions},
                    {"max_candidates", limits.max_candidates}};
    }
};

inline drv_dispatch_scan_limits_t drv_dispatch_limits_from_params(const json& params)
{
    drv_dispatch_scan_limits_t limits;
    if (auto v = parse_param_u64(params, "timeout_ms"))
        limits.timeout_ms = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(*v, 250, 30000));
    if (auto v = parse_param_u64(params, "max_entry_bytes"))
        limits.max_entry_bytes = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(*v, 0x1000, 0x10000));
    else if (auto v = parse_param_u64(params, "entry_scan_bytes"))
        limits.max_entry_bytes = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(*v, 0x1000, 0x10000));
    if (auto v = parse_param_u64(params, "max_entry_instructions"))
        limits.max_entry_instructions = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(*v, 64, 8192));
    if (auto v = parse_param_u64(params, "max_candidates"))
        limits.max_candidates = static_cast<std::size_t>(std::clamp<std::uint64_t>(*v, 1, 512));
    return limits;
}

inline bool read_pe_layout_with_dispatch_diag(std::uint32_t pid,
                                              const target_module_t& mod,
                                              pe_layout_t& pe,
                                              drv_dispatch_scan_context_t& ctx,
                                              json& summary)
{
    summary["pe_read_start_elapsed_ms"] = ctx.elapsed_ms();
    ctx.record("pe_read_start", json{{"module", mod.name}, {"base", sa_format_address(mod.base)}, {"size", mod.size}, {"path", mod.path}});
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch pe_read_start module=%s base=0x%llX size=%llu path=%s elapsed_ms=%llu",
        mod.name.c_str(),
        static_cast<unsigned long long>(mod.base),
        static_cast<unsigned long long>(mod.size),
        mod.path.c_str(),
        static_cast<unsigned long long>(ctx.elapsed_ms()));
    if (ctx.should_stop("pe_read_before")) {
        summary["pe_read_ok"] = false;
        summary["rejection_reason"] = ctx.cancelled ? "cancelled_before_pe_read" : "deadline_before_pe_read";
        return false;
    }
    const ULONGLONG t0 = GetTickCount64();
    const bool ok = read_pe_layout(pid, mod.base, pe);
    const ULONGLONG elapsed = GetTickCount64() - t0;
    summary["pe_read_ok"] = ok;
    summary["pe_read_elapsed_ms"] = elapsed;
    if (ok) {
        summary["entry_va"] = sa_format_address(pe.entry);
        summary["size_of_image"] = pe.size_of_image;
        summary["section_count"] = pe.sections.size();
    }
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch pe_read_end module=%s ok=%d pe_elapsed_ms=%llu entry=0x%llX sections=%zu total_elapsed_ms=%llu",
        mod.name.c_str(),
        ok ? 1 : 0,
        static_cast<unsigned long long>(elapsed),
        static_cast<unsigned long long>(ok ? pe.entry : 0),
        ok ? pe.sections.size() : 0,
        static_cast<unsigned long long>(ctx.elapsed_ms()));
    ctx.record("pe_read_end", json{{"module", mod.name}, {"ok", ok}, {"pe_elapsed_ms", elapsed}, {"entry_va", ok ? json(sa_format_address(pe.entry)) : json(nullptr)}, {"section_count", ok ? pe.sections.size() : 0}});
    ctx.should_stop("pe_read_after");
    return ok;
}

inline std::vector<AsmInstr> disassemble_driver_entry_bounded(std::uint32_t pid,
                                                              const target_module_t& mod,
                                                              const pe_layout_t& pe,
                                                              drv_dispatch_scan_context_t& ctx,
                                                              json& diagnostics)
{
    std::vector<AsmInstr> out;
    const std::uint32_t bytes_to_read = std::clamp<std::uint32_t>(ctx.limits.max_entry_bytes, 0x1000, 0x10000);
    const std::uint32_t max_insns = std::clamp<std::uint32_t>(ctx.limits.max_entry_instructions, 64, 8192);
    diagnostics["scan_window"] = json{{"base", sa_format_address(pe.entry)}, {"size", bytes_to_read}, {"end", sa_format_address(pe.entry + bytes_to_read)}};
    diagnostics["disassembly"] = json{{"max_entry_bytes", bytes_to_read}, {"max_entry_instructions", max_insns}};
    ctx.record("disassembly_start", json{{"module", mod.name}, {"entry", sa_format_address(pe.entry)}, {"bytes", bytes_to_read}, {"max_insns", max_insns}});
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch disasm_start module=%s entry=0x%llX bytes=%u max_insns=%u elapsed_ms=%llu",
        mod.name.c_str(),
        static_cast<unsigned long long>(pe.entry),
        bytes_to_read,
        max_insns,
        static_cast<unsigned long long>(ctx.elapsed_ms()));
    if (ctx.should_stop("driver_entry_disasm_before_read"))
        return out;
    std::vector<std::uint8_t> raw;
    const ULONGLONG read_t0 = GetTickCount64();
    const bool read_ok = read_target_memory(pid, pe.entry, bytes_to_read, raw);
    const ULONGLONG read_elapsed = GetTickCount64() - read_t0;
    diagnostics["disassembly"]["read_ok"] = read_ok;
    diagnostics["disassembly"]["read_elapsed_ms"] = read_elapsed;
    diagnostics["disassembly"]["bytes_read"] = raw.size();
    if (!read_ok || raw.empty()) {
        diagnostics["disassembly"]["rejection_reason"] = read_ok ? "entry_read_empty" : "entry_read_failed";
        ctx.record("disassembly_read_failed", json{{"module", mod.name}, {"read_ok", read_ok}, {"bytes_read", raw.size()}, {"read_elapsed_ms", read_elapsed}});
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch disasm_read_failed module=%s read_ok=%d bytes_read=%zu read_elapsed_ms=%llu total_elapsed_ms=%llu",
            mod.name.c_str(),
            read_ok ? 1 : 0,
            raw.size(),
            static_cast<unsigned long long>(read_elapsed),
            static_cast<unsigned long long>(ctx.elapsed_ms()));
        ctx.should_stop("driver_entry_disasm_after_read_failed");
        return out;
    }
    if (ctx.should_stop("driver_entry_disasm_after_read"))
        return out;
    std::size_t off = 0;
    while (off < raw.size() && out.size() < max_insns) {
        if ((out.size() & 0x7fu) == 0 && ctx.should_stop("driver_entry_disasm_loop"))
            break;
        const int avail = static_cast<int>(std::min<std::size_t>(15, raw.size() - off));
        AsmInstr ins = zydis_decode_one(raw.data() + off, avail, pe.entry + off);
        if (ins.len <= 0)
            ins.len = 1;
        out.push_back(ins);
        off += static_cast<std::size_t>(ins.len);
    }
    diagnostics["disassembly"]["instructions_decoded"] = out.size();
    diagnostics["disassembly"]["bytes_consumed"] = off;
    diagnostics["disassembly"]["instruction_limit_hit"] = out.size() >= max_insns;
    diagnostics["disassembly"]["deadline_hit"] = ctx.deadline_hit;
    diagnostics["disassembly"]["cancelled"] = ctx.cancelled;
    ctx.record("disassembly_end", json{{"module", mod.name}, {"instructions_decoded", out.size()}, {"bytes_consumed", off}, {"instruction_limit_hit", out.size() >= max_insns}});
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch disasm_end module=%s decoded=%zu bytes_consumed=%zu limit_hit=%d deadline_hit=%d cancelled=%d elapsed_ms=%llu",
        mod.name.c_str(),
        out.size(),
        off,
        out.size() >= max_insns ? 1 : 0,
        ctx.deadline_hit ? 1 : 0,
        ctx.cancelled ? 1 : 0,
        static_cast<unsigned long long>(ctx.elapsed_ms()));
    return out;
}

inline std::vector<AsmInstr> disassemble_driver_entry_image_bounded(const std::vector<std::uint8_t>& image,
                                                                    const target_module_t& mod,
                                                                    const pe_layout_t& pe,
                                                                    drv_dispatch_scan_context_t& ctx,
                                                                    json& diagnostics)
{
    std::vector<AsmInstr> out;
    const std::uint32_t bytes_to_read = std::clamp<std::uint32_t>(ctx.limits.max_entry_bytes, 0x1000, 0x10000);
    const std::uint32_t max_insns = std::clamp<std::uint32_t>(ctx.limits.max_entry_instructions, 64, 8192);
    diagnostics["scan_window"] = json{{"base", sa_format_address(pe.entry)}, {"size", bytes_to_read}, {"end", sa_format_address(pe.entry + bytes_to_read)}};
    diagnostics["disassembly"] = json{{"max_entry_bytes", bytes_to_read}, {"max_entry_instructions", max_insns}, {"source", "static_pe_image"}};
    ctx.record("static_disassembly_start", json{{"module", mod.name}, {"entry", sa_format_address(pe.entry)}, {"bytes", bytes_to_read}, {"max_insns", max_insns}});
    if (ctx.should_stop("static_driver_entry_disasm_before_read"))
        return out;
    std::vector<std::uint8_t> raw;
    const bool read_ok = read_image_va_bytes(image, pe, pe.entry, bytes_to_read, raw);
    diagnostics["disassembly"]["read_ok"] = read_ok;
    diagnostics["disassembly"]["bytes_read"] = raw.size();
    if (!read_ok || raw.empty()) {
        diagnostics["disassembly"]["rejection_reason"] = read_ok ? "entry_read_empty" : "entry_read_failed";
        ctx.record("static_disassembly_read_failed", json{{"module", mod.name}, {"read_ok", read_ok}, {"bytes_read", raw.size()}});
        ctx.should_stop("static_driver_entry_disasm_after_read_failed");
        return out;
    }
    std::size_t off = 0;
    while (off < raw.size() && out.size() < max_insns) {
        if ((out.size() & 0x7fu) == 0 && ctx.should_stop("static_driver_entry_disasm_loop"))
            break;
        const int avail = static_cast<int>(std::min<std::size_t>(15, raw.size() - off));
        AsmInstr ins = zydis_decode_one(raw.data() + off, avail, pe.entry + off);
        if (ins.len <= 0)
            ins.len = 1;
        out.push_back(ins);
        off += static_cast<std::size_t>(ins.len);
    }
    diagnostics["disassembly"]["instructions_decoded"] = out.size();
    diagnostics["disassembly"]["bytes_consumed"] = off;
    diagnostics["disassembly"]["instruction_limit_hit"] = out.size() >= max_insns;
    diagnostics["disassembly"]["deadline_hit"] = ctx.deadline_hit;
    diagnostics["disassembly"]["cancelled"] = ctx.cancelled;
    ctx.record("static_disassembly_end", json{{"module", mod.name}, {"instructions_decoded", out.size()}, {"bytes_consumed", off}, {"instruction_limit_hit", out.size() >= max_insns}});
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch static_disasm_end module=%s decoded=%zu bytes_consumed=%zu limit_hit=%d deadline_hit=%d cancelled=%d elapsed_ms=%llu",
        mod.name.c_str(),
        out.size(),
        off,
        out.size() >= max_insns ? 1 : 0,
        ctx.deadline_hit ? 1 : 0,
        ctx.cancelled ? 1 : 0,
        static_cast<unsigned long long>(ctx.elapsed_ms()));
    return out;
}

inline bool parse_driver_entry_assignments(std::uint32_t pid, const target_module_t& mod, const pe_layout_t& pe, json& assignments, json& diagnostics, drv_dispatch_scan_context_t& ctx, const std::vector<std::uint8_t>* image_bytes = nullptr)
{
    assignments = json::array();
    diagnostics = json::object();
    diagnostics["module"] = json{{"name", mod.name}, {"base", sa_format_address(mod.base)}, {"size", mod.size}, {"path", mod.path}};
    diagnostics["scan_budget_start"] = ctx.status();
    diagnostics["candidates"] = json::array();
    diagnostics["rejection_histogram"] = json::object();
    diagnostics["last_candidate"] = nullptr;
    ctx.record("assignment_scan_start", json{{"module", mod.name}, {"base", sa_format_address(mod.base)}, {"size", mod.size}, {"entry", sa_format_address(pe.entry)}, {"budget", ctx.status()}});
    auto insns = image_bytes
        ? disassemble_driver_entry_image_bounded(*image_bytes, mod, pe, ctx, diagnostics)
        : disassemble_driver_entry_bounded(pid, mod, pe, ctx, diagnostics);
    diagnostics["instructions_decoded"] = insns.size();
    std::map<std::string, std::uint64_t> reg_values;
    std::size_t candidate_index = 0;
    for (const auto& ins : insns) {
        if ((candidate_index & 0x3fu) == 0 && ctx.should_stop("dispatch_assignment_loop"))
            break;
        const std::string m = mnemonic_of(ins);
        auto ops = split_operands(ins.ops);
        if ((m == "lea" || m == "mov") && ops.size() >= 2 && !operand_is_memory(ops[0])) {
            std::uint64_t value = 0;
            if (ins.branch_target)
                value = ins.branch_target;
            else if (ins.has_imm)
                value = ins.imm_unsigned;
            else if (auto h = parse_hex_in_text(ops[1]))
                value = *h;
            else if (ins.has_mem_op && ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP) && ins.mem_op.has_disp)
                value = ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)) + static_cast<std::uint64_t>(ins.mem_op.disp);
            if (value)
                reg_values[reg_from_operand(ops[0])] = value;
        }
        if (m != "mov" || ops.size() < 2 || !operand_is_memory(ops[0]))
            continue;
        if (!ins.has_mem_op || !ins.mem_op.has_disp)
            continue;
        const std::int64_t disp = ins.mem_op.disp;
        if (disp < 0x70 || disp >= 0x70 + 28 * 8 || ((disp - 0x70) % 8) != 0)
            continue;
        if (candidate_index >= ctx.limits.max_candidates) {
            diagnostics["candidate_limit_hit"] = true;
            diagnostics["candidate_limit_hit_at"] = candidate_index;
            ctx.stage = "dispatch_candidate_limit";
            ctx.record("assignment_candidate_limit", json{{"module", mod.name}, {"candidate_index", candidate_index}, {"max_candidates", ctx.limits.max_candidates}, {"instructions_decoded", insns.size()}, {"budget", ctx.status()}});
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch candidate_limit module=%s candidate=%llu max=%llu decoded=%zu elapsed_ms=%llu",
                mod.name.c_str(),
                static_cast<unsigned long long>(candidate_index),
                static_cast<unsigned long long>(ctx.limits.max_candidates),
                insns.size(),
                static_cast<unsigned long long>(ctx.elapsed_ms()));
            break;
        }
        const std::uint32_t code = static_cast<std::uint32_t>((disp - 0x70) / 8);
        std::uint64_t handler = 0;
        if (ins.has_imm)
            handler = ins.imm_unsigned;
        else {
            const std::string src = reg_from_operand(ops[1]);
            if (auto v = resolve_last_register_value(reg_values, src))
                handler = *v;
        }
        json a;
        a["assignment_va"] = sa_format_address(ins.addr);
        a["irp_code"] = code;
        a["irp_name"] = irp_name(code);
        a["handler_va"] = handler ? json(sa_format_address(handler)) : json(nullptr);
        a["driver_object_offset"] = sa_format_address(static_cast<std::uint64_t>(disp));
        a["major_function_offset"] = sa_format_address(static_cast<std::uint64_t>(disp));
        a["evidence"] = instruction_to_json(ins);
        a["dispatch_table_evidence"] = driver_object_assignment_evidence(ins, reg_values, disp);
        if (a["dispatch_table_evidence"].value("dispatch_table_va_known", false)) {
            a["driver_object_va"] = a["dispatch_table_evidence"].value("driver_object_va", json(nullptr));
            a["dispatch_table_va"] = a["dispatch_table_evidence"].value("dispatch_table_va", json(nullptr));
            a["dispatch_slot_va"] = a["dispatch_table_evidence"].value("dispatch_slot_va", json(nullptr));
            a["dispatch_table_va_source"] = a["dispatch_table_evidence"].value("driver_object_source", std::string("tracked_register_constant"));
        } else {
            a["dispatch_table_va"] = "driver_object+0x70";
            a["dispatch_table_va_source"] = a["dispatch_table_evidence"].value("driver_object_source", std::string("driver_entry_argument_unmaterialized"));
        }
        a["handler_plausibility"] = handler_plausibility(pid, mod, pe, handler);
        const bool plausible = a["handler_plausibility"].value("plausible", false);
        a["accepted"] = plausible;
        if (!plausible) {
            a["rejection_reason"] = a["handler_plausibility"].value("reason", std::string("handler_rejected"));
            increment_json_counter(diagnostics["rejection_histogram"], a["rejection_reason"].get<std::string>());
        }
        a["candidate_index"] = candidate_index;
        const std::string reason = plausible ? std::string("accepted") : a.value("rejection_reason", std::string("handler_rejected"));
        ctx.record(plausible ? "assignment_accepted" : "assignment_rejected",
            json{{"module", mod.name}, {"candidate_index", candidate_index}, {"assignment_va", sa_format_address(ins.addr)}, {"irp_code", code}, {"handler_va", handler ? json(sa_format_address(handler)) : json(nullptr)}, {"reason", reason}});
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch assignment_%s module=%s candidate=%llu irp=%u assignment=0x%llX handler=0x%llX reason=%s elapsed_ms=%llu",
            plausible ? "accepted" : "rejected",
            mod.name.c_str(),
            static_cast<unsigned long long>(candidate_index),
            code,
            static_cast<unsigned long long>(ins.addr),
            static_cast<unsigned long long>(handler),
            reason.c_str(),
            static_cast<unsigned long long>(ctx.elapsed_ms()));
        ++candidate_index;
        diagnostics["last_candidate"] = a;
        diagnostics["candidates"].push_back(a);
        if (plausible)
            assignments.push_back(std::move(a));
    }
    if (!assignments.empty()) {
        std::vector<json> sorted_assignments;
        sorted_assignments.reserve(assignments.size());
        for (const auto& a : assignments)
            sorted_assignments.push_back(a);
        std::stable_sort(sorted_assignments.begin(), sorted_assignments.end(), dispatch_assignment_less);
        assignments = json::array();
        for (auto& a : sorted_assignments)
            assignments.push_back(std::move(a));
    }
    diagnostics["candidate_count"] = diagnostics["candidates"].size();
    diagnostics["assignment_candidate_count"] = candidate_index;
    diagnostics["accepted_assignment_count"] = assignments.size();
    diagnostics["accepted_slots"] = dispatch_accepted_slots_json(assignments);
    diagnostics["deadline_hit"] = ctx.deadline_hit;
    diagnostics["cancelled"] = ctx.cancelled;
    diagnostics["elapsed_ms"] = ctx.elapsed_ms();
    diagnostics["budget"] = ctx.status();
    diagnostics["scan_budget_end"] = ctx.status();
    if (assignments.empty())
        diagnostics["rejection_reason"] = ctx.cancelled ? "scan_cancelled" : (ctx.deadline_hit ? "scan_deadline_hit" : (diagnostics["candidate_count"].get<std::size_t>() == 0 ? "no_major_function_assignments_in_scan_window" : "all_major_function_candidates_rejected"));
    ctx.record("assignment_scan_end", json{{"module", mod.name}, {"base", sa_format_address(mod.base)}, {"size", mod.size}, {"instructions_decoded", insns.size()}, {"candidate_count", diagnostics["candidate_count"]}, {"accepted_assignment_count", assignments.size()}, {"accepted_slots", diagnostics["accepted_slots"]}, {"rejection_reason", assignments.empty() ? diagnostics.value("rejection_reason", std::string("none")) : std::string("accepted")}, {"budget", ctx.status()}});
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch assignment_scan_end module=%s base=0x%llX size=%llu decoded=%zu candidates=%llu accepted=%llu reason=%s elapsed_ms=%llu timeout_ms=%u deadline_hit=%d cancelled=%d",
        mod.name.c_str(),
        static_cast<unsigned long long>(mod.base),
        static_cast<unsigned long long>(mod.size),
        insns.size(),
        static_cast<unsigned long long>(diagnostics["candidate_count"].get<std::size_t>()),
        static_cast<unsigned long long>(assignments.size()),
        assignments.empty() ? diagnostics.value("rejection_reason", std::string("none")).c_str() : "accepted",
        static_cast<unsigned long long>(ctx.elapsed_ms()),
        ctx.limits.timeout_ms,
        ctx.deadline_hit ? 1 : 0,
        ctx.cancelled ? 1 : 0);
    return !assignments.empty();
}

inline tool_result_t drv_find_dispatch_table(const json& params)
{
    std::string static_image_hex;
    for (const char* key : {"pe_image_hex", "static_pe_image_hex", "fixture_pe_hex", "image_hex"}) {
        if (params.contains(key) && params[key].is_string()) {
            static_image_hex = params[key].get<std::string>();
            break;
        }
    }
    const bool static_image_mode = !static_image_hex.empty();
    tool_result_t chk;
    if (!static_image_mode)
        chk = require_driver();
    auto explicit_driver_object = parse_param_u64(params, "driver_object_va");
    if (!explicit_driver_object)
        explicit_driver_object = parse_param_u64(params, "driver_object");
    const drv_dispatch_scan_limits_t limits = drv_dispatch_limits_from_params(params);
    drv_dispatch_scan_context_t scan_ctx(limits);
    const json scan_budget_start = scan_ctx.status();
    if (!static_image_mode && !chk.success) {
        json out;
        out["dependency_unavailable"] = true;
        out["root_cause"] = "driver_bridge_not_connected";
        out["target_required"] = false;
        out["using_kernel_driver"] = driver_bridge::using_kernel_driver();
        out["attached_pid"] = driver_bridge::attached_pid();
        out["attached_pids"] = driver_bridge::attached_pids();
        out["auto_select_wdm_driver"] = params.value("auto_select_wdm_driver", false);
        out["budget"] = scan_ctx.status();
        out["scan_budget_start"] = scan_budget_start;
        out["breadcrumbs"] = scan_ctx.breadcrumbs;
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch dependency_failed using_driver=%d attached_pid=%u target_required=0 error=%s",
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::attached_pid(),
            chk.text.c_str());
        return tool_result_t::error(chk.text.empty() ? "Driver bridge is not connected" : chk.text, out);
    }
    if (static_image_mode) {
        std::vector<std::uint8_t> image;
        std::string hex_error;
        if (!hex_to_bytes_strict(static_image_hex, image, hex_error) || image.empty()) {
            json out;
            out["analysis_mode"] = "static_pe_image_fixture";
            out["fixture_parser_path_available"] = true;
            out["target_required"] = false;
            out["rejection_reason"] = "invalid_static_pe_image_hex";
            out["error"] = hex_error.empty() ? "static PE image hex did not decode to bytes" : hex_error;
            out["budget"] = scan_ctx.status();
            out["scan_budget_start"] = scan_budget_start;
            return tool_result_t::error("Static PE image fixture could not be decoded.", out);
        }
        const std::uint64_t fixture_base = parse_param_u64(params, "module_base").value_or(parse_param_u64(params, "image_base").value_or(parse_param_u64(params, "base").value_or(0x180000000ULL)));
        pe_layout_t pe;
        if (!read_pe_layout_from_image_bytes(image, fixture_base, pe)) {
            json out;
            out["analysis_mode"] = "static_pe_image_fixture";
            out["fixture_parser_path_available"] = true;
            out["target_required"] = false;
            out["rejection_reason"] = "static_pe_header_parse_failed";
            out["image_size"] = image.size();
            out["budget"] = scan_ctx.status();
            out["scan_budget_start"] = scan_budget_start;
            return tool_result_t::error("Static PE image fixture headers could not be parsed.", out);
        }
        target_module_t static_mod;
        static_mod.pid = 0;
        static_mod.base = pe.base;
        static_mod.size = pe.size_of_image ? pe.size_of_image : image.size();
        static_mod.name = params.value("driver_name", params.value("module_name", std::string("aida_static_dispatch_fixture.sys")));
        static_mod.path = params.value("module_path", std::string("static://aida_static_dispatch_fixture.sys"));
        static_mod.kernel = true;
        json assignments = json::array();
        json diagnostics = json::object();
        parse_driver_entry_assignments(0, static_mod, pe, assignments, diagnostics, scan_ctx, &image);
        json explicit_dispatch_evidence = explicit_driver_object ? apply_explicit_driver_object_to_assignments(assignments, *explicit_driver_object) : json::object();
        json out;
        out["driver_name"] = static_mod.name;
        out["selected_module"] = target_module_json(static_mod);
        out["module_base"] = sa_format_address(static_mod.base);
        out["module_size"] = static_mod.size;
        out["module_path"] = static_mod.path;
        out["auto_selected_wdm_driver"] = false;
        out["selection_policy"] = "deterministic static PE image fixture";
        out["analysis_mode"] = "static_pe_image_fixture";
        out["fixture_parser_path_available"] = true;
        out["target_required"] = false;
        out["dependency_unavailable"] = false;
        out["dependency_state"] = json{{"using_kernel_driver", driver_bridge::using_kernel_driver()}, {"attached_pid", driver_bridge::attached_pid()}, {"attached_pids", driver_bridge::attached_pids()}};
        out["scan_budget_start"] = scan_budget_start;
        out["budget"] = scan_ctx.status();
        out["pe_parse_ok"] = true;
        out["pe"] = json{{"entry_rva", pe.entry >= pe.base ? sa_format_address(pe.entry - pe.base) : "unknown"},
                         {"entry_va", sa_format_address(pe.entry)},
                         {"size_of_image", pe.size_of_image},
                         {"is_64", pe.is_64},
                         {"section_count", pe.sections.size()}};
        out["entry_section"] = section_evidence_for_va(pe, pe.entry);
        out["entry_protection"] = json{{"queried", false}, {"reason", "static_pe_image_fixture"}, {"protect", "unknown"}};
        out["driver_entry_va"] = sa_format_address(pe.entry);
        out["driver_entry_rva"] = pe.entry >= pe.base ? json(sa_format_address(pe.entry - pe.base)) : json(nullptr);
        out["driver_entry_evidence"] = driver_entry_evidence_json(0, static_mod, pe, diagnostics);
        out["dispatch_table_va"] = explicit_driver_object ? json(sa_format_address(*explicit_driver_object + 0x70)) : json("driver_object+0x70");
        out["dispatch_table_va_known"] = explicit_driver_object.has_value();
        out["dispatch_table_va_evidence"] = explicit_driver_object ? explicit_dispatch_evidence : json{{"source", "driver_entry_argument_unmaterialized"}, {"relative", "driver_object+0x70"}, {"actual_va_available", false}};
        out["assignments"] = assignments;
        out["candidate_count"] = diagnostics.value("candidate_count", 0);
        out["accepted_assignment_count"] = diagnostics.value("accepted_assignment_count", 0);
        out["accepted_slots"] = diagnostics.value("accepted_slots", json::array());
        out["scan_window"] = diagnostics.value("scan_window", json::object());
        out["diagnostics"] = diagnostics;
        out["breadcrumbs"] = scan_ctx.breadcrumbs;
        out["deadline_hit"] = scan_ctx.deadline_hit;
        out["cancelled"] = scan_ctx.cancelled;
        out["handler_plausibility_policy"] = "handler must resolve inside an executable section of the selected driver image";
        out["confidence"] = assignments.empty() ? 0.25 : std::min(0.95, 0.45 + assignments.size() * 0.04);
        out["note"] = assignments.empty() ? "No accepted MajorFunction assignments were found in the static DriverEntry fixture." : (explicit_driver_object ? "dispatch_table_va was derived from the explicit driver_object_va parameter." : "dispatch_table_va is expressed relative to the runtime DRIVER_OBJECT because the object pointer is not exposed by this read-only analysis path.");
        if (assignments.empty())
            out["rejection_reason"] = diagnostics.value("rejection_reason", std::string("no_accepted_dispatch_handlers"));
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch static_exit accepted=%u candidates=%u deadline_hit=%d cancelled=%d elapsed_ms=%llu reason=%s",
            out.value("accepted_assignment_count", 0u),
            out.value("candidate_count", 0u),
            scan_ctx.deadline_hit ? 1 : 0,
            scan_ctx.cancelled ? 1 : 0,
            static_cast<unsigned long long>(scan_ctx.elapsed_ms()),
            assignments.empty() ? out.value("rejection_reason", std::string("none")).c_str() : "accepted");
        return assignments.empty()
            ? tool_result_t::error("Static driver dispatch assignment scan found no accepted MajorFunction assignments.", out)
            : tool_result_t::ok("Driver dispatch assignment scan completed", out);
    }
    std::string err;
    std::optional<target_module_t> mod;
    pe_layout_t preselected_pe;
    json preselected_assignments;
    json preselected_diagnostics;
    bool have_preselected_analysis = false;
    bool auto_selected = false;
    std::size_t auto_modules_scanned = 0;
    std::size_t auto_modules_considered = 0;
    std::size_t auto_modules_skipped = 0;
    json auto_select_candidates = json::array();
    json auto_select_ordered_modules = json::array();
    json auto_select_skip_histogram = json::object();
    json auto_select_rejection_histogram = json::object();
    json auto_select_last_candidate = nullptr;
    std::size_t max_auto_modules = 64;
    if (params.contains("max_auto_modules") && params["max_auto_modules"].is_number_unsigned())
        max_auto_modules = (std::min<std::size_t>)(params["max_auto_modules"].get<std::size_t>(), 256);
    else if (params.contains("max_auto_modules") && params["max_auto_modules"].is_number_integer())
        max_auto_modules = (std::min<std::size_t>)(static_cast<std::size_t>((std::max<std::int64_t>)(params["max_auto_modules"].get<std::int64_t>(), 1)), 256);
    const bool explicit_module =
        params.contains("module_base") || params.contains("base") ||
        params.contains("driver_name") || params.contains("module") ||
        params.contains("module_name") || params.contains("name");
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch entry auto_select=%d explicit_module=%d max_auto_modules=%llu timeout_ms=%u max_entry_bytes=%u max_entry_insns=%u max_candidates=%llu attached_pid=%u",
        params.value("auto_select_wdm_driver", false) ? 1 : 0,
        explicit_module ? 1 : 0,
        static_cast<unsigned long long>(max_auto_modules),
        limits.timeout_ms,
        limits.max_entry_bytes,
        limits.max_entry_instructions,
        static_cast<unsigned long long>(limits.max_candidates),
        driver_bridge::attached_pid());
    if (params.value("auto_select_wdm_driver", false) && !explicit_module) {
        std::string qerr;
        scan_ctx.stage = "kernel_module_enumeration";
        auto mods = kernel_modules(&qerr);
        scan_ctx.record("kernel_modules_enumerated", json{{"module_count", mods.size()}, {"error", qerr}});
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch kernel_modules count=%zu error=%s elapsed_ms=%llu",
            mods.size(),
            qerr.c_str(),
            static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
        auto_modules_considered = mods.size();
        std::vector<target_module_t> ordered_mods;
        ordered_mods.reserve(mods.size());
        std::size_t original_index = 0;
        for (const auto& candidate : mods) {
            const int priority = kernel_auto_select_priority(candidate);
            json module_summary = json{{"original_index", original_index}, {"name", candidate.name}, {"base", sa_format_address(candidate.base)}, {"size", candidate.size}, {"path", candidate.path}, {"priority", priority}, {"selection_key", json{{"priority", priority}, {"name", lower_ascii(candidate.name)}, {"base", sa_format_address(candidate.base)}}}};
            const std::string skip_reason = kernel_auto_select_skip_reason(candidate);
            if (!skip_reason.empty()) {
                module_summary["skip_reason"] = skip_reason;
                increment_json_counter(auto_select_skip_histogram, skip_reason);
                ++auto_modules_skipped;
                auto_select_last_candidate = module_summary;
                scan_ctx.record("kernel_module_rejected", module_summary);
                diag::log_tagged_fmt("protected_re",
                    "drv_dispatch kernel_module_rejected index=%llu name=%s base=0x%llX size=%llu priority=%d reason=%s elapsed_ms=%llu",
                    static_cast<unsigned long long>(original_index),
                    candidate.name.c_str(),
                    static_cast<unsigned long long>(candidate.base),
                    static_cast<unsigned long long>(candidate.size),
                    priority,
                    skip_reason.c_str(),
                    static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
                ++original_index;
                continue;
            }
            ordered_mods.push_back(candidate);
            ++original_index;
        }
        std::stable_sort(ordered_mods.begin(), ordered_mods.end(),
            [](const target_module_t& a, const target_module_t& b) {
                const int ap = kernel_auto_select_priority(a);
                const int bp = kernel_auto_select_priority(b);
                if (ap != bp)
                    return ap < bp;
                const std::string an = lower_ascii(a.name);
                const std::string bn = lower_ascii(b.name);
                if (an != bn)
                    return an < bn;
                return a.base < b.base;
            });
        for (const auto& candidate : ordered_mods) {
            if (auto_select_ordered_modules.size() >= 64)
                break;
            const int priority = kernel_auto_select_priority(candidate);
            auto_select_ordered_modules.push_back(json{{"name", candidate.name}, {"base", sa_format_address(candidate.base)}, {"size", candidate.size}, {"path", candidate.path}, {"priority", priority}, {"selection_key", json{{"priority", priority}, {"name", lower_ascii(candidate.name)}, {"base", sa_format_address(candidate.base)}}}});
        }
        scan_ctx.record("kernel_modules_filtered", json{{"module_count", mods.size()}, {"eligible_count", ordered_mods.size()}, {"skipped_count", auto_modules_skipped}, {"skip_histogram", auto_select_skip_histogram}});
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch kernel_modules_filtered total=%zu eligible=%zu skipped=%llu elapsed_ms=%llu",
            mods.size(),
            ordered_mods.size(),
            static_cast<unsigned long long>(auto_modules_skipped),
            static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
        std::size_t candidate_index = 0;
        for (const auto& candidate : ordered_mods) {
            if (scan_ctx.should_stop("auto_select_candidate_loop"))
                break;
            if (auto_modules_scanned >= max_auto_modules)
                break;
            ++auto_modules_scanned;
            pe_layout_t candidate_pe;
            const int priority = kernel_auto_select_priority(candidate);
            json candidate_summary = json{{"candidate_index", candidate_index}, {"name", candidate.name}, {"base", sa_format_address(candidate.base)}, {"size", candidate.size}, {"path", candidate.path}, {"priority", priority}, {"selection_key", json{{"priority", priority}, {"name", lower_ascii(candidate.name)}, {"base", sa_format_address(candidate.base)}}}, {"scan_budget", scan_ctx.status()}};
            auto_select_last_candidate = candidate_summary;
            scan_ctx.record("candidate_begin", candidate_summary);
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch candidate_begin index=%llu priority=%d name=%s base=0x%llX size=%llu path=%s elapsed_ms=%llu",
                static_cast<unsigned long long>(candidate_index),
                priority,
                candidate.name.c_str(),
                static_cast<unsigned long long>(candidate.base),
                static_cast<unsigned long long>(candidate.size),
                candidate.path.c_str(),
                static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
            ++candidate_index;
            if (!read_pe_layout_with_dispatch_diag(0, candidate, candidate_pe, scan_ctx, candidate_summary)) {
                if (!candidate_summary.contains("rejection_reason"))
                    candidate_summary["rejection_reason"] = "pe_header_parse_failed";
                candidate_summary["scan_budget"] = scan_ctx.status();
                increment_json_counter(auto_select_rejection_histogram, candidate_summary["rejection_reason"].get<std::string>());
                auto_select_last_candidate = candidate_summary;
                scan_ctx.record("candidate_rejected", candidate_summary);
                diag::log_tagged_fmt("protected_re",
                    "drv_dispatch candidate_rejected index=%llu name=%s base=0x%llX size=%llu reason=%s decoded=0 candidates=0 accepted=0 elapsed_ms=%llu",
                    static_cast<unsigned long long>(candidate_index - 1),
                    candidate.name.c_str(),
                    static_cast<unsigned long long>(candidate.base),
                    static_cast<unsigned long long>(candidate.size),
                    candidate_summary["rejection_reason"].get<std::string>().c_str(),
                    static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
                if (auto_select_candidates.size() < 16)
                    auto_select_candidates.push_back(std::move(candidate_summary));
                if (scan_ctx.should_stop("auto_select_after_pe_read"))
                    break;
                continue;
            }
            json candidate_assignments;
            json candidate_diagnostics;
            parse_driver_entry_assignments(0, candidate, candidate_pe, candidate_assignments, candidate_diagnostics, scan_ctx);
            candidate_summary["candidate_count"] = candidate_diagnostics.value("candidate_count", 0);
            candidate_summary["accepted_assignment_count"] = candidate_diagnostics.value("accepted_assignment_count", 0);
            candidate_summary["instructions_decoded"] = candidate_diagnostics.value("instructions_decoded", 0);
            candidate_summary["accepted_slots"] = candidate_diagnostics.value("accepted_slots", json::array());
            candidate_summary["rejection_histogram"] = candidate_diagnostics.value("rejection_histogram", json::object());
            candidate_summary["last_candidate"] = candidate_diagnostics.value("last_candidate", json(nullptr));
            candidate_summary["deadline_hit"] = scan_ctx.deadline_hit;
            candidate_summary["cancelled"] = scan_ctx.cancelled;
            candidate_summary["elapsed_ms"] = scan_ctx.elapsed_ms();
            candidate_summary["scan_budget"] = scan_ctx.status();
            if (candidate_assignments.empty()) {
                candidate_summary["rejection_reason"] = candidate_diagnostics.value("rejection_reason", std::string("no_accepted_dispatch_handlers"));
                increment_json_counter(auto_select_rejection_histogram, candidate_summary["rejection_reason"].get<std::string>());
                auto_select_last_candidate = candidate_summary;
                scan_ctx.record("candidate_rejected", candidate_summary);
                diag::log_tagged_fmt("protected_re",
                    "drv_dispatch candidate_rejected index=%llu name=%s base=0x%llX size=%llu reason=%s decoded=%llu candidates=%llu accepted=0 elapsed_ms=%llu",
                    static_cast<unsigned long long>(candidate_index - 1),
                    candidate.name.c_str(),
                    static_cast<unsigned long long>(candidate.base),
                    static_cast<unsigned long long>(candidate.size),
                    candidate_summary["rejection_reason"].get<std::string>().c_str(),
                    static_cast<unsigned long long>(candidate_summary.value("instructions_decoded", 0ull)),
                    static_cast<unsigned long long>(candidate_summary.value("candidate_count", 0ull)),
                    static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
                if (auto_select_candidates.size() < 16)
                    auto_select_candidates.push_back(std::move(candidate_summary));
                if (scan_ctx.should_stop("auto_select_after_candidate_analysis"))
                    break;
                continue;
            }
            mod = candidate;
            preselected_pe = std::move(candidate_pe);
            preselected_assignments = std::move(candidate_assignments);
            preselected_diagnostics = std::move(candidate_diagnostics);
            have_preselected_analysis = true;
            auto_selected = true;
            auto_select_last_candidate = candidate_summary;
            scan_ctx.record("candidate_accepted", candidate_summary);
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch candidate_accepted index=%llu name=%s base=0x%llX size=%llu decoded=%llu candidates=%llu accepted=%llu elapsed_ms=%llu",
                static_cast<unsigned long long>(candidate_index - 1),
                candidate.name.c_str(),
                static_cast<unsigned long long>(candidate.base),
                static_cast<unsigned long long>(candidate.size),
                static_cast<unsigned long long>(candidate_summary.value("instructions_decoded", 0ull)),
                static_cast<unsigned long long>(candidate_summary.value("candidate_count", 0ull)),
                static_cast<unsigned long long>(candidate_summary.value("accepted_assignment_count", 0ull)),
                static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
            if (auto_select_candidates.size() < 16)
                auto_select_candidates.push_back(std::move(candidate_summary));
            break;
        }
        if (!mod) {
            json out;
            out["auto_select_wdm_driver"] = true;
            out["analysis_mode"] = "live_kernel_module_scan";
            out["fixture_parser_path_available"] = false;
            out["auto_modules_considered"] = auto_modules_considered;
            out["auto_modules_skipped"] = auto_modules_skipped;
            out["auto_modules_scanned"] = auto_modules_scanned;
            out["max_auto_modules"] = max_auto_modules;
            out["candidates"] = auto_select_candidates;
            out["auto_select_ordered_modules"] = auto_select_ordered_modules;
            out["auto_select_skip_histogram"] = auto_select_skip_histogram;
            out["auto_select_rejection_histogram"] = auto_select_rejection_histogram;
            out["auto_select_last_candidate"] = auto_select_last_candidate;
            out["budget"] = scan_ctx.status();
            out["scan_budget_start"] = scan_budget_start;
            out["breadcrumbs"] = scan_ctx.breadcrumbs;
            out["deadline_hit"] = scan_ctx.deadline_hit;
            out["cancelled"] = scan_ctx.cancelled;
            out["target_required"] = false;
            out["dependency_state"] = json{{"using_kernel_driver", driver_bridge::using_kernel_driver()}, {"attached_pid", driver_bridge::attached_pid()}, {"attached_pids", driver_bridge::attached_pids()}};
            out["rejection_reason"] = scan_ctx.cancelled ? "scan_cancelled" : (scan_ctx.deadline_hit ? "scan_deadline_hit" : (mods.empty() ? (qerr.empty() ? "no_kernel_modules_available" : qerr) : (ordered_mods.empty() ? "no_likely_wdm_driver_modules_after_filter" : "no_loaded_wdm_driver_with_accepted_major_function_assignments")));
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch auto_select_failed considered=%llu skipped=%llu scanned=%llu max=%llu deadline_hit=%d cancelled=%d reason=%s elapsed_ms=%llu",
                static_cast<unsigned long long>(auto_modules_considered),
                static_cast<unsigned long long>(auto_modules_skipped),
                static_cast<unsigned long long>(auto_modules_scanned),
                static_cast<unsigned long long>(max_auto_modules),
                scan_ctx.deadline_hit ? 1 : 0,
                scan_ctx.cancelled ? 1 : 0,
                out["rejection_reason"].get<std::string>().c_str(),
                static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
            return tool_result_t::error("No loaded WDM driver with accepted MajorFunction assignments was found in the bounded kernel-module scan.", out);
        }
    } else {
        mod = select_module(params, true, &err);
    }
    if (!mod) {
        json out;
        out["dependency_unavailable"] = false;
        out["target_required"] = false;
        out["root_cause"] = "kernel_module_selection_failed";
        out["error"] = err.empty() ? "Kernel module could not be selected" : err;
        out["budget"] = scan_ctx.status();
        out["scan_budget_start"] = scan_budget_start;
        out["breadcrumbs"] = scan_ctx.breadcrumbs;
        out["dependency_state"] = json{{"using_kernel_driver", driver_bridge::using_kernel_driver()}, {"attached_pid", driver_bridge::attached_pid()}, {"attached_pids", driver_bridge::attached_pids()}};
        return tool_result_t::error(err.empty() ? "Kernel module could not be selected" : err, out);
    }
    json base_out;
    base_out["driver_name"] = mod->name;
    base_out["selected_module"] = target_module_json(*mod);
    base_out["module_base"] = sa_format_address(mod->base);
    base_out["module_size"] = mod->size;
    base_out["module_path"] = mod->path;
    base_out["auto_selected_wdm_driver"] = auto_selected;
    base_out["selection_policy"] = "explicit module selection or deterministic auto-select ordered by priority, lowercase module name, and base address";
    base_out["analysis_mode"] = "live_kernel_module_scan";
    base_out["fixture_parser_path_available"] = false;
    base_out["auto_modules_considered"] = auto_modules_considered;
    base_out["auto_modules_skipped"] = auto_modules_skipped;
    base_out["auto_modules_scanned"] = auto_modules_scanned;
    base_out["target_required"] = false;
    base_out["dependency_state"] = json{{"using_kernel_driver", driver_bridge::using_kernel_driver()}, {"attached_pid", driver_bridge::attached_pid()}, {"attached_pids", driver_bridge::attached_pids()}};
    base_out["scan_budget_start"] = scan_budget_start;
    base_out["budget"] = scan_ctx.status();
    if (!auto_select_candidates.empty())
        base_out["auto_select_candidates"] = auto_select_candidates;
    if (!auto_select_ordered_modules.empty())
        base_out["auto_select_ordered_modules"] = auto_select_ordered_modules;
    if (!auto_select_skip_histogram.empty())
        base_out["auto_select_skip_histogram"] = auto_select_skip_histogram;
    if (!auto_select_rejection_histogram.empty())
        base_out["auto_select_rejection_histogram"] = auto_select_rejection_histogram;
    if (!auto_select_last_candidate.is_null())
        base_out["auto_select_last_candidate"] = auto_select_last_candidate;
    pe_layout_t pe = have_preselected_analysis ? preselected_pe : pe_layout_t{};
    json selected_pe_summary = json{{"name", mod->name}, {"base", sa_format_address(mod->base)}, {"size", mod->size}, {"path", mod->path}};
    if (!have_preselected_analysis && !read_pe_layout_with_dispatch_diag(0, *mod, pe, scan_ctx, selected_pe_summary)) {
        base_out["pe_parse_ok"] = false;
        base_out["rejection_reason"] = scan_ctx.cancelled ? "scan_cancelled" : (scan_ctx.deadline_hit ? "scan_deadline_hit" : "pe_header_parse_failed");
        base_out["pe_read"] = selected_pe_summary;
        base_out["budget"] = scan_ctx.status();
        base_out["breadcrumbs"] = scan_ctx.breadcrumbs;
        base_out["deadline_hit"] = scan_ctx.deadline_hit;
        base_out["cancelled"] = scan_ctx.cancelled;
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch selected_pe_failed module=%s reason=%s deadline_hit=%d cancelled=%d elapsed_ms=%llu",
            mod->name.c_str(),
            base_out["rejection_reason"].get<std::string>().c_str(),
            scan_ctx.deadline_hit ? 1 : 0,
            scan_ctx.cancelled ? 1 : 0,
            static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
        return tool_result_t::error("Could not parse PE headers for " + mod->name + " at " + sa_format_address(mod->base), base_out);
    }
    base_out["pe_parse_ok"] = true;
    if (!have_preselected_analysis)
        base_out["pe_read"] = selected_pe_summary;
    base_out["pe"] = json{{"entry_rva", pe.entry >= pe.base ? sa_format_address(pe.entry - pe.base) : "unknown"},
                          {"entry_va", sa_format_address(pe.entry)},
                          {"size_of_image", pe.size_of_image},
                          {"is_64", pe.is_64},
                          {"section_count", pe.sections.size()}};
    base_out["entry_section"] = section_evidence_for_va(pe, pe.entry);
    base_out["entry_protection"] = memory_protection_evidence(0, pe.entry);
    if (module_is_ntoskrnl(*mod)) {
        base_out["dispatch_table_va"] = nullptr;
        base_out["assignments"] = json::array();
        base_out["candidate_count"] = 0;
        base_out["accepted_slots"] = json::array();
        base_out["confidence"] = 0.0;
        base_out["contract"] = "wdm_driver_module_required";
        base_out["rejection_reason"] = "selected_module_is_ntoskrnl_kernel_image_not_wdm_driver_module";
        base_out["note"] = "ntoskrnl is the Windows kernel image and is not a WDM driver dispatch fixture target for this read-only scan.";
        return tool_result_t::error("Selected module is ntoskrnl, not a WDM driver module dispatch fixture.", base_out);
    }
    json assignments = have_preselected_analysis ? std::move(preselected_assignments) : json::array();
    json diagnostics = have_preselected_analysis ? std::move(preselected_diagnostics) : json::object();
    if (!have_preselected_analysis)
        parse_driver_entry_assignments(0, *mod, pe, assignments, diagnostics, scan_ctx);
    json explicit_dispatch_evidence = explicit_driver_object ? apply_explicit_driver_object_to_assignments(assignments, *explicit_driver_object) : json::object();
    json out = base_out;
    out["driver_entry_va"] = sa_format_address(pe.entry);
    out["driver_entry_rva"] = pe.entry >= pe.base ? json(sa_format_address(pe.entry - pe.base)) : json(nullptr);
    out["driver_entry_evidence"] = driver_entry_evidence_json(0, *mod, pe, diagnostics);
    out["dispatch_table_va"] = explicit_driver_object ? json(sa_format_address(*explicit_driver_object + 0x70)) : json("driver_object+0x70");
    out["dispatch_table_va_known"] = explicit_driver_object.has_value();
    out["dispatch_table_va_evidence"] = explicit_driver_object ? explicit_dispatch_evidence : json{{"source", "driver_entry_argument_unmaterialized"}, {"relative", "driver_object+0x70"}, {"actual_va_available", false}};
    out["assignments"] = assignments;
    out["candidate_count"] = diagnostics.value("candidate_count", 0);
    out["accepted_assignment_count"] = diagnostics.value("accepted_assignment_count", 0);
    out["accepted_slots"] = diagnostics.value("accepted_slots", json::array());
    out["scan_window"] = diagnostics["scan_window"];
    out["diagnostics"] = diagnostics;
    out["budget"] = scan_ctx.status();
    out["breadcrumbs"] = scan_ctx.breadcrumbs;
    out["deadline_hit"] = scan_ctx.deadline_hit;
    out["cancelled"] = scan_ctx.cancelled;
    out["handler_plausibility_policy"] = "handler must resolve inside an executable section of the selected driver image";
    out["confidence"] = assignments.empty() ? 0.25 : std::min(0.95, 0.45 + assignments.size() * 0.04);
    out["note"] = assignments.empty() ? "No accepted MajorFunction assignments were found in the bounded DriverEntry scan; inspect diagnostics.candidates and breadcrumbs for rejected or bounded evidence." : (explicit_driver_object ? "dispatch_table_va was derived from the explicit driver_object_va parameter." : "dispatch_table_va is expressed relative to the runtime DRIVER_OBJECT because the object pointer is not exposed by this read-only analysis path.");
    if (assignments.empty())
        out["rejection_reason"] = diagnostics.value("rejection_reason", std::string("no_accepted_dispatch_handlers"));
    diag::log_tagged_fmt("protected_re",
        "drv_dispatch exit module=%s accepted=%u candidates=%u auto_selected=%d deadline_hit=%d cancelled=%d elapsed_ms=%llu reason=%s",
        mod->name.c_str(),
        out.value("accepted_assignment_count", 0u),
        out.value("candidate_count", 0u),
        auto_selected ? 1 : 0,
        scan_ctx.deadline_hit ? 1 : 0,
        scan_ctx.cancelled ? 1 : 0,
        static_cast<unsigned long long>(scan_ctx.elapsed_ms()),
        assignments.empty() ? out.value("rejection_reason", std::string("none")).c_str() : "accepted");
    return tool_result_t::ok("Driver dispatch assignment scan completed", out);
}

inline json drv_analyze_handler_function(std::uint32_t pid, std::uint64_t handler, std::uint32_t max_bytes = 0x8000, std::uint32_t max_insns = 2048)
{
    auto insns = disassemble_target(pid, handler, max_bytes, max_insns);
    json preview = json::array();
    json pseudo = json::array();
    json param_events = json::array();
    json control_transfers = json::array();
    std::uint64_t end = handler;
    std::string stop_reason = insns.empty() ? "no_instructions_decoded" : "max_scan_reached";
    bool uses_driver_object = false;
    bool uses_irp = false;
    bool calls_helpers = false;
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
        end = ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1));
        if (preview.size() < 48)
            preview.push_back(instruction_to_json(ins));
        if (pseudo.size() < 32)
            pseudo.push_back(json{{"va", sa_format_address(ins.addr)}, {"text", std::string(ins.mnem) + (std::strlen(ins.ops) ? " " + std::string(ins.ops) : "")}});
        if (text.find("rcx") != std::string::npos) {
            uses_driver_object = true;
            if (param_events.size() < 64)
                param_events.push_back(json{{"va", sa_format_address(ins.addr)}, {"parameter", "driver_object"}, {"register", "rcx"}, {"instruction", instruction_to_json(ins)}});
        }
        if (text.find("rdx") != std::string::npos) {
            uses_irp = true;
            if (param_events.size() < 64)
                param_events.push_back(json{{"va", sa_format_address(ins.addr)}, {"parameter", "irp"}, {"register", "rdx"}, {"instruction", instruction_to_json(ins)}});
        }
        if (ins.is_call) {
            calls_helpers = true;
            if (control_transfers.size() < 64)
                control_transfers.push_back(json{{"va", sa_format_address(ins.addr)}, {"kind", "call"}, {"target", ins.branch_target ? json(sa_format_address(ins.branch_target)) : json(nullptr)}, {"instruction", instruction_to_json(ins)}});
        } else if (ins.is_branch && ins.branch_target) {
            if (control_transfers.size() < 64)
                control_transfers.push_back(json{{"va", sa_format_address(ins.addr)}, {"kind", "branch"}, {"target", sa_format_address(ins.branch_target)}, {"instruction", instruction_to_json(ins)}});
        }
        if (ins.is_ret) {
            stop_reason = "ret";
            break;
        }
        const std::string m = mnemonic_of(ins);
        if (m == "jmp" && ins.branch_target != 0 && (ins.branch_target < handler || ins.branch_target >= handler + max_bytes)) {
            stop_reason = "tail_jump_outside_scan_window";
            break;
        }
        if (i + 1 >= max_insns)
            stop_reason = "instruction_limit";
    }
    json out;
    out["handler_va"] = sa_format_address(handler);
    out["function_start_va"] = sa_format_address(handler);
    out["function_end_va"] = end > handler ? json(sa_format_address(end)) : json(nullptr);
    out["size"] = end > handler ? end - handler : 0;
    out["stop_reason"] = stop_reason;
    out["instructions_decoded"] = insns.size();
    out["pseudocode_preview"] = preview;
    out["linear_preview"] = pseudo;
    out["parameter_usage"] = json{{"driver_object", json{{"register", "rcx"}, {"observed", uses_driver_object}}},
                                  {"irp", json{{"register", "rdx"}, {"observed", uses_irp}}},
                                  {"events", param_events}};
    out["control_transfers"] = control_transfers;
    out["calls_helpers"] = calls_helpers;
    return out;
}

inline tool_result_t drv_decode_irp_handlers(const json& params)
{
    if (!params.contains("dispatch_table") || !params["dispatch_table"].is_object())
        return tool_result_t::error("dispatch_table object from drv_find_dispatch_table is required");
    const json& dt = params["dispatch_table"];
    const json assigns = dt.value("assignments", json::array());
    if (!assigns.is_array())
        return tool_result_t::error("dispatch_table.assignments must be an array");
    json arr = json::array();
    for (const auto& a : assigns) {
        auto handler = parse_u64_json(a.value("handler_va", json()));
        if (!handler)
            continue;
        json analysis = drv_analyze_handler_function(0, *handler);
        analysis["irp_code"] = a.value("irp_code", 0);
        analysis["irp_name"] = a.value("irp_name", std::string("IRP_MJ_UNKNOWN"));
        analysis["dispatch_assignment_va"] = a.value("assignment_va", json(nullptr));
        arr.push_back(std::move(analysis));
    }
    return tool_result_t::ok(json(arr));
}

inline bool looks_ioctl(std::uint64_t value)
{
    const std::uint64_t function = (value >> 2) & 0xFFFULL;
    const std::uint64_t device = (value >> 16) & 0xFFFFULL;
    return value > 0x1000 && function != 0 && device != 0 && value <= 0xFFFFFFFFULL;
}

inline bool text_has_any_offset(const std::string& text, std::initializer_list<const char*> offsets)
{
    for (const char* off : offsets) {
        if (text.find(off) != std::string::npos)
            return true;
    }
    return false;
}

inline std::string ioctl_stack_role_from_instruction(const AsmInstr& ins)
{
    const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
    if (text_has_any_offset(text, {"+0x18", "+18h", "+18"}) || (ins.has_mem_op && ins.mem_op.has_disp && ins.mem_op.disp == 0x18))
        return "io_control_code";
    if (text_has_any_offset(text, {"+0x10", "+10h", "+10"}) || (ins.has_mem_op && ins.mem_op.has_disp && ins.mem_op.disp == 0x10))
        return "input_buffer_length";
    if (text_has_any_offset(text, {"+0x8", "+08h", "+8"}) || (ins.has_mem_op && ins.mem_op.has_disp && ins.mem_op.disp == 0x8))
        return "output_buffer_length";
    if (text_has_any_offset(text, {"+0x20", "+20h", "+20"}) || (ins.has_mem_op && ins.mem_op.has_disp && ins.mem_op.disp == 0x20))
        return "type3_input_buffer";
    return {};
}

inline void propagate_ioctl_register_roles(const AsmInstr& ins, const std::string& m, const std::vector<std::string>& ops, std::map<std::string, std::string>& roles, json& evidence)
{
    if (ops.empty() || operand_is_memory(ops[0]))
        return;
    const std::string dst = reg_from_operand(ops[0]);
    if (dst.empty())
        return;
    if (m == "mov" || m == "movzx" || m == "movsxd" || m == "lea") {
        std::string role;
        if (ops.size() > 1 && operand_is_memory(ops[1]))
            role = ioctl_stack_role_from_instruction(ins);
        if (role.empty() && ops.size() > 1) {
            const std::string src = reg_from_operand(ops[1]);
            auto it = roles.find(src);
            if (it != roles.end())
                role = it->second;
        }
        if (!role.empty()) {
            roles[dst] = role;
            if (evidence.size() < 64)
                evidence.push_back(json{{"va", sa_format_address(ins.addr)}, {"register", dst}, {"role", role}, {"instruction", instruction_to_json(ins)}});
        } else {
            roles.erase(dst);
        }
        return;
    }
    if ((m == "shr" || m == "sar") && roles[dst] == "io_control_code")
        roles[dst] = "ioctl_function_selector";
    else if ((m == "and" || m == "sub") && roles[dst] == "io_control_code")
        roles[dst] = "ioctl_normalized_selector";
    else if (m == "xor" && ops.size() > 1 && lower_ascii(ops[0]) == lower_ascii(ops[1]))
        roles.erase(dst);
    else if (m == "add" || m == "imul" || m == "mul" || m == "div" || m == "idiv" || m == "rol" || m == "ror")
        roles.erase(dst);
}

inline std::string comparison_role_for_operands(const AsmInstr& ins, const std::vector<std::string>& ops, const std::map<std::string, std::string>& roles)
{
    const std::string direct = ioctl_stack_role_from_instruction(ins);
    if (!direct.empty())
        return direct;
    for (const auto& op : ops) {
        const std::string reg = reg_from_operand(op);
        auto it = roles.find(reg);
        if (it != roles.end())
            return it->second;
    }
    return {};
}

inline std::uint64_t rip_relative_memory_target(const AsmInstr& ins)
{
    if (!ins.has_mem_op || !ins.mem_op.has_disp || ins.mem_op.base_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP))
        return 0;
    std::uint64_t out = 0;
    if (!drv_add_signed_offset(ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)), ins.mem_op.disp, out))
        return 0;
    return out;
}

inline json decode_ioctl_code(std::uint64_t code);

inline json drv_analyze_ioctl_dispatch(std::uint32_t pid, std::uint64_t handler)
{
    auto insns = disassemble_target(pid, handler, 0x10000, 8192);
    json handlers = json::array();
    json comparisons = json::array();
    json role_evidence = json::array();
    json jump_tables = json::array();
    std::map<std::string, std::string> roles;
    std::string type = "if_chain";
    std::uint64_t last_switch_bound = 0;
    std::string last_selector_reg;
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        const std::string m = mnemonic_of(ins);
        auto ops = split_operands(ins.ops);
        propagate_ioctl_register_roles(ins, m, ops, roles, role_evidence);
        if (m == "cmp" || m == "sub") {
            const std::string role = comparison_role_for_operands(ins, ops, roles);
            const bool role_is_ioctl = role == "io_control_code" || role == "ioctl_normalized_selector" || role == "ioctl_function_selector";
            const std::uint64_t imm = ins.has_imm ? ins.imm_unsigned : 0;
            if (role == "ioctl_function_selector" && imm != 0)
                last_switch_bound = std::max<std::uint64_t>(last_switch_bound, imm);
            if (role_is_ioctl && !ops.empty())
                last_selector_reg = reg_from_operand(ops[0]);
            if (!looks_ioctl(imm) && !(role == "io_control_code" && imm != 0 && imm <= 0xFFFFFFFFULL))
                continue;
            std::uint64_t target = 0;
            std::string branch_kind = "none";
            std::string target_source = "comparison_va";
            for (std::size_t j = i + 1; j < insns.size() && j < i + 6; ++j) {
                if (!insns[j].is_branch)
                    continue;
                const std::string bm = mnemonic_of(insns[j]);
                branch_kind = bm;
                if ((bm == "jne" || bm == "jnz") && j + 1 < insns.size()) {
                    target = insns[j].addr + static_cast<std::uint64_t>(std::max(insns[j].len, 1));
                    target_source = "fallthrough_after_not_equal_branch";
                } else if (insns[j].branch_target) {
                    target = insns[j].branch_target;
                    target_source = "conditional_branch_target";
                }
                break;
            }
            json cmp = json{{"compare_va", sa_format_address(ins.addr)},
                            {"ioctl_code", sa_format_address(imm)},
                            {"comparison_role", role.empty() ? "immediate_ioctl_constant" : role},
                            {"instruction", instruction_to_json(ins)},
                            {"branch_kind", branch_kind},
                            {"handler_target", target ? json(sa_format_address(target)) : json(nullptr)},
                            {"target_source", target_source}};
            if (looks_ioctl(imm))
                cmp["decoded_ioctl"] = decode_ioctl_code(imm);
            else if (role == "ioctl_function_selector")
                cmp["ioctl_selector"] = imm;
            comparisons.push_back(cmp);
            json handler_entry{{"ioctl_code", sa_format_address(imm)},
                               {"handler_va", target ? sa_format_address(target) : sa_format_address(ins.addr)},
                               {"compare_va", sa_format_address(ins.addr)},
                               {"dispatch_evidence", cmp},
                               {"confidence", target ? 0.86 : 0.62}};
            if (cmp.contains("decoded_ioctl"))
                handler_entry["decoded_ioctl"] = cmp["decoded_ioctl"];
            if (cmp.contains("ioctl_selector"))
                handler_entry["ioctl_selector"] = cmp["ioctl_selector"];
            handlers.push_back(std::move(handler_entry));
        }
        if (m == "jmp" && ins.has_mem_op) {
            type = "jump_table";
            const std::uint64_t table_va = rip_relative_memory_target(ins);
            json jt{{"jmp_va", sa_format_address(ins.addr)},
                    {"instruction", instruction_to_json(ins)},
                    {"selector_register", last_selector_reg.empty() ? "unknown" : last_selector_reg},
                    {"selector_bound", last_switch_bound},
                    {"table_va", table_va ? json(sa_format_address(table_va)) : json(nullptr)},
                    {"entries", json::array()}};
            if (table_va && last_switch_bound != 0 && last_switch_bound <= 256) {
                for (std::uint64_t n = 0; n <= last_switch_bound && n < 256; ++n) {
                    std::uint64_t entry = 0;
                    if (!read_target_value(pid, table_va + n * sizeof(std::uint64_t), entry))
                        break;
                    if (entry)
                        jt["entries"].push_back(json{{"selector", n}, {"handler_va", sa_format_address(entry)}});
                }
            }
            jump_tables.push_back(std::move(jt));
        }
    }
    if (handlers.size() > 3 && type != "jump_table")
        type = "switch";
    return json{{"dispatch_type", type},
                {"dispatch_va", sa_format_address(handler)},
                {"ioctl_handlers", handlers},
                {"comparison_evidence", comparisons},
                {"register_role_evidence", role_evidence},
                {"jump_tables", jump_tables},
                {"instructions_scanned", insns.size()},
                {"confidence", handlers.empty() ? 0.2 : std::min(0.93, 0.5 + handlers.size() * 0.08 + (jump_tables.empty() ? 0.0 : 0.08))}};
}

inline tool_result_t drv_find_ioctl_dispatch(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto handler = parse_param_u64(params, "device_control_handler_va");
    if (!handler)
        handler = parse_param_u64(params, "handler_va");
    if (!handler)
        return tool_result_t::error("device_control_handler_va is required");
    json out = drv_analyze_ioctl_dispatch(0, *handler);
    return tool_result_t::ok("IOCTL dispatch scan completed", out);
}

inline json decode_ioctl_code(std::uint64_t code)
{
    static const std::array<const char*, 4> methods = { "BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER" };
    static const std::array<const char*, 4> access = { "ANY", "READ", "WRITE", "READ_WRITE" };
    json j;
    j["ioctl_code"] = sa_format_address(code);
    j["device_type"] = static_cast<std::uint32_t>((code >> 16) & 0xFFFFu);
    j["access"] = access[static_cast<std::size_t>((code >> 14) & 3u)];
    j["function"] = static_cast<std::uint32_t>((code >> 2) & 0xFFFu);
    j["method"] = methods[static_cast<std::size_t>(code & 3u)];
    return j;
}

inline json drv_buffer_usage_analysis(std::uint32_t pid, std::uint64_t handler, const std::string& method)
{
    auto insns = disassemble_target(pid, handler, 0x8000, 2048);
    json events = json::array();
    bool input_length = false;
    bool output_length = false;
    bool system_buffer = false;
    bool type3_input = false;
    bool user_buffer = false;
    bool mdl_buffer = false;
    bool probe_read = false;
    bool probe_write = false;
    bool length_compare = false;
    bool output_length_check = false;
    bool integer_overflow_guard = false;
    std::size_t first_pointer_event = static_cast<std::size_t>(-1);
    std::size_t first_length_event = static_cast<std::size_t>(-1);
    std::size_t first_probe_event = static_cast<std::size_t>(-1);
    auto record = [&](std::size_t index, const char* role, const AsmInstr& ins) {
        if (events.size() < 128)
            events.push_back(json{{"order", index}, {"role", role}, {"va", sa_format_address(ins.addr)}, {"instruction", instruction_to_json(ins)}});
    };
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        const std::string m = mnemonic_of(ins);
        const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
        const std::string stack_role = ioctl_stack_role_from_instruction(ins);
        if (stack_role == "input_buffer_length") {
            input_length = true;
            first_length_event = std::min(first_length_event, i);
            record(i, "input_buffer_length", ins);
        } else if (stack_role == "output_buffer_length") {
            output_length = true;
            output_length_check = output_length_check || m == "cmp" || m == "test";
            first_length_event = std::min(first_length_event, i);
            record(i, "output_buffer_length", ins);
        } else if (stack_role == "type3_input_buffer") {
            type3_input = true;
            first_pointer_event = std::min(first_pointer_event, i);
            record(i, "type3_input_buffer", ins);
        }
        if (text.find("systembuffer") != std::string::npos || text.find("associatedirp.systembuffer") != std::string::npos) {
            system_buffer = true;
            first_pointer_event = std::min(first_pointer_event, i);
            record(i, "system_buffer", ins);
        }
        if (text.find("userbuffer") != std::string::npos || text.find("user buffer") != std::string::npos) {
            user_buffer = true;
            first_pointer_event = std::min(first_pointer_event, i);
            record(i, "user_buffer", ins);
        }
        if (text.find("mdladdress") != std::string::npos || text.find("mmbuildmdl") != std::string::npos || text.find("mmgetsystemaddressformdlsafe") != std::string::npos) {
            mdl_buffer = true;
            first_pointer_event = std::min(first_pointer_event, i);
            record(i, "mdl_buffer", ins);
        }
        if (text.find("probeforread") != std::string::npos || text.find("probe for read") != std::string::npos) {
            probe_read = true;
            first_probe_event = std::min(first_probe_event, i);
            record(i, "probe_for_read", ins);
        }
        if (text.find("probeforwrite") != std::string::npos || text.find("probe for write") != std::string::npos) {
            probe_write = true;
            first_probe_event = std::min(first_probe_event, i);
            record(i, "probe_for_write", ins);
        }
        if (m == "cmp" || m == "test") {
            if (stack_role == "input_buffer_length" || stack_role == "output_buffer_length" || ins.has_imm) {
                length_compare = true;
                first_length_event = std::min(first_length_event, i);
                if (stack_role == "output_buffer_length")
                    output_length_check = true;
                record(i, "length_compare", ins);
            }
        }
        if (m == "jo" || m == "jno" || m == "jb" || m == "jbe" || m == "jc" || m == "jae" || text.find("safeint") != std::string::npos) {
            integer_overflow_guard = true;
            record(i, "integer_overflow_guard", ins);
        }
    }
    const bool method_buffered = method == "BUFFERED";
    const bool method_direct = method == "IN_DIRECT" || method == "OUT_DIRECT";
    const bool method_neither = method == "NEITHER";
    const bool input_used = input_length || system_buffer || type3_input || method_buffered || method_direct || method_neither;
    const bool output_used = output_length || user_buffer || system_buffer || mdl_buffer || method_buffered || method_direct || method_neither;
    json out;
    out["input_buffer_used"] = input_used;
    out["output_buffer_used"] = output_used;
    out["input_length_observed"] = input_length;
    out["output_length_observed"] = output_length;
    out["system_buffer_observed"] = system_buffer;
    out["type3_input_buffer_observed"] = type3_input;
    out["user_buffer_observed"] = user_buffer;
    out["mdl_buffer_observed"] = mdl_buffer;
    out["probe_for_read_observed"] = probe_read;
    out["probe_for_write_observed"] = probe_write;
    out["length_compare_observed"] = length_compare;
    out["output_length_check_observed"] = output_length_check;
    out["integer_overflow_guard_observed"] = integer_overflow_guard;
    out["pointer_before_length"] = first_pointer_event != static_cast<std::size_t>(-1) && (first_length_event == static_cast<std::size_t>(-1) || first_pointer_event < first_length_event);
    out["probe_after_pointer"] = first_probe_event != static_cast<std::size_t>(-1) && first_pointer_event != static_cast<std::size_t>(-1) && first_probe_event > first_pointer_event;
    out["events"] = events;
    out["instructions_scanned"] = insns.size();
    return out;
}

inline tool_result_t drv_enumerate_ioctls(const json& params)
{
    if (!params.contains("ioctl_handlers") || !params["ioctl_handlers"].is_array())
        return tool_result_t::error("ioctl_handlers array from drv_find_ioctl_dispatch is required");
    json out = json::array();
    for (const auto& h : params["ioctl_handlers"]) {
        auto code = parse_u64_json(h.value("ioctl_code", json()));
        if (!code)
            continue;
        json e = decode_ioctl_code(*code);
        e["handler_va"] = h.value("handler_va", std::string("unknown"));
        const std::string method = e.value("method", std::string());
        auto handler = parse_u64_json(h.value("handler_va", json()));
        json usage = handler ? drv_buffer_usage_analysis(0, *handler, method) : json::object();
        e["input_buffer_used"] = usage.value("input_buffer_used", true);
        e["output_buffer_used"] = usage.value("output_buffer_used", method == "BUFFERED" || method == "OUT_DIRECT" || method == "NEITHER");
        e["buffer_usage"] = usage;
        if (h.contains("dispatch_evidence"))
            e["dispatch_evidence"] = h["dispatch_evidence"];
        e["risk"] = method == "NEITHER" ? "high" : (method == "BUFFERED" ? "medium" : "medium");
        out.push_back(std::move(e));
    }
    return tool_result_t::ok(json(out));
}

inline tool_result_t drv_map_ioctls(const json& params)
{
    json handlers = params.value("ioctl_handlers", json::array());
    json dispatch = json::object();
    if (!handlers.is_array() || handlers.empty()) {
        auto mapped = drv_find_ioctl_dispatch(params);
        if (!mapped.success)
            return mapped;
        dispatch = mapped.data;
        handlers = dispatch.value("ioctl_handlers", json::array());
    }
    if (!handlers.is_array())
        return tool_result_t::error("ioctl_handlers must be an array or device_control_handler_va must be provided");
    auto decoded = drv_enumerate_ioctls(json{{"ioctl_handlers", handlers}});
    if (!decoded.success)
        return decoded;
    json out = dispatch.is_object() ? dispatch : json::object();
    out["ioctl_handlers"] = handlers;
    out["ioctls"] = decoded.data;
    out["ioctl_count"] = decoded.data.is_array() ? decoded.data.size() : 0;
    out["handler_count"] = handlers.is_array() ? handlers.size() : 0;
    out["provided_handler_count"] = params.contains("ioctl_handlers") && params["ioctl_handlers"].is_array() ? params["ioctl_handlers"].size() : 0;
    out["decoded_count"] = out["ioctl_count"];
    out["mapped_dispatch_used"] = !dispatch.empty();
    out["analysis_backend"] = "bounded_static_ioctl_decode";
    out["source"] = dispatch.empty() ? "provided_ioctl_handlers" : "mapped_device_control_handler";
    return tool_result_t::ok("IOCTL map completed", out);
}

inline bool utf16_at(const std::vector<std::uint8_t>& data, std::size_t pos, const wchar_t* prefix)
{
    for (std::size_t i = 0; prefix[i] != 0; ++i) {
        const std::size_t off = pos + i * sizeof(wchar_t);
        if (off + 1 >= data.size())
            return false;
        wchar_t ch = 0;
        std::memcpy(&ch, data.data() + off, sizeof(wchar_t));
        if (ch != prefix[i])
            return false;
    }
    return true;
}

inline std::string read_utf16_ascii(const std::vector<std::uint8_t>& data, std::size_t pos, std::size_t max_chars)
{
    std::string out;
    for (std::size_t i = 0; i < max_chars; ++i) {
        const std::size_t off = pos + i * sizeof(wchar_t);
        if (off + 1 >= data.size())
            break;
        wchar_t ch = 0;
        std::memcpy(&ch, data.data() + off, sizeof(wchar_t));
        if (ch == 0)
            break;
        out.push_back(ch >= 32 && ch < 127 ? static_cast<char>(ch) : '?');
    }
    return out;
}

inline std::vector<AsmInstr> disassemble_loaded_bytes_window(std::uint64_t va, const std::vector<std::uint8_t>& bytes, std::uint32_t max_insns)
{
    std::vector<AsmInstr> out;
    std::size_t off = 0;
    while (off < bytes.size() && out.size() < max_insns) {
        const int avail = static_cast<int>(std::min<std::size_t>(15, bytes.size() - off));
        AsmInstr ins = zydis_decode_one(bytes.data() + off, avail, va + off);
        if (ins.len <= 0)
            ins.len = 1;
        out.push_back(ins);
        off += static_cast<std::size_t>(ins.len);
    }
    return out;
}

inline json drv_device_name_call_sites(const target_module_t& mod,
                                       const pe_layout_t& pe,
                                       const std::vector<std::uint8_t>& image,
                                       std::uint64_t string_va,
                                       const std::string& type)
{
    json sites = json::array();
    for (const auto& sec : pe.sections) {
        if (!executable_characteristics(sec.characteristics))
            continue;
        if (sec.va < mod.base)
            continue;
        const std::uint64_t off64 = sec.va - mod.base;
        if (off64 >= image.size())
            continue;
        const std::size_t off = static_cast<std::size_t>(off64);
        const std::size_t avail = std::min<std::size_t>(image.size() - off, static_cast<std::size_t>(std::min<std::uint32_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 0x100000)));
        if (avail == 0)
            continue;
        std::vector<std::uint8_t> sec_bytes(image.begin() + static_cast<std::ptrdiff_t>(off), image.begin() + static_cast<std::ptrdiff_t>(off + avail));
        auto insns = disassemble_loaded_bytes_window(sec.va, sec_bytes, 65536);
        for (std::size_t i = 0; i < insns.size(); ++i) {
            const auto& ins = insns[i];
            bool references_string = false;
            std::string reference_source;
            if (ins.has_imm && ins.imm_unsigned == string_va) {
                references_string = true;
                reference_source = "immediate";
            }
            const std::uint64_t rip_target = rip_relative_memory_target(ins);
            if (!references_string && rip_target == string_va) {
                references_string = true;
                reference_source = "rip_relative_memory";
            }
            if (!references_string)
                continue;
            json calls = json::array();
            for (std::size_t j = i + 1; j < insns.size() && j <= i + 24; ++j) {
                if (!insns[j].is_call)
                    continue;
                const std::size_t call_order = calls.size();
                const std::string inferred = call_order == 0 ? "RtlInitUnicodeString_or_inline_string_helper" : (type == "device" ? "IoCreateDevice_or_IoCreateDeviceSecure" : "IoCreateSymbolicLink");
                calls.push_back(json{{"call_va", sa_format_address(insns[j].addr)},
                                     {"target_va", insns[j].branch_target ? json(sa_format_address(insns[j].branch_target)) : json(nullptr)},
                                     {"call_order_after_reference", call_order},
                                     {"api_inferred", inferred},
                                     {"confidence", call_order == 0 ? 0.5 : 0.72},
                                     {"instruction", instruction_to_json(insns[j])}});
                if (calls.size() >= 3)
                    break;
            }
            sites.push_back(json{{"reference_va", sa_format_address(ins.addr)},
                                 {"reference_source", reference_source},
                                 {"reference_instruction", instruction_to_json(ins)},
                                 {"section", sec.name},
                                 {"calls_after_reference", calls},
                                 {"api_evidence_state", calls.empty() ? "string_reference_only" : "string_reference_with_nearby_calls"}});
            if (sites.size() >= 32)
                return sites;
        }
    }
    return sites;
}

inline tool_result_t drv_find_device_names(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::uint64_t timeout_ms = std::clamp<std::uint64_t>(parse_param_u64(params, "timeout_ms").value_or(15000), 500, 60000);
    const std::uint64_t local_deadline = started_ms > std::numeric_limits<std::uint64_t>::max() - timeout_ms ? std::numeric_limits<std::uint64_t>::max() : started_ms + timeout_ms;
    bool deadline_hit = false;
    bool cancelled = false;
    std::string stop_phase;
    std::size_t modules_scanned = 0;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t string_candidates_inspected = 0;
    json module_diagnostics = json::array();
    auto stop_requested = [&](const char* phase) -> bool {
        if (cancelled || deadline_hit)
            return true;
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            stop_phase = phase ? phase : "";
            return true;
        }
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        const std::uint64_t now = GetTickCount64();
        if ((call_deadline != 0 && now >= call_deadline) || now >= local_deadline)
        {
            deadline_hit = true;
            stop_phase = phase ? phase : "";
            return true;
        }
        return false;
    };
    auto partial_payload = [&]() {
        json out;
        out["names"] = json::array();
        out["count"] = 0;
        out["partial"] = true;
        out["deadline_hit"] = deadline_hit;
        out["cancelled"] = cancelled;
        out["phase"] = stop_phase;
        out["timeout_ms"] = timeout_ms;
        out["elapsed_ms"] = GetTickCount64() - started_ms;
        out["modules_scanned"] = modules_scanned;
        out["bytes_scanned"] = bytes_scanned;
        out["string_candidates_inspected"] = string_candidates_inspected;
        out["module_diagnostics"] = module_diagnostics;
        out["mutation"] = "none";
        out["diag_id"] = mcp_standalone::current_call_diag_id();
        out["call_site_policy"] = "Unicode device-name strings are correlated with nearby code references and call instructions; unresolved call targets are marked as inferred.";
        return out;
    };
    std::vector<target_module_t> mods;
    if (params.contains("driver_name") || params.contains("module_name") || params.contains("module_base") || params.contains("module")) {
        std::string err;
        auto m = select_module(params, true, &err);
        if (!m)
            return tool_result_t::error(err);
        mods.push_back(*m);
    } else {
        std::string err;
        mods = kernel_modules(&err);
        if (mods.empty())
            return tool_result_t::error(err.empty() ? "No kernel modules found" : err);
    }
    const std::uint32_t max_modules = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "max_modules").value_or(32)), 1, 128);
    const std::uint64_t read_chunk_size = std::clamp<std::uint64_t>(parse_param_u64(params, "chunk_size").value_or(256ull * 1024ull), 0x1000ull, 1024ull * 1024ull);
    json found = json::array();
    auto partial_with_found = [&]() {
        json out = partial_payload();
        out["names"] = found;
        out["count"] = found.size();
        return out;
    };
    std::set<std::string> seen;
    for (std::size_t mi = 0; mi < mods.size() && mi < max_modules; ++mi) {
        if (stop_requested("module_loop"))
            return tool_result_t::error(cancelled ? "Driver device-name scan cancelled." : "Driver device-name scan deadline reached.", partial_with_found());
        const auto& mod = mods[mi];
        json mod_diag{{"module", mod.name}, {"base", sa_format_address(mod.base)}, {"size", mod.size}};
        const std::uint64_t module_started_ms = GetTickCount64();
        const std::uint64_t scan_size = std::min<std::uint64_t>(mod.size ? mod.size : 0x200000, 16ull * 1024ull * 1024ull);
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(scan_size), 0);
        std::uint64_t module_bytes_read = 0;
        std::uint32_t chunks_attempted = 0;
        std::uint32_t chunks_ok = 0;
        std::uint32_t chunks_failed = 0;
        bool chunk_short_read = false;
        json chunk_diagnostics = json::array();
        for (std::uint64_t off = 0; off < scan_size;) {
            if (stop_requested("module_chunk_read"))
            {
                mod_diag["partial"] = true;
                mod_diag["read_cancelled"] = cancelled;
                mod_diag["deadline_hit"] = deadline_hit;
                mod_diag["last_read_rva"] = off;
                mod_diag["elapsed_ms"] = GetTickCount64() - module_started_ms;
                mod_diag["bytes_read"] = module_bytes_read;
                mod_diag["chunks_attempted"] = chunks_attempted;
                mod_diag["chunks_ok"] = chunks_ok;
                mod_diag["chunks_failed"] = chunks_failed;
                mod_diag["chunk_size"] = read_chunk_size;
                mod_diag["chunk_diagnostics"] = chunk_diagnostics;
                bytes_scanned += module_bytes_read;
                if (module_bytes_read >= 16)
                    ++modules_scanned;
                module_diagnostics.push_back(std::move(mod_diag));
                return tool_result_t::error(cancelled ? "Driver device-name scan cancelled." : "Driver device-name scan deadline reached.", partial_with_found());
            }
            const std::uint64_t chunk_size_u64 = std::min<std::uint64_t>(read_chunk_size, scan_size - off);
            std::vector<std::uint8_t> chunk;
            const std::uint64_t chunk_started = GetTickCount64();
            const bool chunk_ok = read_target_memory(0, mod.base + off, static_cast<std::size_t>(chunk_size_u64), chunk) && !chunk.empty();
            const std::uint64_t chunk_elapsed = GetTickCount64() - chunk_started;
            ++chunks_attempted;
            if (chunk_ok) {
                ++chunks_ok;
                const std::size_t copy_size = std::min<std::size_t>(chunk.size(), static_cast<std::size_t>(chunk_size_u64));
                std::memcpy(bytes.data() + static_cast<std::size_t>(off), chunk.data(), copy_size);
                module_bytes_read += copy_size;
                if (copy_size < chunk_size_u64)
                    chunk_short_read = true;
            } else {
                ++chunks_failed;
            }
            if (chunk_diagnostics.size() < 64) {
                chunk_diagnostics.push_back(json{{"rva", off},
                                                 {"va", sa_format_address(mod.base + off)},
                                                 {"requested", chunk_size_u64},
                                                 {"ok", chunk_ok},
                                                 {"bytes", chunk.size()},
                                                 {"elapsed_ms", chunk_elapsed}});
            }
            off += chunk_size_u64;
        }
        if (module_bytes_read < 16)
        {
            mod_diag["read_ok"] = false;
            mod_diag["elapsed_ms"] = GetTickCount64() - module_started_ms;
            mod_diag["scan_size"] = scan_size;
            mod_diag["chunk_size"] = read_chunk_size;
            mod_diag["bytes_read"] = module_bytes_read;
            mod_diag["chunks_attempted"] = chunks_attempted;
            mod_diag["chunks_ok"] = chunks_ok;
            mod_diag["chunks_failed"] = chunks_failed;
            mod_diag["chunk_short_read"] = chunk_short_read;
            mod_diag["chunk_diagnostics"] = chunk_diagnostics;
            module_diagnostics.push_back(std::move(mod_diag));
            continue;
        }
        bytes_scanned += module_bytes_read;
        ++modules_scanned;
        mod_diag["read_ok"] = true;
        mod_diag["scan_size"] = scan_size;
        mod_diag["chunk_size"] = read_chunk_size;
        mod_diag["bytes_read"] = module_bytes_read;
        mod_diag["bytes_buffered"] = bytes.size();
        mod_diag["chunks_attempted"] = chunks_attempted;
        mod_diag["chunks_ok"] = chunks_ok;
        mod_diag["chunks_failed"] = chunks_failed;
        mod_diag["chunk_short_read"] = chunk_short_read;
        mod_diag["chunk_diagnostics"] = chunk_diagnostics;
        pe_layout_t pe;
        const bool pe_ok = read_pe_layout(0, mod.base, pe);
        for (std::size_t i = 0; i + 16 < bytes.size(); i += 2) {
            if ((i & 0x3FFFu) == 0 && stop_requested("string_scan"))
            {
                mod_diag["partial"] = true;
                mod_diag["last_rva"] = i;
                mod_diag["elapsed_ms"] = GetTickCount64() - module_started_ms;
                module_diagnostics.push_back(std::move(mod_diag));
                return tool_result_t::error(cancelled ? "Driver device-name scan cancelled." : "Driver device-name scan deadline reached.", partial_with_found());
            }
            const char* type = nullptr;
            if (i + 1 < bytes.size() && bytes[i] == 0x5C && bytes[i + 1] == 0x00) {
                if (utf16_at(bytes, i, L"\\Device\\"))
                    type = "device";
                else if (utf16_at(bytes, i, L"\\DosDevices\\") || utf16_at(bytes, i, L"\\??\\"))
                    type = "symlink";
            }
            if (!type)
                continue;
            std::string name = read_utf16_ascii(bytes, i, 260);
            if (name.size() < 4)
                continue;
            ++string_candidates_inspected;
            const std::uint64_t string_va = mod.base + i;
            const std::string seen_key = mod.name + "|" + sa_format_address(string_va) + "|" + type;
            if (!seen.insert(seen_key).second)
                continue;
            json call_sites = pe_ok ? drv_device_name_call_sites(mod, pe, bytes, string_va, type) : json::array();
            json first_call = nullptr;
            for (const auto& site : call_sites) {
                if (!site.contains("calls_after_reference") || !site["calls_after_reference"].is_array())
                    continue;
                for (const auto& call : site["calls_after_reference"]) {
                    const std::string inferred = call.value("api_inferred", std::string());
                    if ((std::string(type) == "device" && inferred.find("IoCreateDevice") != std::string::npos) ||
                        (std::string(type) == "symlink" && inferred.find("IoCreateSymbolicLink") != std::string::npos)) {
                        first_call = call;
                        break;
                    }
                }
                if (!first_call.is_null())
                    break;
            }
            found.push_back(json{{"call_va", first_call.is_object() ? first_call.value("call_va", std::string("unknown")) : std::string("unknown")},
                                 {"string_va", sa_format_address(string_va)},
                                 {"type", type},
                                 {"name", name},
                                 {"module", mod.name},
                                 {"call_sites", call_sites},
                                 {"call_site_count", call_sites.size()},
                                 {"api_evidence_state", call_sites.empty() ? "string_only_no_code_reference_found" : "string_reference_with_callsite_candidates"},
                                 {"confidence", call_sites.empty() ? 0.55 : 0.82}});
            if (found.size() >= 256)
                break;
        }
        mod_diag["elapsed_ms"] = GetTickCount64() - module_started_ms;
        mod_diag["pe_parsed"] = pe_ok;
        module_diagnostics.push_back(std::move(mod_diag));
        if (found.size() >= 256)
            break;
    }
    json out;
    out["names"] = found;
    out["count"] = found.size();
    out["confidence"] = found.empty() ? 0.0 : 0.82;
    out["call_site_policy"] = "Unicode device-name strings are correlated with nearby code references and call instructions; unresolved call targets are marked as inferred.";
    out["partial"] = false;
    out["deadline_hit"] = false;
    out["cancelled"] = false;
    out["timeout_ms"] = timeout_ms;
    out["elapsed_ms"] = GetTickCount64() - started_ms;
    out["modules_scanned"] = modules_scanned;
    out["bytes_scanned"] = bytes_scanned;
    out["string_candidates_inspected"] = string_candidates_inspected;
    out["module_diagnostics"] = module_diagnostics;
    if (modules_scanned == 0) {
        return tool_result_t::error("Kernel module memory read failed for all scanned modules. No device-name strings could be extracted.", out);
    }
    return tool_result_t::ok("Driver device-name scan completed", out);
}

inline tool_result_t drv_check_buffer_safety(const json& params)
{
    if (!params.contains("ioctl_handlers") || !params["ioctl_handlers"].is_array())
        return tool_result_t::error("ioctl_handlers array is required");
    json issues = json::array();
    json analyses = json::array();
    for (const auto& h : params["ioctl_handlers"]) {
        auto code = parse_u64_json(h.value("ioctl_code", json()));
        auto handler = parse_u64_json(h.value("handler_va", json()));
        if (!code || !handler)
            continue;
        json dec = decode_ioctl_code(*code);
        const std::string method = dec.value("method", std::string());
        json usage = drv_buffer_usage_analysis(0, *handler, method);
        analyses.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"method", method}, {"buffer_usage", usage}});
        const bool probe_read = usage.value("probe_for_read_observed", false);
        const bool probe_write = usage.value("probe_for_write_observed", false);
        const bool length_cmp = usage.value("length_compare_observed", false);
        const bool output_len = usage.value("output_length_check_observed", false);
        const bool pointer_before_length = usage.value("pointer_before_length", false);
        const bool probe_after_pointer = usage.value("probe_after_pointer", false);
        const bool overflow_guard = usage.value("integer_overflow_guard_observed", false);
        if (method == "NEITHER" && (!probe_read || !probe_write))
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "method_neither_without_obvious_probe"}, {"va", sa_format_address(*handler)}, {"description", "METHOD_NEITHER exposes raw user pointers and bounded ordered dataflow did not prove both ProbeForRead and ProbeForWrite before use."}, {"severity", "critical"}, {"confidence", 0.8}, {"ordered_evidence", usage.value("events", json::array())}});
        if (method == "NEITHER" && probe_after_pointer)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "method_neither_probe_after_pointer_use"}, {"va", sa_format_address(*handler)}, {"description", "Probe evidence appears after a raw pointer reference in the bounded instruction order."}, {"severity", "critical"}, {"confidence", 0.76}, {"ordered_evidence", usage.value("events", json::array())}});
        if (pointer_before_length)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "pointer_before_length_validation"}, {"va", sa_format_address(*handler)}, {"description", "A buffer pointer reference appears before any recognized input/output length validation in the bounded scan."}, {"severity", method == "NEITHER" ? "high" : "medium"}, {"confidence", 0.68}, {"ordered_evidence", usage.value("events", json::array())}});
        if (!length_cmp)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "missing_obvious_length_validation"}, {"va", sa_format_address(*handler)}, {"description", "No ordered input/output length comparison was recognized before buffer use in the bounded handler scan."}, {"severity", method == "NEITHER" ? "high" : "medium"}, {"confidence", 0.62}, {"ordered_evidence", usage.value("events", json::array())}});
        if (usage.value("output_buffer_used", false) && !output_len)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "missing_output_length_check"}, {"va", sa_format_address(*handler)}, {"description", "Output buffer use is likely, but no ordered output length check was recognized."}, {"severity", "high"}, {"confidence", 0.64}, {"ordered_evidence", usage.value("events", json::array())}});
        if ((usage.value("input_length_observed", false) || usage.value("output_length_observed", false)) && !overflow_guard)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "integer_overflow_guard_not_proven"}, {"va", sa_format_address(*handler)}, {"description", "Length dataflow was observed, but no carry/overflow guard was recognized in the bounded scan."}, {"severity", "medium"}, {"confidence", 0.5}, {"ordered_evidence", usage.value("events", json::array())}});
    }
    return tool_result_t::ok(json{{"issues", issues}, {"issue_count", issues.size()}, {"issues_shape", "array"}, {"issue_schema", json{{"ioctl_code", "hex_string"}, {"handler_va", "hex_string"}, {"issue_type", "string"}, {"va", "hex_string"}, {"description", "string"}, {"severity", "string"}, {"confidence", "number"}, {"ordered_evidence", "array"}}}, {"analyses", analyses}, {"analysis_count", analyses.size()}, {"analysis_backend", "bounded_static_ioctl_buffer_safety"}});
}

struct drv_hook_state_t {
    std::string hook_id;
    std::string driver_name;
    std::uint32_t irp_code = 0;
    std::uint64_t callback_va = 0;
    bool installed = false;
};

inline std::mutex& drv_hook_mutex()
{
    static std::mutex m;
    return m;
}

inline std::map<std::string, drv_hook_state_t>& drv_hook_states()
{
    static std::map<std::string, drv_hook_state_t> s;
    return s;
}

inline json drv_hook_fail_closed_contract(const std::string& reason)
{
    return json{{"backend", "fail_closed_state_only"},
                {"fail_closed_state_only", true},
                {"safe_backend_available", false},
                {"raw_dispatch_patching_allowed", false},
                {"required_capability", "signed_kernel_irp_observer_backend_with_restore_and_audit"},
                {"mutation", "none"},
                {"classification_hint", "security_guard_pass"},
                {"security_guard_pass", true},
                {"count", 0},
                {"reason", reason},
                {"security_contract", "fail_closed_no_kernel_dispatch_mutation"},
                {"supported_actions", json::array({"status", "list", "stop", "remove"})},
                {"unsupported_actions", json::array({"install", "start"})}};
}

inline tool_result_t drv_hook_manage(const json& params)
{
    const std::string action = lower_ascii(compat_action_name(params));
    const json p = compat_action_payload(params);
    if (action == "list" || action == "status" || action.empty()) {
        std::lock_guard<std::mutex> lk(drv_hook_mutex());
        drv_hook_states().clear();
        json out = drv_hook_fail_closed_contract("raw_dispatch_patching_disabled_no_safe_kernel_backend");
        out["action"] = action.empty() ? "status" : action;
        out["hooks"] = json::array();
        return tool_result_t::ok(out);
    }
    if (action == "remove" || action == "stop") {
        const std::string id = p.value("hook_id", std::string());
        if (id.empty()) {
            json out = drv_hook_fail_closed_contract("hook_id_required_no_kernel_mutation_performed");
            out["action"] = action;
            out["stopped"] = false;
            out["mutation"] = "none";
            return tool_result_t::error("hook_id is required for " + action, out);
        }
        std::lock_guard<std::mutex> lk(drv_hook_mutex());
        const auto erased = drv_hook_states().erase(id);
        json out = drv_hook_fail_closed_contract(erased ? "state_only_record_removed_no_kernel_mutation" : "hook_id_not_found_no_kernel_mutation_performed");
        out["action"] = action;
        out["hook_id"] = id;
        out["removed"] = erased != 0;
        out["stopped"] = erased != 0;
        out["mutation"] = "none";
        out["state_record_removed"] = erased != 0;
        out["hooks"] = json::array();
        return erased ? tool_result_t::ok(out) : tool_result_t::error("hook_id not found", out);
    }
    if (action == "install" || action == "start") {
        json out = drv_hook_fail_closed_contract("unsupported_without_existing_safe_kernel_backend");
        out["action"] = action;
        out["installed"] = false;
        out["started"] = false;
        out["mutation"] = "none";
        out["driver_name"] = p.value("driver_name", std::string());
        out["irp_code"] = p.value("irp_code", 0);
        out["irp_name"] = irp_name(p.value("irp_code", 0));
        out["callback_va"] = p.value("callback_va", std::string());
        out["confirm_unsafe_received"] = unsafe_confirmed(params) || unsafe_confirmed(p);
        out["required_capability"] = "signed_kernel_irp_observer_backend_with_restore_and_audit";
        return tool_result_t::error("Kernel IRP hook installation is unsupported in this scope because no safe backend is exposed.", out);
    }
    return compat_unknown_action("drv_hook_manage", action);
}

inline std::wstring utf8_to_wide(const std::string& s)
{
    if (s.empty())
        return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1)
        return {};
    std::wstring w(static_cast<std::size_t>(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

inline tool_result_t drv_send_ioctl(const json& params)
{
    if (!unsafe_confirmed(params))
        return tool_result_t::error("drv_send_ioctl can change device or kernel state. Re-run with confirm_unsafe=true or allow_unsafe=true.",
            destructive_safe_contract_payload("drv_send_ioctl", "send_ioctl", params, "confirm_unsafe_required", "explicit_device_ioctl_dispatch_confirmation"));
    const std::string symlink = params.value("device_symlink", std::string());
    auto code = parse_param_u64(params, "ioctl_code");
    if (symlink.empty() || !code)
    {
        json out = destructive_safe_contract_payload("drv_send_ioctl", "send_ioctl", params, "device_symlink_or_ioctl_code_required", "explicit_device_ioctl_dispatch_confirmation");
        out["device_symlink_present"] = !symlink.empty();
        out["ioctl_code_present"] = code.has_value();
        out["confirm_unsafe_received"] = unsafe_confirmed(params);
        return tool_result_t::error("device_symlink and ioctl_code are required", out);
    }
    std::vector<std::uint8_t> in;
    if (params.contains("input_buffer_hex") && params["input_buffer_hex"].is_string()) {
        std::string hex_error;
        if (!hex_to_bytes_strict(params["input_buffer_hex"].get<std::string>(), in, hex_error))
        {
            json out = destructive_safe_contract_payload("drv_send_ioctl", "send_ioctl", params, "input_buffer_hex_invalid", "explicit_device_ioctl_dispatch_confirmation");
            out["input_buffer_hex_valid"] = false;
            out["validation_error"] = hex_error;
            out["input_buffer_hex_length"] = params["input_buffer_hex"].get<std::string>().size();
            out["confirm_unsafe_received"] = unsafe_confirmed(params);
            return tool_result_t::error(hex_error, out);
        }
    }
    if (in.size() > 1024u * 1024u)
    {
        json out = destructive_safe_contract_payload("drv_send_ioctl", "send_ioctl", params, "input_buffer_too_large", "explicit_device_ioctl_dispatch_confirmation");
        out["input_buffer_size"] = in.size();
        out["max_input_buffer_size"] = 1024u * 1024u;
        out["confirm_unsafe_received"] = unsafe_confirmed(params);
        return tool_result_t::error("input_buffer_hex is too large; max 1MB", out);
    }
    std::uint32_t out_size = static_cast<std::uint32_t>(parse_param_u64(params, "output_buffer_size").value_or(4096));
    out_size = std::clamp<std::uint32_t>(out_size, 0, 1024u * 1024u);
    std::vector<std::uint8_t> out_buf(out_size);
    HANDLE h = CreateFileW(utf8_to_wide(symlink).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD gle = GetLastError();
        json out = destructive_safe_contract_payload("drv_send_ioctl", "send_ioctl", params, "device_open_failed", "explicit_device_ioctl_dispatch_confirmation");
        out["device_symlink"] = symlink;
        out["ioctl_code"] = sa_format_address(*code);
        out["gle"] = gle;
        out["device_open_attempted"] = true;
        out["confirm_unsafe_received"] = unsafe_confirmed(params);
        return tool_result_t::error("CreateFileW failed for device symlink", out);
    }
    DWORD returned = 0;
    SetLastError(0);
    BOOL ok = DeviceIoControl(h, static_cast<DWORD>(*code), in.empty() ? nullptr : in.data(), static_cast<DWORD>(in.size()), out_buf.empty() ? nullptr : out_buf.data(), static_cast<DWORD>(out_buf.size()), &returned, nullptr);
    const DWORD gle = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (returned < out_buf.size())
        out_buf.resize(returned);
    json out;
    out["status"] = ok ? "ok" : "failed";
    out["gle"] = gle;
    out["ioctl_code"] = sa_format_address(*code);
    out["bytes_returned"] = returned;
    out["output_buffer_hex"] = bytes_to_hex(out_buf, 4096);
    out["mutation"] = ok ? "ioctl_dispatched" : "none";
    out["device_symlink"] = symlink;
    out["confirm_unsafe_received"] = unsafe_confirmed(params);
    return ok ? tool_result_t::ok("DeviceIoControl completed", out) : tool_result_t::error("DeviceIoControl failed", out);
}

inline std::string next_prefixed_id(const char* prefix)
{
    static std::atomic<std::uint64_t> next{1};
    char buf[64] = {};
    std::snprintf(buf, sizeof(buf), "%s-%06llu", prefix, static_cast<unsigned long long>(next.fetch_add(1)));
    return std::string(buf);
}

inline json disasm_preview_for_bytes(std::uint64_t va, const std::vector<std::uint8_t>& bytes, std::size_t max_insns = 16)
{
    json arr = json::array();
    std::size_t off = 0;
    while (off < bytes.size() && arr.size() < max_insns) {
        const int avail = static_cast<int>(std::min<std::size_t>(15, bytes.size() - off));
        AsmInstr ins = zydis_decode_one(bytes.data() + off, avail, va + off);
        if (ins.len <= 0)
            ins.len = 1;
        arr.push_back(instruction_to_json(ins));
        off += static_cast<std::size_t>(ins.len);
    }
    return arr;
}

inline std::uint64_t estimate_function_start_near(std::uint32_t pid, std::uint64_t va)
{
    if (va == 0)
        return 0;
    const std::uint64_t scan_back = std::min<std::uint64_t>(va, 0x200);
    const std::uint64_t base = va - scan_back;
    std::vector<std::uint8_t> raw;
    if (!read_target_memory(pid, base, static_cast<std::size_t>(scan_back + 0x40), raw) || raw.empty())
        return va;
    auto insns = disassemble_loaded_bytes_window(base, raw, 256);
    std::uint64_t candidate = va;
    for (const auto& ins : insns) {
        if (ins.addr > va)
            break;
        const std::string m = mnemonic_of(ins);
        const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
        if (ins.is_ret)
            candidate = ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1));
        if ((m == "push" && text.find("rbp") != std::string::npos) ||
            (m == "sub" && text.find("rsp") != std::string::npos) ||
            (m == "endbr64"))
            candidate = ins.addr;
    }
    return candidate;
}

inline json smc_enriched_capture_json(const page_guard_engine::pg_capture_record_t& c, std::uint32_t pid, std::uint64_t watch_va, std::uint64_t watch_size)
{
    json out = page_guard_capture_json(c);
    const auto& m = c.metadata;
    std::vector<std::uint8_t> rip_bytes;
    if (m.rip != 0 && read_target_memory(pid, m.rip, 64, rip_bytes))
        out["rip_disasm_preview"] = disasm_preview_for_bytes(m.rip, rip_bytes, 8);
    else
        out["rip_disasm_preview"] = json::array();
    std::vector<std::uint8_t> fault_bytes;
    if (m.fault_addr != 0 && read_target_memory(pid, m.fault_addr, 64, fault_bytes))
        out["fault_bytes_hex"] = bytes_to_hex(fault_bytes, 64);
    else
        out["fault_bytes_hex"] = "";
    const std::uint64_t function_start = estimate_function_start_near(pid, m.rip);
    out["decryptor_candidate_va"] = function_start ? json(sa_format_address(function_start)) : json(nullptr);
    out["function_start_va"] = function_start ? json(sa_format_address(function_start)) : json(nullptr);
    out["fault_region"] = memory_protection_evidence(pid, m.fault_addr);
    out["rip_region"] = memory_protection_evidence(pid, m.rip);
    out["inside_watch_range"] = watch_size != 0 && m.fault_addr >= watch_va && (m.fault_addr - watch_va) < watch_size;
    out["watch_range"] = json{{"base", sa_format_address(watch_va)}, {"size", watch_size}, {"end", sa_format_address(watch_va + watch_size)}};
    out["write_event"] = m.access_type == 1;
    out["execute_event"] = m.access_type == 8;
    out["callstack_available"] = false;
    out["callstack"] = json::array();
    out["callstack_unavailable_reason"] = "page_guard_capture_record_does_not_include_rsp_or_stack_snapshot";
    return out;
}

inline json smc_active_session_ids_json()
{
    json ids = json::array();
    for (const auto& s : page_guard_engine::g_pg_engine.list_sessions())
        ids.push_back(s.session_id);
    return ids;
}

inline json smc_safe_contract_payload(const char* action, const json& p, const char* contract, const char* validation_code)
{
    json out;
    out["action"] = action ? action : "";
    out["backend"] = "whoswho_driver_page_guard";
    out["required_capability"] = "whoswho_driver_page_guard_confirmed_session";
    out["mutation"] = "none";
    out["side_effects"] = "none";
    out["fail_closed"] = true;
    out["functional_success"] = false;
    out["safe_contract"] = contract ? contract : "fail_closed";
    out["validation_code"] = validation_code ? validation_code : "";
    out["active_session_ids"] = smc_active_session_ids_json();
    out["active_session_count"] = out["active_session_ids"].size();
    out["confirm_unsafe_required"] = std::string(action ? action : "") == "start";
    out["allow_unsafe_alias_accepted"] = true;
    out["allow_unsafe_required"] = false;
    out["confirm_unsafe_received"] = unsafe_confirmed(p);
    out["device_open_attempted"] = false;
    out["security_guard_pass"] = true;
    out["driver_connected"] = driver_bridge::using_kernel_driver() && device && device->is_connected();
    out["diag_id"] = mcp_standalone::current_call_diag_id();
    if (auto id = parse_param_u64(p, "session_id"))
        out["session_id"] = *id;
    if (auto va = parse_param_u64(p, "watch_va"))
        out["watch_va"] = sa_format_address(*va);
    if (auto size = parse_param_u64(p, "watch_size"))
        out["watch_size"] = *size;
    out["capture_on_write"] = p.value("capture_on_write", true);
    out["capture_on_execute"] = p.value("capture_on_execute", true);
    return out;
}

inline tool_result_t smc_manage(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "start") {
        if (!unsafe_confirmed(params) && !unsafe_confirmed(p))
            return tool_result_t::error("smc_manage start installs a target PAGE_GUARD/VEH capture session. Re-run with confirm_unsafe=true or allow_unsafe=true.", smc_safe_contract_payload("start", p, "fail_closed_no_page_guard_install", "confirm_unsafe_required"));
        auto va = parse_param_u64(p, "watch_va");
        auto size = parse_param_u64(p, "watch_size");
        if (!va || !size || *size == 0)
            return tool_result_t::error("watch_va and watch_size are required for start",
                smc_safe_contract_payload("start", p, "fail_closed_invalid_start_params", "watch_va_watch_size_required"));
        const std::uint32_t pid = requested_pid(p);
        if (pid == 0)
            return tool_result_t::error("An attached process or process_id is required",
                smc_safe_contract_payload("start", p, "fail_closed_invalid_start_params", "process_id_required"));
        const std::uint64_t bounded_size = std::min<std::uint64_t>(*size, 1024ull * 1024ull);
        const bool capture_on_write = p.value("capture_on_write", true);
        const bool capture_on_execute = p.value("capture_on_execute", true);
        const bool capture_payloads = capture_on_write || capture_on_execute;
        const std::uint32_t max_records = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(parse_param_u64(p, "max_records_per_drain").value_or(64), 4096));
        const std::uint32_t sid = page_guard_engine::g_pg_engine.install(pid, *va, bounded_size, capture_payloads, max_records, true);
        if (sid == 0) {
            json out = smc_safe_contract_payload("start", p, "fail_closed_page_guard_install_failed", "page_guard_install_failed");
            out["pid"] = pid;
            out["watch_va"] = sa_format_address(*va);
            out["watch_size"] = bounded_size;
            out["capture_payloads"] = capture_payloads;
            out["dependency_blocked"] = true;
            out["failure"] = page_guard_install_failure_json();
            return tool_result_t::error("Failed to install WhosWho driver-backed PAGE_GUARD capture session.", out);
        }
        return tool_result_t::ok("SMC PAGE_GUARD capture session started",
            json{{"session_id", sid}, {"page_guard_session_id", sid}, {"pid", pid}, {"watch_va", sa_format_address(*va)}, {"watch_size", bounded_size}, {"capture_payloads", capture_payloads}, {"capture_on_write", capture_on_write}, {"capture_on_execute", capture_on_execute}, {"max_records_per_drain", max_records}, {"backend", "whoswho_driver_page_guard"}});
    }
    if (action == "captures") {
        const auto id = parse_param_u64(p, "session_id");
        if (!id || *id == 0 || *id > 0xFFFFFFFFULL)
            return tool_result_t::error("session_id is required for captures", smc_safe_contract_payload("captures", p, "fail_closed_invalid_session_id", "session_id_required_or_invalid"));
        std::uint32_t pid = requested_pid(p);
        std::uint64_t watch_va = 0;
        std::uint64_t watch_size = 0;
        bool found_session = false;
        for (const auto& s : page_guard_engine::g_pg_engine.list_sessions()) {
            if (s.session_id == static_cast<std::uint32_t>(*id)) {
                pid = s.pid;
                watch_va = s.target_addr;
                watch_size = s.region_size;
                found_session = true;
                break;
            }
        }
        if (!found_session)
            return tool_result_t::error("session_id not found", smc_safe_contract_payload("captures", p, "fail_closed_missing_session", "session_not_found"));
        auto records = page_guard_engine::g_pg_engine.get_capture_records(static_cast<std::uint32_t>(*id));
        json captures = json::array();
        std::uint64_t write_count = 0;
        std::uint64_t execute_count = 0;
        for (const auto& c : records) {
            if (c.metadata.access_type == 1)
                ++write_count;
            if (c.metadata.access_type == 8)
                ++execute_count;
            captures.push_back(smc_enriched_capture_json(c, pid, watch_va, watch_size));
        }
        return tool_result_t::ok("SMC PAGE_GUARD captures drained",
            json{{"session_id", *id}, {"pid", pid}, {"watch_va", watch_va ? json(sa_format_address(watch_va)) : json(nullptr)}, {"watch_size", watch_size}, {"capture_count", captures.size()}, {"write_event_count", write_count}, {"execute_event_count", execute_count}, {"captures", captures}, {"backend", "whoswho_driver_page_guard"}});
    }
    if (action == "stop") {
        const auto id = parse_param_u64(p, "session_id");
        if (!id || *id == 0 || *id > 0xFFFFFFFFULL)
            return tool_result_t::error("session_id is required for stop", smc_safe_contract_payload("stop", p, "fail_closed_invalid_session_id", "session_id_required_or_invalid"));
        const bool stopped = page_guard_engine::g_pg_engine.uninstall(static_cast<std::uint32_t>(*id));
        return stopped
            ? tool_result_t::ok("SMC PAGE_GUARD capture session stopped", json{{"session_id", *id}, {"backend", "whoswho_driver_page_guard"}})
            : tool_result_t::error("session_id not found", smc_safe_contract_payload("stop", p, "fail_closed_missing_session", "session_not_found"));
    }
    if (action == "list_sessions") {
        json sessions = page_guard_sessions_json();
        return tool_result_t::ok("SMC PAGE_GUARD sessions listed", json{{"sessions", sessions}, {"count", sessions.size()}, {"active_session_ids", smc_active_session_ids_json()}, {"backend", "whoswho_driver_page_guard"}});
    }
    return compat_unknown_action("smc_manage", action);
}

inline bool read_file_bytes_win32(const std::string& path, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (path.empty() || path.rfind("static://", 0) == 0)
        return false;
    HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(hf, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 128ll * 1024ll * 1024ll) {
        CloseHandle(hf);
        return false;
    }
    out.resize(static_cast<std::size_t>(sz.QuadPart));
    DWORD got = 0;
    const BOOL ok = ReadFile(hf, out.data(), static_cast<DWORD>(out.size()), &got, nullptr);
    CloseHandle(hf);
    if (!ok || static_cast<std::size_t>(got) != out.size()) {
        out.clear();
        return false;
    }
    return true;
}

inline json compare_section_to_disk(const mapped_section_t& sec, const std::vector<std::uint8_t>& mapped, const std::vector<std::uint8_t>& file_bytes)
{
    json out;
    out["available"] = false;
    if (file_bytes.empty() || sec.raw_pointer == 0 || sec.raw_pointer >= file_bytes.size()) {
        out["reason"] = file_bytes.empty() ? "module_file_unavailable" : "section_raw_pointer_unavailable";
        return out;
    }
    const std::size_t raw_avail = file_bytes.size() - static_cast<std::size_t>(sec.raw_pointer);
    const std::size_t cmp_size = std::min<std::size_t>(mapped.size(), std::min<std::size_t>(raw_avail, sec.raw_size ? sec.raw_size : mapped.size()));
    if (cmp_size == 0) {
        out["reason"] = "zero_comparable_bytes";
        return out;
    }
    std::uint64_t mismatch_count = 0;
    json first_mismatches = json::array();
    for (std::size_t i = 0; i < cmp_size; ++i) {
        const std::uint8_t disk = file_bytes[static_cast<std::size_t>(sec.raw_pointer) + i];
        const std::uint8_t mem = mapped[i];
        if (disk == mem)
            continue;
        if (first_mismatches.size() < 16)
            first_mismatches.push_back(json{{"offset", i}, {"disk", sa_format_address(disk)}, {"memory", sa_format_address(mem)}});
        ++mismatch_count;
    }
    std::vector<std::uint8_t> disk_slice(file_bytes.begin() + static_cast<std::ptrdiff_t>(sec.raw_pointer), file_bytes.begin() + static_cast<std::ptrdiff_t>(sec.raw_pointer + cmp_size));
    out["available"] = true;
    out["compared_bytes"] = cmp_size;
    out["mismatch_count"] = mismatch_count;
    out["equal"] = mismatch_count == 0;
    out["mismatch_ratio"] = cmp_size ? static_cast<double>(mismatch_count) / static_cast<double>(cmp_size) : 0.0;
    out["disk_entropy"] = entropy_of(disk_slice);
    out["first_mismatches"] = first_mismatches;
    return out;
}

inline tool_result_t smc_scan_encrypted_regions(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::uint32_t pid = requested_pid(params);
    const std::uint64_t timeout_ms = std::clamp<std::uint64_t>(parse_param_u64(params, "timeout_ms").value_or(5500), 500, 30000);
    const std::uint64_t local_deadline = started_ms > std::numeric_limits<std::uint64_t>::max() - timeout_ms ? std::numeric_limits<std::uint64_t>::max() : started_ms + timeout_ms;
    bool deadline_hit = false;
    bool cancelled = false;
    std::string stop_phase;
    auto stop_requested = [&](const char* phase) -> bool {
        if (cancelled || deadline_hit)
            return true;
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            stop_phase = phase ? phase : "";
            return true;
        }
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        const std::uint64_t now = GetTickCount64();
        if ((call_deadline != 0 && now >= call_deadline) || now >= local_deadline)
        {
            deadline_hit = true;
            stop_phase = phase ? phase : "";
            return true;
        }
        return false;
    };
    auto direct_base = parse_param_u64(params, "range_base");
    if (!direct_base)
        direct_base = parse_param_u64(params, "scan_base");
    if (!direct_base)
        direct_base = parse_param_u64(params, "target_va");
    if (!direct_base)
        direct_base = parse_param_u64(params, "watch_va");
    auto direct_size = parse_param_u64(params, "range_size");
    if (!direct_size)
        direct_size = parse_param_u64(params, "scan_size");
    if (!direct_size)
        direct_size = parse_param_u64(params, "target_size");
    if (!direct_size)
        direct_size = parse_param_u64(params, "watch_size");
    if (direct_base && direct_size && *direct_base != 0 && *direct_size != 0) {
        const std::uint64_t bounded_size = std::min<std::uint64_t>(*direct_size, 1024ull * 1024ull);
        std::vector<std::uint8_t> bytes;
        if (!read_target_memory(pid, *direct_base, static_cast<std::size_t>(bounded_size), bytes) || bytes.empty())
            return tool_result_t::error("Could not read bounded SMC scan range", json{{"pid", pid}, {"range_base", sa_format_address(*direct_base)}, {"range_size", bounded_size}, {"direct_range", true}});
        driver_bridge::memory_region_t region{};
        const bool region_ok = driver_bridge::query_memory_for(pid, *direct_base, region);
        const bool mem_exec = region_ok ? executable_protect(region.protect) : false;
        const bool mem_write = region_ok && ((region.protect & 0xFFu) == PAGE_EXECUTE_READWRITE || (region.protect & 0xFFu) == PAGE_EXECUTE_WRITECOPY || (region.protect & 0xFFu) == PAGE_READWRITE || (region.protect & 0xFFu) == PAGE_WRITECOPY);
        std::vector<std::uint8_t> provided_marker;
        std::string marker_source;
        std::string marker_hex_error;
        auto load_marker_hex = [&](const char* key) -> bool {
            if (!params.contains(key) || !params[key].is_string())
                return true;
            marker_source = key;
            return hex_to_bytes_strict(params[key].get<std::string>(), provided_marker, marker_hex_error);
        };
        if (!load_marker_hex("marker_bytes_hex") || !load_marker_hex("marker_hex"))
        {
            json out = destructive_safe_contract_payload("smc_scan_encrypted_regions", "scan", params, "marker_hex_invalid", "bounded_range_marker_or_entropy_evidence");
            out["pid"] = pid;
            out["range_base"] = sa_format_address(*direct_base);
            out["range_size"] = bounded_size;
            out["marker_source"] = marker_source;
            out["marker_hex_valid"] = false;
            out["validation_error"] = marker_hex_error;
            return tool_result_t::error("SMC marker hex is invalid.", out);
        }
        if (provided_marker.empty() && params.contains("marker") && params["marker"].is_string())
        {
            const std::string marker_text = params["marker"].get<std::string>();
            if (!marker_text.empty() && marker_text.size() <= 256)
            {
                marker_source = "marker";
                provided_marker.assign(marker_text.begin(), marker_text.end());
            }
        }
        auto marker_va = parse_param_u64(params, "marker_va");
        auto marker_size = parse_param_u64(params, "marker_size");
        std::uint64_t marker_hits = 0;
        bool marker_read = false;
        bool range_contains_marker = false;
        if (!provided_marker.empty())
        {
            marker_read = true;
            range_contains_marker = true;
            auto it = bytes.begin();
            while ((it = std::search(it, bytes.end(), provided_marker.begin(), provided_marker.end())) != bytes.end()) {
                ++marker_hits;
                ++it;
            }
        }
        if (provided_marker.empty() && marker_va && marker_size && *marker_size != 0 && *marker_size <= 256 && *marker_va >= *direct_base && (*marker_va - *direct_base) + *marker_size <= bytes.size()) {
            range_contains_marker = true;
            std::vector<std::uint8_t> marker;
            marker_read = read_target_memory(pid, *marker_va, static_cast<std::size_t>(*marker_size), marker) && marker.size() == *marker_size;
            if (marker_read && !marker.empty()) {
                marker_source = "marker_va";
                auto it = bytes.begin();
                while ((it = std::search(it, bytes.end(), marker.begin(), marker.end())) != bytes.end()) {
                    ++marker_hits;
                    ++it;
                }
            }
        }
        const double ent = entropy_of(bytes);
        const bool decrypt_candidate = ent > 7.0 || (mem_exec && mem_write) || marker_hits != 0;
        json row{{"va", sa_format_address(*direct_base)},
                 {"size", bytes.size()},
                 {"requested_size", *direct_size},
                 {"entropy", ent},
                 {"section", nullptr},
                 {"module", nullptr},
                 {"direct_range", true},
                 {"classification", ent > 7.0 ? "high_entropy_bounded_range" : (marker_hits != 0 ? "marker_backed_bounded_range" : (mem_exec && mem_write ? "writable_executable_bounded_range" : "bounded_range"))},
                 {"decrypt_candidate", decrypt_candidate},
                 {"marker_va", marker_va ? json(sa_format_address(*marker_va)) : json(nullptr)},
                 {"marker_size", marker_size ? json(*marker_size) : json(nullptr)},
                 {"range_contains_marker", range_contains_marker},
                 {"marker_read", marker_read},
                 {"marker_source", marker_source.empty() ? json(nullptr) : json(marker_source)},
                 {"marker_bytes_provided", !provided_marker.empty()},
                 {"marker_evidence_state", marker_hits != 0 ? "marker_hits_proven" : (marker_read ? "marker_read_no_hits" : "marker_not_provided")},
                 {"entropy_evidence_state", ent > 7.0 ? "high_entropy_proven" : "entropy_below_high_threshold"},
                 {"marker_hits", marker_hits},
                 {"descriptor_marker_evidence", json{{"marker_source", marker_source.empty() ? json(nullptr) : json(marker_source)}, {"marker_read", marker_read}, {"marker_hits", marker_hits}, {"semantic_marker_proven", marker_hits != 0}}},
                 {"memory_protection", region_ok ? json{{"base", sa_format_address(region.base)}, {"size", region.size}, {"protect", protection_name(region.protect)}, {"protect_raw", sa_format_address(region.protect)}, {"state", sa_format_address(region.state)}, {"type", sa_format_address(region.type)}, {"executable", mem_exec}, {"writable", mem_write}, {"guard", (region.protect & PAGE_GUARD) != 0}} : json{{"queried", false}}}};
        return tool_result_t::ok(json{{"regions", json::array({row})}, {"count", 1}, {"direct_range", true}, {"bytes_scanned", bytes.size()}, {"marker_hits", marker_hits}, {"semantic_marker_proven", marker_hits != 0}, {"marker_evidence_state", row["marker_evidence_state"]}, {"entropy_evidence_state", row["entropy_evidence_state"]}, {"functional_success", decrypt_candidate}, {"partial", false}, {"deadline_hit", false}, {"cancelled", false}, {"timeout_ms", timeout_ms}, {"elapsed_ms", GetTickCount64() - started_ms}, {"pid", pid}});
    }
    std::vector<target_module_t> mods;
    if (params.contains("module_base") || params.contains("module_name") || params.contains("module")) {
        std::string err;
        auto mod = select_module(params, false, &err);
        if (!mod)
            return tool_result_t::error(err.empty() ? "No target module found" : err);
        mods.push_back(*mod);
    } else {
        mods = user_modules(pid);
    }
    json regions = json::array();
    std::uint64_t bytes_scanned = 0;
    std::size_t sections_scanned = 0;
    auto partial_payload = [&]() {
        return json{{"regions", regions},
                    {"count", regions.size()},
                    {"direct_range", false},
                    {"bytes_scanned", bytes_scanned},
                    {"sections_scanned", sections_scanned},
                    {"module_count", mods.size()},
                    {"pid", pid},
                    {"partial", true},
                    {"deadline_hit", deadline_hit},
                    {"cancelled", cancelled},
                    {"phase", stop_phase},
                    {"timeout_ms", timeout_ms},
                    {"elapsed_ms", GetTickCount64() - started_ms}};
    };
    for (const auto& m : mods) {
        if (stop_requested("module_loop"))
            return tool_result_t::error(cancelled ? "SMC encrypted-region scan cancelled." : "SMC encrypted-region scan deadline reached.", partial_payload());
        pe_layout_t pe;
        if (!read_pe_layout(pid, m.base, pe))
            continue;
        std::vector<std::uint8_t> file_bytes;
        const bool file_ok = read_file_bytes_win32(m.path, file_bytes);
        for (auto sec : pe.sections) {
            if (stop_requested("section_loop"))
                return tool_result_t::error(cancelled ? "SMC encrypted-region scan cancelled." : "SMC encrypted-region scan deadline reached.", partial_payload());
            const std::uint32_t size = sec.virtual_size ? sec.virtual_size : sec.raw_size;
            if (size == 0)
                continue;
            const std::uint32_t read_size = std::min<std::uint32_t>(size, 1024u * 1024u);
            std::vector<std::uint8_t> bytes;
            if (!read_target_memory(pid, sec.va, read_size, bytes) || bytes.empty())
                continue;
            bytes_scanned += bytes.size();
            ++sections_scanned;
            sec.entropy = entropy_of(bytes);
            driver_bridge::memory_region_t region{};
            const bool region_ok = driver_bridge::query_memory_for(pid, sec.va, region);
            const bool mem_exec = region_ok ? executable_protect(region.protect) : executable_characteristics(sec.characteristics);
            const bool mem_write = region_ok && ((region.protect & 0xFFu) == PAGE_EXECUTE_READWRITE || (region.protect & 0xFFu) == PAGE_EXECUTE_WRITECOPY || (region.protect & 0xFFu) == PAGE_READWRITE || (region.protect & 0xFFu) == PAGE_WRITECOPY);
            json disk_compare = compare_section_to_disk(sec, bytes, file_bytes);
            bool decrypt_candidate = sec.entropy > 7.0 && executable_characteristics(sec.characteristics);
            if (!decrypt_candidate && sec.entropy < 1.0 && executable_characteristics(sec.characteristics))
                decrypt_candidate = true;
            if (!decrypt_candidate && disk_compare.value("available", false) && !disk_compare.value("equal", true) && mem_exec)
                decrypt_candidate = true;
            if (decrypt_candidate || params.value("include_all", false)) {
                regions.push_back(json{{"va", sa_format_address(sec.va)},
                                       {"size", size},
                                       {"entropy", sec.entropy},
                                       {"section", sec.name},
                                       {"module", m.name},
                                       {"module_path", m.path},
                                       {"classification", sec.entropy > 7.0 ? "high_entropy_executable" : (disk_compare.value("available", false) && !disk_compare.value("equal", true) ? "mapped_bytes_differ_from_file" : "low_entropy_or_mutated_executable")},
                                       {"decrypt_candidate", decrypt_candidate},
                                       {"disk_compare", disk_compare},
                                       {"file_compare_available", file_ok && disk_compare.value("available", false)},
                                       {"memory_protection", region_ok ? json{{"base", sa_format_address(region.base)}, {"size", region.size}, {"protect", protection_name(region.protect)}, {"protect_raw", sa_format_address(region.protect)}, {"state", sa_format_address(region.state)}, {"type", sa_format_address(region.type)}, {"executable", mem_exec}, {"writable", mem_write}, {"guard", (region.protect & PAGE_GUARD) != 0}} : json{{"queried", false}}},
                                       {"rx_transition", json{{"section_executable", executable_characteristics(sec.characteristics)}, {"memory_executable", mem_exec}, {"memory_writable", mem_write}, {"guarded", region_ok ? ((region.protect & PAGE_GUARD) != 0) : false}, {"transition_hint", mem_exec && !executable_characteristics(sec.characteristics) ? "non_exec_section_mapped_executable" : (mem_exec && disk_compare.value("available", false) && !disk_compare.value("equal", true) ? "mapped_executable_bytes_differ_from_file" : "none")}}}});
            }
        }
    }
    return tool_result_t::ok(json{{"regions", regions}, {"count", regions.size()}, {"direct_range", false}, {"bytes_scanned", bytes_scanned}, {"sections_scanned", sections_scanned}, {"module_count", mods.size()}, {"pid", pid}, {"partial", false}, {"deadline_hit", false}, {"cancelled", false}, {"timeout_ms", timeout_ms}, {"elapsed_ms", GetTickCount64() - started_ms}});
}

inline tool_result_t smc_detect_selfmod(const json& params)
{
    auto result = smc_scan_encrypted_regions(params);
    if (result.data.is_object()) {
        result.data["alias_tool"] = "smc_detect_selfmod";
        result.data["selfmod_detection"] = true;
    }
    return result;
}

inline tool_result_t smc_snapshot_pages(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto base = parse_param_u64(params, "target_va");
    if (!base)
        base = parse_param_u64(params, "address");
    if (!base)
        base = parse_param_u64(params, "range_base");
    if (!base)
        base = parse_param_u64(params, "watch_va");
    auto size = parse_param_u64(params, "target_size");
    if (!size)
        size = parse_param_u64(params, "size");
    if (!size)
        size = parse_param_u64(params, "range_size");
    if (!size)
        size = parse_param_u64(params, "watch_size");
    if (!base || !size || *size == 0)
        return tool_result_t::error("target_va/address and target_size/size are required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint64_t bounded_size = std::min<std::uint64_t>(*size, 1024ull * 1024ull);
    std::vector<std::uint8_t> bytes;
    if (!read_target_memory(pid, *base, static_cast<std::size_t>(bounded_size), bytes) || bytes.empty())
        return tool_result_t::error("Could not snapshot target range", json{{"target_va", sa_format_address(*base)}, {"target_size", bounded_size}, {"pid", pid}});
    const std::uint64_t page_size = 0x1000;
    json pages = json::array();
    for (std::size_t off = 0; off < bytes.size() && pages.size() < 256; off += static_cast<std::size_t>(page_size)) {
        const std::size_t n = std::min<std::size_t>(static_cast<std::size_t>(page_size), bytes.size() - off);
        std::vector<std::uint8_t> page(n);
        std::memcpy(page.data(), bytes.data() + off, n);
        driver_bridge::memory_region_t region{};
        const bool region_ok = driver_bridge::query_memory_for(pid, *base + off, region);
        pages.push_back(json{{"page_va", sa_format_address(*base + off)}, {"size", n}, {"entropy", entropy_of(page)}, {"protect", region_ok ? protection_name(region.protect) : "unknown"}, {"protect_raw", region_ok ? json(sa_format_address(region.protect)) : json(nullptr)}, {"executable", region_ok ? executable_protect(region.protect) : false}, {"capture_backend", "driver_read_target_memory"}, {"bytes_hex", bytes_to_hex(page, 128)}, {"disasm_preview", disasm_preview_for_bytes(*base + off, page, 8)}});
    }
    return tool_result_t::ok("SMC page snapshot completed", json{{"target_va", sa_format_address(*base)}, {"target_size_requested", *size}, {"target_size_snapshotted", bytes.size()}, {"bounded", *size > bounded_size}, {"bounded_read", true}, {"capture_backend", "driver_read_target_memory"}, {"driver_backed", true}, {"bytes_read", bytes.size()}, {"range", json{{"base_va", sa_format_address(*base)}, {"size", bytes.size()}, {"end_va", sa_format_address(*base + bytes.size())}}}, {"pid", pid}, {"pages", pages}, {"page_count", pages.size()}});
}

inline std::uint64_t memory_reference_target(const AsmInstr& ins)
{
    if (!ins.has_mem_op || !ins.mem_op.has_disp)
        return 0;
    const std::int64_t disp = ins.mem_op.disp;
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP))
        return ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)) + static_cast<std::uint64_t>(disp);
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE))
        return static_cast<std::uint64_t>(disp);
    return static_cast<std::uint64_t>(disp);
}

inline const char* zydis_gpr_name(std::uint16_t reg)
{
    switch (static_cast<ZydisRegister>(reg)) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH: return "rax";
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH: return "rbx";
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH: return "rcx";
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH: return "rdx";
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: case ZYDIS_REGISTER_SIL: return "rsi";
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: case ZYDIS_REGISTER_DIL: return "rdi";
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP: case ZYDIS_REGISTER_BPL: return "rbp";
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: case ZYDIS_REGISTER_SPL: return "rsp";
    case ZYDIS_REGISTER_R8: case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B: return "r8";
    case ZYDIS_REGISTER_R9: case ZYDIS_REGISTER_R9D: case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B: return "r9";
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return "r10";
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return "r11";
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return "r12";
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return "r13";
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return "r14";
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return "r15";
    default: return "";
    }
}

inline bool add_signed_offset(std::uint64_t base, std::int64_t disp, std::uint64_t& out)
{
    if (disp >= 0) {
        const auto udisp = static_cast<std::uint64_t>(disp);
        if (base > std::numeric_limits<std::uint64_t>::max() - udisp)
            return false;
        out = base + udisp;
        return true;
    }
    const auto magnitude = static_cast<std::uint64_t>(-(disp + 1)) + 1;
    if (base < magnitude)
        return false;
    out = base - magnitude;
    return true;
}

inline std::uint64_t memory_reference_target_with_registers(const AsmInstr& ins, const std::map<std::string, std::uint64_t>& reg_values, std::string* source)
{
    if (source)
        source->clear();
    if (!ins.has_mem_op)
        return 0;
    const auto none = static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE);
    const std::int64_t disp = ins.mem_op.has_disp ? ins.mem_op.disp : 0;
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP)) {
        std::uint64_t target = 0;
        if (!add_signed_offset(ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)), disp, target))
            return 0;
        if (source)
            *source = "rip_relative";
        return target;
    }
    if (ins.mem_op.base_reg == none && ins.mem_op.index_reg == none && ins.mem_op.has_disp) {
        if (source)
            *source = "absolute_displacement";
        return static_cast<std::uint64_t>(disp);
    }
    if (ins.mem_op.base_reg != none && ins.mem_op.index_reg == none) {
        const char* base_name = zydis_gpr_name(ins.mem_op.base_reg);
        if (base_name && *base_name) {
            if (auto base_value = resolve_last_register_value(reg_values, base_name)) {
                std::uint64_t target = 0;
                if (add_signed_offset(*base_value, disp, target)) {
                    if (source)
                        *source = std::string("tracked_register:") + base_name;
                    return target;
                }
            }
        }
    }
    const std::uint64_t direct = memory_reference_target(ins);
    if (direct && source)
        *source = "direct_displacement";
    return direct;
}

inline bool resolve_assignment_constant(const AsmInstr& ins, const std::string& mnem, const std::vector<std::string>& ops, const std::map<std::string, std::uint64_t>& reg_values, std::uint64_t& value)
{
    if (ins.branch_target) {
        value = ins.branch_target;
        return true;
    }
    if (ins.has_imm) {
        value = ins.imm_unsigned;
        return true;
    }
    if (ops.size() >= 2) {
        if (auto h = parse_hex_in_text(ops[1])) {
            value = *h;
            return true;
        }
    }
    if (mnem == "lea" && ins.has_mem_op) {
        std::string source;
        const std::uint64_t ref = memory_reference_target_with_registers(ins, reg_values, &source);
        if (ref) {
            value = ref;
            return true;
        }
    }
    return false;
}

inline void update_register_constants(const AsmInstr& ins, const std::string& mnem, const std::vector<std::string>& ops, std::map<std::string, std::uint64_t>& reg_values)
{
    if (ops.empty() || operand_is_memory(ops[0]))
        return;
    const std::string dst = reg_from_operand(ops[0]);
    if (dst.empty())
        return;
    if ((mnem == "xor" || mnem == "sub") && ops.size() >= 2 && lower_ascii(ops[0]) == lower_ascii(ops[1])) {
        reg_values[dst] = 0;
        return;
    }
    if (mnem == "mov" || mnem == "movabs" || mnem == "lea") {
        std::uint64_t value = 0;
        if (resolve_assignment_constant(ins, mnem, ops, reg_values, value))
            reg_values[dst] = value;
        else
            reg_values.erase(dst);
        return;
    }
    if ((mnem == "add" || mnem == "sub") && ops.size() >= 2) {
        auto cur = resolve_last_register_value(reg_values, dst);
        std::uint64_t rhs = 0;
        bool have_rhs = ins.has_imm;
        if (have_rhs)
            rhs = ins.imm_unsigned;
        else if (auto h = parse_hex_in_text(ops[1])) {
            rhs = *h;
            have_rhs = true;
        }
        if (cur && have_rhs && rhs <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            std::uint64_t updated = 0;
            const std::int64_t delta = mnem == "sub" ? -static_cast<std::int64_t>(rhs) : static_cast<std::int64_t>(rhs);
            if (add_signed_offset(*cur, delta, updated)) {
                reg_values[dst] = updated;
                return;
            }
        }
        reg_values.erase(dst);
        return;
    }
    if (mnem == "and" || mnem == "or" || mnem == "imul" || mnem == "mul" || mnem == "div" ||
        mnem == "idiv" || mnem == "shl" || mnem == "shr" || mnem == "sar" || mnem == "rol" ||
        mnem == "ror" || mnem == "not" || mnem == "neg" || mnem == "xchg")
        reg_values.erase(dst);
}

inline std::vector<AsmInstr> disassemble_linear_bytes(std::uint64_t base, const std::vector<std::uint8_t>& bytes, std::uint32_t max_insns)
{
    std::vector<AsmInstr> out;
    if (bytes.empty() || max_insns == 0)
        return out;
    std::size_t off = 0;
    while (off < bytes.size() && out.size() < max_insns) {
        const int avail = static_cast<int>(std::min<std::size_t>(15, bytes.size() - off));
        AsmInstr ins = zydis_decode_one(bytes.data() + off, avail, base + off);
        if (ins.len <= 0)
            ins.len = 1;
        out.push_back(ins);
        off += static_cast<std::size_t>(ins.len);
    }
    return out;
}

inline std::string base_register_from_memory_operand(std::string op)
{
    op = lower_ascii(op);
    for (const char* prefix : { "qword ptr ", "dword ptr ", "word ptr ", "byte ptr ", "ptr " }) {
        const std::string p(prefix);
        const std::size_t pos = op.find(p);
        if (pos != std::string::npos)
            op.erase(pos, p.size());
    }
    const std::size_t open = op.find('[');
    const std::size_t close = op.find(']');
    if (open == std::string::npos || close == std::string::npos || close <= open + 1)
        return {};
    std::string inner = trim_ascii(op.substr(open + 1, close - open - 1));
    for (char& c : inner) {
        if (c == '+' || c == '-' || c == '*' || c == ',') {
            c = ' ';
            break;
        }
    }
    std::istringstream is(inner);
    std::string token;
    is >> token;
    return reg_from_operand(token);
}

inline std::optional<std::int64_t> displacement_from_memory_operand_text(std::string op)
{
    op = lower_ascii(op);
    const std::size_t open = op.find('[');
    const std::size_t close = op.find(']');
    if (open == std::string::npos || close == std::string::npos || close <= open + 1)
        return std::nullopt;
    const std::string inner = op.substr(open + 1, close - open - 1);
    std::size_t pos = inner.find("+0x");
    int sign = 1;
    if (pos == std::string::npos) {
        pos = inner.find("-0x");
        sign = -1;
    }
    if (pos == std::string::npos)
        return 0;
    std::size_t hex_start = pos + 1;
    std::size_t hex_end = hex_start + 2;
    while (hex_end < inner.size() && std::isxdigit(static_cast<unsigned char>(inner[hex_end])))
        ++hex_end;
    auto parsed = sa_parse_address(inner.substr(hex_start, hex_end - hex_start));
    if (!parsed)
        return std::nullopt;
    if (*parsed > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        return std::nullopt;
    return static_cast<std::int64_t>(*parsed) * sign;
}

inline std::uint64_t memory_operand_text_target(const std::vector<std::string>& ops, const std::map<std::string, std::uint64_t>& reg_values, std::string& source, json& evidence)
{
    evidence = json{{"resolver", "operand_text_register_flow"}, {"resolved", false}};
    source.clear();
    if (ops.empty() || !operand_is_memory(ops[0]))
        return 0;
    const std::string base_reg = base_register_from_memory_operand(ops[0]);
    evidence["base_register"] = base_reg;
    if (base_reg.empty()) {
        evidence["reason"] = "no_base_register_in_memory_operand";
        return 0;
    }
    auto base = resolve_last_register_value(reg_values, base_reg);
    if (!base) {
        evidence["reason"] = "base_register_not_tracked";
        return 0;
    }
    evidence["base_value"] = sa_format_address(*base);
    auto disp = displacement_from_memory_operand_text(ops[0]);
    if (!disp) {
        evidence["reason"] = "displacement_parse_failed";
        return 0;
    }
    std::uint64_t target = 0;
    if (!add_signed_offset(*base, *disp, target)) {
        evidence["reason"] = "target_overflow";
        return 0;
    }
    source = "operand_text_tracked_register:" + base_reg;
    evidence["resolved"] = true;
    evidence["displacement"] = *disp;
    evidence["target"] = sa_format_address(target);
    return target;
}

inline std::string bytes_window_hex(const std::vector<std::uint8_t>& bytes, std::size_t center, std::size_t before, std::size_t after)
{
    if (bytes.empty())
        return {};
    const std::size_t begin = center > before ? center - before : 0;
    const std::size_t end = std::min<std::size_t>(bytes.size(), center + after);
    if (end <= begin)
        return {};
    std::vector<std::uint8_t> window(bytes.begin() + static_cast<std::ptrdiff_t>(begin), bytes.begin() + static_cast<std::ptrdiff_t>(end));
    return bytes_to_hex(window, window.size());
}

inline std::uint64_t estimate_function_start_from_instruction_window(const std::vector<AsmInstr>& insns, std::size_t index, std::uint64_t fallback)
{
    if (insns.empty() || index >= insns.size())
        return fallback;
    std::uint64_t candidate = insns[index].addr;
    const std::size_t begin = index > 64 ? index - 64 : 0;
    for (std::size_t i = begin; i <= index; ++i) {
        const auto& ins = insns[i];
        const std::string m = mnemonic_of(ins);
        const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
        if (i < index && ins.is_ret)
            candidate = ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1));
        if ((m == "push" && text.find("rbp") != std::string::npos) ||
            (m == "sub" && text.find("rsp") != std::string::npos) ||
            m == "endbr64")
            candidate = ins.addr;
    }
    return candidate ? candidate : fallback;
}

inline json backtrace_window_json(const std::vector<AsmInstr>& insns, std::size_t index, std::size_t before)
{
    json arr = json::array();
    if (insns.empty() || index >= insns.size())
        return arr;
    const std::size_t begin = index > before ? index - before : 0;
    for (std::size_t i = begin; i <= index; ++i)
        arr.push_back(instruction_to_json(insns[i]));
    return arr;
}

inline tool_result_t smc_find_decryptor(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto target = parse_param_u64(params, "target_va");
    auto size = parse_param_u64(params, "target_size");
    if (!target || !size || *size == 0)
        return tool_result_t::error("target_va and target_size are required");
    const std::uint32_t pid = requested_pid(params);
    const std::uint64_t bounded_target_size = std::min<std::uint64_t>(*size, 16ull * 1024ull * 1024ull);
    const std::uint64_t max_u64 = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t end = *target > max_u64 - bounded_target_size ? max_u64 : *target + bounded_target_size;
    const ULONGLONG started = GetTickCount64();
    auto capped_param = [&](const char* key, std::uint64_t fallback, std::uint64_t lo, std::uint64_t hi) -> std::uint64_t {
        return std::clamp<std::uint64_t>(parse_param_u64(params, key).value_or(fallback), lo, hi);
    };
    const std::size_t max_candidates = static_cast<std::size_t>(capped_param("max_candidates", 8, 1, 64));
    const std::size_t max_decision_samples = static_cast<std::size_t>(capped_param("max_decision_samples", 8, 0, 64));
    const std::size_t max_backtrace_instructions = static_cast<std::size_t>(capped_param("max_backtrace_instructions", 4, 0, 16));
    const std::size_t max_scan_ranges = static_cast<std::size_t>(capped_param("max_scan_ranges", 8, 1, 64));
    const std::uint32_t max_decode_instructions = static_cast<std::uint32_t>(capped_param("max_instructions", 1024, 16, 65536));
    const std::size_t max_payload_bytes = static_cast<std::size_t>(capped_param("max_payload_bytes", 65536, 8192, 1048576));
    const std::size_t max_payload_text_length = static_cast<std::size_t>(capped_param("max_payload_text_length", 4096, 256, 65536));
    const std::uint64_t timeout_ms = capped_param("timeout_ms", 3000, 250, 60000);
    const std::uint64_t local_deadline = started > std::numeric_limits<std::uint64_t>::max() - timeout_ms ? std::numeric_limits<std::uint64_t>::max() : started + timeout_ms;
    const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
    json candidates = json::array();
    json scan_ranges = json::array();
    json decision_samples = json::array();
    std::uint64_t scanned = 0;
    std::uint64_t bytes_read_total = 0;
    std::size_t candidates_considered = 0;
    bool cancelled = false;
    bool deadline_hit = false;
    bool result_truncated = false;
    std::string stop_phase;
    auto remaining_ms = [&]() -> std::uint64_t {
        const std::uint64_t now = GetTickCount64();
        std::uint64_t deadline = local_deadline;
        if (call_deadline != 0)
            deadline = std::min<std::uint64_t>(deadline, call_deadline);
        return deadline > now ? deadline - now : 0;
    };
    auto stop_requested = [&](const char* phase) -> bool {
        if (cancelled || deadline_hit)
            return true;
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            stop_phase = phase ? phase : "";
        }
        else
        {
            const std::uint64_t now = GetTickCount64();
            if (now >= local_deadline || (call_deadline != 0 && now >= call_deadline))
            {
                deadline_hit = true;
                stop_phase = phase ? phase : "";
            }
        }
        if (cancelled || deadline_hit)
        {
            diag::log_tagged_fmt("protected_re",
                                 "smc_find_decryptor budget_exit phase=%s pid=%u cancelled=%d deadline=%d elapsed_ms=%llu remaining_ms=%llu",
                                 stop_phase.c_str(),
                                 pid,
                                 cancelled ? 1 : 0,
                                 deadline_hit ? 1 : 0,
                                 static_cast<unsigned long long>(GetTickCount64() - started),
                                 static_cast<unsigned long long>(remaining_ms()));
            return true;
        }
        return false;
    };
    diag::log_tagged_fmt("protected_re",
                         "smc_find_decryptor enter pid=%u target=%s target_size=%llu max_candidates=%zu max_decisions=%zu max_instructions=%u max_payload_bytes=%zu max_payload_text=%zu timeout_ms=%llu",
                         pid,
                         sa_format_address(*target).c_str(),
                         static_cast<unsigned long long>(bounded_target_size),
                         max_candidates,
                         max_decision_samples,
                         max_decode_instructions,
                         max_payload_bytes,
                         max_payload_text_length,
                         static_cast<unsigned long long>(timeout_ms));
    auto target_contains = [&](std::uint64_t value) {
        return value >= *target && value < end;
    };
    auto scan_code_range = [&](std::uint64_t scan_base, std::uint32_t scan_size, const std::string& source) -> bool {
        if (stop_requested("range_enter"))
            return false;
        const std::uint32_t requested_scan_size = scan_size;
        scan_size = std::clamp<std::uint32_t>(scan_size, 1, 0x100000);
        json range_diag;
        range_diag["source"] = source;
        range_diag["scan_base"] = sa_format_address(scan_base);
        range_diag["scan_size_requested"] = requested_scan_size;
        range_diag["scan_size_initial"] = scan_size;
        range_diag["safe_context_expanded"] = false;
        driver_bridge::memory_region_t region{};
        if (!is_kernel_address(scan_base) && driver_bridge::query_memory_for(pid, scan_base, region) && region.base + region.size > scan_base) {
            const std::uint64_t available = region.base + region.size - scan_base;
            const std::uint32_t expanded = static_cast<std::uint32_t>(std::min<std::uint64_t>(available, 0x100));
            if (expanded > scan_size) {
                scan_size = std::min<std::uint32_t>(expanded, 0x100000);
                range_diag["safe_context_expanded"] = true;
            }
            range_diag["region"] = json{{"base", sa_format_address(region.base)}, {"size", region.size}, {"protect", protection_name(region.protect)}, {"protect_raw", sa_format_address(region.protect)}, {"executable", executable_protect(region.protect)}};
        }
        range_diag["scan_size_effective"] = scan_size;
        std::vector<std::uint8_t> raw;
        const bool raw_ok = read_target_memory(pid, scan_base, scan_size, raw);
        range_diag["read_ok"] = raw_ok;
        range_diag["bytes_read"] = raw.size();
        bytes_read_total += raw.size();
        range_diag["marker_bytes_head"] = bytes_to_hex(raw, 64);
        const ULONGLONG decode_started = GetTickCount64();
        auto insns = raw_ok && !raw.empty() ? disassemble_linear_bytes(scan_base, raw, max_decode_instructions) : disassemble_target(pid, scan_base, scan_size, max_decode_instructions);
        range_diag["instructions_decoded"] = insns.size();
        range_diag["instruction_decode_cap"] = max_decode_instructions;
        range_diag["decode_elapsed_ms"] = GetTickCount64() - decode_started;
        if (insns.size() >= max_decode_instructions)
            result_truncated = true;
        if (scan_ranges.size() < max_scan_ranges)
            scan_ranges.push_back(std::move(range_diag));
        else
            result_truncated = true;
        scanned += insns.size();
        std::map<std::string, std::uint64_t> reg_values;
        for (std::size_t ii = 0; ii < insns.size(); ++ii) {
            if ((ii & 0xFF) == 0 && stop_requested("instruction_scan"))
                return false;
            const auto& ins = insns[ii];
            const std::string mnem = mnemonic_of(ins);
            auto ops = split_operands(ins.ops);
            update_register_constants(ins, mnem, ops, reg_values);
            if (mnem != "mov" && mnem != "movabs" && mnem != "lea" && mnem != "xor" && mnem != "add" && mnem != "sub" && mnem != "rol" && mnem != "ror")
                continue;
            bool match = false;
            std::string ref_source;
            const std::uint64_t ref = memory_reference_target_with_registers(ins, reg_values, &ref_source);
            const bool memory_write = !ops.empty() && operand_is_memory(ops[0]);
            std::string operand_ref_source;
            json operand_ref_evidence;
            std::uint64_t operand_ref = 0;
            if (memory_write)
                operand_ref = memory_operand_text_target(ops, reg_values, operand_ref_source, operand_ref_evidence);
            std::uint64_t chosen_ref = 0;
            std::string chosen_source;
            if (ref && target_contains(ref)) {
                chosen_ref = ref;
                chosen_source = ref_source.empty() ? "decoded_memory_metadata" : ref_source;
                match = true;
            } else if (operand_ref && target_contains(operand_ref)) {
                chosen_ref = operand_ref;
                chosen_source = operand_ref_source.empty() ? "operand_text_register_flow" : operand_ref_source;
                match = true;
            }
            if (!match && ins.has_imm && memory_write) {
                match = target_contains(ins.imm_unsigned);
                if (match) {
                    chosen_ref = ins.imm_unsigned;
                    chosen_source = "immediate_operand_value";
                }
            }
            if (!match)
                continue;
            ++candidates_considered;
            json decision_summary;
            decision_summary["memory_write"] = memory_write;
            decision_summary["decoded_memory_ref"] = ref ? json(sa_format_address(ref)) : json(nullptr);
            decision_summary["decoded_memory_source"] = ref_source.empty() ? "none" : ref_source;
            decision_summary["operand_text_ref"] = operand_ref ? json(sa_format_address(operand_ref)) : json(nullptr);
            decision_summary["operand_text_source"] = operand_ref_source.empty() ? "none" : operand_ref_source;
            decision_summary["chosen_memory_target"] = chosen_ref ? json(sa_format_address(chosen_ref)) : json(nullptr);
            decision_summary["chosen_source"] = chosen_source.empty() ? "none" : chosen_source;
            decision_summary["matched_target_range"] = true;
            decision_summary["tracked_registers"] = reg_values.size();
            if (decision_samples.size() < max_decision_samples)
            {
                json decision = decision_summary;
                decision["instruction"] = instruction_to_json(ins);
                decision["operand_text_evidence"] = operand_ref_evidence.is_null() ? json::object() : operand_ref_evidence;
                decision["target_range"] = json{{"base", sa_format_address(*target)}, {"end", sa_format_address(end)}, {"size", bounded_target_size}};
                decision_samples.push_back(std::move(decision));
            }
            else
            {
                result_truncated = true;
            }
            const std::size_t raw_offset = (ins.addr >= scan_base && ins.addr - scan_base < raw.size()) ? static_cast<std::size_t>(ins.addr - scan_base) : 0;
            const std::string marker_bytes = bytes_window_hex(raw, raw_offset, 16, 24);
            const std::uint64_t function_start = estimate_function_start_from_instruction_window(insns, ii, ins.addr);
            json backtrace = backtrace_window_json(insns, ii, max_backtrace_instructions);
            if (candidates.size() < max_candidates)
            {
                candidates.push_back(json{{"decryptor_va", sa_format_address(function_start)},
                                          {"function_start_va", sa_format_address(function_start)},
                                          {"write_instruction_va", sa_format_address(ins.addr)},
                                          {"memory_reference_va", chosen_ref ? sa_format_address(chosen_ref) : sa_format_address(ins.imm_unsigned)},
                                          {"memory_reference_source", chosen_source.empty() ? "unknown" : chosen_source},
                                          {"key_register", ops.size() > 1 ? reg_from_operand(ops.back()) : "unknown"},
                                          {"key_operand", ops.size() > 1 ? ops.back() : std::string()},
                                          {"estimated_algo", estimate_algo_from_mnemonic(mnem)},
                                          {"evidence", instruction_to_json(ins)},
                                          {"reference_evidence", json{{"function_start_va", sa_format_address(function_start)}, {"backtrace_window", backtrace}, {"backtrace_instruction_count", backtrace.size()}, {"backtrace_truncated", max_backtrace_instructions < 12}}},
                                          {"decision", decision_summary},
                                          {"source", source},
                                          {"tracked_register_count", reg_values.size()},
                                          {"marker_bytes_hex", marker_bytes},
                                          {"confidence", chosen_source.rfind("operand_text_tracked_register:", 0) == 0 ? 0.78 : (chosen_source.rfind("tracked_register:", 0) == 0 ? 0.74 : 0.58)}});
            }
            else
            {
                result_truncated = true;
            }
            if (candidates.size() >= max_candidates)
            {
                result_truncated = true;
                break;
            }
        }
        diag::log_tagged_fmt("protected_re",
                             "smc_find_decryptor range_done pid=%u source=%s decoded=%zu candidates=%zu considered=%zu truncated=%d elapsed_ms=%llu remaining_ms=%llu",
                             pid,
                             source.c_str(),
                             insns.size(),
                             candidates.size(),
                             candidates_considered,
                             result_truncated ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started),
                             static_cast<unsigned long long>(remaining_ms()));
        return !cancelled && !deadline_hit;
    };
    auto finish = [&](bool explicit_scan_mode,
                      bool module_scan_skipped,
                      std::optional<std::uint64_t> explicit_scan_base,
                      std::uint64_t scan_size_requested,
                      std::uint64_t scan_size_effective,
                      const char* cancelled_message,
                      const char* deadline_message) -> tool_result_t {
        const ULONGLONG serialize_started = GetTickCount64();
        const std::size_t pre_payload_candidate_count = candidates.size();
        const std::size_t pre_payload_scan_range_count = scan_ranges.size();
        const std::size_t pre_payload_decision_sample_count = decision_samples.size();
        json out{{"decryptors", candidates},
                 {"count", candidates.size()},
                 {"found", !candidates.empty()},
                 {"best_candidate", candidates.empty() ? json(nullptr) : candidates[0]},
                 {"instructions_scanned", scanned},
                 {"scan_bytes", bytes_read_total},
                 {"candidates_considered", candidates_considered},
                 {"explicit_scan_mode", explicit_scan_mode},
                 {"module_scan_skipped", module_scan_skipped},
                 {"target_va", sa_format_address(*target)},
                 {"target_size_effective", bounded_target_size},
                 {"scan_ranges", scan_ranges},
                 {"decision_samples", decision_samples},
                 {"cancelled", cancelled},
                 {"deadline_hit", deadline_hit},
                 {"partial", cancelled || deadline_hit || result_truncated},
                 {"result_truncated", result_truncated},
                 {"stop_phase", stop_phase},
                 {"timeout_ms", timeout_ms},
                  {"deadline_remaining_ms", remaining_ms()},
                  {"caps", json{{"max_candidates", max_candidates},
                                 {"max_decision_samples", max_decision_samples},
                                 {"max_backtrace_instructions", max_backtrace_instructions},
                                 {"max_scan_ranges", max_scan_ranges},
                                 {"max_instructions", max_decode_instructions},
                                 {"max_payload_bytes", max_payload_bytes},
                                 {"max_payload_text_length", max_payload_text_length}}},
                  {"elapsed_ms", GetTickCount64() - started}};
        if (explicit_scan_base)
        {
            out["scan_base"] = sa_format_address(*explicit_scan_base);
            out["scan_size_requested"] = scan_size_requested;
            out["scan_size_effective"] = scan_size_effective;
        }
        if (candidates.empty())
            out["no_match_reason"] = scanned == 0 ? "no_instructions_decoded" : "no_memory_write_resolved_into_target_range";
        bool payload_truncated = false;
        bool payload_text_truncated = false;
        std::size_t payload_text_fields_truncated = 0;
        std::function<void(json&)> cap_text = [&](json& value) {
            if (value.is_string())
            {
                std::string s = value.get<std::string>();
                if (s.size() > max_payload_text_length)
                {
                    s.resize(max_payload_text_length);
                    value = std::move(s);
                    payload_text_truncated = true;
                    ++payload_text_fields_truncated;
                }
                return;
            }
            if (value.is_array())
            {
                for (auto& item : value)
                    cap_text(item);
                return;
            }
            if (value.is_object())
            {
                for (auto it = value.begin(); it != value.end(); ++it)
                    cap_text(it.value());
            }
        };
        cap_text(out);
        auto serialized_payload_size = [&]() -> std::size_t {
            return out.dump().size();
        };
        std::size_t payload_bytes = serialized_payload_size();
        auto trim_one = [&]() -> bool {
            if (out["decision_samples"].is_array() && !out["decision_samples"].empty()) {
                auto it = out["decision_samples"].end();
                --it;
                out["decision_samples"].erase(it);
                return true;
            }
            if (out["scan_ranges"].is_array() && !out["scan_ranges"].empty()) {
                auto it = out["scan_ranges"].end();
                --it;
                out["scan_ranges"].erase(it);
                return true;
            }
            if (out["decryptors"].is_array() && out["decryptors"].size() > 1) {
                auto it = out["decryptors"].end();
                --it;
                out["decryptors"].erase(it);
                return true;
            }
            return false;
        };
        while (payload_bytes > max_payload_bytes && trim_one())
        {
            payload_truncated = true;
            payload_bytes = serialized_payload_size();
        }
        if (payload_bytes > max_payload_bytes)
            payload_truncated = true;
        const std::size_t returned_candidate_count = out["decryptors"].is_array() ? out["decryptors"].size() : 0;
        const std::size_t returned_scan_range_count = out["scan_ranges"].is_array() ? out["scan_ranges"].size() : 0;
        const std::size_t returned_decision_sample_count = out["decision_samples"].is_array() ? out["decision_samples"].size() : 0;
        out["count"] = returned_candidate_count;
        out["found"] = pre_payload_candidate_count != 0;
        if (returned_candidate_count != 0)
            out["best_candidate"] = out["decryptors"][0];
        else
            out["best_candidate"] = nullptr;
        out["pre_truncation_candidate_count"] = pre_payload_candidate_count;
        out["pre_truncation_scan_range_count"] = pre_payload_scan_range_count;
        out["pre_truncation_decision_sample_count"] = pre_payload_decision_sample_count;
        out["returned_candidate_count"] = returned_candidate_count;
        out["returned_scan_range_count"] = returned_scan_range_count;
        out["returned_decision_sample_count"] = returned_decision_sample_count;
        out["payload_truncated"] = payload_truncated;
        out["payload_text_truncated"] = payload_text_truncated;
        out["payload_text_fields_truncated"] = payload_text_fields_truncated;
        out["payload_max_bytes"] = max_payload_bytes;
        out["payload_text_max_length"] = max_payload_text_length;
        out["payload_bytes"] = payload_bytes;
        if (payload_truncated || payload_text_truncated)
        {
            out["partial"] = true;
            out["result_truncated"] = true;
            result_truncated = true;
        }
        payload_bytes = serialized_payload_size();
        if (payload_bytes > max_payload_bytes)
        {
            payload_truncated = true;
            out["payload_truncated"] = true;
            out["partial"] = true;
            out["result_truncated"] = true;
            result_truncated = true;
            payload_bytes = serialized_payload_size();
            out["payload_bytes"] = payload_bytes;
        }
        out["payload_bytes"] = payload_bytes;
        out["serialization_elapsed_ms"] = GetTickCount64() - serialize_started;
        payload_bytes = serialized_payload_size();
        out["payload_bytes"] = payload_bytes;
        payload_bytes = serialized_payload_size();
        out["payload_bytes"] = payload_bytes;
        if (payload_bytes > max_payload_bytes)
        {
            payload_truncated = true;
            out["payload_truncated"] = true;
            out["partial"] = true;
            out["result_truncated"] = true;
            result_truncated = true;
        }
        diag::log_tagged_fmt("protected_re",
                             "smc_find_decryptor exit pid=%u found=%d count=%zu considered=%zu truncated=%d payload_truncated=%d payload_bytes=%zu cancelled=%d deadline=%d elapsed_ms=%llu serialize_ms=%llu",
                             pid,
                             !candidates.empty() ? 1 : 0,
                             returned_candidate_count,
                             candidates_considered,
                             result_truncated ? 1 : 0,
                             payload_truncated ? 1 : 0,
                             payload_bytes,
                             cancelled ? 1 : 0,
                             deadline_hit ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - started),
                             static_cast<unsigned long long>(out["serialization_elapsed_ms"].get<std::uint64_t>()));
        if (cancelled)
            return tool_result_t::error(cancelled_message, out);
        if (deadline_hit && candidates.empty())
            return tool_result_t::error(deadline_message, out);
        return tool_result_t::ok(out);
    };
    auto scan_base = parse_param_u64(params, "scan_base");
    auto scan_size = parse_param_u64(params, "scan_size");
    if (scan_base) {
        const std::uint32_t bounded_scan = static_cast<std::uint32_t>(std::min<std::uint64_t>(scan_size.value_or(0x10000), 0x100000));
        const std::uint32_t effective_scan = bounded_scan == 0 ? 0x10000 : bounded_scan;
        scan_code_range(*scan_base, effective_scan, "explicit_scan_range");
        std::uint64_t reported_effective = effective_scan;
        if (!scan_ranges.empty() && scan_ranges.back().contains("scan_size_effective") && scan_ranges.back()["scan_size_effective"].is_number_unsigned())
            reported_effective = scan_ranges.back()["scan_size_effective"].get<std::uint64_t>();
        return finish(true, true, scan_base, scan_size.value_or(0x10000), reported_effective, "SMC decryptor explicit scan cancelled", "SMC decryptor explicit scan deadline reached");
    }
    auto mods = user_modules(pid);
    for (const auto& m : mods) {
        if (stop_requested("module_loop"))
            break;
        if (candidates.size() >= max_candidates)
        {
            result_truncated = true;
            break;
        }
        pe_layout_t pe;
        if (!read_pe_layout(pid, m.base, pe))
            continue;
        for (const auto& sec : pe.sections) {
            if (!executable_characteristics(sec.characteristics))
                continue;
            const std::uint32_t sec_size = std::min<std::uint32_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 0x100000);
            if (!scan_code_range(sec.va, sec_size, m.name + ":" + sec.name))
                break;
            if (candidates.size() >= max_candidates)
            {
                result_truncated = true;
                break;
            }
        }
        if (cancelled || deadline_hit)
            break;
    }
    return finish(false, false, std::nullopt, 0, 0, "SMC decryptor scan cancelled", "SMC decryptor scan deadline reached");
}

inline std::optional<target_module_t> select_user_main_module(const json& params, std::string* err)
{
    return select_module(params, false, err);
}

inline bool parse_import_names(std::uint32_t pid, const pe_layout_t& pe, std::vector<std::string>& names, std::size_t max_names)
{
    names.clear();
    if (pe.import_rva == 0)
        return true;
    const std::uint64_t dir = pe.base + pe.import_rva;
    for (std::uint32_t desc = 0; desc < 256 && names.size() < max_names; ++desc) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        if (!read_target_value(pid, dir + static_cast<std::uint64_t>(desc) * sizeof(d), d))
            break;
        if (d.OriginalFirstThunk == 0 && d.FirstThunk == 0)
            break;
        std::string mod;
        std::vector<std::uint8_t> sb;
        if (d.Name && read_target_memory(pid, pe.base + d.Name, 256, sb)) {
            for (std::uint8_t b : sb) {
                if (b == 0)
                    break;
                mod.push_back(static_cast<char>(b));
            }
        }
        if (!mod.empty())
            names.push_back(mod);
    }
    return true;
}

inline json parse_import_summary(std::uint32_t pid, const pe_layout_t& pe, std::size_t max_functions)
{
    json modules = json::array();
    json functions = json::array();
    if (pe.import_rva == 0)
        return json{{"modules", modules}, {"functions", functions}, {"module_count", 0}, {"function_count", 0}, {"directory_present", false}};
    const std::uint64_t dir = pe.base + pe.import_rva;
    for (std::uint32_t desc = 0; desc < 256 && functions.size() < max_functions; ++desc) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        if (!read_target_value(pid, dir + static_cast<std::uint64_t>(desc) * sizeof(d), d))
            break;
        if (d.OriginalFirstThunk == 0 && d.FirstThunk == 0)
            break;
        std::string mod_name;
        std::vector<std::uint8_t> name_bytes;
        if (d.Name && read_target_memory(pid, pe.base + d.Name, 256, name_bytes)) {
            for (std::uint8_t b : name_bytes) {
                if (b == 0)
                    break;
                mod_name.push_back(static_cast<char>(b));
            }
        }
        modules.push_back(mod_name.empty() ? "unknown" : mod_name);
        const std::uint32_t lookup_rva = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        for (std::uint32_t i = 0; i < 4096 && functions.size() < max_functions; ++i) {
            std::uint64_t thunk = 0;
            const std::uint64_t lookup_va = pe.base + lookup_rva + static_cast<std::uint64_t>(i) * (pe.is_64 ? 8 : 4);
            if (pe.is_64) {
                if (!read_target_value(pid, lookup_va, thunk) || thunk == 0)
                    break;
            } else {
                std::uint32_t t32 = 0;
                if (!read_target_value(pid, lookup_va, t32) || t32 == 0)
                    break;
                thunk = t32;
            }
            const bool ordinal = pe.is_64 ? ((thunk & 0x8000000000000000ULL) != 0) : ((thunk & 0x80000000ULL) != 0);
            std::string function_name = "ordinal";
            if (!ordinal) {
                const std::uint32_t hint_name = static_cast<std::uint32_t>(thunk & 0x7FFFFFFFULL);
                std::vector<std::uint8_t> fn_bytes;
                if (read_target_memory(pid, pe.base + hint_name + 2, 256, fn_bytes)) {
                    function_name.clear();
                    for (std::uint8_t b : fn_bytes) {
                        if (b == 0)
                            break;
                        function_name.push_back(static_cast<char>(b));
                    }
                }
            }
            functions.push_back(json{{"module_name", mod_name.empty() ? "unknown" : mod_name}, {"function_name", function_name}, {"ordinal", ordinal}});
        }
    }
    return json{{"modules", modules}, {"functions", functions}, {"module_count", modules.size()}, {"function_count", functions.size()}, {"directory_present", true}, {"truncated", functions.size() >= max_functions}};
}

inline tool_result_t pack_detect(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::uint32_t pid = requested_pid(params);
    std::string err;
    auto mod = select_user_main_module(params, &err);
    if (!mod)
        return tool_result_t::error(err.empty() ? "No target module found" : err);
    pe_layout_t pe;
    if (!read_pe_layout(pid, mod->base, pe))
        return tool_result_t::error("Could not parse PE headers for " + mod->name);
    json entropy_map = json::array();
    int high_entropy_exec = 0;
    std::string hint = "unknown";
    for (auto sec : pe.sections) {
        const std::uint32_t size = std::min<std::uint32_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 1024u * 1024u);
        std::vector<std::uint8_t> bytes;
        if (size && read_target_memory(pid, sec.va, size, bytes))
            sec.entropy = entropy_of(bytes);
        if (executable_characteristics(sec.characteristics) && sec.entropy > 7.2)
            ++high_entropy_exec;
        const std::string lname = lower_ascii(sec.name);
        if (lname.find("upx") != std::string::npos)
            hint = "UPX";
        else if (lname.find("aspack") != std::string::npos)
            hint = "ASPack";
        entropy_map.push_back(json{{"section", sec.name}, {"va", sa_format_address(sec.va)}, {"size", sec.virtual_size ? sec.virtual_size : sec.raw_size}, {"entropy", sec.entropy}, {"executable", executable_characteristics(sec.characteristics)}});
    }
    std::vector<std::string> import_modules;
    parse_import_names(pid, pe, import_modules, 64);
    json import_summary = parse_import_summary(pid, pe, 256);
    const std::uint64_t import_function_count = import_summary.value("function_count", 0ull);
    const bool no_import_directory = !import_summary.value("directory_present", false);
    bool loader_only_imports = import_function_count > 0 && import_function_count <= 8;
    if (loader_only_imports) {
        for (const auto& fn : import_summary.value("functions", json::array())) {
            const std::string name = lower_ascii(fn.value("function_name", std::string()));
            if (name == "loadlibrarya" || name == "loadlibraryw" || name == "loadlibraryexa" || name == "loadlibraryexw" ||
                name == "getprocaddress" || name == "virtualprotect" || name == "virtualalloc" || name == "virtualfree" ||
                name == "exitprocess" || name == "getmodulehandlea" || name == "getmodulehandlew")
                continue;
            loader_only_imports = false;
            break;
        }
    }
    bool minimal_iat = no_import_directory || import_modules.size() <= 2 || import_function_count <= 8 || loader_only_imports;
    if (hint == "unknown" && (high_entropy_exec > 0 || minimal_iat))
        hint = "custom";
    double confidence = 0.1 + high_entropy_exec * 0.35 + (minimal_iat ? 0.2 : 0.0) + (loader_only_imports ? 0.08 : 0.0);
    confidence = std::min(0.95, confidence);
    json out;
    out["likely_packed"] = confidence >= 0.55;
    out["confidence"] = confidence;
    out["entropy_map"] = entropy_map;
    out["packer_hint"] = hint;
    out["module"] = mod->name;
    out["module_base"] = sa_format_address(mod->base);
    out["minimal_iat"] = minimal_iat;
    out["minimal_iat_reason"] = no_import_directory ? "no_import_directory" : (loader_only_imports ? "loader_api_only_imports" : (import_function_count <= 8 ? "low_import_function_count" : "low_import_module_count"));
    out["fixture_kind"] = no_import_directory ? "synthetic_no_import_pe_or_minimal_import_directory" : "pe_import_directory";
    out["empty_imports_expected"] = no_import_directory;
    out["import_summary_zero_is_expected"] = no_import_directory;
    out["pe_parsed"] = true;
    out["section_count"] = pe.sections.size();
    out["high_entropy_executable_section_count"] = high_entropy_exec;
    out["import_module_count"] = import_modules.size();
    out["import_function_count"] = import_function_count;
    out["import_summary"] = import_summary;
    return tool_result_t::ok("Packer detection completed", out);
}

inline std::vector<mapped_section_t> packed_candidate_sections(std::uint32_t pid, const target_module_t& mod)
{
    pe_layout_t pe;
    if (!read_pe_layout(pid, mod.base, pe))
        return {};
    std::vector<mapped_section_t> out;
    for (auto sec : pe.sections) {
        if (!executable_characteristics(sec.characteristics))
            continue;
        const std::uint32_t size = std::min<std::uint32_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 1024u * 1024u);
        std::vector<std::uint8_t> bytes;
        if (size && read_target_memory(pid, sec.va, size, bytes))
            sec.entropy = entropy_of(bytes);
        if (sec.entropy > 7.0 || out.empty())
            out.push_back(sec);
    }
    return out;
}

inline bool address_in_module(const target_module_t& mod, const pe_layout_t& pe, std::uint64_t va)
{
    const std::uint64_t size = std::max<std::uint64_t>(mod.size, pe.size_of_image);
    return size != 0 && va >= mod.base && va < mod.base + size;
}

inline std::string section_for_va(const pe_layout_t& pe, std::uint64_t va)
{
    for (const auto& sec : pe.sections) {
        const std::uint64_t size = std::max<std::uint64_t>(sec.virtual_size, sec.raw_size);
        if (size && va >= sec.va && va < sec.va + size)
            return sec.name;
    }
    return {};
}

inline void append_oep_candidate(json& candidates, json candidate)
{
    const std::string va = candidate.value("va", std::string());
    const std::string strategy = candidate.value("strategy_used", std::string());
    for (const auto& existing : candidates) {
        if (existing.value("va", std::string()) == va && existing.value("strategy_used", std::string()) == strategy)
            return;
    }
    candidates.push_back(std::move(candidate));
}

inline void run_stack_restore_oep_heuristic(std::uint32_t pid, std::uint32_t tid, const target_module_t& mod, const pe_layout_t& pe, json& candidates, json& evidence)
{
    json ev;
    ev["strategy"] = "esp_trick";
    ev["tid"] = tid;
    ev["module_is_64"] = pe.is_64;
    if (tid != 0) {
        voyager::device_t::thread_context ctx{};
        if (read_target_thread_context(pid, tid, ctx)) {
            ev["thread_rip"] = sa_format_address(ctx.rip);
            ev["thread_rsp"] = sa_format_address(ctx.rsp);
        } else {
            ev["thread_context_available"] = false;
        }
    }
    auto insns = disassemble_target(pid, pe.entry, 0x3000, 768);
    bool saw_pushad = false;
    bool saw_popad = false;
    int push_run = 0;
    int pop_run = 0;
    int restore_index = -1;
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const std::string m = mnemonic_of(insns[i]);
        if (m == "pushad" || m == "pusha") {
            saw_pushad = true;
            push_run = std::max(push_run, 8);
        } else if (m == "push" || m == "pushfq" || m == "pushfd") {
            ++push_run;
        }
        if (m == "popad" || m == "popa") {
            saw_popad = true;
            restore_index = static_cast<int>(i);
            break;
        }
        if (m == "pop" || m == "popfq" || m == "popfd") {
            ++pop_run;
            if (pop_run >= 6) {
                restore_index = static_cast<int>(i);
                break;
            }
        } else if (m != "nop") {
            pop_run = 0;
        }
    }
    ev["saw_pushad"] = saw_pushad;
    ev["saw_popad"] = saw_popad;
    ev["push_sequence_count"] = push_run;
    ev["restore_sequence_count"] = pop_run;
    const bool meaningful = saw_pushad || saw_popad || (!pe.is_64 && push_run >= 6) || (push_run >= 6 && pop_run >= 6);
    ev["applicable"] = meaningful;
    if (!meaningful || restore_index < 0) {
        ev["result"] = "skipped_no_stack_restore_pattern";
        evidence.push_back(std::move(ev));
        return;
    }
    ev["restore_va"] = sa_format_address(insns[static_cast<std::size_t>(restore_index)].addr);
    for (std::size_t j = static_cast<std::size_t>(restore_index + 1); j < insns.size() && j <= static_cast<std::size_t>(restore_index + 12); ++j) {
        const auto& ins = insns[j];
        if (!(ins.is_branch || ins.is_call || ins.is_ret))
            continue;
        if (ins.branch_target == 0 || !address_in_module(mod, pe, ins.branch_target))
            continue;
        std::vector<std::uint8_t> bytes;
        read_target_memory(pid, ins.branch_target, 32, bytes);
        json ce;
        ce["va"] = sa_format_address(ins.branch_target);
        ce["strategy_used"] = "esp_trick";
        ce["confidence"] = (saw_pushad && saw_popad) ? "medium" : "low";
        ce["first_instruction_preview"] = disasm_preview_for_bytes(ins.branch_target, bytes, 4);
        ce["evidence"] = json{{"restore_va", sa_format_address(insns[static_cast<std::size_t>(restore_index)].addr)}, {"transfer_va", sa_format_address(ins.addr)}, {"transfer_disasm", std::string(ins.mnem) + " " + ins.ops}, {"tid", tid}, {"observation", "static_stack_restore_transfer"}};
        append_oep_candidate(candidates, std::move(ce));
        ev["result"] = "candidate_from_stack_restore_transfer";
        ev["candidate_va"] = sa_format_address(ins.branch_target);
        evidence.push_back(std::move(ev));
        return;
    }
    ev["result"] = "restore_seen_without_module_transfer";
    evidence.push_back(std::move(ev));
}

inline tool_result_t pack_find_oep(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    if (!unsafe_confirmed(params))
        return tool_result_t::error("pack_find_oep installs temporary PAGE_GUARD or hardware-breakpoint observation. Re-run with confirm_unsafe=true or allow_unsafe=true.",
            destructive_safe_contract_payload("pack_find_oep", "find_oep", params, "confirm_unsafe_required", "temporary_page_guard_or_hardware_breakpoint_observation"));
    const std::uint32_t pid = requested_pid(params);
    if (pid == 0)
        return tool_result_t::error("An attached process or process_id is required",
            destructive_safe_contract_payload("pack_find_oep", "find_oep", params, "process_id_required", "temporary_page_guard_or_hardware_breakpoint_observation"));
    std::string err;
    auto mod = select_user_main_module(params, &err);
    if (!mod)
        return tool_result_t::error(err.empty() ? "No target module found" : err);
    const std::string strategy = lower_ascii(params.value("strategy", std::string("all")));
    if (strategy != "all" && strategy != "page_guard" && strategy != "tail_jump" && strategy != "esp_trick")
        return tool_result_t::error("strategy must be one of all, page_guard, tail_jump, or esp_trick",
            destructive_safe_contract_payload("pack_find_oep", "find_oep", params, "invalid_strategy", "temporary_page_guard_or_hardware_breakpoint_observation"));
    std::uint32_t timeout_ms = static_cast<std::uint32_t>(parse_param_u64(params, "timeout_ms").value_or(30000));
    timeout_ms = std::clamp<std::uint32_t>(timeout_ms, 100, 120000);
    bool deadline_hit = false;
    bool cancelled = false;
    std::string stop_phase;
    auto stop_requested = [&](const char* phase) -> bool {
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            stop_phase = phase ? phase : "";
            return true;
        }
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        if (call_deadline != 0 && GetTickCount64() >= call_deadline)
        {
            deadline_hit = true;
            stop_phase = phase ? phase : "";
            return true;
        }
        return false;
    };
    std::uint32_t tid = 0;
    if (auto t = parse_param_u64(params, "tid"))
        tid = static_cast<std::uint32_t>(*t);
    if (tid == 0) {
        auto threads = enumerate_target_threads(pid);
        if (!threads.empty())
            tid = threads.front().tid;
    }
    pe_layout_t pe;
    if (!read_pe_layout(pid, mod->base, pe))
        return tool_result_t::error("Could not parse PE headers for " + mod->name);
    json candidates = json::array();
    json evidence = json::array();
    if (strategy == "page_guard" || strategy == "all") {
        auto sections = packed_candidate_sections(pid, *mod);
        json ev;
        ev["strategy"] = "page_guard";
        ev["section_count"] = sections.size();
        ev["timeout_ms"] = timeout_ms;
        ev["backend"] = "whoswho_driver_page_guard";
        json installed = json::array();
        json failures = json::array();
        json capture_evidence = json::array();
        std::vector<std::pair<std::uint32_t, mapped_section_t>> sessions;
        const std::uint32_t max_sections = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(parse_param_u64(params, "page_guard_section_limit").value_or(4), 16));
        for (const auto& sec : sections) {
            if (sessions.size() >= max_sections)
                break;
            const std::uint64_t sec_size = std::min<std::uint64_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 1024ull * 1024ull);
            if (sec.va == 0 || sec_size == 0)
                continue;
            const std::uint32_t sid = page_guard_engine::g_pg_engine.install(pid, sec.va, sec_size, false, 64, true);
            if (sid == 0) {
                failures.push_back(json{{"section", sec.name}, {"va", sa_format_address(sec.va)}, {"size", sec_size}, {"failure", page_guard_install_failure_json()}});
                continue;
            }
            sessions.emplace_back(sid, sec);
            installed.push_back(json{{"session_id", sid}, {"section", sec.name}, {"va", sa_format_address(sec.va)}, {"size", sec_size}});
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        std::set<std::uint64_t> seen_candidates;
        while (!sessions.empty() && std::chrono::steady_clock::now() < deadline) {
            if (stop_requested("page_guard_wait"))
                break;
            bool any = false;
            for (const auto& session : sessions) {
                if (stop_requested("page_guard_drain"))
                    break;
                auto records = page_guard_engine::g_pg_engine.get_capture_records(session.first);
                if (!records.empty())
                    any = true;
                for (const auto& rec : records) {
                    const auto& meta = rec.metadata;
                    json cap = page_guard_capture_json(rec);
                    cap["session_id"] = session.first;
                    cap["section"] = session.second.name;
                    capture_evidence.push_back(cap);
                    const std::uint64_t candidate = address_in_module(*mod, pe, meta.fault_addr) ? meta.fault_addr : (address_in_module(*mod, pe, meta.rip) ? meta.rip : 0);
                    if (candidate != 0 && seen_candidates.insert(candidate).second) {
                        std::vector<std::uint8_t> bytes;
                        read_target_memory(pid, candidate, 32, bytes);
                        const std::string sec_name = section_for_va(pe, candidate);
                        append_oep_candidate(candidates, json{{"va", sa_format_address(candidate)}, {"strategy_used", "page_guard"}, {"confidence", meta.access_type == 8 ? "high" : "medium"}, {"first_instruction_preview", disasm_preview_for_bytes(candidate, bytes, 4)}, {"section", sec_name.empty() ? session.second.name : sec_name}, {"evidence", json{{"session_id", session.first}, {"fault_va", sa_format_address(meta.fault_addr)}, {"rip", sa_format_address(meta.rip)}, {"access_type", meta.access_type}, {"exception_code", meta.exception_code}}}});
                    }
                }
            }
            if (seen_candidates.size() >= 8)
                break;
            if (deadline_hit || cancelled)
                break;
            if (!any)
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        if (!cancelled && !deadline_hit && std::chrono::steady_clock::now() >= deadline)
        {
            deadline_hit = true;
            stop_phase = "page_guard_timeout";
        }
        json uninstalled = json::array();
        for (const auto& session : sessions)
            uninstalled.push_back(json{{"session_id", session.first}, {"ok", page_guard_engine::g_pg_engine.uninstall(session.first)}});
        ev["installed"] = installed;
        ev["install_failures"] = failures;
        ev["captures"] = capture_evidence;
        ev["capture_count"] = capture_evidence.size();
        ev["deadline_hit"] = deadline_hit;
        ev["cancelled"] = cancelled;
        ev["stop_phase"] = stop_phase;
        ev["uninstalled"] = uninstalled;
        ev["result"] = seen_candidates.empty() ? (installed.empty() ? "install_failed" : "no_page_guard_hits") : "candidate_found";
        evidence.push_back(std::move(ev));
    }
    if (!deadline_hit && !cancelled && (strategy == "tail_jump" || strategy == "all")) {
        json ev;
        ev["strategy"] = "tail_jump";
        auto insns = disassemble_target(pid, pe.entry, 0x4000, 1024);
        ev["instructions_scanned"] = insns.size();
        for (const auto& ins : insns) {
            if ((ins.is_branch || ins.is_call) && address_in_module(*mod, pe, ins.branch_target)) {
                std::vector<std::uint8_t> bytes;
                read_target_memory(pid, ins.branch_target, 32, bytes);
                const std::string sec_name = section_for_va(pe, ins.branch_target);
                append_oep_candidate(candidates, json{{"va", sa_format_address(ins.branch_target)}, {"strategy_used", "tail_jump"}, {"confidence", sec_name.empty() ? "low" : "medium"}, {"first_instruction_preview", disasm_preview_for_bytes(ins.branch_target, bytes, 4)}, {"section", sec_name.empty() ? "unknown" : sec_name}, {"evidence", json{{"transfer_va", sa_format_address(ins.addr)}, {"transfer_disasm", std::string(ins.mnem) + " " + ins.ops}, {"observation", "static_entry_transfer_into_module"}}}});
                ev["result"] = "candidate_found";
                ev["candidate_va"] = sa_format_address(ins.branch_target);
                break;
            }
        }
        if (!ev.contains("result"))
            ev["result"] = "no_module_tail_transfer";
        evidence.push_back(std::move(ev));
    }
    if (!deadline_hit && !cancelled && (strategy == "esp_trick" || strategy == "all")) {
        run_stack_restore_oep_heuristic(pid, tid, *mod, pe, candidates, evidence);
    }
    json out;
    out["candidates"] = candidates;
    out["count"] = candidates.size();
    out["evidence"] = evidence;
    out["strategy_requested"] = strategy;
    out["pid"] = pid;
    out["tid"] = tid;
    out["module"] = mod->name;
    out["module_base"] = sa_format_address(mod->base);
    out["timeout_ms"] = timeout_ms;
    out["deadline_hit"] = deadline_hit;
    out["cancelled"] = cancelled;
    out["partial"] = deadline_hit || cancelled;
    out["stop_phase"] = stop_phase;
    if (deadline_hit || cancelled)
        return tool_result_t::error(cancelled ? "OEP scan cancelled before all requested strategies completed." : "OEP scan deadline reached before all requested strategies completed.", out);
    if (strategy == "page_guard" && candidates.empty())
        return tool_result_t::error("PAGE_GUARD OEP scan completed without live OEP hits.", out);
    return tool_result_t::ok("OEP scan completed", out);
}

struct iat_session_t {
    std::string id;
    std::uint32_t pid = 0;
    std::vector<std::pair<std::uint32_t, int>> breakpoints;
    std::uint32_t max_captures = 1024;
    json target_exports = json::array();
    json breakpoint_evidence = json::array();
    std::uint32_t resolved_targets = 0;
    std::uint32_t unresolved_targets = 0;
    std::uint32_t slot_limit_skips = 0;
    std::uint32_t failed_arms = 0;
};

inline std::mutex& iat_mutex()
{
    static std::mutex m;
    return m;
}

inline std::map<std::string, iat_session_t>& iat_sessions()
{
    static std::map<std::string, iat_session_t> s;
    return s;
}

inline std::uint64_t resolve_module_export_for_pid(std::uint32_t pid, const char* module_name, const char* export_name)
{
    for (const auto& m : driver_bridge::enumerate_modules_for(pid)) {
        if (lower_ascii(m.name) == lower_ascii(module_name)) {
            active_pid_scope_t scope(pid);
            if (!scope.ok)
                return 0;
            return driver_bridge::resolve_export(m.base, export_name);
        }
    }
    return 0;
}

inline json current_import_table(std::uint32_t pid, const target_module_t& mod, std::size_t max_entries)
{
    json arr = json::array();
    pe_layout_t pe;
    if (!read_pe_layout(pid, mod.base, pe) || pe.import_rva == 0)
        return arr;
    const std::uint64_t dir = pe.base + pe.import_rva;
    for (std::uint32_t desc = 0; desc < 256 && arr.size() < max_entries; ++desc) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        if (!read_target_value(pid, dir + static_cast<std::uint64_t>(desc) * sizeof(d), d))
            break;
        if (d.OriginalFirstThunk == 0 && d.FirstThunk == 0)
            break;
        std::string mod_name;
        std::vector<std::uint8_t> name_bytes;
        if (d.Name && read_target_memory(pid, pe.base + d.Name, 256, name_bytes)) {
            for (std::uint8_t b : name_bytes) {
                if (b == 0)
                    break;
                mod_name.push_back(static_cast<char>(b));
            }
        }
        const std::uint32_t lookup_rva = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        for (std::uint32_t i = 0; i < 4096 && arr.size() < max_entries; ++i) {
            std::uint64_t thunk = 0;
            std::uint64_t bound = 0;
            const std::uint64_t lookup_va = pe.base + lookup_rva + static_cast<std::uint64_t>(i) * (pe.is_64 ? 8 : 4);
            const std::uint64_t iat_va = pe.base + d.FirstThunk + static_cast<std::uint64_t>(i) * (pe.is_64 ? 8 : 4);
            if (pe.is_64) {
                if (!read_target_value(pid, lookup_va, thunk) || thunk == 0)
                    break;
                read_target_value(pid, iat_va, bound);
            } else {
                std::uint32_t t32 = 0, b32 = 0;
                if (!read_target_value(pid, lookup_va, t32) || t32 == 0)
                    break;
                read_target_value(pid, iat_va, b32);
                thunk = t32;
                bound = b32;
            }
            std::string function_name = "ordinal";
            const bool ordinal = pe.is_64 ? ((thunk & 0x8000000000000000ULL) != 0) : ((thunk & 0x80000000ULL) != 0);
            if (!ordinal) {
                std::uint32_t hint_name = static_cast<std::uint32_t>(thunk & 0x7FFFFFFFULL);
                std::vector<std::uint8_t> fn_bytes;
                if (read_target_memory(pid, pe.base + hint_name + 2, 256, fn_bytes)) {
                    function_name.clear();
                    for (std::uint8_t b : fn_bytes) {
                        if (b == 0)
                            break;
                        function_name.push_back(static_cast<char>(b));
                    }
                }
            }
            arr.push_back(json{{"iat_slot_va", sa_format_address(iat_va)}, {"module_name", mod_name}, {"function_name", function_name}, {"resolved_va", sa_format_address(bound)}});
        }
    }
    return arr;
}

inline tool_result_t pack_iat_recover(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::uint32_t pid = requested_pid(params);
    std::string err;
    auto mod = select_user_main_module(params, &err);
    if (!mod)
        return tool_result_t::error(err.empty() ? "No module available for IAT reconstruction" : err);
    const std::size_t max_entries = static_cast<std::size_t>(std::min<std::uint64_t>(parse_param_u64(params, "max_entries").value_or(1024), 16384));
    json entries = current_import_table(pid, *mod, max_entries);
    pe_layout_t pe;
    const bool pe_ok = read_pe_layout(pid, mod->base, pe);
    return tool_result_t::ok("IAT recovery completed", json{{"entries", entries}, {"count", entries.size()}, {"entry_count", entries.size()}, {"max_entries", max_entries}, {"bounded", true}, {"module", mod->name}, {"module_base", sa_format_address(mod->base)}, {"pid", pid}, {"pe_parsed", pe_ok}, {"import_directory_present", pe_ok && pe.import_rva != 0}, {"import_directory_rva", pe_ok ? json(sa_format_address(pe.import_rva)) : json(nullptr)}, {"import_directory_size", pe_ok ? json(pe.import_size) : json(nullptr)}, {"capture_backend", "read_only_current_import_table"}, {"live_hit_collection", "not_requested"}});
}

inline tool_result_t pack_iat_manage(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "start") {
        if (!unsafe_confirmed(params) && !unsafe_confirmed(p))
            return tool_result_t::error("pack_iat_manage start writes hardware breakpoint registers in target threads. Re-run with confirm_unsafe=true or allow_unsafe=true.",
                destructive_safe_contract_payload("pack_iat_manage", "start", p, "confirm_unsafe_required", "temporary_hardware_breakpoint_import_resolution_observation"));
        const std::uint32_t pid = requested_pid(p);
        if (pid == 0)
            return tool_result_t::error("An attached process or process_id is required",
                destructive_safe_contract_payload("pack_iat_manage", "start", p, "process_id_required", "temporary_hardware_breakpoint_import_resolution_observation"));
        const std::vector<std::pair<const char*, const char*>> exports = {
            {"kernel32.dll", "GetProcAddress"},
            {"kernel32.dll", "LoadLibraryExA"},
            {"kernel32.dll", "LoadLibraryExW"},
            {"kernel32.dll", "LoadLibraryA"},
            {"kernel32.dll", "LoadLibraryW"},
            {"kernelbase.dll", "LoadLibraryExA"},
            {"kernelbase.dll", "LoadLibraryExW"},
            {"kernelbase.dll", "LoadLibraryA"},
            {"kernelbase.dll", "LoadLibraryW"}
        };
        struct resolved_export_t {
            const char* module;
            const char* name;
            std::uint64_t va;
        };
        std::vector<resolved_export_t> resolved;
        auto threads = enumerate_target_threads(pid);
        iat_session_t s;
        s.id = next_prefixed_id("iat");
        s.pid = pid;
        s.max_captures = static_cast<std::uint32_t>(std::min<std::uint64_t>(parse_param_u64(p, "max_captures").value_or(1024), 16384));
        for (const auto& ex : exports) {
            const std::uint64_t va = resolve_module_export_for_pid(pid, ex.first, ex.second);
            json target{{"module", ex.first}, {"export", ex.second}, {"address", va ? sa_format_address(va) : "unknown"}, {"resolved", va != 0}};
            s.target_exports.push_back(target);
            if (va) {
                resolved.push_back({ex.first, ex.second, va});
                ++s.resolved_targets;
            } else {
                ++s.unresolved_targets;
            }
        }
        for (const auto& th : threads) {
            int slot = 0;
            for (const auto& ex : resolved) {
                json bp{{"tid", th.tid}, {"module", ex.module}, {"export", ex.name}, {"address", sa_format_address(ex.va)}};
                if (slot >= 4) {
                    ++s.slot_limit_skips;
                    bp["armed"] = false;
                    bp["reason"] = "x64_debug_register_slot_limit";
                    if (s.breakpoint_evidence.size() < 512)
                        s.breakpoint_evidence.push_back(std::move(bp));
                    continue;
                }
                bp["slot"] = slot;
                if (set_target_hardware_breakpoint(pid, th.tid, slot, ex.va, 0, 0)) {
                    s.breakpoints.push_back({th.tid, slot});
                    bp["armed"] = true;
                    ++slot;
                } else {
                    ++s.failed_arms;
                    bp["armed"] = false;
                    bp["reason"] = "set_hardware_breakpoint_failed";
                    bp["win32_error"] = static_cast<unsigned long>(GetLastError());
                    ++slot;
                }
                if (s.breakpoint_evidence.size() < 512)
                    s.breakpoint_evidence.push_back(std::move(bp));
            }
        }
        {
            std::lock_guard<std::mutex> lk(iat_mutex());
            iat_sessions()[s.id] = s;
        }
        return tool_result_t::ok(json{{"session_id", s.id}, {"pid", pid}, {"thread_breakpoints", s.breakpoints.size()}, {"resolved_targets", s.resolved_targets}, {"unresolved_targets", s.unresolved_targets}, {"slot_limit_skips", s.slot_limit_skips}, {"failed_arms", s.failed_arms}, {"target_exports", s.target_exports}, {"breakpoint_evidence", s.breakpoint_evidence}, {"capture_backend", "hardware_breakpoint_observation"}, {"live_hit_collection", "not_connected_to_debug_event_consumer"}, {"note", "results include current IAT reconstruction and session breakpoint evidence; no live hits are synthesized."}});
    }
    if (action == "results") {
        const std::string id = p.value("session_id", std::string());
        iat_session_t s;
        {
            std::lock_guard<std::mutex> lk(iat_mutex());
            auto it = iat_sessions().find(id);
            if (it == iat_sessions().end())
            {
                json out = destructive_safe_contract_payload("pack_iat_manage", "results", p, "session_id_not_found", "existing_iat_observation_session");
                out["session_id"] = id;
                return tool_result_t::error("session_id not found", out);
            }
            s = it->second;
        }
        std::string err;
        json module_query = p;
        if (!module_query.contains("process_id"))
            module_query["process_id"] = s.pid;
        auto mod = select_user_main_module(module_query, &err);
        if (!mod) {
            auto mods = user_modules(s.pid);
            if (mods.empty())
                return tool_result_t::error(err.empty() ? "No module available for IAT reconstruction" : err);
            mod = mods.front();
        }
        json entries = current_import_table(s.pid, *mod, s.max_captures);
        json captured_hits = json::array();
        return tool_result_t::ok(json{{"session_id", id}, {"entries", entries}, {"count", entries.size()}, {"module", mod->name}, {"iat_reconstruction", json{{"module", mod->name}, {"module_base", sa_format_address(mod->base)}, {"entries", entries}, {"count", entries.size()}}}, {"captured_hits", captured_hits}, {"captured_hit_count", 0}, {"capture_backend", "hardware_breakpoint_observation"}, {"live_hit_collection", "not_connected_to_debug_event_consumer"}, {"target_exports", s.target_exports}, {"breakpoint_evidence", s.breakpoint_evidence}, {"resolved_targets", s.resolved_targets}, {"unresolved_targets", s.unresolved_targets}, {"slot_limit_skips", s.slot_limit_skips}, {"failed_arms", s.failed_arms}});
    }
    if (action == "stop") {
        const std::string id = p.value("session_id", std::string());
        iat_session_t s;
        {
            std::lock_guard<std::mutex> lk(iat_mutex());
            auto it = iat_sessions().find(id);
            if (it == iat_sessions().end())
            {
                json out = destructive_safe_contract_payload("pack_iat_manage", "stop", p, "session_id_not_found", "existing_iat_observation_session");
                out["session_id"] = id;
                return tool_result_t::error("session_id not found", out);
            }
            s = it->second;
            iat_sessions().erase(it);
        }
        int cleared = 0;
        for (const auto& bp : s.breakpoints) {
            if (clear_target_hardware_breakpoint(s.pid, bp.first, bp.second))
                ++cleared;
        }
        return tool_result_t::ok(json{{"session_id", id}, {"cleared_breakpoints", cleared}});
    }
    return compat_unknown_action("pack_iat_manage", action);
}

}

inline tool_result_t vm_identify(const json& params) { return detail::vm_identify(params); }
inline tool_result_t vm_trace_bytecode(const json& params) { return detail::vm_trace_bytecode(params); }
inline tool_result_t vm_classify_handler(const json& params) { return detail::vm_classify_handler(params); }
inline tool_result_t vm_build_opcode_map(const json& params) { return detail::vm_build_opcode_map(params); }
inline tool_result_t vm_lift_to_il(const json& params) { return detail::vm_lift_to_il(params); }
inline tool_result_t vm_detect_handlers(const json& params) { return detail::vm_identify(params); }
inline tool_result_t vm_map_bytecode(const json& params) { return detail::vm_build_opcode_map(params); }
inline tool_result_t vm_lift_instruction(const json& params) { return detail::vm_lift_to_il(params); }
inline tool_result_t vm_recover_cfg(const json& params) { return detail::vm_recover_cfg(params); }
inline tool_result_t vm_emit_pseudocode(const json& params) { return detail::vm_emit_pseudocode(params); }
inline tool_result_t cff_detect(const json& params) { return detail::cff_detect(params); }
inline tool_result_t cff_recover_cfg(const json& params) { return detail::cff_recover_cfg(params); }
inline tool_result_t mba_simplify(const json& params) { return detail::mba_simplify(params); }
inline tool_result_t obf_detect_mba(const json& params) { return detail::obf_detect_mba(params); }
inline tool_result_t obf_simplify_expr(const json& params) { return detail::obf_simplify_expr(params); }
inline tool_result_t obf_rename_symbols(const json& params) { return detail::obf_rename_symbols(params); }
inline tool_result_t opaque_predicate_detect(const json& params) { return detail::opaque_predicate_detect(params); }
inline tool_result_t opaque_predicate_patch(const json& params) { return detail::opaque_predicate_patch(params); }
inline tool_result_t bogus_block_remove(const json& params) { return detail::bogus_block_remove(params); }
inline tool_result_t drv_find_dispatch_table(const json& params) { return detail::drv_find_dispatch_table(params); }
inline tool_result_t drv_decode_irp_handlers(const json& params) { return detail::drv_decode_irp_handlers(params); }
inline tool_result_t drv_find_ioctl_dispatch(const json& params) { return detail::drv_find_ioctl_dispatch(params); }
inline tool_result_t drv_enumerate_ioctls(const json& params) { return detail::drv_enumerate_ioctls(params); }
inline tool_result_t drv_map_ioctls(const json& params) { return detail::drv_map_ioctls(params); }
inline tool_result_t drv_find_device_names(const json& params) { return detail::drv_find_device_names(params); }
inline tool_result_t drv_check_buffer_safety(const json& params) { return detail::drv_check_buffer_safety(params); }
inline tool_result_t drv_hook_manage(const json& params) { return detail::drv_hook_manage(params); }
inline tool_result_t drv_send_ioctl(const json& params) { return detail::drv_send_ioctl(params); }
inline tool_result_t smc_manage(const json& params) { return detail::smc_manage(params); }
inline tool_result_t smc_scan_encrypted_regions(const json& params) { return detail::smc_scan_encrypted_regions(params); }
inline tool_result_t smc_detect_selfmod(const json& params) { return detail::smc_detect_selfmod(params); }
inline tool_result_t smc_snapshot_pages(const json& params) { return detail::smc_snapshot_pages(params); }
inline tool_result_t smc_find_decryptor(const json& params) { return detail::smc_find_decryptor(params); }
inline tool_result_t pack_detect(const json& params) { return detail::pack_detect(params); }
inline tool_result_t pack_find_oep(const json& params) { return detail::pack_find_oep(params); }
inline tool_result_t pack_iat_recover(const json& params) { return detail::pack_iat_recover(params); }
inline tool_result_t pack_iat_manage(const json& params) { return detail::pack_iat_manage(params); }

}
