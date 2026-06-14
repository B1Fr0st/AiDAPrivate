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
#include "emulation_engine.hpp"
#include "../analysis/code_patcher.hpp"
#include "../debugger/page_guard_engine.hpp"
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
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
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

inline tool_result_t require_driver()
{
    if (!driver_bridge::using_kernel_driver())
        return tool_result_t::error("Driver bridge is not connected. Attach with sessions_manage action=attach_pid first.");
    return tool_result_t::ok(json{{"status", "ok"}});
}

struct active_pid_scope_t {
    std::uint32_t previous = 0;
    std::uint32_t requested = 0;
    bool changed = false;
    bool ok = true;

    explicit active_pid_scope_t(std::uint32_t pid)
    {
        requested = pid;
        previous = driver_bridge::attached_pid();
        if (pid != 0 && previous != pid) {
            ok = driver_bridge::set_active_pid(pid);
            changed = ok;
        }
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

inline bool read_target_memory(std::uint32_t pid, std::uint64_t address, std::size_t size, std::vector<std::uint8_t>& out)
{
    out.clear();
    if (address == 0 || size == 0)
        return false;
    if (size > 16u * 1024u * 1024u)
        size = 16u * 1024u * 1024u;
    if (is_kernel_address(address))
        return driver_bridge::read_kernel_memory(address, size, out);
    if (pid != 0)
        return driver_bridge::read_memory_for(pid, address, size, out);
    return driver_bridge::read_memory(address, size, out);
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
    if (pid != 0)
        return driver_bridge::write_memory_for(pid, address, bytes);
    return driver_bridge::write_memory(address, bytes);
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
        ms.characteristics = sh.Characteristics;
        out.sections.push_back(std::move(ms));
    }
    return out.entry != 0 && !out.sections.empty();
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

inline std::uint64_t candidate_table_from_instruction(const AsmInstr& ins)
{
    if (!ins.has_mem_op || !ins.mem_op.has_disp)
        return 0;
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP))
        return ins.addr + static_cast<std::uint64_t>(std::max(ins.len, 1)) + static_cast<std::uint64_t>(ins.mem_op.disp);
    if (ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE) && ins.mem_op.index_reg != static_cast<std::uint16_t>(ZYDIS_REGISTER_NONE))
        return static_cast<std::uint64_t>(ins.mem_op.disp);
    return 0;
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
    size = std::clamp<std::uint32_t>(size, 32, 4096);
    auto insns = disassemble_target(pid, handler, size, 256);
    std::map<std::string, int> mcounts;
    bool branch = false;
    bool flags = false;
    bool mem_read = false;
    bool mem_write = false;
    json evidence = json::array();
    for (const auto& ins : insns) {
        const std::string m = mnemonic_of(ins);
        ++mcounts[m];
        if (ins.is_branch || ins.is_call || ins.is_ret)
            branch = true;
        if (m == "cmp" || m == "test" || m == "add" || m == "sub" || m == "xor" || m == "and" || m == "or")
            flags = true;
        const std::string dir = classify_memory_direction(ins);
        if (dir == "read")
            mem_read = true;
        if (dir == "write")
            mem_write = true;
    }
    auto count = [&](const char* m) { auto it = mcounts.find(m); return it == mcounts.end() ? 0 : it->second; };
    std::string semantic = "UNKNOWN";
    double confidence = 0.25;
    if (count("ret") > 0) { semantic = "RET"; confidence = 0.82; }
    else if (count("call") > 0) { semantic = "CALL"; confidence = 0.74; }
    else if (branch && (count("cmp") > 0 || count("test") > 0)) { semantic = "JCC"; confidence = 0.72; }
    else if (mem_write && count("mov") > 0) { semantic = "STORE"; confidence = 0.68; }
    else if (mem_read && count("mov") > 0) { semantic = "LOAD"; confidence = 0.68; }
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
        for (std::size_t i = 0; i < insns.size() && i < 8; ++i)
            evidence.push_back(instruction_to_json(insns[i]));
    }

    json roles;
    if (!insns.empty()) {
        for (const auto& ins : insns) {
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
#ifdef __NT__
    if (!insns.empty() && num_inputs > 0) {
        std::vector<std::uint8_t> code;
        if (read_target_memory(pid, handler, size, code) && !code.empty()) {
            const std::uint32_t traces = std::min<std::uint32_t>(num_inputs, 8);
            for (std::uint32_t i = 0; i < traces; ++i) {
                emulation::process_snapshot_t snap;
                snap.success = true;
                snap.rip = handler;
                snap.rflags = 0x202;
                snap.rax = 0x11110000ULL + i;
                snap.rbx = 0x22220000ULL + i * 3;
                snap.rcx = 0x33330000ULL + i * 5;
                snap.rdx = 0x44440000ULL + i * 7;
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
                cfg.record_mem_reads = false;
                cfg.record_mem_writes = true;
                cfg.record_registers = true;
                cfg.timeout_us = 1000000;
                auto r = emulation::emulate_from_snapshot(snap, cfg);
                differential.push_back(json{{"input_index", i}, {"success", r.success}, {"instructions", r.total_instructions}, {"writes", r.mem_writes.size()}, {"reg_deltas", r.reg_deltas.size()}});
            }
            if (!differential.empty())
                confidence = std::min(0.95, confidence + 0.06);
        }
    }
#else
    (void)num_inputs;
#endif

    json out;
    out["handler_va"] = sa_format_address(handler);
    out["semantic"] = semantic;
    out["operand_roles"] = roles;
    out["affects_flags"] = flags;
    out["is_branch"] = branch;
    out["confidence"] = confidence;
    out["instruction_count"] = insns.size();
    out["evidence"] = evidence;
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
    auto insns = disassemble_target(pid, *addr, 0x4000, 1024);
    if (insns.empty())
        return tool_result_t::error("No code could be decoded at " + sa_format_address(*addr));
    std::uint64_t best_table = 0;
    double best_density = 0.0;
    json table_sample = json::array();
    int indirect_dispatches = 0;
    int arithmetic = 0;
    int stack_ops = 0;
    int rotate_ops = 0;
    int branch_ops = 0;
    json evidence = json::array();
    for (const auto& ins : insns) {
        const std::string m = mnemonic_of(ins);
        if (ins.is_branch)
            ++branch_ops;
        if (m == "xor" || m == "add" || m == "sub" || m == "and" || m == "or")
            ++arithmetic;
        if (m == "rol" || m == "ror" || m == "shl" || m == "shr")
            ++rotate_ops;
        if (m == "push" || m == "pop" || m == "pushfq" || m == "popfq")
            ++stack_ops;
        if ((m == "jmp" || m == "call") && (std::string(ins.ops).find('[') != std::string::npos || ins.branch_target == 0)) {
            ++indirect_dispatches;
            evidence.push_back(instruction_to_json(ins));
            std::uint64_t cand = candidate_table_from_instruction(ins);
            if (cand) {
                json sample = json::array();
                const double density = table_density(pid, cand, 256, &sample);
                if (density > best_density) {
                    best_density = density;
                    best_table = cand;
                    table_sample = std::move(sample);
                }
            }
        }
    }
    double confidence = 0.15;
    if (indirect_dispatches > 0)
        confidence += 0.25;
    if (best_density > 0.35)
        confidence += 0.35;
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
    json out;
    out["name"] = name;
    out["version"] = version;
    out["confidence"] = confidence;
    out["dispatcher_va"] = sa_format_address(*addr);
    out["handler_table_va"] = best_table ? sa_format_address(best_table) : "unknown";
    out["handler_table_density"] = best_density;
    out["handler_table_sample"] = table_sample;
    out["bytecode_va"] = "unknown";
    out["vm_stack_reg"] = most_likely_vm_register(insns, {"rsp","rbp","rsi","rdi","rbx"});
    out["vip_reg"] = most_likely_vm_register(insns, {"rsi","rdi","rbx","rcx","rdx","r8","r9"});
    out["indirect_dispatches"] = indirect_dispatches;
    out["instruction_count"] = insns.size();
    out["evidence"] = evidence;
    return tool_result_t::ok("VM identification completed with heuristic confidence " + std::to_string(confidence), out);
}

inline tool_result_t vm_trace_bytecode(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    auto entry = parse_param_u64(params, "entry_va");
    if (!entry)
        entry = parse_param_u64(params, "address");
    if (!entry)
        return tool_result_t::error("entry_va is required");
    const std::uint32_t pid = requested_pid(params);
    std::uint32_t tid = 0;
    if (auto t = parse_param_u64(params, "tid"))
        tid = static_cast<std::uint32_t>(*t);
    if (tid == 0) {
        auto threads = driver_bridge::enumerate_threads_for(pid);
        if (!threads.empty())
            tid = threads.front().tid;
    }
    if (pid == 0 || tid == 0)
        return tool_result_t::error("An attached process and a target thread are required for snapshot tracing");
    std::uint32_t max_steps = static_cast<std::uint32_t>(parse_param_u64(params, "max_steps").value_or(50000));
    max_steps = std::clamp<std::uint32_t>(max_steps, 1, 100000);
    const std::uint32_t return_limit = std::clamp<std::uint32_t>(static_cast<std::uint32_t>(parse_param_u64(params, "max_returned_steps").value_or(1024)), 1, 4096);
#ifdef __NT__
    emulation::emulation_config_t cfg;
    cfg.start_address = *entry;
    cfg.max_instructions = max_steps;
    cfg.max_trace_entries = max_steps;
    cfg.record_mem_reads = true;
    cfg.record_mem_writes = true;
    cfg.record_registers = true;
    cfg.analyze_effective_ops = true;
    cfg.timeout_us = std::min<std::uint64_t>(parse_param_u64(params, "timeout_us").value_or(15000000), 60000000);
    auto r = emulation::driver_snapshot_and_emulate(pid, tid, cfg, *entry & ~0xFFFULL, 0x40000);
    const auto handler_lookup = handler_opcode_lookup_from_params(pid, params);
    const json opcode_map = params.contains("opcode_map") ? params["opcode_map"] : json::object();
    json steps = json::array();
    for (std::size_t i = 0; i + 1 < r.trace.size() && steps.size() < return_limit; ++i) {
        const auto& cur = r.trace[i];
        const auto& next = r.trace[i + 1];
        const std::string d = lower_ascii(cur.disasm);
        if (d.find("jmp") == std::string::npos && d.find("call") == std::string::npos)
            continue;
        json side_effects;
        json writes = json::array();
        for (const auto& w : r.mem_writes) {
            if (w.insn_address >= cur.address && w.insn_address <= next.address + 16) {
                writes.push_back(json{{"address", sa_format_address(w.address)}, {"size", w.size}, {"from_insn", sa_format_address(w.insn_address)}, {"hex", bytes_to_hex(w.data, 16)}});
                if (writes.size() >= 8)
                    break;
            }
        }
        side_effects["writes"] = std::move(writes);
        json st;
        st["step"] = steps.size();
        st["handler_va"] = sa_format_address(next.address);
        st["dispatch_va"] = sa_format_address(cur.address);
        st["dispatch_disasm"] = cur.disasm;
        st["side_effects"] = std::move(side_effects);
        st["flags_affected"] = d.find("cmp") != std::string::npos || d.find("test") != std::string::npos;
        std::string opcode;
        std::string opcode_source = "unresolved";
        if (auto it = handler_lookup.find(next.address); it != handler_lookup.end()) {
            opcode = it->second;
            opcode_source = "handler_table_or_opcode_map";
        } else {
            opcode = opcode_key_by_handler(opcode_map, next.address);
            if (!opcode.empty())
                opcode_source = "opcode_map_handler_va";
        }
        if (opcode.empty()) {
            st["vopcode"] = "unresolved";
            st["vopcode_resolved"] = false;
            st["unresolved_reason"] = "handler address was not present in the supplied opcode map or handler table";
        } else {
            st["vopcode"] = opcode;
            st["vopcode_resolved"] = true;
            st["opcode_source"] = opcode_source;
            if (const json* entry_json = opcode_map_entry_by_opcode(opcode_map, opcode)) {
                st["semantic"] = entry_json->value("semantic", std::string("UNKNOWN"));
                st["handler_confidence"] = entry_json->value("confidence", 0.0);
                if (entry_json->contains("operand_roles"))
                    st["operand_roles"] = (*entry_json)["operand_roles"];
            }
        }
        steps.push_back(std::move(st));
    }
    json out;
    out["entry_va"] = sa_format_address(*entry);
    out["pid"] = pid;
    out["tid"] = tid;
    out["success"] = r.success;
    out["emulated_instructions"] = r.total_instructions;
    out["trace_entries"] = r.trace.size();
    out["returned_steps"] = steps.size();
    out["truncated"] = r.trace.size() > return_limit;
    out["opcode_lookup_entries"] = handler_lookup.size();
    out["steps"] = steps;
    if (!r.success)
        out["error"] = r.error;
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
    json out = classify_handler_static(pid, *handler, size, inputs);
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
    count = std::clamp<std::uint32_t>(count, 1, 512);
    std::vector<std::uint8_t> bytes;
    if (!read_target_memory(pid, *table, static_cast<std::size_t>(count) * sizeof(std::uint64_t), bytes))
        return tool_result_t::error("Could not read handler table at " + sa_format_address(*table));
    json map = json::object();
    std::uint32_t classified = 0;
    std::uint32_t unknown = 0;
    const std::uint32_t got = static_cast<std::uint32_t>(bytes.size() / sizeof(std::uint64_t));
    for (std::uint32_t i = 0; i < got; ++i) {
        std::uint64_t handler = 0;
        std::memcpy(&handler, bytes.data() + static_cast<std::size_t>(i) * sizeof(handler), sizeof(handler));
        if (!pointer_looks_executable(pid, handler))
            continue;
        json cls = classify_handler_static(pid, handler, 512, 4);
        const std::string sem = cls.value("semantic", std::string("UNKNOWN"));
        if (sem == "UNKNOWN")
            ++unknown;
        else
            ++classified;
        const std::string key = opcode_key_from_index(i);
        cls["opcode"] = key;
        cls["opcode_index"] = i;
        cls["handler_va"] = sa_format_address(handler);
        map[key] = std::move(cls);
    }
    json out;
    out["handler_table_va"] = sa_format_address(*table);
    out["handler_count_requested"] = count;
    out["handler_count_read"] = got;
    out["opcode_map"] = std::move(map);
    out["classified_count"] = classified;
    out["unknown_count"] = unknown;
    out["confidence"] = got ? static_cast<double>(classified) / static_cast<double>(got) : 0.0;
    return tool_result_t::ok("VM opcode map classified " + std::to_string(classified) + " handlers", out);
}

inline std::string semantic_from_opcode_map(const json& map, const std::string& opcode)
{
    if (const json* entry = opcode_map_entry_by_opcode(map, opcode))
        return entry->value("semantic", std::string("UNKNOWN"));
    return "UNKNOWN";
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
        if (semantic.empty() || semantic == "UNKNOWN")
            semantic = "UNRESOLVED";
        json node;
        node["index"] = il.size();
        node["op"] = semantic;
        node["opcode"] = opcode;
        node["handler_va"] = s.value("handler_va", std::string("unknown"));
        node["resolution"] = resolution;
        if (map_entry) {
            node["confidence"] = map_entry->value("confidence", 0.0);
            if (map_entry->contains("operand_roles")) {
                const json& roles = (*map_entry)["operand_roles"];
                if (roles.is_object()) {
                    if (roles.contains("dst"))
                        node["dst"] = roles["dst"];
                    if (roles.contains("src1"))
                        node["src1"] = roles["src1"];
                    if (roles.contains("src2"))
                        node["src2"] = roles["src2"];
                }
            }
            if (map_entry->contains("evidence"))
                node["handler_evidence"] = (*map_entry)["evidence"];
        }
        json effects = s.value("side_effects", json::object());
        if (!effects.is_object())
            effects = json::object({{"raw", effects}});
        if (semantic == "UNRESOLVED") {
            ++unresolved;
            effects["unresolved"] = true;
            effects["unresolved_reason"] = handler_va ? "no opcode-map entry matched handler_va" : "trace step did not include a parseable handler_va";
        }
        node["effects"] = std::move(effects);
        if (semantic == "JCC" || semantic == "RET" || semantic == "CALL")
            node["terminator"] = true;
        if (optimize && semantic == "MOV" && node.contains("src1") && node.contains("dst") && node["src1"] == node["dst"]) {
            ++dead_assignments;
            continue;
        }
        if (optimize && semantic == "XOR" && node.contains("src1") && node.contains("src2") && node["src1"] == node["src2"]) {
            node["op"] = "CONST";
            node["value"] = "0x0";
            ++folded;
        }
        il.push_back(std::move(node));
    }
    json out;
    out["il_instructions"] = il;
    out["virtual_reg_map"] = json::object();
    out["memory_accesses"] = json::array();
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
    json nodes = json::array();
    json current;
    current["id"] = 0;
    current["il_instructions"] = json::array();
    current["successors"] = json::array();
    std::vector<int> exits;
    for (const auto& n : il) {
        current["il_instructions"].push_back(n);
        const std::string op = n.value("op", std::string());
        if (op == "JCC" || op == "RET" || op == "CALL") {
            const int id = current["id"].get<int>();
            if (op == "RET")
                exits.push_back(id);
            else {
                current["successors"].push_back(id + 1);
                if (n.contains("target"))
                    current["successors"].push_back(n["target"]);
            }
            nodes.push_back(current);
            current = json{{"id", id + 1}, {"il_instructions", json::array()}, {"successors", json::array()}};
        }
    }
    if (!current["il_instructions"].empty())
        nodes.push_back(current);
    json out;
    out["nodes"] = nodes;
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
    if (style == "asm_comments") {
        for (const auto& n : nodes) {
            ps << "block_" << n.value("id", 0) << ":\n";
            for (const auto& ins : n.value("il_instructions", json::array()))
                ps << "  ; " << ins.value("op", std::string("UNKNOWN")) << " " << ins.value("handler_va", std::string()) << "\n";
        }
    } else {
        ps << "void recovered_vm_function(void) {\n";
        for (const auto& n : nodes) {
            ps << "block_" << n.value("id", 0) << ":\n";
            for (const auto& ins : n.value("il_instructions", json::array())) {
                const std::string op = ins.value("op", std::string("UNKNOWN"));
                if (op == "UNKNOWN" || op == "UNRESOLVED")
                    unresolved.insert(ins.value("handler_va", std::string("unknown")));
                ps << "    " << lower_ascii(op) << "();\n";
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

inline json detect_flattening(std::uint32_t pid, std::uint64_t address, std::uint32_t size)
{
    auto insns = disassemble_target(pid, address, size, 8192);
    auto blocks = build_blocks(insns);
    int dispatcher = -1;
    std::size_t max_edges = 0;
    std::map<std::int64_t, int> state_disp_counts;
    for (const auto& b : blocks) {
        if (b.successors.size() > max_edges) {
            max_edges = b.successors.size();
            dispatcher = b.id;
        }
        for (const auto& ins : b.insns) {
            const std::string m = mnemonic_of(ins);
            if ((m == "mov" || m == "cmp") && ins.has_mem_op && ins.mem_op.has_disp)
                state_disp_counts[ins.mem_op.disp]++;
        }
    }
    std::int64_t state_disp = 0;
    int state_score = 0;
    for (const auto& it : state_disp_counts) {
        if (it.second > state_score) {
            state_score = it.second;
            state_disp = it.first;
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
    const double state_factor = state_score >= 4 ? 0.25 : (state_score >= 2 ? 0.1 : 0.0);
    const double loop_factor = blocks.empty() ? 0.0 : std::min(0.2, static_cast<double>(back_to_dispatcher) / static_cast<double>(blocks.size()));
    const double confidence = std::min(0.95, block_factor + edge_factor + state_factor + loop_factor);
    json out;
    out["is_flattened"] = confidence >= 0.55;
    out["confidence"] = confidence;
    out["dispatcher_va"] = dispatcher >= 0 && dispatcher < static_cast<int>(blocks.size()) ? sa_format_address(blocks[static_cast<std::size_t>(dispatcher)].start) : "unknown";
    out["state_var_offset"] = state_score ? sa_format_address(static_cast<std::uint64_t>(state_disp)) : "unknown";
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
    auto insns = disassemble_target(pid, *address, size, 8192);
    auto blocks = build_blocks(insns);
    json recovered = json::array();
    for (const auto& b : blocks) {
        json rb;
        rb["id"] = b.id;
        rb["state_in"] = first_immediate_in_block(b).has_value() ? sa_format_address(*first_immediate_in_block(b)) : "unknown";
        json outs = json::array();
        for (int sid : b.successors) {
            if (sid >= 0 && sid < static_cast<int>(blocks.size())) {
                auto imm = first_immediate_in_block(blocks[static_cast<std::size_t>(sid)]);
                outs.push_back(imm ? sa_format_address(*imm) : sa_format_address(blocks[static_cast<std::size_t>(sid)].start));
            }
        }
        rb["state_out"] = outs;
        json il = json::array();
        for (const auto& ins : b.insns)
            il.push_back(json{{"va", sa_format_address(ins.addr)}, {"op", ins.mnem}, {"operands", ins.ops}});
        rb["il"] = il;
        recovered.push_back(std::move(rb));
    }
    std::ostringstream ps;
    ps << "void recovered_flattened_function(void) {\n";
    for (const auto& b : blocks) {
        ps << "block_" << b.id << ":\n";
        if (!b.successors.empty())
            ps << "    goto block_" << b.successors.front() << ";\n";
    }
    ps << "}\n";
    json out;
    out["recovered_blocks"] = recovered;
    out["cfg_dot"] = cfg_to_dot(blocks, "cff_recovered");
    out["pseudocode"] = ps.str();
    out["detection"] = detect_flattening(pid, *address, size);
    return tool_result_t::ok("Recovered a heuristic CFG from flattened control flow", out);
}

inline json z3_backend_state()
{
    json state;
    HMODULE mod = GetModuleHandleW(L"libz3.dll");
    state["module_loaded"] = mod != nullptr;
    state["module_handle"] = mod ? sa_format_address(static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(mod))) : "0x0";
    if (mod) {
        char path[MAX_PATH] = {};
        DWORD len = GetModuleFileNameA(mod, path, MAX_PATH);
        state["module_path"] = len ? std::string(path, path + len) : std::string();
        const bool has_cfg = GetProcAddress(mod, "Z3_mk_config") != nullptr;
        const bool has_ctx = GetProcAddress(mod, "Z3_mk_context") != nullptr;
        const bool has_solver = GetProcAddress(mod, "Z3_mk_solver") != nullptr;
        const bool has_check = GetProcAddress(mod, "Z3_solver_check") != nullptr;
        state["api_mk_config"] = has_cfg;
        state["api_mk_context"] = has_ctx;
        state["api_mk_solver"] = has_solver;
        state["api_solver_check"] = has_check;
        state["api_available"] = has_cfg && has_ctx && has_solver && has_check;
    } else {
        wchar_t preload_dir[MAX_PATH] = {};
        DWORD preload_len = GetEnvironmentVariableW(L"AIDA_Z3_PRELOAD_DIR", preload_dir, MAX_PATH);
        state["module_path"] = "";
        state["api_available"] = false;
        state["preload_env_present"] = preload_len > 0 && preload_len < MAX_PATH;
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
    const json z3_state = z3_backend_state();
    auto insns = disassemble_target(pid, *address, size, 4096);
    json out = json::array();
    std::uint64_t deterministic_count = 0;
    std::uint64_t heuristic_count = 0;
    bool solver_required = false;
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
                const bool z3_api_available = z3_state.value("api_available", false);
                const std::string reason = !use_z3 ? "z3_not_requested" : (!z3_api_available ? "z3_backend_unavailable" : "z3_backend_available_no_owned_mba_solver_adapter");
                out.push_back(json{{"original_va", sa_format_address(ins.addr)}, {"original_expr", "xor/and/add MBA window"}, {"simplified_expr", "candidate_addition_or_bit_blend"}, {"verified", false}, {"proof_method", use_z3 ? "unverified_mba_heuristic_z3_not_invoked" : "unverified_mba_heuristic"}, {"solver_required", true}, {"solver_invoked", false}, {"solver_selection_reason", reason}, {"z3_skip_reason", reason}, {"z3_used", false}});
            }
        }
    }
    const bool z3_api_available = z3_state.value("api_available", false);
    const bool solver_invoked = false;
    std::string selection_reason;
    std::string skip_reason;
    if (!use_z3) {
        selection_reason = "z3_not_requested";
        skip_reason = "z3_not_requested";
    } else if (!solver_required) {
        selection_reason = "deterministic_identities_do_not_require_solver";
        skip_reason = "solver_not_required_for_detected_identities";
    } else if (!z3_api_available) {
        selection_reason = "z3_backend_unavailable";
        skip_reason = "z3_backend_unavailable";
    } else {
        selection_reason = "z3_backend_available_no_owned_mba_solver_adapter";
        skip_reason = "z3_backend_available_no_owned_mba_solver_adapter";
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
    result["z3_used"] = false;
    result["z3_backend"] = z3_state;
    result["solver_required"] = solver_required;
    result["solver_invoked"] = solver_invoked;
    result["solver_selection_reason"] = selection_reason;
    result["z3_skip_reason"] = skip_reason;
    result["expression_complexity"] = json{{"instructions_decoded", insns.size()}, {"deterministic_identity_count", deterministic_count}, {"heuristic_candidate_count", heuristic_count}, {"solver_candidate_count", heuristic_count}, {"scan_size", size}};
    result["proof_backend"] = solver_required ? "deterministic_local_identities_with_unverified_solver_candidates" : "deterministic_local_identities_only";
    result["confidence"] = out.empty() ? 0.0 : 0.65;
    return tool_result_t::ok("MBA simplification scan completed", result);
}

inline tool_result_t obf_detect_mba(const json& params)
{
    return mba_simplify(params);
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
    out["proof_method"] = proof;
    out["confidence"] = verified ? 1.0 : 0.35;
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
        return tool_result_t::error("obf_rename_symbols is read-only in standalone protected RE mode; no symbol database mutation backend is exposed.", json{{"applied", false}, {"mutation", "none"}, {"security_contract", "fail_closed_no_symbol_mutation"}});
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
    return tool_result_t::ok("Symbol rename plan generated without mutation", json{{"renames", renames}, {"count", renames.size()}, {"applied", false}, {"mutation", "none"}});
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
        return tool_result_t::error("opaque_predicate_patch mutates target code. Re-run with confirm_unsafe=true or allow_unsafe=true.");
    if (!params.contains("predicates") || !params["predicates"].is_array())
        return tool_result_t::error("predicates array is required");
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
        auto patch = patch_bytes_for_predicate(pid, pred);
        if (!patch)
            continue;
        const std::string desc = "opaque_predicate_patch " + pred.value("result", std::string("unknown"));
        const int idx = code_patcher::create_patch(*va, *patch, desc);
        bool ok = idx >= 0 && code_patcher::apply_patch(idx);
        if (ok)
            ++patched;
        log.push_back(json{{"va", sa_format_address(*va)}, {"action", pred.value("result", std::string()) == "always_true" ? "replace_with_unconditional_jump" : "nop_conditional_jump"}, {"patch_index", idx}, {"applied", ok}, {"bytes", bytes_to_hex(*patch)}});
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

inline bool parse_driver_entry_assignments(std::uint32_t pid, const target_module_t& mod, const pe_layout_t& pe, json& assignments, json& diagnostics, drv_dispatch_scan_context_t& ctx)
{
    assignments = json::array();
    diagnostics = json::object();
    diagnostics["candidates"] = json::array();
    auto insns = disassemble_driver_entry_bounded(pid, mod, pe, ctx, diagnostics);
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
            ctx.stage = "dispatch_candidate_limit";
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
        a["evidence"] = instruction_to_json(ins);
        a["handler_plausibility"] = handler_plausibility(pid, mod, pe, handler);
        const bool plausible = a["handler_plausibility"].value("plausible", false);
        a["accepted"] = plausible;
        if (!plausible)
            a["rejection_reason"] = a["handler_plausibility"].value("reason", std::string("handler_rejected"));
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
        diagnostics["candidates"].push_back(a);
        if (plausible)
            assignments.push_back(std::move(a));
    }
    diagnostics["candidate_count"] = diagnostics["candidates"].size();
    diagnostics["accepted_assignment_count"] = assignments.size();
    diagnostics["deadline_hit"] = ctx.deadline_hit;
    diagnostics["cancelled"] = ctx.cancelled;
    diagnostics["elapsed_ms"] = ctx.elapsed_ms();
    diagnostics["budget"] = ctx.status();
    if (assignments.empty())
        diagnostics["rejection_reason"] = ctx.cancelled ? "scan_cancelled" : (ctx.deadline_hit ? "scan_deadline_hit" : (diagnostics["candidate_count"].get<std::size_t>() == 0 ? "no_major_function_assignments_in_scan_window" : "all_major_function_candidates_rejected"));
    return !assignments.empty();
}

inline tool_result_t drv_find_dispatch_table(const json& params)
{
    auto chk = require_driver();
    const drv_dispatch_scan_limits_t limits = drv_dispatch_limits_from_params(params);
    drv_dispatch_scan_context_t scan_ctx(limits);
    if (!chk.success) {
        json out;
        out["dependency_unavailable"] = true;
        out["root_cause"] = "driver_bridge_not_connected";
        out["target_required"] = false;
        out["using_kernel_driver"] = driver_bridge::using_kernel_driver();
        out["attached_pid"] = driver_bridge::attached_pid();
        out["attached_pids"] = driver_bridge::attached_pids();
        out["auto_select_wdm_driver"] = params.value("auto_select_wdm_driver", false);
        out["budget"] = scan_ctx.status();
        out["breadcrumbs"] = scan_ctx.breadcrumbs;
        diag::log_tagged_fmt("protected_re",
            "drv_dispatch dependency_failed using_driver=%d attached_pid=%u target_required=0 error=%s",
            driver_bridge::using_kernel_driver() ? 1 : 0,
            driver_bridge::attached_pid(),
            chk.text.c_str());
        return tool_result_t::error(chk.text.empty() ? "Driver bridge is not connected" : chk.text, out);
    }
    std::string err;
    std::optional<target_module_t> mod;
    pe_layout_t preselected_pe;
    json preselected_assignments;
    json preselected_diagnostics;
    bool have_preselected_analysis = false;
    bool auto_selected = false;
    std::size_t auto_modules_scanned = 0;
    json auto_select_candidates = json::array();
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
        std::size_t candidate_index = 0;
        for (const auto& candidate : mods) {
            if (scan_ctx.should_stop("auto_select_candidate_loop"))
                break;
            if (auto_modules_scanned >= max_auto_modules)
                break;
            if (module_is_ntoskrnl(candidate))
                continue;
            ++auto_modules_scanned;
            pe_layout_t candidate_pe;
            json candidate_summary = json{{"candidate_index", candidate_index}, {"name", candidate.name}, {"base", sa_format_address(candidate.base)}, {"size", candidate.size}, {"path", candidate.path}};
            scan_ctx.record("candidate_begin", candidate_summary);
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch candidate_begin index=%llu name=%s base=0x%llX size=%llu path=%s elapsed_ms=%llu",
                static_cast<unsigned long long>(candidate_index),
                candidate.name.c_str(),
                static_cast<unsigned long long>(candidate.base),
                static_cast<unsigned long long>(candidate.size),
                candidate.path.c_str(),
                static_cast<unsigned long long>(scan_ctx.elapsed_ms()));
            ++candidate_index;
            if (!read_pe_layout_with_dispatch_diag(0, candidate, candidate_pe, scan_ctx, candidate_summary)) {
                if (!candidate_summary.contains("rejection_reason"))
                    candidate_summary["rejection_reason"] = "pe_header_parse_failed";
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
            candidate_summary["deadline_hit"] = scan_ctx.deadline_hit;
            candidate_summary["cancelled"] = scan_ctx.cancelled;
            candidate_summary["elapsed_ms"] = scan_ctx.elapsed_ms();
            if (candidate_assignments.empty()) {
                candidate_summary["rejection_reason"] = candidate_diagnostics.value("rejection_reason", std::string("no_accepted_dispatch_handlers"));
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
            if (auto_select_candidates.size() < 16)
                auto_select_candidates.push_back(std::move(candidate_summary));
            break;
        }
        if (!mod) {
            json out;
            out["auto_select_wdm_driver"] = true;
            out["auto_modules_scanned"] = auto_modules_scanned;
            out["max_auto_modules"] = max_auto_modules;
            out["candidates"] = auto_select_candidates;
            out["budget"] = scan_ctx.status();
            out["breadcrumbs"] = scan_ctx.breadcrumbs;
            out["deadline_hit"] = scan_ctx.deadline_hit;
            out["cancelled"] = scan_ctx.cancelled;
            out["target_required"] = false;
            out["dependency_state"] = json{{"using_kernel_driver", driver_bridge::using_kernel_driver()}, {"attached_pid", driver_bridge::attached_pid()}, {"attached_pids", driver_bridge::attached_pids()}};
            out["rejection_reason"] = scan_ctx.cancelled ? "scan_cancelled" : (scan_ctx.deadline_hit ? "scan_deadline_hit" : (mods.empty() ? (qerr.empty() ? "no_kernel_modules_available" : qerr) : "no_loaded_wdm_driver_with_accepted_major_function_assignments"));
            diag::log_tagged_fmt("protected_re",
                "drv_dispatch auto_select_failed scanned=%llu max=%llu deadline_hit=%d cancelled=%d reason=%s elapsed_ms=%llu",
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
    base_out["auto_modules_scanned"] = auto_modules_scanned;
    base_out["target_required"] = false;
    base_out["dependency_state"] = json{{"using_kernel_driver", driver_bridge::using_kernel_driver()}, {"attached_pid", driver_bridge::attached_pid()}, {"attached_pids", driver_bridge::attached_pids()}};
    base_out["budget"] = scan_ctx.status();
    if (!auto_select_candidates.empty())
        base_out["auto_select_candidates"] = auto_select_candidates;
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
    json out = base_out;
    out["driver_entry_va"] = sa_format_address(pe.entry);
    out["driver_entry_rva"] = pe.entry >= pe.base ? json(sa_format_address(pe.entry - pe.base)) : json(nullptr);
    out["dispatch_table_va"] = "driver_object+0x70";
    out["assignments"] = assignments;
    out["candidate_count"] = diagnostics.value("candidate_count", 0);
    out["accepted_assignment_count"] = diagnostics.value("accepted_assignment_count", 0);
    out["scan_window"] = diagnostics["scan_window"];
    out["diagnostics"] = diagnostics;
    out["budget"] = scan_ctx.status();
    out["breadcrumbs"] = scan_ctx.breadcrumbs;
    out["deadline_hit"] = scan_ctx.deadline_hit;
    out["cancelled"] = scan_ctx.cancelled;
    out["handler_plausibility_policy"] = "handler must resolve inside an executable section of the selected driver image";
    out["confidence"] = assignments.empty() ? 0.25 : std::min(0.95, 0.45 + assignments.size() * 0.04);
    out["note"] = assignments.empty() ? "No accepted MajorFunction assignments were found in the bounded DriverEntry scan; inspect diagnostics.candidates and breadcrumbs for rejected or bounded evidence." : "dispatch_table_va is expressed relative to the runtime DRIVER_OBJECT because the object pointer is not exposed by this read-only analysis path.";
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
        auto insns = disassemble_target(0, *handler, 4096, 512);
        std::uint64_t end = *handler;
        json preview = json::array();
        for (std::size_t i = 0; i < insns.size(); ++i) {
            end = insns[i].addr + static_cast<std::uint64_t>(std::max(insns[i].len, 1));
            if (i < 24)
                preview.push_back(instruction_to_json(insns[i]));
            if (insns[i].is_ret)
                break;
        }
        arr.push_back(json{{"irp_code", a.value("irp_code", 0)}, {"irp_name", a.value("irp_name", std::string("IRP_MJ_UNKNOWN"))}, {"handler_va", sa_format_address(*handler)}, {"size", end > *handler ? end - *handler : 0}, {"pseudocode_preview", preview}, {"parameter_usage", json{{"driver_object", "rcx"}, {"irp", "rdx"}}}});
    }
    return tool_result_t::ok(json(arr));
}

inline bool looks_ioctl(std::uint64_t value)
{
    const std::uint64_t function = (value >> 2) & 0xFFFULL;
    const std::uint64_t device = (value >> 16) & 0xFFFFULL;
    return value > 0x1000 && function != 0 && device != 0 && value <= 0xFFFFFFFFULL;
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
    auto insns = disassemble_target(0, *handler, 0x10000, 8192);
    json handlers = json::array();
    std::string type = "if_chain";
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        const std::string m = mnemonic_of(ins);
        if (m == "jmp" && ins.has_mem_op)
            type = "jump_table";
        if (m != "cmp" && m != "sub")
            continue;
        std::uint64_t ioctl = ins.has_imm ? ins.imm_unsigned : 0;
        if (!looks_ioctl(ioctl))
            continue;
        std::uint64_t target = 0;
        for (std::size_t j = i + 1; j < insns.size() && j < i + 5; ++j) {
            if (insns[j].branch_target) {
                target = insns[j].branch_target;
                break;
            }
        }
        handlers.push_back(json{{"ioctl_code", sa_format_address(ioctl)}, {"handler_va", target ? sa_format_address(target) : sa_format_address(ins.addr)}, {"compare_va", sa_format_address(ins.addr)}, {"confidence", target ? 0.78 : 0.55}});
    }
    if (handlers.size() > 3)
        type = "switch";
    json out;
    out["dispatch_type"] = type;
    out["dispatch_va"] = sa_format_address(*handler);
    out["ioctl_handlers"] = handlers;
    out["confidence"] = handlers.empty() ? 0.2 : std::min(0.9, 0.45 + handlers.size() * 0.08);
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
        e["input_buffer_used"] = true;
        e["output_buffer_used"] = method == "BUFFERED" || method == "OUT_DIRECT" || method == "NEITHER";
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

inline tool_result_t drv_find_device_names(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
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
    json found = json::array();
    for (std::size_t mi = 0; mi < mods.size() && mi < max_modules; ++mi) {
        const auto& mod = mods[mi];
        const std::uint64_t scan_size = std::min<std::uint64_t>(mod.size ? mod.size : 0x200000, 16ull * 1024ull * 1024ull);
        std::vector<std::uint8_t> bytes;
        if (!read_target_memory(0, mod.base, static_cast<std::size_t>(scan_size), bytes) || bytes.size() < 16)
            continue;
        for (std::size_t i = 0; i + 16 < bytes.size(); i += 2) {
            const char* type = nullptr;
            if (utf16_at(bytes, i, L"\\Device\\"))
                type = "device";
            else if (utf16_at(bytes, i, L"\\DosDevices\\") || utf16_at(bytes, i, L"\\??\\"))
                type = "symlink";
            if (!type)
                continue;
            std::string name = read_utf16_ascii(bytes, i, 260);
            if (name.size() < 4)
                continue;
            found.push_back(json{{"call_va", "unknown"}, {"string_va", sa_format_address(mod.base + i)}, {"type", type}, {"name", name}, {"module", mod.name}});
            if (found.size() >= 256)
                break;
        }
        if (found.size() >= 256)
            break;
    }
    json out;
    out["names"] = found;
    out["count"] = found.size();
    out["confidence"] = found.empty() ? 0.0 : 0.75;
    return tool_result_t::ok("Driver device-name scan completed", out);
}

inline tool_result_t drv_check_buffer_safety(const json& params)
{
    if (!params.contains("ioctl_handlers") || !params["ioctl_handlers"].is_array())
        return tool_result_t::error("ioctl_handlers array is required");
    json issues = json::array();
    for (const auto& h : params["ioctl_handlers"]) {
        auto code = parse_u64_json(h.value("ioctl_code", json()));
        auto handler = parse_u64_json(h.value("handler_va", json()));
        if (!code || !handler)
            continue;
        json dec = decode_ioctl_code(*code);
        const std::string method = dec.value("method", std::string());
        auto insns = disassemble_target(0, *handler, 4096, 512);
        bool saw_probe = false;
        bool saw_length_cmp = false;
        bool saw_pool = false;
        for (const auto& ins : insns) {
            const std::string text = lower_ascii(std::string(ins.mnem) + " " + ins.ops);
            if (text.find("probe") != std::string::npos)
                saw_probe = true;
            if (mnemonic_of(ins) == "cmp" && (text.find("input") != std::string::npos || text.find("output") != std::string::npos || ins.has_imm))
                saw_length_cmp = true;
            if (text.find("exallocatepool") != std::string::npos || text.find("pool") != std::string::npos)
                saw_pool = true;
        }
        if (method == "NEITHER" && !saw_probe)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "method_neither_without_obvious_probe"}, {"va", sa_format_address(*handler)}, {"description", "METHOD_NEITHER exposes raw user pointers and no ProbeForRead/ProbeForWrite evidence was found in the bounded handler scan."}, {"severity", "critical"}, {"confidence", 0.72}});
        if (!saw_length_cmp)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "missing_obvious_length_validation"}, {"va", sa_format_address(*handler)}, {"description", "No obvious length comparison was found before buffer use in the bounded handler scan."}, {"severity", method == "NEITHER" ? "high" : "medium"}, {"confidence", 0.55}});
        if (saw_pool && !saw_length_cmp)
            issues.push_back(json{{"ioctl_code", sa_format_address(*code)}, {"handler_va", sa_format_address(*handler)}, {"issue_type", "allocation_without_obvious_size_guard"}, {"va", sa_format_address(*handler)}, {"description", "Pool allocation evidence exists but no bounded size guard was recognized."}, {"severity", "high"}, {"confidence", 0.5}});
    }
    return tool_result_t::ok(json(issues));
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
                {"count", 0},
                {"reason", reason},
                {"security_contract", "fail_closed_no_kernel_dispatch_mutation"}};
}

inline tool_result_t drv_hook_manage(const json& params)
{
    const std::string action = lower_ascii(compat_action_name(params));
    const json p = compat_action_payload(params);
    if (action == "list" || action == "status" || action.empty()) {
        std::lock_guard<std::mutex> lk(drv_hook_mutex());
        drv_hook_states().clear();
        json out = drv_hook_fail_closed_contract("raw_dispatch_patching_disabled_no_safe_kernel_backend");
        out["hooks"] = json::array();
        return tool_result_t::ok(out);
    }
    if (action == "remove" || action == "stop") {
        const std::string id = p.value("hook_id", std::string());
        if (id.empty()) {
            json out = drv_hook_fail_closed_contract("hook_id_required_no_kernel_mutation_performed");
            out["stopped"] = false;
            out["mutation"] = "none";
            return tool_result_t::error("hook_id is required for " + action, out);
        }
        std::lock_guard<std::mutex> lk(drv_hook_mutex());
        const auto erased = drv_hook_states().erase(id);
        json out = drv_hook_fail_closed_contract(erased ? "state_only_record_removed_no_kernel_mutation" : "hook_id_not_found_no_kernel_mutation_performed");
        out["hook_id"] = id;
        out["removed"] = erased != 0;
        out["stopped"] = erased != 0;
        out["mutation"] = erased ? "state_only_no_kernel_patch" : "none";
        out["hooks"] = json::array();
        return erased ? tool_result_t::ok(out) : tool_result_t::error("hook_id not found", out);
    }
    if (action == "install" || action == "start") {
        json out = drv_hook_fail_closed_contract("unsupported_without_existing_safe_kernel_backend");
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
        return tool_result_t::error("drv_send_ioctl can change device or kernel state. Re-run with confirm_unsafe=true or allow_unsafe=true.");
    const std::string symlink = params.value("device_symlink", std::string());
    auto code = parse_param_u64(params, "ioctl_code");
    if (symlink.empty() || !code)
        return tool_result_t::error("device_symlink and ioctl_code are required");
    std::vector<std::uint8_t> in;
    if (params.contains("input_buffer_hex") && params["input_buffer_hex"].is_string()) {
        std::string hex_error;
        if (!hex_to_bytes_strict(params["input_buffer_hex"].get<std::string>(), in, hex_error))
            return tool_result_t::error(hex_error, json{{"input_buffer_hex_valid", false}});
    }
    if (in.size() > 1024u * 1024u)
        return tool_result_t::error("input_buffer_hex is too large; max 1MB");
    std::uint32_t out_size = static_cast<std::uint32_t>(parse_param_u64(params, "output_buffer_size").value_or(4096));
    out_size = std::clamp<std::uint32_t>(out_size, 0, 1024u * 1024u);
    std::vector<std::uint8_t> out_buf(out_size);
    HANDLE h = CreateFileW(utf8_to_wide(symlink).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD gle = GetLastError();
        return tool_result_t::error("CreateFileW failed for device symlink", json{{"device_symlink", symlink}, {"gle", gle}});
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
    return ok ? tool_result_t::ok("DeviceIoControl completed", out) : tool_result_t::error("DeviceIoControl failed", out);
}

struct smc_session_t {
    std::string id;
    std::uint32_t pid = 0;
    std::uint32_t page_guard_id = 0;
    std::uint64_t watch_va = 0;
    std::uint64_t watch_size = 0;
    bool capture_on_write = true;
    bool capture_on_execute = true;
};

inline std::mutex& smc_mutex()
{
    static std::mutex m;
    return m;
}

inline std::map<std::string, smc_session_t>& smc_sessions()
{
    static std::map<std::string, smc_session_t> s;
    return s;
}

inline std::string next_prefixed_id(const char* prefix)
{
    static std::atomic<std::uint64_t> next{1};
    char buf[64] = {};
    std::snprintf(buf, sizeof(buf), "%s-%06llu", prefix, static_cast<unsigned long long>(next.fetch_add(1)));
    return std::string(buf);
}

inline std::string pg_access_name(std::uint32_t access)
{
    if (access == 0)
        return "execute";
    if (access == 1)
        return "write";
    if (access == 8)
        return "execute";
    return "access_" + std::to_string(access);
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

inline tool_result_t smc_manage(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::string action = compat_action_name(params);
    const json p = compat_action_payload(params);
    if (action == "start") {
        if (!unsafe_confirmed(params) && !unsafe_confirmed(p))
            return tool_result_t::error("smc_manage start installs a target PAGE_GUARD/VEH capture session. Re-run with confirm_unsafe=true or allow_unsafe=true.");
        auto va = parse_param_u64(p, "watch_va");
        auto size = parse_param_u64(p, "watch_size");
        if (!va || !size || *size == 0)
            return tool_result_t::error("watch_va and watch_size are required for start");
        const std::uint32_t pid = requested_pid(p);
        if (pid == 0)
            return tool_result_t::error("An attached process or process_id is required");
        const std::uint64_t bounded_size = std::min<std::uint64_t>(*size, 1024ull * 1024ull);
        const bool capture_payloads = p.value("capture_on_write", true) || p.value("capture_on_execute", true);
        const std::uint32_t sid = page_guard_engine::g_pg_engine.install(pid, *va, bounded_size, capture_payloads, 128);
        if (sid == 0)
            return tool_result_t::error("PAGE_GUARD capture backend failed to start");
        smc_session_t s;
        s.id = next_prefixed_id("smc");
        s.pid = pid;
        s.page_guard_id = sid;
        s.watch_va = *va;
        s.watch_size = bounded_size;
        s.capture_on_write = p.value("capture_on_write", true);
        s.capture_on_execute = p.value("capture_on_execute", true);
        {
            std::lock_guard<std::mutex> lk(smc_mutex());
            smc_sessions()[s.id] = s;
        }
        return tool_result_t::ok(json{{"session_id", s.id}, {"page_guard_session_id", sid}, {"watch_va", sa_format_address(*va)}, {"watch_size", bounded_size}, {"pid", pid}});
    }
    if (action == "captures") {
        const std::string id = p.value("session_id", std::string());
        smc_session_t s;
        {
            std::lock_guard<std::mutex> lk(smc_mutex());
            auto it = smc_sessions().find(id);
            if (it == smc_sessions().end())
                return tool_result_t::error("session_id not found");
            s = it->second;
        }
        auto records = page_guard_engine::g_pg_engine.get_capture_records(s.page_guard_id);
        json arr = json::array();
        for (const auto& r : records) {
            const std::string event = pg_access_name(r.metadata.access_type);
            if (event == "write" && !s.capture_on_write)
                continue;
            if (event == "execute" && !s.capture_on_execute)
                continue;
            std::vector<std::uint8_t> bytes = r.payload;
            if (bytes.empty())
                read_target_memory(s.pid, s.watch_va, static_cast<std::size_t>(std::min<std::uint64_t>(s.watch_size, 128)), bytes);
            arr.push_back(json{{"event_type", event}, {"trigger_va", sa_format_address(r.metadata.fault_addr)}, {"decryptor_va", sa_format_address(r.metadata.rip)}, {"decryptor_callstack", json::array()}, {"captured_bytes_hex", bytes_to_hex(bytes, 256)}, {"payload_source", r.payload_source}, {"payload_va", r.payload_addr ? sa_format_address(r.payload_addr) : "unknown"}, {"disasm_preview", disasm_preview_for_bytes(r.payload_addr ? r.payload_addr : s.watch_va, bytes, 16)}});
        }
        return tool_result_t::ok(json{{"session_id", id}, {"captures", arr}, {"count", arr.size()}});
    }
    if (action == "stop") {
        const std::string id = p.value("session_id", std::string());
        smc_session_t s;
        {
            std::lock_guard<std::mutex> lk(smc_mutex());
            auto it = smc_sessions().find(id);
            if (it == smc_sessions().end())
                return tool_result_t::error("session_id not found");
            s = it->second;
            smc_sessions().erase(it);
        }
        const bool ok = page_guard_engine::g_pg_engine.uninstall(s.page_guard_id);
        return ok ? tool_result_t::ok(json{{"session_id", id}, {"stopped", true}}) : tool_result_t::error("PAGE_GUARD session uninstall failed", json{{"session_id", id}, {"page_guard_session_id", s.page_guard_id}});
    }
    return compat_unknown_action("smc_manage", action);
}

inline tool_result_t smc_scan_encrypted_regions(const json& params)
{
    auto chk = require_driver();
    if (!chk.success)
        return chk;
    const std::uint32_t pid = requested_pid(params);
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
    for (const auto& m : mods) {
        pe_layout_t pe;
        if (!read_pe_layout(pid, m.base, pe))
            continue;
        for (auto sec : pe.sections) {
            const std::uint32_t size = sec.virtual_size ? sec.virtual_size : sec.raw_size;
            if (size == 0)
                continue;
            const std::uint32_t read_size = std::min<std::uint32_t>(size, 1024u * 1024u);
            std::vector<std::uint8_t> bytes;
            if (!read_target_memory(pid, sec.va, read_size, bytes) || bytes.empty())
                continue;
            sec.entropy = entropy_of(bytes);
            bool decrypt_candidate = sec.entropy > 7.0 && executable_characteristics(sec.characteristics);
            if (!decrypt_candidate && sec.entropy < 1.0 && executable_characteristics(sec.characteristics))
                decrypt_candidate = true;
            if (decrypt_candidate || params.value("include_all", false)) {
                regions.push_back(json{{"va", sa_format_address(sec.va)}, {"size", size}, {"entropy", sec.entropy}, {"section", sec.name}, {"module", m.name}, {"classification", sec.entropy > 7.0 ? "high_entropy_executable" : "low_entropy_or_mutated_executable"}, {"decrypt_candidate", decrypt_candidate}});
            }
        }
    }
    return tool_result_t::ok(json{{"regions", regions}, {"count", regions.size()}});
}

inline tool_result_t smc_detect_selfmod(const json& params)
{
    return smc_scan_encrypted_regions(params);
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
        pages.push_back(json{{"page_va", sa_format_address(*base + off)}, {"size", n}, {"entropy", entropy_of(page)}, {"protect", region_ok ? protection_name(region.protect) : "unknown"}, {"executable", region_ok ? executable_protect(region.protect) : false}, {"bytes_hex", bytes_to_hex(page, 128)}, {"disasm_preview", disasm_preview_for_bytes(*base + off, page, 8)}});
    }
    return tool_result_t::ok("SMC page snapshot completed", json{{"target_va", sa_format_address(*base)}, {"target_size_requested", *size}, {"target_size_snapshotted", bytes.size()}, {"bounded", *size > bounded_size}, {"pid", pid}, {"pages", pages}, {"page_count", pages.size()}});
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
    json candidates = json::array();
    json scan_ranges = json::array();
    json decision_samples = json::array();
    std::uint64_t scanned = 0;
    bool cancelled = false;
    auto target_contains = [&](std::uint64_t value) {
        return value >= *target && value < end;
    };
    auto scan_code_range = [&](std::uint64_t scan_base, std::uint32_t scan_size, const std::string& source) -> bool {
        if (mcp_standalone::current_call_cancelled()) {
            cancelled = true;
            return false;
        }
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
        range_diag["marker_bytes_head"] = bytes_to_hex(raw, 64);
        auto insns = raw_ok && !raw.empty() ? disassemble_linear_bytes(scan_base, raw, 65536) : disassemble_target(pid, scan_base, scan_size, 65536);
        range_diag["instructions_decoded"] = insns.size();
        scan_ranges.push_back(std::move(range_diag));
        scanned += insns.size();
        std::map<std::string, std::uint64_t> reg_values;
        for (std::size_t ii = 0; ii < insns.size(); ++ii) {
            if ((ii & 0x3FF) == 0 && mcp_standalone::current_call_cancelled()) {
                cancelled = true;
                return false;
            }
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
            json decision;
            decision["instruction"] = instruction_to_json(ins);
            decision["memory_write"] = memory_write;
            decision["decoded_memory_ref"] = ref ? json(sa_format_address(ref)) : json(nullptr);
            decision["decoded_memory_source"] = ref_source.empty() ? "none" : ref_source;
            decision["operand_text_ref"] = operand_ref ? json(sa_format_address(operand_ref)) : json(nullptr);
            decision["operand_text_source"] = operand_ref_source.empty() ? "none" : operand_ref_source;
            decision["operand_text_evidence"] = operand_ref_evidence.is_null() ? json::object() : operand_ref_evidence;
            decision["target_range"] = json{{"base", sa_format_address(*target)}, {"end", sa_format_address(end)}, {"size", bounded_target_size}};
            decision["chosen_memory_target"] = chosen_ref ? json(sa_format_address(chosen_ref)) : json(nullptr);
            decision["chosen_source"] = chosen_source.empty() ? "none" : chosen_source;
            decision["matched_target_range"] = match;
            decision["tracked_registers"] = reg_values.size();
            if (decision_samples.size() < 32)
                decision_samples.push_back(decision);
            if (!match)
                continue;
            const std::size_t raw_offset = (ins.addr >= scan_base && ins.addr - scan_base < raw.size()) ? static_cast<std::size_t>(ins.addr - scan_base) : 0;
            const std::string marker_bytes = bytes_window_hex(raw, raw_offset, 16, 24);
            candidates.push_back(json{{"decryptor_va", sa_format_address(ins.addr)},
                                      {"write_instruction_va", sa_format_address(ins.addr)},
                                      {"memory_reference_va", chosen_ref ? sa_format_address(chosen_ref) : sa_format_address(ins.imm_unsigned)},
                                      {"memory_reference_source", chosen_source.empty() ? "unknown" : chosen_source},
                                      {"key_register", ops.size() > 1 ? reg_from_operand(ops.back()) : "unknown"},
                                      {"key_operand", ops.size() > 1 ? ops.back() : std::string()},
                                      {"estimated_algo", estimate_algo_from_mnemonic(mnem)},
                                      {"evidence", instruction_to_json(ins)},
                                      {"decision", decision},
                                      {"source", source},
                                      {"tracked_register_count", reg_values.size()},
                                      {"marker_bytes_hex", marker_bytes},
                                      {"confidence", chosen_source.rfind("operand_text_tracked_register:", 0) == 0 ? 0.78 : (chosen_source.rfind("tracked_register:", 0) == 0 ? 0.74 : 0.58)}});
            if (candidates.size() >= 128)
                break;
        }
        return !cancelled;
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
        json out{{"decryptors", candidates}, {"count", candidates.size()}, {"instructions_scanned", scanned}, {"explicit_scan_mode", true}, {"module_scan_skipped", true}, {"scan_base", sa_format_address(*scan_base)}, {"scan_size_requested", scan_size.value_or(0x10000)}, {"scan_size_effective", reported_effective}, {"target_va", sa_format_address(*target)}, {"target_size_effective", bounded_target_size}, {"scan_ranges", scan_ranges}, {"decision_samples", decision_samples}, {"cancelled", cancelled}, {"elapsed_ms", GetTickCount64() - started}};
        if (candidates.empty())
            out["no_match_reason"] = scanned == 0 ? "no_instructions_decoded" : "no_memory_write_resolved_into_target_range";
        if (cancelled)
            return tool_result_t::error("SMC decryptor explicit scan cancelled", out);
        return tool_result_t::ok(out);
    }
    auto mods = user_modules(pid);
    for (const auto& m : mods) {
        if (mcp_standalone::current_call_cancelled()) {
            cancelled = true;
            break;
        }
        if (candidates.size() >= 128)
            break;
        pe_layout_t pe;
        if (!read_pe_layout(pid, m.base, pe))
            continue;
        for (const auto& sec : pe.sections) {
            if (!executable_characteristics(sec.characteristics))
                continue;
            const std::uint32_t sec_size = std::min<std::uint32_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 0x100000);
            if (!scan_code_range(sec.va, sec_size, m.name + ":" + sec.name))
                break;
            if (candidates.size() >= 128)
                break;
        }
        if (cancelled)
            break;
    }
    json out{{"decryptors", candidates}, {"count", candidates.size()}, {"instructions_scanned", scanned}, {"explicit_scan_mode", false}, {"module_scan_skipped", false}, {"scan_ranges", scan_ranges}, {"decision_samples", decision_samples}, {"cancelled", cancelled}, {"elapsed_ms", GetTickCount64() - started}};
    if (candidates.empty())
        out["no_match_reason"] = scanned == 0 ? "no_instructions_decoded" : "no_memory_write_resolved_into_target_range";
    if (cancelled)
        return tool_result_t::error("SMC decryptor scan cancelled", out);
    return tool_result_t::ok(out);
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
    bool minimal_iat = import_modules.size() <= 3;
    if (hint == "unknown" && (high_entropy_exec > 0 || minimal_iat))
        hint = "custom";
    double confidence = 0.1 + high_entropy_exec * 0.35 + (minimal_iat ? 0.2 : 0.0);
    confidence = std::min(0.95, confidence);
    json out;
    out["likely_packed"] = confidence >= 0.55;
    out["confidence"] = confidence;
    out["entropy_map"] = entropy_map;
    out["packer_hint"] = hint;
    out["module"] = mod->name;
    out["module_base"] = sa_format_address(mod->base);
    out["minimal_iat"] = minimal_iat;
    out["import_module_count"] = import_modules.size();
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

inline json pg_record_evidence(const page_guard_engine::pg_capture_record_t& r)
{
    json ev;
    ev["fault_addr"] = sa_format_address(r.metadata.fault_addr);
    ev["rip"] = sa_format_address(r.metadata.rip);
    ev["ctx_rax"] = sa_format_address(r.metadata.ctx_rax);
    ev["ctx_rcx"] = sa_format_address(r.metadata.ctx_rcx);
    ev["ctx_rdx"] = sa_format_address(r.metadata.ctx_rdx);
    ev["access_type"] = pg_access_name(r.metadata.access_type);
    ev["exception_code"] = sa_format_address(r.metadata.exception_code);
    ev["payload_source"] = r.payload_source;
    ev["payload_addr"] = r.payload_addr ? sa_format_address(r.payload_addr) : "unknown";
    ev["payload_read"] = r.payload_read;
    return ev;
}

inline void run_stack_restore_oep_heuristic(std::uint32_t pid, std::uint32_t tid, const target_module_t& mod, const pe_layout_t& pe, json& candidates, json& evidence)
{
    json ev;
    ev["strategy"] = "esp_trick";
    ev["tid"] = tid;
    ev["module_is_64"] = pe.is_64;
    if (tid != 0) {
        driver_bridge::thread_context_t ctx{};
        if (driver_bridge::get_thread_context(tid, ctx)) {
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
        return tool_result_t::error("pack_find_oep installs temporary PAGE_GUARD or hardware-breakpoint observation. Re-run with confirm_unsafe=true or allow_unsafe=true.");
    const std::uint32_t pid = requested_pid(params);
    if (pid == 0)
        return tool_result_t::error("An attached process or process_id is required");
    std::string err;
    auto mod = select_user_main_module(params, &err);
    if (!mod)
        return tool_result_t::error(err.empty() ? "No target module found" : err);
    const std::string strategy = lower_ascii(params.value("strategy", std::string("all")));
    if (strategy != "all" && strategy != "page_guard" && strategy != "tail_jump" && strategy != "esp_trick")
        return tool_result_t::error("strategy must be one of all, page_guard, tail_jump, or esp_trick");
    std::uint32_t timeout_ms = static_cast<std::uint32_t>(parse_param_u64(params, "timeout_ms").value_or(30000));
    timeout_ms = std::clamp<std::uint32_t>(timeout_ms, 100, 120000);
    std::uint32_t tid = 0;
    if (auto t = parse_param_u64(params, "tid"))
        tid = static_cast<std::uint32_t>(*t);
    if (tid == 0) {
        auto threads = driver_bridge::enumerate_threads_for(pid);
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
        evidence.push_back(ev);
        const ULONGLONG deadline = GetTickCount64() + timeout_ms;
        for (const auto& sec : sections) {
            const std::uint64_t watch_size = std::min<std::uint64_t>(sec.virtual_size ? sec.virtual_size : sec.raw_size, 1024ull * 1024ull);
            if (watch_size == 0)
                continue;
            const std::uint32_t sid = page_guard_engine::g_pg_engine.install(pid, sec.va, watch_size, true, 256);
            json sec_ev;
            sec_ev["strategy"] = "page_guard";
            sec_ev["section"] = sec.name;
            sec_ev["section_va"] = sa_format_address(sec.va);
            sec_ev["section_size"] = watch_size;
            sec_ev["session_id"] = sid;
            if (sid == 0) {
                sec_ev["result"] = "install_failed";
                evidence.push_back(std::move(sec_ev));
                continue;
            }
            bool saw_write = false;
            json events = json::array();
            while (GetTickCount64() < deadline) {
                auto records = page_guard_engine::g_pg_engine.get_capture_records(sid);
                for (const auto& r : records) {
                    const std::string access = pg_access_name(r.metadata.access_type);
                    if (events.size() < 16)
                        events.push_back(pg_record_evidence(r));
                    if (access == "write")
                        saw_write = true;
                    if (access != "execute")
                        continue;
                    std::vector<std::uint8_t> bytes;
                    read_target_memory(pid, r.metadata.fault_addr, 32, bytes);
                    append_oep_candidate(candidates, json{{"va", sa_format_address(r.metadata.fault_addr)}, {"strategy_used", "page_guard"}, {"confidence", saw_write ? "high" : "medium"}, {"first_instruction_preview", disasm_preview_for_bytes(r.metadata.fault_addr, bytes, 4)}, {"section", sec.name}, {"evidence", json{{"saw_write_before_execute", saw_write}, {"page_guard_session_id", sid}, {"record", pg_record_evidence(r)}, {"section_entropy", sec.entropy}}}});
                    break;
                }
                if (!records.empty() && candidates.size() >= 16)
                    break;
                if (mcp_standalone::current_call_cancelled())
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
            page_guard_engine::g_pg_engine.uninstall(sid);
            sec_ev["events"] = std::move(events);
            sec_ev["saw_write"] = saw_write;
            sec_ev["result"] = "completed";
            evidence.push_back(std::move(sec_ev));
            if (mcp_standalone::current_call_cancelled() || GetTickCount64() >= deadline)
                break;
        }
    }
    if (strategy == "tail_jump" || strategy == "all") {
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
    if (strategy == "esp_trick" || strategy == "all") {
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
    return tool_result_t::ok("IAT recovery completed", json{{"entries", entries}, {"count", entries.size()}, {"module", mod->name}, {"module_base", sa_format_address(mod->base)}, {"pid", pid}, {"capture_backend", "read_only_current_import_table"}, {"live_hit_collection", "not_requested"}});
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
            return tool_result_t::error("pack_iat_manage start writes hardware breakpoint registers in target threads. Re-run with confirm_unsafe=true or allow_unsafe=true.");
        const std::uint32_t pid = requested_pid(p);
        if (pid == 0)
            return tool_result_t::error("An attached process or process_id is required");
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
        auto threads = driver_bridge::enumerate_threads_for(pid);
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
                if (driver_bridge::set_hardware_breakpoint(th.tid, slot, ex.va, 0, 0)) {
                    s.breakpoints.push_back({th.tid, slot});
                    bp["armed"] = true;
                    ++slot;
                } else {
                    ++s.failed_arms;
                    bp["armed"] = false;
                    bp["reason"] = driver_bridge::last_error().empty() ? "set_hardware_breakpoint_failed" : driver_bridge::last_error();
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
                return tool_result_t::error("session_id not found");
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
                return tool_result_t::error("session_id not found");
            s = it->second;
            iat_sessions().erase(it);
        }
        int cleared = 0;
        for (const auto& bp : s.breakpoints) {
            if (driver_bridge::clear_hardware_breakpoint(bp.first, bp.second))
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
