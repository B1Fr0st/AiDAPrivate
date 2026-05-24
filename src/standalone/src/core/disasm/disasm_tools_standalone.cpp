#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "standalone_compat.hpp"
#include "zydis_disasm.hpp"
#include "disasm_view.hpp"
#include "function_index.hpp"
#include "rename_store.hpp"
#include "comment_store.hpp"
#include "xref_db.hpp"
#include "xref_engine.hpp"
#include "pe_parser.hpp"
#include "hex_view.hpp"
#include "standalone_driver.hpp"
#include "../helpers/globals.h"
#include "../helpers/diag_log.hpp"

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using tool_result_t = mcp_standalone::tool_result_t;

extern DisasmState g_disasm;

namespace disasm_tools {

static std::string hex_u64(uint64_t value)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

static bool parse_address_param(const json& params, const char* key, uint64_t& out)
{
    if (!params.contains(key))
        return false;
    const auto& v = params[key];
    if (v.is_string()) {
        auto parsed = sa_parse_address(v.get<std::string>());
        if (!parsed) return false;
        out = *parsed;
        return true;
    }
    if (v.is_number_unsigned()) {
        out = v.get<uint64_t>();
        return true;
    }
    if (v.is_number_integer()) {
        int64_t s = v.get<int64_t>();
        if (s < 0) return false;
        out = static_cast<uint64_t>(s);
        return true;
    }
    return false;
}

static std::string lower_copy(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static bool loaded_static_file_available()
{
    return g_disasm.file.loaded && !g_disasm.file.sections.empty() && g_disasm.file.image_base != 0;
}

static int find_instr_index(const DisasmFile& file, uint64_t addr)
{
    int lo = 0;
    int hi = static_cast<int>(file.instrs.size()) - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        uint64_t a = file.instrs[static_cast<size_t>(mid)].addr;
        if (a == addr) return mid;
        if (a < addr) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}

static std::string bytes_to_hex(const uint8_t* data, int len)
{
    if (len <= 0) return std::string();
    std::string out;
    out.reserve(static_cast<size_t>(len) * 3);
    char buf[4];
    for (int i = 0; i < len; ++i) {
        std::snprintf(buf, sizeof(buf), "%02X", static_cast<unsigned>(data[i]));
        if (i > 0) out.push_back(' ');
        out.append(buf, 2);
    }
    return out;
}

static const char* xref_type_label(int t)
{
    switch (t) {
    case static_cast<int>(xref_engine::xref_type_t::call):             return "call";
    case static_cast<int>(xref_engine::xref_type_t::jump):             return "jump";
    case static_cast<int>(xref_engine::xref_type_t::conditional_jump): return "conditional_jump";
    case static_cast<int>(xref_engine::xref_type_t::lea):              return "lea";
    case static_cast<int>(xref_engine::xref_type_t::data_ref):         return "data_ref";
    default: return "unknown";
    }
}

struct resolved_function_t
{
    uint64_t start = 0;
    uint64_t end = 0;
    std::string name;
    std::string section;
    std::string module;
    std::string source;
};

static bool read_routed_process_bytes(uint64_t address, size_t size, std::vector<uint8_t>& out)
{
    out.clear();
    if (size == 0)
        return false;
    if (function_index::detail::read_routed_bytes(address, size, out) && !out.empty())
        return true;
    return driver_bridge::read_memory(address, size, out) && !out.empty();
}

static bool decode_instruction_at(uint64_t address, AsmInstr& out)
{
    std::vector<uint8_t> bytes;
    if (!read_routed_process_bytes(address, 16, bytes))
        return false;
    const int avail = static_cast<int>(std::min<size_t>(bytes.size(), 16));
    if (avail <= 0)
        return false;
    out = zydis_decode_one(bytes.data(), avail, address);
    return true;
}

static bool activate_live_disassembly_for_address(uint64_t address)
{
    const uint32_t attached = driver_bridge::attached_pid();
    if (attached == 0)
        return false;

    if (g_disasm.live_mode &&
        g_disasm.live_pid == attached &&
        g_disasm.live_base != 0 &&
        address >= g_disasm.live_base &&
        address < g_disasm.live_base + g_disasm.live_size) {
        g_disasm.live_view_addr = address;
        g_disasm.live_floor_va = address;
        g_disasm.live_needs_refresh = true;
        disasm::request_live_decode(g_disasm);
        return true;
    }

    for (const auto& mod : driver_bridge::enumerate_modules()) {
        if (mod.base == 0 || mod.size == 0)
            continue;
        const uint64_t end = mod.base + static_cast<uint64_t>(mod.size);
        if (address < mod.base || address >= end)
            continue;
        if (!disasm::start_live(g_disasm, attached, mod.base, mod.size, mod.name))
            return false;
        g_disasm.live_view_addr = address;
        g_disasm.live_floor_va = address;
        g_disasm.live_needs_refresh = true;
        disasm::request_live_decode(g_disasm);
        return true;
    }

    return false;
}

static bool section_for_address(const pe_parser::pe_info_t& pe,
                                uint64_t module_base,
                                uint64_t address,
                                std::string& out_section,
                                uint64_t& out_section_end)
{
    if (address < module_base)
        return false;
    const uint64_t rva = address - module_base;
    for (const auto& sec : pe.sections) {
        uint64_t sec_size = std::max<uint32_t>(sec.virtual_size, sec.raw_size);
        if (sec_size == 0)
            continue;
        const uint64_t sec_start = sec.virtual_address;
        const uint64_t sec_end = sec_start + sec_size;
        if (rva >= sec_start && rva < sec_end) {
            out_section = sec.name;
            out_section_end = module_base + sec_end;
            return true;
        }
    }
    return false;
}

static std::string export_name_for_address(const pe_parser::pe_info_t& pe, uint64_t address)
{
    for (const auto& exp : pe.exports) {
        if (!exp.is_forwarded && exp.address == address && !exp.name.empty())
            return exp.name;
    }
    return {};
}

static bool decode_function_end(uint64_t start, uint64_t max_end, uint64_t& out_end)
{
    if (max_end <= start)
        return false;
    const uint64_t bounded = std::min<uint64_t>(max_end - start, 4096);
    std::vector<uint8_t> bytes;
    if (!read_routed_process_bytes(start, static_cast<size_t>(bounded), bytes))
        return false;

    size_t off = 0;
    int decoded = 0;
    uint64_t last_end = start;
    while (off < bytes.size() && decoded < 512) {
        const int avail = static_cast<int>(std::min<size_t>(bytes.size() - off, 16));
        if (avail <= 0)
            break;
        AsmInstr ins = zydis_decode_one(bytes.data() + off, avail, start + off);
        const int ins_len = std::max(1, ins.len);
        if (off + static_cast<size_t>(ins_len) > bytes.size())
            break;
        last_end = start + off + static_cast<uint64_t>(ins_len);
        ++decoded;
        if (ins.is_ret || std::strcmp(ins.mnem, "jmp") == 0 || std::strcmp(ins.mnem, "int3") == 0) {
            out_end = last_end;
            return true;
        }
        off += static_cast<size_t>(ins_len);
    }

    if (decoded == 0)
        return false;
    out_end = last_end;
    return true;
}

static bool resolve_cached_function(uint64_t addr, resolved_function_t& out)
{
    auto& c = function_index::detail::cache();
    uint64_t start = 0;
    {
        std::shared_lock<std::shared_mutex> lk(c.mutex);
        auto m = c.addr_to_func_start.find(addr);
        if (m != c.addr_to_func_start.end()) {
            start = m->second;
        } else {
            auto& sorted = c.sorted_starts;
            auto it = std::upper_bound(sorted.begin(), sorted.end(), addr);
            if (it == sorted.begin())
                return false;
            --it;
            start = *it;
        }

        auto r = c.by_start.find(start);
        if (r == c.by_start.end())
            return false;
        if (addr < r->second.start || (r->second.end > 0 && addr >= r->second.end))
            return false;
        out.start = r->second.start;
        out.end = r->second.end;
        out.name = r->second.display_name.empty() ? function_index::synthetic_name(start) : r->second.display_name;
        out.section = r->second.section;
        out.module = c.cached_module_name;
        out.source = "function_index";
        return out.end > out.start;
    }
}

static bool resolve_live_function(uint64_t addr, resolved_function_t& out)
{
    uint64_t module_base = 0;
    uint32_t module_size = 0;
    std::string module_name;
    if (!function_index::detail::resolve_module_for_address(addr, module_base, module_size, module_name))
        return false;
    if (module_base == 0 || module_size == 0 || addr < module_base || addr >= module_base + module_size)
        return false;

    pe_parser::pe_info_t pe;
    if (!pe_parser::parse(module_base, pe, false))
        return false;

    std::string section;
    uint64_t section_end = module_base + module_size;
    section_for_address(pe, module_base, addr, section, section_end);

    std::vector<uint64_t> rf_starts;
    std::vector<uint32_t> rf_sizes;
    if (functions_panel::detail::read_runtime_function_table(module_base, pe, rf_starts, rf_sizes)) {
        for (size_t i = 0; i < rf_starts.size() && i < rf_sizes.size(); ++i) {
            const uint64_t start = rf_starts[i];
            const uint64_t end = start + rf_sizes[i];
            if (rf_sizes[i] == 0 || addr < start || addr >= end)
                continue;
            out.start = start;
            out.end = std::min<uint64_t>(end, module_base + module_size);
            out.name = function_index::synthetic_name(start);
            out.section = section.empty() ? function_index::detail::section_name_for_va(pe, module_base, start) : section;
            out.module = module_name;
            out.source = "live_pdata";
            return out.end > out.start;
        }
    }

    pe_parser::parse_exports(module_base, pe, pe.exports, 4096);
    std::string export_name = export_name_for_address(pe, addr);
    if (export_name.empty())
        return false;

    uint64_t decoded_end = 0;
    if (!decode_function_end(addr, section_end, decoded_end))
        return false;
    out.start = addr;
    out.end = decoded_end;
    out.name = export_name;
    out.section = section;
    out.module = module_name;
    out.source = "live_export_decode";
    return out.end > out.start;
}

static bool resolve_function_for_address(uint64_t addr, resolved_function_t& out)
{
    if (resolve_cached_function(addr, out))
        return true;
    return resolve_live_function(addr, out);
}

static json instruction_to_json(const AsmInstr& ins)
{
    json entry;
    entry["address"]  = hex_u64(ins.addr);
    entry["mnemonic"] = std::string(ins.mnem);
    entry["operands"] = std::string(ins.ops);
    entry["length"]   = ins.len;
    entry["bytes"]    = bytes_to_hex(ins.raw, std::min(ins.len, 15));
    entry["is_branch"] = ins.is_branch;
    entry["is_call"]   = ins.is_call;
    entry["is_ret"]    = ins.is_ret;
    std::string c = comment_store::get(ins.addr);
    if (!c.empty()) entry["comment"] = c;
    return entry;
}

static tool_result_t handle_jump_to_address(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "jump_to_address_bad_params");
        return tool_result_t::error("'address' is required (hex string or integer).");
    }
    diag::log_tagged_fmt("disasm_tools", "jump_to_address addr=0x%llX",
        static_cast<unsigned long long>(addr));

    int idx = find_instr_index(g_disasm.file, addr);
    if (idx < 0) {
        AsmInstr live{};
        if (!decode_instruction_at(addr, live)) {
            diag::log_tagged_fmt("disasm_tools", "jump_to_address_not_found addr=0x%llX instrs=%zu live_decode=0",
                static_cast<unsigned long long>(addr), g_disasm.file.instrs.size());
            return tool_result_t::error("Address not found in current disassembly listing and live memory decode failed.");
        }

        const bool live_active = activate_live_disassembly_for_address(addr);
        diag::log_tagged_fmt("disasm_tools", "jump_to_address_live addr=0x%llX live_active=%d mnemonic=%s len=%d",
            static_cast<unsigned long long>(addr),
            live_active ? 1 : 0,
            live.mnem,
            live.len);

        globals::ui::active_center_view = center_view_t::disassembly;
        json result;
        result["address"] = hex_u64(addr);
        result["row_index"] = -1;
        result["active_center_view"] = "disassembly";
        result["source"] = live_active ? "live_disassembly" : "live_memory_decode";
        result["instruction"] = instruction_to_json(live);
        return tool_result_t::ok(result);
    }
    diag::log_tagged_fmt("disasm_tools", "jump_to_address_resolved addr=0x%llX row=%d",
        static_cast<unsigned long long>(addr), idx);

    globals::ui::active_center_view = center_view_t::disassembly;
    disasm_view::goto_address(addr, g_disasm);

    json result;
    result["address"] = hex_u64(addr);
    result["row_index"] = idx;
    result["active_center_view"] = "disassembly";
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_instruction(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "get_instruction_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    diag::log_tagged_fmt("disasm_tools", "get_instruction addr=0x%llX",
        static_cast<unsigned long long>(addr));

    int idx = find_instr_index(g_disasm.file, addr);
    if (idx < 0) {
        AsmInstr live{};
        if (!decode_instruction_at(addr, live)) {
            diag::log_tagged_fmt("disasm_tools", "get_instruction_not_found addr=0x%llX",
                static_cast<unsigned long long>(addr));
            return tool_result_t::error("Address not found in disassembly listing and live memory decode failed.");
        }
        json result = instruction_to_json(live);
        result["source"] = "live_memory";
        return tool_result_t::ok(result);
    }

    const AsmInstr& ins = g_disasm.file.instrs[static_cast<size_t>(idx)];
    diag::log_tagged_fmt("disasm_tools", "get_instruction_result addr=0x%llX mnem=%s len=%d is_call=%d is_ret=%d",
        static_cast<unsigned long long>(ins.addr), ins.mnem, ins.len,
        ins.is_call ? 1 : 0, ins.is_ret ? 1 : 0);

    json result = instruction_to_json(ins);
    result["is_branch"]= ins.is_branch;
    result["is_call"]  = ins.is_call;
    result["is_ret"]   = ins.is_ret;
    result["source"] = "disassembly_listing";
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_function_bounds(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "get_function_bounds_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    diag::log_tagged_fmt("disasm_tools", "get_function_bounds addr=0x%llX",
        static_cast<unsigned long long>(addr));

    resolved_function_t fn;
    if (!resolve_function_for_address(addr, fn))
        return tool_result_t::error("No function found containing this address.");

    diag::log_tagged_fmt("disasm_tools", "get_function_bounds_result addr=0x%llX start=0x%llX end=0x%llX name=%s",
        static_cast<unsigned long long>(addr), static_cast<unsigned long long>(fn.start),
        static_cast<unsigned long long>(fn.end), fn.name.c_str());
    json result;
    result["start"]   = hex_u64(fn.start);
    result["end"]     = hex_u64(fn.end);
    result["size"]    = (fn.end > fn.start) ? (fn.end - fn.start) : 0;
    result["name"]    = fn.name;
    result["section"] = fn.section;
    result["module"]  = fn.module;
    result["source"]  = fn.source;
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_function_disassembly(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "get_function_disasm_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    diag::log_tagged_fmt("disasm_tools", "get_function_disasm addr=0x%llX",
        static_cast<unsigned long long>(addr));

    int max_instrs = 256;
    if (params.contains("max_instrs") && params["max_instrs"].is_number_integer()) {
        int v = params["max_instrs"].get<int>();
        if (v > 0 && v <= 8192) max_instrs = v;
    }

    resolved_function_t fn;
    if (!resolve_function_for_address(addr, fn))
        return tool_result_t::error("No function found containing this address.");
    if (fn.end == 0 || fn.end <= fn.start)
        return tool_result_t::error("Resolved function has no valid end address.");

    int first = find_instr_index(g_disasm.file, fn.start);

    json arr = json::array();
    int emitted = 0;
    if (first >= 0) {
        for (size_t i = static_cast<size_t>(first); i < g_disasm.file.instrs.size() && emitted < max_instrs; ++i) {
            const AsmInstr& ins = g_disasm.file.instrs[i];
            if (ins.addr >= fn.end) break;
            arr.push_back(instruction_to_json(ins));
            ++emitted;
        }
    } else {
        const uint64_t span = std::min<uint64_t>(fn.end - fn.start, static_cast<uint64_t>(max_instrs) * 16ULL);
        std::vector<uint8_t> bytes;
        if (!read_routed_process_bytes(fn.start, static_cast<size_t>(span), bytes))
            return tool_result_t::error("Function bytes could not be read from live memory.");
        size_t off = 0;
        while (off < bytes.size() && emitted < max_instrs) {
            const uint64_t va = fn.start + off;
            if (va >= fn.end)
                break;
            const int avail = static_cast<int>(std::min<size_t>(bytes.size() - off, 16));
            AsmInstr ins = zydis_decode_one(bytes.data() + off, avail, va);
            const int ins_len = std::max(1, ins.len);
            if (off + static_cast<size_t>(ins_len) > bytes.size())
                break;
            arr.push_back(instruction_to_json(ins));
            ++emitted;
            off += static_cast<size_t>(ins_len);
        }
    }

    diag::log_tagged_fmt("disasm_tools", "get_function_disasm_result start=0x%llX end=0x%llX instr_count=%d truncated=%d",
        static_cast<unsigned long long>(fn.start), static_cast<unsigned long long>(fn.end),
        emitted, (emitted >= max_instrs) ? 1 : 0);
    json result;
    result["function_start"] = hex_u64(fn.start);
    result["function_end"]   = hex_u64(fn.end);
    result["function_name"]  = fn.name.empty() ? function_index::synthetic_name(fn.start) : fn.name;
    result["module"] = fn.module;
    result["section"] = fn.section;
    result["source"] = fn.source;
    result["instruction_count"] = emitted;
    result["truncated"] = (emitted >= max_instrs);
    result["instructions"] = std::move(arr);
    return tool_result_t::ok(result);
}

static tool_result_t handle_list_functions(const json& params)
{
    if (!loaded_static_file_available()) {
        diag::log_tagged_fmt("disasm_tools", "list_functions refused no_static_file instrs=%zu sections=%zu image_base=0x%llX",
            g_disasm.file.instrs.size(),
            g_disasm.file.sections.size(),
            static_cast<unsigned long long>(g_disasm.file.image_base));
        return tool_result_t::error("No disassembly file is loaded. Open a file session before listing static functions.");
    }

    std::string filter;
    if (params.contains("filter") && params["filter"].is_string())
        filter = lower_copy(params["filter"].get<std::string>());
    diag::log_tagged_fmt("disasm_tools", "list_functions filter=%s instrs=%zu sections=%zu image_base=0x%llX",
        filter.c_str(),
        g_disasm.file.instrs.size(),
        g_disasm.file.sections.size(),
        static_cast<unsigned long long>(g_disasm.file.image_base));

    size_t offset = 0;
    if (params.contains("offset") && params["offset"].is_number_unsigned())
        offset = params["offset"].get<size_t>();

    size_t limit = 200;
    if (params.contains("limit") && params["limit"].is_number_unsigned()) {
        size_t v = params["limit"].get<size_t>();
        if (v > 0 && v <= 5000) limit = v;
    }

    auto& c = function_index::detail::cache();
    std::vector<uint64_t> starts;
    std::vector<std::string> names;
    std::vector<uint64_t>    ends;
    std::vector<std::string> kinds;
    std::vector<std::string> sections;
    {
        std::shared_lock<std::shared_mutex> lk(c.mutex);
        diag::log_tagged_fmt("disasm_tools",
            "list_functions cache sorted=%zu by_start=%zu status=%zu module_base=0x%llX module_size=0x%X module='%s' built_seq=%llu",
            c.sorted_starts.size(),
            c.by_start.size(),
            c.status_by_start.size(),
            static_cast<unsigned long long>(c.cached_module_base),
            c.cached_module_size,
            c.cached_module_name.c_str(),
            static_cast<unsigned long long>(c.built_seq.load()));
        starts.reserve(c.sorted_starts.size());
        names.reserve(c.sorted_starts.size());
        ends.reserve(c.sorted_starts.size());
        kinds.reserve(c.sorted_starts.size());
        sections.reserve(c.sorted_starts.size());
        for (uint64_t s : c.sorted_starts) {
            auto r = c.by_start.find(s);
            uint64_t e = 0;
            std::string n;
            std::string kind = "function";
            std::string sec;
            if (r != c.by_start.end()) {
                e = r->second.end;
                n = r->second.display_name;
                if (r->second.is_thunk)        kind = "thunk";
                else if (r->second.is_library) kind = "library";
                else if (r->second.is_entry_stub) kind = "entry";
                sec = r->second.section;
            }
            starts.push_back(s);
            ends.push_back(e);
            names.push_back(n.empty() ? function_index::synthetic_name(s) : n);
            kinds.push_back(std::move(kind));
            sections.push_back(std::move(sec));
        }
    }

    json arr = json::array();
    size_t total_matching = 0;
    size_t skipped = 0;
    size_t emitted = 0;
    for (size_t i = 0; i < starts.size(); ++i) {
        if (!filter.empty()) {
            if (lower_copy(names[i]).find(filter) == std::string::npos)
                continue;
        }
        if (skipped < offset) { ++skipped; ++total_matching; continue; }
        ++total_matching;
        if (emitted >= limit) continue;
        json entry;
        entry["address"] = hex_u64(starts[i]);
        entry["name"]    = names[i];
        entry["size"]    = (ends[i] > starts[i]) ? (ends[i] - starts[i]) : 0;
        entry["kind"]    = kinds[i];
        if (!sections[i].empty()) entry["section"] = sections[i];
        arr.push_back(std::move(entry));
        ++emitted;
    }

    diag::log_tagged_fmt("disasm_tools", "list_functions_result total=%zu returned=%zu skipped=%zu filter=%s",
        total_matching, emitted, skipped, filter.c_str());
    json result;
    result["total"]    = total_matching;
    result["offset"]   = offset;
    result["returned"] = emitted;
    result["functions"] = std::move(arr);
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_xrefs_to(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "get_xrefs_to_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    diag::log_tagged_fmt("disasm_tools", "get_xrefs_to addr=0x%llX",
        static_cast<unsigned long long>(addr));

    json arr = json::array();
    {
        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        for (auto& kv : xref_db::g_state.modules) {
            const auto& mod = kv.second;
            if (!mod.built) continue;
            auto it = mod.to_index.find(addr);
            if (it == mod.to_index.end()) continue;
            for (const auto& e : it->second) {
                json o;
                o["from_address"] = hex_u64(e.from_addr);
                o["to_address"]   = hex_u64(e.to_addr);
                o["type"]         = xref_type_label(static_cast<int>(e.type));
                o["disasm"]       = e.disasm_text;
                o["module"]       = mod.name;
                arr.push_back(std::move(o));
            }
        }
    }

    diag::log_tagged_fmt("disasm_tools", "get_xrefs_to_result addr=0x%llX count=%zu",
        static_cast<unsigned long long>(addr), arr.size());
    json result;
    result["address"] = hex_u64(addr);
    result["count"]   = arr.size();
    result["xrefs"]   = std::move(arr);
    if (result["count"] == 0) {
        result["note"] = "No cached xrefs to this address. The module may not be indexed; open the Xref DB panel and click Index.";
    }
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_xrefs_from(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "get_xrefs_from_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    diag::log_tagged_fmt("disasm_tools", "get_xrefs_from addr=0x%llX",
        static_cast<unsigned long long>(addr));

    json arr = json::array();
    {
        std::lock_guard<std::mutex> lk(xref_db::g_state.mutex);
        for (auto& kv : xref_db::g_state.modules) {
            const auto& mod = kv.second;
            if (!mod.built) continue;
            auto it = mod.from_index.find(addr);
            if (it == mod.from_index.end()) continue;
            for (const auto& e : it->second) {
                json o;
                o["from_address"] = hex_u64(e.from_addr);
                o["to_address"]   = hex_u64(e.to_addr);
                o["type"]         = xref_type_label(static_cast<int>(e.type));
                o["disasm"]       = e.disasm_text;
                o["module"]       = mod.name;
                arr.push_back(std::move(o));
            }
        }
    }

    diag::log_tagged_fmt("disasm_tools", "get_xrefs_from_result addr=0x%llX count=%zu",
        static_cast<unsigned long long>(addr), arr.size());
    json result;
    result["address"] = hex_u64(addr);
    result["count"]   = arr.size();
    result["xrefs"]   = std::move(arr);
    if (result["count"] == 0)
        result["note"] = "No cached xrefs originating at this address. Index the module via the Xref DB panel.";
    return tool_result_t::ok(result);
}

static tool_result_t handle_set_comment(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "set_comment_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    std::string text;
    if (params.contains("comment") && params["comment"].is_string())
        text = params["comment"].get<std::string>();
    else if (params.contains("text") && params["text"].is_string())
        text = params["text"].get<std::string>();
    diag::log_tagged_fmt("disasm_tools", "set_comment addr=0x%llX action=%s text=%s",
        static_cast<unsigned long long>(addr),
        text.empty() ? "delete" : "set", text.c_str());
    comment_store::set(addr, text);
    json result;
    result["address"] = hex_u64(addr);
    result["action"]  = text.empty() ? "deleted" : "set";
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_comment(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "get_comment_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    std::string cmt = comment_store::get(addr);
    diag::log_tagged_fmt("disasm_tools", "get_comment addr=0x%llX has_comment=%d",
        static_cast<unsigned long long>(addr), cmt.empty() ? 0 : 1);
    json result;
    result["address"] = hex_u64(addr);
    result["comment"] = cmt;
    return tool_result_t::ok(result);
}

static tool_result_t handle_rename_function(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "rename_function_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    std::string new_name;
    if (params.contains("new_name") && params["new_name"].is_string())
        new_name = params["new_name"].get<std::string>();
    else if (params.contains("name") && params["name"].is_string())
        new_name = params["name"].get<std::string>();
    diag::log_tagged_fmt("disasm_tools", "rename_function addr=0x%llX new_name=%s action=%s",
        static_cast<unsigned long long>(addr), new_name.c_str(),
        new_name.empty() ? "clear" : "rename");
    rename_store::set(addr, new_name);
    disasm_view::bump_format_generation();
    json result;
    result["address"]  = hex_u64(addr);
    result["new_name"] = new_name;
    result["action"]   = new_name.empty() ? "cleared" : "renamed";
    return tool_result_t::ok(result);
}

static tool_result_t handle_get_section_info(const json&)
{
    if (!loaded_static_file_available())
        return tool_result_t::error("No disassembly file is loaded. Open a file session before requesting section info.");

    diag::log_tagged_fmt("disasm_tools", "get_section_info image_base=0x%llX sections=%zu filename=%s",
        static_cast<unsigned long long>(g_disasm.file.image_base),
        g_disasm.file.sections.size(), g_disasm.file.filename.c_str());
    json arr = json::array();
    for (const PESection& sec : g_disasm.file.sections) {
        json o;
        o["va"]       = hex_u64(sec.va);
        o["size"]     = sec.bytes.size();
        o["end"]      = hex_u64(sec.va + sec.bytes.size());
        arr.push_back(std::move(o));
    }
    json result;
    result["image_base"] = hex_u64(g_disasm.file.image_base);
    result["text_va"]    = hex_u64(g_disasm.file.text_va);
    result["filename"]   = g_disasm.file.filename;
    result["section_count"] = arr.size();
    result["sections"]   = std::move(arr);
    return tool_result_t::ok(result);
}

static bool parse_hex_pattern(const std::string& in, std::vector<uint8_t>& bytes,
                              std::vector<bool>& wildmask)
{
    bytes.clear();
    wildmask.clear();
    std::string cur;
    auto flush = [&](const std::string& tok) -> bool {
        if (tok.empty()) return true;
        if (tok == "??" || tok == "?") {
            bytes.push_back(0);
            wildmask.push_back(true);
            return true;
        }
        if (tok.size() != 2) return false;
        auto hex_nibble = [](char c, int& out) -> bool {
            if (c >= '0' && c <= '9') { out = c - '0'; return true; }
            if (c >= 'a' && c <= 'f') { out = 10 + (c - 'a'); return true; }
            if (c >= 'A' && c <= 'F') { out = 10 + (c - 'A'); return true; }
            return false;
        };
        int hi = 0, lo = 0;
        if (!hex_nibble(tok[0], hi) || !hex_nibble(tok[1], lo))
            return false;
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
        wildmask.push_back(false);
        return true;
    };
    for (char c : in) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',') {
            if (!flush(cur)) return false;
            cur.clear();
            continue;
        }
        cur.push_back(c);
        if (cur.size() == 2) {
            if (!flush(cur)) return false;
            cur.clear();
        }
    }
    if (!cur.empty() && !flush(cur)) return false;
    return !bytes.empty();
}

static tool_result_t handle_search_bytes(const json& params)
{
    if (!loaded_static_file_available())
        return tool_result_t::error("No disassembly file is loaded. Open a file session before searching static bytes.");

    if (!params.contains("pattern") || !params["pattern"].is_string()) {
        diag::log_tagged_fmt("disasm_tools", "search_bytes_bad_params");
        return tool_result_t::error("'pattern' is required (hex string, supports '??' wildcards).");
    }

    std::vector<uint8_t> needle;
    std::vector<bool>    wildmask;
    if (!parse_hex_pattern(params["pattern"].get<std::string>(), needle, wildmask)) {
        diag::log_tagged_fmt("disasm_tools", "search_bytes_invalid_pattern pattern=%s",
            params["pattern"].get<std::string>().c_str());
        return tool_result_t::error("Invalid hex pattern.");
    }
    diag::log_tagged_fmt("disasm_tools", "search_bytes pattern=%s needle_len=%zu",
        params["pattern"].get<std::string>().c_str(), needle.size());

    size_t max_hits = 256;
    if (params.contains("max_hits") && params["max_hits"].is_number_unsigned()) {
        size_t v = params["max_hits"].get<size_t>();
        if (v > 0 && v <= 4096) max_hits = v;
    }

    json arr = json::array();
    size_t total_hits = 0;
    for (const PESection& sec : g_disasm.file.sections) {
        if (sec.bytes.size() < needle.size()) continue;
        const uint8_t* base = sec.bytes.data();
        size_t bsz = sec.bytes.size();
        for (size_t i = 0; i + needle.size() <= bsz; ++i) {
            bool ok = true;
            for (size_t j = 0; j < needle.size(); ++j) {
                if (!wildmask[j] && base[i + j] != needle[j]) { ok = false; break; }
            }
            if (!ok) continue;
            ++total_hits;
            if (arr.size() < max_hits) {
                json o;
                o["address"] = hex_u64(sec.va + i);
                arr.push_back(std::move(o));
            }
        }
    }

    diag::log_tagged_fmt("disasm_tools", "search_bytes_result total_hits=%zu returned=%zu",
        total_hits, arr.size());
    json result;
    result["pattern"]    = params["pattern"].get<std::string>();
    result["total_hits"] = total_hits;
    result["returned"]   = arr.size();
    result["matches"]    = std::move(arr);
    if (total_hits == 0)
        result["note"] = "Searched executable sections only. For .rdata/.data scans attach to a process and use debugger_read_memory ranges.";
    return tool_result_t::ok(result);
}

static bool is_printable_ascii(uint8_t b)
{
    return (b >= 0x20 && b <= 0x7E) || b == '\t';
}

static tool_result_t handle_get_strings(const json& params)
{
    if (!loaded_static_file_available()) {
        diag::log_tagged_fmt("disasm_tools", "get_strings refused no_static_file instrs=%zu sections=%zu image_base=0x%llX",
            g_disasm.file.instrs.size(),
            g_disasm.file.sections.size(),
            static_cast<unsigned long long>(g_disasm.file.image_base));
        return tool_result_t::error("No disassembly file is loaded. Open a file session before extracting static strings.");
    }

    diag::log_tagged_fmt("disasm_tools", "get_strings_enter");
    size_t min_len = 4;
    if (params.contains("min_length") && params["min_length"].is_number_unsigned()) {
        size_t v = params["min_length"].get<size_t>();
        if (v >= 2 && v <= 128) min_len = v;
    }
    std::string encoding = "ascii";
    if (params.contains("encoding") && params["encoding"].is_string())
        encoding = lower_copy(params["encoding"].get<std::string>());

    bool want_ascii = (encoding == "ascii" || encoding == "both");
    bool want_utf16 = (encoding == "utf16" || encoding == "both");
    if (!want_ascii && !want_utf16)
        return tool_result_t::error("encoding must be one of: ascii, utf16, both");

    size_t max_results = 2048;
    if (params.contains("limit") && params["limit"].is_number_unsigned()) {
        size_t v = params["limit"].get<size_t>();
        if (v > 0 && v <= 8192) max_results = v;
    }

    json arr = json::array();
    size_t total_found = 0;
    size_t per_section_limit = 65536;

    for (size_t sec_index = 0; sec_index < g_disasm.file.sections.size(); ++sec_index) {
        const PESection& sec = g_disasm.file.sections[sec_index];
        size_t before_section = total_found;
        const uint8_t* p = sec.bytes.data();
        size_t sz = sec.bytes.size();
        if (sz > per_section_limit * 1024) {
            diag::log_tagged_fmt("disasm_tools", "get_strings section_skipped index=%zu va=0x%llX bytes=%zu reason=too_large",
                sec_index,
                static_cast<unsigned long long>(sec.va),
                sz);
            continue;
        }

        if (want_ascii) {
            size_t run_start = 0;
            size_t run_len = 0;
            for (size_t i = 0; i < sz; ++i) {
                if (is_printable_ascii(p[i])) {
                    if (run_len == 0) run_start = i;
                    ++run_len;
                } else {
                    if (p[i] == 0 && run_len >= min_len) {
                        ++total_found;
                        if (arr.size() < max_results) {
                            json o;
                            o["address"]  = hex_u64(sec.va + run_start);
                            o["encoding"] = "ascii";
                            o["length"]   = run_len;
                            o["text"]     = std::string(
                                reinterpret_cast<const char*>(p + run_start), run_len);
                            arr.push_back(std::move(o));
                        }
                    }
                    run_len = 0;
                }
            }
        }

        if (want_utf16) {
            size_t run_start = 0;
            size_t run_chars = 0;
            for (size_t i = 0; i + 1 < sz; i += 2) {
                uint8_t lo = p[i];
                uint8_t hi = p[i + 1];
                if (hi == 0 && is_printable_ascii(lo)) {
                    if (run_chars == 0) run_start = i;
                    ++run_chars;
                } else {
                    if (hi == 0 && lo == 0 && run_chars >= min_len) {
                        ++total_found;
                        if (arr.size() < max_results) {
                            std::string s;
                            s.reserve(run_chars);
                            for (size_t k = 0; k < run_chars; ++k)
                                s.push_back(static_cast<char>(p[run_start + k * 2]));
                            json o;
                            o["address"]  = hex_u64(sec.va + run_start);
                            o["encoding"] = "utf16";
                            o["length"]   = run_chars;
                            o["text"]     = std::move(s);
                            arr.push_back(std::move(o));
                        }
                    }
                    run_chars = 0;
                }
            }
        }
        diag::log_tagged_fmt("disasm_tools", "get_strings section index=%zu va=0x%llX bytes=%zu found_delta=%zu total=%zu returned=%zu",
            sec_index,
            static_cast<unsigned long long>(sec.va),
            sz,
            total_found - before_section,
            total_found,
            arr.size());
    }

    diag::log_tagged_fmt("disasm_tools", "get_strings_result total=%zu returned=%zu encoding=%s min_len=%zu sections=%zu",
        total_found, arr.size(), encoding.c_str(), min_len, g_disasm.file.sections.size());
    json result;
    result["total_found"] = total_found;
    result["returned"]    = arr.size();
    result["min_length"]  = min_len;
    result["encoding"]    = encoding;
    result["strings"]     = std::move(arr);
    return tool_result_t::ok(result);
}

static tool_result_t handle_ui_set_active_view(const json& params)
{
    if (!params.contains("view") || !params["view"].is_string()) {
        diag::log_tagged_fmt("disasm_tools", "ui_set_active_view_bad_params");
        return tool_result_t::error("'view' is required.");
    }
    std::string name = lower_copy(params["view"].get<std::string>());
    diag::log_tagged_fmt("disasm_tools", "ui_set_active_view view=%s", name.c_str());

    struct entry_t { const char* key; center_view_t v; };
    static const entry_t table[] = {
        {"code_editor",     center_view_t::code_editor},
        {"disassembly",     center_view_t::disassembly},
        {"hex_view",        center_view_t::hex_view},
        {"welcome",         center_view_t::welcome},
        {"settings",        center_view_t::settings_view},
        {"settings_view",   center_view_t::settings_view},
        {"network",         center_view_t::network_view},
        {"network_view",    center_view_t::network_view},
        {"memory_scanner",  center_view_t::memory_scanner},
        {"debugger",        center_view_t::debugger_view},
        {"debugger_view",   center_view_t::debugger_view},
        {"pseudocode",      center_view_t::pseudocode},
        {"struct_recon",    center_view_t::struct_recon},
        {"crypto_scanner",  center_view_t::crypto_scanner},
        {"aob_generator",   center_view_t::aob_generator},
        {"fuzzer",          center_view_t::fuzzer_view},
        {"xref_browser",    center_view_t::xref_browser},
        {"snapshot_diff",   center_view_t::snapshot_diff},
        {"pointer_scanner", center_view_t::pointer_scanner},
        {"decrypt_oracle",  center_view_t::decrypt_oracle},
        {"integrity_hunter",center_view_t::integrity_hunter},
        {"symbolic",        center_view_t::symbolic_view},
        {"taint",           center_view_t::taint_view},
        {"deobfuscation",   center_view_t::deobfuscation_view},
        {"stealth",         center_view_t::stealth_view},
        {"scan_hub",        center_view_t::scan_hub},
        {"types_hub",       center_view_t::types_hub},
        {"analysis_hub",    center_view_t::analysis_hub},
        {"binary_map",      center_view_t::binary_map},
        {"graph",           center_view_t::graph_view},
        {"graph_view",      center_view_t::graph_view},
    };

    for (const entry_t& e : table) {
        if (name == e.key) {
            diag::log_tagged_fmt("disasm_tools", "ui_set_active_view_activated view=%s", e.key);
            globals::ui::active_center_view = e.v;
            json result;
            result["view"]   = e.key;
            result["status"] = "activated";
            return tool_result_t::ok(result);
        }
    }
    diag::log_tagged_fmt("disasm_tools", "ui_set_active_view_unknown view=%s", name.c_str());
    return tool_result_t::error("Unknown view name. Accepted: code_editor, disassembly, hex_view, welcome, settings, network, memory_scanner, debugger, pseudocode, struct_recon, crypto_scanner, aob_generator, fuzzer, xref_browser, snapshot_diff, pointer_scanner, decrypt_oracle, integrity_hunter, symbolic, taint, deobfuscation, stealth, scan_hub, types_hub, analysis_hub, binary_map, graph.");
}

static tool_result_t handle_bookmarks_add(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "bookmark_add_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    std::string label;
    if (params.contains("label") && params["label"].is_string())
        label = params["label"].get<std::string>();
    diag::log_tagged_fmt("disasm_tools", "bookmark_add addr=0x%llX label=%s",
        static_cast<unsigned long long>(addr), label.c_str());

    auto& bms = disasm_view::g_state.bookmarks;
    for (auto& bm : bms) {
        if (bm.addr == addr) {
            if (!label.empty()) bm.label = label;
            diag::log_tagged_fmt("disasm_tools", "bookmark_add_updated addr=0x%llX",
                static_cast<unsigned long long>(addr));
            json result;
            result["address"] = hex_u64(addr);
            result["label"]   = bm.label;
            result["status"]  = "updated";
            return tool_result_t::ok(result);
        }
    }
    disasm_view::bookmark_t b;
    b.addr  = addr;
    b.label = label;
    bms.push_back(std::move(b));
    diag::log_tagged_fmt("disasm_tools", "bookmark_add_created addr=0x%llX total=%zu",
        static_cast<unsigned long long>(addr), bms.size());
    json result;
    result["address"] = hex_u64(addr);
    result["label"]   = label;
    result["status"]  = "added";
    return tool_result_t::ok(result);
}

static tool_result_t handle_bookmarks_remove(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "bookmark_remove_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    diag::log_tagged_fmt("disasm_tools", "bookmark_remove addr=0x%llX",
        static_cast<unsigned long long>(addr));
    auto& bms = disasm_view::g_state.bookmarks;
    for (auto it = bms.begin(); it != bms.end(); ++it) {
        if (it->addr == addr) {
            bms.erase(it);
            diag::log_tagged_fmt("disasm_tools", "bookmark_remove_ok addr=0x%llX remaining=%zu",
                static_cast<unsigned long long>(addr), bms.size());
            json result;
            result["address"] = hex_u64(addr);
            result["status"]  = "removed";
            return tool_result_t::ok(result);
        }
    }
    diag::log_tagged_fmt("disasm_tools", "bookmark_remove_not_found addr=0x%llX",
        static_cast<unsigned long long>(addr));
    return tool_result_t::error("Bookmark not found at this address.");
}

static tool_result_t handle_bookmarks_list(const json&)
{
    diag::log_tagged_fmt("disasm_tools", "bookmark_list count=%zu",
        disasm_view::g_state.bookmarks.size());
    json arr = json::array();
    for (const auto& bm : disasm_view::g_state.bookmarks) {
        json o;
        o["address"] = hex_u64(bm.addr);
        o["label"]   = bm.label;
        arr.push_back(std::move(o));
    }
    json result;
    result["count"]     = arr.size();
    result["bookmarks"] = std::move(arr);
    return tool_result_t::ok(result);
}

static tool_result_t handle_hex_view_open(const json& params)
{
    uint64_t addr = 0;
    if (!parse_address_param(params, "address", addr)) {
        diag::log_tagged_fmt("disasm_tools", "hex_view_open_bad_params");
        return tool_result_t::error("'address' is required.");
    }
    size_t size = 0x1000;
    if (params.contains("size") && params["size"].is_number_unsigned()) {
        size_t v = params["size"].get<size_t>();
        if (v == 0) return tool_result_t::error("'size' must be > 0.");
        if (v > (1u << 20)) v = (1u << 20);
        size = v;
    }
    diag::log_tagged_fmt("disasm_tools", "hex_view_open addr=0x%llX size=%zu",
        static_cast<unsigned long long>(addr), size);
    if (!hex_view::read_from_process(addr, size)) {
        std::string err = hex_view::last_error();
        if (err.empty()) err = "hex_view::read_from_process failed.";
        diag::log_tagged_fmt("disasm_tools", "hex_view_open_failed addr=0x%llX err=%s",
            static_cast<unsigned long long>(addr), err.c_str());
        return tool_result_t::error(err);
    }
    diag::log_tagged_fmt("disasm_tools", "hex_view_open_ok addr=0x%llX size=%zu",
        static_cast<unsigned long long>(addr), size);
    globals::ui::active_center_view = center_view_t::hex_view;
    json result;
    result["address"] = hex_u64(addr);
    result["size"]    = size;
    result["status"]  = "opened";
    return tool_result_t::ok(result);
}

void register_disasm_tools(mcp_standalone::server_t& srv)
{
    srv.register_tool({
        "disasm_jump_to_address",
        "Navigate the central Disassembly view to an address. Switches the active center view to disassembly and scrolls the cursor to the requested address.",
        {{"address", "string", "Target address (hex string or integer)", true}},
        false, handle_jump_to_address});

    srv.register_tool({
        "disasm_get_instruction",
        "Return the decoded instruction at an address: mnemonic, operands, length, raw bytes, comment, and branch/call/ret flags.",
        {{"address", "string", "Instruction address (hex string or integer)", true}},
        true, handle_get_instruction});

    srv.register_tool({
        "disasm_get_function_bounds",
        "Return the bounding function metadata (start, end, size, display name, section) for the function that contains a given address.",
        {{"address", "string", "Any address inside the function (hex string or integer)", true}},
        true, handle_get_function_bounds});

    srv.register_tool({
        "disasm_get_function_disassembly",
        "Return the decoded instruction list of the function containing the address, up to max_instrs (default 256, max 8192).",
        {{"address", "string", "Any address inside the function (hex string or integer)", true},
         {"max_instrs", "number", "Maximum instructions to return (default 256, max 8192)", false}},
        true, handle_get_function_disassembly});

    srv.register_tool({
        "disasm_list_functions",
        "List functions known to the analysis function index. Supports case-insensitive substring filter on the display name and offset/limit paging.",
        {{"filter", "string", "Optional case-insensitive substring filter applied to the function name", false},
         {"offset", "number", "Number of matches to skip (default 0)", false},
         {"limit",  "number", "Maximum matches to return (default 200, max 5000)", false}},
        true, handle_list_functions});

    srv.register_tool({
        "disasm_get_xrefs_to",
        "Return cached cross-references that target an address from the xref_db (call/jump/data_ref). Requires the containing module to have been indexed via the Xref DB panel.",
        {{"address", "string", "Target address (hex string or integer)", true}},
        true, handle_get_xrefs_to});

    srv.register_tool({
        "disasm_get_xrefs_from",
        "Return cached cross-references that originate at an address from the xref_db. Requires the containing module to have been indexed.",
        {{"address", "string", "Source address (hex string or integer)", true}},
        true, handle_get_xrefs_from});

    srv.register_tool({
        "disasm_set_comment",
        "Attach (or clear) a comment string for an instruction address. Empty comment deletes the entry.",
        {{"address", "string", "Address (hex string or integer)", true},
         {"comment", "string", "Comment text (empty string clears the comment)", false}},
        false, handle_set_comment});

    srv.register_tool({
        "disasm_get_comment",
        "Return the comment string previously stored for an address (empty when none).",
        {{"address", "string", "Address (hex string or integer)", true}},
        true, handle_get_comment});

    srv.register_tool({
        "disasm_rename_function",
        "Set (or clear) the user-visible name of a function at an address. Empty name clears the rename and falls back to PDB/synthetic naming. Triggers a disasm view format refresh.",
        {{"address", "string", "Function start (hex string or integer)", true},
         {"new_name", "string", "New display name (empty to clear)", false}},
        false, handle_rename_function});

    srv.register_tool({
        "disasm_get_section_info",
        "Return the executable section table of the currently loaded disassembly file (va, size, image_base, text_va).",
        {},
        true, handle_get_section_info});

    srv.register_tool({
        "disasm_search_bytes",
        "Scan executable sections of the loaded file for a hex byte pattern. Pattern accepts hex bytes separated by spaces or commas; '??' is a single-byte wildcard.",
        {{"pattern", "string", "Hex pattern (e.g. '48 8B 05 ?? ?? ?? ??')", true},
         {"max_hits","number", "Maximum match addresses to return (default 256, max 4096)", false}},
        true, handle_search_bytes});

    srv.register_tool({
        "disasm_get_strings",
        "Extract printable string literals from the loaded disassembly file. Streams ASCII and/or UTF-16LE runs from the data sections.",
        {{"min_length", "number", "Minimum run length in characters (default 4)", false},
         {"encoding",   "string", "ascii, utf16, or both (default ascii)", false},
         {"limit",      "number", "Maximum strings to return (default 2048, max 8192)", false}},
        true, handle_get_strings});

    srv.register_tool({
        "ui_set_active_view",
        "Switch the central view to a named panel (disassembly, hex_view, debugger, pseudocode, settings, analysis_hub, etc.).",
        {{"view", "string", "View name (case-insensitive)", true}},
        false, handle_ui_set_active_view});

    srv.register_tool({
        "bookmarks_add",
        "Add an address to the Disassembly bookmark list with an optional label.",
        {{"address", "string", "Bookmark address (hex string or integer)", true},
         {"label",   "string", "Optional descriptive label", false}},
        false, handle_bookmarks_add});

    srv.register_tool({
        "bookmarks_remove",
        "Remove the bookmark at the given address.",
        {{"address", "string", "Bookmark address (hex string or integer)", true}},
        false, handle_bookmarks_remove});

    srv.register_tool({
        "bookmarks_list",
        "List all addresses currently bookmarked in the Disassembly view.",
        {},
        true, handle_bookmarks_list});

    srv.register_tool({
        "hex_view_open",
        "Read a range of bytes from the attached process via the kernel driver and open them in the Hex View (size capped to 1 MiB).",
        {{"address", "string", "Source address (hex string or integer)", true},
         {"size",    "number", "Number of bytes to read (default 4096, max 1048576)", false}},
        false, handle_hex_view_open});
}

}
