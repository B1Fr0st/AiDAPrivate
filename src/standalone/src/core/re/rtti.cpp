#include "rtti.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <regex>
#include <set>

namespace re::rtti
{
namespace
{
struct type_info_t
{
    std::string name;
    std::string decorated_name;
    std::uint64_t type_descriptor_va = 0;
    std::uint64_t vtable_va = 0;
    std::uint64_t col_va = 0;
    std::uint64_t hierarchy_descriptor_va = 0;
    std::vector<std::string> base_classes;
    std::string module_name;
};

std::string undecorate_rtti_name(std::string decorated)
{
    if (decorated.rfind(".?AV", 0) == 0)
        decorated = decorated.substr(4);
    else if (decorated.rfind(".?AU", 0) == 0)
        decorated = decorated.substr(4);
    else if (decorated.rfind(".?AI", 0) == 0)
        decorated = decorated.substr(4);
    while (decorated.size() >= 2 && decorated.compare(decorated.size() - 2, 2, "@@") == 0)
        decorated.resize(decorated.size() - 2);
    std::string out;
    for (std::size_t i = 0; i < decorated.size(); ++i)
    {
        if (decorated[i] == '@')
        {
            if (!out.empty() && out.compare(out.size() >= 2 ? out.size() - 2 : 0, out.size() >= 2 ? 2 : 0, "::") != 0)
                out += "::";
        }
        else
        {
            out.push_back(decorated[i]);
        }
    }
    while (out.size() >= 2 && out.compare(out.size() - 2, 2, "::") == 0)
        out.resize(out.size() - 2);
    return out.empty() ? decorated : out;
}

bool read_c_string_from_buffer(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::string& out)
{
    out.clear();
    if (offset >= bytes.size())
        return false;
    for (std::size_t i = offset; i < bytes.size() && out.size() < 512; ++i)
    {
        char ch = static_cast<char>(bytes[i]);
        if (ch == '\0')
            return out.size() >= 5;
        if (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) > 0x7E)
            return false;
        out.push_back(ch);
    }
    return false;
}

bool valid_rtti_prefix(const std::vector<std::uint8_t>& bytes, std::size_t offset)
{
    if (offset + 4 > bytes.size())
        return false;
    return bytes[offset] == '.' && bytes[offset + 1] == '?' &&
        bytes[offset + 2] == 'A' &&
        (bytes[offset + 3] == 'V' || bytes[offset + 3] == 'U' || bytes[offset + 3] == 'I');
}

std::optional<module_section_t> section_named(const module_layout_t& layout, const char* name)
{
    for (const auto& section : layout.sections)
    {
        if (section.name == name)
            return section;
    }
    return std::nullopt;
}

std::vector<module_section_t> rdata_sections(const module_layout_t& layout)
{
    std::vector<module_section_t> out;
    for (const auto& section : layout.sections)
    {
        const bool readable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool executable = (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const std::string name = lower_ascii(section.name);
        if (readable && !executable && (name.find("rdata") != std::string::npos || name.find("data") != std::string::npos))
            out.push_back(section);
    }
    if (out.empty())
    {
        for (const auto& section : layout.sections)
        {
            if ((section.characteristics & IMAGE_SCN_MEM_READ) != 0 && (section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
                out.push_back(section);
        }
    }
    return out;
}

bool read_i32(std::uint32_t pid, std::uint64_t address, std::int32_t& out)
{
    std::uint32_t value = 0;
    if (!read_u32(pid, address, value))
        return false;
    out = static_cast<std::int32_t>(value);
    return true;
}

std::uint64_t rva_to_va(const driver_bridge::module_info_t& module, std::int32_t rva)
{
    if (rva <= 0)
        return 0;
    return module.base + static_cast<std::uint32_t>(rva);
}

std::optional<driver_bridge::module_info_t> find_module_by_base(std::uint32_t pid, std::uint64_t base)
{
    if (base == 0)
        return std::nullopt;
    for (const auto& module : modules_for(pid))
    {
        if (module.base == base)
            return module;
    }
    return std::nullopt;
}

std::vector<std::string> read_base_classes(std::uint32_t pid,
                                           const driver_bridge::module_info_t& module,
                                           std::uint64_t hierarchy_va,
                                           std::size_t max_bases)
{
    std::vector<std::string> bases;
    if (hierarchy_va == 0)
        return bases;
    std::uint32_t base_count = 0;
    std::int32_t base_array_rva = 0;
    if (!read_u32(pid, hierarchy_va + 8, base_count) || !read_i32(pid, hierarchy_va + 12, base_array_rva))
        return bases;
    base_count = std::min<std::uint32_t>(base_count, static_cast<std::uint32_t>(max_bases));
    const std::uint64_t base_array_va = rva_to_va(module, base_array_rva);
    if (base_array_va == 0)
        return bases;
    for (std::uint32_t i = 0; i < base_count; ++i)
    {
        std::int32_t base_desc_rva = 0;
        if (!read_i32(pid, base_array_va + i * 4, base_desc_rva))
            break;
        const std::uint64_t base_desc_va = rva_to_va(module, base_desc_rva);
        if (base_desc_va == 0)
            continue;
        std::int32_t td_rva = 0;
        if (!read_i32(pid, base_desc_va, td_rva))
            continue;
        const std::uint64_t td_va = rva_to_va(module, td_rva);
        if (td_va == 0)
            continue;
        std::string decorated;
        std::vector<std::uint8_t> name_bytes;
        if (read_bytes(pid, td_va + 16, 256, name_bytes) && read_c_string_from_buffer(name_bytes, 0, decorated))
            bases.push_back(undecorate_rtti_name(decorated));
    }
    return bases;
}

bool type_from_vtable(std::uint32_t pid,
                      const driver_bridge::module_info_t& module,
                      std::uint64_t vtable_va,
                      type_info_t& out)
{
    const std::uint64_t started_ms = GetTickCount64();
    diag::log_tagged_fmt("rtti",
                         "type_from_vtable enter pid=%u module=%s base=%s vtable=%s",
                         pid,
                         (!module.name.empty() ? module.name : module.path).c_str(),
                         sa_format_address(module.base).c_str(),
                         sa_format_address(vtable_va).c_str());
    if (vtable_va < 8)
        return false;
    std::uint64_t col_va = 0;
    if (!read_u64(pid, vtable_va - 8, col_va) || col_va == 0)
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable col_read_failed pid=%u vtable=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    driver_bridge::memory_region_t col_region{};
    if (!query_region(pid, col_va, col_region) || !is_readable(col_region))
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable col_unreadable pid=%u vtable=%s col=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             sa_format_address(col_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    std::uint32_t signature = 0;
    std::int32_t td_rva = 0;
    std::int32_t chd_rva = 0;
    std::int32_t self_rva = 0;
    if (!read_u32(pid, col_va, signature) ||
        !read_i32(pid, col_va + 12, td_rva) ||
        !read_i32(pid, col_va + 16, chd_rva) ||
        !read_i32(pid, col_va + 20, self_rva))
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable col_fields_failed pid=%u vtable=%s col=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             sa_format_address(col_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    const std::uint64_t self_va = rva_to_va(module, self_rva);
    const std::uint64_t td_va = rva_to_va(module, td_rva);
    const std::uint64_t hierarchy_va = rva_to_va(module, chd_rva);
    if (signature != 1 || td_va == 0)
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable invalid_col pid=%u vtable=%s col=%s signature=%u td_rva=%d chd_rva=%d self=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             sa_format_address(col_va).c_str(),
                             signature,
                             td_rva,
                             chd_rva,
                             sa_format_address(self_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    std::string decorated;
    std::vector<std::uint8_t> name_bytes;
    if (!read_bytes(pid, td_va + 16, 256, name_bytes) || !read_c_string_from_buffer(name_bytes, 0, decorated))
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable name_failed pid=%u vtable=%s td=%s bytes=%zu elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             sa_format_address(td_va).c_str(),
                             name_bytes.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    out = {};
    out.decorated_name = decorated;
    out.name = undecorate_rtti_name(decorated);
    out.type_descriptor_va = td_va;
    out.vtable_va = vtable_va;
    out.col_va = col_va;
    out.hierarchy_descriptor_va = hierarchy_va;
    out.base_classes = read_base_classes(pid, module, hierarchy_va, 64);
    out.module_name = module.name;
    diag::log_tagged_fmt("rtti",
                         "type_from_vtable exit pid=%u type=%s decorated=%s vtable=%s col=%s td=%s hierarchy=%s bases=%zu self_match=%d elapsed_ms=%llu",
                         pid,
                         out.name.c_str(),
                         out.decorated_name.c_str(),
                         sa_format_address(out.vtable_va).c_str(),
                         sa_format_address(out.col_va).c_str(),
                         sa_format_address(out.type_descriptor_va).c_str(),
                         sa_format_address(out.hierarchy_descriptor_va).c_str(),
                         out.base_classes.size(),
                         self_va == 0 || self_va == col_va ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return true;
}

std::uint64_t find_vtable_for_col(std::uint32_t pid,
                                  const std::vector<module_section_t>& sections,
                                  std::uint64_t col_va)
{
    const auto needle = u64_to_le(col_va);
    for (const auto& section : sections)
    {
        if (section.size == 0 || section.size > 64ull * 1024ull * 1024ull)
            continue;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(pid, section.va, static_cast<std::size_t>(section.size), bytes) || bytes.size() < 8)
            continue;
        for (std::size_t i = 0; i + 8 <= bytes.size(); i += 8)
        {
            if (std::memcmp(bytes.data() + i, needle.data(), 8) == 0)
                return section.va + i + 8;
        }
    }
    return 0;
}

std::vector<type_info_t> scan_module(std::uint32_t pid,
                                     const driver_bridge::module_info_t& module,
                                     const std::optional<std::regex>& filter,
                                     std::size_t max_results)
{
    std::vector<type_info_t> out;
    module_layout_t layout;
    if (!load_module_layout(pid, module, layout))
        return out;
    auto sections = rdata_sections(layout);
    std::map<std::uint64_t, type_info_t> by_td;
    for (const auto& section : sections)
    {
        if (section.size == 0 || section.size > 64ull * 1024ull * 1024ull)
            continue;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(pid, section.va, static_cast<std::size_t>(section.size), bytes) || bytes.size() < 32)
            continue;
        for (std::size_t i = 16; i + 8 < bytes.size(); ++i)
        {
            if (!valid_rtti_prefix(bytes, i))
                continue;
            std::string decorated;
            if (!read_c_string_from_buffer(bytes, i, decorated))
                continue;
            const std::uint64_t td_va = section.va + i - 16;
            std::uint64_t typeinfo_vftable = 0;
            std::memcpy(&typeinfo_vftable, bytes.data() + i - 16, sizeof(typeinfo_vftable));
            driver_bridge::memory_region_t ti_region{};
            if (!query_region(pid, typeinfo_vftable, ti_region) || !is_readable(ti_region))
                continue;
            const std::string name = undecorate_rtti_name(decorated);
            if (filter && !std::regex_search(name, *filter) && !std::regex_search(decorated, *filter))
                continue;
            type_info_t info;
            info.name = name;
            info.decorated_name = decorated;
            info.type_descriptor_va = td_va;
            info.module_name = module.name;
            by_td[td_va] = std::move(info);
            if (by_td.size() >= max_results)
                break;
        }
        if (by_td.size() >= max_results)
            break;
    }

    if (by_td.empty())
        return out;

    for (const auto& section : sections)
    {
        if (section.size == 0 || section.size > 64ull * 1024ull * 1024ull)
            continue;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(pid, section.va, static_cast<std::size_t>(section.size), bytes) || bytes.size() < 24)
            continue;
        for (std::size_t i = 0; i + 24 <= bytes.size(); i += 4)
        {
            std::uint32_t signature = 0;
            std::memcpy(&signature, bytes.data() + i, 4);
            if (signature != 1)
                continue;
            std::int32_t td_rva = 0;
            std::int32_t chd_rva = 0;
            std::int32_t self_rva = 0;
            std::memcpy(&td_rva, bytes.data() + i + 12, 4);
            std::memcpy(&chd_rva, bytes.data() + i + 16, 4);
            std::memcpy(&self_rva, bytes.data() + i + 20, 4);
            const std::uint64_t td_va = rva_to_va(module, td_rva);
            const std::uint64_t self_va = rva_to_va(module, self_rva);
            const std::uint64_t col_va = section.va + i;
            auto it = by_td.find(td_va);
            if (it == by_td.end() || self_va != col_va)
                continue;
            it->second.col_va = col_va;
            it->second.hierarchy_descriptor_va = rva_to_va(module, chd_rva);
            it->second.vtable_va = find_vtable_for_col(pid, sections, col_va);
            it->second.base_classes = read_base_classes(pid, module, it->second.hierarchy_descriptor_va, 64);
        }
    }

    for (auto& [td, info] : by_td)
    {
        (void)td;
        out.push_back(std::move(info));
    }
    std::sort(out.begin(), out.end(), [](const type_info_t& a, const type_info_t& b) {
        return a.name < b.name;
    });
    return out;
}

std::vector<type_info_t> scan_types(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return {};
    const std::string module_name = string_param(params, "module_name");
    const std::string filter_text = string_param(params, "filter");
    std::optional<std::regex> filter;
    if (!filter_text.empty())
    {
        try
        {
            filter.emplace(filter_text, std::regex::icase);
        }
        catch (...)
        {
            filter.reset();
        }
    }
    const std::size_t max_results = static_cast<std::size_t>(numeric_param(params, "max_results", 2000, 1, 20000));
    std::vector<driver_bridge::module_info_t> modules;
    std::uint64_t module_base = 0;
    std::uint64_t hint_va = 0;
    if (parse_address_param(params, "module_base_va", module_base) || parse_address_param(params, "module_base", module_base))
    {
        if (auto module = find_module_by_base(scope.pid(), module_base))
            modules.push_back(*module);
    }
    else if (parse_address_param(params, "vtable_va", hint_va) ||
             parse_address_param(params, "type_descriptor_va", hint_va) ||
             parse_address_param(params, "type_va", hint_va) ||
             parse_address_param(params, "hint_va", hint_va))
    {
        if (auto module = find_module_for_address(scope.pid(), hint_va))
            modules.push_back(*module);
    }
    else if (!module_name.empty())
    {
        if (auto module = find_module_by_name(scope.pid(), module_name))
            modules.push_back(*module);
    }
    else
    {
        modules = modules_for(scope.pid());
    }
    diag::log_tagged_fmt("rtti",
                         "scan_types enter pid=%u module_name=%s module_count=%zu filter=%s max_results=%zu hint_va=%s elapsed_ms=%llu",
                         scope.pid(),
                         module_name.c_str(),
                         modules.size(),
                         filter_text.c_str(),
                         max_results,
                         hint_va ? sa_format_address(hint_va).c_str() : "0x0",
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    std::vector<type_info_t> out;
    for (const auto& module : modules)
    {
        const std::uint64_t module_started_ms = GetTickCount64();
        auto partial = scan_module(scope.pid(), module, filter, max_results - out.size());
        diag::log_tagged_fmt("rtti",
                             "scan_types module pid=%u name=%s base=%s size=%llu count=%zu elapsed_ms=%llu",
                             scope.pid(),
                             (!module.name.empty() ? module.name : module.path).c_str(),
                             sa_format_address(module.base).c_str(),
                             static_cast<unsigned long long>(module.size),
                             partial.size(),
                             static_cast<unsigned long long>(GetTickCount64() - module_started_ms));
        out.insert(out.end(), partial.begin(), partial.end());
        if (out.size() >= max_results)
            break;
    }
    diag::log_tagged_fmt("rtti",
                         "scan_types exit pid=%u count=%zu elapsed_ms=%llu",
                         scope.pid(),
                         out.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return out;
}

json type_to_json(const type_info_t& type)
{
    json out;
    out["name"] = type.name;
    out["decorated_name"] = type.decorated_name;
    out["type_descriptor_va"] = sa_format_address(type.type_descriptor_va);
    out["vtable_va"] = type.vtable_va ? json(sa_format_address(type.vtable_va)) : json(nullptr);
    out["complete_object_locator_va"] = type.col_va ? json(sa_format_address(type.col_va)) : json(nullptr);
    out["hierarchy_descriptor_va"] = type.hierarchy_descriptor_va ? json(sa_format_address(type.hierarchy_descriptor_va)) : json(nullptr);
    out["module_name"] = type.module_name;
    out["base_classes"] = type.base_classes;
    return out;
}

std::uint64_t approximate_function_start(std::uint32_t pid, std::uint64_t ref_va)
{
    const std::uint64_t start = ref_va > 0x100 ? ref_va - 0x100 : ref_va;
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, start, static_cast<std::size_t>(ref_va - start), bytes) || bytes.empty())
        return ref_va;
    std::uint64_t best = ref_va;
    for (std::size_t i = 0; i + 4 < bytes.size(); ++i)
    {
        if (bytes[i] == 0x40 || bytes[i] == 0x48 || bytes[i] == 0x55)
        {
            AsmInstr ins = zydis_decode_one(bytes.data() + i, static_cast<int>(std::min<std::size_t>(16, bytes.size() - i)), start + i);
            const std::string m = lower_ascii(ins.mnem);
            const std::string ops = lower_ascii(ins.ops);
            if (m == "push" || (m == "sub" && ops.find("rsp") != std::string::npos))
                best = start + i;
        }
    }
    return best;
}

std::vector<std::string> split_operands(std::string ops)
{
    std::vector<std::string> out;
    std::size_t start = 0;
    int bracket_depth = 0;
    for (std::size_t i = 0; i <= ops.size(); ++i)
    {
        const char ch = i < ops.size() ? ops[i] : ',';
        if (ch == '[')
            ++bracket_depth;
        else if (ch == ']' && bracket_depth > 0)
            --bracket_depth;
        if (ch == ',' && bracket_depth == 0)
        {
            out.push_back(trim_ascii(ops.substr(start, i - start)));
            start = i + 1;
        }
    }
    return out;
}

std::string normalize_register_name(std::string value)
{
    value = lower_ascii(trim_ascii(value));
    if (value == "rax" || value == "eax" || value == "ax" || value == "al")
        return "rax";
    if (value == "rbx" || value == "ebx" || value == "bx" || value == "bl")
        return "rbx";
    if (value == "rcx" || value == "ecx" || value == "cx" || value == "cl")
        return "rcx";
    if (value == "rdx" || value == "edx" || value == "dx" || value == "dl")
        return "rdx";
    if (value == "rsi" || value == "esi" || value == "si" || value == "sil")
        return "rsi";
    if (value == "rdi" || value == "edi" || value == "di" || value == "dil")
        return "rdi";
    if (value == "rbp" || value == "ebp" || value == "bp" || value == "bpl")
        return "rbp";
    if (value == "rsp" || value == "esp" || value == "sp" || value == "spl")
        return "rsp";
    for (int i = 8; i <= 15; ++i)
    {
        const std::string base = "r" + std::to_string(i);
        if (value == base || value == base + "d" || value == base + "w" || value == base + "b")
            return base;
    }
    return {};
}

std::string zydis_register_name(std::uint16_t reg)
{
    switch (static_cast<ZydisRegister>(reg))
    {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_AL: return "rax";
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_BL: return "rbx";
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_CL: return "rcx";
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_DL: return "rdx";
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
    default: return {};
    }
}

std::optional<std::uint64_t> instruction_value(std::uint32_t pid,
                                               const AsmInstr& ins,
                                               const std::vector<std::string>& operands,
                                               const std::map<std::string, std::uint64_t>& reg_values)
{
    const std::string m = lower_ascii(ins.mnem);
    if (operands.size() < 2)
        return std::nullopt;
    const std::string rhs_reg = normalize_register_name(operands[1]);
    if (!rhs_reg.empty())
    {
        auto it = reg_values.find(rhs_reg);
        if (it != reg_values.end())
            return it->second;
    }
    if (m == "mov" && ins.has_imm)
        return ins.imm_unsigned;
    if ((m == "lea" || m == "mov") && ins.has_mem_op &&
        ins.mem_op.base_reg == static_cast<std::uint16_t>(ZYDIS_REGISTER_RIP) &&
        ins.mem_op.has_disp)
    {
        const std::uint64_t target = static_cast<std::uint64_t>(static_cast<std::int64_t>(ins.addr + static_cast<std::uint64_t>(ins.len)) + ins.mem_op.disp);
        if (m == "lea")
            return target;
        std::uint64_t value = 0;
        if (read_u64(pid, target, value))
            return value;
    }
    return std::nullopt;
}

bool object_storage_destination(const AsmInstr& ins, const std::string& lhs, const std::set<std::string>& this_regs)
{
    if (lhs.find('[') == std::string::npos || !ins.has_mem_op)
        return false;
    const std::string base = zydis_register_name(ins.mem_op.base_reg);
    if (base.empty() || this_regs.count(base) == 0)
        return false;
    if (ins.mem_op.index_reg != 0)
        return false;
    return ins.mem_op.disp >= 0 && ins.mem_op.disp <= 0x100000;
}

void update_this_aliases(const AsmInstr& ins, const std::vector<std::string>& operands, std::set<std::string>& this_regs)
{
    const std::string m = lower_ascii(ins.mnem);
    if (operands.empty())
        return;
    const std::string dst = normalize_register_name(operands[0]);
    if (dst.empty())
        return;
    bool aliases_this = false;
    if (operands.size() >= 2)
    {
        const std::string src = normalize_register_name(operands[1]);
        if (!src.empty() && this_regs.count(src) != 0)
            aliases_this = true;
        if (m == "lea" && ins.has_mem_op && this_regs.count(zydis_register_name(ins.mem_op.base_reg)) != 0 && ins.mem_op.index_reg == 0)
            aliases_this = true;
    }
    if (aliases_this)
        this_regs.insert(dst);
    else if (m != "cmp" && m != "test")
        this_regs.erase(dst);
}

void update_value_registers(std::uint32_t pid,
                            const AsmInstr& ins,
                            const std::vector<std::string>& operands,
                            std::map<std::string, std::uint64_t>& reg_values)
{
    const std::string m = lower_ascii(ins.mnem);
    if (operands.empty())
        return;
    const std::string dst = normalize_register_name(operands[0]);
    if (dst.empty())
        return;
    if (m == "mov" || m == "lea")
    {
        auto value = instruction_value(pid, ins, operands, reg_values);
        if (value)
            reg_values[dst] = *value;
        else
            reg_values.erase(dst);
        return;
    }
    if (m != "cmp" && m != "test")
        reg_values.erase(dst);
}
}

tool_result_t scan(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    auto types = scan_types(params);
    json arr = json::array();
    for (const auto& type : types)
        arr.push_back(type_to_json(type));
    json result;
    result["process_id"] = scope.pid();
    result["returned"] = arr.size();
    result["types"] = std::move(arr);
    return tool_result_t::ok(result);
}

tool_result_t find_type(const json& params)
{
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string pattern = string_param(params, "pattern");
    if (pattern.empty())
        return tool_result_t::error("'pattern' is required.");
    json scan_params = params;
    scan_params["filter"] = pattern;
    auto types = scan_types(scan_params);
    json matches = json::array();
    for (const auto& type : types)
        matches.push_back(type_to_json(type));
    json result;
    result["pattern"] = pattern;
    result["matches"] = std::move(matches);
    result["count"] = result["matches"].size();
    if (!types.empty())
        result["best"] = type_to_json(types.front());
    return tool_result_t::ok(result);
}

tool_result_t list_hierarchy(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string query = string_param(params, "type_name_or_va");
    if (query.empty())
        return tool_result_t::error("'type_name_or_va' is required.");
    std::uint64_t va = 0;
    const auto parsed_va = sa_parse_address(query);
    const bool query_is_va = parsed_va.has_value();
    if (parsed_va)
        va = *parsed_va;
    std::uint64_t vtable_hint = 0;
    if (parse_address_param(params, "vtable_va", vtable_hint) && vtable_hint != 0)
    {
        if (auto module = find_module_for_address(scope.pid(), vtable_hint))
        {
            type_info_t hinted;
            if (type_from_vtable(scope.pid(), *module, vtable_hint, hinted))
            {
                const std::string query_lower = lower_ascii(query);
                const bool match = query_is_va ? (hinted.vtable_va == va || hinted.type_descriptor_va == va) :
                    (lower_ascii(hinted.name).find(query_lower) != std::string::npos ||
                     lower_ascii(hinted.decorated_name).find(query_lower) != std::string::npos);
                diag::log_tagged_fmt("rtti",
                                     "list_hierarchy vtable_hint pid=%u query=%s match=%d type=%s bases=%zu elapsed_ms=%llu",
                                     scope.pid(),
                                     query.c_str(),
                                     match ? 1 : 0,
                                     hinted.name.c_str(),
                                     hinted.base_classes.size(),
                                     static_cast<unsigned long long>(GetTickCount64() - started_ms));
                if (match)
                {
                    json result = type_to_json(hinted);
                    json hierarchy = json::array();
                    for (std::size_t i = 0; i < hinted.base_classes.size(); ++i)
                    {
                        json row;
                        row["order"] = i;
                        row["name"] = hinted.base_classes[i];
                        row["vtable_va"] = nullptr;
                        row["type_descriptor_va"] = nullptr;
                        hierarchy.push_back(std::move(row));
                    }
                    result["hierarchy"] = std::move(hierarchy);
                    result["resolution"] = "vtable_hint_col";
                    return tool_result_t::ok(result);
                }
            }
        }
    }
    json scan_params = params;
    if (!query_is_va && !scan_params.contains("filter"))
        scan_params["filter"] = query;
    if (!scan_params.contains("max_results"))
        scan_params["max_results"] = 256;
    auto types = scan_types(scan_params);
    diag::log_tagged_fmt("rtti",
                         "list_hierarchy scanned pid=%u query=%s query_is_va=%d types=%zu elapsed_ms=%llu",
                         scope.pid(),
                         query.c_str(),
                         query_is_va ? 1 : 0,
                         types.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    for (const auto& type : types)
    {
        const bool match = query_is_va ? (type.vtable_va == va || type.type_descriptor_va == va) :
            (lower_ascii(type.name).find(lower_ascii(query)) != std::string::npos ||
             lower_ascii(type.decorated_name).find(lower_ascii(query)) != std::string::npos);
        if (!match)
            continue;
        json result = type_to_json(type);
        json hierarchy = json::array();
        std::map<std::string, type_info_t> by_name;
        for (const auto& candidate : types)
            by_name[lower_ascii(candidate.name)] = candidate;
        for (std::size_t i = 0; i < type.base_classes.size(); ++i)
        {
            json row;
            row["order"] = i;
            row["name"] = type.base_classes[i];
            auto parent = by_name.find(lower_ascii(type.base_classes[i]));
            row["vtable_va"] = parent != by_name.end() && parent->second.vtable_va ? json(sa_format_address(parent->second.vtable_va)) : json(nullptr);
            row["type_descriptor_va"] = parent != by_name.end() && parent->second.type_descriptor_va ? json(sa_format_address(parent->second.type_descriptor_va)) : json(nullptr);
            hierarchy.push_back(std::move(row));
        }
        result["hierarchy"] = std::move(hierarchy);
        diag::log_tagged_fmt("rtti",
                             "list_hierarchy match pid=%u query=%s type=%s bases=%zu elapsed_ms=%llu",
                             scope.pid(),
                             query.c_str(),
                             type.name.c_str(),
                             type.base_classes.size(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return tool_result_t::ok(result);
    }
    diag::log_tagged_fmt("rtti",
                         "list_hierarchy miss pid=%u query=%s types=%zu elapsed_ms=%llu",
                         scope.pid(),
                         query.c_str(),
                         types.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::error("RTTI type not found.");
}

tool_result_t find_constructor(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    std::uint64_t vtable_va = 0;
    if (!parse_address_param(params, "vtable_va", vtable_va) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required.");
    const std::size_t max_scan_bytes = static_cast<std::size_t>(numeric_param(params, "max_scan_bytes", 64ull * 1024ull * 1024ull, 4096, 64ull * 1024ull * 1024ull));
    const std::uint64_t timeout_ms = numeric_param(params, "timeout_ms", 5500, 500, 60000);
    const auto module = find_module_for_address(scope.pid(), vtable_va);
    if (!module)
        return tool_result_t::error("Could not resolve vtable module.");
    module_layout_t layout;
    if (!load_module_layout(scope.pid(), *module, layout))
        return tool_result_t::error("Could not read module sections.");
    diag::log_tagged_fmt("rtti",
                         "find_constructor enter pid=%u vtable=%s module=%s base=%s sections=%zu max_scan_bytes=%zu elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         (!module->name.empty() ? module->name : module->path).c_str(),
                         sa_format_address(module->base).c_str(),
                         layout.sections.size(),
                         max_scan_bytes,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    type_info_t hinted_type;
    const bool has_hinted_type = type_from_vtable(scope.pid(), *module, vtable_va, hinted_type);
    json candidates = json::array();
    std::set<std::uint64_t> seen;
    bool deadline_hit = false;
    std::size_t total_reference_hits = 0;
    std::size_t total_windows = 0;
    std::size_t total_decoded = 0;
    auto timed_out = [&]() -> bool {
        if (GetTickCount64() - started_ms < timeout_ms)
            return false;
        deadline_hit = true;
        return true;
    };
    auto append_candidate = [&](const AsmInstr& ins,
                                std::uint64_t fn_start,
                                const char* confidence,
                                const char* phase) {
        if (!seen.insert(fn_start).second)
            return;
        json row;
        row["constructor_candidate_va"] = sa_format_address(fn_start);
        row["write_va"] = sa_format_address(ins.addr);
        row["object_offset"] = ins.mem_op.disp;
        row["confidence"] = confidence;
        row["phase"] = phase;
        row["write_instruction"] = disasm_text(ins);
        row["preview"] = disasm_preview(scope.pid(), fn_start, 8);
        candidates.push_back(std::move(row));
    };
    auto add_window = [](std::vector<std::pair<std::size_t, std::size_t>>& windows,
                         std::size_t begin,
                         std::size_t end) {
        if (begin >= end)
            return;
        for (const auto& existing : windows)
        {
            if (existing.first == begin && existing.second == end)
                return;
        }
        windows.push_back({begin, end});
    };
    auto decode_range = [&](const module_section_t& section,
                            const std::vector<std::uint8_t>& bytes,
                            std::size_t begin,
                            std::size_t end,
                            const char* phase) -> std::size_t {
        std::size_t decoded_count = 0;
        std::map<std::string, std::uint64_t> reg_values;
        std::set<std::string> this_regs;
        this_regs.insert("rcx");
        for (std::size_t i = begin; i < end && candidates.size() < 64;)
        {
            if (timed_out())
                break;
            const int avail = static_cast<int>(std::min<std::size_t>(16, end - i));
            AsmInstr ins = zydis_decode_one(bytes.data() + i, avail, section.va + i);
            ++decoded_count;
            const std::string m = lower_ascii(ins.mnem);
            const auto operands = split_operands(lower_ascii(ins.ops));
            if ((m == "mov" || m == "lea") && operands.size() >= 2 && object_storage_destination(ins, operands[0], this_regs))
            {
                auto value = instruction_value(scope.pid(), ins, operands, reg_values);
                if (value && *value == vtable_va)
                {
                    const std::uint64_t fn_start = approximate_function_start(scope.pid(), ins.addr);
                    append_candidate(ins, fn_start, "high", phase);
                    if (candidates.size() >= 64)
                        break;
                }
            }
            update_this_aliases(ins, operands, this_regs);
            update_value_registers(scope.pid(), ins, operands, reg_values);
            i += static_cast<std::size_t>(std::max(1, ins.len));
        }
        return decoded_count;
    };
    for (const auto& section : layout.sections)
    {
        if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || section.size == 0 || section.size > 64ull * 1024ull * 1024ull)
            continue;
        if (timed_out())
            break;
        const std::uint64_t section_started_ms = GetTickCount64();
        const std::size_t candidates_before = candidates.size();
        std::size_t decoded_count = 0;
        const std::size_t read_size = static_cast<std::size_t>(std::min<std::uint64_t>(section.size, max_scan_bytes));
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), section.va, read_size, bytes) || bytes.empty())
        {
            diag::log_tagged_fmt("rtti",
                                 "find_constructor section_read_failed pid=%u section=%s va=%s read_size=%zu elapsed_ms=%llu",
                                 scope.pid(),
                                 section.name.c_str(),
                                 sa_format_address(section.va).c_str(),
                                 read_size,
                                 static_cast<unsigned long long>(GetTickCount64() - section_started_ms));
            continue;
        }
        std::vector<std::size_t> references;
        const auto needle = u64_to_le(vtable_va);
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            if (i + needle.size() <= bytes.size() && std::memcmp(bytes.data() + i, needle.data(), needle.size()) == 0)
                references.push_back(i);
            if (i + 7 <= bytes.size() && (bytes[i] & 0xF0u) == 0x40u && (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) && (bytes[i + 2] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 3, sizeof(disp));
                const std::uint64_t target = static_cast<std::uint64_t>(static_cast<std::int64_t>(section.va + i + 7) + disp);
                if (target == vtable_va)
                    references.push_back(i);
            }
            if (i + 6 <= bytes.size() && bytes[i] == 0x8D && (bytes[i + 1] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 2, sizeof(disp));
                const std::uint64_t target = static_cast<std::uint64_t>(static_cast<std::int64_t>(section.va + i + 6) + disp);
                if (target == vtable_va)
                    references.push_back(i);
            }
            if (i + 10 <= bytes.size() && (bytes[i] & 0xF8u) == 0x48u && bytes[i + 1] >= 0xB8 && bytes[i + 1] <= 0xBF)
            {
                std::uint64_t imm = 0;
                std::memcpy(&imm, bytes.data() + i + 2, sizeof(imm));
                if (imm == vtable_va)
                    references.push_back(i);
            }
        }
        std::sort(references.begin(), references.end());
        references.erase(std::unique(references.begin(), references.end()), references.end());
        total_reference_hits += references.size();
        std::vector<std::pair<std::size_t, std::size_t>> windows;
        const std::size_t max_windows = static_cast<std::size_t>(numeric_param(params, "max_reference_windows", 128, 1, 4096));
        for (std::size_t ref_index = 0; ref_index < references.size() && windows.size() < max_windows; ++ref_index)
        {
            const std::size_t ref = references[ref_index];
            const std::size_t begin = ref > 192 ? ref - 192 : 0;
            const std::size_t end = std::min<std::size_t>(bytes.size(), ref + 320);
            add_window(windows, begin, end);
            add_window(windows, ref, end);
        }
        if (references.empty())
            add_window(windows, 0, std::min<std::size_t>(bytes.size(), 256 * 1024));
        diag::log_tagged_fmt("rtti",
                             "find_constructor section_prefilter pid=%u section=%s va=%s bytes=%zu refs=%zu windows=%zu elapsed_ms=%llu total_elapsed_ms=%llu",
                             scope.pid(),
                             section.name.c_str(),
                             sa_format_address(section.va).c_str(),
                             bytes.size(),
                             references.size(),
                             windows.size(),
                             static_cast<unsigned long long>(GetTickCount64() - section_started_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        for (const auto& window : windows)
        {
            if (timed_out() || candidates.size() >= 64)
                break;
            ++total_windows;
            for (std::size_t shift = 0; shift < 16 && window.first + shift < window.second && candidates.size() < 64; ++shift)
            {
                if (timed_out())
                    break;
                decoded_count += decode_range(section, bytes, window.first + shift, window.second, references.empty() ? "bounded_fallback_window" : "vtable_reference_window");
            }
        }
        total_decoded += decoded_count;
        diag::log_tagged_fmt("rtti",
                             "find_constructor section_done pid=%u section=%s va=%s bytes=%zu decoded=%zu refs=%zu windows=%zu new_candidates=%zu total_candidates=%zu deadline=%d elapsed_ms=%llu total_elapsed_ms=%llu",
                             scope.pid(),
                             section.name.c_str(),
                             sa_format_address(section.va).c_str(),
                             bytes.size(),
                             decoded_count,
                             references.size(),
                             windows.size(),
                             candidates.size() - candidates_before,
                             candidates.size(),
                             deadline_hit ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - section_started_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (candidates.size() >= 64 || deadline_hit)
            break;
    }
    json result;
    result["process_id"] = scope.pid();
    result["vtable_va"] = sa_format_address(vtable_va);
    result["module_name"] = !module->name.empty() ? module->name : module->path;
    result["timeout_ms"] = timeout_ms;
    result["deadline_hit"] = deadline_hit;
    result["reference_hits"] = total_reference_hits;
    result["decode_windows"] = total_windows;
    result["decoded_instructions"] = total_decoded;
    if (has_hinted_type)
        result["type"] = type_to_json(hinted_type);
    result["candidates"] = std::move(candidates);
    const std::size_t candidate_count = result["candidates"].size();
    result["count"] = candidate_count;
    diag::log_tagged_fmt("rtti",
                         "find_constructor exit pid=%u vtable=%s count=%zu refs=%zu windows=%zu decoded=%zu deadline=%d elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         candidate_count,
                         total_reference_hits,
                         total_windows,
                         total_decoded,
                         deadline_hit ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}
}
