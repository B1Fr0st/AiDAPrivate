#include "rtti.hpp"
#include "../../helpers/diag_log.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <regex>
#include <set>

namespace re::rtti
{
namespace
{
struct col_record_t
{
    std::uint64_t complete_object_locator_va = 0;
    std::uint64_t hierarchy_descriptor_va = 0;
    std::uint32_t signature = 0;
    bool relative = false;
    bool self_consistent = false;
    bool legacy_absolute = false;
    std::string confidence;
};

struct vtable_record_t
{
    std::uint64_t vtable_va = 0;
    std::uint64_t complete_object_locator_va = 0;
    std::size_t sampled_slots = 0;
    std::size_t readable_slots = 0;
    std::size_t executable_slots = 0;
    std::string confidence;
    int score = 0;
};

struct base_class_record_t
{
    std::string name;
    std::string decorated_name;
    std::uint64_t type_descriptor_va = 0;
    std::uint64_t base_descriptor_va = 0;
    std::int32_t mdisp = 0;
    std::int32_t pdisp = 0;
    std::int32_t vdisp = 0;
    std::uint32_t attributes = 0;
};

struct base_classes_result_t
{
    std::vector<std::string> names;
    std::vector<base_class_record_t> records;
};

struct type_info_t
{
    std::string name;
    std::string decorated_name;
    std::uint64_t type_descriptor_va = 0;
    std::uint64_t vtable_va = 0;
    std::uint64_t col_va = 0;
    std::uint64_t hierarchy_descriptor_va = 0;
    std::vector<std::string> base_classes;
    std::vector<base_class_record_t> base_class_records;
    std::vector<col_record_t> cols;
    std::vector<vtable_record_t> vtables;
    std::string module_name;
    int best_col_score = 0;
    int best_vtable_score = 0;
};

struct type_resolution_record_t
{
    std::string name;
    std::string decorated_name;
    std::uint64_t type_descriptor_va = 0;
    std::uint64_t vtable_va = 0;
    std::uint64_t hierarchy_descriptor_va = 0;
    std::vector<vtable_record_t> vtables;
    std::vector<std::string> base_classes;
    std::vector<base_class_record_t> base_class_records;
    std::string module_name;
};

struct col_info_t
{
    std::uint32_t signature = 0;
    std::uint64_t col_va = 0;
    std::uint64_t type_descriptor_va = 0;
    std::uint64_t hierarchy_descriptor_va = 0;
    std::uint64_t self_va = 0;
    bool relative = false;
    bool self_consistent = false;
    bool legacy_absolute = false;
    std::string confidence;
    int score = 0;
};

struct rtti_scan_context_t
{
    std::uint32_t pid = 0;
    std::uint64_t started_ms = 0;
    std::uint64_t timeout_ms = 0;
    bool deadline_hit = false;
    bool cancelled = false;
    std::string stop_stage;
    std::size_t scanned_module_count = 0;
    std::size_t type_descriptor_count = 0;
    std::size_t complete_object_locator_count = 0;
    std::size_t vtable_count = 0;
    std::uint64_t bytes_scanned = 0;
    std::vector<json> scanned_modules;

    bool stop(const char* stage)
    {
        if (cancelled || deadline_hit)
            return true;
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            stop_stage = stage ? stage : "";
            return true;
        }
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        if (call_deadline != 0 && GetTickCount64() >= call_deadline)
        {
            deadline_hit = true;
            stop_stage = stage ? stage : "";
            return true;
        }
        if (timeout_ms != 0 && GetTickCount64() - started_ms >= timeout_ms)
        {
            deadline_hit = true;
            stop_stage = stage ? stage : "";
            return true;
        }
        return false;
    }

    std::uint64_t elapsed_ms() const
    {
        return GetTickCount64() - started_ms;
    }
};

struct scan_result_t
{
    bool ok = false;
    std::string error;
    std::uint32_t pid = 0;
    std::vector<type_info_t> types;
    bool deadline_hit = false;
    bool cancelled = false;
    bool partial = false;
    bool unfiltered_cap_hit = false;
    std::uint64_t elapsed_ms = 0;
    std::uint64_t timeout_ms = 0;
    std::size_t scanned_module_count = 0;
    std::size_t type_descriptor_count = 0;
    std::size_t complete_object_locator_count = 0;
    std::size_t vtable_count = 0;
    std::uint64_t bytes_scanned = 0;
    std::size_t unfiltered_type_count = 0;
    std::vector<json> scanned_modules;
    std::string filter;
    std::string module_filter;
    std::string scan_mode;
    json exact_selector_flags = json::object();
    std::vector<std::string> sample_type_names;
    std::vector<type_resolution_record_t> type_index;
    json error_details = json::object();
};

std::string undecorate_rtti_name(std::string decorated)
{
    if (decorated.rfind(".?AV", 0) == 0)
        decorated = decorated.substr(4);
    else if (decorated.rfind(".?AU", 0) == 0)
        decorated = decorated.substr(4);
    else if (decorated.rfind(".?AI", 0) == 0)
        decorated = decorated.substr(4);
    else if (decorated.rfind(".?AW4", 0) == 0)
        decorated = decorated.substr(5);
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
    if (bytes[offset] != '.' || bytes[offset + 1] != '?' || bytes[offset + 2] != 'A')
        return false;
    if (bytes[offset + 3] == 'V' || bytes[offset + 3] == 'U' || bytes[offset + 3] == 'I')
        return true;
    return offset + 5 <= bytes.size() && bytes[offset + 3] == 'W' && bytes[offset + 4] == '4';
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

std::vector<module_section_t> rdata_sections(const module_layout_t& layout, bool deep_scan = false)
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
    if (deep_scan)
    {
        for (const auto& section : layout.sections)
        {
            const bool readable = (section.characteristics & IMAGE_SCN_MEM_READ) != 0;
            if (!readable)
                continue;
            bool already = false;
            for (const auto& existing : out)
            {
                if (existing.va == section.va)
                {
                    already = true;
                    break;
                }
            }
            if (!already)
                out.push_back(section);
        }
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

std::size_t type_descriptor_name_offset(const module_layout_t& layout)
{
    return layout.pointer_size == 4 ? 8u : 16u;
}

bool read_pointer_from_buffer(const std::uint8_t* bytes, std::size_t size, std::size_t offset, std::uint32_t pointer_size, std::uint64_t& out)
{
    out = 0;
    if (!bytes || (pointer_size != 4 && pointer_size != 8) || offset + pointer_size > size)
        return false;
    if (pointer_size == 4)
    {
        std::uint32_t value = 0;
        std::memcpy(&value, bytes + offset, sizeof(value));
        out = value;
        return true;
    }
    std::memcpy(&out, bytes + offset, sizeof(out));
    return true;
}

bool read_pointer_from_buffer(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t pointer_size, std::uint64_t& out)
{
    return read_pointer_from_buffer(bytes.data(), bytes.size(), offset, pointer_size, out);
}

bool read_pointer_remote(std::uint32_t pid, std::uint64_t address, std::uint32_t pointer_size, std::uint64_t& out)
{
    out = 0;
    if (pointer_size == 4)
    {
        std::uint32_t value = 0;
        if (!read_u32(pid, address, value))
            return false;
        out = value;
        return true;
    }
    if (pointer_size == 8)
        return read_u64(pid, address, out);
    return false;
}

std::uint64_t rva_to_va(const driver_bridge::module_info_t& module, std::int32_t rva)
{
    if (rva <= 0)
        return 0;
    return module.base + static_cast<std::uint32_t>(rva);
}

bool va_in_module(const driver_bridge::module_info_t& module, std::uint64_t va)
{
    if (module.base == 0 || module.size == 0)
        return false;
    const std::uint64_t end = module.base + static_cast<std::uint64_t>(module.size);
    return va >= module.base && va < end;
}

bool plausible_user_va(std::uint64_t va)
{
    return va >= 0x10000ull && va < 0x0000800000000000ull;
}

bool readable_address(std::uint32_t pid, std::uint64_t va)
{
    if (!plausible_user_va(va))
        return false;
    driver_bridge::memory_region_t region{};
    if (query_region(pid, va, region) && is_readable(region))
        return true;
    std::vector<std::uint8_t> probe;
    return read_bytes(pid, va, 1, probe) && !probe.empty();
}

bool read_type_descriptor_name(std::uint32_t pid, const module_layout_t& layout, std::uint64_t td_va, std::string& decorated)
{
    decorated.clear();
    const std::size_t name_offset = type_descriptor_name_offset(layout);
    if (!readable_address(pid, td_va + name_offset))
        return false;
    std::vector<std::uint8_t> name_bytes;
    return read_bytes(pid, td_va + name_offset, 512, name_bytes) &&
        read_c_string_from_buffer(name_bytes, 0, decorated) &&
        valid_rtti_prefix(name_bytes, 0);
}

bool parse_col_from_bytes(std::uint32_t pid,
                          const module_layout_t& layout,
                          std::uint64_t col_va,
                          const std::uint8_t* bytes,
                          std::size_t size,
                          col_info_t& out,
                          std::string* decorated_name = nullptr)
{
    out = {};
    if (!bytes || size < 20)
        return false;
    std::uint32_t signature = 0;
    std::memcpy(&signature, bytes, sizeof(signature));
    std::string decorated;
    if (layout.pointer_size == 8 && signature == 1 && size >= 24)
    {
        std::int32_t td_rva = 0;
        std::int32_t chd_rva = 0;
        std::int32_t self_rva = 0;
        std::memcpy(&td_rva, bytes + 12, sizeof(td_rva));
        std::memcpy(&chd_rva, bytes + 16, sizeof(chd_rva));
        std::memcpy(&self_rva, bytes + 20, sizeof(self_rva));
        const std::uint64_t td_va = rva_to_va(layout.module, td_rva);
        const std::uint64_t chd_va = rva_to_va(layout.module, chd_rva);
        const std::uint64_t self_va = rva_to_va(layout.module, self_rva);
        const bool self_ok = self_va == 0 || self_va == col_va || va_in_module(layout.module, self_va);
        if (td_va != 0 && va_in_module(layout.module, td_va) && self_ok && read_type_descriptor_name(pid, layout, td_va, decorated))
        {
            out.signature = signature;
            out.col_va = col_va;
            out.type_descriptor_va = td_va;
            out.hierarchy_descriptor_va = chd_va;
            out.self_va = self_va;
            out.relative = true;
            out.self_consistent = self_va == 0 || self_va == col_va;
            out.confidence = "high";
            out.score = 95 + (out.self_consistent ? 5 : 0);
            if (decorated_name)
                *decorated_name = decorated;
            return true;
        }
    }
    if (layout.pointer_size == 4 && signature == 0 && size >= 20)
    {
        std::uint32_t td32 = 0;
        std::uint32_t chd32 = 0;
        std::memcpy(&td32, bytes + 12, sizeof(td32));
        std::memcpy(&chd32, bytes + 16, sizeof(chd32));
        const std::uint64_t td_va = td32;
        const std::uint64_t chd_va = chd32;
        if (td_va != 0 && va_in_module(layout.module, td_va) && read_type_descriptor_name(pid, layout, td_va, decorated))
        {
            out.signature = signature;
            out.col_va = col_va;
            out.type_descriptor_va = td_va;
            out.hierarchy_descriptor_va = plausible_user_va(chd_va) ? chd_va : 0;
            out.self_va = 0;
            out.relative = false;
            out.self_consistent = true;
            out.confidence = "high";
            out.score = 90;
            if (decorated_name)
                *decorated_name = decorated;
            return true;
        }
    }
    if (layout.pointer_size == 8 && signature == 0 && size >= 32)
    {
        const std::size_t offsets[] = {16, 12};
        for (const std::size_t pointer_offset : offsets)
        {
            if (pointer_offset + 16 > size)
                continue;
            std::uint64_t td_va = 0;
            std::uint64_t chd_va = 0;
            std::memcpy(&td_va, bytes + pointer_offset, sizeof(td_va));
            std::memcpy(&chd_va, bytes + pointer_offset + 8, sizeof(chd_va));
            if (!plausible_user_va(td_va) || !read_type_descriptor_name(pid, layout, td_va, decorated))
                continue;
            out.signature = signature;
            out.col_va = col_va;
            out.type_descriptor_va = td_va;
            out.hierarchy_descriptor_va = plausible_user_va(chd_va) ? chd_va : 0;
            out.self_va = 0;
            out.relative = false;
            out.self_consistent = true;
            out.legacy_absolute = true;
            out.confidence = "legacy_absolute";
            out.score = 35;
            if (decorated_name)
                *decorated_name = decorated;
            return true;
        }
    }
    return false;
}

bool read_col_info(std::uint32_t pid,
                   const module_layout_t& layout,
                   std::uint64_t col_va,
                   col_info_t& out,
                   std::string* decorated_name = nullptr)
{
    std::vector<std::uint8_t> bytes;
    if (!read_bytes(pid, col_va, 40, bytes) || bytes.size() < 20)
        return false;
    return parse_col_from_bytes(pid, layout, col_va, bytes.data(), bytes.size(), out, decorated_name);
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

bool is_system_module_path(const driver_bridge::module_info_t& module)
{
    std::string path = lower_ascii(module.path);
    std::replace(path.begin(), path.end(), '/', '\\');
    return path.find("\\windows\\system32\\") != std::string::npos ||
        path.find("\\windows\\syswow64\\") != std::string::npos ||
        path.find("\\windows\\winsxs\\") != std::string::npos;
}

int module_scan_priority(const driver_bridge::module_info_t& module)
{
    if (is_system_module_path(module))
        return 40;
    const std::string name = lower_ascii(module.name);
    if (name.empty())
        return 20;
    if (name.find(".exe") != std::string::npos)
        return 0;
    return 10;
}

base_classes_result_t read_base_classes(std::uint32_t pid,
                                         const module_layout_t& layout,
                                         const col_info_t& col,
                                         std::size_t max_bases)
{
    base_classes_result_t bases;
    if (col.hierarchy_descriptor_va == 0)
        return bases;
    std::uint32_t base_count = 0;
    if (!read_u32(pid, col.hierarchy_descriptor_va + 8, base_count))
        return bases;
    base_count = std::min<std::uint32_t>(base_count, static_cast<std::uint32_t>(max_bases));
    std::uint64_t base_array_va = 0;
    if (col.relative)
    {
        std::int32_t base_array_rva = 0;
        if (!read_i32(pid, col.hierarchy_descriptor_va + 12, base_array_rva))
            return bases;
        base_array_va = rva_to_va(layout.module, base_array_rva);
    }
    else if (!read_pointer_remote(pid, col.hierarchy_descriptor_va + 12, layout.pointer_size, base_array_va))
    {
        return bases;
    }
    if (base_array_va == 0)
        return bases;
    for (std::uint32_t i = 0; i < base_count; ++i)
    {
        std::uint64_t base_desc_va = 0;
        if (col.relative)
        {
            std::int32_t base_desc_rva = 0;
            if (!read_i32(pid, base_array_va + i * 4, base_desc_rva))
                break;
            base_desc_va = rva_to_va(layout.module, base_desc_rva);
        }
        else if (!read_pointer_remote(pid, base_array_va + static_cast<std::uint64_t>(i) * layout.pointer_size, layout.pointer_size, base_desc_va))
        {
            break;
        }
        if (base_desc_va == 0)
            continue;
        std::uint64_t td_va = 0;
        if (col.relative)
        {
            std::int32_t td_rva = 0;
            if (!read_i32(pid, base_desc_va, td_rva))
                continue;
            td_va = rva_to_va(layout.module, td_rva);
        }
        else if (!read_pointer_remote(pid, base_desc_va, layout.pointer_size, td_va))
        {
            continue;
        }
        if (td_va == 0)
            continue;
        std::string decorated;
        if (!read_type_descriptor_name(pid, layout, td_va, decorated))
            continue;
        base_class_record_t record;
        record.name = undecorate_rtti_name(decorated);
        record.decorated_name = decorated;
        record.type_descriptor_va = td_va;
        record.base_descriptor_va = base_desc_va;
        read_i32(pid, base_desc_va + 8, record.mdisp);
        read_i32(pid, base_desc_va + 12, record.pdisp);
        read_i32(pid, base_desc_va + 16, record.vdisp);
        read_u32(pid, base_desc_va + 20, record.attributes);
        bases.names.push_back(record.name);
        bases.records.push_back(std::move(record));
    }
    return bases;
}

void apply_base_classes(type_info_t& type, base_classes_result_t bases)
{
    if (!bases.names.empty() || type.base_classes.empty())
        type.base_classes = std::move(bases.names);
    if (!bases.records.empty() || type.base_class_records.empty())
        type.base_class_records = std::move(bases.records);
}

void add_col_record(type_info_t& type, const col_info_t& col)
{
    for (const auto& existing : type.cols)
    {
        if (existing.complete_object_locator_va == col.col_va)
            return;
    }
    col_record_t record;
    record.complete_object_locator_va = col.col_va;
    record.hierarchy_descriptor_va = col.hierarchy_descriptor_va;
    record.signature = col.signature;
    record.relative = col.relative;
    record.self_consistent = col.self_consistent;
    record.legacy_absolute = col.legacy_absolute;
    record.confidence = col.confidence;
    type.cols.push_back(std::move(record));
    if (col.score > type.best_col_score)
    {
        type.best_col_score = col.score;
        type.col_va = col.col_va;
        type.hierarchy_descriptor_va = col.hierarchy_descriptor_va;
    }
}

bool validate_vtable(std::uint32_t pid,
                     const module_layout_t& layout,
                     std::uint64_t vtable_va,
                     vtable_record_t& out)
{
    out = {};
    if (vtable_va == 0 || layout.pointer_size == 0)
        return false;
    constexpr std::size_t max_slots = 8;
    for (std::size_t i = 0; i < max_slots; ++i)
    {
        std::uint64_t target = 0;
        if (!read_pointer_remote(pid, vtable_va + static_cast<std::uint64_t>(i) * layout.pointer_size, layout.pointer_size, target))
            break;
        if (target == 0)
            continue;
        ++out.sampled_slots;
        driver_bridge::memory_region_t region{};
        if (!query_region(pid, target, region))
            continue;
        if (is_readable(region) || is_executable(region))
            ++out.readable_slots;
        if (is_executable(region))
            ++out.executable_slots;
    }
    if (out.executable_slots == 0)
        return false;
    if (out.readable_slots == 0)
        return false;
    out.confidence = out.executable_slots >= 2 ? "high" : "medium";
    out.score = static_cast<int>(out.executable_slots * 10 + out.readable_slots);
    return true;
}

void add_vtable_record(type_info_t& type, const vtable_record_t& record)
{
    for (const auto& existing : type.vtables)
    {
        if (existing.vtable_va == record.vtable_va && existing.complete_object_locator_va == record.complete_object_locator_va)
            return;
    }
    type.vtables.push_back(record);
    if (record.score > type.best_vtable_score)
    {
        type.best_vtable_score = record.score;
        type.vtable_va = record.vtable_va;
        if (record.complete_object_locator_va != 0 && type.col_va == 0)
            type.col_va = record.complete_object_locator_va;
    }
}

void merge_type_info(type_info_t& dst, const type_info_t& src)
{
    if (dst.name.empty())
        dst.name = src.name;
    if (dst.decorated_name.empty())
        dst.decorated_name = src.decorated_name;
    if (dst.type_descriptor_va == 0)
        dst.type_descriptor_va = src.type_descriptor_va;
    if (dst.module_name.empty())
        dst.module_name = src.module_name;
    for (const auto& col : src.cols)
    {
        bool exists = false;
        for (const auto& existing : dst.cols)
        {
            if (existing.complete_object_locator_va == col.complete_object_locator_va)
            {
                exists = true;
                break;
            }
        }
        if (!exists)
            dst.cols.push_back(col);
    }
    for (const auto& vt : src.vtables)
        add_vtable_record(dst, vt);
    if ((src.best_col_score > dst.best_col_score) || dst.col_va == 0)
    {
        dst.best_col_score = src.best_col_score;
        dst.col_va = src.col_va;
        dst.hierarchy_descriptor_va = src.hierarchy_descriptor_va;
    }
    if ((src.best_vtable_score > dst.best_vtable_score) || dst.vtable_va == 0)
    {
        dst.best_vtable_score = src.best_vtable_score;
        dst.vtable_va = src.vtable_va;
    }
    if (dst.base_classes.empty() && !src.base_classes.empty())
        dst.base_classes = src.base_classes;
    if (dst.base_class_records.empty() && !src.base_class_records.empty())
        dst.base_class_records = src.base_class_records;
}

type_resolution_record_t type_resolution_record_from(const type_info_t& type)
{
    type_resolution_record_t out;
    out.name = type.name;
    out.decorated_name = type.decorated_name;
    out.type_descriptor_va = type.type_descriptor_va;
    out.vtable_va = type.vtable_va;
    out.hierarchy_descriptor_va = type.hierarchy_descriptor_va;
    out.vtables = type.vtables;
    out.base_classes = type.base_classes;
    out.base_class_records = type.base_class_records;
    out.module_name = type.module_name;
    return out;
}

std::vector<type_resolution_record_t> build_type_index(const std::vector<type_info_t>& types)
{
    std::vector<type_resolution_record_t> out;
    out.reserve(types.size());
    for (const auto& type : types)
        out.push_back(type_resolution_record_from(type));
    return out;
}

const type_resolution_record_t* find_type_in_index(const std::vector<type_resolution_record_t>& index,
                                                   const base_class_record_t* base,
                                                   const std::string& fallback_name)
{
    if (base && base->type_descriptor_va != 0)
    {
        for (const auto& item : index)
        {
            if (item.type_descriptor_va == base->type_descriptor_va)
                return &item;
        }
    }
    const std::string name = lower_ascii(base && !base->name.empty() ? base->name : fallback_name);
    const std::string decorated = lower_ascii(base ? base->decorated_name : std::string());
    if (name.empty() && decorated.empty())
        return nullptr;
    for (const auto& item : index)
    {
        if (!name.empty() && lower_ascii(item.name) == name)
            return &item;
        if (!decorated.empty() && lower_ascii(item.decorated_name) == decorated)
            return &item;
    }
    return nullptr;
}

json vtable_records_json(const type_resolution_record_t& item, std::size_t max_vtables)
{
    json out = json::array();
    std::size_t emitted = 0;
    for (const auto& vt : item.vtables)
    {
        if (emitted >= max_vtables)
            break;
        json row;
        row["vtable_va"] = sa_format_address(vt.vtable_va);
        row["complete_object_locator_va"] = vt.complete_object_locator_va ? json(sa_format_address(vt.complete_object_locator_va)) : json(nullptr);
        row["confidence"] = vt.confidence;
        out.push_back(std::move(row));
        ++emitted;
    }
    return out;
}

std::string mro_visit_key(const type_resolution_record_t& item)
{
    if (item.type_descriptor_va != 0)
        return "td:" + sa_format_address(item.type_descriptor_va);
    if (!item.decorated_name.empty())
        return "decorated:" + lower_ascii(item.decorated_name);
    return "name:" + lower_ascii(item.name);
}

void append_mro_entries(json& out,
                        const type_resolution_record_t& item,
                        const std::vector<type_resolution_record_t>& index,
                        std::set<std::string>& visited,
                        std::size_t depth,
                        std::size_t max_depth,
                        std::size_t max_vtables_per_type,
                        std::size_t& unresolved)
{
    if (depth > max_depth)
        return;
    const std::string key = mro_visit_key(item);
    if (!visited.insert(key).second)
        return;
    json row;
    row["depth"] = depth;
    row["name"] = item.name;
    row["decorated_name"] = item.decorated_name.empty() ? json(nullptr) : json(item.decorated_name);
    row["type_descriptor_va"] = item.type_descriptor_va ? json(sa_format_address(item.type_descriptor_va)) : json(nullptr);
    row["vtable_va"] = item.vtable_va ? json(sa_format_address(item.vtable_va)) : json(nullptr);
    row["vtables"] = vtable_records_json(item, max_vtables_per_type);
    row["module_name"] = item.module_name;
    row["depth_semantics"] = "recursive_raw_descriptor_walk_depth";
    row["base_descriptor_count"] = std::max(item.base_classes.size(), item.base_class_records.size());
    row["ordering_semantics"] = "msvc_chd_base_class_array_raw_descriptor_order";
    out.push_back(std::move(row));
    const std::size_t count = std::max(item.base_classes.size(), item.base_class_records.size());
    for (std::size_t i = 0; i < count; ++i)
    {
        const base_class_record_t* base = i < item.base_class_records.size() ? &item.base_class_records[i] : nullptr;
        const std::string fallback_name = i < item.base_classes.size() ? item.base_classes[i] : std::string();
        const auto* parent = find_type_in_index(index, base, fallback_name);
        if (!parent)
        {
            ++unresolved;
            continue;
        }
        append_mro_entries(out, *parent, index, visited, depth + 1, max_depth, max_vtables_per_type, unresolved);
    }
}

void attach_hierarchy(json& out,
                      const type_info_t& type,
                      const std::vector<type_resolution_record_t>& index,
                      std::size_t max_vtables_per_type)
{
    json hierarchy = json::array();
    std::size_t unresolved = 0;
    const std::size_t count = std::max(type.base_classes.size(), type.base_class_records.size());
    for (std::size_t i = 0; i < count; ++i)
    {
        const base_class_record_t* base = i < type.base_class_records.size() ? &type.base_class_records[i] : nullptr;
        const std::string fallback_name = i < type.base_classes.size() ? type.base_classes[i] : std::string();
        const auto* parent = find_type_in_index(index, base, fallback_name);
        json row;
        row["order"] = i;
        row["order_semantics"] = "msvc_chd_base_class_array_raw_descriptor_order";
        row["relationship_precision"] = "base_descriptor_entry_not_direct_base_proof";
        row["name"] = base && !base->name.empty() ? base->name : fallback_name;
        row["decorated_name"] = base && !base->decorated_name.empty() ? json(base->decorated_name) : json(nullptr);
        row["type_descriptor_va"] = base && base->type_descriptor_va ? json(sa_format_address(base->type_descriptor_va)) :
            (parent && parent->type_descriptor_va ? json(sa_format_address(parent->type_descriptor_va)) : json(nullptr));
        row["base_descriptor_va"] = base && base->base_descriptor_va ? json(sa_format_address(base->base_descriptor_va)) : json(nullptr);
        row["mdisp"] = base ? base->mdisp : 0;
        row["pdisp"] = base ? base->pdisp : 0;
        row["vdisp"] = base ? base->vdisp : 0;
        row["attributes"] = base ? json(sa_format_address(base->attributes)) : json(nullptr);
        if (parent && parent->vtable_va != 0)
        {
            row["vtable_va"] = sa_format_address(parent->vtable_va);
            row["vtables"] = vtable_records_json(*parent, max_vtables_per_type);
            row["vtable_resolution"] = "validated_parent_type";
        }
        else
        {
            row["vtable_va"] = nullptr;
            row["vtables"] = json::array();
            ++unresolved;
            if (parent)
                row["vtable_resolution"] = "parent_type_found_without_validated_vtable";
            else if (base && base->type_descriptor_va != 0)
                row["vtable_resolution"] = "base_type_descriptor_found_but_parent_type_not_in_scan_scope";
            else if (type.hierarchy_descriptor_va == 0)
                row["vtable_resolution"] = "hierarchy_descriptor_unresolved";
            else
                row["vtable_resolution"] = "base_record_missing_type_descriptor";
        }
        hierarchy.push_back(std::move(row));
    }
    out["hierarchy"] = std::move(hierarchy);
    out["hierarchy_count"] = count;
    out["hierarchy_unresolved_vtable_count"] = unresolved;
    out["hierarchy_ordering_semantics"] = "msvc_chd_base_class_array_raw_descriptor_order";
    out["hierarchy_relationship_precision"] = "raw_base_descriptor_entries_not_verified_direct_base_graph";
    if (count == 0)
        out["hierarchy_resolution"] = type.hierarchy_descriptor_va == 0 ? "hierarchy_descriptor_unresolved" : "no_base_classes_reported";
    else if (unresolved == 0)
        out["hierarchy_resolution"] = "raw_descriptor_order_complete";
    else
        out["hierarchy_resolution"] = "raw_descriptor_order_partial";
    type_resolution_record_t root = type_resolution_record_from(type);
    json mro = json::array();
    std::set<std::string> visited;
    std::size_t mro_unresolved = 0;
    append_mro_entries(mro, root, index, visited, 0, 16, max_vtables_per_type, mro_unresolved);
    out["mro"] = std::move(mro);
    out["mro_count"] = out["mro"].size();
    out["mro_unresolved_base_count"] = mro_unresolved;
    out["mro_semantics"] = "compatibility_field_recursive_raw_descriptor_walk_not_canonical_cxx_mro";
    out["hierarchy_shape"] = {
        {"base_descriptor_count", count},
        {"base_descriptor_unresolved_vtable_count", unresolved},
        {"mro_count", out["mro_count"]},
        {"mro_unresolved_base_count", mro_unresolved},
        {"ordering_semantics", "msvc_chd_base_class_array_raw_descriptor_order"}
    };
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
    module_layout_t layout;
    if (!load_module_layout(pid, module, layout) || layout.pointer_size == 0)
        return false;
    if (vtable_va < layout.pointer_size)
        return false;
    std::uint64_t col_va = 0;
    if (!read_pointer_remote(pid, vtable_va - layout.pointer_size, layout.pointer_size, col_va) || col_va == 0)
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable col_read_failed pid=%u vtable=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    if (!readable_address(pid, col_va))
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable col_unreadable pid=%u vtable=%s col=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             sa_format_address(col_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    col_info_t col{};
    std::string decorated;
    if (!read_col_info(pid, layout, col_va, col, &decorated))
    {
        diag::log_tagged_fmt("rtti",
                             "type_from_vtable invalid_col pid=%u vtable=%s col=%s elapsed_ms=%llu",
                             pid,
                             sa_format_address(vtable_va).c_str(),
                             sa_format_address(col_va).c_str(),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        return false;
    }
    out = {};
    out.decorated_name = decorated;
    out.name = undecorate_rtti_name(decorated);
    out.type_descriptor_va = col.type_descriptor_va;
    out.vtable_va = vtable_va;
    out.col_va = col_va;
    out.hierarchy_descriptor_va = col.hierarchy_descriptor_va;
    add_col_record(out, col);
    vtable_record_t vt;
    if (validate_vtable(pid, layout, vtable_va, vt))
    {
        vt.vtable_va = vtable_va;
        vt.complete_object_locator_va = col_va;
        add_vtable_record(out, vt);
    }
    apply_base_classes(out, read_base_classes(pid, layout, col, 64));
    out.module_name = module.name;
    diag::log_tagged_fmt("rtti",
                         "type_from_vtable exit pid=%u type=%s decorated=%s vtable=%s col=%s td=%s hierarchy=%s bases=%zu signature=%u relative=%d self_match=%d pointer_size=%u elapsed_ms=%llu",
                         pid,
                         out.name.c_str(),
                         out.decorated_name.c_str(),
                         sa_format_address(out.vtable_va).c_str(),
                         sa_format_address(out.col_va).c_str(),
                         sa_format_address(out.type_descriptor_va).c_str(),
                         sa_format_address(out.hierarchy_descriptor_va).c_str(),
                         out.base_classes.size(),
                         col.signature,
                         col.relative ? 1 : 0,
                         col.self_consistent ? 1 : 0,
                         layout.pointer_size,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return true;
}

bool type_from_col(std::uint32_t pid,
                   const driver_bridge::module_info_t& module,
                   std::uint64_t col_va,
                   type_info_t& out)
{
    module_layout_t layout;
    if (!load_module_layout(pid, module, layout) || layout.pointer_size == 0)
        return false;
    col_info_t col{};
    std::string decorated;
    if (!read_col_info(pid, layout, col_va, col, &decorated))
        return false;
    out = {};
    out.decorated_name = decorated;
    out.name = undecorate_rtti_name(decorated);
    out.type_descriptor_va = col.type_descriptor_va;
    out.col_va = col_va;
    out.hierarchy_descriptor_va = col.hierarchy_descriptor_va;
    out.module_name = module.name;
    add_col_record(out, col);
    apply_base_classes(out, read_base_classes(pid, layout, col, 64));
    return true;
}

bool type_from_type_descriptor(std::uint32_t pid,
                               const driver_bridge::module_info_t& module,
                               std::uint64_t type_descriptor_va,
                               type_info_t& out)
{
    module_layout_t layout;
    if (!load_module_layout(pid, module, layout) || layout.pointer_size == 0)
        return false;
    std::string decorated;
    if (!read_type_descriptor_name(pid, layout, type_descriptor_va, decorated))
        return false;
    out = {};
    out.decorated_name = decorated;
    out.name = undecorate_rtti_name(decorated);
    out.type_descriptor_va = type_descriptor_va;
    out.module_name = module.name;
    return true;
}

std::vector<type_info_t> scan_module(rtti_scan_context_t& ctx,
                                     const driver_bridge::module_info_t& module,
                                     bool deep_scan,
                                     std::size_t max_unfiltered)
{
    std::vector<type_info_t> out;
    json module_diag;
    module_diag["name"] = !module.name.empty() ? module.name : module.path;
    module_diag["path"] = module.path;
    module_diag["base"] = sa_format_address(module.base);
    module_diag["size"] = module.size;
    module_diag["priority"] = module_scan_priority(module);
    module_diag["system"] = is_system_module_path(module);
    const std::uint64_t module_started_ms = GetTickCount64();
    ++ctx.scanned_module_count;
    module_layout_t layout;
    if (!load_module_layout(ctx.pid, module, layout))
    {
        module_diag["loaded_layout"] = false;
        module_diag["elapsed_ms"] = GetTickCount64() - module_started_ms;
        ctx.scanned_modules.push_back(std::move(module_diag));
        return out;
    }
    module_diag["loaded_layout"] = true;
    module_diag["machine"] = sa_format_address(layout.machine);
    module_diag["optional_magic"] = sa_format_address(layout.optional_magic);
    module_diag["is_pe32_plus"] = layout.is_pe32_plus;
    module_diag["pointer_size"] = layout.pointer_size;
    module_diag["section_count"] = layout.sections.size();
    auto sections = rdata_sections(layout, deep_scan);
    module_diag["candidate_section_count"] = sections.size();
    std::map<std::uint64_t, type_info_t> by_td;
    std::map<std::uint64_t, std::vector<std::uint8_t>> section_bytes;
    std::uint64_t module_bytes_scanned = 0;
    auto bytes_for_section = [&](const module_section_t& section) -> const std::vector<std::uint8_t>* {
        if (ctx.stop("rtti_section_read"))
            return nullptr;
        auto found = section_bytes.find(section.va);
        if (found != section_bytes.end())
            return &found->second;
        if (section.size == 0 || section.size > 64ull * 1024ull * 1024ull)
            return nullptr;
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(ctx.pid, section.va, static_cast<std::size_t>(section.size), bytes))
            return nullptr;
        if (ctx.stop("rtti_section_read_complete"))
            return nullptr;
        ctx.bytes_scanned += bytes.size();
        module_bytes_scanned += bytes.size();
        auto inserted = section_bytes.emplace(section.va, std::move(bytes));
        return &inserted.first->second;
    };
    auto ensure_type = [&](std::uint64_t td_va, const std::string& decorated) -> type_info_t& {
        auto found = by_td.find(td_va);
        if (found != by_td.end())
            return found->second;
        type_info_t info;
        info.name = undecorate_rtti_name(decorated);
        info.decorated_name = decorated;
        info.type_descriptor_va = td_va;
        info.module_name = module.name;
        auto inserted = by_td.emplace(td_va, std::move(info));
        return inserted.first->second;
    };
    auto add_col_to_type = [&](const col_info_t& col, const std::string& decorated) {
        type_info_t& info = ensure_type(col.type_descriptor_va, decorated);
        const std::size_t before = info.cols.size();
        add_col_record(info, col);
        if (info.cols.size() != before)
            apply_base_classes(info, read_base_classes(ctx.pid, layout, col, 64));
    };
    const std::size_t name_offset = type_descriptor_name_offset(layout);
    for (const auto& section : sections)
    {
        if (ctx.stop("rtti_type_descriptor_sections"))
            break;
        const auto* bytes_ptr = bytes_for_section(section);
        if (!bytes_ptr || bytes_ptr->size() < name_offset + 8)
            continue;
        const auto& bytes = *bytes_ptr;
        for (std::size_t i = name_offset; i + 8 < bytes.size(); ++i)
        {
            if ((i & 0xFFFu) == 0 && ctx.stop("rtti_type_descriptor_scan"))
                break;
            if (by_td.size() >= max_unfiltered)
                break;
            if (!valid_rtti_prefix(bytes, i))
                continue;
            std::string decorated;
            if (!read_c_string_from_buffer(bytes, i, decorated))
                continue;
            const std::uint64_t td_va = section.va + i - name_offset;
            std::uint64_t typeinfo_vftable = 0;
            read_pointer_from_buffer(bytes, i - name_offset, layout.pointer_size, typeinfo_vftable);
            if (typeinfo_vftable != 0 && !readable_address(ctx.pid, typeinfo_vftable))
                continue;
            ensure_type(td_va, decorated);
        }
        if (ctx.stop("rtti_type_descriptor_sections") || by_td.size() >= max_unfiltered)
            break;
    }

    std::map<std::uint32_t, std::uint64_t> td_reference_values;
    for (const auto& [td_va, info] : by_td)
    {
        (void)info;
        if (layout.pointer_size == 8)
        {
            if (td_va >= layout.module.base)
            {
                const std::uint64_t rva = td_va - layout.module.base;
                if (rva <= std::numeric_limits<std::uint32_t>::max())
                    td_reference_values[static_cast<std::uint32_t>(rva)] = td_va;
            }
        }
        else if (td_va <= std::numeric_limits<std::uint32_t>::max())
        {
            td_reference_values[static_cast<std::uint32_t>(td_va)] = td_va;
        }
    }

    std::size_t col_count_before_fallback = 0;
    for (const auto& section : sections)
    {
        if (td_reference_values.empty() || ctx.stop("rtti_col_reference_sections"))
            break;
        const auto* bytes_ptr = bytes_for_section(section);
        if (!bytes_ptr || bytes_ptr->size() < 24)
            continue;
        const auto& bytes = *bytes_ptr;
        for (std::size_t i = 0; i + 4 <= bytes.size(); i += 4)
        {
            if ((i & 0xFFFu) == 0 && ctx.stop("rtti_col_reference_scan"))
                break;
            std::uint32_t value = 0;
            std::memcpy(&value, bytes.data() + i, sizeof(value));
            auto td_ref = td_reference_values.find(value);
            if (td_ref == td_reference_values.end() || i < 12)
                continue;
            const std::size_t col_offset = i - 12;
            if (col_offset + 20 > bytes.size())
                continue;
            col_info_t col{};
            std::string decorated;
            const std::uint64_t col_va = section.va + col_offset;
            if (!parse_col_from_bytes(ctx.pid, layout, col_va, bytes.data() + col_offset, bytes.size() - col_offset, col, &decorated))
                continue;
            add_col_to_type(col, decorated);
        }
        if (ctx.stop("rtti_col_reference_sections"))
            break;
    }

    for (const auto& [td, info] : by_td)
    {
        (void)td;
        col_count_before_fallback += info.cols.size();
    }

    const bool run_direct_col_scan = deep_scan || by_td.empty() || col_count_before_fallback == 0 || col_count_before_fallback * 2 < by_td.size();
    if (run_direct_col_scan)
    {
        for (const auto& section : sections)
        {
            if (ctx.stop("rtti_direct_col_sections"))
                break;
            const auto* bytes_ptr = bytes_for_section(section);
            if (!bytes_ptr || bytes_ptr->size() < 20)
                continue;
            const auto& bytes = *bytes_ptr;
            for (std::size_t i = 0; i + 20 <= bytes.size(); i += 4)
            {
                if ((i & 0xFFFu) == 0 && ctx.stop("rtti_direct_col_scan"))
                    break;
                if (by_td.size() >= max_unfiltered && !deep_scan)
                    break;
                col_info_t col{};
                std::string decorated;
                const std::uint64_t col_va = section.va + i;
                if (!parse_col_from_bytes(ctx.pid, layout, col_va, bytes.data() + i, bytes.size() - i, col, &decorated))
                    continue;
                add_col_to_type(col, decorated);
            }
            if (ctx.stop("rtti_direct_col_sections") || (by_td.size() >= max_unfiltered && !deep_scan))
                break;
        }
    }

    std::map<std::uint64_t, std::uint64_t> col_to_td;
    for (const auto& [td, info] : by_td)
    {
        for (const auto& col : info.cols)
            col_to_td[col.complete_object_locator_va] = td;
    }
    if (!col_to_td.empty())
    {
        for (const auto& section : sections)
        {
            if (ctx.stop("rtti_vtable_sections"))
                break;
            const auto* bytes_ptr = bytes_for_section(section);
            if (!bytes_ptr || bytes_ptr->size() < layout.pointer_size)
                continue;
            const auto& bytes = *bytes_ptr;
            for (std::size_t i = 0; i + layout.pointer_size <= bytes.size(); i += layout.pointer_size)
            {
                if ((i & 0xFFFu) == 0 && ctx.stop("rtti_vtable_scan"))
                    break;
                std::uint64_t value = 0;
                if (!read_pointer_from_buffer(bytes, i, layout.pointer_size, value))
                    continue;
                auto col_it = col_to_td.find(value);
                if (col_it == col_to_td.end())
                    continue;
                const std::uint64_t vtable_va = section.va + i + layout.pointer_size;
                vtable_record_t record;
                if (!validate_vtable(ctx.pid, layout, vtable_va, record))
                    continue;
                record.vtable_va = vtable_va;
                record.complete_object_locator_va = value;
                auto td_it = by_td.find(col_it->second);
                if (td_it != by_td.end())
                    add_vtable_record(td_it->second, record);
            }
            if (ctx.stop("rtti_vtable_sections"))
                break;
        }
    }

    std::size_t module_col_count = 0;
    std::size_t module_vtable_count = 0;
    for (auto& [td, info] : by_td)
    {
        (void)td;
        module_col_count += info.cols.size();
        module_vtable_count += info.vtables.size();
        out.push_back(std::move(info));
    }
    std::sort(out.begin(), out.end(), [](const type_info_t& a, const type_info_t& b) {
        return a.name < b.name;
    });
    ctx.type_descriptor_count += by_td.size();
    ctx.complete_object_locator_count += module_col_count;
    ctx.vtable_count += module_vtable_count;
    module_diag["type_descriptor_count"] = by_td.size();
    module_diag["complete_object_locator_count"] = module_col_count;
    module_diag["vtable_count"] = module_vtable_count;
    module_diag["bytes_scanned"] = module_bytes_scanned;
    module_diag["deadline_hit"] = ctx.deadline_hit;
    module_diag["cancelled"] = ctx.cancelled;
    module_diag["stop_stage"] = ctx.stop_stage;
    module_diag["elapsed_ms"] = GetTickCount64() - module_started_ms;
    ctx.scanned_modules.push_back(std::move(module_diag));
    return out;
}

bool type_has_col(const type_info_t& type, std::uint64_t col_va)
{
    if (col_va == 0)
        return true;
    for (const auto& col : type.cols)
    {
        if (col.complete_object_locator_va == col_va)
            return true;
    }
    return false;
}

bool type_matches_filter(const type_info_t& type, const std::optional<std::regex>& filter)
{
    if (!filter)
        return true;
    return std::regex_search(type.name, *filter) || std::regex_search(type.decorated_name, *filter);
}

std::string json_value_preview(const json& value)
{
    if (value.is_string())
        return value.get<std::string>();
    return value.dump();
}

bool parse_address_selector(const json& params,
                            const char* first_key,
                            const char* second_key,
                            std::uint64_t& out,
                            bool& provided,
                            std::string& used_key,
                            std::string& provided_value,
                            std::string& error)
{
    provided = false;
    used_key.clear();
    provided_value.clear();
    error.clear();
    auto parse_one = [&](const char* key) -> bool {
        if (!key || !params.contains(key))
            return false;
        provided = true;
        used_key = key;
        provided_value = json_value_preview(params[key]);
        if (!parse_u64_value(params[key], out))
            error = std::string("Invalid RTTI address selector '") + key + "'.";
        return true;
    };
    if (parse_one(first_key))
        return error.empty();
    if (parse_one(second_key))
        return error.empty();
    return true;
}

json module_sample_json(const std::vector<driver_bridge::module_info_t>& modules, std::size_t limit)
{
    json sample = json::array();
    for (const auto& module : modules)
    {
        if (sample.size() >= limit)
            break;
        sample.push_back(module_json(module));
    }
    return sample;
}

json selector_failure_details(std::uint32_t pid,
                              const std::string& selector_kind,
                              const std::string& selector_key,
                              const std::string& selector_value,
                              const std::string& module_name,
                              const std::string& module_filter,
                              bool include_system_modules,
                              std::uint64_t module_limit,
                              const std::vector<driver_bridge::module_info_t>& available_modules)
{
    json details;
    details["process_id"] = pid;
    details["selector_kind"] = selector_kind;
    details["selector_key"] = selector_key;
    details["selector_value"] = selector_value;
    details["module_name"] = module_name;
    details["module_filter"] = module_filter;
    details["include_system_modules"] = include_system_modules;
    details["module_limit"] = module_limit;
    details["available_module_count"] = available_modules.size();
    details["available_modules_sample"] = module_sample_json(available_modules, 24);
    return details;
}

scan_result_t scan_types(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    scan_result_t result;
    active_process_scope_t scope(params);
    if (!scope.ok())
    {
        result.error = scope.error();
        result.elapsed_ms = GetTickCount64() - started_ms;
        return result;
    }
    result.pid = scope.pid();
    if (params.contains("filter") && !params["filter"].is_string())
    {
        result.error = "Invalid RTTI filter: 'filter' must be a regular expression string.";
        result.error_details = json{{"filter_value", json_value_preview(params["filter"])}};
        result.elapsed_ms = GetTickCount64() - started_ms;
        return result;
    }
    if (params.contains("module_filter") && !params["module_filter"].is_string())
    {
        result.error = "Invalid RTTI module_filter: expected a string.";
        result.error_details = json{{"module_filter_value", json_value_preview(params["module_filter"])}};
        result.elapsed_ms = GetTickCount64() - started_ms;
        return result;
    }
    if (params.contains("module_name") && !params["module_name"].is_string())
    {
        result.error = "Invalid RTTI module_name: expected a string.";
        result.error_details = json{{"module_name_value", json_value_preview(params["module_name"])}};
        result.elapsed_ms = GetTickCount64() - started_ms;
        return result;
    }
    const std::string module_name = string_param(params, "module_name");
    const std::string filter_text = string_param(params, "filter");
    const std::string module_filter = lower_ascii(trim_ascii(string_param(params, "module_filter")));
    const bool include_system_modules = bool_param(params, "include_system_modules", false);
    std::string scan_mode = lower_ascii(trim_ascii(string_param(params, "scan_mode", "fast")));
    if (scan_mode != "deep")
        scan_mode = "fast";
    const bool deep_scan = scan_mode == "deep";
    const std::size_t max_results = static_cast<std::size_t>(numeric_param(params, "max_results", 2000, 1, 20000));
    const std::uint64_t timeout_ms = numeric_param(params, "timeout_ms", deep_scan ? 30000 : 5500, 500, 120000);
    const std::uint64_t module_limit = numeric_param(params, "module_limit", 0, 0, 4096);
    auto fail_scan = [&](const std::string& message, json details = json::object()) -> scan_result_t {
        result.ok = false;
        result.error = message;
        result.filter = filter_text;
        result.module_filter = module_filter;
        result.scan_mode = scan_mode;
        result.timeout_ms = timeout_ms;
        result.elapsed_ms = GetTickCount64() - started_ms;
        result.error_details = std::move(details);
        return result;
    };
    std::optional<std::regex> filter;
    if (!filter_text.empty())
    {
        try
        {
            filter.emplace(filter_text, std::regex::icase);
        }
        catch (const std::regex_error& e)
        {
            return fail_scan("Invalid RTTI filter regular expression.",
                json{{"filter", filter_text}, {"regex_error", e.what()}, {"regex_code", static_cast<int>(e.code())}});
        }
    }
    const std::uint64_t default_unfiltered_cap = deep_scan ?
        std::max<std::uint64_t>(12000, static_cast<std::uint64_t>(max_results) * 24ull) :
        std::max<std::uint64_t>(4096, static_cast<std::uint64_t>(max_results) * 16ull);
    const std::size_t max_unfiltered = static_cast<std::size_t>(numeric_param(params, "max_unfiltered_types", default_unfiltered_cap, max_results, 100000));
    std::vector<driver_bridge::module_info_t> modules;
    std::uint64_t module_base = 0;
    std::uint64_t exact_type_descriptor_va = 0;
    std::uint64_t exact_col_va = 0;
    std::uint64_t hint_va = 0;
    std::uint64_t vtable_hint_va = 0;
    bool module_base_provided = false;
    bool exact_type_descriptor_provided = false;
    bool exact_col_provided = false;
    bool vtable_hint_provided = false;
    bool hint_provided = false;
    std::string module_base_key;
    std::string exact_type_descriptor_key;
    std::string exact_col_key;
    std::string vtable_hint_key;
    std::string hint_key;
    std::string module_base_value;
    std::string exact_type_descriptor_value;
    std::string exact_col_value;
    std::string vtable_hint_value;
    std::string hint_value;
    std::string address_error;
    if (!parse_address_selector(params, "module_base_va", "module_base", module_base, module_base_provided, module_base_key, module_base_value, address_error))
        return fail_scan(address_error, json{{"selector_key", module_base_key}, {"selector_value", module_base_value}});
    if (!module_base_provided && !parse_address_selector(params, "rtti_module_base_va", nullptr, module_base, module_base_provided, module_base_key, module_base_value, address_error))
        return fail_scan(address_error, json{{"selector_key", module_base_key}, {"selector_value", module_base_value}});
    if (!parse_address_selector(params, "type_descriptor_va", "type_va", exact_type_descriptor_va, exact_type_descriptor_provided, exact_type_descriptor_key, exact_type_descriptor_value, address_error))
        return fail_scan(address_error, json{{"selector_key", exact_type_descriptor_key}, {"selector_value", exact_type_descriptor_value}});
    if (!exact_type_descriptor_provided && !parse_address_selector(params, "rtti_type_descriptor_va", nullptr, exact_type_descriptor_va, exact_type_descriptor_provided, exact_type_descriptor_key, exact_type_descriptor_value, address_error))
        return fail_scan(address_error, json{{"selector_key", exact_type_descriptor_key}, {"selector_value", exact_type_descriptor_value}});
    if (!parse_address_selector(params, "complete_object_locator_va", "col_va", exact_col_va, exact_col_provided, exact_col_key, exact_col_value, address_error))
        return fail_scan(address_error, json{{"selector_key", exact_col_key}, {"selector_value", exact_col_value}});
    if (!exact_col_provided && !parse_address_selector(params, "rtti_complete_object_locator_va", nullptr, exact_col_va, exact_col_provided, exact_col_key, exact_col_value, address_error))
        return fail_scan(address_error, json{{"selector_key", exact_col_key}, {"selector_value", exact_col_value}});
    if (!parse_address_selector(params, "vtable_va", nullptr, vtable_hint_va, vtable_hint_provided, vtable_hint_key, vtable_hint_value, address_error))
        return fail_scan(address_error, json{{"selector_key", vtable_hint_key}, {"selector_value", vtable_hint_value}});
    if (!vtable_hint_provided && !parse_address_selector(params, "rtti_vtable_va", nullptr, vtable_hint_va, vtable_hint_provided, vtable_hint_key, vtable_hint_value, address_error))
        return fail_scan(address_error, json{{"selector_key", vtable_hint_key}, {"selector_value", vtable_hint_value}});
    if (!parse_address_selector(params, "hint_va", nullptr, hint_va, hint_provided, hint_key, hint_value, address_error))
        return fail_scan(address_error, json{{"selector_key", hint_key}, {"selector_value", hint_value}});
    const bool has_exact_type_descriptor = exact_type_descriptor_provided;
    const bool has_exact_col = exact_col_provided;
    const bool has_vtable_hint = vtable_hint_provided && vtable_hint_va != 0;
    const bool exact_selector_fast_path = (has_vtable_hint || has_exact_type_descriptor || has_exact_col) && !deep_scan;
    std::vector<driver_bridge::module_info_t> available_modules;
    bool available_modules_loaded = false;
    auto load_available_modules = [&]() -> const std::vector<driver_bridge::module_info_t>& {
        if (!available_modules_loaded)
        {
            available_modules = modules_for(scope.pid());
            available_modules_loaded = true;
        }
        return available_modules;
    };
    auto find_available_by_base = [&](std::uint64_t base) -> std::optional<driver_bridge::module_info_t> {
        if (base == 0)
            return std::nullopt;
        for (const auto& module : load_available_modules())
        {
            if (module.base == base)
                return module;
        }
        return std::nullopt;
    };
    auto find_available_for_address = [&](std::uint64_t address) -> std::optional<driver_bridge::module_info_t> {
        for (const auto& module : load_available_modules())
        {
            const std::uint64_t end = module.base + static_cast<std::uint64_t>(module.size);
            if (module.base != 0 && address >= module.base && address < end)
                return module;
        }
        return std::nullopt;
    };
    auto find_available_by_name = [&](const std::string& name) -> std::optional<driver_bridge::module_info_t> {
        const std::string wanted = lower_ascii(name);
        for (const auto& module : load_available_modules())
        {
            if (lower_ascii(module.name) == wanted)
                return module;
            if (!module.path.empty())
            {
                std::filesystem::path path(module.path);
                if (lower_ascii(path.filename().string()) == wanted)
                    return module;
            }
        }
        return std::nullopt;
    };
    auto fail_module_selector = [&](const std::string& message,
                                    const std::string& selector_kind,
                                    const std::string& selector_key,
                                    const std::string& selector_value) -> scan_result_t {
        return fail_scan(message, selector_failure_details(scope.pid(),
                                                           selector_kind,
                                                           selector_key,
                                                           selector_value,
                                                           module_name,
                                                           module_filter,
                                                           include_system_modules,
                                                           module_limit,
                                                           load_available_modules()));
    };
    bool explicit_module = false;
    if (module_base_provided)
    {
        explicit_module = true;
        if (auto module = find_available_by_base(module_base))
            modules.push_back(*module);
        else
            return fail_module_selector("RTTI module selector did not resolve a loaded module.", "module_base", module_base_key, module_base_value);
    }
    else if (vtable_hint_provided || exact_type_descriptor_provided || exact_col_provided || hint_provided)
    {
        explicit_module = true;
        std::string selector_kind;
        std::string selector_key;
        std::string selector_value;
        if (vtable_hint_provided && vtable_hint_va != 0)
        {
            hint_va = vtable_hint_va;
            selector_kind = "vtable_hint";
            selector_key = vtable_hint_key;
            selector_value = vtable_hint_value;
        }
        else if (exact_type_descriptor_provided && exact_type_descriptor_va != 0)
        {
            hint_va = exact_type_descriptor_va;
            selector_kind = "type_descriptor_hint";
            selector_key = exact_type_descriptor_key;
            selector_value = exact_type_descriptor_value;
        }
        else if (exact_col_provided && exact_col_va != 0)
        {
            hint_va = exact_col_va;
            selector_kind = "complete_object_locator_hint";
            selector_key = exact_col_key;
            selector_value = exact_col_value;
        }
        else if (hint_provided)
        {
            selector_kind = "hint_va";
            selector_key = hint_key;
            selector_value = hint_value;
        }
        else if (vtable_hint_provided)
        {
            hint_va = vtable_hint_va;
            selector_kind = "vtable_hint";
            selector_key = vtable_hint_key;
            selector_value = vtable_hint_value;
        }
        else if (exact_type_descriptor_provided)
        {
            hint_va = exact_type_descriptor_va;
            selector_kind = "type_descriptor_hint";
            selector_key = exact_type_descriptor_key;
            selector_value = exact_type_descriptor_value;
        }
        else
        {
            hint_va = exact_col_va;
            selector_kind = "complete_object_locator_hint";
            selector_key = exact_col_key;
            selector_value = exact_col_value;
        }
        if (auto module = find_available_for_address(hint_va))
            modules.push_back(*module);
        else
            return fail_module_selector("RTTI address selector did not resolve a loaded module.", selector_kind, selector_key, selector_value);
    }
    else if (!module_name.empty())
    {
        explicit_module = true;
        if (auto module = find_available_by_name(module_name))
            modules.push_back(*module);
        else
            return fail_module_selector("RTTI module_name selector did not resolve a loaded module.", "module_name", "module_name", module_name);
    }
    else
    {
        modules = load_available_modules();
        std::stable_sort(modules.begin(), modules.end(), [](const driver_bridge::module_info_t& a, const driver_bridge::module_info_t& b) {
            const int pa = module_scan_priority(a);
            const int pb = module_scan_priority(b);
            if (pa != pb)
                return pa < pb;
            return a.base < b.base;
        });
        modules.erase(std::remove_if(modules.begin(), modules.end(), [&](const driver_bridge::module_info_t& module) {
            if (!include_system_modules && is_system_module_path(module))
                return true;
            if (module_filter.empty())
                return false;
            const std::string name = lower_ascii(module.name);
            const std::string path = lower_ascii(module.path);
            return name.find(module_filter) == std::string::npos && path.find(module_filter) == std::string::npos;
        }), modules.end());
        if (module_limit != 0 && modules.size() > module_limit)
            modules.resize(static_cast<std::size_t>(module_limit));
        if (!module_filter.empty() && modules.empty())
            return fail_module_selector("RTTI module_filter matched no loaded modules.", "module_filter", "module_filter", module_filter);
    }
    result.ok = true;
    diag::log_tagged_fmt("rtti",
                         "scan_types enter pid=%u module_name=%s module_count=%zu explicit=%d filter=%s module_filter=%s include_system=%d scan_mode=%s max_results=%zu timeout_ms=%llu hint_va=%s elapsed_ms=%llu",
                         scope.pid(),
                         module_name.c_str(),
                         modules.size(),
                         explicit_module ? 1 : 0,
                         filter_text.c_str(),
                         module_filter.c_str(),
                         include_system_modules ? 1 : 0,
                         scan_mode.c_str(),
                         max_results,
                         static_cast<unsigned long long>(timeout_ms),
                         hint_va ? sa_format_address(hint_va).c_str() : "0x0",
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    rtti_scan_context_t ctx;
    ctx.pid = scope.pid();
    ctx.started_ms = started_ms;
    ctx.timeout_ms = timeout_ms;
    std::map<std::uint64_t, type_info_t> all_by_td;
    auto merge_found = [&](const type_info_t& type) {
        if (type.type_descriptor_va == 0)
            return;
        auto found = all_by_td.find(type.type_descriptor_va);
        if (found == all_by_td.end())
            all_by_td.emplace(type.type_descriptor_va, type);
        else
            merge_type_info(found->second, type);
    };
    bool exact_selector_direct_hit = false;
    if (has_vtable_hint)
    {
        if (auto module = find_module_for_address(scope.pid(), vtable_hint_va))
        {
            type_info_t hinted;
            if (type_from_vtable(scope.pid(), *module, vtable_hint_va, hinted))
            {
                merge_found(hinted);
                exact_selector_direct_hit = true;
            }
            else
            {
                return fail_scan("RTTI vtable_va selector did not resolve a valid RTTI type.",
                    selector_failure_details(scope.pid(),
                                             "vtable_hint",
                                             vtable_hint_key,
                                             vtable_hint_value,
                                             module_name,
                                             module_filter,
                                             include_system_modules,
                                             module_limit,
                                             load_available_modules()));
            }
        }
        else
        {
            return fail_module_selector("RTTI vtable_va selector did not resolve a loaded module.", "vtable_hint", vtable_hint_key, vtable_hint_value);
        }
    }
    if (has_exact_col)
    {
        if (ctx.stop("rtti_exact_col_selector"))
        {
            result.ok = false;
            result.deadline_hit = ctx.deadline_hit;
            result.cancelled = ctx.cancelled;
            result.partial = true;
            result.timeout_ms = timeout_ms;
            result.elapsed_ms = GetTickCount64() - started_ms;
            result.error = ctx.cancelled ? "RTTI exact COL selector cancelled." : "RTTI exact COL selector deadline reached.";
            return result;
        }
        if (auto module = find_module_for_address(scope.pid(), exact_col_va))
        {
            type_info_t exact;
            if (type_from_col(scope.pid(), *module, exact_col_va, exact))
            {
                merge_found(exact);
                exact_selector_direct_hit = true;
            }
            else
            {
                return fail_scan("RTTI complete_object_locator_va selector did not resolve a valid RTTI COL.",
                    selector_failure_details(scope.pid(),
                                             "complete_object_locator_hint",
                                             exact_col_key,
                                             exact_col_value,
                                             module_name,
                                             module_filter,
                                             include_system_modules,
                                             module_limit,
                                             load_available_modules()));
            }
        }
        else
        {
            return fail_module_selector("RTTI complete_object_locator_va selector did not resolve a loaded module.", "complete_object_locator_hint", exact_col_key, exact_col_value);
        }
    }
    if (has_exact_type_descriptor)
    {
        if (ctx.stop("rtti_exact_type_descriptor_selector"))
        {
            result.ok = false;
            result.deadline_hit = ctx.deadline_hit;
            result.cancelled = ctx.cancelled;
            result.partial = true;
            result.timeout_ms = timeout_ms;
            result.elapsed_ms = GetTickCount64() - started_ms;
            result.error = ctx.cancelled ? "RTTI exact TypeDescriptor selector cancelled." : "RTTI exact TypeDescriptor selector deadline reached.";
            return result;
        }
        if (auto module = find_module_for_address(scope.pid(), exact_type_descriptor_va))
        {
            type_info_t exact;
            if (type_from_type_descriptor(scope.pid(), *module, exact_type_descriptor_va, exact))
            {
                merge_found(exact);
                exact_selector_direct_hit = true;
            }
            else
            {
                return fail_scan("RTTI type_descriptor_va selector did not resolve a valid RTTI TypeDescriptor.",
                    selector_failure_details(scope.pid(),
                                             "type_descriptor_hint",
                                             exact_type_descriptor_key,
                                             exact_type_descriptor_value,
                                             module_name,
                                             module_filter,
                                             include_system_modules,
                                             module_limit,
                                             load_available_modules()));
            }
        }
        else
        {
            return fail_module_selector("RTTI type_descriptor_va selector did not resolve a loaded module.", "type_descriptor_hint", exact_type_descriptor_key, exact_type_descriptor_value);
        }
    }
    if (!(exact_selector_fast_path && exact_selector_direct_hit) || all_by_td.empty())
    {
    for (const auto& module : modules)
    {
        if (ctx.stop("rtti_module_loop"))
            break;
        const std::uint64_t module_started_ms = GetTickCount64();
        auto partial = scan_module(ctx, module, deep_scan || has_exact_col, max_unfiltered);
        diag::log_tagged_fmt("rtti",
                             "scan_types module pid=%u name=%s base=%s size=%llu priority=%d system=%d count=%zu elapsed_ms=%llu total_elapsed_ms=%llu",
                             scope.pid(),
                             (!module.name.empty() ? module.name : module.path).c_str(),
                             sa_format_address(module.base).c_str(),
                             static_cast<unsigned long long>(module.size),
                             module_scan_priority(module),
                             is_system_module_path(module) ? 1 : 0,
                             partial.size(),
                             static_cast<unsigned long long>(GetTickCount64() - module_started_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        for (const auto& type : partial)
            merge_found(type);
        if (all_by_td.size() >= max_unfiltered)
            break;
    }
    }
    std::vector<type_info_t> unfiltered;
    unfiltered.reserve(all_by_td.size());
    std::size_t unfiltered_build_count = 0;
    for (auto& [td, type] : all_by_td)
    {
        if ((unfiltered_build_count++ & 0xFFu) == 0 && ctx.stop("rtti_unfiltered_build"))
            break;
        (void)td;
        unfiltered.push_back(std::move(type));
    }
    std::sort(unfiltered.begin(), unfiltered.end(), [](const type_info_t& a, const type_info_t& b) {
        return a.name < b.name;
    });
    result.type_index = build_type_index(unfiltered);
    result.unfiltered_type_count = unfiltered.size();
    std::size_t result_filter_count = 0;
    for (const auto& type : unfiltered)
    {
        if ((result_filter_count++ & 0xFFu) == 0 && ctx.stop("rtti_result_filter"))
            break;
        if (has_exact_type_descriptor && type.type_descriptor_va != exact_type_descriptor_va)
            continue;
        if (has_exact_col && !type_has_col(type, exact_col_va))
            continue;
        if (!type_matches_filter(type, filter))
            continue;
        result.types.push_back(type);
        if (result.types.size() >= max_results)
            break;
    }
    if (!filter_text.empty() && result.types.empty() && !unfiltered.empty())
    {
        for (const auto& type : unfiltered)
        {
            result.sample_type_names.push_back(type.name);
            if (result.sample_type_names.size() >= 12)
                break;
        }
    }
    result.unfiltered_cap_hit = all_by_td.size() >= max_unfiltered;
    result.deadline_hit = ctx.deadline_hit;
    result.cancelled = ctx.cancelled;
    result.partial = ctx.deadline_hit || ctx.cancelled || result.unfiltered_cap_hit;
    result.timeout_ms = timeout_ms;
    result.elapsed_ms = GetTickCount64() - started_ms;
    result.scanned_module_count = ctx.scanned_module_count;
    result.type_descriptor_count = ctx.type_descriptor_count;
    result.complete_object_locator_count = ctx.complete_object_locator_count;
    result.vtable_count = ctx.vtable_count;
    result.bytes_scanned = ctx.bytes_scanned;
    result.scanned_modules = std::move(ctx.scanned_modules);
    result.filter = filter_text;
    result.module_filter = module_filter;
    result.scan_mode = scan_mode;
    bool exact_type_descriptor_hit = false;
    bool exact_col_hit = false;
    bool vtable_hint_hit = false;
    for (const auto& type : result.types)
    {
        if (has_exact_type_descriptor && type.type_descriptor_va == exact_type_descriptor_va)
            exact_type_descriptor_hit = true;
        if (has_exact_col && type_has_col(type, exact_col_va))
            exact_col_hit = true;
        if (has_vtable_hint)
        {
            if (type.vtable_va == vtable_hint_va)
                vtable_hint_hit = true;
            for (const auto& vt : type.vtables)
                if (vt.vtable_va == vtable_hint_va)
                    vtable_hint_hit = true;
        }
    }
    result.exact_selector_flags = {
        {"module_base_provided", module_base_provided},
        {"module_base_key", module_base_key},
        {"module_base_va", module_base_provided ? json(sa_format_address(module_base)) : json(nullptr)},
        {"type_descriptor_provided", has_exact_type_descriptor},
        {"type_descriptor_key", exact_type_descriptor_key},
        {"type_descriptor_va", has_exact_type_descriptor ? json(sa_format_address(exact_type_descriptor_va)) : json(nullptr)},
        {"type_descriptor_hit", has_exact_type_descriptor ? exact_type_descriptor_hit : false},
        {"complete_object_locator_provided", has_exact_col},
        {"complete_object_locator_key", exact_col_key},
        {"complete_object_locator_va", has_exact_col ? json(sa_format_address(exact_col_va)) : json(nullptr)},
        {"complete_object_locator_hit", has_exact_col ? exact_col_hit : false},
        {"vtable_hint_provided", has_vtable_hint},
        {"vtable_hint_key", vtable_hint_key},
        {"vtable_va", has_vtable_hint ? json(sa_format_address(vtable_hint_va)) : json(nullptr)},
        {"vtable_hint_hit", has_vtable_hint ? vtable_hint_hit : false},
        {"exact_selector_fast_path", exact_selector_fast_path},
        {"exact_selector_direct_hit", exact_selector_direct_hit}
    };
    if ((has_exact_type_descriptor || has_exact_col) && result.types.empty())
    {
        result.ok = false;
        const bool type_selector = has_exact_type_descriptor;
        result.error = type_selector ?
            "RTTI type_descriptor_va selector did not match a recovered RTTI type." :
            "RTTI complete_object_locator_va selector did not match a recovered RTTI type.";
        result.error_details = selector_failure_details(scope.pid(),
                                                        type_selector ? "type_descriptor_hint" : "complete_object_locator_hint",
                                                        type_selector ? exact_type_descriptor_key : exact_col_key,
                                                        type_selector ? exact_type_descriptor_value : exact_col_value,
                                                        module_name,
                                                        module_filter,
                                                        include_system_modules,
                                                        module_limit,
                                                        load_available_modules());
        result.error_details["explicit_selector_fail_closed"] = true;
        result.error_details["unfiltered_type_count"] = result.unfiltered_type_count;
        result.error_details["type_descriptor_count"] = result.type_descriptor_count;
        result.error_details["complete_object_locator_count"] = result.complete_object_locator_count;
        result.error_details["vtable_count"] = result.vtable_count;
        return result;
    }
    diag::log_tagged_fmt("rtti",
                         "scan_types exit pid=%u count=%zu unfiltered=%zu deadline=%d cancelled=%d elapsed_ms=%llu",
                         scope.pid(),
                         result.types.size(),
                         result.unfiltered_type_count,
                         result.deadline_hit ? 1 : 0,
                         result.cancelled ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return result;
}

json type_to_json(const type_info_t& type, std::size_t max_vtables_per_type = 64)
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
    json base_records = json::array();
    for (const auto& base : type.base_class_records)
    {
        json row;
        row["name"] = base.name;
        row["decorated_name"] = base.decorated_name;
        row["type_descriptor_va"] = base.type_descriptor_va ? json(sa_format_address(base.type_descriptor_va)) : json(nullptr);
        row["base_descriptor_va"] = base.base_descriptor_va ? json(sa_format_address(base.base_descriptor_va)) : json(nullptr);
        row["mdisp"] = base.mdisp;
        row["pdisp"] = base.pdisp;
        row["vdisp"] = base.vdisp;
        row["attributes"] = sa_format_address(base.attributes);
        base_records.push_back(std::move(row));
    }
    out["base_class_records"] = std::move(base_records);
    json cols = json::array();
    for (const auto& col : type.cols)
    {
        json row;
        row["complete_object_locator_va"] = sa_format_address(col.complete_object_locator_va);
        row["hierarchy_descriptor_va"] = col.hierarchy_descriptor_va ? json(sa_format_address(col.hierarchy_descriptor_va)) : json(nullptr);
        row["signature"] = col.signature;
        row["relative"] = col.relative;
        row["self_consistent"] = col.self_consistent;
        row["legacy_absolute"] = col.legacy_absolute;
        row["confidence"] = col.confidence;
        cols.push_back(std::move(row));
    }
    out["cols"] = std::move(cols);
    out["complete_object_locator_count"] = type.cols.size();
    json vtables = json::array();
    std::size_t emitted = 0;
    for (const auto& vt : type.vtables)
    {
        if (emitted >= max_vtables_per_type)
            break;
        json row;
        row["vtable_va"] = sa_format_address(vt.vtable_va);
        row["complete_object_locator_va"] = vt.complete_object_locator_va ? json(sa_format_address(vt.complete_object_locator_va)) : json(nullptr);
        row["sampled_slots"] = vt.sampled_slots;
        row["readable_slots"] = vt.readable_slots;
        row["executable_slots"] = vt.executable_slots;
        row["confidence"] = vt.confidence;
        vtables.push_back(std::move(row));
        ++emitted;
    }
    out["vtables"] = std::move(vtables);
    out["vtable_count"] = type.vtables.size();
    return out;
}

void add_scan_diagnostics(json& out, const scan_result_t& scan, bool include_diagnostics)
{
    out["deadline_hit"] = scan.deadline_hit;
    out["cancelled"] = scan.cancelled;
    out["partial"] = scan.partial;
    out["unfiltered_cap_hit"] = scan.unfiltered_cap_hit;
    out["elapsed_ms"] = scan.elapsed_ms;
    out["timeout_ms"] = scan.timeout_ms;
    out["scanned_module_count"] = scan.scanned_module_count;
    out["type_descriptor_count"] = scan.type_descriptor_count;
    out["complete_object_locator_count"] = scan.complete_object_locator_count;
    out["vtable_count"] = scan.vtable_count;
    out["bytes_scanned"] = scan.bytes_scanned;
    out["filter"] = scan.filter;
    out["module_filter"] = scan.module_filter;
    out["scan_mode"] = scan.scan_mode;
    out["exact_selector_flags"] = scan.exact_selector_flags;
    out["unfiltered_type_count"] = scan.unfiltered_type_count;
    out["sample_type_names"] = scan.sample_type_names;
    out["scanned_modules"] = include_diagnostics ? json(scan.scanned_modules) : json::array();
}

json scan_error_payload(const scan_result_t& scan, bool include_diagnostics)
{
    json out = scan.error_details.is_object() ? scan.error_details : json::object();
    if (!scan.error.empty())
        out["error"] = scan.error;
    add_scan_diagnostics(out, scan, include_diagnostics);
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
    auto scan = scan_types(params);
    const bool include_diagnostics = bool_param(params, "include_diagnostics", true);
    if (!scan.ok)
        return tool_result_t::error(scan.error, scan_error_payload(scan, include_diagnostics));
    const std::size_t max_vtables_per_type = static_cast<std::size_t>(numeric_param(params, "max_vtables_per_type", 64, 1, 512));
    json arr = json::array();
    for (const auto& type : scan.types)
        arr.push_back(type_to_json(type, max_vtables_per_type));
    json result;
    result["process_id"] = scan.pid;
    result["returned"] = arr.size();
    result["types"] = std::move(arr);
    add_scan_diagnostics(result, scan, include_diagnostics);
    return tool_result_t::ok(result);
}

tool_result_t find_type(const json& params)
{
    const std::string pattern = string_param(params, "pattern");
    const bool exact_selector_present =
        params.contains("vtable_va") ||
        params.contains("rtti_vtable_va") ||
        params.contains("type_descriptor_va") ||
        params.contains("rtti_type_descriptor_va") ||
        params.contains("complete_object_locator_va") ||
        params.contains("rtti_complete_object_locator_va");
    if (pattern.empty() && !exact_selector_present)
        return tool_result_t::error("'pattern' is required.");
    json scan_params = params;
    if (!pattern.empty())
        scan_params["filter"] = pattern;
    auto scan = scan_types(scan_params);
    const bool include_diagnostics = bool_param(params, "include_diagnostics", true);
    if (!scan.ok)
        return tool_result_t::error(scan.error, scan_error_payload(scan, include_diagnostics));
    const std::size_t max_vtables_per_type = static_cast<std::size_t>(numeric_param(params, "max_vtables_per_type", 64, 1, 512));
    json matches = json::array();
    for (const auto& type : scan.types)
    {
        json row = type_to_json(type, max_vtables_per_type);
        attach_hierarchy(row, type, scan.type_index, max_vtables_per_type);
        matches.push_back(std::move(row));
    }
    json result;
    result["pattern"] = pattern;
    result["matches"] = std::move(matches);
    result["count"] = result["matches"].size();
    if (!scan.types.empty())
    {
        json best = type_to_json(scan.types.front(), max_vtables_per_type);
        attach_hierarchy(best, scan.types.front(), scan.type_index, max_vtables_per_type);
        result["best"] = std::move(best);
    }
    add_scan_diagnostics(result, scan, include_diagnostics);
    return tool_result_t::ok(result);
}

tool_result_t list_hierarchy(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    const std::string query = string_param(params, "type_name_or_va");
    const bool exact_selector_present =
        params.contains("vtable_va") ||
        params.contains("rtti_vtable_va") ||
        params.contains("type_descriptor_va") ||
        params.contains("rtti_type_descriptor_va") ||
        params.contains("complete_object_locator_va") ||
        params.contains("rtti_complete_object_locator_va");
    if (query.empty() && !exact_selector_present)
        return tool_result_t::error("'type_name_or_va' is required.");
    const bool include_diagnostics = bool_param(params, "include_diagnostics", true);
    std::uint64_t va = 0;
    const auto parsed_va = sa_parse_address(query);
    const bool query_is_va = parsed_va.has_value();
    if (parsed_va)
        va = *parsed_va;
    std::uint64_t vtable_hint = 0;
    const bool has_vtable_hint =
        (parse_address_param(params, "vtable_va", vtable_hint) ||
         parse_address_param(params, "rtti_vtable_va", vtable_hint)) && vtable_hint != 0;
    if (has_vtable_hint)
    {
        if (auto module = find_module_for_address(scope.pid(), vtable_hint))
        {
            type_info_t hinted;
            if (type_from_vtable(scope.pid(), *module, vtable_hint, hinted))
            {
                const std::string query_lower = lower_ascii(query);
                const bool match = query.empty() ? true : (query_is_va ? (hinted.vtable_va == va || hinted.type_descriptor_va == va) :
                    (lower_ascii(hinted.name).find(query_lower) != std::string::npos ||
                     lower_ascii(hinted.decorated_name).find(query_lower) != std::string::npos));
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
                    const std::size_t max_vtables_per_type = static_cast<std::size_t>(numeric_param(params, "max_vtables_per_type", 64, 1, 512));
                    json hierarchy_scan_params = params;
                    hierarchy_scan_params["module_base_va"] = sa_format_address(module->base);
                    hierarchy_scan_params["type_descriptor_va"] = sa_format_address(hinted.type_descriptor_va);
                    hierarchy_scan_params["max_results"] = 1;
                    auto hierarchy_scan = scan_types(hierarchy_scan_params);
                    type_info_t resolved = hinted;
                    std::vector<type_resolution_record_t> index;
                    if (hierarchy_scan.ok)
                    {
                        index = hierarchy_scan.type_index;
                        for (const auto& scanned_type : hierarchy_scan.types)
                        {
                            if (scanned_type.type_descriptor_va == hinted.type_descriptor_va)
                            {
                                resolved = scanned_type;
                                break;
                            }
                        }
                    }
                    if (index.empty())
                    {
                        std::vector<type_info_t> fallback_types;
                        fallback_types.push_back(resolved);
                        index = build_type_index(fallback_types);
                    }
                    json result = type_to_json(resolved, max_vtables_per_type);
                    attach_hierarchy(result, resolved, index, max_vtables_per_type);
                    result["resolution"] = "vtable_hint_col";
                    if (hierarchy_scan.ok)
                    {
                        add_scan_diagnostics(result, hierarchy_scan, include_diagnostics);
                        result["focused_scan_ok"] = true;
                    }
                    else
                    {
                        result["focused_scan_ok"] = false;
                        result["focused_scan_error"] = hierarchy_scan.error;
                        result["focused_scan_details"] = scan_error_payload(hierarchy_scan, include_diagnostics);
                        result["deadline_hit"] = hierarchy_scan.deadline_hit;
                        result["cancelled"] = hierarchy_scan.cancelled;
                        result["partial"] = true;
                        result["timeout_ms"] = hierarchy_scan.timeout_ms;
                        result["elapsed_ms"] = GetTickCount64() - started_ms;
                    }
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
    auto scan = scan_types(scan_params);
    if (!scan.ok)
        return tool_result_t::error(scan.error, scan_error_payload(scan, include_diagnostics));
    const auto& types = scan.types;
    diag::log_tagged_fmt("rtti",
                         "list_hierarchy scanned pid=%u query=%s query_is_va=%d types=%zu elapsed_ms=%llu",
                         scope.pid(),
                         query.c_str(),
                         query_is_va ? 1 : 0,
                         types.size(),
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    for (const auto& type : types)
    {
        const bool match = query.empty() ? true : (query_is_va ? (type.vtable_va == va || type.type_descriptor_va == va) :
            (lower_ascii(type.name).find(lower_ascii(query)) != std::string::npos ||
             lower_ascii(type.decorated_name).find(lower_ascii(query)) != std::string::npos));
        if (!match)
            continue;
        const std::size_t max_vtables_per_type = static_cast<std::size_t>(numeric_param(params, "max_vtables_per_type", 64, 1, 512));
        json result = type_to_json(type, max_vtables_per_type);
        attach_hierarchy(result, type, scan.type_index, max_vtables_per_type);
        add_scan_diagnostics(result, scan, include_diagnostics);
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
    json details;
    add_scan_diagnostics(details, scan, include_diagnostics);
    return tool_result_t::error("RTTI type not found.", details);
}

tool_result_t find_constructor(const json& params)
{
    const std::uint64_t started_ms = GetTickCount64();
    active_process_scope_t scope(params);
    if (!scope.ok())
        return tool_result_t::error(scope.error());
    std::uint64_t vtable_va = 0;
    if ((!parse_address_param(params, "vtable_va", vtable_va) && !parse_address_param(params, "rtti_vtable_va", vtable_va)) || vtable_va == 0)
        return tool_result_t::error("'vtable_va' is required.");
    std::uint64_t constructor_fn_va = 0;
    const bool constructor_selector_provided =
        parse_address_param(params, "constructor_fn_va", constructor_fn_va) ||
        parse_address_param(params, "rtti_constructor_fn_va", constructor_fn_va);
    std::uint64_t scan_start_va = 0;
    std::uint64_t scan_size = 0;
    std::uint64_t scan_end_va = 0;
    const bool scan_start_provided =
        parse_address_param(params, "scan_start_va", scan_start_va) ||
        parse_address_param(params, "scan_base", scan_start_va) ||
        parse_address_param(params, "range_base", scan_start_va);
    if (scan_start_provided)
    {
        if (!parse_address_param(params, "scan_size", scan_size) &&
            !parse_address_param(params, "range_size", scan_size) &&
            !parse_address_param(params, "size", scan_size))
        {
            if (parse_address_param(params, "scan_end_va", scan_end_va) ||
                parse_address_param(params, "range_end_va", scan_end_va) ||
                parse_address_param(params, "end_va", scan_end_va))
                scan_size = scan_end_va > scan_start_va ? scan_end_va - scan_start_va : 0;
        }
    }
    if (scan_start_va != 0 && scan_size != 0 && scan_start_va > std::numeric_limits<std::uint64_t>::max() - scan_size)
    {
        return tool_result_t::error("Bounded constructor scan range overflows.",
            json{{"scan_start_va", sa_format_address(scan_start_va)}, {"scan_size", scan_size}});
    }
    const bool bounded_scan = scan_start_va != 0 && scan_size != 0;
    const std::uint64_t scan_end_checked = bounded_scan ? scan_start_va + scan_size : 0;
    const std::size_t max_scan_bytes = static_cast<std::size_t>(numeric_param(params, "max_scan_bytes", 64ull * 1024ull * 1024ull, 4096, 64ull * 1024ull * 1024ull));
    const std::uint64_t timeout_ms = numeric_param(params, "timeout_ms", 5500, 500, 60000);
    const std::size_t max_candidates = static_cast<std::size_t>(numeric_param(params, "max_candidates", 64, 1, 512));
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
    bool cancelled = false;
    std::size_t total_reference_hits = 0;
    std::size_t total_windows = 0;
    std::size_t total_decoded = 0;
    std::size_t sections_scanned = 0;
    std::uint64_t bytes_scanned = 0;
    auto timed_out = [&]() -> bool {
        if (cancelled || deadline_hit)
            return true;
        if (mcp_standalone::current_call_cancelled())
        {
            cancelled = true;
            return true;
        }
        const std::uint64_t call_deadline = mcp_standalone::current_call_deadline_ms();
        if (call_deadline != 0 && GetTickCount64() >= call_deadline)
        {
            deadline_hit = true;
            return true;
        }
        if (GetTickCount64() - started_ms < timeout_ms)
            return false;
        deadline_hit = true;
        return true;
    };
    auto build_constructor_result = [&](const char* phase) {
        json result;
        result["process_id"] = scope.pid();
        result["vtable_va"] = sa_format_address(vtable_va);
        result["module_name"] = !module->name.empty() ? module->name : module->path;
        result["module_base_va"] = sa_format_address(module->base);
        result["timeout_ms"] = timeout_ms;
        result["max_candidates"] = max_candidates;
        result["deadline_hit"] = deadline_hit;
        result["cancelled"] = cancelled;
        result["partial"] = deadline_hit || cancelled;
        result["phase"] = phase ? phase : "";
        result["reference_hits"] = total_reference_hits;
        result["decode_windows"] = total_windows;
        result["decoded_instructions"] = total_decoded;
        result["sections_scanned"] = sections_scanned;
        result["bytes_scanned"] = bytes_scanned;
        result["bounded_scan"] = bounded_scan;
        result["scan_range"] = bounded_scan ?
            json{{"base_va", sa_format_address(scan_start_va)}, {"size", scan_size}, {"end_va", sa_format_address(scan_end_checked)}} :
            json{{"base_va", nullptr}, {"size", 0}, {"end_va", nullptr}};
        result["exact_selector_flags"] = {
            {"vtable_provided", true},
            {"vtable_va", sa_format_address(vtable_va)},
            {"constructor_fn_provided", constructor_selector_provided},
            {"constructor_fn_va", constructor_selector_provided ? json(sa_format_address(constructor_fn_va)) : json(nullptr)},
            {"constructor_fn_hit", constructor_selector_provided && !candidates.empty()}
        };
        if (has_hinted_type)
            result["type"] = type_to_json(hinted_type);
        result["candidates"] = candidates;
        result["count"] = result["candidates"].size();
        return result;
    };
    if (constructor_selector_provided)
    {
        const std::uint64_t module_end = module->base + static_cast<std::uint64_t>(module->size);
        if (constructor_fn_va < module->base || constructor_fn_va >= module_end)
        {
            json details = build_constructor_result("exact_constructor_selector");
            details["validation_code"] = "constructor_selector_outside_vtable_module";
            details["constructor_module_match"] = false;
            return tool_result_t::error("constructor_fn_va does not belong to the vtable module.", details);
        }
        if (seen.insert(constructor_fn_va).second)
        {
            json row;
            row["constructor_candidate_va"] = sa_format_address(constructor_fn_va);
            row["write_va"] = nullptr;
            row["object_offset"] = nullptr;
            row["confidence"] = "exact";
            row["phase"] = "exact_constructor_selector";
            row["selector_direct"] = true;
            row["module_match"] = true;
            row["preview"] = disasm_preview(scope.pid(), constructor_fn_va, 12);
            candidates.push_back(std::move(row));
        }
        return tool_result_t::ok(build_constructor_result("exact_constructor_selector"));
    }
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
        for (std::size_t i = begin; i < end && candidates.size() < max_candidates;)
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
                    if (candidates.size() >= max_candidates)
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
        std::uint64_t read_base = section.va;
        std::uint64_t read_size64 = std::min<std::uint64_t>(section.size, max_scan_bytes);
        if (bounded_scan)
        {
            if (section.va > std::numeric_limits<std::uint64_t>::max() - section.size)
                continue;
            const std::uint64_t section_end = section.va + section.size;
            const std::uint64_t requested_end = scan_end_checked;
            const std::uint64_t overlap_begin = std::max<std::uint64_t>(section.va, scan_start_va);
            const std::uint64_t overlap_end = std::min<std::uint64_t>(section_end, requested_end);
            if (overlap_begin >= overlap_end)
                continue;
            read_base = overlap_begin;
            read_size64 = std::min<std::uint64_t>(overlap_end - overlap_begin, max_scan_bytes);
        }
        if (timed_out())
            break;
        const std::uint64_t section_started_ms = GetTickCount64();
        const std::size_t candidates_before = candidates.size();
        std::size_t decoded_count = 0;
        const std::size_t read_size = static_cast<std::size_t>(read_size64);
        std::vector<std::uint8_t> bytes;
        if (!read_bytes(scope.pid(), read_base, read_size, bytes) || bytes.empty())
        {
            diag::log_tagged_fmt("rtti",
                                 "find_constructor section_read_failed pid=%u section=%s va=%s read_size=%zu elapsed_ms=%llu",
                                 scope.pid(),
                                 section.name.c_str(),
                                 sa_format_address(read_base).c_str(),
                                 read_size,
                                 static_cast<unsigned long long>(GetTickCount64() - section_started_ms));
            continue;
        }
        ++sections_scanned;
        bytes_scanned += bytes.size();
        module_section_t scan_section = section;
        scan_section.va = read_base;
        scan_section.size = bytes.size();
        std::vector<std::size_t> references;
        auto needle = u64_to_le(vtable_va);
        if (layout.pointer_size == 4 && needle.size() > 4)
            needle.resize(4);
        for (std::size_t i = 0; i < bytes.size(); ++i)
        {
            if ((i & 0xFFFu) == 0 && timed_out())
                break;
            if (i + needle.size() <= bytes.size() && std::memcmp(bytes.data() + i, needle.data(), needle.size()) == 0)
                references.push_back(i);
            if (i + 7 <= bytes.size() && (bytes[i] & 0xF0u) == 0x40u && (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) && (bytes[i + 2] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 3, sizeof(disp));
                const std::uint64_t target = static_cast<std::uint64_t>(static_cast<std::int64_t>(scan_section.va + i + 7) + disp);
                if (target == vtable_va)
                    references.push_back(i);
            }
            if (i + 6 <= bytes.size() && bytes[i] == 0x8D && (bytes[i + 1] & 0xC7u) == 0x05u)
            {
                std::int32_t disp = 0;
                std::memcpy(&disp, bytes.data() + i + 2, sizeof(disp));
                const std::uint64_t target = static_cast<std::uint64_t>(static_cast<std::int64_t>(scan_section.va + i + 6) + disp);
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
        if (deadline_hit || cancelled)
            break;
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
                             sa_format_address(scan_section.va).c_str(),
                             bytes.size(),
                             references.size(),
                             windows.size(),
                             static_cast<unsigned long long>(GetTickCount64() - section_started_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        for (const auto& window : windows)
        {
            if (timed_out() || candidates.size() >= max_candidates)
                break;
            ++total_windows;
            for (std::size_t shift = 0; shift < 16 && window.first + shift < window.second && candidates.size() < max_candidates; ++shift)
            {
                if (timed_out())
                    break;
                decoded_count += decode_range(scan_section, bytes, window.first + shift, window.second, references.empty() ? "bounded_fallback_window" : "vtable_reference_window");
            }
        }
        total_decoded += decoded_count;
        diag::log_tagged_fmt("rtti",
                             "find_constructor section_done pid=%u section=%s va=%s bytes=%zu decoded=%zu refs=%zu windows=%zu new_candidates=%zu total_candidates=%zu deadline=%d elapsed_ms=%llu total_elapsed_ms=%llu",
                             scope.pid(),
                             section.name.c_str(),
                             sa_format_address(scan_section.va).c_str(),
                             bytes.size(),
                             decoded_count,
                             references.size(),
                             windows.size(),
                             candidates.size() - candidates_before,
                             candidates.size(),
                             deadline_hit ? 1 : 0,
                             static_cast<unsigned long long>(GetTickCount64() - section_started_ms),
                             static_cast<unsigned long long>(GetTickCount64() - started_ms));
        if (candidates.size() >= max_candidates || deadline_hit || cancelled)
            break;
    }
    json result = build_constructor_result("complete");
    const std::size_t candidate_count = result["candidates"].size();
    result["count"] = candidate_count;
    diag::log_tagged_fmt("rtti",
                         "find_constructor exit pid=%u vtable=%s count=%zu refs=%zu windows=%zu decoded=%zu deadline=%d cancelled=%d elapsed_ms=%llu",
                         scope.pid(),
                         sa_format_address(vtable_va).c_str(),
                         candidate_count,
                         total_reference_hits,
                         total_windows,
                         total_decoded,
                         deadline_hit ? 1 : 0,
                         cancelled ? 1 : 0,
                         static_cast<unsigned long long>(GetTickCount64() - started_ms));
    return tool_result_t::ok(result);
}
}
