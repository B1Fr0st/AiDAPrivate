#pragma once

#include "disasm_view.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace file_metadata_banner {

inline std::string machine_name(std::uint16_t machine) {
    switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x86-64";
    case 0x01c0: return "ARM";
    case 0xaa64: return "ARM64";
    default: {
        char buffer[24]{};
        std::snprintf(buffer, sizeof(buffer), "machine 0x%04X", machine);
        return buffer;
    }
    }
}

inline std::string section_flags(const aida::analysis::pe_section_t& section) {
    std::string value;
    auto append = [&value](const char* label) {
        if (!value.empty())
            value.push_back(' ');
        value.append(label);
    };
    if ((section.characteristics & 0x08000000u) != 0)
        append("Not pageable");
    if (section.executable)
        append("Executable");
    if (section.readable)
        append("Readable");
    if (section.writable)
        append("Writable");
    return value.empty() ? "No access attributes" : value;
}

inline std::uint64_t signature(const disasm_view::workspace_context_t& context,
                               std::uint64_t image_base) {
    std::uint64_t value = context.publication ? context.publication->generation : 0;
    value ^= image_base + 0x9E3779B97F4A7C15ull + (value << 6u) + (value >> 2u);
    if (context.image) {
        value ^= static_cast<std::uint64_t>(context.image->timestamp()) << 32u;
        value ^= static_cast<std::uint64_t>(context.image->sections().size()) *
            0xD6E8FEB86659FD93ull;
    }
    return value == 0 ? 1 : value;
}

inline void refresh(const disasm_view::workspace_context_t& context) {
    if (!context.workspace || !context.image)
        return;
    const auto& identity = context.workspace->identity();
    const auto& image = *context.image;
    std::uint64_t image_base = image.image_base();
    {
        std::lock_guard<std::mutex> lock(context.view->mutex);
        if (context.view->display_image_base)
            image_base = *context.view->display_image_base;
        const auto current_signature = signature(context, image_base);
        if (context.view->metadata_signature == current_signature &&
            !context.view->metadata_lines.empty())
            return;
    }

    std::vector<disasm_view::metadata_line_t> lines;
    lines.reserve(36);
    auto append = [&lines](disasm_view::metadata_line_kind_t kind, std::string text = {}) {
        lines.push_back({std::move(text), kind});
    };
    using kind_t = disasm_view::metadata_line_kind_t;
    append(kind_t::comment, ";");
    append(kind_t::banner, "; +-------------------------------------------------------------------------+");
    append(kind_t::banner, "; |             AiDA - Reverse-engineering toolkit by AiDA Team             |");
    append(kind_t::banner, "; |                          aida.app - Standalone                          |");
    append(kind_t::banner, "; +-------------------------------------------------------------------------+");
    append(kind_t::comment, ";");
    append(kind_t::comment, "; Input SHA256 : " + identity.content_hash().to_hex());
    append(kind_t::comment, "; Input MD5    : (unavailable)");
    append(kind_t::comment, "; Input CRC32  : (unavailable)");
    append(kind_t::comment, "; Compiler     : (unavailable)");
    append(kind_t::blank);
    append(kind_t::comment, "; File Name   : " + identity.normalized_source_path());
    append(kind_t::comment, "; Format      : Portable executable for " + machine_name(image.machine()));
    char buffer[512]{};
    std::snprintf(buffer, sizeof(buffer), "; Imagebase   : %llX",
        static_cast<unsigned long long>(image_base));
    append(kind_t::comment, buffer);
    const auto primary = std::find_if(image.sections().begin(), image.sections().end(),
        [](const aida::analysis::pe_section_t& section) { return section.executable; });
    if (primary != image.sections().end()) {
        const auto section_number = static_cast<std::size_t>(
            std::distance(image.sections().begin(), primary)) + 1;
        std::snprintf(buffer, sizeof(buffer), "; Section %zu. (virtual address %08X)",
            section_number, primary->virtual_address);
        append(kind_t::comment, buffer);
        std::snprintf(buffer, sizeof(buffer), "; Virtual size                  : %08X ( %u.)",
            primary->virtual_size, primary->virtual_size);
        append(kind_t::comment, buffer);
        std::snprintf(buffer, sizeof(buffer), "; Section size in file          : %08X ( %u.)",
            primary->raw_size, primary->raw_size);
        append(kind_t::comment, buffer);
        std::snprintf(buffer, sizeof(buffer), "; Offset to raw data for section: %08X",
            primary->raw_offset);
        append(kind_t::comment, buffer);
        const auto flags = section_flags(*primary);
        std::snprintf(buffer, sizeof(buffer), "; Flags %08X: %s",
            primary->characteristics, flags.c_str());
        append(kind_t::comment, buffer);
        append(kind_t::comment, "; Alignment     : default");
    }
    append(kind_t::blank);
    append(kind_t::directive, image.machine() == 0x8664 ? ".x64" : ".686p");
    append(kind_t::directive, ".model flat");
    append(kind_t::blank);
    append(kind_t::banner, "; ===========================================================================");
    append(kind_t::blank);
    append(kind_t::keyword, "; Segment type: Pure code");
    append(kind_t::keyword, "; Segment permissions: Read/Execute");
    if (primary != image.sections().end()) {
        std::string name = primary->name;
        if (!name.empty() && name.front() == '.')
            name.front() = '_';
        append(kind_t::directive, name + " segment para public 'CODE' use64");
        append(kind_t::directive, "assume cs:" + name);
    }
    append(kind_t::blank);

    std::lock_guard<std::mutex> lock(context.view->mutex);
    context.view->metadata_lines = std::move(lines);
    context.view->metadata_signature = signature(context, image_base);
}

}
