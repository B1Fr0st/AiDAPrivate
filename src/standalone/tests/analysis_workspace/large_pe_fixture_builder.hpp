#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include "workspace_fixture_builder.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis::test_fixture {

struct large_pe_params_t {
    std::uint64_t code_bytes = 32ULL * 1024ULL * 1024ULL;
    std::uint32_t function_count = 0;
    std::uint64_t seed = 0xA1DA0001ULL;
    std::uint32_t code_sections = 1;
    std::uint32_t string_count = 4096;
    std::uint32_t data_pointer_count = 4096;
    bool seed_pdata = true;
    std::uint8_t call_density_pct = 12;
    std::uint8_t jump_density_pct = 8;
    std::uint8_t padding_pct = 6;
};

struct large_pe_section_manifest_t {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_size = 0;
};

struct large_pe_manifest_t {
    std::vector<large_pe_section_manifest_t> sections;
    std::uint32_t function_rva_begin = 0;
    std::uint32_t function_rva_end = 0;
    std::uint64_t function_count = 0;
    std::uint64_t instruction_count_estimate = 0;
    std::uint64_t code_bytes = 0;
    std::uint64_t pdata_bytes = 0;
    std::uint64_t xdata_bytes = 0;
    std::uint64_t rdata_bytes = 0;
    std::uint64_t data_bytes = 0;
    std::uint64_t reloc_bytes = 0;
    std::uint64_t file_size = 0;
};

large_pe_params_t validated_large_pe_params(const large_pe_params_t& params);
large_pe_manifest_t describe_large_pe(const large_pe_params_t& params);
std::vector<std::uint8_t> build_large_pe64(const large_pe_params_t& params);
void write_large_pe64(const std::filesystem::path& path, const large_pe_params_t& params);
std::string large_pe_sha256(const large_pe_params_t& params);

namespace detail {

constexpr std::uint64_t large_pe_image_base = 0x140000000ULL;
constexpr std::uint32_t large_pe_section_alignment = 0x1000;
constexpr std::uint32_t large_pe_file_alignment = 0x200;

inline std::uint32_t align_up_u32(std::uint64_t value, std::uint32_t alignment)
{
    const std::uint64_t aligned = (value + alignment - 1) &
        ~static_cast<std::uint64_t>(alignment - 1);
    if (aligned > 0xFFFFFFFFULL)
        throw fixture_error_t("large PE layout exceeds 32-bit RVA space");
    return static_cast<std::uint32_t>(aligned);
}

struct splitmix64_t {
    std::uint64_t state = 0;
    std::uint64_t next()
    {
        state += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    std::uint64_t below(std::uint64_t bound)
    {
        return bound == 0 ? 0 : next() % bound;
    }
};

enum large_pe_function_flag_t : std::uint8_t {
    large_pe_fn_tail_call = 1U << 0,
    large_pe_fn_jump_table = 1U << 1,
    large_pe_fn_entry = 1U << 2
};

struct large_pe_function_plan_t {
    std::uint32_t rva = 0;
    std::uint32_t byte_size = 0;
    std::uint16_t block_count = 2;
    std::uint8_t prologue_kind = 0;
    std::uint8_t flags = 0;
};

struct large_pe_jump_table_plan_t {
    std::uint32_t function_index = 0;
    std::uint32_t table_rva = 0;
    std::uint32_t case_count = 0;
    std::vector<std::uint32_t> case_rvas;
};

struct large_pe_plan_t {
    large_pe_params_t params;
    std::vector<large_pe_function_plan_t> functions;
    std::vector<std::uint32_t> string_rvas;
    std::vector<std::uint32_t> string_sizes;
    std::vector<large_pe_jump_table_plan_t> jump_tables;
    std::vector<large_pe_section_manifest_t> sections;
    std::uint32_t pdata_section_index = 0;
    std::uint32_t xdata_section_index = 0;
    std::uint32_t rdata_section_index = 0;
    std::uint32_t data_section_index = 0;
    std::uint32_t reloc_section_index = 0;
    bool has_pdata = false;
    std::uint32_t entry_point_rva = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t import_descriptor_rva = 0;
    std::uint32_t ilt_rva = 0;
    std::uint32_t iat_rva = 0;
    std::uint32_t dll_name_rva = 0;
    std::uint32_t import_name_rva = 0;
    std::uint32_t data_slots_rva = 0;
    std::uint64_t instruction_count_estimate = 0;
    std::uint64_t code_bytes_total = 0;
    std::uint64_t file_size = 0;
};

inline std::uint32_t prologue_length(std::uint8_t kind)
{
    return kind == 0 ? 8U : 7U;
}

inline std::uint32_t epilogue_base_length(std::uint8_t kind)
{
    return kind == 0 ? 6U : 8U;
}

inline void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
}

inline void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value)
{
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFFU));
}

inline void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value)
{
    append_u32(out, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    append_u32(out, static_cast<std::uint32_t>((value >> 32) & 0xFFFFFFFFULL));
}

inline void append_i32(std::vector<std::uint8_t>& out, std::int32_t value)
{
    append_u32(out, static_cast<std::uint32_t>(value));
}

inline void append_bytes(std::vector<std::uint8_t>& out,
                         const std::initializer_list<std::uint8_t>& values)
{
    out.insert(out.end(), values.begin(), values.end());
}

inline std::int32_t rel_displacement(std::uint64_t target, std::uint64_t instruction_end)
{
    const std::int64_t delta = static_cast<std::int64_t>(target) -
        static_cast<std::int64_t>(instruction_end);
    if (delta > 0x7FFFFFFFLL || delta < -0x80000000LL)
        throw fixture_error_t("large PE branch displacement exceeds rel32 range");
    return static_cast<std::int32_t>(delta);
}

inline large_pe_plan_t plan_large_pe(const large_pe_params_t& raw_params)
{
    const large_pe_params_t params = validated_large_pe_params(raw_params);
    large_pe_plan_t plan;
    plan.params = params;
    splitmix64_t prng{params.seed};

    const std::uint32_t function_total = params.function_count;
    plan.functions.resize(function_total);
    std::vector<std::uint32_t> table_function_indices;
    for (std::uint32_t index = 0; index < function_total; ++index) {
        auto& fn = plan.functions[index];
        const std::uint64_t class_draw = prng.below(100);
        std::uint8_t size_class = 0;
        std::uint32_t byte_size = 0;
        if (class_draw < 20) {
            byte_size = 16 + static_cast<std::uint32_t>(prng.below(17));
            size_class = 0;
        } else if (class_draw < 65) {
            byte_size = 33 + static_cast<std::uint32_t>(prng.below(64));
            size_class = 1;
        } else if (class_draw < 90) {
            byte_size = 97 + static_cast<std::uint32_t>(prng.below(160));
            size_class = 2;
        } else if (class_draw < 98) {
            byte_size = 257 + static_cast<std::uint32_t>(prng.below(256));
            size_class = 3;
        } else {
            byte_size = 513 + static_cast<std::uint32_t>(prng.below(512));
            size_class = 4;
        }
        const std::uint64_t prologue_draw = prng.below(100);
        if (size_class >= 3) {
            fn.prologue_kind = prologue_draw < 55 ? 0 : (prologue_draw < 85 ? 1 : 2);
        } else {
            fn.prologue_kind = prologue_draw < 70 ? 0 : 1;
        }
        fn.block_count = static_cast<std::uint16_t>(
            size_class == 0 ? 2 :
            size_class == 1 ? 2 + prng.below(2) :
            size_class == 2 ? 3 + prng.below(2) :
            size_class == 3 ? 4 + prng.below(3) :
            5 + prng.below(2));
        if (index != 0 && prng.below(100) < 5)
            fn.flags |= large_pe_fn_tail_call;
        if (index != 0 && prng.below(512) == 0) {
            fn.flags |= large_pe_fn_jump_table;
            table_function_indices.push_back(index);
        }
        if (index == 0) {
            fn.flags |= large_pe_fn_entry;
            fn.prologue_kind = 0;
            fn.block_count = 2;
            byte_size = (std::max<std::uint32_t>)(byte_size, 48);
        }
        const std::uint32_t minimum_bytes =
            prologue_length(fn.prologue_kind) +
            epilogue_base_length(fn.prologue_kind) +
            ((fn.flags & large_pe_fn_tail_call) != 0 ? 4U : 0U) +
            ((fn.flags & large_pe_fn_entry) != 0 ? 11U : 0U) +
            ((fn.flags & large_pe_fn_jump_table) != 0 ? 7U : 0U) + 2U;
        fn.byte_size = (std::max<std::uint32_t>)(byte_size, minimum_bytes);
    }

    plan.string_sizes.resize(params.string_count);
    for (std::uint32_t index = 0; index < params.string_count; ++index)
        plan.string_sizes[index] = 8 + static_cast<std::uint32_t>(prng.below(57));

    plan.jump_tables.resize(table_function_indices.size());
    for (std::size_t table = 0; table < table_function_indices.size(); ++table) {
        plan.jump_tables[table].function_index = table_function_indices[table];
        plan.jump_tables[table].case_count = 4 + static_cast<std::uint32_t>(prng.below(13));
    }

    const std::uint32_t code_sections = params.code_sections;
    plan.has_pdata = params.seed_pdata;
    const std::uint32_t section_total = code_sections + (plan.has_pdata ? 5U : 3U);
    plan.sections.resize(section_total);
    static const char* const code_names[8] = {
        ".text", ".text$mn", ".text$m2", ".text$m3",
        ".text$m4", ".text$m5", ".text$m6", ".text$m7"};
    std::uint64_t rva_cursor = large_pe_section_alignment;
    std::uint64_t code_bytes_total = 0;
    std::uint32_t functions_assigned = 0;
    for (std::uint32_t section = 0; section < code_sections; ++section) {
        auto& manifest = plan.sections[section];
        manifest.name = code_names[section];
        manifest.rva = align_up_u32(rva_cursor, large_pe_section_alignment);
        const std::uint32_t partition_begin =
            section * function_total / code_sections;
        const std::uint32_t partition_end =
            (section + 1) * function_total / code_sections;
        std::uint64_t cursor = manifest.rva;
        for (std::uint32_t index = partition_begin; index < partition_end; ++index) {
            auto& fn = plan.functions[index];
            std::uint32_t skew = static_cast<std::uint32_t>(prng.below(16));
            skew = params.padding_pct >= 100 ? skew : skew * params.padding_pct / 100;
            fn.rva = align_up_u32(cursor + skew, 16);
            cursor = static_cast<std::uint64_t>(fn.rva) + fn.byte_size;
        }
        manifest.virtual_size = align_up_u32(cursor - manifest.rva, 1);
        code_bytes_total += manifest.virtual_size;
        rva_cursor = static_cast<std::uint64_t>(manifest.rva) + manifest.virtual_size;
        functions_assigned = partition_end;
    }
    if (functions_assigned != function_total)
        throw fixture_error_t("large PE code partition lost functions");
    plan.code_bytes_total = code_bytes_total;

    std::uint32_t section_index = code_sections;
    if (plan.has_pdata) {
        plan.pdata_section_index = section_index++;
        auto& pdata = plan.sections[plan.pdata_section_index];
        pdata.name = ".pdata";
        pdata.rva = align_up_u32(rva_cursor, large_pe_section_alignment);
        pdata.virtual_size = function_total * 12U;
        rva_cursor = static_cast<std::uint64_t>(pdata.rva) + pdata.virtual_size;
        plan.xdata_section_index = section_index++;
        auto& xdata = plan.sections[plan.xdata_section_index];
        xdata.name = ".xdata";
        xdata.rva = align_up_u32(rva_cursor, large_pe_section_alignment);
        xdata.virtual_size = function_total * 4U;
        rva_cursor = static_cast<std::uint64_t>(xdata.rva) + xdata.virtual_size;
    }

    plan.rdata_section_index = section_index++;
    auto& rdata = plan.sections[plan.rdata_section_index];
    rdata.name = ".rdata";
    rdata.rva = align_up_u32(rva_cursor, large_pe_section_alignment);
    plan.string_rvas.resize(plan.string_sizes.size());
    std::uint64_t rdata_cursor = rdata.rva;
    for (std::size_t index = 0; index < plan.string_sizes.size(); ++index) {
        plan.string_rvas[index] = static_cast<std::uint32_t>(rdata_cursor);
        rdata_cursor += plan.string_sizes[index] + 1;
    }
    rdata_cursor = (rdata_cursor + 3) & ~std::uint64_t(3);
    for (auto& table : plan.jump_tables) {
        table.table_rva = static_cast<std::uint32_t>(rdata_cursor);
        table.case_rvas.assign(table.case_count, 0);
        rdata_cursor += static_cast<std::uint64_t>(table.case_count) * 4;
    }
    rdata.virtual_size = align_up_u32(
        (std::max<std::uint64_t>)(rdata_cursor - rdata.rva, 1), 1);
    rva_cursor = static_cast<std::uint64_t>(rdata.rva) + rdata.virtual_size;

    plan.data_section_index = section_index++;
    auto& data = plan.sections[plan.data_section_index];
    data.name = ".data";
    data.rva = align_up_u32(rva_cursor, large_pe_section_alignment);
    plan.data_slots_rva = data.rva;
    const std::uint64_t slot_bytes =
        static_cast<std::uint64_t>(params.data_pointer_count) * 8;
    const std::uint64_t import_base = (data.rva + slot_bytes + 15) & ~std::uint64_t(15);
    plan.import_descriptor_rva = static_cast<std::uint32_t>(import_base);
    plan.ilt_rva = plan.import_descriptor_rva + 0x28;
    plan.iat_rva = plan.import_descriptor_rva + 0x38;
    plan.dll_name_rva = plan.import_descriptor_rva + 0x48;
    plan.import_name_rva = plan.import_descriptor_rva + 0x58;
    const std::uint64_t import_end = plan.import_name_rva + 2 + 12;
    data.virtual_size = align_up_u32(import_end - data.rva, 1);
    rva_cursor = static_cast<std::uint64_t>(data.rva) + data.virtual_size;

    plan.reloc_section_index = section_index++;
    auto& reloc = plan.sections[plan.reloc_section_index];
    reloc.name = ".reloc";
    reloc.rva = align_up_u32(rva_cursor, large_pe_section_alignment);
    const std::uint64_t data_pages =
        (data.virtual_size + large_pe_section_alignment - 1) / large_pe_section_alignment;
    std::uint64_t reloc_size = 0;
    for (std::uint64_t page = 0; page < data_pages; ++page) {
        const std::uint64_t page_first_byte = page * large_pe_section_alignment;
        std::uint64_t entries = 0;
        if (page_first_byte < slot_bytes) {
            const std::uint64_t in_page =
                (std::min<std::uint64_t>)(slot_bytes - page_first_byte,
                                          large_pe_section_alignment);
            entries = in_page / 8;
        }
        reloc_size += (8 + entries * 2 + 3) & ~std::uint64_t(3);
    }
    reloc.virtual_size = align_up_u32(reloc_size, 1);
    rva_cursor = static_cast<std::uint64_t>(reloc.rva) + reloc.virtual_size;

    plan.entry_point_rva = plan.sections[0].rva;
    plan.size_of_image = align_up_u32(rva_cursor, large_pe_section_alignment);
    plan.size_of_headers = align_up_u32(
        0x80 + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) +
            static_cast<std::uint64_t>(section_total) * sizeof(IMAGE_SECTION_HEADER),
        large_pe_file_alignment);

    std::uint64_t raw_cursor = plan.size_of_headers;
    for (auto& manifest : plan.sections) {
        manifest.raw_offset = static_cast<std::uint32_t>(raw_cursor);
        manifest.raw_size = align_up_u32(manifest.virtual_size, large_pe_file_alignment);
        raw_cursor += manifest.raw_size;
    }
    plan.file_size = raw_cursor;
    plan.instruction_count_estimate = (plan.code_bytes_total * 10) / 46 + 1;
    return plan;
}

struct large_pe_emit_state_t {
    splitmix64_t prng;
    std::vector<std::uint32_t> block_rvas;
    std::uint64_t cursor_rva = 0;
};

inline std::uint32_t emit_mov_imm(large_pe_emit_state_t& state,
                                  std::vector<std::uint8_t>& out)
{
    const std::uint8_t reg = static_cast<std::uint8_t>(state.prng.below(8));
    if ((state.prng.next() & 1) != 0) {
        out.push_back(0x48);
        out.push_back(static_cast<std::uint8_t>(0xB8 + reg));
        append_u64(out, state.prng.next());
        state.cursor_rva += 10;
        return 10;
    }
    out.push_back(static_cast<std::uint8_t>(0xB8 + reg));
    append_u32(out, static_cast<std::uint32_t>(state.prng.next()));
    state.cursor_rva += 5;
    return 5;
}

inline void emit_mov_imm32(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out)
{
    const std::uint8_t reg = static_cast<std::uint8_t>(state.prng.below(8));
    out.push_back(static_cast<std::uint8_t>(0xB8 + reg));
    append_u32(out, static_cast<std::uint32_t>(state.prng.next()));
    state.cursor_rva += 5;
}

inline void emit_mov_reg(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out)
{
    const std::uint8_t dst = static_cast<std::uint8_t>(state.prng.below(8));
    const std::uint8_t src = static_cast<std::uint8_t>(state.prng.below(8));
    append_bytes(out, {0x48, 0x8B, static_cast<std::uint8_t>(0xC0 + dst * 8 + src)});
    state.cursor_rva += 3;
}

inline void emit_mov32_reg(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out)
{
    const std::uint8_t dst = static_cast<std::uint8_t>(state.prng.below(8));
    const std::uint8_t src = static_cast<std::uint8_t>(state.prng.below(8));
    append_bytes(out, {0x8B, static_cast<std::uint8_t>(0xC0 + dst * 8 + src)});
    state.cursor_rva += 2;
}

inline void emit_lea_rdata(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out,
                           std::uint32_t target_rva)
{
    const std::uint8_t reg = static_cast<std::uint8_t>(state.prng.below(8));
    append_bytes(out, {0x48, 0x8D, static_cast<std::uint8_t>(0x05 + reg * 8)});
    append_i32(out, rel_displacement(target_rva, state.cursor_rva + 7));
    state.cursor_rva += 7;
}

inline void emit_load_rip(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out,
                          std::uint32_t target_rva)
{
    const std::uint8_t reg = static_cast<std::uint8_t>(state.prng.below(8));
    append_bytes(out, {0x48, 0x8B, static_cast<std::uint8_t>(0x05 + reg * 8)});
    append_i32(out, rel_displacement(target_rva, state.cursor_rva + 7));
    state.cursor_rva += 7;
}

inline void emit_alu4(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out)
{
    static const std::uint8_t opcodes[6] = {0xC0, 0xC8, 0xE0, 0xE8, 0xF0, 0xF8};
    const std::uint8_t reg = static_cast<std::uint8_t>(state.prng.below(8));
    const std::uint8_t opcode = opcodes[state.prng.below(6)];
    append_bytes(out, {0x48, 0x83, static_cast<std::uint8_t>(opcode + reg),
        static_cast<std::uint8_t>(state.prng.next() & 0x7F)});
    state.cursor_rva += 4;
}

inline std::uint32_t emit_alu(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out)
{
    if (state.prng.below(7) == 6) {
        const std::uint8_t dst = static_cast<std::uint8_t>(state.prng.below(8));
        const std::uint8_t src = static_cast<std::uint8_t>(state.prng.below(8));
        append_bytes(out, {0x48, 0x85, static_cast<std::uint8_t>(0xC0 + dst * 8 + src)});
        state.cursor_rva += 3;
        return 3;
    }
    emit_alu4(state, out);
    return 4;
}

inline void emit_exact_fill(large_pe_emit_state_t& state, std::vector<std::uint8_t>& out,
                            std::uint32_t bytes)
{
    while (bytes != 0) {
        if (bytes == 1)
            throw fixture_error_t("large PE body fill reached a single-byte remainder");
        if (bytes == 5 || bytes >= 9) {
            emit_mov_imm32(state, out);
            bytes -= 5;
        } else if (bytes >= 4) {
            emit_alu4(state, out);
            bytes -= 4;
        } else if (bytes == 3) {
            emit_mov_reg(state, out);
            bytes -= 3;
        } else {
            emit_mov32_reg(state, out);
            bytes -= 2;
        }
    }
}

inline std::vector<std::uint8_t> build_function_body(
    large_pe_plan_t& plan, std::uint32_t function_index,
    large_pe_emit_state_t& state)
{
    const auto& fn = plan.functions[function_index];
    std::vector<std::uint8_t> out;
    out.reserve(fn.byte_size);
    state.cursor_rva = fn.rva;
    state.block_rvas.clear();

    const std::uint8_t prologue_imm8 = static_cast<std::uint8_t>(
        8 + state.prng.below(15) * 8);
    const std::uint32_t prologue_imm32 =
        0x40 + static_cast<std::uint32_t>(state.prng.below(0x200)) * 16;
    const std::uint32_t prologue_len = prologue_length(fn.prologue_kind);
    const std::uint32_t epilogue_len = epilogue_base_length(fn.prologue_kind) +
        ((fn.flags & large_pe_fn_tail_call) != 0 ? 4U : 0U);
    std::uint32_t prefix_len = 0;
    if ((fn.flags & large_pe_fn_entry) != 0)
        prefix_len += 11;
    if ((fn.flags & large_pe_fn_jump_table) != 0)
        prefix_len += 7;
    if (fn.byte_size < prologue_len + epilogue_len + prefix_len + 2)
        throw fixture_error_t("large PE function plan underflowed its byte budget");

    switch (fn.prologue_kind) {
    case 0:
        append_bytes(out, {0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC});
        out.push_back(prologue_imm8);
        break;
    case 1:
        append_bytes(out, {0x48, 0x81, 0xEC});
        append_u32(out, prologue_imm32);
        break;
    default:
        append_bytes(out, {0x53, 0x56, 0x57, 0x48, 0x83, 0xEC});
        out.push_back(prologue_imm8);
        break;
    }
    state.cursor_rva += prologue_len;

    if ((fn.flags & large_pe_fn_entry) != 0) {
        append_bytes(out, {0xFF, 0x15});
        append_i32(out, rel_displacement(plan.iat_rva, state.cursor_rva + 6));
        append_bytes(out, {0xB8, 0x00, 0x00, 0x00, 0x00});
        state.cursor_rva += 11;
    }
    if ((fn.flags & large_pe_fn_jump_table) != 0) {
        const auto table_it = std::find_if(plan.jump_tables.begin(), plan.jump_tables.end(),
            [function_index](const large_pe_jump_table_plan_t& table) {
                return table.function_index == function_index;
            });
        if (table_it == plan.jump_tables.end())
            throw fixture_error_t("large PE jump table plan is inconsistent");
        append_bytes(out, {0x48, 0x8D, 0x05});
        append_i32(out, rel_displacement(table_it->table_rva, state.cursor_rva + 7));
        state.cursor_rva += 7;
    }

    const std::uint32_t body_budget = fn.byte_size - prologue_len - epilogue_len - prefix_len;
    const std::uint32_t block_total = (std::max<std::uint32_t>)(1,
        (std::min<std::uint32_t>)(fn.block_count, body_budget / 4));
    std::uint32_t emitted = 0;
    std::uint32_t block_index = 0;
    state.block_rvas.push_back(static_cast<std::uint32_t>(state.cursor_rva));
    std::uint32_t block_target = (std::max<std::uint32_t>)(4, body_budget / block_total) +
        static_cast<std::uint32_t>(state.prng.below(8));
    const std::uint32_t call_ceiling = 70 + plan.params.call_density_pct;
    const std::uint32_t jcc_ceiling = call_ceiling +
        plan.params.jump_density_pct * 3U / 4U;
    const std::uint32_t jmp_ceiling = jcc_ceiling +
        (plan.params.jump_density_pct - plan.params.jump_density_pct * 3U / 4U);

    while (emitted < body_budget) {
        const std::uint32_t remaining = body_budget - emitted;
        if (remaining <= 12) {
            emit_exact_fill(state, out, remaining);
            emitted = body_budget;
            break;
        }
        const std::uint64_t pick = state.prng.below(100);
        if (pick < 18) {
            emitted += emit_mov_imm(state, out);
        } else if (pick < 32) {
            emit_mov_reg(state, out);
            emitted += 3;
        } else if (pick < 40) {
            if (!plan.string_rvas.empty()) {
                const std::uint32_t target = plan.string_rvas[
                    state.prng.below(plan.string_rvas.size())];
                emit_lea_rdata(state, out, target);
                emitted += 7;
            } else {
                emitted += emit_alu(state, out);
            }
        } else if (pick < 48) {
            if (plan.params.data_pointer_count != 0) {
                const std::uint32_t target = plan.data_slots_rva +
                    static_cast<std::uint32_t>(
                        state.prng.below(plan.params.data_pointer_count)) * 8;
                emit_load_rip(state, out, target);
                emitted += 7;
            } else {
                emitted += emit_alu(state, out);
            }
        } else if (pick < 70 || pick >= jmp_ceiling) {
            emitted += emit_alu(state, out);
        } else if (pick < call_ceiling) {
            const bool backward_possible = function_index != 0;
            const bool forward_possible =
                function_index + 1 < plan.functions.size();
            const bool backward = backward_possible &&
                (!forward_possible || state.prng.below(10) < 7);
            std::uint32_t target_index = function_index;
            if (backward) {
                target_index = static_cast<std::uint32_t>(
                    state.prng.below(function_index));
            } else if (forward_possible) {
                target_index = function_index + 1 + static_cast<std::uint32_t>(
                    state.prng.below(plan.functions.size() - function_index - 1));
            }
            if (target_index == function_index) {
                emitted += emit_alu(state, out);
            } else {
                out.push_back(0xE8);
                append_i32(out, rel_displacement(
                    plan.functions[target_index].rva, state.cursor_rva + 5));
                state.cursor_rva += 5;
                emitted += 5;
            }
        } else if (pick < jcc_ceiling) {
            const std::uint32_t label = state.block_rvas[
                state.prng.below(state.block_rvas.size())];
            append_bytes(out, {0x0F, static_cast<std::uint8_t>(0x84 +
                state.prng.below(12))});
            append_i32(out, rel_displacement(label, state.cursor_rva + 6));
            state.cursor_rva += 6;
            emitted += 6;
        } else {
            const std::uint32_t label = state.block_rvas[
                state.prng.below(state.block_rvas.size())];
            out.push_back(0xE9);
            append_i32(out, rel_displacement(label, state.cursor_rva + 5));
            state.cursor_rva += 5;
            emitted += 5;
        }
        if (block_index + 1 < block_total && emitted >= block_target &&
            body_budget - emitted > 12) {
            ++block_index;
            state.block_rvas.push_back(static_cast<std::uint32_t>(state.cursor_rva));
            block_target = emitted + (std::max<std::uint32_t>)(4,
                (body_budget - emitted) / (block_total - block_index)) +
                static_cast<std::uint32_t>(state.prng.below(8));
        }
    }
    while (state.block_rvas.size() < block_total)
        state.block_rvas.push_back(static_cast<std::uint32_t>(state.cursor_rva));

    std::uint32_t adjust_len = 0;
    switch (fn.prologue_kind) {
    case 0:
        append_bytes(out, {0x48, 0x83, 0xC4});
        out.push_back(prologue_imm8);
        out.push_back(0x5D);
        adjust_len = 5;
        break;
    case 1:
        append_bytes(out, {0x48, 0x81, 0xC4});
        append_u32(out, prologue_imm32);
        adjust_len = 7;
        break;
    default:
        append_bytes(out, {0x48, 0x83, 0xC4});
        out.push_back(prologue_imm8);
        append_bytes(out, {0x5F, 0x5E, 0x5B});
        adjust_len = 7;
        break;
    }
    state.cursor_rva += adjust_len;
    if ((fn.flags & large_pe_fn_tail_call) != 0) {
        const std::uint32_t target_index = static_cast<std::uint32_t>(
            state.prng.below(function_index));
        out.push_back(0xE9);
        append_i32(out, rel_displacement(
            plan.functions[target_index].rva, state.cursor_rva + 5));
        state.cursor_rva += 5;
    } else {
        out.push_back(0xC3);
        state.cursor_rva += 1;
    }
    if (out.size() != fn.byte_size)
        throw fixture_error_t("large PE function emission diverged from its byte plan");
    if (state.cursor_rva != static_cast<std::uint64_t>(fn.rva) + fn.byte_size)
        throw fixture_error_t("large PE function emission diverged from its RVA plan");

    if ((fn.flags & large_pe_fn_jump_table) != 0) {
        const auto table_it = std::find_if(plan.jump_tables.begin(), plan.jump_tables.end(),
            [function_index](const large_pe_jump_table_plan_t& table) {
                return table.function_index == function_index;
            });
        if (table_it == plan.jump_tables.end())
            throw fixture_error_t("large PE jump table plan is inconsistent");
        for (auto& case_rva : table_it->case_rvas) {
            case_rva = state.block_rvas[
                state.prng.below(state.block_rvas.size())];
        }
    }
    return out;
}

class large_pe_sha256_stream_t {
public:
    void open()
    {
        BCRYPT_ALG_HANDLE raw_algorithm = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &raw_algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (!BCRYPT_SUCCESS(status))
            throw fixture_error_t("BCryptOpenAlgorithmProvider failed for large PE digest");
        algorithm_.reset(raw_algorithm);
        DWORD object_bytes = 0;
        DWORD result_bytes = 0;
        status = BCryptGetProperty(raw_algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_bytes), sizeof(object_bytes), &result_bytes, 0);
        if (!BCRYPT_SUCCESS(status) || result_bytes != sizeof(object_bytes) ||
            object_bytes == 0)
            throw fixture_error_t("BCryptGetProperty failed for large PE digest");
        object_.resize(object_bytes);
        BCRYPT_HASH_HANDLE raw_hash = nullptr;
        status = BCryptCreateHash(raw_algorithm, &raw_hash, object_.data(),
            static_cast<ULONG>(object_.size()), nullptr, 0, 0);
        if (!BCRYPT_SUCCESS(status))
            throw fixture_error_t("BCryptCreateHash failed for large PE digest");
        hash_.reset(raw_hash);
    }

    void update(const std::uint8_t* data, std::size_t size)
    {
        while (size != 0) {
            const auto chunk = static_cast<ULONG>(
                (std::min<std::size_t>)(size, 0x10000000ULL));
            const NTSTATUS status = BCryptHashData(
                static_cast<BCRYPT_HASH_HANDLE>(hash_.get()),
                const_cast<PUCHAR>(data), chunk, 0);
            if (!BCRYPT_SUCCESS(status))
                throw fixture_error_t("BCryptHashData failed for large PE digest");
            data += chunk;
            size -= chunk;
        }
    }

    std::array<std::uint8_t, 32> finish()
    {
        std::array<std::uint8_t, 32> digest{};
        const NTSTATUS status = BCryptFinishHash(
            static_cast<BCRYPT_HASH_HANDLE>(hash_.get()), digest.data(),
            static_cast<ULONG>(digest.size()), 0);
        if (!BCRYPT_SUCCESS(status))
            throw fixture_error_t("BCryptFinishHash failed for large PE digest");
        return digest;
    }

private:
    struct algorithm_closer_t {
        void operator()(void* value) const noexcept {
            if (value)
                BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(value), 0);
        }
    };
    struct hash_closer_t {
        void operator()(void* value) const noexcept {
            if (value)
                BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(value));
        }
    };
    std::unique_ptr<void, algorithm_closer_t> algorithm_;
    std::unique_ptr<void, hash_closer_t> hash_;
    std::vector<std::uint8_t> object_;
};

inline std::string large_pe_hex(const std::uint8_t* bytes, std::size_t size)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string hex;
    hex.resize(size * 2);
    for (std::size_t index = 0; index < size; ++index) {
        hex[index * 2] = digits[bytes[index] >> 4];
        hex[index * 2 + 1] = digits[bytes[index] & 0x0F];
    }
    return hex;
}

struct large_pe_vector_sink_t {
    std::vector<std::uint8_t> output;
    std::uint64_t offset = 0;
    void bytes(const void* data, std::size_t size)
    {
        const auto* first = static_cast<const std::uint8_t*>(data);
        output.insert(output.end(), first, first + size);
        offset += size;
    }
    void fill(std::uint8_t value, std::size_t count)
    {
        output.insert(output.end(), count, value);
        offset += count;
    }
};

struct large_pe_hash_sink_t {
    large_pe_sha256_stream_t stream;
    std::uint64_t offset = 0;
    void bytes(const void* data, std::size_t size)
    {
        stream.update(static_cast<const std::uint8_t*>(data), size);
        offset += size;
    }
    void fill(std::uint8_t value, std::size_t count)
    {
        std::array<std::uint8_t, 4096> chunk{};
        chunk.fill(value);
        while (count != 0) {
            const std::size_t amount = (std::min<std::size_t>)(count, chunk.size());
            stream.update(chunk.data(), amount);
            offset += amount;
            count -= amount;
        }
    }
};

struct large_pe_file_sink_t {
    std::ofstream stream;
    std::vector<std::uint8_t> buffer;
    std::uint64_t offset = 0;
    explicit large_pe_file_sink_t(const std::filesystem::path& path)
    {
        buffer.reserve(1024 * 1024);
        stream.open(path, std::ios::binary | std::ios::trunc);
        if (!stream)
            throw fixture_error_t("unable to open large PE output stream");
    }
    void flush()
    {
        if (buffer.empty())
            return;
        stream.write(reinterpret_cast<const char*>(buffer.data()),
            static_cast<std::streamsize>(buffer.size()));
        buffer.clear();
        if (!stream)
            throw fixture_error_t("large PE output stream write failed");
    }
    void bytes(const void* data, std::size_t size)
    {
        const auto* first = static_cast<const std::uint8_t*>(data);
        while (size != 0) {
            if (buffer.size() == 1024 * 1024)
                flush();
            const std::size_t amount =
                (std::min<std::size_t>)(size, 1024 * 1024 - buffer.size());
            buffer.insert(buffer.end(), first, first + amount);
            first += amount;
            size -= amount;
            offset += amount;
        }
    }
    void fill(std::uint8_t value, std::size_t count)
    {
        std::array<std::uint8_t, 4096> chunk{};
        chunk.fill(value);
        while (count != 0) {
            const std::size_t amount = (std::min<std::size_t>)(count, chunk.size());
            bytes(chunk.data(), amount);
            count -= amount;
        }
    }
    void finish()
    {
        flush();
        stream.flush();
        if (!stream)
            throw fixture_error_t("large PE output stream finalize failed");
    }
};

template <typename sink_t>
void emit_large_pe64(large_pe_plan_t& plan, sink_t& sink)
{
    large_pe_emit_state_t state;
    state.prng.state = plan.params.seed ^ 0xC0DEC0DEC0DEC0DEULL;

    std::vector<std::uint8_t> headers(plan.size_of_headers, 0);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    fixture_store(headers, 0, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = static_cast<WORD>(plan.sections.size());
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.FileHeader.Characteristics =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.AddressOfEntryPoint = plan.entry_point_rva;
    nt.OptionalHeader.BaseOfCode = plan.sections[0].rva;
    nt.OptionalHeader.ImageBase = large_pe_image_base;
    nt.OptionalHeader.SectionAlignment = large_pe_section_alignment;
    nt.OptionalHeader.FileAlignment = large_pe_file_alignment;
    nt.OptionalHeader.MajorOperatingSystemVersion = 10;
    nt.OptionalHeader.MajorSubsystemVersion = 10;
    nt.OptionalHeader.SizeOfImage = plan.size_of_image;
    nt.OptionalHeader.SizeOfHeaders = plan.size_of_headers;
    nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt.OptionalHeader.SizeOfStackReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfStackCommit = 4096;
    nt.OptionalHeader.SizeOfHeapReserve = 1ULL << 20;
    nt.OptionalHeader.SizeOfHeapCommit = 4096;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    if (plan.has_pdata) {
        const auto& pdata = plan.sections[plan.pdata_section_index];
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {
            pdata.rva, pdata.virtual_size};
    }
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
        plan.import_descriptor_rva,
        2U * static_cast<DWORD>(sizeof(IMAGE_IMPORT_DESCRIPTOR))};
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {plan.iat_rva, 16};
    const auto& reloc_manifest = plan.sections[plan.reloc_section_index];
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {
        reloc_manifest.rva, reloc_manifest.virtual_size};
    fixture_store(headers, static_cast<std::size_t>(dos.e_lfanew), nt);

    std::vector<IMAGE_SECTION_HEADER> section_headers(plan.sections.size());
    for (std::size_t index = 0; index < plan.sections.size(); ++index) {
        const auto& manifest = plan.sections[index];
        auto& header = section_headers[index];
        const std::size_t name_size =
            (std::min<std::size_t>)(manifest.name.size(), sizeof(header.Name));
        std::memcpy(header.Name, manifest.name.data(), name_size);
        header.Misc.VirtualSize = manifest.virtual_size;
        header.VirtualAddress = manifest.rva;
        header.SizeOfRawData = manifest.raw_size;
        header.PointerToRawData = manifest.raw_offset;
        const bool code = index < plan.params.code_sections;
        const bool data_section = index == plan.data_section_index;
        const bool reloc_section = index == plan.reloc_section_index;
        header.Characteristics =
            code ? (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ) :
            data_section ? (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
                            IMAGE_SCN_MEM_WRITE) :
            reloc_section ? (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
                             IMAGE_SCN_MEM_DISCARDABLE) :
            (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    }
    const std::size_t section_offset = static_cast<std::size_t>(dos.e_lfanew) +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    fixture_store(headers, section_offset, section_headers.data(),
        section_headers.size() * sizeof(section_headers[0]));
    sink.bytes(headers.data(), headers.size());

    std::uint64_t expected_offset = plan.size_of_headers;
    const auto expect = [&sink](std::uint64_t offset, const char* phase) {
        if (sink.offset != offset)
            throw fixture_error_t(std::string("large PE emitter stream diverged at ") + phase);
    };
    expect(expected_offset, "headers");

    std::uint32_t functions_emitted = 0;
    std::vector<std::uint8_t> body;
    for (std::uint32_t section = 0; section < plan.params.code_sections; ++section) {
        const auto& manifest = plan.sections[section];
        const std::uint32_t partition_begin =
            section * static_cast<std::uint32_t>(plan.functions.size()) /
            plan.params.code_sections;
        const std::uint32_t partition_end =
            (section + 1) * static_cast<std::uint32_t>(plan.functions.size()) /
            plan.params.code_sections;
        std::uint64_t cursor = manifest.rva;
        for (std::uint32_t index = partition_begin; index < partition_end; ++index) {
            const auto& fn = plan.functions[index];
            if (fn.rva < cursor)
                throw fixture_error_t("large PE function RVAs are not ascending");
            sink.fill(0xCC, static_cast<std::size_t>(fn.rva - cursor));
            body = build_function_body(plan, index, state);
            sink.bytes(body.data(), body.size());
            cursor = static_cast<std::uint64_t>(fn.rva) + fn.byte_size;
            functions_emitted = index + 1;
        }
        const std::uint64_t section_end =
            static_cast<std::uint64_t>(manifest.rva) + manifest.virtual_size;
        if (cursor > section_end)
            throw fixture_error_t("large PE code section overran its virtual extent");
        sink.fill(0xCC, static_cast<std::size_t>(section_end - cursor));
        sink.fill(0, manifest.raw_size - manifest.virtual_size);
        expected_offset += manifest.raw_size;
        expect(expected_offset, manifest.name.c_str());
    }
    if (functions_emitted != plan.functions.size())
        throw fixture_error_t("large PE emitter lost functions");

    if (plan.has_pdata) {
        std::vector<std::uint8_t> pdata;
        pdata.reserve(plan.functions.size() * sizeof(RUNTIME_FUNCTION));
        const auto& xdata = plan.sections[plan.xdata_section_index];
        for (const auto& fn : plan.functions) {
            RUNTIME_FUNCTION record{};
            record.BeginAddress = fn.rva;
            record.EndAddress = fn.rva + fn.byte_size;
            record.UnwindData = xdata.rva +
                static_cast<std::uint32_t>(pdata.size() / sizeof(RUNTIME_FUNCTION)) * 4U;
            const auto* first = reinterpret_cast<const std::uint8_t*>(&record);
            pdata.insert(pdata.end(), first, first + sizeof(record));
        }
        sink.bytes(pdata.data(), pdata.size());
        const auto& manifest = plan.sections[plan.pdata_section_index];
        sink.fill(0, manifest.raw_size - manifest.virtual_size);
        expected_offset += manifest.raw_size;
        expect(expected_offset, ".pdata");

        std::vector<std::uint8_t> xdata_bytes(plan.functions.size() * 4, 0);
        for (std::size_t index = 0; index < plan.functions.size(); ++index)
            xdata_bytes[index * 4] = 0x09;
        sink.bytes(xdata_bytes.data(), xdata_bytes.size());
        sink.fill(0, xdata.raw_size - xdata.virtual_size);
        expected_offset += xdata.raw_size;
        expect(expected_offset, ".xdata");
    }

    const auto& rdata = plan.sections[plan.rdata_section_index];
    static constexpr char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.";
    std::uint64_t rdata_cursor = rdata.rva;
    for (const auto string_size : plan.string_sizes) {
        std::vector<std::uint8_t> value(string_size + 1, 0);
        for (std::uint32_t position = 0; position < string_size; ++position)
            value[position] = static_cast<std::uint8_t>(
                charset[state.prng.below(sizeof(charset) - 1)]);
        sink.bytes(value.data(), value.size());
        rdata_cursor += string_size + 1;
    }
    {
        const std::uint64_t aligned = (rdata_cursor + 3) & ~std::uint64_t(3);
        sink.fill(0, static_cast<std::size_t>(aligned - rdata_cursor));
        rdata_cursor = aligned;
    }
    for (const auto& table : plan.jump_tables) {
        if (table.table_rva != rdata_cursor)
            throw fixture_error_t("large PE jump table layout diverged during emission");
        for (const auto case_rva : table.case_rvas) {
            if (case_rva == 0)
                throw fixture_error_t("large PE jump table cases were not recorded");
            std::vector<std::uint8_t> entry;
            append_u32(entry, case_rva);
            sink.bytes(entry.data(), entry.size());
            rdata_cursor += 4;
        }
    }
    {
        const std::uint64_t rdata_end =
            static_cast<std::uint64_t>(rdata.rva) + rdata.virtual_size;
        if (rdata_cursor > rdata_end)
            throw fixture_error_t("large PE rdata emission overran its virtual extent");
        sink.fill(0, static_cast<std::size_t>(rdata_end - rdata_cursor));
        sink.fill(0, rdata.raw_size - rdata.virtual_size);
        expected_offset += rdata.raw_size;
        expect(expected_offset, ".rdata");
    }

    const auto& data = plan.sections[plan.data_section_index];
    std::vector<std::uint8_t> slots;
    slots.reserve(static_cast<std::size_t>(
        (std::min<std::uint32_t>)(plan.params.data_pointer_count, 1U << 16)) * 8);
    const std::uint64_t slot_bytes =
        static_cast<std::uint64_t>(plan.params.data_pointer_count) * 8;
    for (std::uint32_t index = 0; index < plan.params.data_pointer_count; ++index) {
        std::uint32_t target = 0;
        if (!plan.string_rvas.empty() && (index & 1U) != 0) {
            target = plan.string_rvas[
                static_cast<std::size_t>(index) % plan.string_rvas.size()];
        } else {
            target = plan.functions[
                static_cast<std::size_t>(index) % plan.functions.size()].rva;
        }
        append_u64(slots, large_pe_image_base + target);
    }
    sink.bytes(slots.data(), slots.size());
    std::vector<std::uint8_t> import_area;
    const std::uint64_t import_prefix =
        plan.import_descriptor_rva - (plan.data_slots_rva + slot_bytes);
    import_area.assign(static_cast<std::size_t>(import_prefix), 0);
    IMAGE_IMPORT_DESCRIPTOR descriptor{};
    descriptor.OriginalFirstThunk = plan.ilt_rva;
    descriptor.Name = plan.dll_name_rva;
    descriptor.FirstThunk = plan.iat_rva;
    const auto* descriptor_bytes = reinterpret_cast<const std::uint8_t*>(&descriptor);
    import_area.insert(import_area.end(), descriptor_bytes,
        descriptor_bytes + sizeof(descriptor));
    import_area.insert(import_area.end(), sizeof(IMAGE_IMPORT_DESCRIPTOR), 0);
    append_u64(import_area, plan.import_name_rva);
    append_u64(import_area, 0);
    append_u64(import_area, plan.import_name_rva);
    append_u64(import_area, 0);
    const char dll_name[] = "KERNEL32.dll";
    import_area.insert(import_area.end(), dll_name, dll_name + sizeof(dll_name));
    append_u16(import_area, 0);
    const char import_name[] = "ExitProcess";
    import_area.insert(import_area.end(), import_name, import_name + sizeof(import_name));
    sink.bytes(import_area.data(), import_area.size());
    {
        const std::uint64_t import_bytes = import_area.size();
        if (slot_bytes + import_bytes > data.virtual_size)
            throw fixture_error_t("large PE import area overran the data section");
        sink.fill(0, static_cast<std::size_t>(data.virtual_size - slot_bytes - import_bytes));
        sink.fill(0, data.raw_size - data.virtual_size);
        expected_offset += data.raw_size;
        expect(expected_offset, ".data");
    }

    const auto& reloc = plan.sections[plan.reloc_section_index];
    const std::uint64_t data_pages =
        (data.virtual_size + large_pe_section_alignment - 1) / large_pe_section_alignment;
    for (std::uint64_t page = 0; page < data_pages; ++page) {
        const std::uint64_t page_first_byte = page * large_pe_section_alignment;
        std::uint64_t entries = 0;
        if (page_first_byte < slot_bytes) {
            entries = (std::min<std::uint64_t>)(slot_bytes - page_first_byte,
                                                large_pe_section_alignment) / 8;
        }
        const std::uint32_t block_size = static_cast<std::uint32_t>(
            (8 + entries * 2 + 3) & ~std::uint64_t(3));
        std::vector<std::uint8_t> block;
        block.reserve(block_size);
        IMAGE_BASE_RELOCATION header{};
        header.VirtualAddress = data.rva + static_cast<DWORD>(page_first_byte);
        header.SizeOfBlock = block_size;
        const auto* header_bytes = reinterpret_cast<const std::uint8_t*>(&header);
        block.insert(block.end(), header_bytes, header_bytes + sizeof(header));
        for (std::uint64_t entry = 0; entry < entries; ++entry) {
            const std::uint16_t value = static_cast<std::uint16_t>(
                (IMAGE_REL_BASED_DIR64 << 12) |
                static_cast<std::uint16_t>(entry * 8));
            append_u16(block, value);
        }
        while (block.size() < block_size)
            block.push_back(0);
        sink.bytes(block.data(), block.size());
    }
    {
        std::uint64_t emitted = reloc.virtual_size;
        for (std::uint64_t page = 0; page < data_pages; ++page) {
            const std::uint64_t page_first_byte = page * large_pe_section_alignment;
            std::uint64_t entries = 0;
            if (page_first_byte < slot_bytes) {
                entries = (std::min<std::uint64_t>)(slot_bytes - page_first_byte,
                                                    large_pe_section_alignment) / 8;
            }
            emitted -= (8 + entries * 2 + 3) & ~std::uint64_t(3);
        }
        sink.fill(0, static_cast<std::size_t>(emitted));
        sink.fill(0, reloc.raw_size - reloc.virtual_size);
        expected_offset += reloc.raw_size;
        expect(expected_offset, ".reloc");
    }
    if (expected_offset != plan.file_size)
        throw fixture_error_t("large PE emitter size diverged from the manifest");
}

inline large_pe_manifest_t manifest_from_plan(const large_pe_plan_t& plan)
{
    large_pe_manifest_t manifest;
    manifest.sections = plan.sections;
    manifest.function_rva_begin = plan.functions.front().rva;
    manifest.function_rva_end = plan.functions.back().rva + plan.functions.back().byte_size;
    manifest.function_count = plan.functions.size();
    manifest.instruction_count_estimate = plan.instruction_count_estimate;
    manifest.code_bytes = plan.code_bytes_total;
    if (plan.has_pdata) {
        manifest.pdata_bytes = plan.sections[plan.pdata_section_index].virtual_size;
        manifest.xdata_bytes = plan.sections[plan.xdata_section_index].virtual_size;
    }
    manifest.rdata_bytes = plan.sections[plan.rdata_section_index].virtual_size;
    manifest.data_bytes = plan.sections[plan.data_section_index].virtual_size;
    manifest.reloc_bytes = plan.sections[plan.reloc_section_index].virtual_size;
    manifest.file_size = plan.file_size;
    return manifest;
}

}

inline large_pe_params_t validated_large_pe_params(const large_pe_params_t& params)
{
    constexpr std::uint64_t minimum_code = 1ULL * 1024ULL * 1024ULL;
    constexpr std::uint64_t maximum_code = 1024ULL * 1024ULL * 1024ULL;
    if (params.code_bytes < minimum_code || params.code_bytes > maximum_code)
        throw fixture_error_t("large PE code_bytes is outside the supported 1 MiB..1 GiB range");
    if (params.code_sections == 0 || params.code_sections > 8)
        throw fixture_error_t("large PE code_sections must be within 1..8");
    if (params.string_count > (1U << 20))
        throw fixture_error_t("large PE string_count exceeds the generator bound");
    if (params.data_pointer_count > (1U << 22))
        throw fixture_error_t("large PE data_pointer_count exceeds the generator bound");
    if (params.call_density_pct > 100 || params.jump_density_pct > 100 ||
        params.padding_pct > 100)
        throw fixture_error_t("large PE density percentages must be within 0..100");
    large_pe_params_t validated = params;
    if (validated.function_count == 0) {
        validated.function_count = static_cast<std::uint32_t>(
            (std::max<std::uint64_t>)(1, validated.code_bytes / 96));
    }
    if (validated.function_count > (1U << 26))
        throw fixture_error_t("large PE function_count exceeds the generator bound");
    if (validated.function_count < validated.code_sections)
        throw fixture_error_t("large PE function_count must cover every code section");
    if (validated.code_bytes < static_cast<std::uint64_t>(validated.function_count) * 16)
        throw fixture_error_t("large PE code_bytes cannot hold the requested functions");
    return validated;
}

inline large_pe_manifest_t describe_large_pe(const large_pe_params_t& params)
{
    return detail::manifest_from_plan(detail::plan_large_pe(params));
}

inline std::vector<std::uint8_t> build_large_pe64(const large_pe_params_t& params)
{
    auto plan = detail::plan_large_pe(params);
    constexpr std::uint64_t in_memory_limit = 128ULL * 1024ULL * 1024ULL;
    if (plan.file_size > in_memory_limit)
        throw fixture_error_t("build_large_pe64 is bounded to 128 MiB; use write_large_pe64");
    detail::large_pe_vector_sink_t sink;
    sink.output.reserve(static_cast<std::size_t>(plan.file_size));
    detail::emit_large_pe64(plan, sink);
    return std::move(sink.output);
}

inline void write_large_pe64(const std::filesystem::path& path,
                             const large_pe_params_t& params)
{
    auto plan = detail::plan_large_pe(params);
    std::error_code error;
    if (path.has_parent_path())
        std::filesystem::create_directories(path.parent_path(), error);
    if (error)
        throw fixture_error_t("unable to create large PE output directory: " + error.message());
    detail::large_pe_file_sink_t sink(path);
    detail::emit_large_pe64(plan, sink);
    sink.finish();
}

inline std::string large_pe_sha256(const large_pe_params_t& params)
{
    auto plan = detail::plan_large_pe(params);
    detail::large_pe_hash_sink_t sink;
    sink.stream.open();
    detail::emit_large_pe64(plan, sink);
    const auto digest = sink.stream.finish();
    return detail::large_pe_hex(digest.data(), digest.size());
}

}
