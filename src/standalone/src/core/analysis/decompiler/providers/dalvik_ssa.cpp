#include "dalvik_ssa.hpp"
#include "../isolated_worker_codec.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace aida::analysis::dalvik_ssa {
namespace {

constexpr std::uint32_t k_artifact_magic = 0x53534444U;
constexpr std::uint32_t k_artifact_version = 1;
constexpr std::uint32_t k_capture_magic = 0x32434444U;
constexpr std::uint32_t k_capture_version = 1;
constexpr std::size_t k_artifact_max_bytes = 32U * 1024U * 1024U;
constexpr std::uint32_t k_no_register = 0xFFFFFFFFU;
constexpr std::size_t k_max_blocks = 1U << 20;
constexpr std::size_t k_max_values = 1U << 22;
constexpr std::size_t k_max_types = 1U << 20;

const char* restored_mnemonic(const std::uint16_t opcode_unit, const std::uint8_t opcode) noexcept
{
    if (opcode == 0) {
        switch (opcode_unit >> 8U) {
        case 1: return "packed-switch-payload";
        case 2: return "sparse-switch-payload";
        case 3: return "fill-array-data-payload";
        default: break;
        }
    }
    return dalvik_opcode_mnemonic(opcode);
}

struct artifact_reader_t {
    const std::string& bytes;
    std::size_t offset = 0;

    bool u32(std::uint32_t& value) {
        if (offset > bytes.size() || bytes.size() - offset < sizeof(value))
            return false;
        value = 0;
        for (std::size_t index = 0; index < sizeof(value); ++index)
            value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset++])) << (index * 8U);
        return true;
    }

    bool string(std::string& value) {
        std::uint32_t size = 0;
        if (!u32(size) || size > k_artifact_max_bytes || offset > bytes.size() || bytes.size() - offset < size)
            return false;
        value.assign(bytes.data() + offset, size);
        offset += size;
        return true;
    }

    bool complete() const noexcept { return offset == bytes.size(); }
};

void append_u32(std::string& bytes, const std::uint32_t value)
{
    for (std::size_t index = 0; index < sizeof(value); ++index)
        bytes.push_back(static_cast<char>(value >> (index * 8U)));
}

bool append_string(std::string& bytes, const std::string& value)
{
    if (value.size() > k_artifact_max_bytes || bytes.size() > k_artifact_max_bytes - sizeof(std::uint32_t) - value.size())
        return false;
    append_u32(bytes, static_cast<std::uint32_t>(value.size()));
    bytes.append(value);
    return true;
}

decompiler_diagnostic_t diagnostic(const decompiler_diagnostic_severity_t severity,
                                    const decompiler_diagnostic_code_t code,
                                    std::string key,
                                    const std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = severity;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

source_coordinate_t make_coordinate(const dalvik_ssa_request_t& request,
                                    const decompiler_coordinate_layer_t layer,
                                    const std::uint32_t code_unit_offset,
                                    const std::uint32_t width = 1)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = request.workspace_generation;
    result.entity = request.entity;
    decompiler_address_range_t range;
    range.begin.space = address_space_id_t::relative_virtual;
    range.begin.value = code_unit_offset;
    range.begin.architecture = architecture_id_t::dalvik_bytecode;
    range.begin.mode = architecture_mode_t::dalvik;
    range.end = range.begin;
    range.end.value = code_unit_offset + width;
    result.address_range = range;
    return result;
}

source_coordinate_t make_coordinate_with_debug(const dalvik_ssa_request_t& request,
                                                const decompiler_coordinate_layer_t layer,
                                                const std::uint32_t code_unit_offset,
                                                const std::uint32_t width,
                                                const dex_code_item_t& code_item)
{
    auto coord = make_coordinate(request, layer, code_unit_offset, width);
    if (code_item.debug_info) {
        for (const auto& pos : code_item.debug_info->positions) {
            if (pos.address == code_unit_offset) {
                decompiler_source_origin_t origin;
                origin.source_artifact_hash = {};
                origin.source_path = "dalvik:" + request.dex_version;
                origin.first_line = static_cast<std::uint32_t>(pos.line);
                origin.last_line = static_cast<std::uint32_t>(pos.line);
                origin.first_column = 1;
                origin.last_column = 1;
                coord.source_origin = origin;
                break;
            }
        }
    }
    return coord;
}

bool is_wide_opcode(std::uint8_t opcode) noexcept
{
    switch (opcode) {
    case 0x04: case 0x05: case 0x06:
    case 0x0b:
    case 0x10:
    case 0x16: case 0x17: case 0x18: case 0x19:
    case 0x45:
    case 0x53:
    case 0x5a:
    case 0x61:
    case 0x68:
    case 0x7d: case 0x7e:
    case 0x80:
    case 0x81: case 0x83:
    case 0x84: case 0x86:
    case 0x88: case 0x89:
    case 0x8a: case 0x8b:
    case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f:
    case 0xa0: case 0xa1: case 0xa2:
    case 0xa3: case 0xa4: case 0xa5:
    case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf:
    case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
    case 0xc0: case 0xc1: case 0xc2:
    case 0xc3: case 0xc4: case 0xc5:
    case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf:
    case 0x2f: case 0x30: case 0x31:
    case 0x4c:
        return true;
    default:
        return false;
    }
}

bool is_wide_source2_opcode(std::uint8_t opcode) noexcept
{
    switch (opcode) {
    case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f:
    case 0xa0: case 0xa1: case 0xa2:
    case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf:
    case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf:
    case 0xc0: case 0xc1: case 0xc2:
    case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf:
    case 0x2f: case 0x30: case 0x31:
        return true;
    default:
        return false;
    }
}

bool is_shift_long_opcode(std::uint8_t opcode) noexcept
{
    return opcode >= 0xa3 && opcode <= 0xa5;
}

bool is_2addr_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0xb0 && opcode <= 0xcf);
}

bool is_branch_opcode(std::uint8_t opcode) noexcept
{
    return opcode == 0x28 || opcode == 0x29 || opcode == 0x2a;
}

bool is_conditional_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0x32 && opcode <= 0x3d);
}

bool is_switch_opcode(std::uint8_t opcode) noexcept
{
    return opcode == 0x2b || opcode == 0x2c;
}

bool is_return_opcode(std::uint8_t opcode) noexcept
{
    return opcode >= 0x0e && opcode <= 0x11;
}

bool is_throw_opcode(std::uint8_t opcode) noexcept
{
    return opcode == 0x27;
}

bool is_invoke_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0x6e && opcode <= 0x72) || (opcode >= 0x74 && opcode <= 0x78);
}

bool is_invoke_range_opcode(std::uint8_t opcode) noexcept
{
    return opcode >= 0x74 && opcode <= 0x78;
}

bool is_move_result_opcode(std::uint8_t opcode) noexcept
{
    return opcode >= 0x0a && opcode <= 0x0c;
}

bool is_field_load_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0x52 && opcode <= 0x58) || (opcode >= 0x60 && opcode <= 0x66);
}

bool is_field_store_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0x59 && opcode <= 0x5f) || (opcode >= 0x67 && opcode <= 0x6d);
}

bool is_array_load_opcode(std::uint8_t opcode) noexcept
{
    return opcode >= 0x44 && opcode <= 0x4a;
}

bool is_array_store_opcode(std::uint8_t opcode) noexcept
{
    return opcode >= 0x4b && opcode <= 0x51;
}

bool is_unary_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0x7b && opcode <= 0x8f);
}

bool is_binary_3reg_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0x90 && opcode <= 0xaf);
}

bool is_binary_lit_opcode(std::uint8_t opcode) noexcept
{
    return (opcode >= 0xd0 && opcode <= 0xe2);
}

bool is_monitor_opcode(std::uint8_t opcode) noexcept
{
    return opcode == 0x1d || opcode == 0x1e;
}

bool is_terminator_opcode(std::uint8_t opcode) noexcept
{
    return is_branch_opcode(opcode) || is_return_opcode(opcode) || is_throw_opcode(opcode) ||
           is_switch_opcode(opcode);
}

hir_node_kind_t hir_kind_for_opcode(std::uint8_t opcode)
{
    if (opcode == 0x00) return hir_node_kind_t::unknown;
    if (opcode >= 0x01 && opcode <= 0x0d) return hir_node_kind_t::assignment;
    if (opcode >= 0x0e && opcode <= 0x11) return hir_node_kind_t::return_value;
    if (opcode >= 0x12 && opcode <= 0x19) return hir_node_kind_t::literal;
    if (opcode >= 0x1a && opcode <= 0x1c) return hir_node_kind_t::reference;
    if (opcode >= 0x1d && opcode <= 0x1e) return hir_node_kind_t::unknown;
    if (opcode == 0x1f) return hir_node_kind_t::cast;
    if (opcode == 0x20) return hir_node_kind_t::binary;
    if (opcode == 0x21) return hir_node_kind_t::unary;
    if (opcode == 0x22 || opcode == 0x23) return hir_node_kind_t::reference;
    if (opcode >= 0x24 && opcode <= 0x25) return hir_node_kind_t::reference;
    if (opcode == 0x26) return hir_node_kind_t::store;
    if (opcode == 0x27) return hir_node_kind_t::throw_value;
    if (opcode >= 0x28 && opcode <= 0x2a) return hir_node_kind_t::branch;
    if (opcode >= 0x2b && opcode <= 0x2c) return hir_node_kind_t::switch_branch;
    if (opcode >= 0x2d && opcode <= 0x31) return hir_node_kind_t::binary;
    if (opcode >= 0x32 && opcode <= 0x3d) return hir_node_kind_t::conditional;
    if (opcode >= 0x44 && opcode <= 0x4a) return hir_node_kind_t::index;
    if (opcode >= 0x4b && opcode <= 0x51) return hir_node_kind_t::index;
    if (opcode >= 0x52 && opcode <= 0x58) return hir_node_kind_t::field;
    if (opcode >= 0x59 && opcode <= 0x5f) return hir_node_kind_t::field;
    if (opcode >= 0x60 && opcode <= 0x66) return hir_node_kind_t::field;
    if (opcode >= 0x67 && opcode <= 0x6d) return hir_node_kind_t::field;
    if (opcode >= 0x6e && opcode <= 0x78) return hir_node_kind_t::call;
    if (opcode >= 0x7b && opcode <= 0x8f) return hir_node_kind_t::unary;
    if (opcode >= 0x90 && opcode <= 0xaf) return hir_node_kind_t::binary;
    if (opcode >= 0xb0 && opcode <= 0xcf) return hir_node_kind_t::binary;
    if (opcode >= 0xd0 && opcode <= 0xe2) return hir_node_kind_t::binary;
    if (opcode >= 0xfa && opcode <= 0xfd) return hir_node_kind_t::call;
    if (opcode >= 0xfe && opcode <= 0xff) return hir_node_kind_t::reference;
    return hir_node_kind_t::unknown;
}

provider_ir_opcode_t ir_opcode_for_opcode(std::uint8_t opcode)
{
    if (opcode == 0x00) return provider_ir_opcode_t::unknown;
    if (opcode >= 0x01 && opcode <= 0x0d) return provider_ir_opcode_t::copy;
    if (opcode >= 0x0e && opcode <= 0x11) return provider_ir_opcode_t::return_value;
    if (opcode >= 0x12 && opcode <= 0x19) return provider_ir_opcode_t::constant;
    if (opcode >= 0x1a && opcode <= 0x1c) return provider_ir_opcode_t::constant;
    if (opcode == 0x1d) return provider_ir_opcode_t::monitor_enter;
    if (opcode == 0x1e) return provider_ir_opcode_t::monitor_exit;
    if (opcode == 0x1f) return provider_ir_opcode_t::cast;
    if (opcode == 0x20) return provider_ir_opcode_t::binary;
    if (opcode == 0x21) return provider_ir_opcode_t::unary;
    if (opcode == 0x22 || opcode == 0x23) return provider_ir_opcode_t::constant;
    if (opcode >= 0x24 && opcode <= 0x25) return provider_ir_opcode_t::constant;
    if (opcode == 0x26) return provider_ir_opcode_t::store;
    if (opcode == 0x27) return provider_ir_opcode_t::throw_value;
    if (opcode >= 0x28 && opcode <= 0x2a) return provider_ir_opcode_t::branch;
    if (opcode >= 0x2b && opcode <= 0x2c) return provider_ir_opcode_t::switch_branch;
    if (opcode >= 0x2d && opcode <= 0x31) return provider_ir_opcode_t::binary;
    if (opcode >= 0x32 && opcode <= 0x3d) return provider_ir_opcode_t::conditional_branch;
    if (opcode >= 0x44 && opcode <= 0x4a) return provider_ir_opcode_t::array_load;
    if (opcode >= 0x4b && opcode <= 0x51) return provider_ir_opcode_t::array_store;
    if (opcode >= 0x52 && opcode <= 0x58) return provider_ir_opcode_t::field_load;
    if (opcode >= 0x59 && opcode <= 0x5f) return provider_ir_opcode_t::field_store;
    if (opcode >= 0x60 && opcode <= 0x66) return provider_ir_opcode_t::field_load;
    if (opcode >= 0x67 && opcode <= 0x6d) return provider_ir_opcode_t::field_store;
    if (opcode >= 0x6e && opcode <= 0x78) return provider_ir_opcode_t::call;
    if (opcode >= 0x7b && opcode <= 0x8f) return provider_ir_opcode_t::unary;
    if (opcode >= 0x90 && opcode <= 0xaf) return provider_ir_opcode_t::binary;
    if (opcode >= 0xb0 && opcode <= 0xcf) return provider_ir_opcode_t::binary;
    if (opcode >= 0xd0 && opcode <= 0xe2) return provider_ir_opcode_t::binary;
    if (opcode >= 0xfa && opcode <= 0xfd) return provider_ir_opcode_t::call;
    if (opcode >= 0xfe && opcode <= 0xff) return provider_ir_opcode_t::constant;
    return provider_ir_opcode_t::unknown;
}

struct instruction_info_t {
    std::uint32_t dest_reg = k_no_register;
    bool dest_wide = false;
    std::vector<std::uint32_t> src_regs;
    std::vector<bool> src_wide;
    std::vector<std::uint32_t> range_regs;
    bool is_branch = false;
    bool is_conditional = false;
    bool is_switch = false;
    bool is_return = false;
    bool is_throw = false;
    bool is_invoke = false;
    bool is_invoke_range = false;
    bool is_terminator = false;
    bool has_dest = false;
    bool has_result = false;
    bool is_move_result = false;
    bool is_move_exception = false;
    bool is_monitor = false;
    bool is_field_load = false;
    bool is_field_store = false;
    bool is_array_load = false;
    bool is_array_store = false;
    bool is_payload = false;
    bool is_2addr = false;
    hir_node_kind_t hir_kind = hir_node_kind_t::unknown;
    provider_ir_opcode_t ir_opcode = provider_ir_opcode_t::unknown;
    std::uint32_t branch_target_offset = 0;
    std::uint32_t fallthrough_offset = 0;
    bool has_fallthrough = true;
};

dalvik_format_t format_table[256];
std::once_flag format_table_once;

void init_format_table()
{
    for (int i = 0; i < 256; ++i)
        format_table[i] = dalvik_format_t::funknown;

    format_table[0x00] = dalvik_format_t::f10x;
    format_table[0x01] = dalvik_format_t::f12x;
    format_table[0x02] = dalvik_format_t::f22x;
    format_table[0x03] = dalvik_format_t::f32x;
    format_table[0x04] = dalvik_format_t::f12x;
    format_table[0x05] = dalvik_format_t::f22x;
    format_table[0x06] = dalvik_format_t::f32x;
    format_table[0x07] = dalvik_format_t::f12x;
    format_table[0x08] = dalvik_format_t::f22x;
    format_table[0x09] = dalvik_format_t::f32x;
    format_table[0x0a] = dalvik_format_t::f11x;
    format_table[0x0b] = dalvik_format_t::f11x;
    format_table[0x0c] = dalvik_format_t::f11x;
    format_table[0x0d] = dalvik_format_t::f11x;
    format_table[0x0e] = dalvik_format_t::f10x;
    format_table[0x0f] = dalvik_format_t::f11x;
    format_table[0x10] = dalvik_format_t::f11x;
    format_table[0x11] = dalvik_format_t::f11x;
    format_table[0x12] = dalvik_format_t::f11n;
    format_table[0x13] = dalvik_format_t::f21s;
    format_table[0x14] = dalvik_format_t::f31i;
    format_table[0x15] = dalvik_format_t::f21h;
    format_table[0x16] = dalvik_format_t::f21s;
    format_table[0x17] = dalvik_format_t::f31i;
    format_table[0x18] = dalvik_format_t::f51l;
    format_table[0x19] = dalvik_format_t::f21h;
    format_table[0x1a] = dalvik_format_t::f21c;
    format_table[0x1b] = dalvik_format_t::f31c;
    format_table[0x1c] = dalvik_format_t::f21c;
    format_table[0x1d] = dalvik_format_t::f11x;
    format_table[0x1e] = dalvik_format_t::f11x;
    format_table[0x1f] = dalvik_format_t::f21c;
    format_table[0x20] = dalvik_format_t::f22c;
    format_table[0x21] = dalvik_format_t::f12x;
    format_table[0x22] = dalvik_format_t::f21c;
    format_table[0x23] = dalvik_format_t::f22c;
    format_table[0x24] = dalvik_format_t::f35c;
    format_table[0x25] = dalvik_format_t::f3rc;
    format_table[0x26] = dalvik_format_t::f31t;
    format_table[0x27] = dalvik_format_t::f11x;
    format_table[0x28] = dalvik_format_t::f10t;
    format_table[0x29] = dalvik_format_t::f20t;
    format_table[0x2a] = dalvik_format_t::f30t;
    format_table[0x2b] = dalvik_format_t::f31t;
    format_table[0x2c] = dalvik_format_t::f31t;
    format_table[0x2d] = dalvik_format_t::f23x;
    format_table[0x2e] = dalvik_format_t::f23x;
    format_table[0x2f] = dalvik_format_t::f23x;
    format_table[0x30] = dalvik_format_t::f23x;
    format_table[0x31] = dalvik_format_t::f23x;
    for (int i = 0x32; i <= 0x37; ++i) format_table[i] = dalvik_format_t::f22t;
    for (int i = 0x38; i <= 0x3d; ++i) format_table[i] = dalvik_format_t::f21t;
    for (int i = 0x44; i <= 0x51; ++i) format_table[i] = dalvik_format_t::f23x;
    for (int i = 0x52; i <= 0x5f; ++i) format_table[i] = dalvik_format_t::f22c;
    for (int i = 0x60; i <= 0x6d; ++i) format_table[i] = dalvik_format_t::f21c;
    for (int i = 0x6e; i <= 0x72; ++i) format_table[i] = dalvik_format_t::f35c;
    for (int i = 0x74; i <= 0x78; ++i) format_table[i] = dalvik_format_t::f3rc;
    for (int i = 0x7b; i <= 0x8f; ++i) format_table[i] = dalvik_format_t::f12x;
    for (int i = 0x90; i <= 0xaf; ++i) format_table[i] = dalvik_format_t::f23x;
    for (int i = 0xb0; i <= 0xcf; ++i) format_table[i] = dalvik_format_t::f12x;
    for (int i = 0xd0; i <= 0xd7; ++i) format_table[i] = dalvik_format_t::f22s;
    for (int i = 0xd8; i <= 0xe2; ++i) format_table[i] = dalvik_format_t::f22b;
    format_table[0xfa] = dalvik_format_t::f45cc;
    format_table[0xfb] = dalvik_format_t::f4rcc;
    format_table[0xfc] = dalvik_format_t::f35c;
    format_table[0xfd] = dalvik_format_t::f3rc;
    format_table[0xfe] = dalvik_format_t::f21c;
    format_table[0xff] = dalvik_format_t::f21c;
}

std::int32_t sign_extend_4(std::uint8_t value) noexcept
{
    return static_cast<std::int32_t>(static_cast<std::int8_t>(value << 4)) >> 4;
}

std::int32_t sign_extend_8(std::uint8_t value) noexcept
{
    return static_cast<std::int32_t>(static_cast<std::int8_t>(value));
}

std::int32_t sign_extend_16(std::uint16_t value) noexcept
{
    return static_cast<std::int32_t>(static_cast<std::int16_t>(value));
}

std::int64_t sign_extend_32(std::uint32_t value) noexcept
{
    return static_cast<std::int64_t>(static_cast<std::int32_t>(value));
}

instruction_info_t extract_instruction_info(std::uint8_t opcode,
                                             const std::vector<std::uint16_t>& code_units,
                                             std::uint32_t offset,
                                             std::uint16_t opcode_unit)
{
    instruction_info_t info;
    info.hir_kind = hir_kind_for_opcode(opcode);
    info.ir_opcode = ir_opcode_for_opcode(opcode);
    info.is_branch = is_branch_opcode(opcode);
    info.is_conditional = is_conditional_opcode(opcode);
    info.is_switch = is_switch_opcode(opcode);
    info.is_return = is_return_opcode(opcode);
    info.is_throw = is_throw_opcode(opcode);
    info.is_invoke = is_invoke_opcode(opcode);
    info.is_invoke_range = is_invoke_range_opcode(opcode);
    info.is_terminator = is_terminator_opcode(opcode);
    info.is_move_result = is_move_result_opcode(opcode);
    info.is_move_exception = (opcode == 0x0d);
    info.is_monitor = is_monitor_opcode(opcode);
    info.is_field_load = is_field_load_opcode(opcode);
    info.is_field_store = is_field_store_opcode(opcode);
    info.is_array_load = is_array_load_opcode(opcode);
    info.is_array_store = is_array_store_opcode(opcode);
    info.is_2addr = is_2addr_opcode(opcode);
    info.has_fallthrough = !info.is_terminator || info.is_conditional;
    info.fallthrough_offset = offset + 1;

    const bool wide = is_wide_opcode(opcode);
    const auto format = format_table[opcode];

    switch (format) {
    case dalvik_format_t::f10x:
        info.fallthrough_offset = offset + 1;
        break;
    case dalvik_format_t::f12x: {
        const std::uint8_t vA = (opcode_unit >> 8) & 0xF;
        const std::uint8_t vB = (opcode_unit >> 12) & 0xF;
        if (info.is_2addr) {
            info.dest_reg = vA;
            info.dest_wide = wide;
            info.has_dest = true;
            info.src_regs.push_back(vA);
            info.src_wide.push_back(wide);
            info.src_regs.push_back(vB);
            info.src_wide.push_back(is_shift_long_opcode(opcode) ? false : wide);
        } else {
            info.dest_reg = vA;
            info.dest_wide = wide;
            info.has_dest = true;
            info.src_regs.push_back(vB);
            info.src_wide.push_back(wide);
        }
        info.fallthrough_offset = offset + 1;
        break;
    }
    case dalvik_format_t::f11n: {
        const std::uint8_t vA = (opcode_unit >> 8) & 0xF;
        info.dest_reg = vA;
        info.dest_wide = false;
        info.has_dest = true;
        info.fallthrough_offset = offset + 1;
        break;
    }
    case dalvik_format_t::f11x: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (info.is_return || info.is_throw || info.is_monitor) {
            info.src_regs.push_back(vAA);
            info.src_wide.push_back(wide);
        } else {
            info.dest_reg = vAA;
            info.dest_wide = wide;
            info.has_dest = true;
            if (info.is_move_result) {
                info.has_result = true;
            }
            if (info.is_move_exception) {
                info.has_dest = true;
            }
        }
        info.fallthrough_offset = offset + 1;
        break;
    }
    case dalvik_format_t::f10t: {
        const std::int8_t offset8 = static_cast<std::int8_t>((opcode_unit >> 8) & 0xFF);
        info.branch_target_offset = static_cast<std::uint32_t>(static_cast<std::int32_t>(offset) + offset8);
        info.has_fallthrough = false;
        break;
    }
    case dalvik_format_t::f20t: {
        if (offset + 1 < code_units.size()) {
            const std::int16_t off16 = static_cast<std::int16_t>(code_units[offset + 1]);
            info.branch_target_offset = static_cast<std::uint32_t>(static_cast<std::int32_t>(offset) + off16);
        }
        info.has_fallthrough = false;
        break;
    }
    case dalvik_format_t::f22x: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (offset + 1 < code_units.size()) {
            const std::uint16_t vBBBB = code_units[offset + 1];
            info.dest_reg = vAA;
            info.dest_wide = wide;
            info.has_dest = true;
            info.src_regs.push_back(vBBBB);
            info.src_wide.push_back(wide);
        }
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f21t: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (offset + 1 < code_units.size()) {
            const std::int16_t off16 = static_cast<std::int16_t>(code_units[offset + 1]);
            info.branch_target_offset = static_cast<std::uint32_t>(static_cast<std::int32_t>(offset) + off16);
        }
        info.src_regs.push_back(vAA);
        info.src_wide.push_back(wide);
        info.has_fallthrough = true;
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f21s:
    case dalvik_format_t::f21h: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        info.dest_reg = vAA;
        info.dest_wide = wide;
        info.has_dest = true;
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f21c: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (info.is_field_store) {
            info.src_regs.push_back(vAA);
            info.src_wide.push_back(wide);
        } else {
            info.dest_reg = vAA;
            info.dest_wide = wide;
            info.has_dest = true;
        }
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f23x: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (offset + 1 < code_units.size()) {
            const std::uint16_t unit1 = code_units[offset + 1];
            const std::uint8_t vBB = unit1 & 0xFF;
            const std::uint8_t vCC = (unit1 >> 8) & 0xFF;
            if (info.is_array_store) {
                info.src_regs.push_back(vAA);
                info.src_wide.push_back(wide);
                info.src_regs.push_back(vBB);
                info.src_wide.push_back(false);
                info.src_regs.push_back(vCC);
                info.src_wide.push_back(false);
            } else {
                info.dest_reg = vAA;
                info.dest_wide = wide;
                info.has_dest = true;
                info.src_regs.push_back(vBB);
                info.src_wide.push_back(wide);
                info.src_regs.push_back(vCC);
                info.src_wide.push_back(is_wide_source2_opcode(opcode) ? wide : false);
                if (is_shift_long_opcode(opcode)) {
                    info.src_wide.back() = false;
                }
            }
        }
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f22b: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (offset + 1 < code_units.size()) {
            const std::uint16_t unit1 = code_units[offset + 1];
            const std::uint8_t vBB = unit1 & 0xFF;
            info.dest_reg = vAA;
            info.dest_wide = false;
            info.has_dest = true;
            info.src_regs.push_back(vBB);
            info.src_wide.push_back(false);
        }
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f22t: {
        const std::uint8_t vA = (opcode_unit >> 8) & 0xF;
        const std::uint8_t vB = (opcode_unit >> 12) & 0xF;
        if (offset + 1 < code_units.size()) {
            const std::int16_t off16 = static_cast<std::int16_t>(code_units[offset + 1]);
            info.branch_target_offset = static_cast<std::uint32_t>(static_cast<std::int32_t>(offset) + off16);
        }
        info.src_regs.push_back(vA);
        info.src_wide.push_back(false);
        info.src_regs.push_back(vB);
        info.src_wide.push_back(false);
        info.has_fallthrough = true;
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f22s:
    case dalvik_format_t::f22c: {
        const std::uint8_t vA = (opcode_unit >> 8) & 0xF;
        const std::uint8_t vB = (opcode_unit >> 12) & 0xF;
        if (info.is_field_store) {
            info.src_regs.push_back(vA);
            info.src_wide.push_back(wide);
            info.src_regs.push_back(vB);
            info.src_wide.push_back(false);
        } else if (info.is_field_load) {
            info.dest_reg = vA;
            info.dest_wide = wide;
            info.has_dest = true;
            info.src_regs.push_back(vB);
            info.src_wide.push_back(false);
        } else {
            info.dest_reg = vA;
            info.dest_wide = wide;
            info.has_dest = true;
            info.src_regs.push_back(vB);
            info.src_wide.push_back(false);
        }
        info.fallthrough_offset = offset + 2;
        break;
    }
    case dalvik_format_t::f30t: {
        if (offset + 2 < code_units.size()) {
            const std::uint32_t off32 = static_cast<std::uint32_t>(code_units[offset + 1]) |
                (static_cast<std::uint32_t>(code_units[offset + 2]) << 16);
            info.branch_target_offset = static_cast<std::uint32_t>(static_cast<std::int32_t>(offset) +
                static_cast<std::int32_t>(off32));
        }
        info.has_fallthrough = false;
        break;
    }
    case dalvik_format_t::f32x: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        if (offset + 1 < code_units.size()) {
            const std::uint16_t vBBBB = code_units[offset + 1];
            info.dest_reg = vAA;
            info.dest_wide = wide;
            info.has_dest = true;
            info.src_regs.push_back(vBBBB);
            info.src_wide.push_back(wide);
        }
        info.fallthrough_offset = offset + 3;
        break;
    }
    case dalvik_format_t::f31i: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        info.dest_reg = vAA;
        info.dest_wide = wide;
        info.has_dest = true;
        info.fallthrough_offset = offset + 3;
        break;
    }
    case dalvik_format_t::f31t: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        info.src_regs.push_back(vAA);
        info.src_wide.push_back(false);
        if (offset + 2 < code_units.size()) {
            const std::uint32_t off32 = static_cast<std::uint32_t>(code_units[offset + 1]) |
                (static_cast<std::uint32_t>(code_units[offset + 2]) << 16);
            info.branch_target_offset = static_cast<std::uint32_t>(static_cast<std::int32_t>(offset) +
                static_cast<std::int32_t>(off32));
        }
        info.has_fallthrough = true;
        info.fallthrough_offset = offset + 3;
        break;
    }
    case dalvik_format_t::f31c: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        info.dest_reg = vAA;
        info.dest_wide = false;
        info.has_dest = true;
        info.fallthrough_offset = offset + 3;
        break;
    }
    case dalvik_format_t::f35c: {
        const std::uint8_t count = (opcode_unit >> 12) & 0xF;
        const std::uint8_t vG = (opcode_unit >> 8) & 0xF;
        if (offset + 2 < code_units.size()) {
            const std::uint16_t unit2 = code_units[offset + 2];
            const std::uint8_t vC = unit2 & 0xF;
            const std::uint8_t vD = (unit2 >> 4) & 0xF;
            const std::uint8_t vE = (unit2 >> 8) & 0xF;
            const std::uint8_t vF = (unit2 >> 12) & 0xF;
            const std::array<std::uint8_t, 5> regs = {vC, vD, vE, vF, vG};
            for (std::uint8_t i = 0; i < count && i < 5; ++i) {
                info.src_regs.push_back(regs[i]);
                info.src_wide.push_back(false);
            }
        }
        info.has_result = info.is_invoke;
        info.fallthrough_offset = offset + 3;
        break;
    }
    case dalvik_format_t::f3rc: {
        const std::uint8_t count = (opcode_unit >> 8) & 0xFF;
        if (offset + 2 < code_units.size()) {
            const std::uint16_t first_reg = code_units[offset + 2];
            for (std::uint16_t i = 0; i < count; ++i) {
                info.range_regs.push_back(static_cast<std::uint32_t>(first_reg) + i);
                info.src_regs.push_back(static_cast<std::uint32_t>(first_reg) + i);
                info.src_wide.push_back(false);
            }
        }
        info.has_result = info.is_invoke;
        info.fallthrough_offset = offset + 3;
        break;
    }
    case dalvik_format_t::f45cc: {
        const std::uint8_t count = (opcode_unit >> 12) & 0xF;
        const std::uint8_t vG = (opcode_unit >> 8) & 0xF;
        if (offset + 3 < code_units.size()) {
            const std::uint16_t unit2 = code_units[offset + 2];
            const std::uint8_t vC = unit2 & 0xF;
            const std::uint8_t vD = (unit2 >> 4) & 0xF;
            const std::uint8_t vE = (unit2 >> 8) & 0xF;
            const std::uint8_t vF = (unit2 >> 12) & 0xF;
            const std::array<std::uint8_t, 5> regs = {vC, vD, vE, vF, vG};
            for (std::uint8_t i = 0; i < count && i < 5; ++i) {
                info.src_regs.push_back(regs[i]);
                info.src_wide.push_back(false);
            }
        }
        info.has_result = true;
        info.fallthrough_offset = offset + 4;
        break;
    }
    case dalvik_format_t::f4rcc: {
        const std::uint8_t count = (opcode_unit >> 8) & 0xFF;
        if (offset + 3 < code_units.size()) {
            const std::uint16_t first_reg = code_units[offset + 2];
            for (std::uint16_t i = 0; i < count; ++i) {
                info.range_regs.push_back(static_cast<std::uint32_t>(first_reg) + i);
                info.src_regs.push_back(static_cast<std::uint32_t>(first_reg) + i);
                info.src_wide.push_back(false);
            }
        }
        info.has_result = true;
        info.fallthrough_offset = offset + 4;
        break;
    }
    case dalvik_format_t::f51l: {
        const std::uint8_t vAA = (opcode_unit >> 8) & 0xFF;
        info.dest_reg = vAA;
        info.dest_wide = true;
        info.has_dest = true;
        info.fallthrough_offset = offset + 5;
        break;
    }
    default:
        info.fallthrough_offset = offset + 1;
        break;
    }

    return info;
}

decompiler_type_kind_t type_kind_from_descriptor(const std::string& descriptor)
{
    if (descriptor.empty()) return decompiler_type_kind_t::unknown;
    switch (descriptor[0]) {
    case 'V': return decompiler_type_kind_t::void_type;
    case 'Z': return decompiler_type_kind_t::boolean;
    case 'B': return decompiler_type_kind_t::signed_integer;
    case 'S': return decompiler_type_kind_t::signed_integer;
    case 'C': return decompiler_type_kind_t::unsigned_integer;
    case 'I': return decompiler_type_kind_t::signed_integer;
    case 'J': return decompiler_type_kind_t::signed_integer;
    case 'F': return decompiler_type_kind_t::floating_point;
    case 'D': return decompiler_type_kind_t::floating_point;
    case '[': return decompiler_type_kind_t::array;
    case 'L': return decompiler_type_kind_t::class_type;
    default: return decompiler_type_kind_t::unknown;
    }
}

std::optional<std::uint64_t> type_byte_size(const std::string& descriptor)
{
    if (descriptor.empty()) return std::nullopt;
    switch (descriptor[0]) {
    case 'V': return std::nullopt;
    case 'Z': return std::uint64_t{1};
    case 'B': return std::uint64_t{1};
    case 'S': return std::uint64_t{2};
    case 'C': return std::uint64_t{2};
    case 'I': return std::uint64_t{4};
    case 'J': return std::uint64_t{8};
    case 'F': return std::uint64_t{4};
    case 'D': return std::uint64_t{8};
    case '[': return std::uint64_t{4};
    case 'L': return std::nullopt;
    default: return std::nullopt;
    }
}

bool type_is_wide(const std::string& descriptor)
{
    if (descriptor.empty()) return false;
    return descriptor[0] == 'J' || descriptor[0] == 'D';
}

bool type_is_object(const std::string& descriptor)
{
    if (descriptor.empty()) return false;
    return descriptor[0] == 'L' || descriptor[0] == '[';
}

std::string type_display_name(const std::string& descriptor)
{
    if (descriptor.empty()) return "unknown";
    if (descriptor == "V") return "void";
    if (descriptor == "Z") return "boolean";
    if (descriptor == "B") return "byte";
    if (descriptor == "S") return "short";
    if (descriptor == "C") return "char";
    if (descriptor == "I") return "int";
    if (descriptor == "J") return "long";
    if (descriptor == "F") return "float";
    if (descriptor == "D") return "double";
    if (descriptor[0] == '[') {
        std::string element = descriptor.substr(1);
        return type_display_name(element) + "[]";
    }
    if (descriptor[0] == 'L' && descriptor.back() == ';') {
        std::string inner = descriptor.substr(1, descriptor.size() - 2);
        std::replace(inner.begin(), inner.end(), '/', '.');
        return inner;
    }
    return descriptor;
}

std::string array_element_descriptor(const std::string& descriptor)
{
    if (descriptor.empty() || descriptor[0] != '[') return {};
    return descriptor.substr(1);
}

std::vector<std::string> parse_prototype_params(const std::string& descriptor)
{
    std::vector<std::string> result;
    if (descriptor.empty() || descriptor[0] != '(') return result;
    std::size_t pos = 1;
    while (pos < descriptor.size() && descriptor[pos] != ')') {
        if (descriptor[pos] == 'L') {
            std::size_t end = descriptor.find(';', pos);
            if (end == std::string::npos) break;
            result.push_back(descriptor.substr(pos, end - pos + 1));
            pos = end + 1;
        } else if (descriptor[pos] == '[') {
            std::size_t start = pos;
            while (pos < descriptor.size() && descriptor[pos] == '[') ++pos;
            if (pos < descriptor.size() && descriptor[pos] == 'L') {
                std::size_t end = descriptor.find(';', pos);
                if (end == std::string::npos) break;
                result.push_back(descriptor.substr(start, end - start + 1));
                pos = end + 1;
            } else if (pos < descriptor.size()) {
                result.push_back(descriptor.substr(start, pos - start + 1));
                pos = pos + 1;
            }
        } else {
            result.push_back(std::string(1, descriptor[pos]));
            pos = pos + 1;
        }
    }
    return result;
}

std::string parse_prototype_return(const std::string& descriptor)
{
    if (descriptor.empty()) return "V";
    std::size_t close = descriptor.find(')');
    if (close == std::string::npos || close + 1 >= descriptor.size()) return "V";
    std::string ret = descriptor.substr(close + 1);
    if (ret.empty()) return "V";
    return ret;
}

struct type_registry_t {
    std::map<std::string, std::uint64_t> descriptor_to_id;
    std::vector<dalvik_ssa_type_ref_t> types;
    std::uint64_t next_id = 1;

    std::uint64_t ensure(const std::string& descriptor)
    {
        if (descriptor.empty()) return 0;
        const auto found = descriptor_to_id.find(descriptor);
        if (found != descriptor_to_id.end()) return found->second;
        const auto id = next_id++;
        dalvik_ssa_type_ref_t ref;
        ref.id = id;
        ref.descriptor = descriptor;
        ref.kind = type_kind_from_descriptor(descriptor);
        ref.display_name = type_display_name(descriptor);
        ref.byte_size = type_byte_size(descriptor);
        ref.is_wide = type_is_wide(descriptor);
        ref.is_object = type_is_object(descriptor);
        ref.is_array = (!descriptor.empty() && descriptor[0] == '[');
        if (ref.is_array) {
            ref.element_descriptor = array_element_descriptor(descriptor);
        }
        descriptor_to_id.emplace(descriptor, id);
        types.push_back(std::move(ref));
        return id;
    }

    void resolve_edges()
    {
        for (auto& type_ref : types) {
            if (type_ref.is_array && !type_ref.element_descriptor.empty()) {
                const auto element_id = ensure(type_ref.element_descriptor);
                if (element_id != 0) {
                    type_ref.edges.push_back({element_id, decompiler_type_edge_kind_t::element});
                }
            }
        }
    }
};

struct basic_block_t {
    std::uint64_t id = 0;
    std::uint32_t start_offset = 0;
    std::uint32_t end_offset = 0;
    std::vector<std::uint32_t> instruction_offsets;
    std::vector<std::uint64_t> predecessor_ids;
    std::vector<std::uint64_t> successor_ids;
    std::vector<std::uint64_t> exception_successor_ids;
    bool is_exception_handler = false;
    bool is_entry = false;
};

struct ssa_phi_t {
    std::uint32_t register_number = 0;
    std::uint64_t block_id = 0;
    std::uint64_t value_id = 0;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> incoming;
    std::uint32_t version = 0;
    bool is_wide = false;
};

std::vector<basic_block_t> build_basic_blocks(
    const std::vector<dalvik_instruction_t>& instructions,
    const std::vector<std::uint16_t>& code_units,
    const dex_code_item_t& code_item,
    std::uint32_t& diagnostic_ordinal,
    std::vector<decompiler_diagnostic_t>& diagnostics)
{
    std::set<std::uint32_t> leaders;
    if (!instructions.empty())
        leaders.insert(instructions.front().code_unit_offset);

    for (const auto& insn : instructions) {
        const auto info = extract_instruction_info(insn.opcode, code_units, insn.code_unit_offset, insn.opcode_unit);
        if (info.is_terminator) {
            if (info.has_fallthrough && info.fallthrough_offset > insn.code_unit_offset) {
                leaders.insert(info.fallthrough_offset);
            }
            if (info.is_branch || info.is_conditional) {
                if (info.branch_target_offset < code_item.instruction_count * 2U + 0x10U)
                    leaders.insert(info.branch_target_offset);
            }
        }
        if (info.is_switch && info.branch_target_offset < code_units.size()) {
            leaders.insert(info.branch_target_offset);
            const std::uint32_t payload_off = info.branch_target_offset;
            if (payload_off + 1 < code_units.size()) {
                const std::uint16_t ident = code_units[payload_off];
                if (ident == 0x0100) {
                    if (payload_off + 2 < code_units.size()) {
                        const std::uint16_t size = code_units[payload_off + 1];
                        for (std::uint16_t i = 0; i < size; ++i) {
                            const std::uint32_t target_idx = payload_off + 4 + i * 2;
                            if (target_idx + 1 < code_units.size()) {
                                const std::int32_t target = static_cast<std::int32_t>(insn.code_unit_offset) +
                                    static_cast<std::int32_t>(static_cast<std::uint32_t>(code_units[target_idx]) |
                                    (static_cast<std::uint32_t>(code_units[target_idx + 1]) << 16));
                                leaders.insert(static_cast<std::uint32_t>(target));
                            }
                        }
                    }
                } else if (ident == 0x0200) {
                    if (payload_off + 2 < code_units.size()) {
                        const std::uint16_t size = code_units[payload_off + 1];
                        for (std::uint16_t i = 0; i < size; ++i) {
                            const std::uint32_t target_idx = payload_off + 2 + size + i * 2;
                            if (target_idx + 1 < code_units.size()) {
                                const std::int32_t target = static_cast<std::int32_t>(insn.code_unit_offset) +
                                    static_cast<std::int32_t>(static_cast<std::uint32_t>(code_units[target_idx]) |
                                    (static_cast<std::uint32_t>(code_units[target_idx + 1]) << 16));
                                leaders.insert(static_cast<std::uint32_t>(target));
                            }
                        }
                    }
                }
            }
        }
    }

    for (const auto& try_item : code_item.tries) {
        leaders.insert(try_item.start_address);
    }

    std::set<std::uint32_t> handler_addresses;
    for (const auto& handler : code_item.catch_handlers) {
        for (const auto& typed : handler.typed_handlers) {
            handler_addresses.insert(typed.second);
            leaders.insert(typed.second);
        }
        if (handler.catch_all_address) {
            handler_addresses.insert(*handler.catch_all_address);
            leaders.insert(*handler.catch_all_address);
        }
    }

    for (const auto& insn : instructions) {
        const auto info = extract_instruction_info(insn.opcode, code_units, insn.code_unit_offset, insn.opcode_unit);
        if (info.is_terminator) {
            const auto next_off = insn.code_unit_offset + insn.width_code_units;
            if (info.has_fallthrough && leaders.find(next_off) == leaders.end()) {
                leaders.insert(next_off);
            }
        }
    }

    std::vector<basic_block_t> blocks;
    std::map<std::uint32_t, std::size_t> offset_to_block;

    auto it = instructions.begin();
    for (auto leader_it = leaders.begin(); leader_it != leaders.end(); ++leader_it) {
        auto next_leader_it = std::next(leader_it);
        const std::uint32_t start = *leader_it;
        basic_block_t block;
        block.start_offset = start;
        block.is_exception_handler = handler_addresses.count(start) > 0;
        block.is_entry = (start == instructions.front().code_unit_offset);

        while (it != instructions.end() && it->code_unit_offset < start)
            ++it;
        auto block_start = it;
        while (it != instructions.end() &&
               (next_leader_it == leaders.end() || it->code_unit_offset < *next_leader_it)) {
            block.instruction_offsets.push_back(it->code_unit_offset);
            block.end_offset = it->code_unit_offset + it->width_code_units;
            ++it;
        }
        if (block.instruction_offsets.empty()) {
            continue;
        }
        blocks.push_back(std::move(block));
        offset_to_block[start] = blocks.size() - 1;
    }

    for (auto& block : blocks) {
        if (block.instruction_offsets.empty()) continue;
        const auto& last_insn = *std::find_if(instructions.rbegin(), instructions.rend(),
            [&](const dalvik_instruction_t& i) { return i.code_unit_offset == block.instruction_offsets.back(); });
        if (last_insn.code_unit_offset != block.instruction_offsets.back()) continue;
        const auto info = extract_instruction_info(last_insn.opcode, code_units, last_insn.code_unit_offset, last_insn.opcode_unit);
        if (info.has_fallthrough) {
            const auto ft_off = info.fallthrough_offset;
            const auto ft_it = offset_to_block.find(ft_off);
            if (ft_it != offset_to_block.end()) {
                block.successor_ids.push_back(static_cast<std::uint64_t>(ft_it->second + 1));
            }
        }
        if (info.is_branch || info.is_conditional) {
            const auto br_it = offset_to_block.find(info.branch_target_offset);
            if (br_it != offset_to_block.end()) {
                block.successor_ids.push_back(static_cast<std::uint64_t>(br_it->second + 1));
            } else {
                diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::malformed_provider_ir,
                    "dalvik_ssa.unresolved_branch_target", diagnostic_ordinal++));
            }
        }
        if (info.is_switch && info.branch_target_offset < code_units.size()) {
            const std::uint32_t payload_off = info.branch_target_offset;
            if (payload_off + 1 < code_units.size()) {
                const std::uint16_t ident = code_units[payload_off];
                if (ident == 0x0100) {
                    if (payload_off + 2 < code_units.size()) {
                        const std::uint16_t size = code_units[payload_off + 1];
                        for (std::uint16_t i = 0; i < size; ++i) {
                            const std::uint32_t target_idx = payload_off + 4 + i * 2;
                            if (target_idx + 1 < code_units.size()) {
                                const std::int32_t target = static_cast<std::int32_t>(last_insn.code_unit_offset) +
                                    static_cast<std::int32_t>(static_cast<std::uint32_t>(code_units[target_idx]) |
                                    (static_cast<std::uint32_t>(code_units[target_idx + 1]) << 16));
                                const auto br_it = offset_to_block.find(static_cast<std::uint32_t>(target));
                                if (br_it != offset_to_block.end()) {
                                    const auto sid = static_cast<std::uint64_t>(br_it->second + 1);
                                    if (std::find(block.successor_ids.begin(), block.successor_ids.end(), sid) == block.successor_ids.end())
                                        block.successor_ids.push_back(sid);
                                }
                            }
                        }
                    }
                } else if (ident == 0x0200) {
                    if (payload_off + 2 < code_units.size()) {
                        const std::uint16_t size = code_units[payload_off + 1];
                        for (std::uint16_t i = 0; i < size; ++i) {
                            const std::uint32_t target_idx = payload_off + 2 + size + i * 2;
                            if (target_idx + 1 < code_units.size()) {
                                const std::int32_t target = static_cast<std::int32_t>(last_insn.code_unit_offset) +
                                    static_cast<std::int32_t>(static_cast<std::uint32_t>(code_units[target_idx]) |
                                    (static_cast<std::uint32_t>(code_units[target_idx + 1]) << 16));
                                const auto br_it = offset_to_block.find(static_cast<std::uint32_t>(target));
                                if (br_it != offset_to_block.end()) {
                                    const auto sid = static_cast<std::uint64_t>(br_it->second + 1);
                                    if (std::find(block.successor_ids.begin(), block.successor_ids.end(), sid) == block.successor_ids.end())
                                        block.successor_ids.push_back(sid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (std::size_t i = 0; i < blocks.size(); ++i) {
        blocks[i].id = static_cast<std::uint64_t>(i + 1);
    }

    for (auto& block : blocks) {
        for (const auto succ : block.successor_ids) {
            if (succ > 0 && succ <= blocks.size()) {
                auto& target = blocks[succ - 1];
                const auto my_id = block.id;
                if (std::find(target.predecessor_ids.begin(), target.predecessor_ids.end(), my_id) == target.predecessor_ids.end())
                    target.predecessor_ids.push_back(my_id);
            }
        }
    }

    for (const auto& try_item : code_item.tries) {
        const std::uint32_t try_start = try_item.start_address;
        const std::uint32_t try_end = try_start + try_item.instruction_count;
        for (auto& block : blocks) {
            if (block.start_offset >= try_start && block.start_offset < try_end) {
                if (try_item.handler_offset < code_item.catch_handlers.size()) {
                    const auto& handler = code_item.catch_handlers[try_item.handler_offset];
                    for (const auto& typed : handler.typed_handlers) {
                        const auto handler_it = offset_to_block.find(typed.second);
                        if (handler_it != offset_to_block.end()) {
                            const auto hid = static_cast<std::uint64_t>(handler_it->second + 1);
                            if (std::find(block.exception_successor_ids.begin(), block.exception_successor_ids.end(), hid) == block.exception_successor_ids.end())
                                block.exception_successor_ids.push_back(hid);
                            if (std::find(block.successor_ids.begin(), block.successor_ids.end(), hid) == block.successor_ids.end())
                                block.successor_ids.push_back(hid);
                            if (hid > 0 && hid <= blocks.size()) {
                                auto& handler_block = blocks[hid - 1];
                                if (std::find(handler_block.predecessor_ids.begin(), handler_block.predecessor_ids.end(), block.id) == handler_block.predecessor_ids.end())
                                    handler_block.predecessor_ids.push_back(block.id);
                            }
                        }
                    }
                    if (handler.catch_all_address) {
                        const auto handler_it = offset_to_block.find(*handler.catch_all_address);
                        if (handler_it != offset_to_block.end()) {
                            const auto hid = static_cast<std::uint64_t>(handler_it->second + 1);
                            if (std::find(block.exception_successor_ids.begin(), block.exception_successor_ids.end(), hid) == block.exception_successor_ids.end())
                                block.exception_successor_ids.push_back(hid);
                            if (std::find(block.successor_ids.begin(), block.successor_ids.end(), hid) == block.successor_ids.end())
                                block.successor_ids.push_back(hid);
                            if (hid > 0 && hid <= blocks.size()) {
                                auto& handler_block = blocks[hid - 1];
                                if (std::find(handler_block.predecessor_ids.begin(), handler_block.predecessor_ids.end(), block.id) == handler_block.predecessor_ids.end())
                                    handler_block.predecessor_ids.push_back(block.id);
                            }
                        }
                    }
                }
            }
        }
    }

    std::sort(blocks.begin(), blocks.end(), [](const basic_block_t& a, const basic_block_t& b) {
        return a.start_offset < b.start_offset;
    });

    std::map<std::uint32_t, std::uint64_t> offset_to_block_id;
    for (const auto& block : blocks) {
        offset_to_block_id[block.start_offset] = block.id;
        for (const auto& off : block.instruction_offsets)
            offset_to_block_id[off] = block.id;
    }

    for (auto& block : blocks) {
        for (auto& succ : block.successor_ids) {
            if (succ > 0 && succ <= blocks.size()) {
                succ = blocks[succ - 1].id;
            }
        }
        for (auto& pred : block.predecessor_ids) {
            if (pred > 0 && pred <= blocks.size()) {
                pred = blocks[pred - 1].id;
            }
        }
        for (auto& exc : block.exception_successor_ids) {
            if (exc > 0 && exc <= blocks.size()) {
                exc = blocks[exc - 1].id;
            }
        }
        std::sort(block.successor_ids.begin(), block.successor_ids.end());
        auto last = std::unique(block.successor_ids.begin(), block.successor_ids.end());
        block.successor_ids.erase(last, block.successor_ids.end());
        std::sort(block.predecessor_ids.begin(), block.predecessor_ids.end());
        last = std::unique(block.predecessor_ids.begin(), block.predecessor_ids.end());
        block.predecessor_ids.erase(last, block.predecessor_ids.end());
        std::sort(block.exception_successor_ids.begin(), block.exception_successor_ids.end());
        last = std::unique(block.exception_successor_ids.begin(), block.exception_successor_ids.end());
        block.exception_successor_ids.erase(last, block.exception_successor_ids.end());
    }

    return blocks;
}

std::vector<std::uint64_t> compute_reverse_postorder(const std::vector<basic_block_t>& blocks, std::uint64_t entry_id)
{
    std::vector<std::uint64_t> order;
    std::set<std::uint64_t> visited;
    std::function<void(std::uint64_t)> dfs = [&](std::uint64_t block_id) {
        if (visited.count(block_id)) return;
        visited.insert(block_id);
        const auto* block = &blocks[block_id - 1];
        for (const auto succ : block->successor_ids) {
            if (succ > 0 && succ <= blocks.size())
                dfs(succ);
        }
        for (const auto exc : block->exception_successor_ids) {
            if (exc > 0 && exc <= blocks.size())
                dfs(exc);
        }
        order.push_back(block_id);
    };
    dfs(entry_id);
    std::reverse(order.begin(), order.end());
    return order;
}

std::map<std::uint64_t, std::uint64_t> compute_dominators(
    const std::vector<basic_block_t>& blocks,
    const std::vector<std::uint64_t>& rpo,
    std::uint64_t entry_id)
{
    std::map<std::uint64_t, std::uint64_t> dom;
    dom[entry_id] = entry_id;
    bool changed = true;
    int iterations = 0;
    const int max_iterations = static_cast<int>(blocks.size()) * 4 + 10;

    std::map<std::uint64_t, std::size_t> rpo_index;
    for (std::size_t i = 0; i < rpo.size(); ++i)
        rpo_index[rpo[i]] = i;

    while (changed && iterations < max_iterations) {
        changed = false;
        ++iterations;
        for (const auto block_id : rpo) {
            if (block_id == entry_id) continue;
            const auto* block = &blocks[block_id - 1];
            std::uint64_t new_idom = 0;
            for (const auto pred : block->predecessor_ids) {
                if (pred == 0 || pred > blocks.size()) continue;
                if (dom.find(pred) == dom.end()) continue;
                if (new_idom == 0) {
                    new_idom = pred;
                } else {
                    auto b1 = pred;
                    auto b2 = new_idom;
                    while (b1 != b2) {
                        while (rpo_index[b1] > rpo_index[b2]) {
                            auto it = dom.find(b1);
                            if (it == dom.end()) break;
                            b1 = it->second;
                        }
                        while (rpo_index[b2] > rpo_index[b1]) {
                            auto it = dom.find(b2);
                            if (it == dom.end()) break;
                            b2 = it->second;
                        }
                    }
                    new_idom = b1;
                }
            }
            if (new_idom != 0) {
                auto it = dom.find(block_id);
                if (it == dom.end() || it->second != new_idom) {
                    dom[block_id] = new_idom;
                    changed = true;
                }
            }
        }
    }
    return dom;
}

std::map<std::uint64_t, std::set<std::uint64_t>> compute_dominance_frontiers(
    const std::vector<basic_block_t>& blocks,
    const std::map<std::uint64_t, std::uint64_t>& dom)
{
    std::map<std::uint64_t, std::set<std::uint64_t>> df;
    for (const auto& block : blocks) {
        if (block.predecessor_ids.size() < 2) continue;
        for (const auto pred : block.predecessor_ids) {
            auto runner = pred;
            while (runner != 0 && dom.count(runner) && dom.at(runner) != block.id) {
                df[runner].insert(block.id);
                auto it = dom.find(runner);
                if (it == dom.end()) break;
                runner = it->second;
                if (runner == block.id) break;
            }
        }
    }
    return df;
}

struct ssa_context_t {
    std::map<std::uint32_t, std::vector<std::uint32_t>> register_versions;
    std::map<std::uint32_t, std::uint32_t> current_version;
    std::map<std::uint64_t, std::vector<ssa_phi_t>> block_phis;
    std::map<std::pair<std::uint64_t, std::uint32_t>, std::uint64_t> ssa_value_lookup;
    std::uint64_t next_value_id = 1;

    std::uint32_t new_version(std::uint32_t reg)
    {
        const auto v = ++current_version[reg];
        return v;
    }

    std::uint32_t get_version(std::uint32_t reg) const
    {
        const auto it = current_version.find(reg);
        return it != current_version.end() ? it->second : 0;
    }

    void push_version(std::uint32_t reg, std::uint32_t version)
    {
        register_versions[reg].push_back(version);
        current_version[reg] = version;
    }

    void pop_version(std::uint32_t reg)
    {
        auto& stack = register_versions[reg];
        if (!stack.empty()) stack.pop_back();
        current_version[reg] = stack.empty() ? 0 : stack.back();
    }
};

void place_phi_nodes(
    const std::vector<basic_block_t>& blocks,
    const std::map<std::uint64_t, std::set<std::uint64_t>>& df,
    const std::map<std::uint32_t, std::set<std::uint64_t>>& reg_defs,
    ssa_context_t& ctx,
    std::uint16_t registers_size)
{
    for (std::uint32_t reg = 0; reg < registers_size; ++reg) {
        const auto def_it = reg_defs.find(reg);
        if (def_it == reg_defs.end()) continue;
        std::set<std::uint64_t> worklist(def_it->second.begin(), def_it->second.end());
        std::set<std::uint64_t> has_phi;
        while (!worklist.empty()) {
            const auto block_id = *worklist.begin();
            worklist.erase(worklist.begin());
            const auto df_it = df.find(block_id);
            if (df_it == df.end()) continue;
            for (const auto frontier : df_it->second) {
                if (has_phi.count(frontier)) continue;
                has_phi.insert(frontier);
                ssa_phi_t phi;
                phi.register_number = reg;
                phi.block_id = frontier;
                phi.value_id = ctx.next_value_id++;
                const auto* block = &blocks[frontier - 1];
                for (const auto pred : block->predecessor_ids) {
                    phi.incoming.push_back({pred, 0});
                }
                ctx.block_phis[frontier].push_back(std::move(phi));
                if (def_it->second.count(frontier) == 0)
                    worklist.insert(frontier);
            }
        }
    }
}

void rename_registers(
    const std::vector<basic_block_t>& blocks,
    const std::map<std::uint64_t, std::uint64_t>& dom,
    const std::map<std::uint64_t, std::set<std::uint64_t>>& dom_children_map,
    std::uint64_t entry_id,
    ssa_context_t& ctx,
    const std::vector<dalvik_instruction_t>& instructions,
    const std::vector<std::uint16_t>& code_units,
    const std::map<std::uint32_t, std::size_t>& offset_to_instruction,
    std::uint16_t registers_size,
    std::uint16_t ins_size,
    const std::vector<std::string>& param_descriptors,
    type_registry_t& type_reg,
    std::map<std::pair<std::uint64_t, std::uint32_t>, dalvik_ssa_value_t>& block_values,
    std::map<std::pair<std::uint64_t, std::uint32_t>, ssa_phi_t>& block_phi_map,
    std::vector<dalvik_ssa_variable_t>& variables,
    std::uint32_t& diagnostic_ordinal,
    std::vector<decompiler_diagnostic_t>& diagnostics)
{
    std::map<std::uint32_t, std::uint64_t> param_type_ids;
    std::uint32_t param_reg = registers_size;
    for (std::size_t i = 0; i < param_descriptors.size(); ++i) {
        const auto& desc = param_descriptors[i];
        const bool wide = type_is_wide(desc);
        param_reg -= wide ? 2 : 1;
        param_type_ids[param_reg] = type_reg.ensure(desc);
        dalvik_ssa_variable_t var;
        var.register_number = param_reg;
        var.stable_name = "p" + std::to_string(i);
        var.type_id = param_type_ids[param_reg];
        var.is_parameter = true;
        var.is_wide = wide;
        variables.push_back(std::move(var));
        ctx.current_version[param_reg] = 1;
        ctx.register_versions[param_reg].push_back(1);
    }

    for (std::uint32_t reg = 0; reg < registers_size - ins_size; ++reg) {
        if (ctx.current_version.find(reg) == ctx.current_version.end()) {
            dalvik_ssa_variable_t var;
            var.register_number = reg;
            var.stable_name = "v" + std::to_string(reg);
            var.type_id = type_reg.ensure("I");
            var.is_parameter = false;
            var.is_wide = false;
            variables.push_back(std::move(var));
            ctx.current_version[reg] = 0;
        }
    }

    std::function<void(std::uint64_t)> rename_block = [&](std::uint64_t block_id) {
        const auto* block = &blocks[block_id - 1];
        std::vector<std::uint32_t> defined_regs;

        auto phi_it = ctx.block_phis.find(block_id);
        if (phi_it != ctx.block_phis.end()) {
            for (auto& phi : phi_it->second) {
                const auto v = ctx.new_version(phi.register_number);
                phi.version = v;
                dalvik_ssa_value_t value;
                value.id = phi.value_id;
                value.kind = dalvik_ssa_value_kind_t::phi;
                value.dalvik_opcode = 0;
                value.type_id = type_reg.ensure("I");
                value.register_number = phi.register_number;
                value.ssa_version = v;
                value.code_unit_offset = block->start_offset;
                value.stable_symbol = "phi_v" + std::to_string(phi.register_number) + "_" + std::to_string(v);
                value.is_wide = phi.is_wide;
                block_values[{block_id, phi.value_id}] = std::move(value);
                block_phi_map[{block_id, phi.register_number}] = phi;
                ctx.push_version(phi.register_number, v);
                defined_regs.push_back(phi.register_number);
            }
        }

        for (const auto offset : block->instruction_offsets) {
            const auto insn_it = offset_to_instruction.find(offset);
            if (insn_it == offset_to_instruction.end()) continue;
            const auto& insn = instructions[insn_it->second];
            const auto info = extract_instruction_info(insn.opcode, code_units, offset, insn.opcode_unit);

            for (std::size_t i = 0; i < info.src_regs.size(); ++i) {
                const auto reg = info.src_regs[i];
                const auto version = ctx.get_version(reg);
                if (version == 0) continue;
            }

            if (info.has_dest && info.dest_reg != k_no_register) {
                const auto v = ctx.new_version(info.dest_reg);
                ctx.push_version(info.dest_reg, v);
                defined_regs.push_back(info.dest_reg);
                if (info.dest_wide) {
                    ctx.current_version[info.dest_reg + 1] = v;
                    defined_regs.push_back(info.dest_reg + 1);
                }

                dalvik_ssa_value_t value;
                value.id = ctx.next_value_id++;
                value.kind = dalvik_ssa_value_kind_t::register_def;
                value.dalvik_opcode = insn.opcode;
                value.register_number = info.dest_reg;
                value.ssa_version = v;
                value.code_unit_offset = offset;
                value.is_wide = info.dest_wide;
                if (insn.reference_kind != dalvik_reference_kind_t::none) {
                    value.reference_kind = insn.reference_kind;
                    value.reference_index = insn.reference_index;
                    value.secondary_reference_index = insn.secondary_reference_index;
                }
                if (insn.literal) {
                    value.stable_immediate = std::to_string(*insn.literal);
                }
                value.stable_symbol = insn.mnemonic;
                value.type_id = type_reg.ensure("I");
                block_values[{block_id, value.id}] = std::move(value);
            } else if (info.is_invoke || info.has_result) {
                dalvik_ssa_value_t value;
                value.id = ctx.next_value_id++;
                value.kind = info.is_invoke ? dalvik_ssa_value_kind_t::method_reference : dalvik_ssa_value_kind_t::call_result;
                value.dalvik_opcode = insn.opcode;
                value.code_unit_offset = offset;
                if (insn.reference_kind != dalvik_reference_kind_t::none) {
                    value.reference_kind = insn.reference_kind;
                    value.reference_index = insn.reference_index;
                    value.secondary_reference_index = insn.secondary_reference_index;
                }
                value.stable_symbol = insn.mnemonic;
                value.type_id = type_reg.ensure("I");
                block_values[{block_id, value.id}] = std::move(value);
            } else if (info.is_return || info.is_throw || info.is_branch || info.is_conditional ||
                       info.is_switch || info.is_monitor || info.is_field_store || info.is_array_store) {
                dalvik_ssa_value_t value;
                value.id = ctx.next_value_id++;
                value.kind = dalvik_ssa_value_kind_t::register_def;
                value.dalvik_opcode = insn.opcode;
                value.code_unit_offset = offset;
                value.stable_symbol = insn.mnemonic;
                value.type_id = type_reg.ensure("I");
                if (insn.reference_kind != dalvik_reference_kind_t::none) {
                    value.reference_kind = insn.reference_kind;
                    value.reference_index = insn.reference_index;
                }
                if (insn.literal) {
                    value.stable_immediate = std::to_string(*insn.literal);
                }
                block_values[{block_id, value.id}] = std::move(value);
            } else {
                dalvik_ssa_value_t value;
                value.id = ctx.next_value_id++;
                value.kind = dalvik_ssa_value_kind_t::register_def;
                value.dalvik_opcode = insn.opcode;
                value.code_unit_offset = offset;
                value.stable_symbol = insn.mnemonic;
                value.type_id = type_reg.ensure("I");
                if (insn.reference_kind != dalvik_reference_kind_t::none) {
                    value.reference_kind = insn.reference_kind;
                    value.reference_index = insn.reference_index;
                }
                if (insn.literal) {
                    value.stable_immediate = std::to_string(*insn.literal);
                }
                block_values[{block_id, value.id}] = std::move(value);
            }
        }

        auto phi_block_it = ctx.block_phis.find(block_id);
        for (const auto succ : block->successor_ids) {
            auto succ_phi_it = ctx.block_phis.find(succ);
            if (succ_phi_it != ctx.block_phis.end()) {
                for (auto& phi : succ_phi_it->second) {
                    const auto version = ctx.get_version(phi.register_number);
                    for (auto& incoming : phi.incoming) {
                        if (incoming.first == block_id) {
                            incoming.second = version;
                        }
                    }
                }
            }
        }
        for (const auto exc : block->exception_successor_ids) {
            auto exc_phi_it = ctx.block_phis.find(exc);
            if (exc_phi_it != ctx.block_phis.end()) {
                for (auto& phi : exc_phi_it->second) {
                    const auto version = ctx.get_version(phi.register_number);
                    for (auto& incoming : phi.incoming) {
                        if (incoming.first == block_id) {
                            incoming.second = version;
                        }
                    }
                }
            }
        }

        auto children_it = dom_children_map.find(block_id);
        if (children_it != dom_children_map.end()) {
            for (const auto child : children_it->second) {
                rename_block(child);
            }
        }

        for (const auto reg : defined_regs) {
            ctx.pop_version(reg);
        }
    };

    rename_block(entry_id);
}

std::map<std::uint64_t, std::set<std::uint64_t>> build_dom_children(
    const std::map<std::uint64_t, std::uint64_t>& dom,
    std::uint64_t entry_id)
{
    std::map<std::uint64_t, std::set<std::uint64_t>> children;
    for (const auto& [block_id, idom] : dom) {
        if (block_id == entry_id) continue;
        children[idom].insert(block_id);
    }
    return children;
}

}

dalvik_format_t instruction_format(std::uint8_t opcode) noexcept
{
    std::call_once(format_table_once, init_format_table);
    if (opcode >= 256) return dalvik_format_t::funknown;
    return format_table[opcode];
}

const char* format_name(dalvik_format_t format) noexcept
{
    switch (format) {
    case dalvik_format_t::f10x: return "10x";
    case dalvik_format_t::f12x: return "12x";
    case dalvik_format_t::f11n: return "11n";
    case dalvik_format_t::f11x: return "11x";
    case dalvik_format_t::f10t: return "10t";
    case dalvik_format_t::f20t: return "20t";
    case dalvik_format_t::f22x: return "22x";
    case dalvik_format_t::f21t: return "21t";
    case dalvik_format_t::f21s: return "21s";
    case dalvik_format_t::f21h: return "21h";
    case dalvik_format_t::f21c: return "21c";
    case dalvik_format_t::f23x: return "23x";
    case dalvik_format_t::f22b: return "22b";
    case dalvik_format_t::f22t: return "22t";
    case dalvik_format_t::f22s: return "22s";
    case dalvik_format_t::f22c: return "22c";
    case dalvik_format_t::f30t: return "30t";
    case dalvik_format_t::f32x: return "32x";
    case dalvik_format_t::f31i: return "31i";
    case dalvik_format_t::f31t: return "31t";
    case dalvik_format_t::f31c: return "31c";
    case dalvik_format_t::f35c: return "35c";
    case dalvik_format_t::f3rc: return "3rc";
    case dalvik_format_t::f45cc: return "45cc";
    case dalvik_format_t::f4rcc: return "4rcc";
    case dalvik_format_t::f51l: return "51l";
    case dalvik_format_t::fpayload: return "payload";
    default: return "unknown";
    }
}

dalvik_ssa_result_t normalize(const dalvik_ssa_capture_t& capture)
{
    std::call_once(format_table_once, init_format_table);

    dalvik_ssa_result_t result;
    std::uint32_t diagnostic_ordinal = 1;
    const auto fail = [&result, &diagnostic_ordinal](const decompiler_diagnostic_code_t code, const char* key) {
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error, code, key, diagnostic_ordinal++));
    };

    if (!capture.code_item) {
        fail(decompiler_diagnostic_code_t::invalid_contract, "dalvik_ssa.missing_code_item");
        return result;
    }
    if (capture.request.workspace_generation == 0 || capture.request.type_graph_revision == 0 ||
        !std::holds_alternative<dalvik_decompiler_entity_identity_t>(capture.request.entity.identity) ||
        !validate_decompiler_entity_key(capture.request.entity).valid() ||
        capture.request.entity.kind != decompiler_entity_kind_t::dalvik_method) {
        fail(decompiler_diagnostic_code_t::invalid_contract, "dalvik_ssa.entity");
        return result;
    }

    const auto& code_item = *capture.code_item;
    if (code_item.registers_size == 0) {
        fail(decompiler_diagnostic_code_t::malformed_input, "dalvik_ssa.registers_size");
        return result;
    }
    if (code_item.ins_size > code_item.registers_size) {
        fail(decompiler_diagnostic_code_t::malformed_input, "dalvik_ssa.ins_size");
        return result;
    }
    if (code_item.outs_size > code_item.registers_size) {
        fail(decompiler_diagnostic_code_t::malformed_input, "dalvik_ssa.outs_size");
        return result;
    }
    if (code_item.instructions.empty()) {
        fail(decompiler_diagnostic_code_t::malformed_input, "dalvik_ssa.empty_instructions");
        return result;
    }
    if (code_item.instructions.size() > k_max_values) {
        fail(decompiler_diagnostic_code_t::resource_limit, "dalvik_ssa.too_many_instructions");
        return result;
    }

    type_registry_t type_reg;
    const auto void_id = type_reg.ensure("V");
    const auto int_id = type_reg.ensure("I");
    const auto long_id = type_reg.ensure("J");
    const auto float_id = type_reg.ensure("F");
    const auto double_id = type_reg.ensure("D");
    const auto boolean_id = type_reg.ensure("Z");
    const auto object_id = type_reg.ensure("Ljava/lang/Object;");

    std::vector<std::string> param_descriptors;
    if (!capture.prototype.empty()) {
        param_descriptors = parse_prototype_params(capture.prototype);
    } else if (!capture.shorty.empty() && capture.shorty.size() > 1) {
        for (std::size_t i = 1; i < capture.shorty.size(); ++i) {
            if (capture.shorty[i] == 'L') {
                param_descriptors.push_back("Ljava/lang/Object;");
            } else {
                param_descriptors.push_back(std::string(1, capture.shorty[i]));
            }
        }
    }

    std::uint32_t expected_ins = 0;
    for (const auto& desc : param_descriptors) {
        expected_ins += type_is_wide(desc) ? 2 : 1;
    }
    if (expected_ins != code_item.ins_size && !param_descriptors.empty()) {
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::malformed_input, "dalvik_ssa.ins_size_mismatch", diagnostic_ordinal++));
    }

    const std::string return_desc = capture.prototype.empty()
        ? (capture.shorty.empty() ? "V" : std::string(1, capture.shorty[0]))
        : parse_prototype_return(capture.prototype);
    const auto return_type_id = type_reg.ensure(return_desc);

    for (const auto& insn : code_item.instructions) {
        if (insn.reference_kind == dalvik_reference_kind_t::string && insn.reference_index) {
            if (*insn.reference_index < capture.strings.size()) {
                type_reg.ensure("Ljava/lang/String;");
            } else {
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unresolved_symbol,
                    "dalvik_ssa.malformed_string_index", diagnostic_ordinal++));
            }
        }
        if (insn.reference_kind == dalvik_reference_kind_t::type && insn.reference_index) {
            if (*insn.reference_index < capture.types.size()) {
                type_reg.ensure(capture.types[*insn.reference_index].descriptor);
            } else {
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unresolved_type,
                    "dalvik_ssa.malformed_type_index", diagnostic_ordinal++));
            }
        }
        if (insn.reference_kind == dalvik_reference_kind_t::field && insn.reference_index) {
            if (*insn.reference_index < capture.fields.size()) {
                type_reg.ensure(capture.fields[*insn.reference_index].type_descriptor);
            } else {
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unresolved_symbol,
                    "dalvik_ssa.malformed_field_index", diagnostic_ordinal++));
            }
        }
        if (insn.reference_kind == dalvik_reference_kind_t::method && insn.reference_index) {
            if (*insn.reference_index < capture.methods.size()) {
                const auto& method = capture.methods[*insn.reference_index];
                type_reg.ensure(method.class_descriptor);
                type_reg.ensure(parse_prototype_return(method.descriptor));
                for (const auto& p : parse_prototype_params(method.descriptor))
                    type_reg.ensure(p);
            } else {
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unresolved_symbol,
                    "dalvik_ssa.malformed_method_index", diagnostic_ordinal++));
            }
        }
        if (insn.reference_kind == dalvik_reference_kind_t::proto && insn.reference_index) {
            if (*insn.reference_index < capture.protos.size()) {
                type_reg.ensure(capture.protos[*insn.reference_index].descriptor);
            } else {
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unresolved_type,
                    "dalvik_ssa.malformed_proto_index", diagnostic_ordinal++));
            }
        }
    }

    type_reg.resolve_edges();

    auto blocks = build_basic_blocks(code_item.instructions, capture.code_units,
        code_item, diagnostic_ordinal, result.diagnostics);
    if (blocks.empty()) {
        fail(decompiler_diagnostic_code_t::malformed_provider_ir, "dalvik_ssa.no_blocks");
        return result;
    }

    const auto entry_id = blocks.front().id;
    const auto rpo = compute_reverse_postorder(blocks, entry_id);
    const auto dom = compute_dominators(blocks, rpo, entry_id);
    const auto df = compute_dominance_frontiers(blocks, dom);
    const auto dom_children = build_dom_children(dom, entry_id);

    std::map<std::uint32_t, std::size_t> offset_to_instruction;
    for (std::size_t i = 0; i < code_item.instructions.size(); ++i)
        offset_to_instruction[code_item.instructions[i].code_unit_offset] = i;

    std::map<std::uint32_t, std::set<std::uint64_t>> reg_defs;
    for (const auto& block : blocks) {
        for (const auto offset : block.instruction_offsets) {
            const auto insn_it = offset_to_instruction.find(offset);
            if (insn_it == offset_to_instruction.end()) continue;
            const auto& insn = code_item.instructions[insn_it->second];
            const auto info = extract_instruction_info(insn.opcode, capture.code_units, offset, insn.opcode_unit);
            if (info.has_dest && info.dest_reg != k_no_register && info.dest_reg < code_item.registers_size) {
                reg_defs[info.dest_reg].insert(block.id);
            }
        }
    }

    ssa_context_t ctx;
    place_phi_nodes(blocks, df, reg_defs, ctx, code_item.registers_size);

    std::map<std::pair<std::uint64_t, std::uint32_t>, dalvik_ssa_value_t> block_values;
    std::map<std::pair<std::uint64_t, std::uint32_t>, ssa_phi_t> block_phi_map;
    std::vector<dalvik_ssa_variable_t> variables;

    rename_registers(blocks, dom, dom_children, entry_id, ctx,
        code_item.instructions, capture.code_units, offset_to_instruction,
        code_item.registers_size, code_item.ins_size, param_descriptors,
        type_reg, block_values, block_phi_map, variables,
        diagnostic_ordinal, result.diagnostics);

    std::uint64_t next_value_id = 1;
    std::map<std::uint64_t, std::uint64_t> old_to_new_value_id;
    for (auto& [key, value] : block_values) {
        old_to_new_value_id[value.id] = next_value_id;
        value.id = next_value_id++;
    }

    for (auto& [key, phi] : block_phi_map) {
        if (old_to_new_value_id.find(phi.value_id) != old_to_new_value_id.end()) {
            phi.value_id = old_to_new_value_id[phi.value_id];
        }
    }

    type_graph_t type_graph;
    type_graph.schema_version = k_type_graph_schema_version;
    type_graph.entity = capture.request.entity;
    type_graph.revision = capture.request.type_graph_revision;
    std::uint32_t edge_ordinal = 1;
    for (const auto& type_ref : type_reg.types) {
        decompiler_type_node_t node;
        node.id = type_ref.id;
        node.kind = type_ref.kind;
        node.canonical_name = type_ref.descriptor;
        node.display_name = type_ref.display_name;
        node.byte_size = type_ref.byte_size;
        node.alignment = 1;
        node.is_signed = (type_ref.kind == decompiler_type_kind_t::signed_integer);
        node.confidence = type_ref.kind == decompiler_type_kind_t::unknown ? 50 : 100;
        node.provenance = decompiler_fact_provenance_t::bytecode_verifier;
        node.coordinates.push_back(make_coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir, 0));
        type_graph.nodes.push_back(std::move(node));
    }
    for (const auto& type_ref : type_reg.types) {
        for (const auto& [target_id, edge_kind] : type_ref.edges) {
            decompiler_type_edge_t edge;
            edge.source_type_id = type_ref.id;
            edge.target_type_id = target_id;
            edge.kind = edge_kind;
            edge.stable_name = edge_kind == decompiler_type_edge_kind_t::element ? "element" : "edge";
            edge.ordinal = edge_ordinal++;
            edge.confidence = 100;
            edge.provenance = decompiler_fact_provenance_t::bytecode_verifier;
            type_graph.edges.push_back(std::move(edge));
        }
    }

    provider_ir_t provider_ir;
    provider_ir.provider = capture.request.provider;
    provider_ir.language = capture.request.language;
    provider_ir.entity = capture.request.entity;
    provider_ir.entry_block_id = entry_id;

    hir_function_t hir;
    hir.entity = capture.request.entity;
    hir.type_graph_revision = type_graph.revision;
    hir.return_type_id = return_type_id;

    std::uint64_t param_var_id = 1;
    for (const auto& var : variables) {
        if (!var.is_parameter) continue;
        hir_variable_t hvar;
        hvar.id = param_var_id++;
        hvar.stable_name = var.stable_name;
        hvar.type_id = var.type_id;
        hvar.coordinate = make_coordinate(capture.request, decompiler_coordinate_layer_t::hir,
            var.register_number, 1);
        hvar.confidence = 100;
        hvar.provenance = decompiler_fact_provenance_t::bytecode_verifier;
        hir.parameters.push_back(std::move(hvar));
    }

    std::uint64_t local_var_id = 1;
    for (const auto& var : variables) {
        if (var.is_parameter) continue;
        hir_variable_t hvar;
        hvar.id = param_var_id + local_var_id - 1;
        local_var_id++;
        hvar.stable_name = var.stable_name;
        hvar.type_id = var.type_id;
        hvar.coordinate = make_coordinate(capture.request, decompiler_coordinate_layer_t::hir,
            var.register_number, 1);
        hvar.confidence = 80;
        hvar.provenance = decompiler_fact_provenance_t::provider_semantics;
        hir.locals.push_back(std::move(hvar));
    }

    std::uint32_t provider_diag_ordinal = 1;
    std::uint32_t hir_diag_ordinal = 1;
    std::uint64_t global_value_id = 1;

    for (const auto& block : blocks) {
        provider_ir_block_t pblock;
        pblock.id = block.id;
        pblock.predecessor_ids = block.predecessor_ids;
        pblock.successor_ids = block.successor_ids;
        pblock.exception_successor_ids = block.exception_successor_ids;
        pblock.coordinate = make_coordinate_with_debug(capture.request,
            decompiler_coordinate_layer_t::provider_ir, block.start_offset,
            block.end_offset - block.start_offset, code_item);

        hir_block_t hblock;
        hblock.id = block.id;
        hblock.predecessor_ids = block.predecessor_ids;
        hblock.successor_ids = block.successor_ids;
        hblock.exception_successor_ids = block.exception_successor_ids;
        hblock.coordinate = make_coordinate_with_debug(capture.request,
            decompiler_coordinate_layer_t::hir, block.start_offset,
            block.end_offset - block.start_offset, code_item);

        auto phi_it = ctx.block_phis.find(block.id);
        if (phi_it != ctx.block_phis.end()) {
            for (const auto& phi : phi_it->second) {
                const auto phi_value_it = block_values.find({block.id, phi.value_id});
                if (phi_value_it == block_values.end()) continue;
                const auto& ssa_val = phi_value_it->second;

                provider_ir_value_t pval;
                pval.id = global_value_id;
                pval.opcode = provider_ir_opcode_t::phi;
                pval.type_id = ssa_val.type_id != 0 ? ssa_val.type_id : int_id;
                for (const auto& [pred_id, version] : phi.incoming) {
                    for (const auto& [vk, vv] : block_values) {
                        if (vk.first == pred_id && vv.register_number == phi.register_number &&
                            vv.ssa_version == version) {
                            pval.operand_ids.push_back(old_to_new_value_id.count(vv.id) ? old_to_new_value_id[vv.id] : vv.id);
                            break;
                        }
                    }
                }
                pval.stable_symbol = "phi_v" + std::to_string(phi.register_number);
                pval.coordinate = make_coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir, block.start_offset);
                pval.confidence = 100;
                pval.provenance = decompiler_fact_provenance_t::provider_semantics;
                pblock.values.push_back(pval);

                hir_value_t hval;
                hval.id = global_value_id;
                hval.kind = hir_node_kind_t::phi;
                hval.type_id = pval.type_id;
                hval.operand_ids = pval.operand_ids;
                hval.stable_value = "phi_v" + std::to_string(phi.register_number) + "_" + std::to_string(phi.version);
                hval.coordinate = make_coordinate(capture.request, decompiler_coordinate_layer_t::hir, block.start_offset);
                hval.confidence = 100;
                hval.provenance = decompiler_fact_provenance_t::provider_semantics;
                hblock.values.push_back(hval);

                ++global_value_id;
            }
        }

        for (const auto offset : block.instruction_offsets) {
            const auto insn_it = offset_to_instruction.find(offset);
            if (insn_it == offset_to_instruction.end()) continue;
            const auto& insn = code_item.instructions[insn_it->second];
            const auto info = extract_instruction_info(insn.opcode, capture.code_units, offset, insn.opcode_unit);

            const auto ssa_value_key = std::make_pair(block.id, static_cast<std::uint32_t>(0));
            std::uint64_t this_value_id = 0;
            for (const auto& [vk, vv] : block_values) {
                if (vk.first == block.id && vv.code_unit_offset == offset) {
                    if (old_to_new_value_id.count(vv.id)) {
                        this_value_id = old_to_new_value_id[vv.id];
                    } else {
                        this_value_id = vv.id;
                    }
                    break;
                }
            }
            if (this_value_id == 0) {
                this_value_id = global_value_id;
            }

            const auto coord = make_coordinate_with_debug(capture.request,
                decompiler_coordinate_layer_t::provider_ir, offset, insn.width_code_units, code_item);

            std::string stable_symbol = insn.mnemonic;
            std::string stable_immediate;
            if (insn.literal) {
                stable_immediate = std::to_string(*insn.literal);
            }
            if (insn.reference_kind == dalvik_reference_kind_t::string && insn.reference_index) {
                if (*insn.reference_index < capture.strings.size()) {
                    stable_symbol = "const-string:" + capture.strings[*insn.reference_index].value;
                }
            } else if (insn.reference_kind == dalvik_reference_kind_t::type && insn.reference_index) {
                if (*insn.reference_index < capture.types.size()) {
                    stable_symbol = capture.types[*insn.reference_index].descriptor;
                }
            } else if (insn.reference_kind == dalvik_reference_kind_t::field && insn.reference_index) {
                if (*insn.reference_index < capture.fields.size()) {
                    const auto& field = capture.fields[*insn.reference_index];
                    stable_symbol = field.class_descriptor + "." + field.name + ":" + field.type_descriptor;
                }
            } else if (insn.reference_kind == dalvik_reference_kind_t::method && insn.reference_index) {
                if (*insn.reference_index < capture.methods.size()) {
                    const auto& method = capture.methods[*insn.reference_index];
                    stable_symbol = method.class_descriptor + "." + method.name + method.descriptor;
                }
            }

            std::uint64_t type_id_for_value = int_id;
            if (info.dest_wide) type_id_for_value = long_id;
            if (info.is_field_load && insn.reference_index && *insn.reference_index < capture.fields.size()) {
                type_id_for_value = type_reg.ensure(capture.fields[*insn.reference_index].type_descriptor);
            }
            if (info.is_array_load) {
                type_id_for_value = int_id;
            }
            if (info.is_invoke) {
                type_id_for_value = object_id;
                if (insn.reference_index && *insn.reference_index < capture.methods.size()) {
                    const auto& method = capture.methods[*insn.reference_index];
                    type_id_for_value = type_reg.ensure(parse_prototype_return(method.descriptor));
                }
            }
            if (info.is_return) {
                type_id_for_value = return_type_id;
            }

            std::vector<std::uint64_t> operand_ids;
            for (std::size_t i = 0; i < info.src_regs.size(); ++i) {
                const auto reg = info.src_regs[i];
                const auto version = ctx.get_version(reg);
                if (version == 0) continue;
                for (const auto& [vk, vv] : block_values) {
                    if (vk.first == block.id && vv.register_number == reg && vv.ssa_version == version) {
                        const auto mapped = old_to_new_value_id.count(vv.id) ? old_to_new_value_id[vv.id] : vv.id;
                        if (std::find(operand_ids.begin(), operand_ids.end(), mapped) == operand_ids.end())
                            operand_ids.push_back(mapped);
                        break;
                    }
                }
            }

            const auto supported = (info.ir_opcode != provider_ir_opcode_t::unknown || insn.opcode == 0x00);

            provider_ir_value_t pval;
            pval.id = global_value_id;
            pval.opcode = info.ir_opcode;
            pval.type_id = type_id_for_value != 0 ? type_id_for_value : int_id;
            pval.operand_ids = operand_ids;
            pval.stable_immediate = stable_immediate;
            pval.stable_symbol = stable_symbol;
            pval.coordinate = coord;
            pval.confidence = supported ? 100 : 50;
            pval.provenance = decompiler_fact_provenance_t::bytecode_verifier;
            pblock.values.push_back(pval);

            hir_value_t hval;
            hval.id = global_value_id;
            hval.kind = info.hir_kind;
            hval.type_id = pval.type_id;
            hval.operand_ids = operand_ids;
            hval.stable_value = stable_symbol.empty() ? insn.mnemonic : stable_symbol;
            if (!stable_immediate.empty())
                hval.stable_value += "=" + stable_immediate;
            hval.coordinate = make_coordinate_with_debug(capture.request,
                decompiler_coordinate_layer_t::hir, offset, insn.width_code_units, code_item);
            hval.confidence = pval.confidence;
            hval.provenance = pval.provenance;
            hblock.values.push_back(hval);

            if (!supported) {
                decompiler_unknown_t punknown;
                punknown.reason = decompiler_unknown_reason_t::unsupported_instruction;
                punknown.stable_token = "dalvik.opcode." + std::to_string(insn.opcode) + "." + std::to_string(offset);
                punknown.coordinate = coord;
                punknown.confidence = 0;
                punknown.provenance = decompiler_fact_provenance_t::bytecode_verifier;
                provider_ir.unknowns.push_back(punknown);
                decompiler_unknown_t hunknown = punknown;
                hunknown.coordinate.layer = decompiler_coordinate_layer_t::hir;
                hir.unknowns.push_back(hunknown);
                provider_ir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_provider,
                    "dalvik_ssa.unsupported_opcode", provider_diag_ordinal++));
                hir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_provider,
                    "dalvik_ssa.unsupported_opcode", hir_diag_ordinal++));
            }

            ++global_value_id;
        }

        provider_ir.source_coordinates.push_back(pblock.coordinate);
        hir.source_coordinates.push_back(hblock.coordinate);
        provider_ir.blocks.push_back(std::move(pblock));
        hir.blocks.push_back(std::move(hblock));
    }

    hir.provider_ir_hash = stable_serialization_hash(provider_ir);

    for (auto& diag : result.diagnostics) {
        diag.ordinal = diagnostic_ordinal++;
    }
    for (auto& diag : provider_ir.diagnostics) {
        if (diag.ordinal == 0) diag.ordinal = diagnostic_ordinal++;
    }
    for (auto& diag : hir.diagnostics) {
        if (diag.ordinal == 0) diag.ordinal = diagnostic_ordinal++;
    }

    const auto provider_validation = validate_provider_ir(provider_ir);
    const auto hir_validation = validate_hir_function(hir);
    const auto type_validation = validate_type_graph(type_graph);
    if (!provider_validation.valid() || !hir_validation.valid() || !type_validation.valid()) {
        result.diagnostics.insert(result.diagnostics.end(), provider_validation.diagnostics.begin(), provider_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), hir_validation.diagnostics.begin(), hir_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), type_validation.diagnostics.begin(), type_validation.diagnostics.end());
        return result;
    }

    result.artifacts = dalvik_ssa_typed_artifacts_t{std::move(provider_ir), std::move(hir), std::move(type_graph)};
    return result;
}

std::string serialize_capture(const dalvik_ssa_capture_t& capture)
{
    using isolated_worker_codec::writer_t;
    if (!capture.code_item || !validate_decompiler_entity_key(capture.request.entity).valid() ||
        capture.request.entity.kind != decompiler_entity_kind_t::dalvik_method ||
        capture.request.provider.provider != decompiler_provider_id_t::dalvik_ssa ||
        capture.request.provider.provider_name.empty() ||
        capture.request.provider.provider_version.empty() ||
        capture.request.provider.provider_binary_hash.empty() ||
        capture.request.provider.worker_build_id.empty() ||
        capture.request.provider.worker_build_hash.empty() ||
        capture.request.language.language_id.empty() ||
        capture.request.language.language_version.empty() ||
        capture.request.language.compiler_spec_id.empty() ||
        capture.request.language.language_spec_hash.empty() ||
        capture.request.language.architecture != architecture_id_t::dalvik_bytecode ||
        capture.request.language.mode != architecture_mode_t::dalvik ||
        capture.request.workspace_generation == 0 || capture.request.type_graph_revision == 0)
        return {};
    writer_t writer;
    writer.u32(k_capture_magic);
    writer.u32(k_capture_version);
    isolated_worker_codec::write_provider_identity(writer, capture.request.provider);
    isolated_worker_codec::write_language_identity(writer, capture.request.language);
    isolated_worker_codec::write_entity(writer, capture.request.entity);
    writer.u64(capture.request.workspace_generation);
    writer.u64(capture.request.type_graph_revision);
    writer.u64(capture.request.return_type_id);
    writer.string(capture.request.dex_version);
    const auto& code = *capture.code_item;
    writer.u32(code.offset);
    writer.u16(code.registers_size);
    writer.u16(code.ins_size);
    writer.u16(code.outs_size);
    writer.u16(code.tries_size);
    writer.u32(code.debug_info_offset);
    writer.u32(code.instruction_count);
    writer.vector(code.instructions, [](writer_t& target, const dalvik_instruction_t& value) {
        target.u32(value.code_unit_offset);
        target.u64(value.file_offset);
        target.u16(value.opcode_unit);
        target.u8(value.opcode);
        target.u16(value.width_code_units);
        target.boolean(value.payload);
        target.enumeration(value.reference_kind);
        target.optional(value.reference_index,
            [](writer_t& nested, const std::uint32_t item) { nested.u32(item); });
        target.optional(value.secondary_reference_index,
            [](writer_t& nested, const std::uint32_t item) { nested.u32(item); });
        target.optional(value.literal,
            [](writer_t& nested, const std::int64_t item) { nested.i64(item); });
        target.optional(value.branch_target,
            [](writer_t& nested, const std::int32_t item) { nested.i32(item); });
    });
    writer.vector(code.tries, [](writer_t& target, const dex_try_item_t& value) {
        target.u32(value.start_address);
        target.u16(value.instruction_count);
        target.u16(value.handler_offset);
    });
    writer.vector(code.catch_handlers, [](writer_t& target, const dex_catch_handler_t& value) {
        target.u32(value.relative_offset);
        target.vector(value.typed_handlers,
            [](writer_t& nested, const std::pair<std::uint32_t, std::uint32_t>& item) {
                nested.u32(item.first);
                nested.u32(item.second);
            });
        target.optional(value.catch_all_address,
            [](writer_t& nested, const std::uint32_t item) { nested.u32(item); });
    });
    writer.optional(code.debug_info, [](writer_t& target, const dex_debug_info_t& value) {
        target.u32(value.offset);
        target.u32(value.line_start);
        target.vector(value.parameter_name_string_indices,
            [](writer_t& nested, const std::optional<std::uint32_t>& item) {
                nested.optional(item,
                    [](writer_t& leaf, const std::uint32_t index) { leaf.u32(index); });
            });
        target.vector(value.positions, [](writer_t& nested, const dex_debug_position_t& item) {
            nested.u32(item.address);
            nested.i32(item.line);
            nested.optional(item.source_file_string_index,
                [](writer_t& leaf, const std::uint32_t index) { leaf.u32(index); });
        });
    });
    writer.vector(capture.code_units,
        [](writer_t& target, const std::uint16_t value) { target.u16(value); });
    writer.vector(capture.strings, [](writer_t& target, const dex_string_t& value) {
        target.u32(value.index);
        target.u32(value.data_offset);
        target.u32(value.utf16_length);
        target.string(value.value);
    });
    writer.vector(capture.types, [](writer_t& target, const dex_type_t& value) {
        target.u32(value.index);
        target.u32(value.descriptor_string_index);
        target.string(value.descriptor);
    });
    writer.vector(capture.protos, [](writer_t& target, const dex_proto_t& value) {
        target.u32(value.index);
        target.u32(value.shorty_string_index);
        target.u32(value.return_type_index);
        target.u32(value.parameters_offset);
        target.string(value.shorty);
        target.string(value.descriptor);
        target.vector(value.parameter_type_indices,
            [](writer_t& nested, const std::uint16_t item) { nested.u16(item); });
    });
    writer.vector(capture.fields, [](writer_t& target, const dex_field_t& value) {
        target.u32(value.index);
        target.u16(value.class_type_index);
        target.u16(value.type_index);
        target.u32(value.name_string_index);
        target.string(value.class_descriptor);
        target.string(value.type_descriptor);
        target.string(value.name);
    });
    writer.vector(capture.methods, [](writer_t& target, const dex_method_t& value) {
        target.u32(value.index);
        target.u16(value.class_type_index);
        target.u16(value.proto_index);
        target.u32(value.name_string_index);
        target.string(value.class_descriptor);
        target.string(value.name);
        target.string(value.descriptor);
    });
    writer.u32(capture.method_id);
    writer.string(capture.class_descriptor);
    writer.string(capture.method_name);
    writer.string(capture.prototype);
    writer.string(capture.shorty);
    return writer.take();
}

std::optional<dalvik_ssa_capture_t> deserialize_capture(
    const std::string& bytes, std::vector<decompiler_diagnostic_t>& diagnostics)
{
    using isolated_worker_codec::reader_t;
    diagnostics.clear();
    reader_t reader(bytes);
    dalvik_ssa_capture_t capture;
    dex_code_item_t code;
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    const bool decoded = reader.u32(magic) && magic == k_capture_magic &&
        reader.u32(version) && version == k_capture_version &&
        isolated_worker_codec::read_provider_identity(reader, capture.request.provider) &&
        isolated_worker_codec::read_language_identity(reader, capture.request.language) &&
        isolated_worker_codec::read_entity(reader, capture.request.entity) &&
        reader.u64(capture.request.workspace_generation) &&
        reader.u64(capture.request.type_graph_revision) &&
        reader.u64(capture.request.return_type_id) &&
        reader.string(capture.request.dex_version) && reader.u32(code.offset) &&
        reader.u16(code.registers_size) && reader.u16(code.ins_size) &&
        reader.u16(code.outs_size) && reader.u16(code.tries_size) &&
        reader.u32(code.debug_info_offset) && reader.u32(code.instruction_count) &&
        reader.vector(code.instructions, [](reader_t& source, dalvik_instruction_t& value) {
            const bool valid = source.u32(value.code_unit_offset) && source.u64(value.file_offset) &&
                source.u16(value.opcode_unit) && source.u8(value.opcode) &&
                source.u16(value.width_code_units) && source.boolean(value.payload) &&
                source.enumeration(value.reference_kind) &&
                source.optional(value.reference_index,
                    [](reader_t& nested, std::uint32_t& item) { return nested.u32(item); }) &&
                source.optional(value.secondary_reference_index,
                    [](reader_t& nested, std::uint32_t& item) { return nested.u32(item); }) &&
                source.optional(value.literal,
                    [](reader_t& nested, std::int64_t& item) { return nested.i64(item); }) &&
                source.optional(value.branch_target,
                    [](reader_t& nested, std::int32_t& item) { return nested.i32(item); });
            value.mnemonic = restored_mnemonic(value.opcode_unit, value.opcode);
            return valid;
        }) &&
        reader.vector(code.tries, [](reader_t& source, dex_try_item_t& value) {
            return source.u32(value.start_address) && source.u16(value.instruction_count) &&
                source.u16(value.handler_offset);
        }) &&
        reader.vector(code.catch_handlers, [](reader_t& source, dex_catch_handler_t& value) {
            return source.u32(value.relative_offset) &&
                source.vector(value.typed_handlers,
                    [](reader_t& nested, std::pair<std::uint32_t, std::uint32_t>& item) {
                        return nested.u32(item.first) && nested.u32(item.second);
                    }) &&
                source.optional(value.catch_all_address,
                    [](reader_t& nested, std::uint32_t& item) { return nested.u32(item); });
        }) &&
        reader.optional(code.debug_info, [](reader_t& source, dex_debug_info_t& value) {
            return source.u32(value.offset) && source.u32(value.line_start) &&
                source.vector(value.parameter_name_string_indices,
                    [](reader_t& nested, std::optional<std::uint32_t>& item) {
                        return nested.optional(item,
                            [](reader_t& leaf, std::uint32_t& index) { return leaf.u32(index); });
                    }) &&
                source.vector(value.positions, [](reader_t& nested, dex_debug_position_t& item) {
                    return nested.u32(item.address) && nested.i32(item.line) &&
                        nested.optional(item.source_file_string_index,
                            [](reader_t& leaf, std::uint32_t& index) { return leaf.u32(index); });
                });
        }) &&
        reader.vector(capture.code_units,
            [](reader_t& source, std::uint16_t& value) { return source.u16(value); }) &&
        reader.vector(capture.strings, [](reader_t& source, dex_string_t& value) {
            return source.u32(value.index) && source.u32(value.data_offset) &&
                source.u32(value.utf16_length) && source.string(value.value);
        }) &&
        reader.vector(capture.types, [](reader_t& source, dex_type_t& value) {
            return source.u32(value.index) && source.u32(value.descriptor_string_index) &&
                source.string(value.descriptor);
        }) &&
        reader.vector(capture.protos, [](reader_t& source, dex_proto_t& value) {
            return source.u32(value.index) && source.u32(value.shorty_string_index) &&
                source.u32(value.return_type_index) && source.u32(value.parameters_offset) &&
                source.string(value.shorty) && source.string(value.descriptor) &&
                source.vector(value.parameter_type_indices,
                    [](reader_t& nested, std::uint16_t& item) { return nested.u16(item); });
        }) &&
        reader.vector(capture.fields, [](reader_t& source, dex_field_t& value) {
            return source.u32(value.index) && source.u16(value.class_type_index) &&
                source.u16(value.type_index) && source.u32(value.name_string_index) &&
                source.string(value.class_descriptor) && source.string(value.type_descriptor) &&
                source.string(value.name);
        }) &&
        reader.vector(capture.methods, [](reader_t& source, dex_method_t& value) {
            return source.u32(value.index) && source.u16(value.class_type_index) &&
                source.u16(value.proto_index) && source.u32(value.name_string_index) &&
                source.string(value.class_descriptor) && source.string(value.name) &&
                source.string(value.descriptor);
        }) && reader.u32(capture.method_id) && reader.string(capture.class_descriptor) &&
        reader.string(capture.method_name) && reader.string(capture.prototype) &&
        reader.string(capture.shorty) && reader.complete();
    if (!decoded || !validate_decompiler_entity_key(capture.request.entity).valid() ||
        capture.request.entity.kind != decompiler_entity_kind_t::dalvik_method ||
        capture.request.provider.provider != decompiler_provider_id_t::dalvik_ssa ||
        capture.request.provider.provider_name.empty() ||
        capture.request.provider.provider_version.empty() ||
        capture.request.provider.provider_binary_hash.empty() ||
        capture.request.provider.worker_build_id.empty() ||
        capture.request.provider.worker_build_hash.empty() ||
        capture.request.language.language_id.empty() ||
        capture.request.language.language_version.empty() ||
        capture.request.language.compiler_spec_id.empty() ||
        capture.request.language.language_spec_hash.empty() ||
        capture.request.language.architecture != architecture_id_t::dalvik_bytecode ||
        capture.request.language.mode != architecture_mode_t::dalvik ||
        capture.request.workspace_generation == 0 || capture.request.type_graph_revision == 0 ||
        code.instruction_count != capture.code_units.size()) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization,
            "dalvik_ssa.capture.decode", 1));
        return std::nullopt;
    }
    try {
        capture.code_item = std::make_shared<const dex_code_item_t>(std::move(code));
    } catch (...) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::resource_limit,
            "dalvik_ssa.capture.allocation", 1));
        return std::nullopt;
    }
    return capture;
}

std::string serialize_artifacts(const dalvik_ssa_typed_artifacts_t& artifacts)
{
    if (!validate_provider_ir(artifacts.provider_ir).valid() || !validate_hir_function(artifacts.hir).valid() ||
        !validate_type_graph(artifacts.type_graph).valid() ||
        !(artifacts.provider_ir.entity == artifacts.hir.entity) ||
        !(artifacts.provider_ir.entity == artifacts.type_graph.entity) ||
        artifacts.hir.provider_ir_hash != stable_serialization_hash(artifacts.provider_ir) ||
        artifacts.hir.type_graph_revision != artifacts.type_graph.revision)
        return {};
    try {
        std::string result;
        result.reserve(256);
        append_u32(result, k_artifact_magic);
        append_u32(result, k_artifact_version);
        if (!append_string(result, serialize_provider_ir(artifacts.provider_ir)) ||
            !append_string(result, serialize_hir_function(artifacts.hir)) ||
            !append_string(result, serialize_type_graph(artifacts.type_graph)))
            return {};
        return result;
    } catch (const std::exception&) {
        return {};
    }
}

std::optional<dalvik_ssa_typed_artifacts_t> deserialize_artifacts(
    const std::string& bytes, std::vector<decompiler_diagnostic_t>& diagnostics)
{
    diagnostics.clear();
    artifact_reader_t reader{bytes};
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::string provider_bytes;
    std::string hir_bytes;
    std::string type_bytes;
    if (bytes.size() > k_artifact_max_bytes || !reader.u32(magic) || magic != k_artifact_magic ||
        !reader.u32(version) || version != k_artifact_version || !reader.string(provider_bytes) ||
        !reader.string(hir_bytes) || !reader.string(type_bytes) || !reader.complete()) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization, "dalvik_ssa.artifact.decode", 1));
        return std::nullopt;
    }
    const auto provider = deserialize_provider_ir(provider_bytes);
    const auto hir = deserialize_hir_function(hir_bytes);
    const auto types = deserialize_type_graph(type_bytes);
    if (!provider.valid() || !hir.valid() || !types.valid() || !provider.value || !hir.value || !types.value ||
        !(provider.value->entity == hir.value->entity) ||
        !(provider.value->entity == types.value->entity) ||
        hir.value->provider_ir_hash != stable_serialization_hash(*provider.value) ||
        hir.value->type_graph_revision != types.value->revision) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization, "dalvik_ssa.artifact.binding", 1));
        return std::nullopt;
    }
    return dalvik_ssa_typed_artifacts_t{std::move(*provider.value), std::move(*hir.value), std::move(*types.value)};
}

}
