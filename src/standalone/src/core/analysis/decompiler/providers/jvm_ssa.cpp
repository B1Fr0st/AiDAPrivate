#include "jvm_ssa.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace aida::analysis::jvm_ssa {
namespace {

constexpr std::uint32_t k_artifact_magic = 0x5353564AU;
constexpr std::uint32_t k_artifact_version = 1;
constexpr std::size_t k_artifact_max_bytes = 32U * 1024U * 1024U;

decompiler_diagnostic_t make_diagnostic(decompiler_diagnostic_severity_t severity,
                                         decompiler_diagnostic_code_t code,
                                         std::string key,
                                         std::uint32_t ordinal)
{
    decompiler_diagnostic_t result;
    result.severity = severity;
    result.code = code;
    result.localization_key = std::move(key);
    result.confidence = 100;
    result.ordinal = ordinal;
    return result;
}

source_coordinate_t make_coordinate(const jvm_method_input_t& input,
                                     decompiler_coordinate_layer_t layer,
                                     std::uint64_t bytecode_offset,
                                     std::uint64_t instruction_length = 1)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = input.workspace_generation;
    result.entity = input.entity;
    decompiler_address_range_t range;
    range.begin = {address_space_id_t::relative_virtual, bytecode_offset,
                    architecture_id_t::jvm_bytecode, architecture_mode_t::jvm};
    range.end = {address_space_id_t::relative_virtual,
                  bytecode_offset == (std::numeric_limits<std::uint64_t>::max)() ? bytecode_offset : bytecode_offset + instruction_length,
                  architecture_id_t::jvm_bytecode, architecture_mode_t::jvm};
    result.address_range = range;
    for (const auto& ln : input.context.line_numbers) {
        if (ln.start_pc <= bytecode_offset) {
            decompiler_source_origin_t origin;
            origin.source_path = input.context.class_internal_name + ".java";
            origin.first_line = ln.line_number;
            origin.last_line = ln.line_number;
            result.source_origin = origin;
            break;
        }
    }
    return result;
}

struct bytecode_reader_t {
    const std::vector<std::uint8_t>& code;
    std::size_t pos = 0;

    bool has(std::size_t n) const noexcept { return pos + n <= code.size(); }
    bool at_end() const noexcept { return pos >= code.size(); }

    std::uint8_t u8() { return code[pos++]; }
    std::uint16_t u16() {
        std::uint16_t v = 0;
        v = static_cast<std::uint16_t>(code[pos++]) << 8;
        v |= static_cast<std::uint16_t>(code[pos++]);
        return v;
    }
    std::int16_t s16() { return static_cast<std::int16_t>(u16()); }
    std::uint32_t u32() {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i)
            v = (v << 8) | static_cast<std::uint32_t>(code[pos++]);
        return v;
    }
    std::int32_t s32() { return static_cast<std::int32_t>(u32()); }
    std::uint64_t u64() {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v = (v << 8) | static_cast<std::uint64_t>(code[pos++]);
        return v;
    }
};

struct instruction_t {
    std::uint64_t offset = 0;
    std::uint8_t opcode = 0;
    std::uint32_t length = 1;
    std::string mnemonic;
    std::optional<std::uint16_t> cp_index;
    std::optional<std::uint16_t> local_index;
    std::optional<std::int16_t> wide_local_index;
    std::optional<std::int8_t> iinc_const;
    std::optional<std::int16_t> wide_iinc_const;
    std::optional<std::int32_t> branch_offset;
    std::optional<std::int32_t> switch_default;
    std::vector<std::int32_t> switch_offsets;
    std::vector<std::int32_t> switch_matches;
    std::optional<std::uint8_t> array_type;
    std::optional<std::uint8_t> dimensions;
    std::optional<std::uint8_t> interface_count;
    std::optional<std::uint16_t> bootstrap_index;
    bool is_wide = false;
    bool is_reserved = false;
};

enum opcode_flags_t : std::uint16_t {
    flag_none = 0,
    flag_branch = 1 << 0,
    flag_switch = 1 << 1,
    flag_return = 1 << 2,
    flag_throw = 1 << 3,
    flag_call = 1 << 4,
    flag_field = 1 << 5,
    flag_array = 1 << 6,
    flag_monitor = 1 << 7,
    flag_jsr = 1 << 8,
    flag_reserved = 1 << 9,
    flag_cat2_result = 1 << 10,
    flag_dynamic_stack = 1 << 11,
    flag_load_local = 1 << 12,
    flag_store_local = 1 << 13,
    flag_terminator = 1 << 14
};

struct opcode_info_t {
    const char* mnemonic;
    std::uint8_t length;
    std::int8_t pop_slots;
    std::int8_t push_slots;
    provider_ir_opcode_t ir_opcode;
    hir_node_kind_t hir_kind;
    std::uint16_t flags;
};

static const opcode_info_t& opcode_info(std::uint8_t opcode)
{
    static const opcode_info_t table[256] = {
        {"nop",1,0,0,provider_ir_opcode_t::unknown,hir_node_kind_t::unknown,flag_none},
        {"aconst_null",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_m1",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_0",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_1",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_2",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_3",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_4",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"iconst_5",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"lconst_0",1,0,2,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_cat2_result},
        {"lconst_1",1,0,2,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_cat2_result},
        {"fconst_0",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"fconst_1",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"fconst_2",1,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"dconst_0",1,0,2,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_cat2_result},
        {"dconst_1",1,0,2,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_cat2_result},
        {"bipush",2,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"sipush",3,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_none},
        {"ldc",2,0,-1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_dynamic_stack},
        {"ldc_w",3,0,-1,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_dynamic_stack},
        {"ldc2_w",3,0,2,provider_ir_opcode_t::constant,hir_node_kind_t::literal,flag_cat2_result},
        {"iload",2,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"lload",2,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"fload",2,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"dload",2,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"aload",2,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"iload_0",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"iload_1",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"iload_2",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"iload_3",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"lload_0",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"lload_1",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"lload_2",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"lload_3",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"fload_0",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"fload_1",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"fload_2",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"fload_3",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"dload_0",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"dload_1",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"dload_2",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"dload_3",1,0,2,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local|flag_cat2_result},
        {"aload_0",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"aload_1",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"aload_2",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"aload_3",1,0,1,provider_ir_opcode_t::load,hir_node_kind_t::load,flag_load_local},
        {"iaload",1,2,1,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array},
        {"laload",1,2,2,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array|flag_cat2_result},
        {"faload",1,2,1,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array},
        {"daload",1,2,2,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array|flag_cat2_result},
        {"aaload",1,2,1,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array},
        {"baload",1,2,1,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array},
        {"caload",1,2,1,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array},
        {"saload",1,2,1,provider_ir_opcode_t::array_load,hir_node_kind_t::index,flag_array},
        {"istore",2,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"lstore",2,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"fstore",2,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"dstore",2,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"astore",2,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"istore_0",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"istore_1",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"istore_2",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"istore_3",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"lstore_0",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"lstore_1",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"lstore_2",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"lstore_3",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"fstore_0",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"fstore_1",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"fstore_2",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"fstore_3",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"dstore_0",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"dstore_1",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"dstore_2",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"dstore_3",1,2,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"astore_0",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"astore_1",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"astore_2",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"astore_3",1,1,0,provider_ir_opcode_t::store,hir_node_kind_t::store,flag_store_local},
        {"iastore",1,3,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"lastore",1,4,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"fastore",1,3,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"dastore",1,4,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"aastore",1,3,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"bastore",1,3,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"castore",1,3,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"sastore",1,3,0,provider_ir_opcode_t::array_store,hir_node_kind_t::index,flag_array},
        {"pop",1,1,0,provider_ir_opcode_t::unknown,hir_node_kind_t::unknown,flag_none},
        {"pop2",1,2,0,provider_ir_opcode_t::unknown,hir_node_kind_t::unknown,flag_none},
        {"dup",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"dup_x1",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"dup_x2",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"dup2",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"dup2_x1",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"dup2_x2",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"swap",1,0,0,provider_ir_opcode_t::copy,hir_node_kind_t::assignment,flag_none},
        {"iadd",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"ladd",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"fadd",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"dadd",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"isub",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lsub",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"fsub",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"dsub",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"imul",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lmul",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"fmul",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"dmul",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"idiv",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"ldiv",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"fdiv",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"ddiv",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"irem",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lrem",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"frem",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"drem",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"ineg",1,1,1,provider_ir_opcode_t::unary,hir_node_kind_t::unary,flag_none},
        {"lneg",1,2,2,provider_ir_opcode_t::unary,hir_node_kind_t::unary,flag_cat2_result},
        {"fneg",1,1,1,provider_ir_opcode_t::unary,hir_node_kind_t::unary,flag_none},
        {"dneg",1,2,2,provider_ir_opcode_t::unary,hir_node_kind_t::unary,flag_cat2_result},
        {"ishl",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lshl",1,3,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"ishr",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lshr",1,3,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"iushr",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lushr",1,3,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"iand",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"land",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"ior",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lor",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"ixor",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"lxor",1,4,2,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_cat2_result},
        {"iinc",3,0,0,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_load_local|flag_store_local},
        {"i2l",1,1,2,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_cat2_result},
        {"i2f",1,1,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"i2d",1,1,2,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_cat2_result},
        {"l2i",1,2,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"l2f",1,2,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"l2d",1,2,2,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_cat2_result},
        {"f2i",1,1,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"f2l",1,1,2,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_cat2_result},
        {"f2d",1,1,2,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_cat2_result},
        {"d2i",1,2,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"d2l",1,2,2,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_cat2_result},
        {"d2f",1,2,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"i2b",1,1,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"i2c",1,1,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"i2s",1,1,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"lcmp",1,4,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"fcmpl",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"fcmpg",1,2,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"dcmpl",1,4,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"dcmpg",1,4,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"ifeq",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"ifne",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"iflt",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"ifge",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"ifgt",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"ifle",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_icmpeq",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_icmpne",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_icmplt",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_icmpge",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_icmpgt",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_icmple",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_acmpeq",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"if_acmpne",3,2,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"goto",3,0,0,provider_ir_opcode_t::branch,hir_node_kind_t::branch,flag_branch|flag_terminator},
        {"jsr",3,0,1,provider_ir_opcode_t::branch,hir_node_kind_t::branch,flag_jsr|flag_branch},
        {"ret",2,0,0,provider_ir_opcode_t::branch,hir_node_kind_t::branch,flag_jsr|flag_terminator},
        {"tableswitch",0,1,0,provider_ir_opcode_t::switch_branch,hir_node_kind_t::switch_branch,flag_switch|flag_terminator},
        {"lookupswitch",0,1,0,provider_ir_opcode_t::switch_branch,hir_node_kind_t::switch_branch,flag_switch|flag_terminator},
        {"ireturn",1,1,0,provider_ir_opcode_t::return_value,hir_node_kind_t::return_value,flag_return|flag_terminator},
        {"lreturn",1,2,0,provider_ir_opcode_t::return_value,hir_node_kind_t::return_value,flag_return|flag_terminator},
        {"freturn",1,1,0,provider_ir_opcode_t::return_value,hir_node_kind_t::return_value,flag_return|flag_terminator},
        {"dreturn",1,2,0,provider_ir_opcode_t::return_value,hir_node_kind_t::return_value,flag_return|flag_terminator},
        {"areturn",1,1,0,provider_ir_opcode_t::return_value,hir_node_kind_t::return_value,flag_return|flag_terminator},
        {"return",1,0,0,provider_ir_opcode_t::return_value,hir_node_kind_t::return_value,flag_return|flag_terminator},
        {"getstatic",3,-1,-1,provider_ir_opcode_t::field_load,hir_node_kind_t::field,flag_field|flag_dynamic_stack},
        {"putstatic",3,-1,-1,provider_ir_opcode_t::field_store,hir_node_kind_t::field,flag_field|flag_dynamic_stack},
        {"getfield",3,-1,-1,provider_ir_opcode_t::field_load,hir_node_kind_t::field,flag_field|flag_dynamic_stack},
        {"putfield",3,-1,-1,provider_ir_opcode_t::field_store,hir_node_kind_t::field,flag_field|flag_dynamic_stack},
        {"invokevirtual",3,-1,-1,provider_ir_opcode_t::call,hir_node_kind_t::call,flag_call|flag_dynamic_stack},
        {"invokespecial",3,-1,-1,provider_ir_opcode_t::call,hir_node_kind_t::call,flag_call|flag_dynamic_stack},
        {"invokestatic",3,-1,-1,provider_ir_opcode_t::call,hir_node_kind_t::call,flag_call|flag_dynamic_stack},
        {"invokeinterface",5,-1,-1,provider_ir_opcode_t::call,hir_node_kind_t::call,flag_call|flag_dynamic_stack},
        {"invokedynamic",5,-1,-1,provider_ir_opcode_t::call,hir_node_kind_t::call,flag_call|flag_dynamic_stack},
        {"new",3,0,1,provider_ir_opcode_t::constant,hir_node_kind_t::reference,flag_none},
        {"newarray",2,1,1,provider_ir_opcode_t::constant,hir_node_kind_t::reference,flag_array},
        {"anewarray",3,1,1,provider_ir_opcode_t::constant,hir_node_kind_t::reference,flag_array},
        {"arraylength",1,1,1,provider_ir_opcode_t::unary,hir_node_kind_t::unary,flag_array},
        {"athrow",1,1,0,provider_ir_opcode_t::throw_value,hir_node_kind_t::throw_value,flag_throw|flag_terminator},
        {"checkcast",3,1,1,provider_ir_opcode_t::cast,hir_node_kind_t::cast,flag_none},
        {"instanceof",3,1,1,provider_ir_opcode_t::binary,hir_node_kind_t::binary,flag_none},
        {"monitorenter",1,1,0,provider_ir_opcode_t::monitor_enter,hir_node_kind_t::unknown,flag_monitor},
        {"monitorexit",1,1,0,provider_ir_opcode_t::monitor_exit,hir_node_kind_t::unknown,flag_monitor},
        {"wide",0,0,0,provider_ir_opcode_t::unknown,hir_node_kind_t::unknown,flag_none},
        {"multianewarray",4,-1,1,provider_ir_opcode_t::constant,hir_node_kind_t::reference,flag_array|flag_dynamic_stack},
        {"ifnull",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"ifnonnull",3,1,0,provider_ir_opcode_t::conditional_branch,hir_node_kind_t::conditional,flag_branch},
        {"goto_w",5,0,0,provider_ir_opcode_t::branch,hir_node_kind_t::branch,flag_branch|flag_terminator},
        {"jsr_w",5,0,1,provider_ir_opcode_t::branch,hir_node_kind_t::branch,flag_jsr|flag_branch},
        {"breakpoint",1,0,0,provider_ir_opcode_t::unknown,hir_node_kind_t::unknown,flag_reserved},
    };
    return table[opcode & 0xFF];
}

static void fill_unused(opcode_info_t& info, std::uint8_t opcode)
{
    if (opcode >= 0xCB && opcode <= 0xFD) {
        info.mnemonic = "unused";
        info.length = 1;
        info.flags = flag_reserved;
    } else if (opcode == 0xFE) {
        info.mnemonic = "impdep1";
        info.length = 1;
        info.flags = flag_reserved;
    } else if (opcode == 0xFF) {
        info.mnemonic = "impdep2";
        info.length = 1;
        info.flags = flag_reserved;
    }
}

struct decoded_instruction_t {
    instruction_t inst;
    bool valid = false;
    std::string error;
};

decoded_instruction_t decode_instruction(const std::vector<std::uint8_t>& code, std::size_t offset)
{
    decoded_instruction_t result;
    if (offset >= code.size()) {
        result.error = "instruction offset beyond code array";
        return result;
    }
    auto& inst = result.inst;
    inst.offset = offset;
    inst.opcode = code[offset];
    auto info = opcode_info(inst.opcode);
    fill_unused(info, inst.opcode);
    inst.mnemonic = info.mnemonic;
    inst.is_reserved = (info.flags & flag_reserved) != 0;

    if (inst.is_reserved) {
        inst.length = info.length > 0 ? info.length : 1;
        result.valid = true;
        return result;
    }

    bytecode_reader_t reader{code, offset + 1};

    switch (inst.opcode) {
    case 0x10:
        if (!reader.has(1)) { result.error = "bipush truncated"; return result; }
        inst.length = 2;
        result.valid = true;
        return result;
    case 0x11:
        if (!reader.has(2)) { result.error = "sipush truncated"; return result; }
        inst.length = 3;
        result.valid = true;
        return result;
    case 0x12:
        if (!reader.has(1)) { result.error = "ldc truncated"; return result; }
        inst.cp_index = reader.u8();
        inst.length = 2;
        result.valid = true;
        return result;
    case 0x13: case 0x14:
        if (!reader.has(2)) { result.error = "ldc_w/ldc2_w truncated"; return result; }
        inst.cp_index = reader.u16();
        inst.length = 3;
        result.valid = true;
        return result;
    case 0x15: case 0x16: case 0x17: case 0x18: case 0x19:
    case 0x36: case 0x37: case 0x38: case 0x39: case 0x3A:
        if (!reader.has(1)) { result.error = "load/store truncated"; return result; }
        inst.local_index = reader.u8();
        inst.length = 2;
        result.valid = true;
        return result;
    case 0xA9:
        if (!reader.has(1)) { result.error = "ret truncated"; return result; }
        inst.local_index = reader.u8();
        inst.length = 2;
        result.valid = true;
        return result;
    case 0x84:
        if (!reader.has(2)) { result.error = "iinc truncated"; return result; }
        inst.local_index = reader.u8();
        inst.iinc_const = static_cast<std::int8_t>(reader.u8());
        inst.length = 3;
        result.valid = true;
        return result;
    case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E:
    case 0x9F: case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4:
    case 0xA5: case 0xA6: case 0xA7: case 0xA8:
    case 0xC6: case 0xC7:
        if (!reader.has(2)) { result.error = "branch truncated"; return result; }
        inst.branch_offset = reader.s16();
        inst.length = 3;
        result.valid = true;
        return result;
    case 0xC8: case 0xC9:
        if (!reader.has(4)) { result.error = "goto_w/jsr_w truncated"; return result; }
        inst.branch_offset = reader.s32();
        inst.length = 5;
        result.valid = true;
        return result;
    case 0xB2: case 0xB3: case 0xB4: case 0xB5:
    case 0xB6: case 0xB7: case 0xB8:
    case 0xBB: case 0xBD: case 0xC0: case 0xC1:
        if (!reader.has(2)) { result.error = "cp ref truncated"; return result; }
        inst.cp_index = reader.u16();
        inst.length = 3;
        result.valid = true;
        return result;
    case 0xB9:
        if (!reader.has(4)) { result.error = "invokeinterface truncated"; return result; }
        inst.cp_index = reader.u16();
        inst.interface_count = reader.u8();
        inst.length = 5;
        result.valid = true;
        return result;
    case 0xBA:
        if (!reader.has(4)) { result.error = "invokedynamic truncated"; return result; }
        inst.cp_index = reader.u16();
        reader.u8();
        reader.u8();
        inst.length = 5;
        result.valid = true;
        return result;
    case 0xBC:
        if (!reader.has(1)) { result.error = "newarray truncated"; return result; }
        inst.array_type = reader.u8();
        inst.length = 2;
        result.valid = true;
        return result;
    case 0xC5:
        if (!reader.has(3)) { result.error = "multianewarray truncated"; return result; }
        inst.cp_index = reader.u16();
        inst.dimensions = reader.u8();
        inst.length = 4;
        result.valid = true;
        return result;
    case 0xC4: {
        if (!reader.has(1)) { result.error = "wide truncated"; return result; }
        auto sub = reader.u8();
        inst.is_wide = true;
        if (sub == 0x84) {
            if (!reader.has(4)) { result.error = "wide iinc truncated"; return result; }
            inst.wide_local_index = static_cast<std::int16_t>(reader.u16());
            inst.wide_iinc_const = static_cast<std::int16_t>(reader.u16());
            inst.opcode = 0x84;
            inst.mnemonic = "wide iinc";
            inst.length = 6;
        } else {
            if (!reader.has(2)) { result.error = "wide truncated"; return result; }
            inst.wide_local_index = static_cast<std::int16_t>(reader.u16());
            inst.opcode = sub;
            auto sub_info = opcode_info(sub);
            inst.mnemonic = sub_info.mnemonic;
            inst.length = 4;
        }
        result.valid = true;
        return result;
    }
    case 0xAA: {
        std::size_t pad = (3 - (offset & 3)) & 3;
        if (!reader.has(pad + 12)) { result.error = "tableswitch truncated"; return result; }
        reader.pos += pad;
        inst.switch_default = reader.s32();
        std::int32_t low = reader.s32();
        std::int32_t high = reader.s32();
        std::int32_t count = high - low + 1;
        if (count < 0 || count > static_cast<std::int32_t>(1 << 20)) { result.error = "tableswitch range invalid"; return result; }
        if (!reader.has(static_cast<std::size_t>(count) * 4)) { result.error = "tableswitch offsets truncated"; return result; }
        inst.switch_matches.push_back(low);
        inst.switch_matches.push_back(high);
        for (std::int32_t i = 0; i < count; ++i)
            inst.switch_offsets.push_back(reader.s32());
        inst.length = static_cast<std::uint32_t>(1 + pad + 12 + count * 4);
        result.valid = true;
        return result;
    }
    case 0xAB: {
        std::size_t pad = (3 - (offset & 3)) & 3;
        if (!reader.has(pad + 8)) { result.error = "lookupswitch truncated"; return result; }
        reader.pos += pad;
        inst.switch_default = reader.s32();
        std::int32_t npairs = reader.s32();
        if (npairs < 0 || npairs > static_cast<std::int32_t>(1 << 20)) { result.error = "lookupswitch npairs invalid"; return result; }
        if (!reader.has(static_cast<std::size_t>(npairs) * 8)) { result.error = "lookupswitch pairs truncated"; return result; }
        for (std::int32_t i = 0; i < npairs; ++i) {
            inst.switch_matches.push_back(reader.s32());
            inst.switch_offsets.push_back(reader.s32());
        }
        inst.length = static_cast<std::uint32_t>(1 + pad + 8 + npairs * 8);
        result.valid = true;
        return result;
    }
    default:
        if (info.length == 0) {
            result.error = "unrecognized variable-length opcode";
            return result;
        }
        if (!reader.has(info.length - 1)) { result.error = "instruction truncated"; return result; }
        inst.length = info.length;
        result.valid = true;
        return result;
    }
}

std::vector<instruction_t> decode_all(const std::vector<std::uint8_t>& code,
                                       std::vector<decompiler_diagnostic_t>& diagnostics)
{
    std::vector<instruction_t> instructions;
    std::uint32_t ordinal = 1;
    std::size_t offset = 0;
    while (offset < code.size()) {
        auto decoded = decode_instruction(code, offset);
        if (!decoded.valid) {
            diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::malformed_provider_ir,
                "jvm_ssa.decode." + std::to_string(offset) + ":" + decoded.error,
                ordinal++));
            break;
        }
        instructions.push_back(decoded.inst);
        offset += decoded.inst.length;
    }
    return instructions;
}

std::string cp_utf8(const std::vector<jvm_constant_pool_entry_t>& cp, std::uint16_t index)
{
    if (index == 0 || index >= cp.size())
        return {};
    const auto& entry = cp[index];
    if (entry.tag == jvm_constant_tag_t::utf8)
        return entry.utf8_value;
    return {};
}

std::string cp_class_name(const std::vector<jvm_constant_pool_entry_t>& cp, std::uint16_t index)
{
    if (index == 0 || index >= cp.size())
        return {};
    const auto& entry = cp[index];
    if (entry.tag == jvm_constant_tag_t::class_ref)
        return cp_utf8(cp, entry.ref_index1);
    return {};
}

struct name_and_type_t {
    std::string name;
    std::string descriptor;
};

name_and_type_t cp_name_and_type(const std::vector<jvm_constant_pool_entry_t>& cp, std::uint16_t index)
{
    name_and_type_t result;
    if (index == 0 || index >= cp.size())
        return result;
    const auto& entry = cp[index];
    if (entry.tag == jvm_constant_tag_t::name_and_type) {
        result.name = cp_utf8(cp, entry.ref_index1);
        result.descriptor = cp_utf8(cp, entry.ref_index2);
    }
    return result;
}

struct ref_info_t {
    std::string class_name;
    std::string name;
    std::string descriptor;
    std::uint16_t bootstrap_index = 0;
    bool is_invokedynamic = false;
};

ref_info_t cp_ref(const std::vector<jvm_constant_pool_entry_t>& cp, std::uint16_t index)
{
    ref_info_t result;
    if (index == 0 || index >= cp.size())
        return result;
    const auto& entry = cp[index];
    if (entry.tag == jvm_constant_tag_t::fieldref ||
        entry.tag == jvm_constant_tag_t::methodref ||
        entry.tag == jvm_constant_tag_t::interface_methodref) {
        result.class_name = cp_class_name(cp, entry.ref_index1);
        auto nat = cp_name_and_type(cp, entry.ref_index2);
        result.name = nat.name;
        result.descriptor = nat.descriptor;
    } else if (entry.tag == jvm_constant_tag_t::invoke_dynamic) {
        result.bootstrap_index = entry.bootstrap_method_attr_index;
        auto nat = cp_name_and_type(cp, entry.ref_index2);
        result.name = nat.name;
        result.descriptor = nat.descriptor;
        result.is_invokedynamic = true;
    }
    return result;
}

struct type_descriptor_t {
    std::string descriptor;
    bool is_category_2 = false;
    bool is_reference = false;
    bool is_array = false;
    bool is_void = false;
    std::string element_descriptor;
    std::string class_name;
};

type_descriptor_t parse_type_descriptor(const std::string& descriptor, std::size_t& pos)
{
    type_descriptor_t result;
    if (pos >= descriptor.size())
        return result;
    result.descriptor = std::string(1, descriptor[pos]);
    switch (descriptor[pos]) {
    case 'B': case 'C': case 'I': case 'S': case 'Z':
        pos++;
        return result;
    case 'F':
        pos++;
        return result;
    case 'J':
        result.is_category_2 = true;
        pos++;
        return result;
    case 'D':
        result.is_category_2 = true;
        pos++;
        return result;
    case 'V':
        result.is_void = true;
        pos++;
        return result;
    case 'L':
        result.is_reference = true;
        {
            std::size_t end = descriptor.find(';', pos);
            if (end == std::string::npos)
                return result;
            result.class_name = descriptor.substr(pos + 1, end - pos - 1);
            result.descriptor = descriptor.substr(pos, end - pos + 1);
            pos = end + 1;
        }
        return result;
    case '[':
        result.is_array = true;
        result.is_reference = true;
        pos++;
        {
            std::size_t elem_start = pos;
            auto inner = parse_type_descriptor(descriptor, pos);
            result.element_descriptor = descriptor.substr(elem_start, pos - elem_start);
            result.descriptor = "[" + result.element_descriptor;
        }
        return result;
    default:
        return result;
    }
}

type_descriptor_t parse_single_type(const std::string& descriptor)
{
    std::size_t pos = 0;
    return parse_type_descriptor(descriptor, pos);
}

struct method_descriptor_t {
    std::vector<type_descriptor_t> parameters;
    type_descriptor_t return_type;
    bool valid = false;
};

method_descriptor_t parse_method_descriptor(const std::string& descriptor)
{
    method_descriptor_t result;
    std::size_t pos = 0;
    if (pos >= descriptor.size() || descriptor[pos] != '(')
        return result;
    pos++;
    while (pos < descriptor.size() && descriptor[pos] != ')') {
        auto param = parse_type_descriptor(descriptor, pos);
        if (param.descriptor.empty())
            return result;
        result.parameters.push_back(param);
    }
    if (pos >= descriptor.size() || descriptor[pos] != ')')
        return result;
    pos++;
    result.return_type = parse_type_descriptor(descriptor, pos);
    result.valid = true;
    return result;
}

std::uint8_t type_descriptor_slots(const type_descriptor_t& td)
{
    return td.is_category_2 ? 2 : 1;
}

decompiler_type_kind_t type_kind_from_descriptor(const type_descriptor_t& td)
{
    if (td.is_void) return decompiler_type_kind_t::void_type;
    if (td.is_array) return decompiler_type_kind_t::array;
    if (td.is_reference) return decompiler_type_kind_t::class_type;
    if (td.is_category_2) {
        if (td.descriptor == "J") return decompiler_type_kind_t::signed_integer;
        if (td.descriptor == "D") return decompiler_type_kind_t::floating_point;
    }
    if (td.descriptor == "Z") return decompiler_type_kind_t::boolean;
    if (td.descriptor == "F") return decompiler_type_kind_t::floating_point;
    return decompiler_type_kind_t::signed_integer;
}

class type_registry_t {
public:
    explicit type_registry_t(const jvm_method_input_t& input)
        : input_(input)
    {
        register_primitive("V", decompiler_type_kind_t::void_type, 0, false);
        register_primitive("Z", decompiler_type_kind_t::boolean, 1, false);
        register_primitive("B", decompiler_type_kind_t::signed_integer, 1, true);
        register_primitive("C", decompiler_type_kind_t::unsigned_integer, 2, false);
        register_primitive("S", decompiler_type_kind_t::signed_integer, 2, true);
        register_primitive("I", decompiler_type_kind_t::signed_integer, 4, true);
        register_primitive("J", decompiler_type_kind_t::signed_integer, 8, true);
        register_primitive("F", decompiler_type_kind_t::floating_point, 4, false);
        register_primitive("D", decompiler_type_kind_t::floating_point, 8, false);
        register_class("java/lang/Object");
        register_class("java/lang/String");
        register_class("java/lang/Throwable");
        register_class(input_.context.class_internal_name);
    }

    std::uint64_t register_type(const type_descriptor_t& td)
    {
        if (td.is_void) return id_for_descriptor("V");
        if (td.descriptor.empty()) return 0;
        auto found = descriptor_to_id_.find(td.descriptor);
        if (found != descriptor_to_id_.end())
            return found->second;
        if (td.is_array) {
            std::uint64_t element_id = register_type(parse_single_type(td.element_descriptor));
            std::uint64_t id = next_id_++;
            decompiler_type_node_t node;
            node.id = id;
            node.kind = decompiler_type_kind_t::array;
            node.canonical_name = td.descriptor;
            node.display_name = td.descriptor;
            node.byte_size = std::nullopt;
            node.alignment = 8;
            node.confidence = 100;
            node.provenance = decompiler_fact_provenance_t::loader_metadata;
            node.coordinates.push_back(make_coordinate(input_, decompiler_coordinate_layer_t::provider_ir, 0));
            nodes_.push_back(node);
            decompiler_type_edge_t edge;
            edge.source_type_id = id;
            edge.target_type_id = element_id;
            edge.kind = decompiler_type_edge_kind_t::element;
            edge.stable_name = "element";
            edge.ordinal = static_cast<std::uint32_t>(edges_.size() + 1);
            edge.confidence = 100;
            edge.provenance = decompiler_fact_provenance_t::loader_metadata;
            edges_.push_back(edge);
            descriptor_to_id_[td.descriptor] = id;
            return id;
        }
        if (td.is_reference)
            return register_class(td.class_name);
        return id_for_descriptor(td.descriptor);
    }

    std::uint64_t register_class(const std::string& internal_name)
    {
        std::string desc = "L" + internal_name + ";";
        auto found = descriptor_to_id_.find(desc);
        if (found != descriptor_to_id_.end())
            return found->second;
        std::uint64_t id = next_id_++;
        decompiler_type_node_t node;
        node.id = id;
        node.kind = decompiler_type_kind_t::class_type;
        node.canonical_name = internal_name;
        node.display_name = internal_name;
        node.byte_size = std::nullopt;
        node.alignment = 8;
        node.confidence = 100;
        node.provenance = decompiler_fact_provenance_t::loader_metadata;
        node.coordinates.push_back(make_coordinate(input_, decompiler_coordinate_layer_t::provider_ir, 0));
        nodes_.push_back(node);
        descriptor_to_id_[desc] = id;
        return id;
    }

    std::uint64_t register_return_address()
    {
        auto found = descriptor_to_id_.find("ret_addr");
        if (found != descriptor_to_id_.end())
            return found->second;
        std::uint64_t id = next_id_++;
        decompiler_type_node_t node;
        node.id = id;
        node.kind = decompiler_type_kind_t::pointer;
        node.canonical_name = "ret_addr";
        node.display_name = "return_address";
        node.byte_size = 8;
        node.alignment = 8;
        node.confidence = 100;
        node.provenance = decompiler_fact_provenance_t::bytecode_verifier;
        nodes_.push_back(node);
        descriptor_to_id_["ret_addr"] = id;
        return id;
    }

    std::uint64_t register_null_type()
    {
        auto found = descriptor_to_id_.find("null");
        if (found != descriptor_to_id_.end())
            return found->second;
        std::uint64_t id = next_id_++;
        decompiler_type_node_t node;
        node.id = id;
        node.kind = decompiler_type_kind_t::unknown;
        node.canonical_name = "null";
        node.display_name = "null";
        node.byte_size = 0;
        node.alignment = 0;
        node.confidence = 100;
        node.provenance = decompiler_fact_provenance_t::bytecode_verifier;
        nodes_.push_back(node);
        descriptor_to_id_["null"] = id;
        return id;
    }

    std::uint64_t id_for_descriptor(const std::string& desc) const
    {
        auto found = descriptor_to_id_.find(desc);
        return found != descriptor_to_id_.end() ? found->second : 0;
    }

    std::uint64_t return_type_id(const std::string& method_descriptor)
    {
        auto md = parse_method_descriptor(method_descriptor);
        if (!md.valid)
            return id_for_descriptor("V");
        return register_type(md.return_type);
    }

    const std::vector<decompiler_type_node_t>& nodes() const noexcept { return nodes_; }
    const std::vector<decompiler_type_edge_t>& edges() const noexcept { return edges_; }

private:
    void register_primitive(const std::string& desc, decompiler_type_kind_t kind,
                             std::uint64_t byte_size, bool is_signed)
    {
        std::uint64_t id = next_id_++;
        decompiler_type_node_t node;
        node.id = id;
        node.kind = kind;
        node.canonical_name = desc;
        node.display_name = desc;
        node.byte_size = byte_size;
        node.alignment = byte_size > 0 ? static_cast<std::uint32_t>(byte_size) : 1;
        node.is_signed = is_signed;
        node.confidence = 100;
        node.provenance = decompiler_fact_provenance_t::loader_metadata;
        nodes_.push_back(node);
        descriptor_to_id_[desc] = id;
    }

    const jvm_method_input_t& input_;
    std::vector<decompiler_type_node_t> nodes_;
    std::vector<decompiler_type_edge_t> edges_;
    std::unordered_map<std::string, std::uint64_t> descriptor_to_id_;
    std::uint64_t next_id_ = 1;
};

struct cfg_block_t {
    std::uint64_t id = 0;
    std::uint64_t start_offset = 0;
    std::uint64_t end_offset = 0;
    std::vector<std::uint64_t> instruction_indices;
    std::vector<std::uint64_t> predecessor_ids;
    std::vector<std::uint64_t> successor_ids;
    std::vector<std::uint64_t> exception_successor_ids;
    std::vector<std::uint64_t> exception_predecessor_ids;
    bool is_exception_handler = false;
    bool is_jsr_target = false;
};

struct cfg_t {
    std::vector<cfg_block_t> blocks;
    std::unordered_map<std::uint64_t, std::size_t> offset_to_block;
    std::uint64_t entry_block_id = 0;
};

cfg_t build_cfg(const std::vector<instruction_t>& instructions,
                const std::vector<jvm_code_exception_t>& exceptions,
                std::vector<decompiler_diagnostic_t>& diagnostics)
{
    cfg_t cfg;
    std::uint32_t ordinal = static_cast<std::uint32_t>(diagnostics.size() + 1);

    if (instructions.empty()) {
        diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_provider_ir,
            "jvm_ssa.cfg.empty", ordinal));
        return cfg;
    }

    std::set<std::uint64_t> leaders;
    leaders.insert(0);

    for (const auto& inst : instructions) {
        auto info = opcode_info(inst.opcode);
        fill_unused(info, inst.opcode);

        if (info.flags & flag_branch) {
            if (inst.branch_offset.has_value()) {
                std::int64_t target = static_cast<std::int64_t>(inst.offset) + *inst.branch_offset;
                if (target < 0 || target > static_cast<std::int64_t>(instructions.back().offset + instructions.back().length)) {
                    diagnostics.push_back(make_diagnostic(
                        decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::malformed_provider_ir,
                        "jvm_ssa.cfg.branch_target." + std::to_string(inst.offset),
                        ordinal++));
                } else {
                    leaders.insert(static_cast<std::uint64_t>(target));
                }
            }
            if (!(info.flags & flag_terminator) || inst.opcode == 0x99 || inst.opcode == 0x9A ||
                inst.opcode == 0x9B || inst.opcode == 0x9C || inst.opcode == 0x9D || inst.opcode == 0x9E ||
                inst.opcode == 0x9F || inst.opcode == 0xA0 || inst.opcode == 0xA1 || inst.opcode == 0xA2 ||
                inst.opcode == 0xA3 || inst.opcode == 0xA4 || inst.opcode == 0xA5 || inst.opcode == 0xA6 ||
                inst.opcode == 0xC6 || inst.opcode == 0xC7) {
                std::uint64_t fallthrough = inst.offset + inst.length;
                if (fallthrough <= instructions.back().offset + instructions.back().length)
                    leaders.insert(fallthrough);
            }
        }

        if (info.flags & flag_switch) {
            if (inst.switch_default.has_value()) {
                std::int64_t target = static_cast<std::int64_t>(inst.offset) + *inst.switch_default;
                if (target >= 0 && target <= static_cast<std::int64_t>(instructions.back().offset + instructions.back().length))
                    leaders.insert(static_cast<std::uint64_t>(target));
            }
            for (auto off : inst.switch_offsets) {
                std::int64_t target = static_cast<std::int64_t>(inst.offset) + off;
                if (target >= 0 && target <= static_cast<std::int64_t>(instructions.back().offset + instructions.back().length))
                    leaders.insert(static_cast<std::uint64_t>(target));
            }
            std::uint64_t fallthrough = inst.offset + inst.length;
            if (fallthrough <= instructions.back().offset + instructions.back().length)
                leaders.insert(fallthrough);
        }

        if (inst.opcode == 0xA8 || inst.opcode == 0xC9)
            leaders.insert(inst.offset + inst.length);
    }

    for (const auto& exc : exceptions) {
        if (exc.handler_pc < instructions.back().offset + instructions.back().length)
            leaders.insert(exc.handler_pc);
    }

    std::vector<std::uint64_t> sorted_leaders(leaders.begin(), leaders.end());
    std::sort(sorted_leaders.begin(), sorted_leaders.end());

    std::unordered_map<std::uint64_t, std::size_t> inst_offset_to_idx;
    for (std::size_t i = 0; i < instructions.size(); ++i)
        inst_offset_to_idx[instructions[i].offset] = i;

    std::uint64_t block_id = 1;
    for (std::size_t i = 0; i < sorted_leaders.size(); ++i) {
        cfg_block_t block;
        block.id = block_id++;
        block.start_offset = sorted_leaders[i];
        block.end_offset = (i + 1 < sorted_leaders.size()) ? sorted_leaders[i + 1] :
            (instructions.back().offset + instructions.back().length);

        auto it = inst_offset_to_idx.find(block.start_offset);
        if (it == inst_offset_to_idx.end())
            continue;

        for (std::size_t j = it->second; j < instructions.size(); ++j) {
            if (instructions[j].offset >= block.end_offset)
                break;
            block.instruction_indices.push_back(j);
        }

        if (!block.instruction_indices.empty()) {
            cfg.blocks.push_back(std::move(block));
        }
    }

    for (std::size_t bi = 0; bi < cfg.blocks.size(); ++bi) {
        cfg.offset_to_block[cfg.blocks[bi].start_offset] = bi;
    }

    for (std::size_t bi = 0; bi < cfg.blocks.size(); ++bi) {
        auto& block = cfg.blocks[bi];
        if (block.instruction_indices.empty())
            continue;
        const auto& last_inst = instructions[block.instruction_indices.back()];
        const auto info = opcode_info(last_inst.opcode);

        auto add_succ = [&](std::uint64_t target) {
            auto it = cfg.offset_to_block.find(target);
            if (it != cfg.offset_to_block.end()) {
                block.successor_ids.push_back(cfg.blocks[it->second].id);
            }
        };

        if (info.flags & flag_branch) {
            if (last_inst.branch_offset.has_value()) {
                std::int64_t target = static_cast<std::int64_t>(last_inst.offset) + *last_inst.branch_offset;
                if (target >= 0)
                    add_succ(static_cast<std::uint64_t>(target));
            }
            bool has_fallthrough = !(info.flags & flag_terminator) ||
                last_inst.opcode == 0x99 || last_inst.opcode == 0x9A ||
                last_inst.opcode == 0x9B || last_inst.opcode == 0x9C ||
                last_inst.opcode == 0x9D || last_inst.opcode == 0x9E ||
                last_inst.opcode == 0x9F || last_inst.opcode == 0xA0 ||
                last_inst.opcode == 0xA1 || last_inst.opcode == 0xA2 ||
                last_inst.opcode == 0xA3 || last_inst.opcode == 0xA4 ||
                last_inst.opcode == 0xA5 || last_inst.opcode == 0xA6 ||
                last_inst.opcode == 0xC6 || last_inst.opcode == 0xC7;
            if (has_fallthrough) {
                std::uint64_t fallthrough = last_inst.offset + last_inst.length;
                if (fallthrough < block.end_offset + 1)
                    add_succ(fallthrough);
            }
        } else if (info.flags & flag_switch) {
            if (last_inst.switch_default.has_value()) {
                std::int64_t target = static_cast<std::int64_t>(last_inst.offset) + *last_inst.switch_default;
                if (target >= 0)
                    add_succ(static_cast<std::uint64_t>(target));
            }
            for (auto off : last_inst.switch_offsets) {
                std::int64_t target = static_cast<std::int64_t>(last_inst.offset) + off;
                if (target >= 0)
                    add_succ(static_cast<std::uint64_t>(target));
            }
        } else if (!(info.flags & flag_terminator) && !(info.flags & flag_throw)) {
            std::uint64_t fallthrough = last_inst.offset + last_inst.length;
            add_succ(fallthrough);
        }
    }

    for (const auto& exc : exceptions) {
        auto handler_it = cfg.offset_to_block.find(exc.handler_pc);
        if (handler_it == cfg.offset_to_block.end())
            continue;
        auto& handler_block = cfg.blocks[handler_it->second];
        handler_block.is_exception_handler = true;

        for (auto& block : cfg.blocks) {
            if (block.instruction_indices.empty())
                continue;
            const auto& first_inst = instructions[block.instruction_indices.front()];
            const auto& last_inst_idx = block.instruction_indices.back();
            const auto& last_inst = instructions[last_inst_idx];
            std::uint64_t block_start = first_inst.offset;
            std::uint64_t block_end = last_inst.offset + last_inst.length;

            if (block_start < exc.end_pc && block_end > exc.start_pc) {
                block.exception_successor_ids.push_back(handler_block.id);
                handler_block.exception_predecessor_ids.push_back(block.id);
            }
        }
    }

    for (auto& block : cfg.blocks) {
        std::sort(block.successor_ids.begin(), block.successor_ids.end());
        auto last = std::unique(block.successor_ids.begin(), block.successor_ids.end());
        block.successor_ids.erase(last, block.successor_ids.end());
        std::sort(block.exception_successor_ids.begin(), block.exception_successor_ids.end());
        last = std::unique(block.exception_successor_ids.begin(), block.exception_successor_ids.end());
        block.exception_successor_ids.erase(last, block.exception_successor_ids.end());
    }

    for (auto& block : cfg.blocks) {
        for (auto succ_id : block.successor_ids) {
            for (auto& succ : cfg.blocks) {
                if (succ.id == succ_id) {
                    succ.predecessor_ids.push_back(block.id);
                    break;
                }
            }
        }
    }

    for (auto& block : cfg.blocks) {
        std::sort(block.predecessor_ids.begin(), block.predecessor_ids.end());
        auto last = std::unique(block.predecessor_ids.begin(), block.predecessor_ids.end());
        block.predecessor_ids.erase(last, block.predecessor_ids.end());
    }

    cfg.entry_block_id = cfg.blocks.empty() ? 0 : cfg.blocks.front().id;
    return cfg;
}

struct slot_t {
    std::uint64_t value_id = 0;
    bool cat2_top = false;
};

struct frame_t {
    std::vector<slot_t> stack;
    std::vector<slot_t> locals;
};

struct ssa_value_t {
    std::uint64_t id = 0;
    provider_ir_opcode_t ir_opcode = provider_ir_opcode_t::unknown;
    hir_node_kind_t hir_kind = hir_node_kind_t::unknown;
    std::uint64_t type_id = 0;
    std::vector<std::uint64_t> operand_ids;
    std::string stable_immediate;
    std::string stable_symbol;
    std::uint64_t bytecode_offset = 0;
    std::uint32_t instruction_length = 1;
    std::uint8_t confidence = 100;
    decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::provider_semantics;
    bool is_phi = false;
    bool is_category_2 = false;
    bool supported = true;
    std::uint64_t block_id = 0;
    std::optional<std::uint16_t> local_index;
    std::string local_name;
};

struct block_state_t {
    frame_t entry_frame;
    frame_t exit_frame;
    std::vector<ssa_value_t> values;
    bool processed = false;
    bool reachable = false;
    std::vector<std::uint64_t> phi_for_local_slots;
    std::vector<std::uint64_t> phi_for_stack_slots;
};

class ssa_builder_t {
public:
    ssa_builder_t(const jvm_method_input_t& input,
                  const std::vector<instruction_t>& instructions,
                  const cfg_t& cfg,
                  type_registry_t& types,
                  std::vector<decompiler_diagnostic_t>& diagnostics)
        : input_(input)
        , instructions_(instructions)
        , cfg_(cfg)
        , types_(types)
        , diagnostics_(diagnostics)
    {
        states_.resize(cfg.blocks.size());
        for (std::size_t i = 0; i < cfg.blocks.size(); ++i) {
            states_[i].entry_frame.locals.resize(input_.context.max_locals);
        }
        setup_entry_block();
    }

    void run()
    {
        std::vector<std::size_t> worklist;
        for (std::size_t i = 0; i < cfg_.blocks.size(); ++i) {
            if (cfg_.blocks[i].id == cfg_.entry_block_id) {
                worklist.push_back(i);
                states_[i].reachable = true;
                break;
            }
        }

        std::size_t iterations = 0;
        const std::size_t max_iterations = cfg_.blocks.size() * 4 + 16;

        while (!worklist.empty() && iterations < max_iterations) {
            ++iterations;
            std::size_t bi = worklist.back();
            worklist.pop_back();

            auto& block = cfg_.blocks[bi];
            auto& state = states_[bi];

            if (!merge_predecessors(bi)) {
                continue;
            }

            frame_t saved_entry = state.entry_frame;
            simulate_block(bi);

            if (state.processed && frames_equal(saved_entry, state.entry_frame)) {
                continue;
            }

            state.processed = true;
            state.entry_frame = saved_entry;

            for (auto succ_id : block.successor_ids) {
                for (std::size_t j = 0; j < cfg_.blocks.size(); ++j) {
                    if (cfg_.blocks[j].id == succ_id) {
                        states_[j].reachable = true;
                        worklist.push_back(j);
                        break;
                    }
                }
            }

            for (auto exc_succ_id : block.exception_successor_ids) {
                for (std::size_t j = 0; j < cfg_.blocks.size(); ++j) {
                    if (cfg_.blocks[j].id == exc_succ_id) {
                        states_[j].reachable = true;
                        worklist.push_back(j);
                        break;
                    }
                }
            }
        }
    }

    const std::vector<block_state_t>& states() const noexcept { return states_; }
    const std::vector<ssa_value_t>& all_values() const noexcept { return all_values_; }
    std::uint64_t next_value_id() const noexcept { return next_value_id_; }

private:
    void setup_entry_block()
    {
        for (std::size_t i = 0; i < cfg_.blocks.size(); ++i) {
            if (cfg_.blocks[i].id == cfg_.entry_block_id) {
                auto& entry = states_[i].entry_frame;
                entry.locals.resize(input_.context.max_locals);

                bool is_static = (input_.context.access_flags & jvm_acc_static) != 0;
                std::uint16_t local_idx = 0;

                if (!is_static) {
                    ssa_value_t this_val;
                    this_val.id = next_value_id_++;
                    this_val.ir_opcode = provider_ir_opcode_t::parameter;
                    this_val.hir_kind = hir_node_kind_t::parameter;
                    this_val.type_id = types_.register_class(input_.context.class_internal_name);
                    this_val.bytecode_offset = 0;
                    this_val.provenance = decompiler_fact_provenance_t::loader_metadata;
                    this_val.block_id = cfg_.entry_block_id;
                    this_val.local_index = 0;
                    this_val.local_name = "this";
                    all_values_.push_back(this_val);
                    entry.locals[0] = {this_val.id, false};
                    local_idx = 1;
                }

                auto md = parse_method_descriptor(input_.context.method_descriptor);
                if (md.valid) {
                    for (const auto& param : md.parameters) {
                        std::uint64_t type_id = types_.register_type(param);
                        ssa_value_t param_val;
                        param_val.id = next_value_id_++;
                        param_val.ir_opcode = provider_ir_opcode_t::parameter;
                        param_val.hir_kind = hir_node_kind_t::parameter;
                        param_val.type_id = type_id;
                        param_val.bytecode_offset = 0;
                        param_val.provenance = decompiler_fact_provenance_t::loader_metadata;
                        param_val.block_id = cfg_.entry_block_id;
                        param_val.local_index = local_idx;
                        param_val.is_category_2 = param.is_category_2;

                        for (const auto& lv : input_.context.local_variables) {
                            if (lv.index == local_idx && lv.start_pc == 0) {
                                param_val.local_name = lv.name;
                                break;
                            }
                        }
                        if (param_val.local_name.empty())
                            param_val.local_name = "local_" + std::to_string(local_idx);

                        all_values_.push_back(param_val);
                        entry.locals[local_idx] = {param_val.id, false};
                        if (param.is_category_2 && local_idx + 1 < entry.locals.size()) {
                            entry.locals[local_idx + 1] = {param_val.id, true};
                            local_idx += 2;
                        } else {
                            local_idx += 1;
                        }
                    }
                }

                states_[i].entry_frame = entry;
                states_[i].reachable = true;
                break;
            }
        }
    }

    bool frames_equal(const frame_t& a, const frame_t& b) const
    {
        if (a.stack.size() != b.stack.size()) return false;
        if (a.locals.size() != b.locals.size()) return false;
        for (std::size_t i = 0; i < a.stack.size(); ++i)
            if (a.stack[i].value_id != b.stack[i].value_id) return false;
        for (std::size_t i = 0; i < a.locals.size(); ++i)
            if (a.locals[i].value_id != b.locals[i].value_id) return false;
        return true;
    }

    bool merge_predecessors(std::size_t bi)
    {
        auto& block = cfg_.blocks[bi];
        auto& state = states_[bi];

        if (block.predecessor_ids.empty() && block.id != cfg_.entry_block_id) {
            if (!block.is_exception_handler)
                state.reachable = false;
            return false;
        }

        if (block.id == cfg_.entry_block_id && block.predecessor_ids.empty()) {
            return true;
        }

        std::vector<frame_t> pred_frames;
        for (auto pred_id : block.predecessor_ids) {
            for (std::size_t j = 0; j < cfg_.blocks.size(); ++j) {
                if (cfg_.blocks[j].id == pred_id && states_[j].processed && states_[j].reachable) {
                    pred_frames.push_back(states_[j].exit_frame);
                    break;
                }
            }
        }

        if (block.is_exception_handler) {
            frame_t exc_frame;
            exc_frame.stack.resize(1);
            ssa_value_t exc_val;
            exc_val.id = next_value_id_++;
            exc_val.ir_opcode = provider_ir_opcode_t::constant;
            exc_val.hir_kind = hir_node_kind_t::reference;
            exc_val.type_id = types_.register_class("java/lang/Throwable");
            exc_val.bytecode_offset = block.start_offset;
            exc_val.provenance = decompiler_fact_provenance_t::bytecode_verifier;
            exc_val.block_id = block.id;
            exc_val.stable_symbol = "exception";
            all_values_.push_back(exc_val);
            exc_frame.stack[0] = {exc_val.id, false};

            if (!pred_frames.empty()) {
                exc_frame.locals = pred_frames[0].locals;
                for (std::size_t i = 1; i < pred_frames.size(); ++i) {
                    if (pred_frames[i].locals.size() > exc_frame.locals.size())
                        exc_frame.locals.resize(pred_frames[i].locals.size());
                    for (std::size_t li = 0; li < exc_frame.locals.size() && li < pred_frames[i].locals.size(); ++li) {
                        if (exc_frame.locals[li].value_id != pred_frames[i].locals[li].value_id) {
                            exc_frame.locals[li] = create_phi(block.id, li, exc_frame.locals[li], pred_frames[i].locals[li]);
                        }
                    }
                }
            } else {
                exc_frame.locals.resize(input_.context.max_locals);
            }

            state.entry_frame = exc_frame;
            return true;
        }

        if (pred_frames.empty())
            return false;

        frame_t merged = pred_frames[0];
        for (std::size_t i = 1; i < pred_frames.size(); ++i) {
            if (pred_frames[i].stack.size() != merged.stack.size()) {
                diagnostics_.push_back(make_diagnostic(
                    decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::malformed_provider_ir,
                    "jvm_ssa.ssa.stack_depth_mismatch." + std::to_string(block.start_offset),
                    static_cast<std::uint32_t>(diagnostics_.size() + 1)));
                continue;
            }
            for (std::size_t si = 0; si < merged.stack.size(); ++si) {
                if (merged.stack[si].value_id != pred_frames[i].stack[si].value_id) {
                    merged.stack[si] = create_phi(block.id, si | 0x80000000ULL,
                                                     merged.stack[si], pred_frames[i].stack[si]);
                }
            }
            if (pred_frames[i].locals.size() > merged.locals.size())
                merged.locals.resize(pred_frames[i].locals.size());
            for (std::size_t li = 0; li < merged.locals.size() && li < pred_frames[i].locals.size(); ++li) {
                if (merged.locals[li].value_id != pred_frames[i].locals[li].value_id) {
                    merged.locals[li] = create_phi(block.id, li, merged.locals[li], pred_frames[i].locals[li]);
                }
            }
        }

        state.entry_frame = merged;
        return true;
    }

    slot_t create_phi(std::uint64_t block_id, std::uint64_t slot_key,
                       const slot_t& a, const slot_t& b)
    {
        ssa_value_t phi;
        phi.id = next_value_id_++;
        phi.ir_opcode = provider_ir_opcode_t::phi;
        phi.hir_kind = hir_node_kind_t::phi;
        phi.is_phi = true;
        phi.bytecode_offset = 0;
        phi.block_id = block_id;
        phi.provenance = decompiler_fact_provenance_t::provider_semantics;
        phi.operand_ids.push_back(a.value_id);
        phi.operand_ids.push_back(b.value_id);
        phi.confidence = 90;
        phi.type_id = find_type_for_value(a.value_id);
        all_values_.push_back(phi);
        slot_t result;
        result.value_id = phi.id;
        result.cat2_top = a.cat2_top;
        return result;
    }

    std::uint64_t find_type_for_value(std::uint64_t value_id) const
    {
        for (const auto& v : all_values_) {
            if (v.id == value_id)
                return v.type_id;
        }
        return 0;
    }

    void simulate_block(std::size_t bi)
    {
        auto& block = cfg_.blocks[bi];
        auto& state = states_[bi];

        frame_t frame = state.entry_frame;
        state.values.clear();

        for (auto inst_idx : block.instruction_indices) {
            const auto& inst = instructions_[inst_idx];
            simulate_instruction(bi, inst, frame, state.values);
        }

        state.exit_frame = frame;
    }

    void simulate_instruction(std::size_t bi, const instruction_t& inst,
                               frame_t& frame, std::vector<ssa_value_t>& values)
    {
        auto& block = cfg_.blocks[bi];
        auto info = opcode_info(inst.opcode);
        fill_unused(info, inst.opcode);

        if (inst.is_reserved) {
            ssa_value_t val;
            val.id = next_value_id_++;
            val.ir_opcode = provider_ir_opcode_t::unknown;
            val.hir_kind = hir_node_kind_t::unknown;
            val.bytecode_offset = inst.offset;
            val.instruction_length = inst.length;
            val.block_id = block.id;
            val.supported = false;
            val.stable_symbol = inst.mnemonic;
            all_values_.push_back(val);
            values.push_back(val);

            decompiler_unknown_t unknown;
            unknown.reason = decompiler_unknown_reason_t::unsupported_instruction;
            unknown.stable_token = "jvm.opcode." + std::to_string(inst.opcode) + "." + inst.mnemonic;
            unknown.coordinate = make_coordinate(input_, decompiler_coordinate_layer_t::provider_ir, inst.offset, inst.length);
            unknown.confidence = 0;
            unknown.provenance = decompiler_fact_provenance_t::provider_semantics;
            unknowns_.push_back(unknown);
            return;
        }

        const auto flags = info.flags;

        if (flags & flag_store_local) {
            std::uint16_t idx = get_local_index(inst);
            std::uint8_t pop_count = (flags & flag_cat2_result) ? 2 : 1;

            if (inst.opcode == 0x84) {
                if (idx >= frame.locals.size()) {
                    add_verifier_warning(inst, "iinc_local_out_of_range");
                    return;
                }
                ssa_value_t const_val;
                const_val.id = next_value_id_++;
                const_val.ir_opcode = provider_ir_opcode_t::constant;
                const_val.hir_kind = hir_node_kind_t::literal;
                const_val.bytecode_offset = inst.offset;
                const_val.instruction_length = inst.length;
                const_val.block_id = block.id;
                const_val.stable_immediate = inst.iinc_const.has_value() ?
                    std::to_string(*inst.iinc_const) : std::to_string(*inst.wide_iinc_const);
                const_val.type_id = types_.id_for_descriptor("I");
                all_values_.push_back(const_val);
                values.push_back(const_val);

                ssa_value_t add_val;
                add_val.id = next_value_id_++;
                add_val.ir_opcode = provider_ir_opcode_t::binary;
                add_val.hir_kind = hir_node_kind_t::binary;
                add_val.bytecode_offset = inst.offset;
                add_val.instruction_length = inst.length;
                add_val.block_id = block.id;
                add_val.operand_ids.push_back(frame.locals[idx].value_id);
                add_val.operand_ids.push_back(const_val.id);
                add_val.type_id = types_.id_for_descriptor("I");
                add_val.stable_symbol = "iadd";
                add_val.local_index = idx;
                all_values_.push_back(add_val);
                values.push_back(add_val);

                if (idx < frame.locals.size())
                    frame.locals[idx] = {add_val.id, false};
                return;
            }

            if (frame.stack.size() < pop_count) {
                add_verifier_warning(inst, "store_stack_underflow");
                return;
            }
            std::vector<slot_t> popped;
            for (std::uint8_t i = 0; i < pop_count; ++i) {
                popped.push_back(frame.stack.back());
                frame.stack.pop_back();
            }
            ssa_value_t val;
            val.id = next_value_id_++;
            val.ir_opcode = info.ir_opcode;
            val.hir_kind = info.hir_kind;
            val.bytecode_offset = inst.offset;
            val.instruction_length = inst.length;
            val.block_id = block.id;
            val.operand_ids.push_back(popped.front().value_id);
            val.is_category_2 = pop_count == 2;
            val.type_id = infer_local_type(idx, val.is_category_2);
            val.local_index = idx;
            val.local_name = lookup_local_name(idx);
            val.stable_immediate = inst.mnemonic;
            all_values_.push_back(val);
            values.push_back(val);
            if (idx < frame.locals.size()) {
                frame.locals[idx] = {val.id, false};
                if (val.is_category_2 && idx + 1 < frame.locals.size())
                    frame.locals[idx + 1] = {val.id, true};
            }
            return;
        }

        if (flags & flag_load_local) {
            std::uint16_t idx = get_local_index(inst);
            if (idx >= frame.locals.size()) {
                add_verifier_warning(inst, "local_index_out_of_range");
                return;
            }
            ssa_value_t val;
            val.id = next_value_id_++;
            val.ir_opcode = info.ir_opcode;
            val.hir_kind = info.hir_kind;
            val.bytecode_offset = inst.offset;
            val.instruction_length = inst.length;
            val.block_id = block.id;
            val.operand_ids.push_back(frame.locals[idx].value_id);
            val.is_category_2 = (flags & flag_cat2_result) != 0;
            val.type_id = infer_local_type(idx, val.is_category_2);
            val.local_index = idx;
            val.local_name = lookup_local_name(idx);
            val.stable_immediate = inst.mnemonic;
            all_values_.push_back(val);
            values.push_back(val);
            frame.stack.push_back({val.id, false});
            if (val.is_category_2)
                frame.stack.push_back({val.id, true});
            return;
        }

        if (flags & flag_dynamic_stack) {
            simulate_dynamic(bi, inst, frame, values, info);
            return;
        }

        switch (inst.opcode) {
        case 0x57:
            if (!frame.stack.empty()) frame.stack.pop_back();
            return;
        case 0x58:
            if (frame.stack.size() >= 2) { frame.stack.pop_back(); frame.stack.pop_back(); }
            return;
        case 0x59:
            if (!frame.stack.empty()) frame.stack.push_back(frame.stack.back());
            return;
        case 0x5A:
            if (frame.stack.size() >= 2) {
                auto v1 = frame.stack.back(); frame.stack.pop_back();
                auto v2 = frame.stack.back(); frame.stack.pop_back();
                frame.stack.push_back(v1);
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
            }
            return;
        case 0x5B:
            if (frame.stack.size() >= 3) {
                auto v1 = frame.stack.back(); frame.stack.pop_back();
                auto v2 = frame.stack.back(); frame.stack.pop_back();
                auto v3 = frame.stack.back(); frame.stack.pop_back();
                frame.stack.push_back(v1);
                frame.stack.push_back(v3);
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
            }
            return;
        case 0x5C:
            if (frame.stack.size() >= 2) {
                auto v1 = frame.stack.back(); frame.stack.pop_back();
                auto v2 = frame.stack.back(); frame.stack.pop_back();
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
            }
            return;
        case 0x5D:
            if (frame.stack.size() >= 3) {
                auto v1 = frame.stack.back(); frame.stack.pop_back();
                auto v2 = frame.stack.back(); frame.stack.pop_back();
                auto v3 = frame.stack.back(); frame.stack.pop_back();
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
                frame.stack.push_back(v3);
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
            }
            return;
        case 0x5E:
            if (frame.stack.size() >= 4) {
                auto v1 = frame.stack.back(); frame.stack.pop_back();
                auto v2 = frame.stack.back(); frame.stack.pop_back();
                auto v3 = frame.stack.back(); frame.stack.pop_back();
                auto v4 = frame.stack.back(); frame.stack.pop_back();
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
                frame.stack.push_back(v4);
                frame.stack.push_back(v3);
                frame.stack.push_back(v2);
                frame.stack.push_back(v1);
            }
            return;
        case 0x5F:
            if (frame.stack.size() >= 2) {
                auto v1 = frame.stack.back(); frame.stack.pop_back();
                auto v2 = frame.stack.back(); frame.stack.pop_back();
                frame.stack.push_back(v1);
                frame.stack.push_back(v2);
            }
            return;
        }

        std::int8_t pop_slots = info.pop_slots;
        std::int8_t push_slots = info.push_slots;
        bool cat2_result = (flags & flag_cat2_result) != 0;

        std::vector<std::uint64_t> operand_ids;
        if (pop_slots > 0) {
            if (frame.stack.size() < static_cast<std::size_t>(pop_slots)) {
                add_verifier_warning(inst, "stack_underflow");
                return;
            }
            for (std::int8_t i = 0; i < pop_slots; ++i) {
                operand_ids.push_back(frame.stack.back().value_id);
                frame.stack.pop_back();
            }
        }

        ssa_value_t val;
        val.id = next_value_id_++;
        val.ir_opcode = info.ir_opcode;
        val.hir_kind = info.hir_kind;
        val.bytecode_offset = inst.offset;
        val.instruction_length = inst.length;
        val.block_id = block.id;
        val.operand_ids = std::move(operand_ids);
        val.is_category_2 = cat2_result;
        val.stable_immediate = inst.mnemonic;
        val.stable_symbol = inst.mnemonic;
        val.type_id = infer_result_type(inst, info);

        if (flags & (flag_branch | flag_switch | flag_return | flag_throw | flag_monitor)) {
            val.confidence = 100;
            val.provenance = decompiler_fact_provenance_t::provider_semantics;
        }

        all_values_.push_back(val);
        values.push_back(val);

        if (push_slots > 0) {
            frame.stack.push_back({val.id, false});
            if (cat2_result)
                frame.stack.push_back({val.id, true});
        }

        if (flags & flag_jsr) {
            block.is_jsr_target = true;
        }
    }

    void simulate_dynamic(std::size_t bi, const instruction_t& inst,
                           frame_t& frame, std::vector<ssa_value_t>& values,
                           const opcode_info_t& info)
    {
        auto& block = cfg_.blocks[bi];

        switch (inst.opcode) {
        case 0x12: case 0x13: case 0x14: {
            std::uint16_t cp_idx = inst.cp_index.value_or(0);
            const auto& cp = input_.context.constant_pool;
            type_descriptor_t td;
            if (cp_idx > 0 && cp_idx < cp.size()) {
                const auto& entry = cp[cp_idx];
                switch (entry.tag) {
                case jvm_constant_tag_t::integer:
                    td.descriptor = "I";
                    break;
                case jvm_constant_tag_t::float_:
                    td.descriptor = "F";
                    break;
                case jvm_constant_tag_t::long_:
                    td.descriptor = "J";
                    td.is_category_2 = true;
                    break;
                case jvm_constant_tag_t::double_:
                    td.descriptor = "D";
                    td.is_category_2 = true;
                    break;
                case jvm_constant_tag_t::string_ref:
                    td.descriptor = "Ljava/lang/String;";
                    td.is_reference = true;
                    td.class_name = "java/lang/String";
                    break;
                case jvm_constant_tag_t::class_ref:
                    td.descriptor = "Ljava/lang/Class;";
                    td.is_reference = true;
                    td.class_name = "java/lang/Class";
                    break;
                case jvm_constant_tag_t::method_type:
                    td.descriptor = "Ljava/lang/invoke/MethodType;";
                    td.is_reference = true;
                    td.class_name = "java/lang/invoke/MethodType";
                    break;
                case jvm_constant_tag_t::method_handle:
                    td.descriptor = "Ljava/lang/invoke/MethodHandle;";
                    td.is_reference = true;
                    td.class_name = "java/lang/invoke/MethodHandle";
                    break;
                default:
                    break;
                }
            }
            std::uint64_t type_id = types_.register_type(td);
            ssa_value_t val;
            val.id = next_value_id_++;
            val.ir_opcode = provider_ir_opcode_t::constant;
            val.hir_kind = hir_node_kind_t::literal;
            val.bytecode_offset = inst.offset;
            val.instruction_length = inst.length;
            val.block_id = block.id;
            val.type_id = type_id;
            val.is_category_2 = td.is_category_2;
            val.stable_immediate = "cp#" + std::to_string(cp_idx);
            val.stable_symbol = cp_utf8(cp, cp_idx);
            all_values_.push_back(val);
            values.push_back(val);
            frame.stack.push_back({val.id, false});
            if (td.is_category_2)
                frame.stack.push_back({val.id, true});
            return;
        }
        case 0xB2: case 0xB3: case 0xB4: case 0xB5: {
            auto ref = cp_ref(input_.context.constant_pool, inst.cp_index.value_or(0));
            auto td = parse_single_type(ref.descriptor);
            std::uint64_t type_id = types_.register_type(td);

            if (inst.opcode == 0xB4 || inst.opcode == 0xB2) {
                std::uint8_t pop_count = 0;
                if (inst.opcode == 0xB4) pop_count = 1;
                std::vector<std::uint64_t> ops;
                for (std::uint8_t i = 0; i < pop_count; ++i) {
                    if (frame.stack.empty()) { add_verifier_warning(inst, "getfield_underflow"); return; }
                    ops.push_back(frame.stack.back().value_id);
                    frame.stack.pop_back();
                }
                ssa_value_t val;
                val.id = next_value_id_++;
                val.ir_opcode = provider_ir_opcode_t::field_load;
                val.hir_kind = hir_node_kind_t::field;
                val.bytecode_offset = inst.offset;
                val.instruction_length = inst.length;
                val.block_id = block.id;
                val.operand_ids = std::move(ops);
                val.type_id = type_id;
                val.is_category_2 = td.is_category_2;
                val.stable_symbol = ref.class_name + "." + ref.name;
                val.stable_immediate = ref.descriptor;
                all_values_.push_back(val);
                values.push_back(val);
                frame.stack.push_back({val.id, false});
                if (td.is_category_2)
                    frame.stack.push_back({val.id, true});
            } else {
                std::uint8_t pop_count = type_descriptor_slots(td);
                if (inst.opcode == 0xB5) pop_count += 1;
                std::vector<std::uint64_t> ops;
                for (std::uint8_t i = 0; i < pop_count; ++i) {
                    if (frame.stack.empty()) { add_verifier_warning(inst, "putfield_underflow"); return; }
                    ops.push_back(frame.stack.back().value_id);
                    frame.stack.pop_back();
                }
                ssa_value_t val;
                val.id = next_value_id_++;
                val.ir_opcode = provider_ir_opcode_t::field_store;
                val.hir_kind = hir_node_kind_t::field;
                val.bytecode_offset = inst.offset;
                val.instruction_length = inst.length;
                val.block_id = block.id;
                val.operand_ids = std::move(ops);
                val.type_id = type_id;
                val.stable_symbol = ref.class_name + "." + ref.name;
                val.stable_immediate = ref.descriptor;
                all_values_.push_back(val);
                values.push_back(val);
            }
            return;
        }
        case 0xB6: case 0xB7: case 0xB8: case 0xB9: case 0xBA: {
            auto ref = cp_ref(input_.context.constant_pool, inst.cp_index.value_or(0));
            auto md = parse_method_descriptor(ref.descriptor);
            std::uint64_t return_type_id = 0;
            bool return_cat2 = false;
            if (md.valid) {
                return_type_id = types_.register_type(md.return_type);
                return_cat2 = md.return_type.is_category_2;
            }

            std::uint16_t arg_slots = 0;
            if (md.valid) {
                for (const auto& p : md.parameters)
                    arg_slots += type_descriptor_slots(p);
            }
            bool has_this = (inst.opcode != 0xB8 && inst.opcode != 0xBA);
            if (has_this) arg_slots += 1;

            std::vector<std::uint64_t> ops;
            for (std::uint16_t i = 0; i < arg_slots; ++i) {
                if (frame.stack.empty()) { add_verifier_warning(inst, "invoke_underflow"); return; }
                ops.push_back(frame.stack.back().value_id);
                frame.stack.pop_back();
            }
            std::reverse(ops.begin(), ops.end());

            ssa_value_t val;
            val.id = next_value_id_++;
            val.ir_opcode = provider_ir_opcode_t::call;
            val.hir_kind = hir_node_kind_t::call;
            val.bytecode_offset = inst.offset;
            val.instruction_length = inst.length;
            val.block_id = block.id;
            val.operand_ids = std::move(ops);
            val.type_id = return_type_id;
            val.is_category_2 = return_cat2;
            val.stable_symbol = ref.class_name + "." + ref.name;
            val.stable_immediate = ref.descriptor;
            if (inst.opcode == 0xBA) {
                val.stable_immediate += " bootstrap=" + std::to_string(ref.bootstrap_index);
            }
            all_values_.push_back(val);
            values.push_back(val);

            if (md.valid && !md.return_type.is_void) {
                frame.stack.push_back({val.id, false});
                if (return_cat2)
                    frame.stack.push_back({val.id, true});
            }
            return;
        }
        case 0xC5: {
            auto ref = cp_ref(input_.context.constant_pool, inst.cp_index.value_or(0));
            std::uint8_t dims = inst.dimensions.value_or(1);
            std::vector<std::uint64_t> ops;
            for (std::uint8_t i = 0; i < dims; ++i) {
                if (frame.stack.empty()) { add_verifier_warning(inst, "multianewarray_underflow"); return; }
                ops.push_back(frame.stack.back().value_id);
                frame.stack.pop_back();
            }
            std::reverse(ops.begin(), ops.end());
            std::uint64_t type_id = types_.register_class(ref.class_name);
            ssa_value_t val;
            val.id = next_value_id_++;
            val.ir_opcode = provider_ir_opcode_t::constant;
            val.hir_kind = hir_node_kind_t::reference;
            val.bytecode_offset = inst.offset;
            val.instruction_length = inst.length;
            val.block_id = block.id;
            val.operand_ids = std::move(ops);
            val.type_id = type_id;
            val.stable_symbol = "multianewarray " + ref.class_name;
            val.stable_immediate = "dims=" + std::to_string(dims);
            all_values_.push_back(val);
            values.push_back(val);
            frame.stack.push_back({val.id, false});
            return;
        }
        }
    }

    std::uint16_t get_local_index(const instruction_t& inst) const
    {
        if (inst.is_wide && inst.wide_local_index.has_value())
            return static_cast<std::uint16_t>(*inst.wide_local_index);
        if (inst.local_index.has_value())
            return *inst.local_index;
        if (inst.opcode >= 0x1A && inst.opcode <= 0x1D)
            return static_cast<std::uint16_t>(inst.opcode - 0x1A);
        if (inst.opcode >= 0x1E && inst.opcode <= 0x21)
            return static_cast<std::uint16_t>(inst.opcode - 0x1E);
        if (inst.opcode >= 0x22 && inst.opcode <= 0x25)
            return static_cast<std::uint16_t>(inst.opcode - 0x22);
        if (inst.opcode >= 0x26 && inst.opcode <= 0x29)
            return static_cast<std::uint16_t>(inst.opcode - 0x26);
        if (inst.opcode >= 0x2A && inst.opcode <= 0x2D)
            return static_cast<std::uint16_t>(inst.opcode - 0x2A);
        if (inst.opcode >= 0x3B && inst.opcode <= 0x3E)
            return static_cast<std::uint16_t>(inst.opcode - 0x3B);
        if (inst.opcode >= 0x3F && inst.opcode <= 0x42)
            return static_cast<std::uint16_t>(inst.opcode - 0x3F);
        if (inst.opcode >= 0x43 && inst.opcode <= 0x46)
            return static_cast<std::uint16_t>(inst.opcode - 0x43);
        if (inst.opcode >= 0x47 && inst.opcode <= 0x4A)
            return static_cast<std::uint16_t>(inst.opcode - 0x47);
        if (inst.opcode >= 0x4B && inst.opcode <= 0x4E)
            return static_cast<std::uint16_t>(inst.opcode - 0x4B);
        return 0;
    }

    std::string lookup_local_name(std::uint16_t idx) const
    {
        for (const auto& lv : input_.context.local_variables) {
            if (lv.index == idx)
                return lv.name;
        }
        return {};
    }

    std::uint64_t infer_local_type(std::uint16_t idx, bool is_cat2) const
    {
        for (const auto& lv : input_.context.local_variables) {
            if (lv.index == idx && !lv.descriptor.empty()) {
                auto td = parse_single_type(lv.descriptor);
                return const_cast<type_registry_t&>(types_).register_type(td);
            }
        }
        if (is_cat2)
            return types_.id_for_descriptor("J");
        return types_.id_for_descriptor("I");
    }

    std::uint64_t infer_result_type(const instruction_t& inst, const opcode_info_t& info) const
    {
        switch (inst.opcode) {
        case 0x01: return types_.register_null_type();
        case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07: case 0x08:
        case 0x10: case 0x11:
            return types_.id_for_descriptor("I");
        case 0x09: case 0x0A:
            return types_.id_for_descriptor("J");
        case 0x0B: case 0x0C: case 0x0D:
            return types_.id_for_descriptor("F");
        case 0x0E: case 0x0F:
            return types_.id_for_descriptor("D");
        case 0x60: case 0x64: case 0x68: case 0x6C: case 0x70:
        case 0x74: case 0x78: case 0x7C: case 0x7E: case 0x80: case 0x82:
            return types_.id_for_descriptor("I");
        case 0x61: case 0x65: case 0x69: case 0x6D: case 0x71:
        case 0x75: case 0x79: case 0x7D: case 0x7F: case 0x81: case 0x83:
            return types_.id_for_descriptor("J");
        case 0x62: case 0x66: case 0x6A: case 0x6E: case 0x72:
        case 0x76: case 0x7A:
            return types_.id_for_descriptor("F");
        case 0x63: case 0x67: case 0x6B: case 0x6F: case 0x73:
        case 0x77: case 0x7B:
            return types_.id_for_descriptor("D");
        case 0x91: case 0x92: case 0x93:
            return types_.id_for_descriptor("I");
        case 0x85: return types_.id_for_descriptor("J");
        case 0x86: return types_.id_for_descriptor("F");
        case 0x87: return types_.id_for_descriptor("D");
        case 0x88: return types_.id_for_descriptor("I");
        case 0x89: return types_.id_for_descriptor("F");
        case 0x8A: return types_.id_for_descriptor("D");
        case 0x8B: return types_.id_for_descriptor("I");
        case 0x8C: return types_.id_for_descriptor("J");
        case 0x8D: return types_.id_for_descriptor("D");
        case 0x8E: return types_.id_for_descriptor("I");
        case 0x8F: return types_.id_for_descriptor("J");
        case 0x90: return types_.id_for_descriptor("F");
        case 0x94: case 0x95: case 0x96: case 0x97: case 0x98:
            return types_.id_for_descriptor("I");
        case 0xBE: return types_.id_for_descriptor("I");
        case 0xC1: return types_.id_for_descriptor("I");
        case 0xC0: {
            auto ref = cp_class_name(input_.context.constant_pool, inst.cp_index.value_or(0));
            if (!ref.empty())
                return const_cast<type_registry_t&>(types_).register_class(ref);
            return types_.register_class("java/lang/Object");
        }
        case 0xBB: {
            auto ref = cp_class_name(input_.context.constant_pool, inst.cp_index.value_or(0));
            if (!ref.empty())
                return const_cast<type_registry_t&>(types_).register_class(ref);
            return types_.register_class("java/lang/Object");
        }
        case 0xBC: {
            static constexpr const char* atype_descs[] = {
                nullptr, nullptr, nullptr, nullptr,
                "Z", "C", "F", "D", "B", "S", "I", "J"
            };
            const auto at = inst.array_type.value_or(10);
            const char* elem = (at >= 4 && at <= 11) ? atype_descs[at] : "I";
            std::string desc = std::string("[") + elem;
            return types_.id_for_descriptor(desc);
        }
        case 0xBD: {
            auto ref = cp_class_name(input_.context.constant_pool, inst.cp_index.value_or(0));
            if (!ref.empty())
                return const_cast<type_registry_t&>(types_).register_class(ref);
            return types_.register_class("java/lang/Object");
        }
        case 0xAC: return types_.id_for_descriptor("I");
        case 0xAD: return types_.id_for_descriptor("J");
        case 0xAE: return types_.id_for_descriptor("F");
        case 0xAF: return types_.id_for_descriptor("D");
        case 0xB0: return types_.register_class("java/lang/Object");
        case 0xB1: return types_.id_for_descriptor("V");
        case 0xA8: case 0xC9: return types_.register_return_address();
        default:
            if (info.flags & flag_cat2_result)
                return types_.id_for_descriptor("J");
            return types_.id_for_descriptor("I");
        }
    }

    void add_verifier_warning(const instruction_t& inst, const std::string& issue)
    {
        decompiler_unknown_t unknown;
        unknown.reason = decompiler_unknown_reason_t::malformed_input;
        unknown.stable_token = "jvm_ssa.verifier." + issue + "." + std::to_string(inst.offset);
        unknown.coordinate = make_coordinate(input_, decompiler_coordinate_layer_t::provider_ir, inst.offset, inst.length);
        unknown.confidence = 0;
        unknown.provenance = decompiler_fact_provenance_t::bytecode_verifier;
        unknowns_.push_back(unknown);

        diagnostics_.push_back(make_diagnostic(
            decompiler_diagnostic_severity_t::warning,
            decompiler_diagnostic_code_t::malformed_provider_ir,
            "jvm_ssa.verifier." + issue + "." + std::to_string(inst.offset),
            static_cast<std::uint32_t>(diagnostics_.size() + 1)));
    }

    const jvm_method_input_t& input_;
    const std::vector<instruction_t>& instructions_;
    const cfg_t& cfg_;
    type_registry_t& types_;
    std::vector<decompiler_diagnostic_t>& diagnostics_;
    std::vector<block_state_t> states_;
    std::vector<ssa_value_t> all_values_;
    std::vector<decompiler_unknown_t> unknowns_;
    std::uint64_t next_value_id_ = 1;

    friend struct ssa_builder_access_t;
};

struct ssa_builder_access_t {
    static const std::vector<decompiler_unknown_t>& unknowns(const ssa_builder_t& b) { return b.unknowns_; }
};

struct artifact_reader_t {
    const std::string& bytes;
    std::size_t offset = 0;

    bool u32(std::uint32_t& value) {
        if (offset > bytes.size() || bytes.size() - offset < sizeof(value))
            return false;
        value = 0;
        for (std::size_t i = 0; i < sizeof(value); ++i)
            value |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset++])) << (i * 8U);
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

void append_u32(std::string& bytes, std::uint32_t value)
{
    for (std::size_t i = 0; i < sizeof(value); ++i)
        bytes.push_back(static_cast<char>(value >> (i * 8U)));
}

bool append_string(std::string& bytes, const std::string& value)
{
    if (value.size() > k_artifact_max_bytes || bytes.size() > k_artifact_max_bytes - sizeof(std::uint32_t) - value.size())
        return false;
    append_u32(bytes, static_cast<std::uint32_t>(value.size()));
    bytes.append(value);
    return true;
}

}

jvm_ssa_result_t decompile_method(const jvm_method_input_t& input)
{
    jvm_ssa_result_t result;
    std::uint32_t ordinal = 1;

    const auto fail = [&](decompiler_diagnostic_code_t code, const std::string& key) {
        result.diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_severity_t::error, code, key, ordinal++));
    };

    if (input.context.code.empty()) {
        fail(decompiler_diagnostic_code_t::malformed_provider_ir, "jvm_ssa.empty_code");
        return result;
    }

    if (!validate_decompiler_entity_key(input.entity).valid()) {
        fail(decompiler_diagnostic_code_t::invalid_contract, "jvm_ssa.entity_key");
        return result;
    }

    if (!std::holds_alternative<jvm_decompiler_entity_identity_t>(input.entity.identity)) {
        fail(decompiler_diagnostic_code_t::invalid_contract, "jvm_ssa.entity_kind");
        return result;
    }

    auto instructions = decode_all(input.context.code, result.diagnostics);
    if (instructions.empty()) {
        if (result.diagnostics.empty())
            fail(decompiler_diagnostic_code_t::malformed_provider_ir, "jvm_ssa.decode_empty");
        return result;
    }

    for (const auto& inst : instructions) {
        if (inst.is_reserved) {
            result.diagnostics.push_back(make_diagnostic(
                decompiler_diagnostic_severity_t::warning,
                decompiler_diagnostic_code_t::unsupported_entity,
                "jvm_ssa.reserved_opcode." + std::to_string(inst.offset),
                ordinal++));
        }
    }

    auto cfg = build_cfg(instructions, input.context.exceptions, result.diagnostics);
    if (cfg.blocks.empty()) {
        fail(decompiler_diagnostic_code_t::malformed_provider_ir, "jvm_ssa.cfg_empty");
        return result;
    }

    type_registry_t types(input);

    ssa_builder_t builder(input, instructions, cfg, types, result.diagnostics);
    builder.run();

    const auto& states = builder.states();
    const auto& all_values = builder.all_values();

    type_graph_t type_graph;
    type_graph.schema_version = k_type_graph_schema_version;
    type_graph.entity = input.entity;
    type_graph.revision = input.type_graph_revision;
    type_graph.nodes = types.nodes();
    type_graph.edges = types.edges();

    provider_ir_t provider_ir;
    provider_ir.schema_version = k_provider_ir_schema_version;
    provider_ir.provider = input.provider;
    provider_ir.language = input.language;
    provider_ir.entity = input.entity;
    provider_ir.entry_block_id = cfg.entry_block_id;

    hir_function_t hir;
    hir.schema_version = k_hir_schema_version;
    hir.entity = input.entity;
    hir.type_graph_revision = input.type_graph_revision;
    hir.return_type_id = types.return_type_id(input.context.method_descriptor);

    std::unordered_map<std::uint64_t, std::uint64_t> value_id_remap;
    std::uint64_t new_id = 1;
    for (const auto& v : all_values) {
        value_id_remap[v.id] = new_id++;
    }

    auto remap = [&](std::uint64_t id) -> std::uint64_t {
        auto it = value_id_remap.find(id);
        return it != value_id_remap.end() ? it->second : 0;
    };

    auto remap_vec = [&](const std::vector<std::uint64_t>& ids) -> std::vector<std::uint64_t> {
        std::vector<std::uint64_t> result;
        result.reserve(ids.size());
        for (auto id : ids)
            result.push_back(remap(id));
        return result;
    };

    for (const auto& v : all_values) {
        if (v.ir_opcode == provider_ir_opcode_t::parameter) {
            hir_variable_t var;
            var.id = remap(v.id);
            var.stable_name = v.local_name.empty() ? "param_" + std::to_string(*v.local_index) : v.local_name;
            var.type_id = v.type_id;
            var.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::hir, v.bytecode_offset, v.instruction_length);
            var.confidence = 100;
            var.provenance = v.provenance;
            hir.parameters.push_back(var);
        }
    }

    std::set<std::uint16_t> param_locals;
    for (const auto& v : all_values) {
        if (v.ir_opcode == provider_ir_opcode_t::parameter && v.local_index.has_value())
            param_locals.insert(*v.local_index);
    }

    for (const auto& v : all_values) {
        if (v.local_index.has_value() && v.ir_opcode != provider_ir_opcode_t::parameter) {
            auto idx = *v.local_index;
            if (param_locals.count(idx))
                continue;
            hir_variable_t var;
            var.id = remap(v.id);
            var.stable_name = v.local_name.empty() ? "local_" + std::to_string(idx) : v.local_name;
            var.type_id = v.type_id;
            var.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::hir, v.bytecode_offset, v.instruction_length);
            var.confidence = 90;
            var.provenance = v.provenance;
            bool exists = false;
            for (const auto& existing : hir.locals) {
                if (existing.stable_name == var.stable_name) {
                    exists = true;
                    break;
                }
            }
            if (!exists)
                hir.locals.push_back(var);
        }
    }

    for (std::size_t bi = 0; bi < cfg.blocks.size(); ++bi) {
        const auto& block = cfg.blocks[bi];
        const auto& state = states[bi];

        provider_ir_block_t pblock;
        pblock.id = block.id;
        pblock.predecessor_ids = block.predecessor_ids;
        pblock.successor_ids = block.successor_ids;
        pblock.exception_successor_ids = block.exception_successor_ids;
        pblock.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::provider_ir, block.start_offset);

        hir_block_t hblock;
        hblock.id = block.id;
        hblock.predecessor_ids = block.predecessor_ids;
        hblock.successor_ids = block.successor_ids;
        hblock.exception_successor_ids = block.exception_successor_ids;
        hblock.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::hir, block.start_offset);

        for (const auto& v : state.values) {
            provider_ir_value_t pv;
            pv.id = remap(v.id);
            pv.opcode = v.ir_opcode;
            pv.type_id = v.type_id;
            pv.operand_ids = remap_vec(v.operand_ids);
            pv.stable_immediate = v.stable_immediate;
            pv.stable_symbol = v.stable_symbol;
            pv.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::provider_ir, v.bytecode_offset, v.instruction_length);
            pv.confidence = v.confidence;
            pv.provenance = v.provenance;
            pblock.values.push_back(pv);

            hir_value_t hv;
            hv.id = pv.id;
            hv.kind = v.hir_kind;
            hv.type_id = pv.type_id;
            hv.operand_ids = pv.operand_ids;
            hv.stable_value = v.stable_symbol.empty() ? v.stable_immediate : v.stable_symbol;
            hv.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::hir, v.bytecode_offset, v.instruction_length);
            hv.confidence = pv.confidence;
            hv.provenance = pv.provenance;
            hblock.values.push_back(hv);

            if (!v.supported) {
                decompiler_unknown_t unknown;
                unknown.reason = decompiler_unknown_reason_t::unsupported_instruction;
                unknown.stable_token = "jvm.opcode." + std::to_string(instructions[block.instruction_indices.empty() ? 0 : block.instruction_indices.front()].opcode) + "." + std::to_string(v.bytecode_offset);
                unknown.coordinate = pv.coordinate;
                unknown.confidence = 0;
                unknown.provenance = decompiler_fact_provenance_t::provider_semantics;
                provider_ir.unknowns.push_back(unknown);
                decompiler_unknown_t hir_unknown = unknown;
                hir_unknown.coordinate.layer = decompiler_coordinate_layer_t::hir;
                hir.unknowns.push_back(hir_unknown);

                provider_ir.diagnostics.push_back(make_diagnostic(
                    decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_entity,
                    "jvm_ssa.unsupported_opcode." + std::to_string(v.bytecode_offset),
                    ordinal++));
                hir.diagnostics.push_back(make_diagnostic(
                    decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_entity,
                    "jvm_ssa.unsupported_opcode." + std::to_string(v.bytecode_offset),
                    ordinal++));
            }
        }

        for (const auto& v : all_values) {
            if (v.is_phi && v.block_id == block.id) {
                provider_ir_value_t pv;
                pv.id = remap(v.id);
                pv.opcode = provider_ir_opcode_t::phi;
                pv.type_id = v.type_id;
                pv.operand_ids = remap_vec(v.operand_ids);
                pv.stable_immediate = "phi";
                pv.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::provider_ir, block.start_offset);
                pv.confidence = v.confidence;
                pv.provenance = v.provenance;
                pblock.values.insert(pblock.values.begin(), pv);

                hir_value_t hv;
                hv.id = pv.id;
                hv.kind = hir_node_kind_t::phi;
                hv.type_id = pv.type_id;
                hv.operand_ids = pv.operand_ids;
                hv.stable_value = "phi";
                hv.coordinate = make_coordinate(input, decompiler_coordinate_layer_t::hir, block.start_offset);
                hv.confidence = pv.confidence;
                hv.provenance = pv.provenance;
                hblock.values.insert(hblock.values.begin(), hv);
            }
        }

        provider_ir.source_coordinates.push_back(pblock.coordinate);
        hir.source_coordinates.push_back(hblock.coordinate);
        provider_ir.blocks.push_back(std::move(pblock));
        hir.blocks.push_back(std::move(hblock));
    }

    hir.provider_ir_hash = stable_serialization_hash(provider_ir);

    const auto& builder_unknowns = ssa_builder_access_t::unknowns(builder);
    for (const auto& u : builder_unknowns) {
        provider_ir.unknowns.push_back(u);
        decompiler_unknown_t hir_unknown = u;
        hir_unknown.coordinate.layer = decompiler_coordinate_layer_t::hir;
        hir.unknowns.push_back(hir_unknown);
    }

    for (const auto& d : result.diagnostics) {
        provider_ir.diagnostics.push_back(d);
        hir.diagnostics.push_back(d);
    }
    auto preserved_diagnostics = result.diagnostics;

    const auto provider_validation = validate_provider_ir(provider_ir);
    const auto hir_validation = validate_hir_function(hir);
    const auto type_validation = validate_type_graph(type_graph);

    if (!provider_validation.valid() || !hir_validation.valid() || !type_validation.valid()) {
        for (const auto& d : provider_validation.diagnostics)
            result.diagnostics.push_back(d);
        for (const auto& d : hir_validation.diagnostics)
            result.diagnostics.push_back(d);
        for (const auto& d : type_validation.diagnostics)
            result.diagnostics.push_back(d);
        return result;
    }

    result.provider_ir = std::move(provider_ir);
    result.hir = std::move(hir);
    result.type_graph = std::move(type_graph);
    result.diagnostics = std::move(preserved_diagnostics);
    return result;
}

jvm_method_context_t extract_method_context(const classfile_image_t& classfile,
                                             std::uint32_t method_index)
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = classfile.this_class_name;
    ctx.constant_pool = classfile.constant_pool;
    ctx.bootstrap_methods = classfile.bootstrap_methods;

    if (method_index >= classfile.methods.size())
        return ctx;

    const auto& method = classfile.methods[method_index];
    ctx.method_name = method.name;
    ctx.method_descriptor = method.descriptor;
    ctx.access_flags = method.access_flags;

    if (method.code) {
        const auto& code = *method.code;
        ctx.max_stack = code.max_stack;
        ctx.max_locals = code.max_locals;
        ctx.code = code.code;
        ctx.exceptions = code.exceptions;
        ctx.line_numbers = code.line_numbers;
        ctx.local_variables = code.local_variables;
        ctx.code_offset = static_cast<std::uint32_t>(code.code_offset);
    }

    return ctx;
}

std::string serialize_jvm_ssa_result(const jvm_ssa_result_t& result)
{
    if (!result.succeeded())
        return {};
    try {
        std::string bytes;
        bytes.reserve(256);
        append_u32(bytes, k_artifact_magic);
        append_u32(bytes, k_artifact_version);
        if (!append_string(bytes, serialize_provider_ir(*result.provider_ir)) ||
            !append_string(bytes, serialize_hir_function(*result.hir)) ||
            !append_string(bytes, serialize_type_graph(*result.type_graph)))
            return {};
        return bytes;
    } catch (const std::exception&) {
        return {};
    }
}

std::optional<jvm_ssa_result_t> deserialize_jvm_ssa_result(const std::string& bytes,
                                                            std::vector<decompiler_diagnostic_t>& diagnostics)
{
    diagnostics.clear();
    artifact_reader_t reader{bytes};
    std::uint32_t magic = 0, version = 0;
    std::string provider_bytes, hir_bytes, type_bytes;
    if (bytes.size() > k_artifact_max_bytes || !reader.u32(magic) || magic != k_artifact_magic ||
        !reader.u32(version) || version != k_artifact_version ||
        !reader.string(provider_bytes) || !reader.string(hir_bytes) ||
        !reader.string(type_bytes) || !reader.complete()) {
        diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization,
            "jvm_ssa.artifact.decode", 1));
        return std::nullopt;
    }
    auto provider = deserialize_provider_ir(provider_bytes);
    auto hir = deserialize_hir_function(hir_bytes);
    auto types = deserialize_type_graph(type_bytes);
    if (!provider.valid() || !hir.valid() || !types.valid() ||
        !provider.value || !hir.value || !types.value ||
        !((*provider.value).entity == (*hir.value).entity) ||
        !((*provider.value).entity == (*types.value).entity) ||
        (*hir.value).provider_ir_hash != stable_serialization_hash(*provider.value) ||
        (*hir.value).type_graph_revision != (*types.value).revision) {
        diagnostics.push_back(make_diagnostic(
            decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization,
            "jvm_ssa.artifact.binding", 1));
        return std::nullopt;
    }
    jvm_ssa_result_t result;
    result.provider_ir = std::move(*provider.value);
    result.hir = std::move(*hir.value);
    result.type_graph = std::move(*types.value);
    return result;
}

}
