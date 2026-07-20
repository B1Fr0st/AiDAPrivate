#include "ghidra_ir_adapter.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <initializer_list>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4099)
#endif
#include "funcdata.hh"
#include "fspec.hh"
#include "opcodes.hh"
#include "type.hh"
#include "variable.hh"
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

namespace aida::analysis::ghidra_ir_adapter {
namespace {

constexpr std::uint32_t k_artifact_magic = 0x41524947U;
constexpr std::uint32_t k_artifact_version = 1;
constexpr std::size_t k_artifact_max_bytes = 32U * 1024U * 1024U;
constexpr std::size_t k_provider_text_max_bytes = 4096U;

std::string bounded_utf8(const std::string_view input)
{
    std::string output;
    output.reserve((std::min)(input.size(), k_provider_text_max_bytes));
    const auto replacement = [&output]() {
        if (output.size() <= k_provider_text_max_bytes - 3U)
            output.append("\xEF\xBF\xBD", 3U);
    };
    for (std::size_t index = 0; index < input.size() && output.size() < k_provider_text_max_bytes;) {
        const auto first = static_cast<unsigned char>(input[index]);
        if (first <= 0x7FU) {
            if (first >= 0x20U && first != 0x7FU)
                output.push_back(static_cast<char>(first));
            else
                replacement();
            ++index;
            continue;
        }
        std::size_t length = 0;
        std::uint32_t scalar = 0;
        std::uint32_t minimum = 0;
        if (first >= 0xC2U && first <= 0xDFU) {
            length = 2;
            scalar = first & 0x1FU;
            minimum = 0x80U;
        } else if (first >= 0xE0U && first <= 0xEFU) {
            length = 3;
            scalar = first & 0x0FU;
            minimum = 0x800U;
        } else if (first >= 0xF0U && first <= 0xF4U) {
            length = 4;
            scalar = first & 0x07U;
            minimum = 0x10000U;
        }
        bool valid = length != 0 && length <= input.size() - index;
        if (valid) {
            for (std::size_t offset = 1; offset < length; ++offset) {
                const auto continuation = static_cast<unsigned char>(input[index + offset]);
                if ((continuation & 0xC0U) != 0x80U) {
                    valid = false;
                    break;
                }
                scalar = (scalar << 6U) | (continuation & 0x3FU);
            }
        }
        if (valid && (scalar < minimum || scalar > 0x10FFFFU ||
                      (scalar >= 0xD800U && scalar <= 0xDFFFU)))
            valid = false;
        if (!valid) {
            replacement();
            ++index;
            continue;
        }
        if (length > k_provider_text_max_bytes - output.size())
            break;
        output.append(input.data() + index, length);
        index += length;
    }
    return output;
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

source_coordinate_t coordinate(const capture_request_t& request,
                               const decompiler_coordinate_layer_t layer,
                               const std::uint64_t address)
{
    source_coordinate_t result;
    result.layer = layer;
    result.workspace_generation = request.workspace_generation;
    result.entity = request.entity;
    decompiler_address_range_t range;
    const auto* native = std::get_if<native_decompiler_entity_identity_t>(&request.entity.identity);
    range.begin = native ? native->entry : address_t{};
    range.end = range.begin;
    range.begin.value = address;
    range.end.value = address == (std::numeric_limits<std::uint64_t>::max)() ? address : address + 1U;
    result.address_range = range;
    return result;
}

provider_ir_opcode_t provider_opcode(const capture_value_t& value, bool& supported)
{
    supported = true;
    switch (value.kind) {
    case capture_value_kind_t::parameter:
        return provider_ir_opcode_t::parameter;
    case capture_value_kind_t::local:
        return provider_ir_opcode_t::local;
    case capture_value_kind_t::constant:
        return provider_ir_opcode_t::constant;
    case capture_value_kind_t::pcode:
        break;
    }
    switch (value.pcode_opcode) {
    case ghidra::CPUI_COPY:
        return provider_ir_opcode_t::copy;
    case ghidra::CPUI_LOAD:
        return provider_ir_opcode_t::load;
    case ghidra::CPUI_STORE:
        return provider_ir_opcode_t::store;
    case ghidra::CPUI_BRANCH:
        return provider_ir_opcode_t::branch;
    case ghidra::CPUI_CBRANCH:
        return provider_ir_opcode_t::conditional_branch;
    case ghidra::CPUI_BRANCHIND:
        return provider_ir_opcode_t::switch_branch;
    case ghidra::CPUI_CALL:
        return provider_ir_opcode_t::call;
    case ghidra::CPUI_CALLIND:
        return provider_ir_opcode_t::indirect_call;
    case ghidra::CPUI_RETURN:
        return provider_ir_opcode_t::return_value;
    case ghidra::CPUI_MULTIEQUAL:
        return provider_ir_opcode_t::phi;
    case ghidra::CPUI_CAST:
    case ghidra::CPUI_INT_ZEXT:
    case ghidra::CPUI_INT_SEXT:
    case ghidra::CPUI_SUBPIECE:
        return provider_ir_opcode_t::cast;
    case ghidra::CPUI_PTRADD:
        return provider_ir_opcode_t::array_load;
    case ghidra::CPUI_PTRSUB:
        return provider_ir_opcode_t::field_load;
    case ghidra::CPUI_INT_2COMP:
    case ghidra::CPUI_INT_NEGATE:
    case ghidra::CPUI_BOOL_NEGATE:
    case ghidra::CPUI_FLOAT_NEG:
    case ghidra::CPUI_FLOAT_ABS:
    case ghidra::CPUI_FLOAT_SQRT:
        return provider_ir_opcode_t::unary;
    case ghidra::CPUI_INT_EQUAL:
    case ghidra::CPUI_INT_NOTEQUAL:
    case ghidra::CPUI_INT_SLESS:
    case ghidra::CPUI_INT_SLESSEQUAL:
    case ghidra::CPUI_INT_LESS:
    case ghidra::CPUI_INT_LESSEQUAL:
    case ghidra::CPUI_INT_ADD:
    case ghidra::CPUI_INT_SUB:
    case ghidra::CPUI_INT_CARRY:
    case ghidra::CPUI_INT_SCARRY:
    case ghidra::CPUI_INT_SBORROW:
    case ghidra::CPUI_INT_XOR:
    case ghidra::CPUI_INT_AND:
    case ghidra::CPUI_INT_OR:
    case ghidra::CPUI_INT_LEFT:
    case ghidra::CPUI_INT_RIGHT:
    case ghidra::CPUI_INT_SRIGHT:
    case ghidra::CPUI_INT_MULT:
    case ghidra::CPUI_INT_DIV:
    case ghidra::CPUI_INT_SDIV:
    case ghidra::CPUI_INT_REM:
    case ghidra::CPUI_INT_SREM:
    case ghidra::CPUI_BOOL_XOR:
    case ghidra::CPUI_BOOL_AND:
    case ghidra::CPUI_BOOL_OR:
    case ghidra::CPUI_FLOAT_EQUAL:
    case ghidra::CPUI_FLOAT_NOTEQUAL:
    case ghidra::CPUI_FLOAT_LESS:
    case ghidra::CPUI_FLOAT_LESSEQUAL:
    case ghidra::CPUI_FLOAT_ADD:
    case ghidra::CPUI_FLOAT_DIV:
    case ghidra::CPUI_FLOAT_MULT:
    case ghidra::CPUI_FLOAT_SUB:
    case ghidra::CPUI_PIECE:
    case ghidra::CPUI_INSERT:
        return provider_ir_opcode_t::binary;
    default:
        supported = false;
        return provider_ir_opcode_t::unknown;
    }
}

hir_node_kind_t hir_kind(const provider_ir_opcode_t opcode)
{
    switch (opcode) {
    case provider_ir_opcode_t::parameter: return hir_node_kind_t::parameter;
    case provider_ir_opcode_t::local: return hir_node_kind_t::local;
    case provider_ir_opcode_t::constant: return hir_node_kind_t::literal;
    case provider_ir_opcode_t::copy: return hir_node_kind_t::assignment;
    case provider_ir_opcode_t::unary: return hir_node_kind_t::unary;
    case provider_ir_opcode_t::binary: return hir_node_kind_t::binary;
    case provider_ir_opcode_t::cast: return hir_node_kind_t::cast;
    case provider_ir_opcode_t::load: return hir_node_kind_t::load;
    case provider_ir_opcode_t::store: return hir_node_kind_t::store;
    case provider_ir_opcode_t::field_load:
    case provider_ir_opcode_t::field_store: return hir_node_kind_t::field;
    case provider_ir_opcode_t::array_load:
    case provider_ir_opcode_t::array_store: return hir_node_kind_t::index;
    case provider_ir_opcode_t::call:
    case provider_ir_opcode_t::indirect_call: return hir_node_kind_t::call;
    case provider_ir_opcode_t::phi: return hir_node_kind_t::phi;
    case provider_ir_opcode_t::branch: return hir_node_kind_t::branch;
    case provider_ir_opcode_t::conditional_branch: return hir_node_kind_t::conditional;
    case provider_ir_opcode_t::switch_branch: return hir_node_kind_t::switch_branch;
    case provider_ir_opcode_t::return_value: return hir_node_kind_t::return_value;
    case provider_ir_opcode_t::throw_value: return hir_node_kind_t::throw_value;
    default: return hir_node_kind_t::unknown;
    }
}

std::string value_text(const capture_value_t& value)
{
    if (!value.stable_symbol.empty())
        return value.stable_symbol;
    if (!value.stable_immediate.empty())
        return value.stable_immediate;
    if (value.kind == capture_value_kind_t::parameter)
        return "parameter_" + std::to_string(value.id);
    if (value.kind == capture_value_kind_t::local)
        return "local_" + std::to_string(value.id);
    if (value.kind == capture_value_kind_t::constant)
        return "constant_" + std::to_string(value.id);
    return ghidra::get_opname(static_cast<ghidra::OpCode>(value.pcode_opcode));
}

std::string binary_operator(const std::uint16_t opcode)
{
    switch (opcode) {
    case ghidra::CPUI_INT_EQUAL:
    case ghidra::CPUI_FLOAT_EQUAL: return "==";
    case ghidra::CPUI_INT_NOTEQUAL:
    case ghidra::CPUI_FLOAT_NOTEQUAL:
    case ghidra::CPUI_BOOL_XOR: return "!=";
    case ghidra::CPUI_INT_SLESS:
    case ghidra::CPUI_INT_LESS:
    case ghidra::CPUI_FLOAT_LESS: return "<";
    case ghidra::CPUI_INT_SLESSEQUAL:
    case ghidra::CPUI_INT_LESSEQUAL:
    case ghidra::CPUI_FLOAT_LESSEQUAL: return "<=";
    case ghidra::CPUI_INT_ADD:
    case ghidra::CPUI_FLOAT_ADD: return "+";
    case ghidra::CPUI_INT_SUB:
    case ghidra::CPUI_FLOAT_SUB: return "-";
    case ghidra::CPUI_INT_XOR: return "^";
    case ghidra::CPUI_INT_AND: return "&";
    case ghidra::CPUI_INT_OR: return "|";
    case ghidra::CPUI_INT_LEFT: return "<<";
    case ghidra::CPUI_INT_RIGHT:
    case ghidra::CPUI_INT_SRIGHT: return ">>";
    case ghidra::CPUI_INT_MULT:
    case ghidra::CPUI_FLOAT_MULT: return "*";
    case ghidra::CPUI_INT_DIV:
    case ghidra::CPUI_INT_SDIV:
    case ghidra::CPUI_FLOAT_DIV: return "/";
    case ghidra::CPUI_INT_REM:
    case ghidra::CPUI_INT_SREM: return "%";
    case ghidra::CPUI_BOOL_AND: return "&&";
    case ghidra::CPUI_BOOL_OR: return "||";
    default: return {};
    }
}

std::string unary_operator(const std::uint16_t opcode)
{
    switch (opcode) {
    case ghidra::CPUI_INT_2COMP:
    case ghidra::CPUI_FLOAT_NEG: return "-";
    case ghidra::CPUI_INT_NEGATE: return "~";
    case ghidra::CPUI_BOOL_NEGATE: return "!";
    default: return {};
    }
}

struct hir_semantics_t {
    hir_node_kind_t kind = hir_node_kind_t::unknown;
    std::vector<std::uint64_t> operands;
    std::string stable_value;
    bool supported = true;
};

hir_semantics_t hir_semantics(const capture_value_t& value,
                              const provider_ir_opcode_t opcode,
                              const bool provider_supported)
{
    hir_semantics_t result;
    result.kind = hir_kind(opcode);
    result.operands = value.operand_ids;
    result.stable_value = value_text(value);
    result.supported = provider_supported;
    if (value.kind != capture_value_kind_t::pcode) {
        if (value.kind == capture_value_kind_t::constant && !value.stable_symbol.empty())
            result.kind = hir_node_kind_t::reference;
        return result;
    }
    const auto select = [&result, &value](const std::initializer_list<std::size_t> indices) {
        std::vector<std::uint64_t> selected;
        selected.reserve(indices.size());
        for (const auto index : indices) {
            if (index >= value.operand_ids.size())
                return false;
            selected.push_back(value.operand_ids[index]);
        }
        result.operands = std::move(selected);
        return true;
    };
    switch (value.pcode_opcode) {
    case ghidra::CPUI_COPY:
        result.kind = hir_node_kind_t::cast;
        result.stable_value = "copy";
        result.supported = select({0}) && value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_LOAD:
        result.supported = select({1}) && value.operand_ids.size() == 2;
        break;
    case ghidra::CPUI_STORE:
        result.supported = select({1, 2}) && value.operand_ids.size() == 3;
        break;
    case ghidra::CPUI_BRANCH:
        result.operands.clear();
        result.supported = value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_CBRANCH:
        result.supported = select({1}) && value.operand_ids.size() == 2;
        break;
    case ghidra::CPUI_BRANCHIND:
        result.supported = false;
        break;
    case ghidra::CPUI_CALL:
    case ghidra::CPUI_CALLIND:
        result.supported = !value.operand_ids.empty();
        break;
    case ghidra::CPUI_RETURN:
        result.operands.clear();
        if (value.operand_ids.size() > 1)
            result.operands.assign(value.operand_ids.begin() + 1, value.operand_ids.end());
        result.supported = result.operands.size() <= 1;
        break;
    case ghidra::CPUI_MULTIEQUAL:
        result.supported = false;
        break;
    case ghidra::CPUI_CAST:
    case ghidra::CPUI_INT_ZEXT:
    case ghidra::CPUI_INT_SEXT:
        result.supported = select({0}) && value.operand_ids.size() == 1;
        break;
    case ghidra::CPUI_SUBPIECE:
        result.supported = false;
        break;
    case ghidra::CPUI_PTRADD:
    case ghidra::CPUI_PTRSUB:
        result.kind = hir_node_kind_t::index;
        result.supported = select({0, 1}) &&
            (value.pcode_opcode == ghidra::CPUI_PTRSUB || value.operand_ids.size() == 3);
        break;
    default:
        if (result.kind == hir_node_kind_t::unary) {
            result.stable_value = unary_operator(value.pcode_opcode);
            result.supported = !result.stable_value.empty() && value.operand_ids.size() == 1;
        } else if (result.kind == hir_node_kind_t::binary) {
            result.stable_value = binary_operator(value.pcode_opcode);
            result.supported = !result.stable_value.empty() && value.operand_ids.size() == 2;
        }
        break;
    }
    if (!result.supported) {
        result.kind = hir_node_kind_t::unknown;
        result.operands.clear();
        result.stable_value = "unknown_pcode_" + std::to_string(value.pcode_opcode) +
            "_" + std::to_string(value.id);
    }
    return result;
}

bool sorted_unique(std::vector<std::uint64_t>& ids)
{
    std::sort(ids.begin(), ids.end());
    return std::adjacent_find(ids.begin(), ids.end()) == ids.end();
}

decompiler_type_kind_t type_kind(const ghidra::Datatype* type)
{
    if (!type)
        return decompiler_type_kind_t::unknown;
    switch (type->getMetatype()) {
    case ghidra::TYPE_VOID: return decompiler_type_kind_t::void_type;
    case ghidra::TYPE_BOOL: return decompiler_type_kind_t::boolean;
    case ghidra::TYPE_INT: return decompiler_type_kind_t::signed_integer;
    case ghidra::TYPE_UINT: return decompiler_type_kind_t::unsigned_integer;
    case ghidra::TYPE_FLOAT: return decompiler_type_kind_t::floating_point;
    case ghidra::TYPE_PTR: return decompiler_type_kind_t::pointer;
    case ghidra::TYPE_ARRAY: return decompiler_type_kind_t::array;
    case ghidra::TYPE_STRUCT: return decompiler_type_kind_t::structure;
    case ghidra::TYPE_UNION: return decompiler_type_kind_t::union_type;
    case ghidra::TYPE_CODE: return decompiler_type_kind_t::function;
    default: return decompiler_type_kind_t::unknown;
    }
}

}

extraction_result_t normalize(const capture_t& capture)
{
    extraction_result_t result;
    std::uint32_t ordinal = 1;
    const auto fail = [&result, &ordinal](const decompiler_diagnostic_code_t code, const char* key) {
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error, code, key, ordinal++));
    };
    if (capture.request.workspace_generation == 0 || capture.request.type_graph_revision == 0 ||
        !std::holds_alternative<native_decompiler_entity_identity_t>(capture.request.entity.identity) ||
        !validate_decompiler_entity_key(capture.request.entity).valid() || capture.types.empty() ||
        capture.blocks.empty() || capture.entry_block_id == 0) {
        fail(decompiler_diagnostic_code_t::invalid_contract, "ghidra_ir.capture.header");
        return result;
    }

    std::vector<capture_type_t> types = capture.types;
    std::sort(types.begin(), types.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
    std::unordered_map<std::uint64_t, std::uint64_t> type_ids;
    type_graph_t type_graph;
    type_graph.entity = capture.request.entity;
    type_graph.revision = capture.request.type_graph_revision;
    for (const auto& type : types) {
        if (type.id == 0 || type_ids.find(type.id) != type_ids.end()) {
            fail(decompiler_diagnostic_code_t::malformed_type_graph, "ghidra_ir.capture.type_id");
            return result;
        }
        const std::uint64_t normalized_id = static_cast<std::uint64_t>(type_ids.size() + 1U);
        type_ids.emplace(type.id, normalized_id);
        decompiler_type_node_t node;
        node.id = normalized_id;
        node.kind = type.kind;
        node.canonical_name = type.canonical_name.empty() ? "ghidra.type." + std::to_string(type.id) : type.canonical_name;
        node.display_name = type.display_name.empty() ? node.canonical_name : type.display_name;
        node.byte_size = type.byte_size;
        node.alignment = type.alignment == 0 ? 1U : type.alignment;
        node.is_signed = type.is_signed;
        node.confidence = type.kind == decompiler_type_kind_t::unknown ? 50U : 100U;
        node.provenance = decompiler_fact_provenance_t::provider_semantics;
        node.coordinates.push_back(coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir,
            std::get<native_decompiler_entity_identity_t>(capture.request.entity.identity).entry.value));
        type_graph.nodes.push_back(std::move(node));
    }
    std::uint32_t edge_ordinal = 1;
    for (const auto& type : types) {
        const auto source = type_ids.find(type.id);
        for (const auto& edge : type.edges) {
            const auto target = type_ids.find(edge.target_type_id);
            if (source == type_ids.end() || target == type_ids.end()) {
                fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.type_edge");
                return result;
            }
            decompiler_type_edge_t normalized;
            normalized.source_type_id = source->second;
            normalized.target_type_id = target->second;
            normalized.kind = edge.kind;
            normalized.stable_name = edge.stable_name.empty() ? "ghidra.type.edge." + std::to_string(edge_ordinal) : edge.stable_name;
            normalized.byte_offset = edge.byte_offset;
            normalized.ordinal = edge_ordinal++;
            normalized.confidence = 100;
            normalized.provenance = decompiler_fact_provenance_t::provider_semantics;
            type_graph.edges.push_back(std::move(normalized));
        }
    }
    const auto return_type = type_ids.find(capture.request.return_type_id);
    if (return_type == type_ids.end()) {
        fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.return_type");
        return result;
    }

    std::vector<capture_block_t> blocks = capture.blocks;
    std::sort(blocks.begin(), blocks.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
    std::set<std::uint64_t> block_ids;
    for (auto& block : blocks) {
        if (block.id == 0 || !block_ids.insert(block.id).second || block.values.empty()) {
            fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.block");
            return result;
        }
        if (!sorted_unique(block.predecessor_ids) || !sorted_unique(block.successor_ids) ||
            !sorted_unique(block.exception_successor_ids)) {
            fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.edge");
            return result;
        }
        std::sort(block.values.begin(), block.values.end(), [](const auto& left, const auto& right) {
            return left.id < right.id;
        });
    }
    if (block_ids.find(capture.entry_block_id) == block_ids.end()) {
        fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.entry");
        return result;
    }

    provider_ir_t provider_ir;
    provider_ir.provider = capture.request.provider;
    provider_ir.language = capture.request.language;
    provider_ir.entity = capture.request.entity;
    provider_ir.entry_block_id = capture.entry_block_id;
    hir_function_t hir;
    hir.entity = capture.request.entity;
    hir.type_graph_revision = type_graph.revision;
    hir.return_type_id = return_type->second;
    std::uint64_t previous_value_id = 0;
    std::uint32_t provider_diagnostic_ordinal = 1;
    std::uint32_t hir_diagnostic_ordinal = 1;
    for (const auto& block : blocks) {
        provider_ir_block_t provider_block;
        provider_block.id = block.id;
        provider_block.predecessor_ids = block.predecessor_ids;
        provider_block.successor_ids = block.successor_ids;
        provider_block.exception_successor_ids = block.exception_successor_ids;
        provider_block.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir, block.address);
        hir_block_t hir_block;
        hir_block.id = block.id;
        hir_block.predecessor_ids = block.predecessor_ids;
        hir_block.successor_ids = block.successor_ids;
        hir_block.exception_successor_ids = block.exception_successor_ids;
        hir_block.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::hir, block.address);
        std::sort(provider_block.predecessor_ids.begin(), provider_block.predecessor_ids.end());
        std::sort(provider_block.successor_ids.begin(), provider_block.successor_ids.end());
        std::sort(provider_block.exception_successor_ids.begin(), provider_block.exception_successor_ids.end());
        std::sort(hir_block.predecessor_ids.begin(), hir_block.predecessor_ids.end());
        std::sort(hir_block.successor_ids.begin(), hir_block.successor_ids.end());
        std::sort(hir_block.exception_successor_ids.begin(), hir_block.exception_successor_ids.end());
        for (const auto& value : block.values) {
            if (value.id == 0 || value.id <= previous_value_id || type_ids.find(value.type_id) == type_ids.end()) {
                fail(decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.capture.value");
                return result;
            }
            previous_value_id = value.id;
            bool supported = false;
            const auto opcode = provider_opcode(value, supported);
            provider_ir_value_t provider_value;
            provider_value.id = value.id;
            provider_value.opcode = opcode;
            provider_value.type_id = type_ids.at(value.type_id);
            provider_value.operand_ids = value.operand_ids;
            provider_value.stable_immediate = value.stable_immediate;
            provider_value.stable_symbol = value.stable_symbol;
            provider_value.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::provider_ir, value.address);
            provider_value.confidence = supported ? 100U : 50U;
            provider_value.provenance = decompiler_fact_provenance_t::provider_semantics;
            provider_block.values.push_back(provider_value);
            const auto semantics = hir_semantics(value, opcode, supported);
            hir_value_t hir_value;
            hir_value.id = value.id;
            hir_value.kind = semantics.kind;
            hir_value.type_id = provider_value.type_id;
            hir_value.operand_ids = semantics.operands;
            hir_value.stable_value = semantics.stable_value;
            hir_value.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::hir, value.address);
            hir_value.confidence = semantics.supported ? provider_value.confidence : 0U;
            hir_value.provenance = provider_value.provenance;
            hir_block.values.push_back(std::move(hir_value));
            if (!semantics.supported) {
                decompiler_unknown_t provider_unknown;
                provider_unknown.reason = decompiler_unknown_reason_t::unsupported_instruction;
                provider_unknown.stable_token = "ghidra.pcode." + std::to_string(value.pcode_opcode) + "." + std::to_string(value.id);
                provider_unknown.coordinate = provider_value.coordinate;
                provider_unknown.confidence = 0;
                provider_unknown.provenance = decompiler_fact_provenance_t::provider_semantics;
                provider_ir.unknowns.push_back(provider_unknown);
                decompiler_unknown_t hir_unknown = provider_unknown;
                hir_unknown.coordinate.layer = decompiler_coordinate_layer_t::hir;
                hir.unknowns.push_back(std::move(hir_unknown));
                provider_ir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_provider, "ghidra_ir.unsupported_pcode", provider_diagnostic_ordinal++));
                hir.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::warning,
                    decompiler_diagnostic_code_t::unsupported_provider, "ghidra_ir.unsupported_pcode", hir_diagnostic_ordinal++));
            }
        }
        provider_ir.source_coordinates.push_back(provider_block.coordinate);
        hir.source_coordinates.push_back(hir_block.coordinate);
        provider_ir.blocks.push_back(std::move(provider_block));
        hir.blocks.push_back(std::move(hir_block));
    }

    std::vector<capture_high_variable_t> highs = capture.high_variables;
    std::sort(highs.begin(), highs.end(), [](const auto& left, const auto& right) { return left.id < right.id; });
    std::uint64_t parameter_id = 1;
    std::uint64_t local_id = 1;
    for (const auto& high : highs) {
        const auto type = type_ids.find(high.type_id);
        if (high.id == 0 || type == type_ids.end()) {
            fail(decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.capture.high_variable");
            return result;
        }
        hir_variable_t variable;
        variable.id = high.parameter ? parameter_id++ : local_id++;
        variable.stable_name = high.stable_name.empty() ? "high_" + std::to_string(high.id) : high.stable_name;
        variable.type_id = type->second;
        variable.coordinate = coordinate(capture.request, decompiler_coordinate_layer_t::hir, high.address);
        variable.confidence = 100;
        variable.provenance = decompiler_fact_provenance_t::provider_semantics;
        if (high.parameter)
            hir.parameters.push_back(std::move(variable));
        else
            hir.locals.push_back(std::move(variable));
    }
    hir.provider_ir_hash = stable_serialization_hash(provider_ir);

    const auto provider_validation = validate_provider_ir(provider_ir);
    const auto hir_validation = validate_hir_function(hir);
    const auto type_validation = validate_type_graph(type_graph);
    if (!provider_validation.valid() || !hir_validation.valid() || !type_validation.valid()) {
        result.diagnostics.insert(result.diagnostics.end(), provider_validation.diagnostics.begin(), provider_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), hir_validation.diagnostics.begin(), hir_validation.diagnostics.end());
        result.diagnostics.insert(result.diagnostics.end(), type_validation.diagnostics.begin(), type_validation.diagnostics.end());
        return result;
    }
    result.artifacts = typed_artifacts_t{std::move(provider_ir), std::move(hir), std::move(type_graph)};
    return result;
}

extraction_result_t extract(const ghidra::Funcdata& function, const capture_request_t& request)
{
    capture_t capture;
    capture.request = request;
    if (auto* native = std::get_if<native_decompiler_entity_identity_t>(
            &capture.request.entity.identity)) {
        native->canonical_symbol = bounded_utf8(native->canonical_symbol);
        if (native->canonical_symbol.empty())
            native->canonical_symbol = "sub_" + std::to_string(native->entry.value);
    }
    const auto* native_entity = std::get_if<native_decompiler_entity_identity_t>(
        &capture.request.entity.identity);
    const std::uint64_t runtime_entry = function.getAddress().getOffset();
    std::uint64_t coordinate_bias = 0;
    if (native_entity && native_entity->entry.space == address_space_id_t::relative_virtual) {
        if (runtime_entry < native_entity->entry.value) {
            extraction_result_t result;
            result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::source_map_rejected,
                "ghidra_ir.runtime_entry_bias", 1));
            return result;
        }
        coordinate_bias = runtime_entry - native_entity->entry.value;
    }
    const auto code_coordinate = [coordinate_bias, runtime_entry, native_entity](
            const std::uint64_t address) {
        if (!native_entity || native_entity->entry.space != address_space_id_t::relative_virtual)
            return address;
        if (address < coordinate_bias)
            return native_entity->entry.value;
        const auto normalized = address - coordinate_bias;
        return address < runtime_entry ? native_entity->entry.value : normalized;
    };
    std::map<const ghidra::Datatype*, std::uint64_t> types;
    std::function<std::uint64_t(const ghidra::Datatype*)> ensure_type;
    ensure_type = [&capture, &types, &ensure_type](const ghidra::Datatype* type) {
        if (!type)
            return std::uint64_t{0};
        const auto found = types.find(type);
        if (found != types.end())
            return found->second;
        const auto id = static_cast<std::uint64_t>(types.size() + 1U);
        types.emplace(type, id);
        capture_type_t value;
        value.id = id;
        value.kind = type_kind(type);
        value.canonical_name = bounded_utf8(type->getName());
        value.display_name = bounded_utf8(type->getDisplayName());
        if (type->getSize() > 0)
            value.byte_size = static_cast<std::uint64_t>(type->getSize());
        value.alignment = type->getAlignment() > 0 ? static_cast<std::uint32_t>(type->getAlignment()) : 1U;
        value.is_signed = type->getMetatype() == ghidra::TYPE_INT;
        capture.types.push_back(std::move(value));
        const auto append_edge = [&](const ghidra::Datatype* target,
                                     const decompiler_type_edge_kind_t kind,
                                     std::string stable_name,
                                     std::optional<std::uint64_t> byte_offset = std::nullopt) {
            const auto target_id = ensure_type(target);
            if (target_id == 0 || target_id == id)
                return;
            auto& source = capture.types.at(static_cast<std::size_t>(id - 1U));
            const auto duplicate = std::find_if(source.edges.begin(), source.edges.end(),
                [&](const capture_type_edge_t& edge) {
                    return edge.target_type_id == target_id && edge.kind == kind &&
                        edge.stable_name == stable_name && edge.byte_offset == byte_offset;
                });
            if (duplicate == source.edges.end())
                source.edges.push_back({target_id, kind, std::move(stable_name), byte_offset});
        };
        if (const auto* alias = type->getTypedef(); alias && alias != type)
            append_edge(alias, decompiler_type_edge_kind_t::alias, "typedef");
        if (const auto* pointer = dynamic_cast<const ghidra::TypePointer*>(type)) {
            append_edge(pointer->getPtrTo(), decompiler_type_edge_kind_t::pointee, "pointee");
            return id;
        }
        if (const auto* array = dynamic_cast<const ghidra::TypeArray*>(type)) {
            append_edge(array->getBase(), decompiler_type_edge_kind_t::element, "element", 0U);
            return id;
        }
        if (const auto* structure = dynamic_cast<const ghidra::TypeStruct*>(type)) {
            std::uint32_t index = 0;
            for (auto field = structure->beginField(); field != structure->endField(); ++field, ++index) {
                const std::string name = field->name.empty()
                    ? "member." + std::to_string(index) : bounded_utf8(field->name);
                append_edge(field->type, decompiler_type_edge_kind_t::member, name,
                    field->offset >= 0 ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(field->offset)}
                                       : std::nullopt);
            }
            return id;
        }
        if (const auto* union_type = dynamic_cast<const ghidra::TypeUnion*>(type)) {
            for (ghidra::int4 index = 0; index < union_type->numDepend(); ++index) {
                const auto* field = union_type->getField(index);
                if (!field)
                    continue;
                const std::string name = field->name.empty()
                    ? "member." + std::to_string(index) : bounded_utf8(field->name);
                append_edge(field->type, decompiler_type_edge_kind_t::member, name,
                    field->offset >= 0 ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(field->offset)}
                                       : std::nullopt);
            }
            return id;
        }
        if (const auto* code = dynamic_cast<const ghidra::TypeCode*>(type)) {
            const auto* prototype = code->getPrototype();
            if (prototype) {
                append_edge(prototype->getOutputType(), decompiler_type_edge_kind_t::return_type, "return");
                for (ghidra::int4 index = 0; index < prototype->numParams(); ++index) {
                    const auto* parameter = prototype->getParam(index);
                    append_edge(parameter ? parameter->getType() : nullptr,
                        decompiler_type_edge_kind_t::parameter, "parameter." + std::to_string(index));
                }
            }
            return id;
        }
        for (ghidra::int4 index = 0; index < type->numDepend(); ++index)
            append_edge(type->getDepend(index), decompiler_type_edge_kind_t::alias,
                "dependency." + std::to_string(index));
        return id;
    };
    capture.request.return_type_id = ensure_type(function.getFuncProto().getOutputType());
    std::map<std::uint64_t, capture_block_t> blocks;
    std::map<const ghidra::PcodeOp*, std::uint64_t> operation_ids;
    std::map<std::uint64_t, std::vector<const ghidra::PcodeOp*>> operations_by_block;
    std::map<const ghidra::Varnode*, std::uint64_t> input_ids;
    std::map<const ghidra::Varnode*, std::string> input_symbols;
    std::map<const ghidra::Varnode*, std::uint64_t> defined_ids;
    std::map<const ghidra::HighVariable*, std::uint64_t> high_ids;
    std::uint64_t next_value_id = 1;
    const auto associated_high = [](const ghidra::Varnode* node)
        -> const ghidra::HighVariable* {
        if (!node || node->isAnnotation())
            return nullptr;
        return node->getHigh();
    };
    const auto value_type = [&associated_high](const ghidra::Varnode* node,
                                                const bool definition_facing)
        -> const ghidra::Datatype* {
        if (!node)
            return nullptr;
        const auto* high = associated_high(node);
        if (!high)
            return definition_facing ? node->getTypeDefFacing() : node->getType();
        return definition_facing ? node->getHighTypeDefFacing() : high->getType();
    };
    const auto& graph = function.getBasicBlocks();
    for (ghidra::int4 index = 0; index < graph.getSize(); ++index) {
        const auto* block = graph.getBlock(index);
        if (!block)
            continue;
        const auto id = static_cast<std::uint64_t>(block->getIndex() + 1);
        capture_block_t capture_block;
        capture_block.id = id;
        for (ghidra::int4 edge = 0; edge < block->sizeIn(); ++edge)
            capture_block.predecessor_ids.push_back(static_cast<std::uint64_t>(block->getIn(edge)->getIndex() + 1));
        for (ghidra::int4 edge = 0; edge < block->sizeOut(); ++edge)
            capture_block.successor_ids.push_back(static_cast<std::uint64_t>(block->getOut(edge)->getIndex() + 1));
        blocks.emplace(id, std::move(capture_block));
    }
    for (auto iterator = function.beginOpAll(); iterator != function.endOpAll(); ++iterator) {
        const auto* operation = (*iterator).second;
        if (!operation || !operation->getParent())
            continue;
        const auto block_id = static_cast<std::uint64_t>(operation->getParent()->getIndex() + 1);
        const auto block = blocks.find(block_id);
        if (block == blocks.end())
            continue;
        operation_ids.emplace(operation, 0);
        operations_by_block[block_id].push_back(operation);
        if (operation->code() == ghidra::CPUI_CALL && operation->numInput() > 0) {
            const auto* target = operation->getIn(0);
            const auto* specification = function.getCallSpecs(operation);
            if (target && specification) {
                auto name = bounded_utf8(specification->getName());
                if (name.empty())
                    name = "sub_" + std::to_string(specification->getEntryAddress().getOffset());
                input_symbols[target] = std::move(name);
            }
        }
    }
    if (operation_ids.empty()) {
        extraction_result_t result;
        result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::provider_failure, "ghidra_ir.empty_pcode", 1));
        return result;
    }
    const auto entry_block = operations_by_block.begin()->first;
    capture.entry_block_id = entry_block;
    auto entry = blocks.find(entry_block);
    for (const auto& entry_pair : operations_by_block) {
        for (const auto* operation : entry_pair.second) {
            for (ghidra::int4 index = 0; index < operation->numInput(); ++index) {
                const auto* input = operation->getIn(index);
                if (!input || input->getDef())
                    continue;
                if (input_ids.find(input) == input_ids.end())
                    input_ids.emplace(input, next_value_id++);
            }
        }
    }
    for (const auto& entry_pair : operations_by_block) {
        for (const auto* operation : entry_pair.second) {
            const auto operation_id = next_value_id++;
            operation_ids.at(operation) = operation_id;
            const auto* output = operation->getOut();
            if (output && !defined_ids.emplace(output, operation_id).second) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.duplicate_output_varnode", 1));
                return result;
            }
        }
    }
    const auto collect_high = [&capture, &high_ids, &ensure_type, &associated_high,
                               native_entity, &code_coordinate, runtime_entry](
                               const ghidra::Varnode* node) {
        const auto* high = associated_high(node);
        if (!high)
            return true;
        if (high_ids.find(high) != high_ids.end())
            return true;
        const auto type_id = ensure_type(high->getType());
        if (type_id == 0)
            return false;
        const auto id = static_cast<std::uint64_t>(high_ids.size() + 1U);
        high_ids.emplace(high, id);
        capture_high_variable_t variable;
        variable.id = id;
        variable.parameter = high->isInput();
        variable.stable_name = "high_" + std::to_string(id);
        variable.type_id = type_id;
        variable.address = native_entity ? native_entity->entry.value : code_coordinate(runtime_entry);
        capture.high_variables.push_back(std::move(variable));
        return true;
    };
    for (const auto& pair : input_ids) {
        const auto* input = pair.first;
        capture_value_t value;
        value.id = pair.second;
        value.kind = input->isConstant() ? capture_value_kind_t::constant :
            (input->isInput() ? capture_value_kind_t::parameter : capture_value_kind_t::local);
        value.type_id = ensure_type(value_type(input, false));
        if (value.type_id == 0)
            value.type_id = ensure_type(input->getType());
        value.address = native_entity ? native_entity->entry.value : code_coordinate(runtime_entry);
        value.stable_immediate = input->isConstant() ? std::to_string(input->getOffset()) : std::string{};
        if (const auto symbol = input_symbols.find(input); symbol != input_symbols.end())
            value.stable_symbol = symbol->second;
        entry->second.values.push_back(std::move(value));
        if (!collect_high(input)) {
            extraction_result_t result;
            result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.input_varnode_type", 1));
            return result;
        }
    }
    for (const auto& entry_pair : operations_by_block) {
        auto block = blocks.find(entry_pair.first);
        if (block == blocks.end())
            continue;
        for (const auto* operation : entry_pair.second) {
            const auto value_id = operation_ids.at(operation);
            capture_value_t value;
            value.id = value_id;
            value.kind = capture_value_kind_t::pcode;
            value.pcode_opcode = static_cast<std::uint16_t>(operation->code());
            const auto* output = operation->getOut();
            if (output && defined_ids.find(output) == defined_ids.end()) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.output_varnode_binding", 1));
                return result;
            }
            value.type_id = ensure_type(output ? value_type(output, true) : function.getFuncProto().getOutputType());
            if (value.type_id == 0)
                value.type_id = ensure_type(output ? output->getTypeDefFacing() : function.getFuncProto().getOutputType());
            if (value.type_id == 0) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.output_varnode_type", 1));
                return result;
            }
            value.address = code_coordinate(operation->getSeqNum().getAddr().getOffset());
            if (operation->code() == ghidra::CPUI_CBRANCH && operation->getParent() &&
                operation->getParent()->sizeOut() == 2) {
                const auto true_id = static_cast<std::uint64_t>(
                    operation->getParent()->getTrueOut()->getIndex() + 1);
                value.stable_symbol = "condition.true=" + std::to_string(true_id) +
                    ";negated=" + (operation->isBooleanFlip() ? "1" : "0");
            } else {
                value.stable_symbol = ghidra::get_opname(operation->code());
            }
            for (ghidra::int4 index = 0; index < operation->numInput(); ++index) {
                const auto* input = operation->getIn(index);
                if (!input)
                    continue;
                if (const auto defined = defined_ids.find(input); defined != defined_ids.end()) {
                    value.operand_ids.push_back(defined->second);
                } else if (const auto input_id = input_ids.find(input); input_id != input_ids.end()) {
                    value.operand_ids.push_back(input_id->second);
                } else {
                    extraction_result_t result;
                    result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::malformed_provider_ir, "ghidra_ir.input_varnode_binding", 1));
                    return result;
                }
                if (!collect_high(input)) {
                    extraction_result_t result;
                    result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                        decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.input_varnode_type", 1));
                    return result;
                }
            }
            if (!collect_high(output)) {
                extraction_result_t result;
                result.diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
                    decompiler_diagnostic_code_t::unresolved_type, "ghidra_ir.output_varnode_high_type", 1));
                return result;
            }
            block->second.values.push_back(std::move(value));
        }
    }
    for (auto& pair : blocks) {
        auto& block = pair.second;
        if (block.values.empty())
            continue;
        block.address = block.values.front().address;
        block.predecessor_ids.erase(std::remove_if(block.predecessor_ids.begin(), block.predecessor_ids.end(),
            [&blocks](const auto id) { const auto found = blocks.find(id); return found == blocks.end() || found->second.values.empty(); }), block.predecessor_ids.end());
        block.successor_ids.erase(std::remove_if(block.successor_ids.begin(), block.successor_ids.end(),
            [&blocks](const auto id) { const auto found = blocks.find(id); return found == blocks.end() || found->second.values.empty(); }), block.successor_ids.end());
        capture.blocks.push_back(std::move(block));
    }
    if (std::none_of(capture.blocks.begin(), capture.blocks.end(), [&capture](const auto& block) { return block.id == capture.entry_block_id; }))
        capture.entry_block_id = capture.blocks.empty() ? 0 : capture.blocks.front().id;
    return normalize(capture);
}

std::string serialize_artifacts(const typed_artifacts_t& artifacts)
{
    if (!validate_provider_ir(artifacts.provider_ir).valid() || !validate_hir_function(artifacts.hir).valid() ||
        !validate_type_graph(artifacts.type_graph).valid() || !(artifacts.provider_ir.entity == artifacts.hir.entity) ||
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

std::optional<typed_artifacts_t> deserialize_artifacts(const std::string& bytes,
                                                       std::vector<decompiler_diagnostic_t>& diagnostics)
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
            decompiler_diagnostic_code_t::malformed_serialization, "ghidra_ir.artifact.decode", 1));
        return std::nullopt;
    }
    const auto provider = deserialize_provider_ir(provider_bytes);
    const auto hir = deserialize_hir_function(hir_bytes);
    const auto types = deserialize_type_graph(type_bytes);
    if (!provider.valid() || !hir.valid() || !types.valid() || !provider.value || !hir.value || !types.value ||
        !(provider.value->entity == hir.value->entity) || !(provider.value->entity == types.value->entity) ||
        hir.value->provider_ir_hash != stable_serialization_hash(*provider.value) ||
        hir.value->type_graph_revision != types.value->revision) {
        diagnostics.push_back(diagnostic(decompiler_diagnostic_severity_t::error,
            decompiler_diagnostic_code_t::malformed_serialization, "ghidra_ir.artifact.binding", 1));
        return std::nullopt;
    }
    return typed_artifacts_t{std::move(*provider.value), std::move(*hir.value), std::move(*types.value)};
}

}
