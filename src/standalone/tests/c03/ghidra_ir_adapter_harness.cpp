#include "ghidra_ir_adapter_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/providers/ghidra_ir_adapter.hpp"
#include "../../src/core/disasm/ghidra_decompiler.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using ghidra_ir_adapter::capture_block_t;
using ghidra_ir_adapter::capture_high_variable_t;
using ghidra_ir_adapter::capture_t;
using ghidra_ir_adapter::capture_type_t;
using ghidra_ir_adapter::capture_value_kind_t;
using ghidra_ir_adapter::capture_value_t;

constexpr std::uint16_t k_pcode_copy = 1;
constexpr std::uint16_t k_pcode_load = 2;
constexpr std::uint16_t k_pcode_store = 3;
constexpr std::uint16_t k_pcode_branch = 4;
constexpr std::uint16_t k_pcode_cbranch = 5;
constexpr std::uint16_t k_pcode_branchind = 6;
constexpr std::uint16_t k_pcode_call = 7;
constexpr std::uint16_t k_pcode_callind = 8;
constexpr std::uint16_t k_pcode_callother = 9;
constexpr std::uint16_t k_pcode_return = 10;
constexpr std::uint16_t k_pcode_int_zext = 17;
constexpr std::uint16_t k_pcode_int_add = 19;
constexpr std::uint16_t k_pcode_multiequal = 60;
constexpr std::uint16_t k_pcode_subpiece = 63;
constexpr std::uint16_t k_pcode_ptradd = 65;
constexpr std::uint16_t k_pcode_ptrsub = 66;
constexpr std::uint16_t k_pcode_future_unsupported = 68;

void require(const bool condition, const std::string& message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

capture_t fixture(const std::string& language_id,
                  const architecture_id_t architecture,
                  const architecture_mode_t mode,
                  const endian_t endian)
{
    capture_t result;
    auto& request = result.request;
    request.provider.provider = decompiler_provider_id_t::ghidra_native;
    request.provider.provider_name = "aida-ghidra-native";
    request.provider.provider_version = "1";
    request.provider.provider_binary_hash = stable_serialization_hash("ghidra-ir-harness-provider");
    request.provider.worker_build_id = "ghidra-ir-harness";
    request.provider.worker_build_hash = stable_serialization_hash("ghidra-ir-harness-build");
    request.language.language_id = language_id;
    request.language.language_version = "staged";
    request.language.compiler_spec_id = "default";
    request.language.language_spec_hash = stable_serialization_hash(language_id);
    request.language.architecture = architecture;
    request.language.mode = mode;
    request.language.endian = endian;
    request.workspace_generation = 7;
    request.type_graph_revision = 11;
    request.return_type_id = 2;
    native_decompiler_entity_identity_t identity;
    identity.function_id = 0x41;
    identity.entry = {address_space_id_t::relative_virtual, 0x1000, architecture, mode};
    identity.end = {address_space_id_t::relative_virtual, 0x1040, architecture, mode};
    identity.function_bytes_hash = stable_serialization_hash(language_id + ".function");
    identity.canonical_symbol = "fixture_" + language_id;
    request.entity.kind = decompiler_entity_kind_t::native_function;
    request.entity.format = format_id_t::pe32_plus;
    request.entity.architecture = architecture;
    request.entity.mode = mode;
    request.entity.endian = endian;
    request.entity.identity = std::move(identity);

    capture_type_t signed_integer;
    signed_integer.id = 1;
    signed_integer.kind = decompiler_type_kind_t::signed_integer;
    signed_integer.canonical_name = "int32_t";
    signed_integer.display_name = "int";
    signed_integer.byte_size = 4;
    signed_integer.alignment = 4;
    signed_integer.is_signed = true;
    result.types.push_back(std::move(signed_integer));
    capture_type_t void_type;
    void_type.id = 2;
    void_type.kind = decompiler_type_kind_t::void_type;
    void_type.canonical_name = "void";
    void_type.display_name = "void";
    void_type.alignment = 1;
    result.types.push_back(std::move(void_type));
    capture_type_t pointer;
    pointer.id = 3;
    pointer.kind = decompiler_type_kind_t::pointer;
    pointer.canonical_name = "int32_t*";
    pointer.display_name = "int*";
    pointer.byte_size = architecture == architecture_id_t::x86 ? 4U : 8U;
    pointer.alignment = static_cast<std::uint32_t>(*pointer.byte_size);
    pointer.edges.push_back({1, decompiler_type_edge_kind_t::pointee, "pointee", std::nullopt});
    result.types.push_back(std::move(pointer));

    capture_block_t entry;
    entry.id = 1;
    entry.successor_ids = {2};
    entry.address = 0x1000;
    entry.values = {
        {1, capture_value_kind_t::parameter, 0, 3, {}, 0x1000, {}, "arg0"},
        {2, capture_value_kind_t::local, 0, 1, {}, 0x1004, {}, "defined_output"},
        {3, capture_value_kind_t::pcode, k_pcode_int_add, 1, {1, 2}, 0x1004, {}, "INT_ADD"},
        {4, capture_value_kind_t::pcode, k_pcode_call, 2, {3}, 0x1008, {}, "CALL"}
    };
    result.blocks.push_back(std::move(entry));
    capture_block_t exit;
    exit.id = 2;
    exit.predecessor_ids = {1};
    exit.address = 0x1010;
    exit.values = {
        {5, capture_value_kind_t::pcode, k_pcode_return, 2, {}, 0x1010, {}, "RETURN"}
    };
    result.blocks.push_back(std::move(exit));
    result.entry_block_id = 1;
    result.high_variables = {
        {1, true, "arg0", 1, 0x1000},
        {2, false, "accumulator", 1, 0x1004}
    };
    return result;
}

capture_value_t capture_value(const std::uint64_t id,
                              const capture_value_kind_t kind,
                              const std::uint16_t opcode,
                              const std::uint64_t type_id,
                              std::vector<std::uint64_t> operands,
                              const std::uint64_t address,
                              std::string immediate = {},
                              std::string symbol = {},
                              const bool unresolved_reference = false)
{
    capture_value_t result;
    result.id = id;
    result.kind = kind;
    result.pcode_opcode = opcode;
    result.type_id = type_id;
    result.operand_ids = std::move(operands);
    result.address = address;
    result.stable_immediate = std::move(immediate);
    result.stable_symbol = std::move(symbol);
    result.unresolved_reference = unresolved_reference;
    return result;
}

capture_t liveness_fixture()
{
    auto result = fixture("x86:LE:64:default", architecture_id_t::x86_64,
        architecture_mode_t::x86_64, endian_t::little);
    result.request.function_type_id = 5;

    capture_type_t unknown;
    unknown.id = 4;
    unknown.kind = decompiler_type_kind_t::unknown;
    unknown.canonical_name = "undefined4";
    unknown.display_name = "undefined4";
    unknown.byte_size = 4;
    unknown.alignment = 4;
    unknown.confidence = 40;
    result.types.push_back(std::move(unknown));

    capture_type_t function;
    function.id = 5;
    function.kind = decompiler_type_kind_t::function;
    function.canonical_name = "fixture.signature";
    function.display_name = "fixture.signature";
    function.alignment = 1;
    function.edges.push_back({2, decompiler_type_edge_kind_t::return_type, "return", std::nullopt});
    function.edges.push_back({1, decompiler_type_edge_kind_t::parameter, "arg0", std::nullopt});
    result.types.push_back(std::move(function));

    capture_type_t dead_unsupported;
    dead_unsupported.id = 6;
    dead_unsupported.kind = decompiler_type_kind_t::unknown;
    dead_unsupported.canonical_name = "dead_unsupported_type";
    dead_unsupported.display_name = "dead_unsupported_type";
    dead_unsupported.byte_size = 4;
    dead_unsupported.alignment = 4;
    dead_unsupported.confidence = 25;
    result.types.push_back(std::move(dead_unsupported));

    capture_block_t entry;
    entry.id = 1;
    entry.successor_ids = {2, 3};
    entry.address = 0x1000;
    entry.values = {
        capture_value(1, capture_value_kind_t::parameter, 0, 1, {}, 0x1000, {}, "arg0"),
        capture_value(2, capture_value_kind_t::local, 0, 4, {}, 0x1001),
        capture_value(3, capture_value_kind_t::local, 0, 1, {}, 0x1002, {}, "named_local"),
        capture_value(4, capture_value_kind_t::constant, 0, 4, {}, 0x1003, "7"),
        capture_value(5, capture_value_kind_t::constant, 0, 1, {}, 0x1004, "11"),
        capture_value(6, capture_value_kind_t::pcode, k_pcode_copy, 1, {5}, 0x1005),
        capture_value(7, capture_value_kind_t::pcode, k_pcode_int_add, 1, {5, 5}, 0x1006),
        capture_value(8, capture_value_kind_t::pcode, k_pcode_int_zext, 1, {5}, 0x1007),
        capture_value(9, capture_value_kind_t::local, 0, 3, {}, 0x1008),
        capture_value(10, capture_value_kind_t::constant, 0, 1, {}, 0x1009, "ram"),
        capture_value(11, capture_value_kind_t::pcode, k_pcode_load, 1, {10, 9}, 0x100a),
        capture_value(12, capture_value_kind_t::pcode, k_pcode_store, 2, {10, 9, 5}, 0x100b),
        capture_value(13, capture_value_kind_t::constant, 0, 3, {}, 0x100c, {}, "sub_2000"),
        capture_value(14, capture_value_kind_t::pcode, k_pcode_call, 2, {13, 5}, 0x100d,
            {}, "callee", true),
        capture_value(15, capture_value_kind_t::constant, 0, 1, {}, 0x100e, "block_3"),
        capture_value(16, capture_value_kind_t::pcode, k_pcode_branch, 2, {15}, 0x100f),
        capture_value(17, capture_value_kind_t::pcode, k_pcode_cbranch, 2, {15, 1}, 0x1010),
        capture_value(18, capture_value_kind_t::pcode, k_pcode_multiequal, 1, {6, 7}, 0x1011),
        capture_value(19, capture_value_kind_t::pcode, k_pcode_subpiece, 1, {18, 10}, 0x1012),
        capture_value(20, capture_value_kind_t::pcode, k_pcode_callother, 1, {5}, 0x1013),
        capture_value(21, capture_value_kind_t::pcode, k_pcode_callind, 2, {13, 5, 18, 19}, 0x1014,
            {}, "resolved_indirect_target"),
        capture_value(22, capture_value_kind_t::pcode, k_pcode_ptradd, 3, {9, 5, 5}, 0x1015),
        capture_value(23, capture_value_kind_t::pcode, k_pcode_ptrsub, 3, {9, 5}, 0x1016),
        capture_value(24, capture_value_kind_t::pcode, k_pcode_multiequal, 6, {6, 7}, 0x1017),
        capture_value(25, capture_value_kind_t::pcode, k_pcode_subpiece, 6, {24, 10}, 0x1018),
        capture_value(26, capture_value_kind_t::pcode, k_pcode_future_unsupported, 6, {25}, 0x1019)
    };

    capture_block_t exception_source;
    exception_source.id = 2;
    exception_source.predecessor_ids = {1};
    exception_source.successor_ids = {3};
    exception_source.exception_successor_ids = {4};
    exception_source.address = 0x1020;
    exception_source.values = {
        capture_value(30, capture_value_kind_t::constant, 0, 1, {}, 0x1020, "13"),
        capture_value(31, capture_value_kind_t::pcode, k_pcode_copy, 1, {30}, 0x1021)
    };

    capture_block_t indirect_branch;
    indirect_branch.id = 3;
    indirect_branch.predecessor_ids = {1, 2};
    indirect_branch.successor_ids = {4};
    indirect_branch.address = 0x1030;
    indirect_branch.values = {
        capture_value(40, capture_value_kind_t::constant, 0, 1, {}, 0x1030, "jump_target"),
        capture_value(41, capture_value_kind_t::pcode, k_pcode_branchind, 2, {40}, 0x1031)
    };

    capture_block_t exit;
    exit.id = 4;
    exit.predecessor_ids = {2, 3};
    exit.address = 0x1040;
    exit.values = {
        capture_value(50, capture_value_kind_t::pcode, k_pcode_return, 2, {}, 0x1040)
    };

    result.blocks = {std::move(entry), std::move(exception_source),
        std::move(indirect_branch), std::move(exit)};
    result.entry_block_id = 1;
    result.high_variables = {
        {1, true, "arg0", 1, 0x1000},
        {2, false, "local_2", 4, 0x1001},
        {3, false, "descriptive_name", 4, 0x1002},
        {4, false, "local_4", 3, 0x1008},
        {5, false, "local_5", 4, 0x1003},
        {6, false, "local_6", 6, 0x1011}
    };
    return result;
}

const provider_ir_value_t* find_provider_value(const provider_ir_t& provider_ir,
                                               const std::uint64_t id)
{
    for (const auto& block : provider_ir.blocks) {
        const auto found = std::find_if(block.values.begin(), block.values.end(),
            [id](const provider_ir_value_t& value) { return value.id == id; });
        if (found != block.values.end())
            return &*found;
    }
    return nullptr;
}

const hir_value_t* find_hir_value(const hir_function_t& hir, const std::uint64_t id)
{
    for (const auto& block : hir.blocks) {
        const auto found = std::find_if(block.values.begin(), block.values.end(),
            [id](const hir_value_t& value) { return value.id == id; });
        if (found != block.values.end())
            return &*found;
    }
    return nullptr;
}

const decompiler_unknown_t* find_unknown_token(const std::vector<decompiler_unknown_t>& unknowns,
                                               const std::string& token)
{
    const auto found = std::find_if(unknowns.begin(), unknowns.end(), [&token](const decompiler_unknown_t& unknown) {
        return unknown.stable_token == token;
    });
    return found == unknowns.end() ? nullptr : &*found;
}

bool has_unknown_token(const std::vector<decompiler_unknown_t>& unknowns,
                       const std::string& token)
{
    return find_unknown_token(unknowns, token) != nullptr;
}

std::size_t provider_value_count(const provider_ir_t& provider_ir)
{
    std::size_t result = 0;
    for (const auto& block : provider_ir.blocks)
        result += block.values.size();
    return result;
}

void verify_supported_languages()
{
    const std::array<std::tuple<const char*, architecture_id_t, architecture_mode_t, endian_t>, 9> languages = {{
        {"x86:LE:32:default", architecture_id_t::x86, architecture_mode_t::x86_32, endian_t::little},
        {"x86:LE:64:default", architecture_id_t::x86_64, architecture_mode_t::x86_64, endian_t::little},
        {"ARM:LE:32:v8", architecture_id_t::arm, architecture_mode_t::arm_a32, endian_t::little},
        {"ARM:LE:32:v8T", architecture_id_t::arm, architecture_mode_t::arm_thumb, endian_t::little},
        {"AARCH64:LE:64:v8A", architecture_id_t::aarch64, architecture_mode_t::aarch64, endian_t::little},
        {"MIPS:LE:32:default", architecture_id_t::mips, architecture_mode_t::mips32, endian_t::little},
        {"MIPS:BE:64:default", architecture_id_t::mips64, architecture_mode_t::mips64, endian_t::big},
        {"PowerPC:BE:64:default", architecture_id_t::ppc64, architecture_mode_t::ppc64, endian_t::big},
        {"RISCV:LE:64:default", architecture_id_t::riscv64, architecture_mode_t::riscv64, endian_t::little}
    }};
    for (const auto& language : languages) {
        const auto source = fixture(std::get<0>(language), std::get<1>(language), std::get<2>(language), std::get<3>(language));
        const auto first = ghidra_ir_adapter::normalize(source);
        const auto second = ghidra_ir_adapter::normalize(source);
        require(first.succeeded() && second.succeeded(), "staged language fixture did not produce typed artifacts");
        require(stable_serialization_hash(first.artifacts->provider_ir) == stable_serialization_hash(second.artifacts->provider_ir),
            "provider IR normalization is not deterministic");
        require(stable_serialization_hash(first.artifacts->hir) == stable_serialization_hash(second.artifacts->hir),
            "HIR normalization is not deterministic");
        require(stable_serialization_hash(first.artifacts->type_graph) == stable_serialization_hash(second.artifacts->type_graph),
            "type graph normalization is not deterministic");
        const auto bytes = ghidra_ir_adapter::serialize_artifacts(*first.artifacts);
        require(!bytes.empty(), "typed artifact serialization returned an empty payload");
        std::vector<decompiler_diagnostic_t> diagnostics;
        const auto restored = ghidra_ir_adapter::deserialize_artifacts(bytes, diagnostics);
        require(restored.has_value() && diagnostics.empty(), "typed artifact wire round trip failed");
        require(stable_serialization_hash(restored->provider_ir) == stable_serialization_hash(first.artifacts->provider_ir),
            "typed artifact wire round trip changed provider IR");
        require(stable_serialization_hash(restored->hir) == stable_serialization_hash(first.artifacts->hir),
            "typed artifact wire round trip changed HIR");
        require(stable_serialization_hash(restored->type_graph) == stable_serialization_hash(first.artifacts->type_graph),
            "typed artifact wire round trip changed the type graph");
        require(serialize_provider_ir(restored->provider_ir) == serialize_provider_ir(first.artifacts->provider_ir),
            "provider IR serialization is not byte-stable after artifact round trip");
        require(serialize_hir_function(restored->hir) == serialize_hir_function(first.artifacts->hir),
            "HIR serialization is not byte-stable after artifact round trip");
        require(serialize_type_graph(restored->type_graph) == serialize_type_graph(first.artifacts->type_graph),
            "type graph serialization is not byte-stable after artifact round trip");
        require(std::any_of(first.artifacts->type_graph.edges.begin(), first.artifacts->type_graph.edges.end(),
            [](const decompiler_type_edge_t& edge) {
                return edge.kind == decompiler_type_edge_kind_t::pointee && edge.source_type_id == 3 &&
                    edge.target_type_id == 1 && edge.stable_name == "pointee";
            }), "typed artifact normalization dropped the provider type edge");
        const auto local = std::find_if(first.artifacts->hir.blocks.front().values.begin(),
            first.artifacts->hir.blocks.front().values.end(), [](const hir_value_t& value) {
                return value.id == 2 && value.kind == hir_node_kind_t::local &&
                    value.stable_value == "defined_output";
            });
        require(local != first.artifacts->hir.blocks.front().values.end(),
            "typed artifact normalization dropped the defined output varnode");
    }
}

void verify_unsupported_pcode()
{
    auto source = fixture("x86:LE:64:default", architecture_id_t::x86_64, architecture_mode_t::x86_64, endian_t::little);
    source.blocks.front().values[2].pcode_opcode = k_pcode_callother;
    const auto result = ghidra_ir_adapter::normalize(source);
    require(result.succeeded(), "unknown p-code must remain representable in typed artifacts");
    require(!result.artifacts->provider_ir.unknowns.empty(), "unknown p-code is missing an explicit unknown record");
    require(!result.artifacts->provider_ir.diagnostics.empty(), "unknown p-code is missing an explicit diagnostic");
    require(result.artifacts->provider_ir.diagnostics.front().code == decompiler_diagnostic_code_t::unsupported_provider,
        "unknown p-code emitted the wrong diagnostic code");
}

void verify_native_liveness_and_lossless_provider_ir()
{
    const auto source = liveness_fixture();
    const auto result = ghidra_ir_adapter::normalize(source);
    require(result.succeeded(), "native liveness fixture did not normalize");
    const auto& artifacts = *result.artifacts;
    require(validate_provider_ir(artifacts.provider_ir).valid(), "native liveness provider IR is invalid");
    require(validate_hir_function(artifacts.hir).valid(), "native liveness HIR is invalid");
    require(validate_type_graph(artifacts.type_graph).valid(), "native liveness type graph is invalid");

    std::size_t source_value_count = 0;
    for (const auto& block : source.blocks) {
        source_value_count += block.values.size();
        for (const auto& value : block.values) {
            const auto* provider_value = find_provider_value(artifacts.provider_ir, value.id);
            require(provider_value != nullptr, "provider IR pruned a captured value");
            require(provider_value->operand_ids == value.operand_ids,
                "provider IR changed captured operands");
            require(provider_value->stable_immediate == value.stable_immediate,
                "provider IR changed a captured immediate");
            require(provider_value->stable_symbol == value.stable_symbol,
                "provider IR changed a captured symbol");
        }
    }
    require(provider_value_count(artifacts.provider_ir) == source_value_count,
        "provider IR value count is not lossless");

    const std::vector<std::uint64_t> retained_ids = {
        1, 3, 5, 9, 11, 12, 14, 16, 17, 18, 19, 20, 21, 30, 31, 41, 50
    };
    for (const auto id : retained_ids)
        require(find_hir_value(artifacts.hir, id) != nullptr, "HIR dropped a required liveness root or dependency");
    const std::vector<std::uint64_t> removed_ids = {2, 4, 6, 7, 8, 10, 13, 15, 22, 23, 24, 25, 26, 40};
    for (const auto id : removed_ids)
        require(find_hir_value(artifacts.hir, id) == nullptr, "HIR retained a dead pure native value");

    const std::array<std::pair<std::uint16_t, std::uint64_t>, 7> unsupported = {{
        {k_pcode_multiequal, 18},
        {k_pcode_subpiece, 19},
        {k_pcode_callother, 20},
        {k_pcode_branchind, 41},
        {k_pcode_multiequal, 24},
        {k_pcode_subpiece, 25},
        {k_pcode_future_unsupported, 26}
    }};
    for (const auto& [opcode, id] : unsupported) {
        const auto token = "ghidra.pcode." + std::to_string(opcode) + "." + std::to_string(id);
        const auto* provider_unknown = find_unknown_token(artifacts.provider_ir.unknowns, token);
        require(provider_unknown != nullptr,
            "unsupported normalized p-code is missing its provider unknown");
        require(provider_unknown->reason == decompiler_unknown_reason_t::unsupported_instruction &&
                provider_unknown->coordinate.layer == decompiler_coordinate_layer_t::provider_ir &&
                provider_unknown->confidence == 0 &&
                provider_unknown->provenance == decompiler_fact_provenance_t::provider_semantics,
            "unsupported normalized p-code provider evidence is incoherent");
    }
    const std::array<std::pair<std::uint16_t, std::uint64_t>, 4> live_unsupported = {{
        {k_pcode_multiequal, 18},
        {k_pcode_subpiece, 19},
        {k_pcode_callother, 20},
        {k_pcode_branchind, 41}
    }};
    for (const auto& [opcode, id] : live_unsupported) {
        const auto token = "ghidra.pcode." + std::to_string(opcode) + "." + std::to_string(id);
        const auto* hir_unknown = find_unknown_token(artifacts.hir.unknowns, token);
        require(hir_unknown != nullptr &&
                hir_unknown->reason == decompiler_unknown_reason_t::unsupported_instruction &&
                hir_unknown->coordinate.layer == decompiler_coordinate_layer_t::hir &&
                hir_unknown->confidence == 0 &&
                hir_unknown->provenance == decompiler_fact_provenance_t::provider_semantics,
            "live unsupported normalized p-code is missing coherent HIR unknown evidence");
    }
    for (const auto& [opcode, id] : std::array<std::pair<std::uint16_t, std::uint64_t>, 3>{{
            {k_pcode_multiequal, 24},
            {k_pcode_subpiece, 25},
            {k_pcode_future_unsupported, 26}}}) {
        const auto token = "ghidra.pcode." + std::to_string(opcode) + "." + std::to_string(id);
        require(find_unknown_token(artifacts.hir.unknowns, token) == nullptr,
            "dead unsupported dependency island leaked unknown evidence into HIR");
    }
    require(std::count_if(artifacts.provider_ir.diagnostics.begin(), artifacts.provider_ir.diagnostics.end(),
                [](const decompiler_diagnostic_t& value) {
                    return value.code == decompiler_diagnostic_code_t::unsupported_provider;
                }) == static_cast<std::ptrdiff_t>(unsupported.size()) &&
            std::count_if(artifacts.hir.diagnostics.begin(), artifacts.hir.diagnostics.end(),
                [](const decompiler_diagnostic_t& value) {
                    return value.code == decompiler_diagnostic_code_t::unsupported_provider;
                }) == static_cast<std::ptrdiff_t>(live_unsupported.size()),
        "unsupported normalized p-code diagnostics do not match provider and live-HIR scopes");
    for (const auto id : {std::uint64_t{18}, std::uint64_t{19}, std::uint64_t{20}, std::uint64_t{41}}) {
        const auto* value = find_hir_value(artifacts.hir, id);
        require(value != nullptr && value->kind == hir_node_kind_t::unknown &&
                value->operand_ids.empty() && value->confidence == 0,
            "live unsupported p-code is not a coherent retained HIR unknown");
    }
    require(std::none_of(artifacts.hir.blocks.begin(), artifacts.hir.blocks.end(),
        [](const hir_block_t& block) {
            return std::any_of(block.values.begin(), block.values.end(),
                [](const hir_value_t& value) { return value.type_id == 6; });
        }), "dead unsupported dependency island leaked values into HIR type work");
    require(find_provider_value(artifacts.provider_ir, 18)->opcode == provider_ir_opcode_t::phi,
        "MULTIEQUAL did not retain its provider opcode classification");
    require(find_provider_value(artifacts.provider_ir, 19)->opcode == provider_ir_opcode_t::cast,
        "SUBPIECE did not retain its provider opcode classification");
    require(find_provider_value(artifacts.provider_ir, 41)->opcode == provider_ir_opcode_t::switch_branch,
        "BRANCHIND did not retain its provider opcode classification");
    require(has_unknown_token(artifacts.provider_ir.unknowns, "ghidra.call.unresolved.14") &&
            has_unknown_token(artifacts.hir.unknowns, "ghidra.call.unresolved.14"),
        "unresolved native call evidence is not coherent across provider IR and HIR");

    require(artifacts.hir.parameters.size() == 1 && artifacts.hir.parameters.front().stable_name == "arg0",
        "native parameter high variable was not retained");
    require(std::any_of(artifacts.hir.locals.begin(), artifacts.hir.locals.end(),
        [](const hir_variable_t& local) { return local.stable_name == "descriptive_name"; }),
        "named native high variable was not retained");
    require(std::any_of(artifacts.hir.locals.begin(), artifacts.hir.locals.end(),
        [](const hir_variable_t& local) { return local.stable_name == "local_4"; }),
        "live generated native high variable was not retained");
    require(std::none_of(artifacts.hir.locals.begin(), artifacts.hir.locals.end(),
        [](const hir_variable_t& local) {
            return local.stable_name == "local_2" || local.stable_name == "local_5" ||
                local.stable_name == "local_6";
        }), "dead generated native high variables were retained");

    const auto unknown_width = std::find_if(artifacts.type_graph.nodes.begin(), artifacts.type_graph.nodes.end(),
        [](const decompiler_type_node_t& node) { return node.canonical_name == "undefined4"; });
    require(unknown_width != artifacts.type_graph.nodes.end() &&
            unknown_width->kind == decompiler_type_kind_t::unknown &&
            unknown_width->byte_size.has_value() && *unknown_width->byte_size == 4 &&
            unknown_width->confidence == 40,
        "sized native unknown type lost its width or confidence");
}

void verify_native_order_and_hash_determinism()
{
    const auto canonical_source = liveness_fixture();
    auto reordered_source = canonical_source;
    std::reverse(reordered_source.types.begin(), reordered_source.types.end());
    std::reverse(reordered_source.blocks.begin(), reordered_source.blocks.end());
    std::reverse(reordered_source.high_variables.begin(), reordered_source.high_variables.end());
    for (auto& block : reordered_source.blocks) {
        std::reverse(block.predecessor_ids.begin(), block.predecessor_ids.end());
        std::reverse(block.successor_ids.begin(), block.successor_ids.end());
        std::reverse(block.exception_successor_ids.begin(), block.exception_successor_ids.end());
        std::reverse(block.values.begin(), block.values.end());
    }

    const auto canonical = ghidra_ir_adapter::normalize(canonical_source);
    const auto reordered = ghidra_ir_adapter::normalize(reordered_source);
    require(canonical.succeeded() && reordered.succeeded(),
        "native order determinism fixture did not normalize");
    require(serialize_provider_ir(canonical.artifacts->provider_ir) ==
            serialize_provider_ir(reordered.artifacts->provider_ir),
        "provider IR serialization depends on capture collection order");
    require(serialize_hir_function(canonical.artifacts->hir) ==
            serialize_hir_function(reordered.artifacts->hir),
        "HIR serialization depends on capture collection order");
    require(serialize_type_graph(canonical.artifacts->type_graph) ==
            serialize_type_graph(reordered.artifacts->type_graph),
        "type graph serialization depends on capture collection order");
    require(stable_serialization_hash(canonical.artifacts->provider_ir) ==
            stable_serialization_hash(reordered.artifacts->provider_ir) &&
            stable_serialization_hash(canonical.artifacts->hir) ==
            stable_serialization_hash(reordered.artifacts->hir) &&
            stable_serialization_hash(canonical.artifacts->type_graph) ==
            stable_serialization_hash(reordered.artifacts->type_graph),
        "native normalized artifact hashes depend on capture collection order");
}

void verify_invalid_capture()
{
    auto source = fixture("x86:LE:64:default", architecture_id_t::x86_64, architecture_mode_t::x86_64, endian_t::little);
    source.blocks.front().values.clear();
    const auto result = ghidra_ir_adapter::normalize(source);
    require(!result.succeeded() && !result.diagnostics.empty(), "empty p-code block must fail closed");
}

ghidra_ir_adapter::capture_request_t arch_session_request()
{
    auto source = fixture("x86:LE:64:default", architecture_id_t::x86_64,
        architecture_mode_t::x86_64, endian_t::little);
    auto request = source.request;
    request.return_type_id = 0;
    return request;
}

void verify_arch_session_equivalence()
{
    const std::vector<std::uint8_t> function_bytes{
        0x55, 0x48, 0x89, 0xE5, 0xB8, 0x05, 0x00, 0x00,
        0x00, 0x83, 0xC0, 0x03, 0x5D, 0xC3};
    const std::uint64_t image_base = 0x140000000ULL;
    const std::uint64_t image_size = 0x2000;
    const std::uint64_t entry_addr = image_base + 0x1000;
    const auto request = arch_session_request();
    require(validate_decompiler_entity_key(request.entity).valid(),
        "arch session fixture entity is invalid");
    ghidra_decompiler::ghidra_decompile_result_limits_t limits;
    const auto make_regions = [&]() {
        std::vector<aida_ghidra::region_t> regions;
        aida_ghidra::region_t region;
        region.start_va = entry_addr;
        region.data = function_bytes;
        regions.push_back(std::move(region));
        return regions;
    };
    const auto fresh = ghidra_decompiler::decompile_isolated_regions(
        make_regions(), image_base, image_size, entry_addr, "x86:LE:64:default",
        architecture_mode_t::x86_64, nullptr, std::nullopt, limits, request);
    require(!fresh.is_error && fresh.typed_artifacts.has_value(),
        "fresh isolated-region decompilation failed: " + fresh.error_text);
    require(!fresh.typed_artifacts->hir.blocks.empty(),
        "fresh isolated-region decompilation produced an empty HIR");

    ghidra_decompiler::arch_pool_key_t key;
    key.language_id = request.language.language_id;
    key.compiler_spec_id = request.language.compiler_spec_id;
    key.architecture_mode = request.language.mode;
    key.endian = request.language.endian;
    key.snapshot_hash = stable_serialization_hash("arch-session-equivalence");
    auto created = ghidra_decompiler::make_arch_session_entry(
        make_regions(), image_base, image_size, key, false);
    require(created.ok && created.entry,
        "arch session entry creation failed: " + created.error_text);
    const auto reuse_first = ghidra_decompiler::decompile_isolated_regions_reusing(
        *created.entry, entry_addr, nullptr, std::nullopt, limits, request);
    require(!reuse_first.is_error && reuse_first.typed_artifacts.has_value(),
        "first session-reuse decompilation failed: " + reuse_first.error_text);
    const auto reuse_second = ghidra_decompiler::decompile_isolated_regions_reusing(
        *created.entry, entry_addr, nullptr, std::nullopt, limits, request);
    require(!reuse_second.is_error && reuse_second.typed_artifacts.has_value(),
        "second session-reuse decompilation failed: " + reuse_second.error_text);
    require(created.entry->jobs_completed == 2,
        "arch session reuse did not execute both decompilations on the pooled session");

    const auto fresh_serialized = ghidra_ir_adapter::serialize_artifacts(*fresh.typed_artifacts);
    const auto reuse_first_serialized =
        ghidra_ir_adapter::serialize_artifacts(*reuse_first.typed_artifacts);
    const auto reuse_second_serialized =
        ghidra_ir_adapter::serialize_artifacts(*reuse_second.typed_artifacts);
    require(!fresh_serialized.empty() && fresh_serialized == reuse_first_serialized &&
            reuse_first_serialized == reuse_second_serialized,
        "fresh and session-reuse typed artifacts are not byte-identical");
    require(stable_serialization_hash(fresh.typed_artifacts->provider_ir) ==
            stable_serialization_hash(reuse_first.typed_artifacts->provider_ir) &&
            stable_serialization_hash(reuse_first.typed_artifacts->provider_ir) ==
            stable_serialization_hash(reuse_second.typed_artifacts->provider_ir),
        "provider IR diverged between fresh and session-reuse decompilation");
    require(stable_serialization_hash(fresh.typed_artifacts->hir) ==
            stable_serialization_hash(reuse_first.typed_artifacts->hir) &&
            stable_serialization_hash(reuse_first.typed_artifacts->hir) ==
            stable_serialization_hash(reuse_second.typed_artifacts->hir),
        "HIR diverged between fresh and session-reuse decompilation");
    require(stable_serialization_hash(fresh.typed_artifacts->type_graph) ==
            stable_serialization_hash(reuse_first.typed_artifacts->type_graph) &&
            stable_serialization_hash(reuse_first.typed_artifacts->type_graph) ==
            stable_serialization_hash(reuse_second.typed_artifacts->type_graph),
        "type graph diverged between fresh and session-reuse decompilation");
}

}

void run_ghidra_ir_adapter_harness()
{
    verify_supported_languages();
    verify_unsupported_pcode();
    verify_native_liveness_and_lossless_provider_ir();
    verify_native_order_and_hash_determinism();
    verify_invalid_capture();
    verify_arch_session_equivalence();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_ghidra_ir_adapter_harness();
        std::cout << "ghidra_ir_adapter_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
