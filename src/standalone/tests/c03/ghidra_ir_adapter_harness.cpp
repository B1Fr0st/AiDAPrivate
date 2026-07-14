#include "ghidra_ir_adapter_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/providers/ghidra_ir_adapter.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>

namespace aida::analysis::c03_test {
namespace {

using ghidra_ir_adapter::capture_block_t;
using ghidra_ir_adapter::capture_high_variable_t;
using ghidra_ir_adapter::capture_t;
using ghidra_ir_adapter::capture_type_t;
using ghidra_ir_adapter::capture_value_kind_t;
using ghidra_ir_adapter::capture_value_t;

constexpr std::uint16_t k_pcode_call = 7;
constexpr std::uint16_t k_pcode_callother = 9;
constexpr std::uint16_t k_pcode_return = 10;
constexpr std::uint16_t k_pcode_int_add = 19;

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

void verify_invalid_capture()
{
    auto source = fixture("x86:LE:64:default", architecture_id_t::x86_64, architecture_mode_t::x86_64, endian_t::little);
    source.blocks.front().values.clear();
    const auto result = ghidra_ir_adapter::normalize(source);
    require(!result.succeeded() && !result.diagnostics.empty(), "empty p-code block must fail closed");
}

}

void run_ghidra_ir_adapter_harness()
{
    verify_supported_languages();
    verify_unsupported_pcode();
    verify_invalid_capture();
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
