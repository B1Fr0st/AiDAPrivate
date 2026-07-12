#include "dalvik_ssa_harness.hpp"

#include "../../src/core/analysis/decompiler/providers/dalvik_ssa.hpp"
#include "../../src/core/analysis/decompiler/decompiler_contracts.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using dalvik_ssa::dalvik_ssa_capture_t;
using dalvik_ssa::dalvik_ssa_request_t;
using dalvik_ssa::dalvik_ssa_result_t;
using dalvik_ssa::dalvik_ssa_typed_artifacts_t;

void require(const bool condition, const std::string& message)
{
    if (!condition)
        throw std::runtime_error(message);
}

dalvik_instruction_t make_insn(std::uint32_t offset, std::uint8_t opcode,
                                std::uint16_t width, std::uint16_t opcode_unit,
                                const char* mnemonic)
{
    dalvik_instruction_t insn;
    insn.code_unit_offset = offset;
    insn.file_offset = offset * 2;
    insn.opcode_unit = opcode_unit;
    insn.opcode = opcode;
    insn.width_code_units = width;
    insn.mnemonic = mnemonic;
    insn.payload = false;
    insn.reference_kind = dalvik_reference_kind_t::none;
    return insn;
}

dalvik_instruction_t make_insn_ref(std::uint32_t offset, std::uint8_t opcode,
                                    std::uint16_t width, std::uint16_t opcode_unit,
                                    const char* mnemonic,
                                    dalvik_reference_kind_t ref_kind,
                                    std::uint32_t ref_index)
{
    auto insn = make_insn(offset, opcode, width, opcode_unit, mnemonic);
    insn.reference_kind = ref_kind;
    insn.reference_index = ref_index;
    return insn;
}

dalvik_instruction_t make_insn_lit(std::uint32_t offset, std::uint8_t opcode,
                                    std::uint16_t width, std::uint16_t opcode_unit,
                                    const char* mnemonic,
                                    std::int64_t literal)
{
    auto insn = make_insn(offset, opcode, width, opcode_unit, mnemonic);
    insn.literal = literal;
    return insn;
}

dalvik_instruction_t make_insn_branch(std::uint32_t offset, std::uint8_t opcode,
                                       std::uint16_t width, std::uint16_t opcode_unit,
                                       const char* mnemonic,
                                       std::int32_t target)
{
    auto insn = make_insn(offset, opcode, width, opcode_unit, mnemonic);
    insn.branch_target = target;
    return insn;
}

dalvik_instruction_t make_insn_payload(std::uint32_t offset, std::uint16_t width,
                                        std::uint16_t opcode_unit,
                                        const char* mnemonic)
{
    auto insn = make_insn(offset, 0x00, width, opcode_unit, mnemonic);
    insn.payload = true;
    return insn;
}

dalvik_ssa_request_t make_request(const std::string& dex_version)
{
    dalvik_ssa_request_t request;
    request.provider.provider = decompiler_provider_id_t::dalvik_ssa;
    request.provider.provider_name = "aida-dalvik-ssa";
    request.provider.provider_version = "1";
    request.provider.provider_binary_hash = stable_serialization_hash("dalvik-ssa-harness-provider");
    request.provider.worker_build_id = "dalvik-ssa-harness";
    request.provider.worker_build_hash = stable_serialization_hash("dalvik-ssa-harness-build");
    request.language.language_id = "dalvik";
    request.language.language_version = dex_version;
    request.language.compiler_spec_id = "dalvik";
    request.language.language_spec_hash = stable_serialization_hash("dalvik:" + dex_version);
    request.language.architecture = architecture_id_t::dalvik_bytecode;
    request.language.mode = architecture_mode_t::dalvik;
    request.language.endian = endian_t::little;
    request.workspace_generation = 7;
    request.type_graph_revision = 11;
    request.return_type_id = 0;
    request.dex_version = dex_version;

    dalvik_decompiler_entity_identity_t identity;
    identity.dex_hash = stable_serialization_hash("dalvik-ssa-harness-dex-" + dex_version);
    identity.dex_ordinal = 0;
    identity.class_descriptor = "Lcom/test/TestClass;";
    identity.method_name = "testMethod";
    identity.prototype = "(II)I";
    identity.method_id = 0;
    identity.code_item_offset = 0;

    request.entity.kind = decompiler_entity_kind_t::dalvik_method;
    request.entity.format = format_id_t::dex;
    request.entity.architecture = architecture_id_t::dalvik_bytecode;
    request.entity.mode = architecture_mode_t::dalvik;
    request.entity.endian = endian_t::little;
    request.entity.identity = std::move(identity);
    return request;
}

std::shared_ptr<dex_code_item_t> make_code_item(
    std::uint16_t registers_size, std::uint16_t ins_size, std::uint16_t outs_size,
    std::vector<dalvik_instruction_t> instructions,
    std::vector<dex_try_item_t> tries = {},
    std::vector<dex_catch_handler_t> catch_handlers = {},
    std::optional<dex_debug_info_t> debug_info = std::nullopt)
{
    auto code = std::make_shared<dex_code_item_t>();
    code->offset = 0;
    code->registers_size = registers_size;
    code->ins_size = ins_size;
    code->outs_size = outs_size;
    code->tries_size = static_cast<std::uint16_t>(tries.size());
    code->debug_info_offset = 0;
    code->instruction_count = static_cast<std::uint32_t>(instructions.size());
    code->instructions = std::move(instructions);
    code->tries = std::move(tries);
    code->catch_handlers = std::move(catch_handlers);
    code->debug_info = std::move(debug_info);
    return code;
}

dalvik_ssa_capture_t make_base_capture(const std::string& dex_version)
{
    dalvik_ssa_capture_t capture;
    capture.request = make_request(dex_version);
    capture.method_id = 0;
    capture.class_descriptor = "Lcom/test/TestClass;";
    capture.method_name = "testMethod";
    capture.prototype = "(II)I";
    capture.shorty = "III";

    dex_method_t method;
    method.index = 0;
    method.class_type_index = 0;
    method.proto_index = 0;
    method.name_string_index = 0;
    method.class_descriptor = "Lcom/test/TestClass;";
    method.name = "testMethod";
    method.descriptor = "(II)I";
    capture.methods.push_back(std::move(method));

    dex_type_t type;
    type.index = 0;
    type.descriptor_string_index = 0;
    type.descriptor = "Lcom/test/TestClass;";
    capture.types.push_back(std::move(type));

    dex_proto_t proto;
    proto.index = 0;
    proto.shorty_string_index = 0;
    proto.return_type_index = 0;
    proto.parameters_offset = 0;
    proto.shorty = "III";
    proto.descriptor = "(II)I";
    proto.parameter_type_indices = {1, 2};
    capture.protos.push_back(std::move(proto));

    dex_type_t int_type;
    int_type.index = 1;
    int_type.descriptor = "I";
    capture.types.push_back(std::move(int_type));

    dex_type_t int_type2;
    int_type2.index = 2;
    int_type2.descriptor = "I";
    capture.types.push_back(std::move(int_type2));

    dex_string_t str;
    str.index = 0;
    str.value = "testMethod";
    capture.strings.push_back(std::move(str));

    return capture;
}

void verify_dex_versions()
{
    const std::array<const char*, 6> versions = {"035", "037", "038", "039", "040", "041"};
    for (const auto* version : versions) {
        auto capture = make_base_capture(version);
        std::vector<std::uint16_t> code_units = {0x0012, 0x000f};
        std::vector<dalvik_instruction_t> insns = {
            make_insn_lit(0, 0x12, 1, 0x0012, "const/4", 0),
            make_insn(1, 0x0f, 1, 0x000f, "return")
        };
        capture.code_item = make_code_item(2, 0, 0, std::move(insns));
        capture.code_units = std::move(code_units);

        const auto first = dalvik_ssa::normalize(capture);
        require(first.succeeded(), std::string("DEX version ") + version + " failed to produce artifacts");
        require(!first.artifacts->provider_ir.blocks.empty(), std::string("DEX version ") + version + " produced empty provider IR");
        require(!first.artifacts->hir.blocks.empty(), std::string("DEX version ") + version + " produced empty HIR");
        require(first.artifacts->type_graph.revision == 11, std::string("DEX version ") + version + " type graph revision mismatch");
        require(first.artifacts->provider_ir.provider.provider == decompiler_provider_id_t::dalvik_ssa,
            std::string("DEX version ") + version + " provider ID mismatch");
    }
}

void verify_range_invoke()
{
    auto capture = make_base_capture("038");
    std::vector<std::uint16_t> code_units;
    std::vector<dalvik_instruction_t> insns;

    code_units.push_back(0x0374);
    code_units.push_back(0x0000);
    code_units.push_back(0x0000);
    insns.push_back(make_insn_ref(0, 0x74, 3, 0x0374, "invoke-virtual/range",
        dalvik_reference_kind_t::method, 0));

    code_units.push_back(0x000a);
    insns.push_back(make_insn(3, 0x0a, 1, 0x000a, "move-result"));

    code_units.push_back(0x000f);
    insns.push_back(make_insn(4, 0x0f, 1, 0x000f, "return"));

    capture.code_item = make_code_item(4, 0, 3, std::move(insns));
    capture.code_units = std::move(code_units);

    const auto result = dalvik_ssa::normalize(capture);
    require(result.succeeded(), "invoke-range failed to produce artifacts");
    require(result.artifacts->provider_ir.blocks.size() >= 1, "invoke-range produced no blocks");
    const auto& hir = result.artifacts->hir;
    bool found_call = false;
    for (const auto& block : hir.blocks) {
        for (const auto& value : block.values) {
            if (value.kind == hir_node_kind_t::call) {
                found_call = true;
                break;
            }
        }
    }
    require(found_call, "invoke-range did not produce a call HIR node");
}

void verify_payload_alignment()
{
    auto capture = make_base_capture("035");

    std::vector<std::uint16_t> code_units;
    std::vector<dalvik_instruction_t> insns;

    code_units.push_back(0x0012);
    insns.push_back(make_insn_lit(0, 0x12, 1, 0x0012, "const/4", 0));

    code_units.push_back(0x002b);
    code_units.push_back(0x0007);
    code_units.push_back(0x0000);
    insns.push_back(make_insn_branch(1, 0x2b, 3, 0x002b, "packed-switch", 8));

    code_units.push_back(0x000e);
    insns.push_back(make_insn(4, 0x0e, 1, 0x000e, "return-void"));

    code_units.push_back(0x0112);
    insns.push_back(make_insn_lit(5, 0x12, 1, 0x0112, "const/4", 1));

    code_units.push_back(0x010f);
    insns.push_back(make_insn(6, 0x0f, 1, 0x010f, "return"));

    while (code_units.size() < 8) code_units.push_back(0x0000);
    code_units.push_back(0x0100);
    code_units.push_back(0x0002);
    code_units.push_back(0x0000);
    code_units.push_back(0x0000);
    code_units.push_back(0x0004);
    code_units.push_back(0x0000);
    code_units.push_back(0x0005);
    code_units.push_back(0x0000);
    insns.push_back(make_insn_payload(8, 8, 0x0100, "packed-switch-payload"));

    capture.code_item = make_code_item(4, 0, 0, std::move(insns));
    capture.code_units = std::move(code_units);

    const auto result = dalvik_ssa::normalize(capture);
    require(result.succeeded(), "packed-switch payload alignment failed to produce artifacts");
    require(result.artifacts->provider_ir.blocks.size() >= 2, "packed-switch produced too few blocks");

    bool found_switch = false;
    for (const auto& block : result.artifacts->hir.blocks) {
        for (const auto& value : block.values) {
            if (value.kind == hir_node_kind_t::switch_branch) {
                found_switch = true;
                break;
            }
        }
    }
    require(found_switch, "packed-switch did not produce a switch_branch HIR node");
}

void verify_wide_registers()
{
    auto capture = make_base_capture("035");

    std::vector<std::uint16_t> code_units;
    std::vector<dalvik_instruction_t> insns;

    code_units.push_back(0x0018);
    code_units.push_back(0x002A);
    code_units.push_back(0x0000);
    code_units.push_back(0x0000);
    code_units.push_back(0x0000);
    insns.push_back(make_insn_lit(0, 0x18, 5, 0x0018, "const-wide", 42));

    code_units.push_back(0x0218);
    code_units.push_back(0x000A);
    code_units.push_back(0x0000);
    code_units.push_back(0x0000);
    code_units.push_back(0x0000);
    insns.push_back(make_insn_lit(5, 0x18, 5, 0x0218, "const-wide", 10));

    code_units.push_back(0x009b);
    code_units.push_back(0x0200);
    insns.push_back(make_insn(10, 0x9b, 2, 0x009b, "add-long"));

    code_units.push_back(0x0010);
    insns.push_back(make_insn(12, 0x10, 1, 0x0010, "return-wide"));

    capture.code_item = make_code_item(6, 0, 0, std::move(insns));
    capture.code_units = std::move(code_units);

    const auto result = dalvik_ssa::normalize(capture);
    require(result.succeeded(), "wide register test failed to produce artifacts");
    require(!result.artifacts->hir.blocks.empty(), "wide register test produced empty HIR");
    require(result.artifacts->type_graph.nodes.size() >= 2, "wide register test produced too few type nodes");

    bool found_wide_type = false;
    for (const auto& node : result.artifacts->type_graph.nodes) {
        if (node.canonical_name == "J" && node.byte_size && *node.byte_size == 8) {
            found_wide_type = true;
            break;
        }
    }
    require(found_wide_type, "wide register test missing long type node");
}

void verify_try_catch()
{
    auto capture = make_base_capture("035");

    std::vector<std::uint16_t> code_units;
    std::vector<dalvik_instruction_t> insns;

    code_units.push_back(0x0012);
    insns.push_back(make_insn_lit(0, 0x12, 1, 0x0012, "const/4", 0));

    code_units.push_back(0x0112);
    insns.push_back(make_insn_lit(1, 0x12, 1, 0x0112, "const/4", 1));

    code_units.push_back(0x000f);
    insns.push_back(make_insn(2, 0x0f, 1, 0x000f, "return"));

    code_units.push_back(0x010d);
    insns.push_back(make_insn(3, 0x0d, 1, 0x010d, "move-exception"));

    code_units.push_back(0x010f);
    insns.push_back(make_insn(4, 0x0f, 1, 0x010f, "return"));

    std::vector<dex_try_item_t> tries;
    dex_try_item_t try_item;
    try_item.start_address = 0;
    try_item.instruction_count = 2;
    try_item.handler_offset = 0;
    tries.push_back(try_item);

    std::vector<dex_catch_handler_t> handlers;
    dex_catch_handler_t handler;
    handler.relative_offset = 0;
    handler.typed_handlers.push_back({0, 3});
    handler.catch_all_address = std::nullopt;
    handlers.push_back(handler);

    capture.code_item = make_code_item(4, 0, 0, std::move(insns),
        std::move(tries), std::move(handlers));
    capture.code_units = std::move(code_units);

    const auto result = dalvik_ssa::normalize(capture);
    require(result.succeeded(), "try/catch test failed to produce artifacts");

    bool has_exception_edge = false;
    for (const auto& block : result.artifacts->provider_ir.blocks) {
        if (!block.exception_successor_ids.empty()) {
            has_exception_edge = true;
            break;
        }
    }
    require(has_exception_edge, "try/catch test missing exception successor edges");
}

void verify_malformed_indexes()
{
    auto capture = make_base_capture("035");

    std::vector<std::uint16_t> code_units;
    std::vector<dalvik_instruction_t> insns;

    code_units.push_back(0x001a);
    code_units.push_back(0xFFFF);
    insns.push_back(make_insn_ref(0, 0x1a, 2, 0x001a, "const-string",
        dalvik_reference_kind_t::string, 0xFFFF));

    code_units.push_back(0x000f);
    insns.push_back(make_insn(2, 0x0f, 1, 0x000f, "return"));

    capture.code_item = make_code_item(2, 0, 0, std::move(insns));
    capture.code_units = std::move(code_units);

    const auto result = dalvik_ssa::normalize(capture);
    require(result.succeeded(), "malformed index test should still produce artifacts");
    bool has_diagnostic = false;
    for (const auto& diag : result.diagnostics) {
        if (diag.code == decompiler_diagnostic_code_t::unresolved_symbol ||
            diag.code == decompiler_diagnostic_code_t::unresolved_type) {
            has_diagnostic = true;
            break;
        }
    }
    require(has_diagnostic, "malformed string index should produce a diagnostic");
}

void verify_deterministic_ssa()
{
    auto capture = make_base_capture("038");

    std::vector<std::uint16_t> code_units;
    std::vector<dalvik_instruction_t> insns;

    code_units.push_back(0x0012);
    insns.push_back(make_insn_lit(0, 0x12, 1, 0x0012, "const/4", 0));

    code_units.push_back(0x0038);
    code_units.push_back(0x0003);
    insns.push_back(make_insn_branch(1, 0x38, 2, 0x0038, "if-eqz", 4));

    code_units.push_back(0x1012);
    insns.push_back(make_insn_lit(3, 0x12, 1, 0x1012, "const/4", 1));

    code_units.push_back(0x000f);
    insns.push_back(make_insn(4, 0x0f, 1, 0x000f, "return"));

    capture.code_item = make_code_item(4, 0, 0, std::move(insns));
    capture.code_units = std::move(code_units);

    const auto first = dalvik_ssa::normalize(capture);
    const auto second = dalvik_ssa::normalize(capture);
    require(first.succeeded() && second.succeeded(), "deterministic SSA test failed to produce artifacts");
    require(stable_serialization_hash(first.artifacts->provider_ir) == stable_serialization_hash(second.artifacts->provider_ir),
        "provider IR is not deterministic");
    require(stable_serialization_hash(first.artifacts->hir) == stable_serialization_hash(second.artifacts->hir),
        "HIR is not deterministic");
    require(stable_serialization_hash(first.artifacts->type_graph) == stable_serialization_hash(second.artifacts->type_graph),
        "type graph is not deterministic");

    const auto bytes = dalvik_ssa::serialize_artifacts(*first.artifacts);
    require(!bytes.empty(), "artifact serialization returned empty payload");
    std::vector<decompiler_diagnostic_t> diag;
    const auto restored = dalvik_ssa::deserialize_artifacts(bytes, diag);
    require(restored.has_value() && diag.empty(), "artifact round-trip failed");
    require(stable_serialization_hash(restored->provider_ir) == stable_serialization_hash(first.artifacts->provider_ir),
        "round-trip changed provider IR");
    require(stable_serialization_hash(restored->hir) == stable_serialization_hash(first.artifacts->hir),
        "round-trip changed HIR");
    require(stable_serialization_hash(restored->type_graph) == stable_serialization_hash(first.artifacts->type_graph),
        "round-trip changed type graph");

    bool has_phi = false;
    for (const auto& block : first.artifacts->hir.blocks) {
        for (const auto& value : block.values) {
            if (value.kind == hir_node_kind_t::phi) {
                has_phi = true;
                break;
            }
        }
    }
    require(has_phi, "deterministic SSA test with conditional branch did not produce phi nodes");

    bool has_conditional = false;
    for (const auto& block : first.artifacts->hir.blocks) {
        for (const auto& value : block.values) {
            if (value.kind == hir_node_kind_t::conditional) {
                has_conditional = true;
                break;
            }
        }
    }
    require(has_conditional, "deterministic SSA test missing conditional branch HIR node");
}

void verify_format_table()
{
    require(dalvik_ssa::instruction_format(0x00) == dalvik_ssa::dalvik_format_t::f10x, "nop format mismatch");
    require(dalvik_ssa::instruction_format(0x12) == dalvik_ssa::dalvik_format_t::f11n, "const/4 format mismatch");
    require(dalvik_ssa::instruction_format(0x74) == dalvik_ssa::dalvik_format_t::f3rc, "invoke-virtual/range format mismatch");
    require(dalvik_ssa::instruction_format(0x18) == dalvik_ssa::dalvik_format_t::f51l, "const-wide format mismatch");
    require(dalvik_ssa::instruction_format(0x2b) == dalvik_ssa::dalvik_format_t::f31t, "packed-switch format mismatch");
    require(dalvik_ssa::instruction_format(0x90) == dalvik_ssa::dalvik_format_t::f23x, "add-int format mismatch");
    require(dalvik_ssa::instruction_format(0xb0) == dalvik_ssa::dalvik_format_t::f12x, "add-int/2addr format mismatch");
    require(dalvik_ssa::instruction_format(0x6e) == dalvik_ssa::dalvik_format_t::f35c, "invoke-virtual format mismatch");
    require(dalvik_ssa::instruction_format(0x28) == dalvik_ssa::dalvik_format_t::f10t, "goto format mismatch");
    require(dalvik_ssa::instruction_format(0x38) == dalvik_ssa::dalvik_format_t::f21t, "if-eqz format mismatch");
    require(dalvik_ssa::instruction_format(0xfa) == dalvik_ssa::dalvik_format_t::f45cc, "invoke-polymorphic format mismatch");
    require(dalvik_ssa::instruction_format(0xfb) == dalvik_ssa::dalvik_format_t::f4rcc, "invoke-polymorphic/range format mismatch");
    require(dalvik_ssa::instruction_format(0x9b) == dalvik_ssa::dalvik_format_t::f23x, "add-long format mismatch");
    require(dalvik_ssa::instruction_format(0xa3) == dalvik_ssa::dalvik_format_t::f23x, "shl-long format mismatch");
    require(dalvik_ssa::instruction_format(0xc3) == dalvik_ssa::dalvik_format_t::f12x, "shl-long/2addr format mismatch");
    require(dalvik_ssa::instruction_format(0xd0) == dalvik_ssa::dalvik_format_t::f22s, "add-int/lit16 format mismatch");
    require(dalvik_ssa::instruction_format(0xd8) == dalvik_ssa::dalvik_format_t::f22b, "add-int/lit8 format mismatch");
    require(dalvik_ssa::instruction_format(0x52) == dalvik_ssa::dalvik_format_t::f22c, "iget format mismatch");
    require(dalvik_ssa::instruction_format(0x60) == dalvik_ssa::dalvik_format_t::f21c, "sget format mismatch");
}

}

void run_dalvik_ssa_harness()
{
    verify_format_table();
    verify_dex_versions();
    verify_range_invoke();
    verify_payload_alignment();
    verify_wide_registers();
    verify_try_catch();
    verify_malformed_indexes();
    verify_deterministic_ssa();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_dalvik_ssa_harness();
        std::cout << "dalvik_ssa_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
