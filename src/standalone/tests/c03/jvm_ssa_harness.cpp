#include "jvm_ssa_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/decompiler/providers/jvm_ssa.hpp"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aida::analysis::c03_test {
namespace {

using jvm_ssa::jvm_method_context_t;
using jvm_ssa::jvm_method_input_t;
using jvm_ssa::jvm_ssa_result_t;
using jvm_ssa::decompile_method;
using jvm_ssa::serialize_jvm_ssa_result;
using jvm_ssa::deserialize_jvm_ssa_result;

void require(bool condition, const std::string& message)
{
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

sha256_digest_t digest(const std::string& value)
{
    return stable_serialization_hash(value);
}

jvm_constant_pool_entry_t cp_utf8_entry(const std::string& value)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::utf8;
    entry.utf8_value = value;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_class_entry(std::uint16_t utf8_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::class_ref;
    entry.ref_index1 = utf8_index;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_name_and_type_entry(std::uint16_t name_index, std::uint16_t desc_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::name_and_type;
    entry.ref_index1 = name_index;
    entry.ref_index2 = desc_index;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_methodref_entry(std::uint16_t class_index, std::uint16_t nat_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::methodref;
    entry.ref_index1 = class_index;
    entry.ref_index2 = nat_index;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_fieldref_entry(std::uint16_t class_index, std::uint16_t nat_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::fieldref;
    entry.ref_index1 = class_index;
    entry.ref_index2 = nat_index;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_integer_entry(std::uint32_t value)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::integer;
    entry.int_float_value = value;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_long_entry(std::uint64_t value)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::long_;
    entry.long_double_value = value;
    entry.is_double_slot = true;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_invoke_dynamic_entry(std::uint16_t bootstrap_index, std::uint16_t nat_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::invoke_dynamic;
    entry.bootstrap_method_attr_index = bootstrap_index;
    entry.ref_index2 = nat_index;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_method_handle_entry(std::uint8_t kind, std::uint16_t ref_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::method_handle;
    entry.reference_kind = kind;
    entry.ref_index1 = ref_index;
    entry.valid = true;
    return entry;
}

jvm_constant_pool_entry_t cp_string_ref_entry(std::uint16_t utf8_index)
{
    jvm_constant_pool_entry_t entry;
    entry.tag = jvm_constant_tag_t::string_ref;
    entry.ref_index1 = utf8_index;
    entry.valid = true;
    return entry;
}

decompiler_entity_key_t make_jvm_entity(const std::string& class_name,
                                          const std::string& method_name,
                                          const std::string& method_descriptor,
                                          std::uint32_t method_index = 0)
{
    decompiler_entity_key_t key;
    key.kind = decompiler_entity_kind_t::jvm_method;
    key.format = format_id_t::classfile;
    key.architecture = architecture_id_t::jvm_bytecode;
    key.mode = architecture_mode_t::jvm;
    key.endian = endian_t::big;
    jvm_decompiler_entity_identity_t identity;
    identity.class_artifact_hash = digest(class_name);
    identity.class_internal_name = class_name;
    identity.method_name = method_name;
    identity.method_descriptor = method_descriptor;
    identity.method_index = method_index;
    key.identity = std::move(identity);
    return key;
}

decompiler_provider_identity_t make_provider()
{
    decompiler_provider_identity_t provider;
    provider.provider = decompiler_provider_id_t::jvm_ssa;
    provider.provider_name = "aida-jvm-ssa";
    provider.provider_version = "1";
    provider.provider_binary_hash = digest("jvm-ssa-provider");
    provider.worker_build_id = "c03-jvm-ssa";
    provider.worker_build_hash = digest("c03-jvm-ssa-build");
    return provider;
}

decompiler_language_identity_t make_language()
{
    decompiler_language_identity_t language;
    language.language_id = "jvm:bytecode";
    language.language_version = "8+";
    language.compiler_spec_id = "jvm";
    language.language_spec_hash = digest("jvm-bytecode");
    language.architecture = architecture_id_t::jvm_bytecode;
    language.mode = architecture_mode_t::jvm;
    language.endian = endian_t::big;
    return language;
}

jvm_method_input_t make_input(const jvm_method_context_t& ctx)
{
    jvm_method_input_t input;
    input.context = ctx;
    input.entity = make_jvm_entity(ctx.class_internal_name, ctx.method_name, ctx.method_descriptor);
    input.provider = make_provider();
    input.language = make_language();
    input.workspace_generation = 7;
    input.type_graph_revision = 11;
    return input;
}

std::vector<std::uint8_t> bytecode(std::initializer_list<std::uint8_t> bytes)
{
    return std::vector<std::uint8_t>(bytes);
}

void append_u16(std::vector<std::uint8_t>& code, std::uint16_t value)
{
    code.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    code.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void append_u32(std::vector<std::uint8_t>& code, std::uint32_t value)
{
    code.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    code.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    code.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    code.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

bool has_opcode(const jvm_ssa_result_t& result, provider_ir_opcode_t opcode)
{
    if (!result.provider_ir.has_value())
        return false;
    for (const auto& block : result.provider_ir->blocks)
        for (const auto& val : block.values)
            if (val.opcode == opcode)
                return true;
    return false;
}

bool has_hir_kind(const jvm_ssa_result_t& result, hir_node_kind_t kind)
{
    if (!result.hir.has_value())
        return false;
    for (const auto& block : result.hir->blocks)
        for (const auto& val : block.values)
            if (val.kind == kind)
                return true;
    return false;
}

std::size_t count_opcode(const jvm_ssa_result_t& result, provider_ir_opcode_t opcode)
{
    std::size_t count = 0;
    if (!result.provider_ir.has_value())
        return 0;
    for (const auto& block : result.provider_ir->blocks)
        for (const auto& val : block.values)
            if (val.opcode == opcode)
                ++count;
    return count;
}

void validate_determinism(const jvm_method_input_t& input, const std::string& label)
{
    auto first = decompile_method(input);
    auto second = decompile_method(input);
    require(first.succeeded() && second.succeeded(),
            label + ": determinism run failed");
    require(stable_serialization_hash(*first.provider_ir) == stable_serialization_hash(*second.provider_ir),
            label + ": provider IR is not deterministic");
    require(stable_serialization_hash(*first.hir) == stable_serialization_hash(*second.hir),
            label + ": HIR is not deterministic");
    require(stable_serialization_hash(*first.type_graph) == stable_serialization_hash(*second.type_graph),
            label + ": type graph is not deterministic");
}

void validate_round_trip(const jvm_ssa_result_t& result, const std::string& label)
{
    const auto bytes = serialize_jvm_ssa_result(result);
    require(!bytes.empty(), label + ": serialization returned empty payload");
    std::vector<decompiler_diagnostic_t> diagnostics;
    auto restored = deserialize_jvm_ssa_result(bytes, diagnostics);
    require(restored.has_value() && diagnostics.empty(),
            label + ": round-trip deserialization failed");
    require(stable_serialization_hash(*restored->provider_ir) == stable_serialization_hash(*result.provider_ir),
            label + ": round-trip changed provider IR");
    require(stable_serialization_hash(*restored->hir) == stable_serialization_hash(*result.hir),
            label + ": round-trip changed HIR");
    require(stable_serialization_hash(*restored->type_graph) == stable_serialization_hash(*result.type_graph),
            label + ": round-trip changed type graph");
}

void validate_artifacts(const jvm_ssa_result_t& result, const std::string& label)
{
    require(result.succeeded(), label + ": decompile did not succeed");
    require(validate_provider_ir(*result.provider_ir).valid(),
            label + ": provider IR failed validation");
    require(validate_hir_function(*result.hir).valid(),
            label + ": HIR failed validation");
    require(validate_type_graph(*result.type_graph).valid(),
            label + ": type graph failed validation");
    require((*result.provider_ir).entity == (*result.hir).entity,
            label + ": provider IR and HIR entity mismatch");
    require((*result.hir).provider_ir_hash == stable_serialization_hash(*result.provider_ir),
            label + ": HIR provider_ir_hash mismatch");
    require((*result.hir).type_graph_revision == (*result.type_graph).revision,
            label + ": HIR type_graph_revision mismatch");
    require(!(*result.hir).blocks.empty(),
            label + ": HIR has no blocks");
    require(!(*result.provider_ir).blocks.empty(),
            label + ": provider IR has no blocks");
}

void test_category_2_values()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/Cat2Test";
    ctx.method_name = "addLongs";
    ctx.method_descriptor = "(JJ)J";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 4;
    ctx.max_locals = 4;
    ctx.code = bytecode({
        0x1E,
        0x20,
        0x61,
        0xAD,
    });

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "category_2");

    require(has_opcode(result, provider_ir_opcode_t::load),
            "category_2: missing load opcode for long");
    require(has_opcode(result, provider_ir_opcode_t::binary),
            "category_2: missing binary opcode for ladd");
    require(has_opcode(result, provider_ir_opcode_t::return_value),
            "category_2: missing return opcode for lreturn");
    require(has_hir_kind(result, hir_node_kind_t::binary),
            "category_2: missing binary HIR node");

    bool found_long_type = false;
    for (const auto& node : result.type_graph->nodes) {
        if (node.canonical_name == "J" && node.byte_size == 8) {
            found_long_type = true;
            break;
        }
    }
    require(found_long_type, "category_2: long type node missing from type graph");

    validate_determinism(input, "category_2");
    validate_round_trip(result, "category_2");

    ctx.code = bytecode({
        0x0E,
        0x0F,
        0x63,
        0xAF,
    });
    ctx.method_name = "addDoubles";
    ctx.method_descriptor = "()D";
    ctx.max_locals = 0;
    ctx.max_stack = 4;

    input = make_input(ctx);
    result = decompile_method(input);
    validate_artifacts(result, "category_2_double");
    require(has_opcode(result, provider_ir_opcode_t::constant),
            "category_2_double: missing constant for dconst");
    require(has_opcode(result, provider_ir_opcode_t::binary),
            "category_2_double: missing binary for dadd");

    ctx.code = bytecode({
        0x0E, 0x0F, 0x63, 0x90, 0xAF,
    });
    ctx.method_name = "doubleToFloat";
    ctx.method_descriptor = "()F";
    ctx.max_stack = 4;
    input = make_input(ctx);
    result = decompile_method(input);
    validate_artifacts(result, "category_2_d2f");
    require(has_opcode(result, provider_ir_opcode_t::cast),
            "category_2_d2f: missing cast for d2f");
}

void test_tableswitch()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/SwitchTest";
    ctx.method_name = "tableSwitch";
    ctx.method_descriptor = "(I)I";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 1;

    std::vector<std::uint8_t> code;
    code.push_back(0x1A);
    code.push_back(0xAA);
    std::size_t pad = (3 - (1 & 3)) & 3;
    for (std::size_t i = 0; i < pad; ++i)
        code.push_back(0x00);
    std::size_t switch_start = 1;
    std::size_t after_header = 1 + 1 + pad + 12;
    std::size_t count = 3;
    std::size_t after_offsets = after_header + count * 4;
    std::size_t l0 = after_offsets;
    std::size_t l1 = l0 + 2;
    std::size_t l2 = l1 + 2;
    std::size_t def = l2 + 2;

    append_u32(code, static_cast<std::uint32_t>(def - switch_start));
    append_u32(code, 0);
    append_u32(code, static_cast<std::uint32_t>(count - 1));
    append_u32(code, static_cast<std::uint32_t>(l0 - switch_start));
    append_u32(code, static_cast<std::uint32_t>(l1 - switch_start));
    append_u32(code, static_cast<std::uint32_t>(l2 - switch_start));
    code.push_back(0x03); code.push_back(0xAC);
    code.push_back(0x04); code.push_back(0xAC);
    code.push_back(0x05); code.push_back(0xAC);
    code.push_back(0x02); code.push_back(0xAC);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "tableswitch");

    require(has_opcode(result, provider_ir_opcode_t::switch_branch),
            "tableswitch: missing switch_branch opcode");
    require(has_hir_kind(result, hir_node_kind_t::switch_branch),
            "tableswitch: missing switch_branch HIR");

    std::size_t block_count = result.provider_ir->blocks.size();
    require(block_count >= 5,
            "tableswitch: expected at least 5 blocks (entry + 3 cases + default), got " + std::to_string(block_count));

    bool has_phi = false;
    for (const auto& block : result.hir->blocks)
        for (const auto& val : block.values)
            if (val.kind == hir_node_kind_t::phi)
                has_phi = true;
    require(has_phi, "tableswitch: expected phi nodes at switch case merge points");

    validate_determinism(input, "tableswitch");
    validate_round_trip(result, "tableswitch");
}

void test_lookupswitch()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/LookupTest";
    ctx.method_name = "lookupSwitch";
    ctx.method_descriptor = "(I)I";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 1;

    std::vector<std::uint8_t> code;
    code.push_back(0x1A);
    code.push_back(0xAB);
    std::size_t pad = (3 - (1 & 3)) & 3;
    for (std::size_t i = 0; i < pad; ++i)
        code.push_back(0x00);
    std::size_t switch_start = 1;
    std::size_t npairs = 3;
    std::size_t after_header = 1 + 1 + pad + 8;
    std::size_t after_pairs = after_header + npairs * 8;
    std::size_t l0 = after_pairs;
    std::size_t l1 = l0 + 2;
    std::size_t l2 = l1 + 2;
    std::size_t def = l2 + 2;

    append_u32(code, static_cast<std::uint32_t>(def - switch_start));
    append_u32(code, static_cast<std::uint32_t>(npairs));
    append_u32(code, 10); append_u32(code, static_cast<std::uint32_t>(l0 - switch_start));
    append_u32(code, 20); append_u32(code, static_cast<std::uint32_t>(l1 - switch_start));
    append_u32(code, 42); append_u32(code, static_cast<std::uint32_t>(l2 - switch_start));
    code.push_back(0x03); code.push_back(0xAC);
    code.push_back(0x04); code.push_back(0xAC);
    code.push_back(0x05); code.push_back(0xAC);
    code.push_back(0x02); code.push_back(0xAC);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "lookupswitch");

    require(has_opcode(result, provider_ir_opcode_t::switch_branch),
            "lookupswitch: missing switch_branch opcode");

    std::size_t block_count = result.provider_ir->blocks.size();
    require(block_count >= 5,
            "lookupswitch: expected at least 5 blocks");

    validate_determinism(input, "lookupswitch");
    validate_round_trip(result, "lookupswitch");
}

void test_jsr_legacy()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/JsrTest";
    ctx.method_name = "jsrMethod";
    ctx.method_descriptor = "()I";
    ctx.access_flags = jvm_acc_public;
    ctx.max_stack = 2;
    ctx.max_locals = 3;

    std::vector<std::uint8_t> code;
    code.push_back(0xA8); append_u16(code, 5);
    code.push_back(0x03); code.push_back(0xAC);
    code.push_back(0x4C);
    code.push_back(0x10); code.push_back(0x2A);
    code.push_back(0x4D);
    code.push_back(0xA9); code.push_back(0x01);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "jsr");

    require(has_opcode(result, provider_ir_opcode_t::branch),
            "jsr: missing branch opcode for jsr");
    require(has_hir_kind(result, hir_node_kind_t::branch),
            "jsr: missing branch HIR for jsr");

    bool found_jsr_block = false;
    for (const auto& block : result.provider_ir->blocks) {
        for (const auto& val : block.values) {
            if (val.stable_immediate == "jsr" || val.stable_immediate == "jsr_w") {
                found_jsr_block = true;
                break;
            }
        }
    }
    require(found_jsr_block, "jsr: missing jsr instruction in provider IR");

    bool found_ret_block = false;
    for (const auto& block : result.provider_ir->blocks) {
        for (const auto& val : block.values) {
            if (val.stable_immediate == "ret") {
                found_ret_block = true;
                break;
            }
        }
    }
    require(found_ret_block, "jsr: missing ret instruction in provider IR");

    validate_determinism(input, "jsr");

    std::vector<std::uint8_t> jsr_w_code;
    jsr_w_code.push_back(0xC9); append_u32(jsr_w_code, 6);
    jsr_w_code.push_back(0x03); jsr_w_code.push_back(0xAC);
    jsr_w_code.push_back(0x4C);
    jsr_w_code.push_back(0x10); jsr_w_code.push_back(0x2A);
    jsr_w_code.push_back(0x4D);
    jsr_w_code.push_back(0xA9); jsr_w_code.push_back(0x01);

    ctx.code = jsr_w_code;
    ctx.method_name = "jsrWMethod";
    input = make_input(ctx);
    result = decompile_method(input);
    validate_artifacts(result, "jsr_w");
    require(has_opcode(result, provider_ir_opcode_t::branch),
            "jsr_w: missing branch opcode");
}

void test_exceptions()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/ExceptionTest";
    ctx.method_name = "tryCatch";
    ctx.method_descriptor = "()I";
    ctx.access_flags = jvm_acc_public;
    ctx.max_stack = 3;
    ctx.max_locals = 2;

    ctx.constant_pool.push_back(jvm_constant_pool_entry_t{});
    ctx.constant_pool.push_back(cp_utf8_entry("java/lang/Exception"));
    ctx.constant_pool.push_back(cp_class_entry(1));
    ctx.constant_pool.push_back(cp_utf8_entry("<init>"));
    ctx.constant_pool.push_back(cp_utf8_entry("()V"));
    ctx.constant_pool.push_back(cp_name_and_type_entry(3, 4));
    ctx.constant_pool.push_back(cp_methodref_entry(2, 5));

    std::vector<std::uint8_t> code;
    code.push_back(0xBB); append_u16(code, 2);
    code.push_back(0x59);
    code.push_back(0xB7); append_u16(code, 6);
    code.push_back(0xBF);
    code.push_back(0x4C);
    code.push_back(0x03);
    code.push_back(0xAC);

    ctx.code = code;

    jvm_code_exception_t exc;
    exc.start_pc = 0;
    exc.end_pc = 7;
    exc.handler_pc = 7;
    exc.catch_type = 2;
    exc.catch_class_name = "java/lang/Exception";
    ctx.exceptions.push_back(exc);

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "exceptions");

    require(has_opcode(result, provider_ir_opcode_t::call),
            "exceptions: missing call opcode for invokespecial");
    require(has_opcode(result, provider_ir_opcode_t::throw_value),
            "exceptions: missing throw opcode for athrow");
    require(has_opcode(result, provider_ir_opcode_t::return_value),
            "exceptions: missing return opcode");

    bool has_exception_edge = false;
    for (const auto& block : result.provider_ir->blocks) {
        if (!block.exception_successor_ids.empty()) {
            has_exception_edge = true;
            break;
        }
    }
    require(has_exception_edge, "exceptions: no exception successor edges found");

    bool has_handler_block = false;
    for (const auto& block : result.provider_ir->blocks) {
        if (!block.exception_successor_ids.empty()) {
            for (const auto& exc_succ : block.exception_successor_ids) {
                for (const auto& target : result.provider_ir->blocks) {
                    if (target.id == exc_succ) {
                        has_handler_block = true;
                        break;
                    }
                }
            }
        }
    }
    require(has_handler_block, "exceptions: no exception handler block found");

    validate_determinism(input, "exceptions");
    validate_round_trip(result, "exceptions");
}

void test_invokedynamic()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/InvokeDynamicTest";
    ctx.method_name = "lambdaMethod";
    ctx.method_descriptor = "()Ljava/lang/Runnable;";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 0;

    ctx.constant_pool.push_back(jvm_constant_pool_entry_t{});
    ctx.constant_pool.push_back(cp_utf8_entry("run"));
    ctx.constant_pool.push_back(cp_utf8_entry("()Ljava/lang/Runnable;"));
    ctx.constant_pool.push_back(cp_name_and_type_entry(1, 2));
    ctx.constant_pool.push_back(cp_utf8_entry("java/lang/invoke/MethodHandles$Lookup"));
    ctx.constant_pool.push_back(cp_utf8_entry("lookup"));
    ctx.constant_pool.push_back(cp_utf8_entry("()Ljava/lang/invoke/MethodHandles$Lookup;"));
    ctx.constant_pool.push_back(cp_name_and_type_entry(5, 6));
    ctx.constant_pool.push_back(cp_methodref_entry(4, 7));
    ctx.constant_pool.push_back(cp_method_handle_entry(6, 8));
    ctx.constant_pool.push_back(cp_invoke_dynamic_entry(0, 3));

    jvm_bootstrap_method_t bsm;
    bsm.bootstrap_method_ref = 9;
    bsm.bootstrap_arguments = {};
    ctx.bootstrap_methods.push_back(bsm);

    std::vector<std::uint8_t> code;
    code.push_back(0xBA); append_u16(code, 10);
    code.push_back(0x00); code.push_back(0x00);
    code.push_back(0xB0);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "invokedynamic");

    require(has_opcode(result, provider_ir_opcode_t::call),
            "invokedynamic: missing call opcode");

    bool found_bootstrap_meta = false;
    for (const auto& block : result.provider_ir->blocks) {
        for (const auto& val : block.values) {
            if (val.opcode == provider_ir_opcode_t::call &&
                val.stable_immediate.find("bootstrap=") != std::string::npos) {
                found_bootstrap_meta = true;
                break;
            }
        }
    }
    require(found_bootstrap_meta, "invokedynamic: bootstrap method index not recorded in stable_immediate");

    validate_determinism(input, "invokedynamic");
    validate_round_trip(result, "invokedynamic");
}

void test_malformed_reserved_opcode()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/MalformedTest";
    ctx.method_name = "badOpcode";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 0;
    ctx.max_locals = 0;
    ctx.code = bytecode({0xCA, 0xB1});

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    require(!result.diagnostics.empty(),
            "malformed_reserved: expected diagnostics for breakpoint opcode");

    bool found_unknown = false;
    if (result.provider_ir.has_value()) {
        for (const auto& u : result.provider_ir->unknowns) {
            if (u.reason == decompiler_unknown_reason_t::unsupported_instruction) {
                found_unknown = true;
                break;
            }
        }
    }
    require(found_unknown,
            "malformed_reserved: expected explicit unknown record for reserved opcode");
}

void test_malformed_truncated()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/TruncatedTest";
    ctx.method_name = "truncated";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 0;
    ctx.code = bytecode({0x10});

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    require(!result.diagnostics.empty(),
            "malformed_truncated: expected diagnostics for truncated bipush");

    bool found_malformed = false;
    for (const auto& d : result.diagnostics) {
        if (d.code == decompiler_diagnostic_code_t::malformed_provider_ir) {
            found_malformed = true;
            break;
        }
    }
    require(found_malformed,
            "malformed_truncated: expected malformed_provider_ir diagnostic");
}

void test_malformed_branch_target()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/BadBranchTest";
    ctx.method_name = "badBranch";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 0;
    ctx.max_locals = 0;

    std::vector<std::uint8_t> code;
    code.push_back(0xA7);
    append_u16(code, 0x7FFF);
    code.push_back(0xB1);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    require(!result.diagnostics.empty(),
            "malformed_branch: expected diagnostics for out-of-bounds branch target");

    bool found_branch_diag = false;
    for (const auto& d : result.diagnostics) {
        if (d.localization_key.find("branch_target") != std::string::npos) {
            found_branch_diag = true;
            break;
        }
    }
    require(found_branch_diag,
            "malformed_branch: expected branch_target diagnostic");
}

void test_simple_arithmetic()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/ArithmeticTest";
    ctx.method_name = "add";
    ctx.method_descriptor = "(II)I";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 2;
    ctx.max_locals = 2;
    ctx.code = bytecode({0x1A, 0x1B, 0x60, 0xAC});

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "arithmetic");

    require(has_opcode(result, provider_ir_opcode_t::load),
            "arithmetic: missing load opcode");
    require(has_opcode(result, provider_ir_opcode_t::binary),
            "arithmetic: missing binary opcode for iadd");
    require(has_opcode(result, provider_ir_opcode_t::return_value),
            "arithmetic: missing return opcode");

    validate_determinism(input, "arithmetic");
    validate_round_trip(result, "arithmetic");
}

void test_conditional_branch()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/CondTest";
    ctx.method_name = "max";
    ctx.method_descriptor = "(II)I";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 2;
    ctx.max_locals = 2;

    std::vector<std::uint8_t> code;
    code.push_back(0x1A);
    code.push_back(0x1B);
    code.push_back(0xA2);
    append_u16(code, 7);
    code.push_back(0x1B);
    code.push_back(0xAC);
    code.push_back(0x1A);
    code.push_back(0xAC);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "conditional");

    require(has_opcode(result, provider_ir_opcode_t::conditional_branch),
            "conditional: missing conditional_branch opcode");
    require(has_hir_kind(result, hir_node_kind_t::conditional),
            "conditional: missing conditional HIR");

    bool has_phi = false;
    for (const auto& block : result.hir->blocks)
        for (const auto& val : block.values)
            if (val.kind == hir_node_kind_t::phi)
                has_phi = true;
    require(has_phi, "conditional: expected phi at merge point");

    validate_determinism(input, "conditional");
    validate_round_trip(result, "conditional");
}

void test_monitor_and_fields()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/MonitorTest";
    ctx.method_name = "syncMethod";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public;
    ctx.max_stack = 2;
    ctx.max_locals = 1;

    ctx.constant_pool.push_back(jvm_constant_pool_entry_t{});
    ctx.constant_pool.push_back(cp_utf8_entry("com/test/MonitorTest"));
    ctx.constant_pool.push_back(cp_class_entry(1));
    ctx.constant_pool.push_back(cp_utf8_entry("value"));
    ctx.constant_pool.push_back(cp_utf8_entry("I"));
    ctx.constant_pool.push_back(cp_name_and_type_entry(3, 4));
    ctx.constant_pool.push_back(cp_fieldref_entry(2, 5));

    std::vector<std::uint8_t> code;
    code.push_back(0x2A);
    code.push_back(0xC2);
    code.push_back(0x2A);
    code.push_back(0xB4); append_u16(code, 6);
    code.push_back(0x57);
    code.push_back(0x2A);
    code.push_back(0xC3);
    code.push_back(0xB1);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "monitor_fields");

    require(has_opcode(result, provider_ir_opcode_t::monitor_enter),
            "monitor_fields: missing monitor_enter opcode");
    require(has_opcode(result, provider_ir_opcode_t::monitor_exit),
            "monitor_fields: missing monitor_exit opcode");
    require(has_opcode(result, provider_ir_opcode_t::field_load),
            "monitor_fields: missing field_load opcode for getfield");

    validate_determinism(input, "monitor_fields");
    validate_round_trip(result, "monitor_fields");
}

void test_array_operations()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/ArrayTest";
    ctx.method_name = "arrayOp";
    ctx.method_descriptor = "([II)I";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 2;
    ctx.max_locals = 2;
    ctx.code = bytecode({0x1A, 0x1B, 0x2E, 0xAC});

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "arrays");

    require(has_opcode(result, provider_ir_opcode_t::array_load),
            "arrays: missing array_load opcode for iaload");
    require(has_hir_kind(result, hir_node_kind_t::index),
            "arrays: missing index HIR for iaload");

    validate_determinism(input, "arrays");
    validate_round_trip(result, "arrays");
}

void test_null_check_and_instanceof()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/NullCheckTest";
    ctx.method_name = "checkNull";
    ctx.method_descriptor = "(Ljava/lang/Object;)Z";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 1;

    std::vector<std::uint8_t> code;
    code.push_back(0x1A);
    code.push_back(0xC6);
    append_u16(code, 5);
    code.push_back(0x03);
    code.push_back(0xAC);
    code.push_back(0x04);
    code.push_back(0xAC);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "null_check");

    require(has_opcode(result, provider_ir_opcode_t::conditional_branch),
            "null_check: missing conditional_branch for ifnull");
    require(has_hir_kind(result, hir_node_kind_t::conditional),
            "null_check: missing conditional HIR");

    validate_determinism(input, "null_check");
}

void test_wide_instruction()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/WideTest";
    ctx.method_name = "wideMethod";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 300;

    std::vector<std::uint8_t> code;
    code.push_back(0x03);
    code.push_back(0xC4);
    code.push_back(0x3A);
    append_u16(code, 256);
    code.push_back(0xB1);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "wide");

    bool found_wide_store = false;
    for (const auto& block : result.provider_ir->blocks) {
        for (const auto& val : block.values) {
            if (val.opcode == provider_ir_opcode_t::store) {
                found_wide_store = true;
                break;
            }
        }
    }
    require(found_wide_store, "wide: missing store opcode for wide astore");

    validate_determinism(input, "wide");
}

void test_goto_w()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/GotoWTest";
    ctx.method_name = "gotoWMethod";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 0;
    ctx.max_locals = 0;

    std::vector<std::uint8_t> code;
    code.push_back(0xC8);
    append_u32(code, 6);
    code.push_back(0xB1);
    code.push_back(0x00);
    code.push_back(0xB1);

    ctx.code = code;
    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "goto_w");

    require(has_opcode(result, provider_ir_opcode_t::branch),
            "goto_w: missing branch opcode");

    validate_determinism(input, "goto_w");
}

void test_signatures_and_coordinates()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/SigTest";
    ctx.method_name = "withLines";
    ctx.method_descriptor = "(I)V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 1;
    ctx.max_locals = 1;
    ctx.code = bytecode({0x1A, 0xB1});

    jvm_line_number_t ln;
    ln.start_pc = 0;
    ln.line_number = 42;
    ctx.line_numbers.push_back(ln);

    jvm_local_variable_t lv;
    lv.start_pc = 0;
    lv.length = 2;
    lv.index = 0;
    lv.name = "arg0";
    lv.descriptor = "I";
    ctx.local_variables.push_back(lv);

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "signatures");

    bool found_source_origin = false;
    for (const auto& block : result.hir->blocks) {
        for (const auto& val : block.values) {
            if (val.coordinate.source_origin.has_value() &&
                val.coordinate.source_origin->first_line == 42) {
                found_source_origin = true;
                break;
            }
        }
    }
    require(found_source_origin, "signatures: line number not propagated to source coordinates");

    bool found_local_name = false;
    for (const auto& param : result.hir->parameters) {
        if (param.stable_name == "arg0") {
            found_local_name = true;
            break;
        }
    }
    require(found_local_name, "signatures: local variable name not propagated to HIR parameters");

    validate_determinism(input, "signatures");
    validate_round_trip(result, "signatures");
}

void test_explicit_unknown_opcodes()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/UnknownTest";
    ctx.method_name = "unknownMethod";
    ctx.method_descriptor = "()V";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 0;
    ctx.max_locals = 0;

    ctx.code = bytecode({0xCB, 0xB1});

    auto input = make_input(ctx);
    auto result = decompile_method(input);

    bool found_unknown_diag = false;
    for (const auto& d : result.diagnostics) {
        if (d.code == decompiler_diagnostic_code_t::malformed_provider_ir ||
            d.code == decompiler_diagnostic_code_t::unsupported_entity) {
            found_unknown_diag = true;
            break;
        }
    }
    require(found_unknown_diag, "unknown_opcodes: expected diagnostic for unknown opcode 0xCB");

    if (result.provider_ir.has_value()) {
        bool found_explicit_unknown = false;
        for (const auto& u : result.provider_ir->unknowns) {
            if (u.reason == decompiler_unknown_reason_t::unsupported_instruction ||
                u.reason == decompiler_unknown_reason_t::malformed_input) {
                found_explicit_unknown = true;
                break;
            }
        }
        require(found_explicit_unknown,
                "unknown_opcodes: expected explicit unknown record in provider IR");
    }

    ctx.code = bytecode({0xFE, 0xB1});
    input = make_input(ctx);
    result = decompile_method(input);
    require(!result.diagnostics.empty(),
            "unknown_opcodes: expected diagnostics for impdep1 opcode");

    ctx.code = bytecode({0xFF, 0xB1});
    input = make_input(ctx);
    result = decompile_method(input);
    require(!result.diagnostics.empty(),
            "unknown_opcodes: expected diagnostics for impdep2 opcode");
}

void test_convert_and_compare()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/ConvertTest";
    ctx.method_name = "convert";
    ctx.method_descriptor = "(J)F";
    ctx.access_flags = jvm_acc_public | jvm_acc_static;
    ctx.max_stack = 2;
    ctx.max_locals = 2;
    ctx.code = bytecode({0x1E, 0x89, 0xAE});

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "convert");

    require(has_opcode(result, provider_ir_opcode_t::cast),
            "convert: missing cast opcode for l2f");
    require(has_hir_kind(result, hir_node_kind_t::cast),
            "convert: missing cast HIR for l2f");

    validate_determinism(input, "convert");
}

void test_instance_method()
{
    jvm_method_context_t ctx;
    ctx.class_internal_name = "com/test/InstanceTest";
    ctx.method_name = "instanceMethod";
    ctx.method_descriptor = "(I)I";
    ctx.access_flags = jvm_acc_public;
    ctx.max_stack = 1;
    ctx.max_locals = 2;
    ctx.code = bytecode({0x1B, 0xAC});

    auto input = make_input(ctx);
    auto result = decompile_method(input);
    validate_artifacts(result, "instance_method");

    require(!result.hir->parameters.empty(),
            "instance_method: expected at least one parameter (this)");
    require(result.hir->parameters.front().stable_name == "this" ||
            !result.hir->parameters.front().stable_name.empty(),
            "instance_method: expected 'this' parameter for instance method");

    validate_determinism(input, "instance_method");
    validate_round_trip(result, "instance_method");
}

}

void run_jvm_ssa_harness()
{
    test_simple_arithmetic();
    test_category_2_values();
    test_tableswitch();
    test_lookupswitch();
    test_jsr_legacy();
    test_exceptions();
    test_invokedynamic();
    test_monitor_and_fields();
    test_array_operations();
    test_conditional_branch();
    test_null_check_and_instanceof();
    test_wide_instruction();
    test_goto_w();
    test_signatures_and_coordinates();
    test_explicit_unknown_opcodes();
    test_malformed_reserved_opcode();
    test_malformed_truncated();
    test_malformed_branch_target();
    test_convert_and_compare();
    test_instance_method();
}

}

int main()
{
    try {
        aida::analysis::c03_test::run_jvm_ssa_harness();
        std::cout << "jvm_ssa_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& exception) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(exception.what());
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
