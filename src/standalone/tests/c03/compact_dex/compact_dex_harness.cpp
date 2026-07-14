#include "compact_dex_fixture.hpp"

#include "../analysis_memory_provider.hpp"
#include "../../../src/core/analysis/readers/managed/dex_reader.hpp"
#include "../../../src/core/analysis/readers/managed/managed_reader_contracts.hpp"
#include "../../../src/core/analysis/workspace/dex_image.hpp"

#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace aida::analysis::c03_test {
namespace {

namespace managed = ::aida::analysis::readers::managed;

void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

template <typename value_t>
value_t require_value(workspace_result_t<value_t> result,
                      const char* message) {
    if (!result)
        throw std::runtime_error(
            std::string(message) + ": " + result.error().stable_code());
    return result.take_value();
}

void verify_compact_image(bool preheader) {
    const auto fixture = make_compact_dex_fixture(preheader);
    memory_provider_t provider(fixture.bytes,
        preheader ? "compact-preheader.cdex" : "compact-fast.cdex");
    const auto container = require_value(
        detect_dex_container(provider), "compact DEX detection failed");
    require(container.kind == dex_container_kind_t::compact_dex &&
            container.version == "001" && container.header_size == 136 &&
            container.compact_features.has_value(),
        "compact DEX identity is incomplete");
    require(container.compact_features->debug_info_offsets_position ==
                fixture.debug_table_position &&
            container.compact_features->debug_info_offsets_table_offset == 4 &&
            container.compact_features->debug_info_base ==
                fixture.debug_info_offset &&
            container.compact_features->owned_data_end == fixture.data_size,
        "compact DEX extension fields were not preserved");

    const auto image = require_value(
        parse_dex_image(provider), "compact DEX parse failed");
    require(image.container.kind == dex_container_kind_t::compact_dex &&
            image.managed_identity.version == "001" &&
            image.header.file_size == fixture.main_size &&
            image.payload_size == fixture.bytes.size() &&
            image.normalized.image_size == fixture.bytes.size(),
        "compact DEX split payload identity is invalid");
    require(image.strings.size() == 4 && image.strings[0].utf8 == "LTest;" &&
            image.types.size() == 2 && image.methods.size() == 2 &&
            image.classes.size() == 1 &&
            image.classes[0].direct_methods.size() == 2,
        "compact DEX metadata graph is incomplete");
    const auto code = image.classes[0].direct_methods[0].code;
    const auto second_code = image.classes[0].direct_methods[1].code;
    require(code && code->offset == fixture.main_size + fixture.code_item_offset &&
            code->instructions_offset ==
                fixture.main_size + fixture.instructions_offset &&
            code->instruction_count == 1 && code->instructions.size() == 1 &&
            code->instructions[0].opcode == 0x0eU &&
            code->debug_info_offset ==
                fixture.main_size + fixture.debug_info_offset &&
            code->debug_info.has_value(),
        "compact DEX code or debug metadata is invalid");
    require(second_code && second_code->offset == code->offset &&
            second_code != code &&
            second_code->instructions_offset == code->instructions_offset &&
            second_code->debug_info_offset ==
                fixture.main_size + fixture.second_debug_info_offset &&
            second_code->debug_info.has_value() &&
            second_code->debug_info->line_start == 2 &&
            code->debug_info->line_start == 1,
        "shared compact code did not retain method-indexed debug metadata");
    require(code->registers_size == (preheader ? 16U : 1U),
        "compact DEX register preheader was decoded incorrectly");

    const auto artifact = require_value(
        managed::read_dex(provider), "compact managed DEX read failed");
    require(artifact.valid() &&
            artifact.kind == managed::managed_artifact_kind_t::dex &&
            artifact.module_identity.version == "001" &&
            artifact.module_identity.artifact_size == fixture.bytes.size() &&
            artifact.normalized.format_name == "compact-dex:001" &&
            artifact.code_ranges.size() == 2 &&
            artifact.code_ranges[0].offset ==
                fixture.main_size + fixture.instructions_offset &&
            artifact.code_ranges[0].size == 2 &&
            artifact.methods.size() == 2 &&
            artifact.methods[0].code_offset == artifact.code_ranges[0].offset,
        "compact managed DEX artifact does not preserve exact code ranges");
}

void verify_malformed_compact_inputs() {
    auto unknown_feature = make_compact_dex_fixture();
    compact_fixture_write_u32(unknown_feature.bytes, 112, 2);
    memory_provider_t unknown_provider(
        std::move(unknown_feature.bytes), "compact-unknown-feature.cdex");
    const auto unknown = parse_dex_image(unknown_provider);
    require(!unknown &&
            unknown.error().code == workspace_error_code_t::unsupported_format,
        "compact DEX unknown feature flag did not fail closed");

    auto bad_table = make_compact_dex_fixture();
    compact_fixture_write_u32(bad_table.bytes, 120, 8);
    memory_provider_t table_provider(
        std::move(bad_table.bytes), "compact-bad-debug-table.cdex");
    const auto table = parse_dex_image(table_provider);
    require(!table && table.error().code == workspace_error_code_t::malformed_image,
        "compact DEX invalid debug table did not fail closed");

    auto bad_preheader = make_compact_dex_fixture();
    const auto data = bad_preheader.main_size;
    bad_preheader.bytes[data + bad_preheader.class_data_offset + 6U] = 28;
    compact_fixture_write_u16(bad_preheader.bytes, data + 28U, 0);
    compact_fixture_write_u16(bad_preheader.bytes, data + 30U, 0x30U);
    memory_provider_t preheader_provider(
        std::move(bad_preheader.bytes), "compact-bad-preheader.cdex");
    const auto preheader = parse_dex_image(preheader_provider);
    require(!preheader,
        "compact DEX invalid instruction preheader was accepted");

    auto bad_string = make_compact_dex_fixture();
    compact_fixture_write_u32(bad_string.bytes, 136, bad_string.data_size);
    memory_provider_t string_provider(
        std::move(bad_string.bytes), "compact-bad-data-offset.cdex");
    const auto string = parse_dex_image(string_provider);
    require(!string && string.error().code == workspace_error_code_t::out_of_range,
        "compact DEX out-of-range shared-data offset was accepted");
}

void verify_compact_limits_and_cancellation() {
    const auto fixture = make_compact_dex_fixture();
    memory_provider_t provider(fixture.bytes, "compact-limits.cdex");
    dex_parse_limits_t limits;
    limits.max_string_ids = 3;
    const auto limited = parse_dex_image(provider, limits);
    require(!limited && limited.error().code == workspace_error_code_t::limit_exceeded,
        "compact DEX identifier budget did not fail closed");

    cancellation_source_t source;
    source.request_cancel();
    const auto cancelled = parse_dex_image(provider, source.token());
    require(!cancelled && cancelled.error().code == workspace_error_code_t::cancelled &&
            cancelled.error().cancellation,
        "compact DEX cancellation did not propagate");
}

void verify_embedded_compact_vdex() {
    const auto fixture = make_compact_dex_fixture();
    memory_provider_t provider(
        make_compact_vdex_fixture(fixture), "compact-container.vdex");
    const auto multidex = require_value(
        managed::read_multidex_container(provider),
        "embedded compact VDEX read failed");
    require(multidex.container_kind == managed::managed_artifact_kind_t::vdex &&
            multidex.artifacts.size() == 1 &&
            multidex.embedded_offsets.size() == 1 &&
            multidex.embedded_offsets[0] == 64 &&
            multidex.artifacts[0].kind == managed::managed_artifact_kind_t::vdex &&
            multidex.artifacts[0].module_identity.artifact_offset == 64 &&
            multidex.artifacts[0].module_identity.artifact_size ==
                fixture.bytes.size() &&
            multidex.artifacts[0].code_ranges.size() == 2,
        "embedded compact VDEX artifact identity is invalid");
}

}

int run_compact_dex_harness() {
    verify_compact_image(true);
    verify_compact_image(false);
    verify_malformed_compact_inputs();
    verify_compact_limits_and_cancellation();
    verify_embedded_compact_vdex();
    return 0;
}

}

int main() {
    try {
        aida::analysis::c03_test::run_compact_dex_harness();
        std::cout << "C03 compact DEX harness passed" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "C03 compact DEX harness failed: " << error.what()
                  << std::endl;
        return 1;
    }
}
