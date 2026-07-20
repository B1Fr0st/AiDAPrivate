#include "image_layout_index_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/analysis/image_layout_index.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace aida {
namespace analysis {
namespace c03_test {
namespace {

void require(bool condition, const char* message) {
	assertion_telemetry::record_assertion(condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(message);
}

binary_id_t content_id(std::uint8_t seed) {
    binary_id_t result;
    for (std::size_t index = 0; index < result.bytes.size(); ++index)
        result.bytes[index] = static_cast<std::uint8_t>(seed + index * 13U);
    return result;
}

image_layout_definition_t base_definition(std::uint8_t width_bits = 64U) {
    image_layout_definition_t definition;
    definition.identity.content_id = content_id(7U);
    definition.identity.format = format_id_t::pe32_plus;
    definition.identity.endian = endian_t::little;
    definition.identity.address_width_bits = width_bits;
    definition.identity.image_base = width_bits == 32U ? 0x00400000U : 0x0000000140000000ULL;
    definition.identity.provider_size = 0x2000U;
    definition.members.push_back({5U, "fixture.bin", 0x200U, 0x1000U});
    definition.segments.push_back({10U, ".image", 0x100U, 0x300U, 0x400U, 0x280U,
                                   image_permission_read | image_permission_execute});
    definition.sections.push_back({1U, ".text", 0x100U, 0x80U, 0x400U, 0x60U,
                                   image_permission_read | image_permission_execute});
    definition.sections.push_back({2U, ".data", 0x200U, 0x80U, 0x600U, 0x80U,
                                   image_permission_read | image_permission_write});
    const auto base = definition.identity.image_base;
    definition.mappings.push_back({100U, 0x100U, base + 0x100U, 0x80U, 0x400U, 0x60U,
                                   image_permission_read | image_permission_execute, 1U, 10U, 5U});
    definition.mappings.push_back({101U, 0x200U, base + 0x200U, 0x80U, 0x600U, 0x80U,
                                   image_permission_read | image_permission_write, 2U, 10U, 5U});
    return definition;
}

image_layout_index_t build_index(image_layout_definition_t definition) {
    const auto result = image_layout_index_t::build(std::move(definition));
    require(result.has_value(), "image layout build failed");
    return result.value();
}

void verify_immutability_after_build() {
    static_assert(std::is_const_v<std::remove_reference_t<decltype(
                      std::declval<const image_layout_index_t&>().identity())>>);
    static_assert(std::is_const_v<std::remove_reference_t<decltype(
                      std::declval<const image_layout_index_t&>().mappings())>>);
    static_assert(std::is_const_v<std::remove_reference_t<decltype(
                      std::declval<const image_layout_index_t&>().sections())>>);
    static_assert(std::is_const_v<std::remove_reference_t<decltype(
                      std::declval<const image_layout_index_t&>().segments())>>);
    static_assert(std::is_const_v<std::remove_reference_t<decltype(
                      std::declval<const image_layout_index_t&>().members())>>);

    auto definition = base_definition();
    const auto expected_identity = definition.identity;
    const auto index = build_index(definition);
    const auto copied_index = index;
    definition.identity = {};
    definition.mappings.clear();
    definition.sections.clear();
    definition.segments.clear();
    definition.members.clear();

    require(index.identity() == expected_identity, "caller mutation changed built image identity");
    require(index.mappings().size() == 2U && index.mappings()[0].id == 100U,
            "caller mutation changed built mappings");
    require(index.sections().size() == 2U && index.sections()[0].name == ".text",
            "caller mutation changed built sections");
    require(index.segments().size() == 1U && index.segments()[0].name == ".image",
            "caller mutation changed built segments");
    require(index.members().size() == 1U && index.members()[0].name == "fixture.bin",
            "caller mutation changed built members");
    require(copied_index.identity() == index.identity() &&
                copied_index.mappings().size() == index.mappings().size(),
            "copied index did not preserve the immutable layout snapshot");
}

void verify_round_trip_properties() {
    auto definition = base_definition();
    definition.mappings.clear();
    definition.sections.clear();
    definition.segments.clear();
    constexpr std::uint32_t k_count = 256U;
    const auto base = definition.identity.image_base;
    for (std::uint32_t index = 0; index < k_count; ++index) {
        const auto rva = 0x1000ULL + static_cast<std::uint64_t>(index) * 0x80ULL;
        const auto file = 0x400ULL + static_cast<std::uint64_t>(index) * 0x40ULL;
        definition.mappings.push_back({1000U + index, rva, base + rva, 0x40U, file, 0x40U,
                                       image_permission_read | image_permission_execute,
                                       std::nullopt, std::nullopt, 5U});
    }
    definition.identity.provider_size = 0x400U + static_cast<std::uint64_t>(k_count) * 0x40ULL;
    const auto index = build_index(std::move(definition));
    std::uint32_t state = 0xC03B02U;
    for (std::uint32_t iteration = 0; iteration < 1024U; ++iteration) {
        state = state * 1664525U + 1013904223U;
        const auto mapping = state % k_count;
        const auto byte = (state >> 16U) % 0x40U;
        const auto expected_rva = 0x1000ULL + static_cast<std::uint64_t>(mapping) * 0x80ULL + byte;
        const auto expected_file = 0x400ULL + static_cast<std::uint64_t>(mapping) * 0x40ULL + byte;
        const auto by_rva = index.lookup_rva(expected_rva);
        require(by_rva && by_rva.value().has_value(), "RVA property lookup missed mapping");
        require(by_rva.value()->file_offset && *by_rva.value()->file_offset == expected_file,
                "RVA property lookup file translation drifted");
        const auto by_file = index.lookup_file_offset(expected_file);
        require(by_file && by_file.value().has_value(), "file property lookup missed mapping");
        require(by_file.value()->rva == expected_rva, "file property lookup RVA translation drifted");
        const auto by_va = index.lookup_va(index.identity().image_base + expected_rva);
        require(by_va && by_va.value().has_value(), "VA property lookup missed mapping");
        require(by_va.value()->rva == expected_rva, "VA property lookup RVA translation drifted");
    }
}

void verify_holes_zero_fill_and_intervals() {
    const auto index = build_index(base_definition());
    const auto zero_fill = index.lookup_rva(0x165U);
    require(zero_fill && zero_fill.value().has_value(), "zero-fill RVA was not indexed");
    require(zero_fill.value()->zero_fill, "zero-fill RVA was reported as file-backed");
    require(!zero_fill.value()->file_offset.has_value(), "zero-fill RVA exposed a file offset");
    require(zero_fill.value()->permissions == (image_permission_read | image_permission_execute),
            "zero-fill permissions drifted");
    require(zero_fill.value()->section_ids == std::vector<std::uint32_t>{1U}, "section range lookup drifted");
    require(zero_fill.value()->segment_ids == std::vector<std::uint32_t>{10U}, "segment range lookup drifted");
    require(zero_fill.value()->member_ids == std::vector<std::uint32_t>{5U}, "member association drifted");

    const auto rva_hole = index.lookup_rva(0x180U);
    require(rva_hole && !rva_hole.value().has_value(), "RVA hole resolved to a mapping");
    const auto file_hole = index.lookup_file_offset(0x580U);
    require(file_hole && !file_hole.value().has_value(), "file hole resolved to a mapping");

    const auto interval = index.lookup_interval(address_space_id_t::relative_virtual, 0x150U, 0x130U);
    require(interval.has_value(), "interval lookup rejected a valid interval");
    require(!interval.value().complete, "interval with a hole was reported complete");
    require(interval.value().slices.size() == 4U, "interval lookup did not split file, zero-fill, hole, and mapping spans");
    require(interval.value().slices[0].lookup.has_value() && !interval.value().slices[0].lookup->zero_fill,
            "interval file-backed slice drifted");
    require(interval.value().slices[1].lookup.has_value() && interval.value().slices[1].lookup->zero_fill,
            "interval zero-fill slice drifted");
    require(!interval.value().slices[2].lookup.has_value(), "interval hole slice drifted");
    require(interval.value().slices[3].lookup.has_value(), "interval trailing mapping slice drifted");
}

void verify_explicit_section_segment_associations() {
    auto detached_definition = base_definition();
    detached_definition.sections[0].rva = 0x1000U;
    detached_definition.sections[0].file_offset = 0x1000U;
    detached_definition.segments[0].rva = 0x1400U;
    detached_definition.segments[0].file_offset = 0x1400U;
    const auto detached_index = build_index(std::move(detached_definition));
    const auto detached_lookup = detached_index.lookup_rva(0x120U);
    require(detached_lookup && detached_lookup.value().has_value(),
            "explicit association lookup missed mapping");
    require(detached_lookup.value()->section_ids == std::vector<std::uint32_t>{1U},
            "explicit section association was not returned");
    require(detached_lookup.value()->segment_ids == std::vector<std::uint32_t>{10U},
            "explicit segment association was not returned");
    require(!detached_lookup.value()->ambiguous,
            "single explicit section and segment associations were marked ambiguous");

    const auto coalesced_index = build_index(base_definition());
    const auto coalesced_lookup = coalesced_index.lookup_rva(0x120U);
    require(coalesced_lookup && coalesced_lookup.value().has_value(),
            "coalesced association lookup missed mapping");
    require(coalesced_lookup.value()->section_ids == std::vector<std::uint32_t>{1U} &&
                coalesced_lookup.value()->segment_ids == std::vector<std::uint32_t>{10U},
            "duplicate explicit and inferred associations were not coalesced");
    require(!coalesced_lookup.value()->ambiguous,
            "duplicate observations of identical associations were marked ambiguous");
}

void verify_overlap_rejection() {
    auto virtual_overlap = base_definition();
    virtual_overlap.mappings[1].rva = 0x170U;
    virtual_overlap.mappings[1].virtual_address = virtual_overlap.identity.image_base + 0x170U;
    const auto virtual_result = image_layout_index_t::build(std::move(virtual_overlap));
    require(!virtual_result.has_value() && virtual_result.error().code == workspace_error_code_t::malformed_image,
            "overlapping virtual mappings were accepted");

    auto file_overlap = base_definition();
    file_overlap.mappings[1].file_offset = 0x450U;
    const auto file_result = image_layout_index_t::build(std::move(file_overlap));
    require(!file_result.has_value() && file_result.error().code == workspace_error_code_t::malformed_image,
            "overlapping file mappings were accepted");
}

void verify_width_overflow_rejection() {
    auto rva_32_overflow = base_definition(32U);
    rva_32_overflow.mappings[0].rva = 0xFFFFFFF0ULL;
    rva_32_overflow.mappings[0].virtual_address = rva_32_overflow.identity.image_base + rva_32_overflow.mappings[0].rva;
    const auto rva_32_result = image_layout_index_t::build(std::move(rva_32_overflow));
    require(!rva_32_result.has_value() && rva_32_result.error().code == workspace_error_code_t::range_overflow,
            "32-bit RVA overflow was accepted");

    auto va_32_overflow = base_definition(32U);
    va_32_overflow.identity.image_base = 0xFFFFF000ULL;
    va_32_overflow.mappings[0].rva = 0x1000U;
    va_32_overflow.mappings[0].virtual_address = 0x100000000ULL;
    const auto va_32_result = image_layout_index_t::build(std::move(va_32_overflow));
    require(!va_32_result.has_value() && va_32_result.error().code == workspace_error_code_t::range_overflow,
            "32-bit VA overflow was accepted");

    auto va_64_overflow = base_definition();
    va_64_overflow.identity.image_base = std::numeric_limits<std::uint64_t>::max() - 0x10U;
    va_64_overflow.mappings[0].rva = 0x20U;
    va_64_overflow.mappings[0].virtual_address = 0;
    const auto va_64_result = image_layout_index_t::build(std::move(va_64_overflow));
    require(!va_64_result.has_value() && va_64_result.error().code == workspace_error_code_t::range_overflow,
            "64-bit VA overflow was accepted");

    auto file_64_overflow = base_definition();
    file_64_overflow.identity.provider_size = 0;
    file_64_overflow.mappings[0].file_offset = std::numeric_limits<std::uint64_t>::max() - 0x10U;
    file_64_overflow.mappings[0].file_size = 0x20U;
    const auto file_64_result = image_layout_index_t::build(std::move(file_64_overflow));
    require(!file_64_result.has_value() && file_64_result.error().code == workspace_error_code_t::range_overflow,
            "64-bit file overflow was accepted");
}

void verify_named_range_overflow_rejection() {
    auto section_32_overflow = base_definition(32U);
    section_32_overflow.identity.image_base = 0xFFFFF000ULL;
    section_32_overflow.mappings.clear();
    section_32_overflow.segments.clear();
    section_32_overflow.sections.resize(1U);
    section_32_overflow.sections[0].rva = 0x1000U;
    section_32_overflow.sections[0].virtual_size = 0x20U;
    section_32_overflow.sections[0].file_size = 0x20U;
    const auto section_32_result = image_layout_index_t::build(std::move(section_32_overflow));
    require(!section_32_result.has_value() &&
                section_32_result.error().code == workspace_error_code_t::range_overflow &&
                section_32_result.error().phase == "sections",
            "32-bit section image-base-plus-RVA overflow was accepted");

    auto section_64_overflow = base_definition();
    section_64_overflow.identity.image_base = std::numeric_limits<std::uint64_t>::max() - 0x10U;
    section_64_overflow.mappings.clear();
    section_64_overflow.segments.clear();
    section_64_overflow.sections.resize(1U);
    section_64_overflow.sections[0].rva = 0x20U;
    section_64_overflow.sections[0].virtual_size = 0x20U;
    section_64_overflow.sections[0].file_size = 0x20U;
    const auto section_64_result = image_layout_index_t::build(std::move(section_64_overflow));
    require(!section_64_result.has_value() &&
                section_64_result.error().code == workspace_error_code_t::range_overflow &&
                section_64_result.error().phase == "sections",
            "64-bit section image-base-plus-RVA overflow was accepted");

    auto segment_32_overflow = base_definition(32U);
    segment_32_overflow.identity.image_base = 0xFFFFF000ULL;
    segment_32_overflow.mappings.clear();
    segment_32_overflow.sections.clear();
    segment_32_overflow.segments.resize(1U);
    segment_32_overflow.segments[0].rva = 0x1000U;
    segment_32_overflow.segments[0].virtual_size = 0x20U;
    segment_32_overflow.segments[0].file_size = 0x20U;
    const auto segment_32_result = image_layout_index_t::build(std::move(segment_32_overflow));
    require(!segment_32_result.has_value() &&
                segment_32_result.error().code == workspace_error_code_t::range_overflow &&
                segment_32_result.error().phase == "segments",
            "32-bit segment image-base-plus-RVA overflow was accepted");

    auto segment_64_overflow = base_definition();
    segment_64_overflow.identity.image_base = std::numeric_limits<std::uint64_t>::max() - 0x10U;
    segment_64_overflow.mappings.clear();
    segment_64_overflow.sections.clear();
    segment_64_overflow.segments.resize(1U);
    segment_64_overflow.segments[0].rva = 0x20U;
    segment_64_overflow.segments[0].virtual_size = 0x20U;
    segment_64_overflow.segments[0].file_size = 0x20U;
    const auto segment_64_result = image_layout_index_t::build(std::move(segment_64_overflow));
    require(!segment_64_result.has_value() &&
                segment_64_result.error().code == workspace_error_code_t::range_overflow &&
                segment_64_result.error().phase == "segments",
            "64-bit segment image-base-plus-RVA overflow was accepted");
}

void verify_unknown_permission_rejection() {
    constexpr std::uint32_t k_unknown_permission = 1U << 31U;

    auto mapping_definition = base_definition();
    mapping_definition.mappings[0].permissions |= k_unknown_permission;
    const auto mapping_result = image_layout_index_t::build(std::move(mapping_definition));
    require(!mapping_result.has_value() &&
                mapping_result.error().code == workspace_error_code_t::malformed_image &&
                mapping_result.error().phase == "mappings",
            "unknown mapping permission was accepted");

    auto section_definition = base_definition();
    section_definition.sections[0].permissions |= k_unknown_permission;
    const auto section_result = image_layout_index_t::build(std::move(section_definition));
    require(!section_result.has_value() &&
                section_result.error().code == workspace_error_code_t::malformed_image &&
                section_result.error().phase == "sections",
            "unknown section permission was accepted");

    auto segment_definition = base_definition();
    segment_definition.segments[0].permissions |= k_unknown_permission;
    const auto segment_result = image_layout_index_t::build(std::move(segment_definition));
    require(!segment_result.has_value() &&
                segment_result.error().code == workspace_error_code_t::malformed_image &&
                segment_result.error().phase == "segments",
            "unknown segment permission was accepted");
}

void verify_endian_neutral_identity() {
    auto identity = base_definition().identity;
    identity.image_base = 0x0102030405060708ULL;
    identity.provider_size = 0x1112131415161718ULL;
    identity.member = provider_member_metadata_t{"nested/member", 0x21U, 0x22U, 0x23U, 0x24U, 2U, 0xAABBCCDDU, true};
    const auto bytes = identity.canonical_bytes();
    require(bytes.size() > 56U, "canonical identity bytes were incomplete");
    const std::array<std::uint8_t, 8> expected_base{1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
    require(std::equal(expected_base.begin(), expected_base.end(), bytes.begin() + 39),
            "canonical identity did not use endian-neutral integer encoding");
    require(identity.canonical_bytes() == bytes && identity.canonical_hash() == identity.canonical_hash(),
            "canonical identity was not deterministic");
    auto changed_endian = identity;
    changed_endian.endian = endian_t::big;
    require(changed_endian.canonical_bytes() != bytes && changed_endian.canonical_hash() != identity.canonical_hash(),
            "canonical identity ignored image endian metadata");
}

void verify_metadata_ambiguity() {
    auto member_definition = base_definition();
    member_definition.members.push_back({6U, "overlapping.bin", 0x440U, 0x100U});
    const auto member_index = build_index(std::move(member_definition));
    const auto member_lookup = member_index.lookup_file_offset(0x450U);
    require(member_lookup && member_lookup.value().has_value(), "ambiguous member lookup missed file mapping");
    require(member_lookup.value()->ambiguous, "overlapping member metadata was not marked ambiguous");
    require(member_lookup.value()->member_ids == std::vector<std::uint32_t>({5U, 6U}),
            "ambiguous member identifiers were not stable");

    auto range_definition = base_definition();
    range_definition.sections[0].rva = 0x1000U;
    range_definition.sections[0].file_offset = 0x1000U;
    range_definition.segments[0].rva = 0x1400U;
    range_definition.segments[0].file_offset = 0x1400U;
    range_definition.sections.push_back({3U, ".text.alias", 0x100U, 0x80U, 0x400U, 0x60U,
                                         image_permission_read | image_permission_execute});
    range_definition.segments.push_back({11U, ".image.alias", 0x100U, 0x300U, 0x400U, 0x280U,
                                         image_permission_read | image_permission_execute});
    const auto range_index = build_index(std::move(range_definition));
    const auto range_lookup = range_index.lookup_rva(0x120U);
    require(range_lookup && range_lookup.value().has_value(),
            "ambiguous section and segment lookup missed mapping");
    require(range_lookup.value()->ambiguous,
            "distinct explicit and inferred section or segment identities were not marked ambiguous");
    require(range_lookup.value()->section_ids == std::vector<std::uint32_t>({1U, 3U}),
            "ambiguous section identifiers were not stable");
    require(range_lookup.value()->segment_ids == std::vector<std::uint32_t>({10U, 11U}),
            "ambiguous segment identifiers were not stable");
}

void verify_interval_query_counter_classification() {
    const auto index = build_index(base_definition());
    const auto before = index.query_counters();
    const auto rva_interval = index.lookup_interval(address_space_id_t::relative_virtual, 0x110U, 0x10U);
    const auto va_interval = index.lookup_interval(address_space_id_t::virtual_address,
                                                   index.identity().image_base + 0x110U, 0x10U);
    const auto file_interval = index.lookup_interval(address_space_id_t::file_offset, 0x410U, 0x10U);
    require(rva_interval && rva_interval.value().complete &&
                va_interval && va_interval.value().complete &&
                file_interval && file_interval.value().complete,
            "valid interval counter probes did not resolve completely");
    const auto after = index.query_counters();
    require(after.queries - before.queries == 3U,
            "interval queries were not included in generic query counters");
    require(after.interval_queries - before.interval_queries == 3U &&
                after.point_queries == before.point_queries,
            "interval queries drifted into point-query counters");
    require(after.rva_queries - before.rva_queries == 1U &&
                after.va_queries - before.va_queries == 1U &&
                after.file_queries - before.file_queries == 1U,
            "interval queries were not classified by address space");
}

void verify_metadata_query_counters() {
    const auto index = build_index(base_definition());
    const auto before = index.query_counters();
    const auto lookup = index.lookup_rva(0x120U);
    require(lookup && lookup.value().has_value(), "metadata counter lookup missed mapping");
    const auto after = index.query_counters();
    const auto returned_metadata = lookup.value()->section_ids.size() +
                                   lookup.value()->segment_ids.size() +
                                   lookup.value()->member_ids.size();
    require(after.metadata_binary_search_steps > before.metadata_binary_search_steps,
            "metadata interval searches were not instrumented");
    require(after.metadata_matches - before.metadata_matches == returned_metadata,
            "metadata match counters did not track normalized lookup identities");
}

void verify_logarithmic_query_counters() {
    auto definition = base_definition();
    definition.mappings.clear();
    definition.sections.clear();
    definition.segments.clear();
    constexpr std::uint32_t k_count = 4096U;
    const auto base = definition.identity.image_base;
    for (std::uint32_t index = 0; index < k_count; ++index) {
        const auto rva = 0x1000ULL + static_cast<std::uint64_t>(index) * 0x40ULL;
        const auto file = 0x400ULL + static_cast<std::uint64_t>(index) * 0x40ULL;
        definition.mappings.push_back({index, rva, base + rva, 0x20U, file, 0x20U,
                                       image_permission_read, std::nullopt, std::nullopt, 5U});
    }
    definition.identity.provider_size = 0x400ULL + static_cast<std::uint64_t>(k_count) * 0x40ULL;
    const auto index = build_index(std::move(definition));
    const auto before = index.query_counters();
    const auto present = index.lookup_rva(0x1000ULL + static_cast<std::uint64_t>(k_count - 1U) * 0x40ULL + 0x1FU);
    require(present && present.value().has_value(), "large index present lookup missed mapping");
    const auto missing = index.lookup_rva(0x1000ULL + static_cast<std::uint64_t>(k_count) * 0x40ULL);
    require(missing && !missing.value().has_value(), "large index hole lookup resolved unexpectedly");
    const auto after = index.query_counters();
    const auto search_steps = after.mapping_binary_search_steps - before.mapping_binary_search_steps;
    require(search_steps <= 26U, "point lookup exceeded logarithmic binary-search probe budget");
    require(after.queries - before.queries == 2U && after.point_queries - before.point_queries == 2U,
            "query instrumentation did not count point lookups");
    require(after.rva_queries - before.rva_queries == 2U, "query instrumentation did not classify RVA lookups");
}

}

void run_image_layout_index_harness() {
    verify_immutability_after_build();
    verify_round_trip_properties();
    verify_holes_zero_fill_and_intervals();
    verify_explicit_section_segment_associations();
    verify_overlap_rejection();
    verify_width_overflow_rejection();
    verify_named_range_overflow_rejection();
    verify_unknown_permission_rejection();
    verify_endian_neutral_identity();
    verify_metadata_ambiguity();
    verify_interval_query_counter_classification();
    verify_metadata_query_counters();
    verify_logarithmic_query_counters();
}

}
}
}

int main() {
    try {
        aida::analysis::c03_test::run_image_layout_index_harness();
        std::cout << "image_layout_index_harness source contract satisfied\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << error.what() << '\n';
        return 1;
    }
}
