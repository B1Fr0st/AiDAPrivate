#include "xref_discovery_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"
#include "analysis_memory_provider.hpp"

#include "../../src/core/analysis/workspace/data_discovery.hpp"
#include "../../src/core/analysis/workspace/string_discovery.hpp"
#include "../../src/core/analysis/workspace/symbol_type_candidates.hpp"
#include "../../src/core/analysis/workspace/xref_builder.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {
namespace {

void require(bool condition, std::string_view message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename T>
T require_value(workspace_result_t<T> result, std::string_view message)
{
    const bool accepted = static_cast<bool>(result);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(std::string(message) + ": " + result.error().message);
    return result.take_value();
}

address_t rva(std::uint64_t value)
{
    return {address_space_id_t::relative_virtual, value,
        architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

workspace_image_t make_image(format_id_t format = format_id_t::pe32_plus,
                             abi_id_t abi = abi_id_t::windows_x64)
{
    workspace_image_t image;
    image.format = format;
    image.architecture = architecture_id_t::x86_64;
    image.architecture_mode = architecture_mode_t::x86_64;
    image.abi = abi;
    image.endian = endian_t::little;
    image.address_width_bits = 64;
    image.image_base = 0x140000000ULL;
    image.image_size = 0x3000;
    image.format_name = "c03-discovery";
    image.provider_source = "c03-memory";
    image.provider_size = 0x3000;
    image_section_t text;
    text.index = 1;
    text.name = ".text";
    text.virtual_address = 0x1000;
    text.virtual_size = 0x200;
    text.file_offset = 0x1000;
    text.file_size = 0x200;
    text.permissions = image_permission_read | image_permission_execute;
    image.sections.push_back(std::move(text));
    image_section_t data;
    data.index = 2;
    data.name = ".rdata";
    data.virtual_address = 0x2000;
    data.virtual_size = 0x400;
    data.file_offset = 0x2000;
    data.file_size = 0x400;
    data.permissions = image_permission_read;
    image.sections.push_back(std::move(data));
    image_export_t exported;
    exported.name = "conflict_name";
    exported.ordinal = 1;
    exported.address = rva(0x1000);
    image.exports.push_back(std::move(exported));
    image_symbol_t conflicting;
    conflicting.ordinal = 2;
    conflicting.name = "conflict_name";
    conflicting.address = rva(0x1000);
    conflicting.kind = image_symbol_kind_t::object;
    conflicting.binding = image_symbol_binding_t::global;
    conflicting.defined = true;
    image.symbols.push_back(std::move(conflicting));
    image_symbol_t vtable;
    vtable.ordinal = 3;
    vtable.name = "_ZTVFixture";
    vtable.address = rva(0x2020);
    vtable.kind = image_symbol_kind_t::object;
    vtable.binding = image_symbol_binding_t::global;
    vtable.defined = true;
    image.symbols.push_back(std::move(vtable));
    return image;
}

void write_u64(std::vector<std::uint8_t>& bytes, std::size_t offset,
               std::uint64_t value)
{
    for (std::size_t index = 0; index < 8; ++index)
        bytes[offset + index] = static_cast<std::uint8_t>(value >> (index * 8U));
}

std::vector<std::uint8_t> make_bytes(const workspace_image_t& image)
{
    std::vector<std::uint8_t> bytes(
        static_cast<std::size_t>(image.provider_size), 0);
    write_u64(bytes, 0x2000, image.image_base + 0x1000);
    write_u64(bytes, 0x2008, image.image_base + 0x1010);
    write_u64(bytes, 0x2010, 0xfefefefefefefefeULL);
    const std::string ascii = "AsciiText";
    std::copy(ascii.begin(), ascii.end(), bytes.begin() + 0x2100);
    const std::vector<std::uint8_t> utf8{0x43, 0x61, 0x66, 0xc3, 0xa9, 0};
    std::copy(utf8.begin(), utf8.end(), bytes.begin() + 0x2120);
    const std::vector<std::uint8_t> utf16{
        0x57, 0, 0x69, 0, 0x64, 0, 0x65, 0, 0, 0};
    std::copy(utf16.begin(), utf16.end(), bytes.begin() + 0x2140);
    const std::vector<std::uint8_t> invalid_utf8{0xc3, 0x28, 0xa0, 0xa1, 0};
    std::copy(invalid_utf8.begin(), invalid_utf8.end(), bytes.begin() + 0x2160);
    std::fill(bytes.begin() + 0x2180, bytes.begin() + 0x21c0,
        static_cast<std::uint8_t>('A'));
    bytes[0x21c0] = 0;
    return bytes;
}

std::vector<data_pointer_seed_t> pointer_seeds(bool reverse)
{
    std::vector<data_pointer_seed_t> seeds;
    data_pointer_seed_t valid;
    valid.slot = rva(0x2000);
    valid.kind = data_candidate_kind_t::in_image_pointer;
    valid.width_bytes = 8;
    valid.provenance = fact_provenance_t::relocation;
    valid.confidence = 92;
    valid.read_target_from_image = true;
    seeds.push_back(valid);
    seeds.push_back(valid);
    data_pointer_seed_t conflict = valid;
    conflict.target = rva(0x1010);
    conflict.read_target_from_image = false;
    conflict.confidence = 80;
    seeds.push_back(std::move(conflict));
    data_pointer_seed_t invalid = valid;
    invalid.slot = rva(0x2010);
    invalid.confidence = 70;
    seeds.push_back(std::move(invalid));
    if (reverse)
        std::reverse(seeds.begin(), seeds.end());
    return seeds;
}

std::uint64_t mix(std::uint64_t value) noexcept
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    return value ^ (value >> 31U);
}

std::uint64_t combine(std::uint64_t seed, std::uint64_t value) noexcept
{
    return mix(seed ^ (mix(value) + 0x9e3779b97f4a7c15ULL +
        (seed << 6U) + (seed >> 2U)));
}

std::uint64_t combine_text(std::uint64_t seed, std::string_view value) noexcept
{
    seed = combine(seed, value.size());
    for (const auto character : value)
        seed = combine(seed, static_cast<unsigned char>(character));
    return seed;
}

std::uint64_t data_signature(const data_discovery_result_t& result) noexcept
{
    std::uint64_t value = 0xc303da7aULL;
    value = combine(value, result.bytes_scanned);
    value = combine(value, result.mapped_bytes);
    value = combine(value, result.provider_leases);
    value = combine(value, result.invalid_pointer_values);
    value = combine(value, result.duplicate_candidates);
    value = combine(value, result.duplicate_pointer_facts);
    for (const auto& candidate : result.candidates) {
        value = combine(value, candidate.id);
        value = combine(value, candidate.address.value);
        value = combine(value, candidate.size);
        value = combine(value, static_cast<std::uint64_t>(candidate.kind));
        value = combine(value, candidate.target ? candidate.target->value : 0);
        value = combine(value, static_cast<std::uint64_t>(candidate.provenance));
        value = combine(value, candidate.confidence);
    }
    for (const auto& pointer : result.pointer_facts) {
        value = combine(value, pointer.id);
        value = combine(value, pointer.slot.value);
        value = combine(value, pointer.target.value);
        value = combine(value, static_cast<std::uint64_t>(pointer.candidate_kind));
        value = combine(value, static_cast<std::uint64_t>(pointer.encoding));
        value = combine(value, pointer.width_bytes);
        value = combine(value, static_cast<std::uint64_t>(pointer.provenance));
        value = combine(value, pointer.confidence);
    }
    for (const auto& conflict : result.conflicts) {
        value = combine(value, conflict.id);
        value = combine(value, conflict.address.value);
        value = combine(value, static_cast<std::uint64_t>(conflict.kind));
        value = combine(value, conflict.selected_target
            ? conflict.selected_target->value : 0);
        value = combine(value, conflict.rejected_target
            ? conflict.rejected_target->value : 0);
        value = combine(value,
            static_cast<std::uint64_t>(conflict.selected_provenance));
        value = combine(value,
            static_cast<std::uint64_t>(conflict.rejected_provenance));
        value = combine(value, conflict.selected_confidence);
        value = combine(value, conflict.rejected_confidence);
    }
    return value;
}

std::uint64_t symbol_signature(const symbol_type_candidate_result_t& result) noexcept
{
    std::uint64_t value = 0xc3037a9eULL;
    value = combine(value, result.duplicate_symbols);
    value = combine(value, result.duplicate_type_candidates);
    value = combine(value, result.duplicate_type_references);
    for (const auto& symbol : result.symbols) {
        value = combine(value, symbol.id);
        value = combine(value, symbol.address.value);
        value = combine(value, static_cast<std::uint64_t>(symbol.kind));
        value = combine(value, static_cast<std::uint64_t>(symbol.provenance));
        value = combine(value, symbol.confidence);
        value = combine_text(value, symbol.name);
    }
    for (const auto& type : result.type_candidates) {
        value = combine(value, type.id);
        value = combine(value, type.address ? type.address->value : 0);
        value = combine(value, type.related_address ? type.related_address->value : 0);
        value = combine(value, static_cast<std::uint64_t>(type.kind));
        value = combine(value, static_cast<std::uint64_t>(type.provenance));
        value = combine(value, type.confidence);
        value = combine(value, type.explicitly_unknown ? 1 : 0);
        value = combine_text(value, type.display_name);
        value = combine_text(value, type.canonical_type);
        value = combine_text(value, type.source_key);
    }
    for (const auto& reference : result.type_references) {
        value = combine(value, reference.id);
        value = combine(value, reference.source ? reference.source->value : 0);
        value = combine(value, reference.target ? reference.target->value : 0);
        value = combine(value, reference.source_entity);
        value = combine(value, reference.target_entity);
        value = combine(value, static_cast<std::uint64_t>(reference.kind));
        value = combine(value, static_cast<std::uint64_t>(reference.provenance));
        value = combine(value, reference.confidence);
        value = combine_text(value, reference.source_key);
    }
    for (const auto& conflict : result.conflicts) {
        value = combine(value, conflict.id);
        value = combine(value, conflict.address ? conflict.address->value : 0);
        value = combine(value, static_cast<std::uint64_t>(conflict.kind));
        value = combine(value,
            static_cast<std::uint64_t>(conflict.selected_provenance));
        value = combine(value,
            static_cast<std::uint64_t>(conflict.rejected_provenance));
        value = combine(value, conflict.selected_confidence);
        value = combine(value, conflict.rejected_confidence);
        value = combine_text(value, conflict.identity);
        value = combine_text(value, conflict.selected_value);
        value = combine_text(value, conflict.rejected_value);
    }
    return value;
}

data_discovery_result_t discover_data(const workspace_image_t& image,
                                      const memory_provider_t& provider,
                                      bool reverse)
{
    data_discovery_limits_t limits;
    limits.max_pointer_scan_bytes = 0;
    return require_value(data_discovery_t::discover(image, provider, {}, {},
        pointer_seeds(reverse), limits, {}), "data discovery failed");
}

std::vector<function_record_t> functions()
{
    std::vector<function_record_t> result;
    function_record_t first;
    first.id = (3ULL << 56U) | 1ULL;
    first.start = rva(0x1000);
    first.end = rva(0x1001);
    first.provenance = fact_provenance_t::debug_symbol;
    first.confidence = 95;
    result.push_back(first);
    function_record_t second = first;
    second.id = (3ULL << 56U) | 2ULL;
    second.start = rva(0x1010);
    second.end = rva(0x1011);
    result.push_back(second);
    return result;
}

symbol_type_candidate_result_t discover_symbols(
    workspace_image_t image,
    const std::vector<data_candidate_record_t>& data_candidates,
    bool reverse)
{
    if (reverse) {
        std::reverse(image.symbols.begin(), image.symbols.end());
        std::reverse(image.exports.begin(), image.exports.end());
    }
    return require_value(symbol_type_candidate_builder_t::build(image, functions(),
        data_candidates, {}, {}, {}), "symbol and type discovery failed");
}

string_discovery_result_t discover_strings(const workspace_image_t& image,
                                            const memory_provider_t& provider)
{
    string_discovery_limits_t limits;
    limits.max_string_bytes = 16;
    limits.max_string_value_bytes = 16;
    limits.minimum_code_points = 4;
    limits.scan_executable_regions = false;
    limits.require_null_terminator = true;
    return require_value(string_discovery_t::discover(image, provider, limits, {}),
        "string discovery failed");
}

void append_instruction_facts(analysis_snapshot_t& snapshot)
{
    instruction_record_t instruction;
    instruction.id = (1ULL << 56U) | 1ULL;
    instruction.address = rva(0x1000);
    instruction.length = 1;
    instruction.flow_flags = flow_fallthrough;
    instruction.target_fact_begin = 0;
    instruction.target_fact_count = 2;
    instruction.provenance = fact_provenance_t::recursive_decode;
    instruction.confidence = 95;
    instruction.coverage = coverage_reason_t::decoded;
    snapshot.instructions.push_back(instruction);
    for (std::size_t index = 0; index < 2; ++index) {
        target_fact_t target;
        target.instruction_id = instruction.id;
        target.target = rva(0x2000);
        target.kind = target_kind_record_t::data;
        target.resolution = target_resolution_t::image_relative;
        target.direct = true;
        snapshot.target_facts.push_back(std::move(target));
    }
}

void test_data_deduplication_invalid_pointers_and_stable_ids()
{
    const auto image = make_image();
    memory_provider_t provider(make_bytes(image));
    const auto forward = discover_data(image, provider, false);
    const auto reverse = discover_data(image, provider, true);
    require(data_signature(forward) == data_signature(reverse),
            "shuffled pointer evidence changed data discovery identities");
    require(forward.duplicate_candidates != 0 &&
                forward.duplicate_pointer_facts != 0 &&
                forward.invalid_pointer_values != 0 && !forward.conflicts.empty(),
            "data discovery omitted deduplication, invalid-pointer, or conflict facts");
    const auto retained = std::find_if(forward.pointer_facts.begin(),
        forward.pointer_facts.end(), [](const data_pointer_fact_t& pointer) {
            return pointer.slot.value == 0x2000 && pointer.target.value == 0x1000;
        });
    require(retained != forward.pointer_facts.end(),
            "valid relocatable pointer fact was not retained");
}

void test_string_encodings_and_bounds()
{
    const auto image = make_image();
    memory_provider_t provider(make_bytes(image));
    const auto strings = discover_strings(image, provider);
    bool ascii = false;
    bool utf8 = false;
    bool utf16 = false;
    for (const auto& string : strings.strings) {
        ascii = ascii || (string.address.value == 0x2100 &&
            string.encoding == string_encoding_t::ascii);
        utf8 = utf8 || (string.address.value == 0x2120 &&
            string.encoding == string_encoding_t::utf8);
        utf16 = utf16 || (string.address.value == 0x2140 &&
            string.encoding == string_encoding_t::utf16_le);
        require(string.byte_length <= 16, "oversized string escaped discovery bounds");
    }
    require(ascii && utf8 && utf16 &&
                strings.rejected_invalid_sequences != 0 &&
                strings.rejected_oversized_strings != 0,
            "string encoding or rejection evidence is incomplete");
}

void test_rich_fact_publication_and_metadata_conflicts()
{
    const auto image = make_image();
    memory_provider_t provider(make_bytes(image));
    auto data = discover_data(image, provider, false);
    auto symbols = discover_symbols(image, data.candidates, false);
    const auto reversed_symbols = discover_symbols(image, data.candidates, true);
    require(symbol_signature(symbols) == symbol_signature(reversed_symbols),
            "shuffled symbol metadata changed stable identities");
    const auto metadata_conflict = std::find_if(symbols.conflicts.begin(),
        symbols.conflicts.end(), [](const metadata_conflict_record_t& conflict) {
            return conflict.kind == metadata_conflict_kind_t::symbol_kind;
        });
    const auto vtable = std::find_if(symbols.type_candidates.begin(),
        symbols.type_candidates.end(), [](const symbol_type_candidate_record_t& type) {
            return type.kind == symbol_type_candidate_kind_t::virtual_table;
        });
    require(metadata_conflict != symbols.conflicts.end() &&
                vtable != symbols.type_candidates.end() &&
                !symbols.type_references.empty(),
            "metadata conflicts, vtable types, or type references were omitted");
    analysis_snapshot_t snapshot;
    snapshot.binary_id.bytes[0] = 0xc3;
    snapshot.load_profile_hash.bytes[0] = 0x33;
    snapshot.generation = 1;
    snapshot.analysis_revision = 1;
    snapshot.normalized_image = std::make_shared<const workspace_image_t>(image);
    append_instruction_facts(snapshot);
    auto xrefs = require_value(xref_builder_t::build(image, snapshot.instructions,
        snapshot.operand_facts, snapshot.target_facts,
        std::make_shared<data_discovery_result_t>(std::move(data)),
        symbols.type_references, {}, {}), "xref construction failed");
    require(xrefs.duplicate_xrefs != 0 && !xrefs.data_pointer_facts.empty(),
            "xref construction dropped duplicate accounting or pointer facts");
    auto strings = discover_strings(image, provider);
    const auto published = xref_builder_t::publish(snapshot, std::move(xrefs),
        std::move(strings), std::move(symbols), {});
    require(static_cast<bool>(published), "rich fact publication was rejected");
    const auto validated = validate_analysis_snapshot(snapshot, false, {});
    require(static_cast<bool>(validated),
            "snapshot rejected published C03 rich facts");
    require(!snapshot.rich_facts.data_pointer_facts.empty() &&
                !snapshot.rich_facts.type_references.empty() &&
                !snapshot.rich_facts.metadata_conflicts.empty(),
            "rich fact publication lost pointer, type-reference, or conflict facts");
    auto malformed_pointer = snapshot.rich_facts;
    malformed_pointer.data_pointer_facts.front().width_bytes = 3;
    const auto pointer_rejected = validate_rich_fact_publication(
        snapshot, malformed_pointer, {});
    require(!pointer_rejected,
            "invalid pointer width passed rich fact publication validation");
    auto malformed_conflict = snapshot.rich_facts;
    malformed_conflict.metadata_conflicts.front().rejected_value =
        malformed_conflict.metadata_conflicts.front().selected_value;
    const auto conflict_rejected = validate_rich_fact_publication(
        snapshot, malformed_conflict, {});
    require(!conflict_rejected,
            "degenerate metadata conflict passed rich fact publication validation");
}

void test_cross_format_normalized_discovery()
{
    constexpr std::array<std::pair<format_id_t, abi_id_t>, 3> formats{{
        {format_id_t::pe32_plus, abi_id_t::windows_x64},
        {format_id_t::elf, abi_id_t::linux_x64},
        {format_id_t::macho, abi_id_t::darwin_x86_64}
    }};
    std::uint64_t expected_data_signature = 0;
    std::uint64_t expected_symbol_signature = 0;
    for (std::size_t index = 0; index < formats.size(); ++index) {
        const auto image = make_image(formats[index].first, formats[index].second);
        memory_provider_t provider(make_bytes(image));
        auto data = discover_data(image, provider, false);
        auto symbols = discover_symbols(image, data.candidates, false);
        const auto data_value = data_signature(data);
        const auto symbol_value = symbol_signature(symbols);
        if (index == 0) {
            expected_data_signature = data_value;
            expected_symbol_signature = symbol_value;
        }
        require(data_value == expected_data_signature &&
                    symbol_value == expected_symbol_signature,
                "normalized cross-format discovery changed stable identities");
        auto xrefs = require_value(xref_builder_t::build(image, {}, {}, {},
            std::move(data), symbols.type_references, {}, {}),
            "cross-format xref construction failed");
        const auto strings = discover_strings(image, provider);
        require(!xrefs.xrefs.empty() && !xrefs.data_pointer_facts.empty() &&
                    !strings.strings.empty() && !symbols.type_candidates.empty(),
                "cross-format discovery omitted normalized rich facts");
    }
}

}

bool run_xref_discovery_harness(std::string& failure)
{
    try {
        test_data_deduplication_invalid_pointers_and_stable_ids();
        test_string_encodings_and_bounds();
        test_rich_fact_publication_and_metadata_conflicts();
        test_cross_format_normalized_discovery();
        return true;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    return aida::analysis::c03::run_xref_discovery_harness(failure) ? 0 : 1;
}
