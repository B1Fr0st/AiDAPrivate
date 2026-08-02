#include "search_query_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "analysis_memory_provider.hpp"
#include "../../src/core/analysis/provider_snapshot.hpp"
#include "../../src/core/analysis/workspace/query_index.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace aida::analysis::c03 {
namespace {

constexpr std::uint64_t kGeneration = 41;
constexpr std::uint64_t kAnalysisRevision = 7;
constexpr std::uint64_t kOverlayRevision = 3;

class sealed_memory_provider_t final : public byte_provider_t {
public:
    static workspace_result_t<std::shared_ptr<sealed_memory_provider_t>> create(
        std::vector<std::uint8_t> bytes) {
        try {
            auto source = std::make_shared<memory_provider_t>(std::move(bytes),
                "c03://search-query-fixture");
            auto digest = source->compute_content_sha256();
            if (!digest) {
                return workspace_result_t<std::shared_ptr<sealed_memory_provider_t>>::failure(
                    digest.error());
            }
            auto identity = source->identity();
            identity.content_sha256 = digest.take_value();
            identity.file_id[0] = 0xC0;
            identity.file_id[1] = 0x04;
            return workspace_result_t<std::shared_ptr<sealed_memory_provider_t>>::success(
                std::shared_ptr<sealed_memory_provider_t>(new sealed_memory_provider_t(
                    std::move(source), std::move(identity))));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::shared_ptr<sealed_memory_provider_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "sealed fixture provider allocation failed", "search_query_harness"));
        }
    }

    const byte_provider_identity_t& identity() const noexcept override {
        return identity_;
    }

    std::uint64_t size() const noexcept override {
        return source_->size();
    }

    std::uint64_t maximum_contiguous_lease(std::uint64_t offset) const noexcept override {
        return source_->maximum_contiguous_lease(offset);
    }

    workspace_result_t<byte_view_t> lease(std::uint64_t offset, std::uint64_t size,
        const cancellation_token_t& cancel = {}) const override {
        return source_->lease(offset, size, cancel);
    }

private:
    sealed_memory_provider_t(std::shared_ptr<const memory_provider_t> source,
        byte_provider_identity_t identity)
        : source_(std::move(source)), identity_(std::move(identity)) {}

    std::shared_ptr<const memory_provider_t> source_;
    byte_provider_identity_t identity_;
};

void require(bool condition, std::string_view message) {
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename T>
T require_value(workspace_result_t<T> result, std::string_view message) {
	const bool accepted = static_cast<bool>(result);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(std::string(message) + ": " + result.error().stable_code());
    return result.take_value();
}

template <typename T>
void require_error(workspace_result_t<T> result, workspace_error_code_t code,
    std::string_view message) {
	const bool accepted = !result && result.error().code == code;
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(std::string(message));
}

address_t relative_address(std::uint64_t value) {
    return address_t{address_space_id_t::relative_virtual, value,
        architecture_id_t::x86_64, architecture_mode_t::x86_64};
}

binary_id_t identity_bytes(std::uint8_t seed) {
    binary_id_t result;
    for (std::size_t index = 0; index < result.bytes.size(); ++index)
        result.bytes[index] = static_cast<std::uint8_t>(seed + index);
    return result;
}

std::vector<std::uint8_t> fixture_bytes() {
    std::vector<std::uint8_t> bytes(64, 0x90U);
    const std::array<std::uint8_t, 4> exact{0xDEU, 0xADU, 0xBEU, 0xEFU};
    for (const std::size_t offset : {7U, 18U, 31U})
        std::copy(exact.begin(), exact.end(), bytes.begin() + offset);
    bytes[12] = 0xABU;
    bytes[13] = 0xCDU;
    bytes[40] = 0xA1U;
    bytes[41] = 0x2DU;
    return bytes;
}

symbol_record_t symbol(entity_id_t id, std::uint64_t address_value,
    std::string name, symbol_kind_t kind) {
    symbol_record_t result;
    result.id = id;
    result.address = relative_address(address_value);
    result.name = std::move(name);
    result.kind = kind;
    result.provenance = fact_provenance_t::debug_symbol;
    result.confidence = 95;
    return result;
}

string_record_t string_record(entity_id_t id, std::uint64_t address_value,
    std::string value, string_encoding_t encoding = string_encoding_t::utf8) {
    string_record_t result;
    result.id = id;
    result.address = relative_address(address_value);
    result.byte_length = value.size();
    result.encoding = encoding;
    result.value = std::move(value);
    result.provenance = fact_provenance_t::recursive_decode;
    result.confidence = 94;
    return result;
}

instruction_record_t instruction(entity_id_t id, std::uint64_t address_value,
    std::uint32_t opcode, std::uint32_t flow) {
    instruction_record_t result;
    result.id = id;
    result.address = relative_address(address_value);
    result.length = 1;
    result.opcode_id = opcode;
    result.flow_flags = flow;
    result.provenance = fact_provenance_t::recursive_decode;
    result.confidence = 98;
    result.stable_source_id = address_value;
    return result;
}

operand_fact_t immediate(entity_id_t id, entity_id_t instruction_id,
    std::uint64_t value) {
    operand_fact_t result;
    result.id = id;
    result.instruction_id = instruction_id;
    result.kind = operand_kind_t::immediate;
    result.immediate = value;
    result.bit_width = 64;
    return result;
}

std::shared_ptr<analysis_snapshot_t> analysis_snapshot(
    const sha256_digest_t& provider_hash, std::uint64_t provider_size) {
    auto snapshot = std::make_shared<analysis_snapshot_t>();
    snapshot->binary_id = identity_bytes(0x11U);
    snapshot->load_profile_hash = identity_bytes(0x51U);
    snapshot->generation = kGeneration;
    snapshot->analysis_revision = kAnalysisRevision;
    snapshot->overlay_revision = kOverlayRevision;
    snapshot->baseline_complete = true;

    auto image = std::make_shared<workspace_image_t>();
    image->format = format_id_t::pe32_plus;
    image->architecture = architecture_id_t::x86_64;
    image->architecture_mode = architecture_mode_t::x86_64;
    image->abi = abi_id_t::windows_x64;
    image->address_width_bits = 64;
    image->image_base = 0x140000000ULL;
    image->image_size = 0x10000;
    image->provider_size = provider_size;
    image->provider_content_hash = provider_hash;
    image->workspace_binary_id = snapshot->binary_id;
    image->provider_binding_verified = true;
    snapshot->normalized_image = std::move(image);

    const std::string unicode_name = std::string("CAF") + "\xC3\x89" + "_" + "\xCE\x94";
    snapshot->symbols.push_back(symbol(101, 0x1000, "AlphaParser", symbol_kind_t::function));
    snapshot->symbols.push_back(symbol(102, 0x1010, "NeedleWorker", symbol_kind_t::function));
    snapshot->symbols.push_back(symbol(103, 0x1020, "needle_worker", symbol_kind_t::data));
    snapshot->symbols.push_back(symbol(104, 0x1030, unicode_name, symbol_kind_t::debug_symbol));

    snapshot->strings.push_back(string_record(201, 0x2000, "Needle payload"));
    snapshot->strings.push_back(string_record(202, 0x2010, "Needle payload"));
    snapshot->strings.push_back(string_record(203, 0x2020, "needle payload"));
    snapshot->strings.push_back(string_record(204, 0x2030, "prefix Needle suffix"));
    snapshot->strings.push_back(string_record(205, 0x2040,
        std::string(1, static_cast<char>(0xFF)) + "broken"));

    snapshot->instructions.push_back(instruction(301, 0x3000, 0x90,
        flow_fallthrough));
    snapshot->instructions.push_back(instruction(302, 0x3010, 0xE8,
        flow_call | flow_direct | flow_fallthrough));
    snapshot->instructions.push_back(instruction(303, 0x3020, 0xE8,
        flow_call | flow_indirect));
    snapshot->instructions.push_back(instruction(304, 0x3030, 0xC3,
        flow_return | flow_terminal));
    snapshot->operand_facts.append(immediate(701, 302, 0x1234), 1);
    snapshot->operand_facts.append(immediate(702, 303, 0x5678), 2);
    return snapshot;
}

std::vector<data_candidate_record_t> data_candidates() {
    data_candidate_record_t value;
    value.id = 501;
    value.address = relative_address(0x5000);
    value.size = 8;
    value.kind = data_candidate_kind_t::in_image_pointer;
    value.target = relative_address(0x1000);
    value.provenance = fact_provenance_t::relocation;
    value.confidence = 92;
    return {value};
}

std::vector<switch_record_t> switches() {
    switch_record_t value;
    value.id = 601;
    value.function_id = 101;
    value.dispatch = relative_address(0x6000);
    value.table = relative_address(0x6100);
    value.case_targets = {relative_address(0x6200), relative_address(0x6300)};
    value.entry_size = 4;
    value.provenance = fact_provenance_t::recursive_decode;
    value.confidence = 91;
    return {value};
}

std::vector<type_candidate_record_t> types() {
    type_candidate_record_t first;
    first.id = 401;
    first.address = relative_address(0x4000);
    first.kind = type_candidate_kind_t::global_object;
    first.display_name = "NeedleType";
    first.canonical_type = "struct NeedleType *";
    first.provenance = fact_provenance_t::debug_symbol;
    first.confidence = 93;
    first.explicitly_unknown = false;

    type_candidate_record_t second;
    second.id = 402;
    second.address = relative_address(0x4010);
    second.kind = type_candidate_kind_t::function_prototype;
    second.display_name = "CafeType";
    second.canonical_type = "int (__fastcall *)(void *)";
    second.provenance = fact_provenance_t::debug_symbol;
    second.confidence = 90;
    second.explicitly_unknown = false;
    return {std::move(first), std::move(second)};
}

search_index_limits_t search_limits() {
    search_index_limits_t limits;
    limits.max_entries = 64;
    limits.max_trigram_postings = 4096;
    limits.max_indexed_text_bytes = 64U * 1024U;
    limits.max_index_bytes = 2U * 1024U * 1024U;
    limits.max_query_bytes = 1024;
    limits.max_results_per_query = 128;
    limits.cancellation_check_interval = 1;
    return limits;
}

query_index_limits_t query_limits() {
    query_index_limits_t limits;
    limits.max_page_size = 128;
    limits.max_query_bytes = 1024;
    limits.max_byte_pattern_bytes = 32;
    limits.max_bytes_scanned_per_page = 12;
    limits.byte_scan_window_bytes = 8;
    limits.max_regex_candidates = 64;
    limits.cancellation_check_interval = 1;
    limits.max_query_elapsed_ns = 1000ULL * 1000ULL * 1000ULL;
    limits.regex.max_pattern_bytes = 256;
    limits.regex.max_subject_bytes = 16U * 1024U;
    limits.regex.max_compiled_bytes = 64U * 1024U;
    limits.regex.max_capture_count = 16;
    limits.regex.max_parenthesis_depth = 64;
    limits.regex.max_variable_lookbehind = 64;
    limits.regex.match_limit = 10000;
    limits.regex.depth_limit = 256;
    limits.regex.heap_limit_kib = 1024;
    limits.regex.max_elapsed_ns = 250ULL * 1000ULL * 1000ULL;
    return limits;
}

struct fixture_t {
    std::shared_ptr<sealed_memory_provider_t> source;
    std::shared_ptr<provider_snapshot_t> provider;
    std::shared_ptr<analysis_snapshot_t> snapshot;
    std::shared_ptr<search_index_t> search;
    std::shared_ptr<const query_index_t> query;
    std::shared_ptr<std::vector<query_telemetry_t>> telemetry;
    query_index_limits_t limits;
};

fixture_t make_fixture() {
    fixture_t fixture;
    fixture.source = require_value(sealed_memory_provider_t::create(fixture_bytes()),
        "fixture provider creation failed");
    fixture.provider = require_value(provider_snapshot_t::capture(
        fixture.source, kGeneration), "fixture provider capture failed");
    require(fixture.provider->identity().content_sha256.has_value(),
        "fixture provider hash is absent");
    fixture.snapshot = analysis_snapshot(*fixture.provider->identity().content_sha256,
        fixture.provider->size());
    fixture.search = require_value(search_index_t::build(fixture.snapshot,
        data_candidates(), switches(), types(),
        std::make_shared<analysis_metrics_t>(kGeneration), search_limits(), {}),
        "fixture search index build failed");
    fixture.telemetry = std::make_shared<std::vector<query_telemetry_t>>();
    fixture.limits = query_limits();
    fixture.query = require_value(query_index_t::build(fixture.search, fixture.provider,
        fixture.limits, [events = fixture.telemetry](const query_telemetry_t& value) {
            events->push_back(value);
        }), "fixture query index build failed");
    return fixture;
}

std::set<entity_id_t> entity_ids(const std::vector<search_hit_t>& hits);

void verify_serialized_round_trip(fixture_t& fixture) {
    const auto expected_size = require_value(fixture.search->serialized_size({}),
        "serialized search size failed");
    require(expected_size != 0 &&
        expected_size <= static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()),
        "serialized search size is outside addressable memory");
    std::vector<std::uint8_t> serialized;
    serialized.reserve(static_cast<std::size_t>(expected_size));
    auto serialized_result = fixture.search->serialize_to(
        [&serialized](const std::uint8_t* data, std::size_t size) {
            serialized.insert(serialized.end(), data, data + size);
            return workspace_result_t<void>::success();
        });
    require(static_cast<bool>(serialized_result), "serialized search write failed");
    require(serialized.size() == expected_size,
        "serialized search size diverged from the streamed byte count");

    auto restored = require_value(search_index_t::restore(
        fixture.snapshot, data_candidates(), switches(), types(),
        std::make_shared<analysis_metrics_t>(kGeneration), search_limits(),
        serialized, {}), "serialized search restore failed");
    require(restored->matches(fixture.snapshot) &&
        restored->identity() == fixture.search->identity() &&
        restored->record_count() == fixture.search->record_count() &&
        restored->text_record_count() == fixture.search->text_record_count() &&
        restored->data_candidates().size() == fixture.search->data_candidates().size() &&
        restored->switches().size() == fixture.search->switches().size() &&
        restored->types().size() == fixture.search->types().size(),
        "restored search generation diverged from its immutable source index");

    const auto original_page = require_value(
        fixture.search->find_text("needle payload", 0, 16, {}),
        "source packed-index comparison query failed");
    const auto restored_page = require_value(
        restored->find_text("needle payload", 0, 16, {}),
        "restored packed-index comparison query failed");
    require(original_page.total == restored_page.total &&
        original_page.truncated == restored_page.truncated &&
        entity_ids(original_page.hits) == entity_ids(restored_page.hits),
        "restored packed-index query results diverged");

    auto restored_query = require_value(query_index_t::build(
        restored, fixture.provider, fixture.limits),
        "restored query-index construction failed");
    const auto restored_query_page = require_value(restored_query->query(
        search_query_t{literal_search_query_t{"Needle", true}}),
        "restored production query failed");
    require(restored_query_page.total == 5 &&
        entity_ids(restored_query_page.hits) ==
            std::set<entity_id_t>{102, 201, 202, 204, 401},
        "restored production query results diverged");

    cancellation_source_t cancelled;
    cancelled.request_cancel();
    require_error(fixture.search->serialized_size(cancelled.token()),
        workspace_error_code_t::cancelled,
        "cancelled serialized-size request succeeded");
    require_error(fixture.search->serialize_to(
        [](const std::uint8_t*, std::size_t) {
            return workspace_result_t<void>::success();
        }, cancelled.token()), workspace_error_code_t::cancelled,
        "cancelled serialized write succeeded");
    require_error(search_index_t::restore(
        fixture.snapshot, data_candidates(), switches(), types(),
        std::make_shared<analysis_metrics_t>(kGeneration), search_limits(),
        serialized, cancelled.token()), workspace_error_code_t::cancelled,
        "cancelled serialized restore succeeded");

    auto corrupted = serialized;
    corrupted.front() ^= 0x80U;
    require_error(search_index_t::restore(
        fixture.snapshot, data_candidates(), switches(), types(),
        std::make_shared<analysis_metrics_t>(kGeneration), search_limits(),
        corrupted, {}), workspace_error_code_t::integrity_failure,
        "corrupted serialized search index restored");
    auto truncated = serialized;
    truncated.erase(truncated.begin() + 8);
    require_error(search_index_t::restore(
        fixture.snapshot, data_candidates(), switches(), types(),
        std::make_shared<analysis_metrics_t>(kGeneration), search_limits(),
        truncated, {}), workspace_error_code_t::integrity_failure,
        "truncated serialized search index restored");
}

void verify_index_accounting(fixture_t& fixture) {
    require(fixture.search->record_count() == 17, "packed record count diverged");
    require(fixture.search->text_record_count() == 11, "packed text count diverged");
    const auto accounting = fixture.search->size_accounting();
    require(accounting.record_count == 17, "record accounting diverged");
    require(accounting.text_reference_count == 11, "text-reference accounting diverged");
    require(accounting.source_text_bytes == 131, "source-text accounting diverged");
    require(accounting.referenced_text_bytes == 262,
        "referenced-text accounting diverged");
    require(accounting.string_count == 16, "interned string count diverged");
    require(accounting.unique_text_bytes == 186, "interned byte count diverged");
    require(accounting.unique_text_bytes < accounting.referenced_text_bytes,
        "final search text was not interned");
    require(accounting.memory_bytes == fixture.search->memory_bytes(),
        "memory accounting accessor diverged");
    require(fixture.search->generation_handle().valid(),
        "immutable generation handle is invalid");
    require(fixture.query->identity() == fixture.search->identity(),
        "query identity diverged from the search generation");
    require(fixture.query->has_byte_provider(), "query byte provider is absent");

    const auto frozen_identity = fixture.search->identity();
    const auto copied_snapshot = std::make_shared<analysis_snapshot_t>(*fixture.snapshot);
    require(!fixture.search->matches(copied_snapshot),
        "copied snapshot ownership was accepted by the immutable index");
    fixture.snapshot->symbols[0].name = "mutated-source-alias";
    auto packed_alias_query = require_value(fixture.query->query(
        search_query_t{literal_search_query_t{"AlphaParser", true}}),
        "packed source-alias query failed");
    require(packed_alias_query.total == 1 && packed_alias_query.hits[0].entity_id == 101,
        "packed text changed through a mutable source alias");
    ++fixture.snapshot->generation;
    require(fixture.search->identity() == frozen_identity,
        "search identity changed through a mutable source alias");
    require(fixture.search->generation_handle().valid(),
        "generation handle changed through a mutable source alias");
    require(!fixture.search->matches(fixture.snapshot),
        "mutated source alias still matched the immutable index");
    --fixture.snapshot->generation;
    fixture.snapshot->symbols[0].name = "AlphaParser";
    require(fixture.search->matches(fixture.snapshot),
        "restored source identity no longer matched the immutable index");
}

std::set<entity_id_t> entity_ids(const std::vector<search_hit_t>& hits) {
    std::set<entity_id_t> result;
    for (const auto& hit : hits)
        result.insert(hit.entity_id);
    return result;
}

void verify_literal_queries(fixture_t& fixture) {
    const search_query_t query = literal_search_query_t{"Needle", true};
    query_page_request_t request;
    request.limit = 2;
    auto first = require_value(fixture.query->query(query, request),
        "literal first page failed");
    require(first.total == 5 && first.total_is_exact && first.hits.size() == 2 &&
        first.truncated && first.next, "literal first page contract diverged");
    require(first.next->position == 2 && first.next->matches_consumed == 2 &&
        first.next->integrity_tag != 0,
        "literal first cursor diverged");

    request.cursor = first.next;
    auto second = require_value(fixture.query->query(query, request),
        "literal second page failed");
    require(second.total == 5 && second.hits.size() == 2 && second.next,
        "literal second page contract diverged");

    request.cursor = second.next;
    auto third = require_value(fixture.query->query(query, request),
        "literal final page failed");
    require(third.total == 5 && third.hits.size() == 1 && !third.truncated && !third.next,
        "literal final page contract diverged");

    std::vector<search_hit_t> all;
    all.insert(all.end(), first.hits.begin(), first.hits.end());
    all.insert(all.end(), second.hits.begin(), second.hits.end());
    all.insert(all.end(), third.hits.begin(), third.hits.end());
    require(entity_ids(all) == std::set<entity_id_t>{102, 201, 202, 204, 401},
        "literal result identities diverged");

    request = {};
    request.limit = 16;
    auto insensitive = require_value(fixture.query->query(
        search_query_t{literal_search_query_t{"needle", false}}, request),
        "case-insensitive literal query failed");
    require(insensitive.total == 7 && insensitive.hits.size() == 7,
        "case-insensitive literal count diverged");

    auto metacharacters = require_value(fixture.query->query(
        search_query_t{literal_search_query_t{"^Needle", false}}, request),
        "literal metacharacter query failed");
    require(metacharacters.total == 0 && metacharacters.hits.empty(),
        "literal metacharacters were interpreted as a regular expression");

    const std::string unicode_query = std::string("caf") + "\xC3\xA9";
    auto unicode = require_value(fixture.query->query(
        search_query_t{literal_search_query_t{unicode_query, false}}, request),
        "Unicode literal query failed");
    require(unicode.total == 1 && unicode.hits[0].entity_id == 104,
        "Unicode case folding diverged");

    const std::string invalid_prefix(1, static_cast<char>(0xFF));
    auto raw = require_value(fixture.query->query(
        search_query_t{literal_search_query_t{invalid_prefix, true}}, request),
        "raw literal query failed");
    require(raw.total == 1 && raw.hits[0].entity_id == 205,
        "raw literal bytes diverged");

    auto normalized = require_value(fixture.search->find_text("needle payload", 0, 16, {}),
        "packed normalized lookup failed");
    require(normalized.total == 3 && normalized.hits.size() == 3,
        "packed normalized lookup count diverged");
}

void verify_regex_queries(fixture_t& fixture) {
    query_page_request_t request;
    request.limit = 16;
    regex_search_query_t exact;
    exact.pattern = "^Needle payload$";
    auto page = require_value(fixture.query->query(search_query_t{exact}, request),
        "regex exact query failed");
    require(page.total == 2 && page.hits.size() == 2,
        "regex exact count diverged");

    exact.options.case_sensitive = false;
    auto insensitive = require_value(fixture.query->query(search_query_t{exact}, request),
        "regex insensitive query failed");
    require(insensitive.total == 3 && insensitive.hits.size() == 3,
        "regex insensitive count diverged");

    auto compiled = require_value(regex_query_t::compile("(Needle)", {},
        fixture.limits.regex), "regex compilation failed");
    require(compiled->capture_count() == 1 && compiled->compiled_bytes() != 0,
        "compiled regex metadata diverged");
    auto match = require_value(compiled->match("prefix Needle suffix"),
        "regex direct match failed");
    require(match.matched && match.start == 7 && match.length == 6 &&
        match.engine_steps != 0, "regex direct match range diverged");

    require_error(regex_query_t::compile("(", {}, fixture.limits.regex),
        workspace_error_code_t::invalid_argument, "invalid regex compiled");
    require_error(compiled->match(std::string(1, static_cast<char>(0xFF))),
        workspace_error_code_t::invalid_argument, "invalid UTF subject matched");

    cancellation_source_t cancelled;
    cancelled.request_cancel();
    require_error(compiled->match("Needle", cancelled.token()),
        workspace_error_code_t::cancelled, "cancelled regex match succeeded");

    auto bounded_limits = fixture.limits.regex;
    bounded_limits.match_limit = 64;
    bounded_limits.depth_limit = 64;
    bounded_limits.max_elapsed_ns = 100ULL * 1000ULL * 1000ULL;
    auto bounded = require_value(regex_query_t::compile(
        "(*NO_AUTO_POSSESS)^(a|aa)+$", {}, bounded_limits),
        "bounded catastrophic regex compilation failed");
    std::string catastrophic(4096, 'a');
    catastrophic.push_back('!');
    auto bounded_result = bounded->match(catastrophic);
    require(!bounded_result &&
        (bounded_result.error().code == workspace_error_code_t::limit_exceeded ||
         bounded_result.error().code == workspace_error_code_t::deadline_exceeded),
        "catastrophic regex escaped resource bounds");

    regex_search_query_t all_valid;
    all_valid.pattern = ".";
    const auto event_index = fixture.telemetry->size();
    auto all_valid_page = require_value(fixture.query->query(
        search_query_t{all_valid}, request), "regex UTF telemetry query failed");
    require(all_valid_page.total == 10, "regex valid-subject count diverged");
    require(fixture.telemetry->size() == event_index + 1 &&
        (*fixture.telemetry)[event_index].invalid_utf_subjects == 1,
        "regex invalid-UTF telemetry diverged");
}

struct byte_collection_t {
    std::vector<std::uint64_t> offsets;
    std::uint64_t total = 0;
    std::uint64_t pages = 0;
};

byte_collection_t collect_bytes(const query_index_t& index,
    const byte_search_query_t& query, std::uint32_t limit) {
    byte_collection_t result;
    query_page_request_t request;
    request.limit = limit;
    std::uint64_t previous_position = query.begin_offset;
    for (std::uint32_t attempt = 0; attempt < 64; ++attempt) {
        auto page = require_value(index.query(search_query_t{query}, request),
            "byte-query page failed");
        ++result.pages;
        for (const auto& hit : page.hits) {
            require(hit.kind == search_entity_kind_t::byte_sequence &&
                hit.address.space == address_space_id_t::file_offset,
                "byte-query hit metadata diverged");
            result.offsets.push_back(hit.address.value);
        }
        if (!page.next) {
            require(page.total_is_exact && !page.truncated,
                "byte-query final page is not exact");
            result.total = page.total;
            return result;
        }
        require(page.truncated && !page.total_is_exact,
            "byte-query continuation is not marked partial");
        require(page.next->position > previous_position,
            "byte-query cursor made no forward progress");
        previous_position = page.next->position;
        request.cursor = page.next;
    }
    throw std::runtime_error("byte-query pagination did not terminate");
}

void verify_byte_queries(fixture_t& fixture) {
    byte_search_query_t exact;
    exact.pattern = {0xDEU, 0xADU, 0xBEU, 0xEFU};
    auto exact_hits = collect_bytes(*fixture.query, exact, 2);
    require(exact_hits.offsets == std::vector<std::uint64_t>{7, 18, 31} &&
        exact_hits.total == 3 && exact_hits.pages == 8,
        "exact byte-query fixtures diverged");

    byte_search_query_t masked;
    masked.pattern = {0xA0U, 0x0DU};
    masked.mask = {0xF0U, 0x0FU};
    auto masked_hits = collect_bytes(*fixture.query, masked, 4);
    require(masked_hits.offsets == std::vector<std::uint64_t>{12, 40} &&
        masked_hits.total == 2, "masked byte-query fixtures diverged");

    exact.begin_offset = 18;
    exact.end_offset = 22;
    auto ranged = collect_bytes(*fixture.query, exact, 4);
    require(ranged.offsets == std::vector<std::uint64_t>{18} && ranged.total == 1,
        "bounded byte-query range diverged");

    auto text_only = require_value(query_index_t::build(fixture.search, {}, fixture.limits),
        "text-only query index build failed");
    require_error(text_only->query(search_query_t{byte_search_query_t{}}),
        workspace_error_code_t::provider_unavailable,
        "byte query without a provider succeeded");

    byte_search_query_t mask_mismatch;
    mask_mismatch.pattern = {0x90U, 0x90U};
    mask_mismatch.mask = {0xFFU};
    require_error(fixture.query->query(search_query_t{mask_mismatch}),
        workspace_error_code_t::invalid_argument, "mismatched byte mask succeeded");

    byte_search_query_t wildcard;
    wildcard.pattern = {0x90U, 0x90U};
    wildcard.mask = {0, 0};
    require_error(fixture.query->query(search_query_t{wildcard}),
        workspace_error_code_t::invalid_argument, "unconstrained byte mask succeeded");

    byte_search_query_t outside;
    outside.pattern = {0x90U};
    outside.begin_offset = fixture.provider->size() + 1;
    require_error(fixture.query->query(search_query_t{outside}),
        workspace_error_code_t::out_of_range, "out-of-range byte query succeeded");

    auto progress_limits = fixture.limits;
    progress_limits.max_bytes_scanned_per_page = 3;
    progress_limits.byte_scan_window_bytes = 3;
    auto progress_index = require_value(query_index_t::build(fixture.search,
        fixture.provider, progress_limits), "small-budget query index build failed");
    byte_search_query_t oversized_for_page;
    oversized_for_page.pattern = {0xDEU, 0xADU, 0xBEU, 0xEFU};
    require_error(progress_index->query(search_query_t{oversized_for_page}),
        workspace_error_code_t::limit_exceeded,
        "non-progressing byte query returned a cursor");

    query_page_request_t first_request;
    first_request.limit = 1;
    auto first = require_value(fixture.query->query(
        search_query_t{byte_search_query_t{{0xDEU, 0xADU, 0xBEU, 0xEFU}}},
        first_request), "byte cursor fixture failed");
    require(first.next.has_value(), "byte cursor fixture has no continuation");
    auto forged = *first.next;
    forged.matches_consumed = forged.position + 1;
    query_page_request_t forged_request;
    forged_request.limit = 1;
    forged_request.cursor = forged;
    require_error(fixture.query->query(
        search_query_t{byte_search_query_t{{0xDEU, 0xADU, 0xBEU, 0xEFU}}},
        forged_request), workspace_error_code_t::invalid_argument,
        "forged byte cursor succeeded");
}

void verify_instruction_entity_address_queries(fixture_t& fixture) {
    instruction_search_query_t opcode;
    opcode.filter.opcode_id = 0xE8;
    query_page_request_t request;
    request.limit = 1;
    auto first = require_value(fixture.query->query(search_query_t{opcode}, request),
        "instruction first page failed");
    require(first.total == 2 && first.hits.size() == 1 && first.next,
        "instruction first page diverged");
    request.cursor = first.next;
    auto second = require_value(fixture.query->query(search_query_t{opcode}, request),
        "instruction final page failed");
    require(second.total == 2 && second.hits.size() == 1 && !second.next,
        "instruction final page diverged");

    instruction_search_query_t combined;
    combined.filter.opcode_id = 0xE8;
    combined.filter.immediate = 0x1234;
    combined.filter.required_flow_flags = flow_call | flow_direct;
    combined.filter.forbidden_flow_flags = flow_indirect;
    auto combined_page = require_value(fixture.query->query(search_query_t{combined}),
        "combined instruction query failed");
    require(combined_page.total == 1 && combined_page.hits[0].entity_id == 302 &&
        combined_page.hits[0].numeric_value == 0x1234,
        "combined instruction result diverged");

    instruction_search_query_t contradictory;
    contradictory.filter.required_flow_flags = flow_call;
    contradictory.filter.forbidden_flow_flags = flow_call;
    require_error(fixture.query->query(search_query_t{contradictory}),
        workspace_error_code_t::invalid_argument,
        "contradictory instruction flags succeeded");

    instruction_search_query_t incomplete_range;
    incomplete_range.filter.begin = relative_address(0x3000);
    require_error(fixture.query->query(search_query_t{incomplete_range}),
        workspace_error_code_t::invalid_argument,
        "incomplete instruction range succeeded");

    entity_search_query_t strings_query;
    strings_query.filter.kind = search_entity_kind_t::string;
    auto strings_page = require_value(fixture.query->query(search_query_t{strings_query}),
        "string entity query failed");
    require(strings_page.total == 5 && strings_page.hits.size() == 5,
        "string entity count diverged");

    entity_search_query_t id_query;
    id_query.filter.entity_id = 501;
    auto id_page = require_value(fixture.query->query(search_query_t{id_query}),
        "identifier entity query failed");
    require(id_page.total == 1 && id_page.hits[0].kind ==
        search_entity_kind_t::data_candidate, "identifier entity result diverged");

    entity_search_query_t all_query;
    auto all_page = require_value(fixture.query->query(search_query_t{all_query}),
        "all-entity query failed");
    require(all_page.total == 17, "all-entity count diverged");

    entity_search_query_t invalid_id;
    invalid_id.filter.entity_id = 0;
    require_error(fixture.query->query(search_query_t{invalid_id}),
        workspace_error_code_t::invalid_argument, "zero entity identifier succeeded");

    address_search_query_t address_query;
    address_query.begin = relative_address(0x1000);
    address_query.end = relative_address(0x1100);
    auto address_page = require_value(fixture.query->query(search_query_t{address_query}),
        "address query failed");
    require(address_page.total == 4 && address_page.hits.size() == 4,
        "address query count diverged");

    std::swap(address_query.begin, address_query.end);
    require_error(fixture.query->query(search_query_t{address_query}),
        workspace_error_code_t::invalid_argument, "reversed address range succeeded");

    require(!fixture.telemetry->empty() && fixture.telemetry->back().outcome ==
        query_outcome_t::invalid, "invalid query telemetry outcome diverged");
}

void verify_cursor_validation(fixture_t& fixture) {
    const search_query_t query = literal_search_query_t{"Needle", true};
    query_page_request_t request;
    request.limit = 2;
    auto page = require_value(fixture.query->query(query, request),
        "cursor source query failed");
    require(page.next.has_value(), "cursor source query has no continuation");

    auto rebuilt = require_value(query_index_t::build(fixture.search, fixture.provider,
        fixture.limits), "cursor rebuild query index failed");
    request.cursor = page.next;
    auto rebuilt_page = require_value(rebuilt->query(query, request),
        "cursor did not survive query-index reconstruction");
    require(rebuilt_page.hits.size() == 2 && rebuilt_page.total == 5,
        "rebuilt query-index cursor page diverged");

    auto wrong_query = *page.next;
    ++wrong_query.query_fingerprint;
    request.cursor = wrong_query;
    require_error(fixture.query->query(query, request),
        workspace_error_code_t::stale_generation,
        "cursor with a wrong query fingerprint succeeded");

    auto wrong_generation = *page.next;
    ++wrong_generation.generation.generation;
    request.cursor = wrong_generation;
    require_error(fixture.query->query(query, request),
        workspace_error_code_t::stale_generation,
        "cursor with a wrong generation succeeded");

    auto malformed = *page.next;
    ++malformed.matches_consumed;
    request.cursor = malformed;
    require_error(fixture.query->query(query, request),
        workspace_error_code_t::invalid_argument,
        "structurally malformed cursor succeeded");

    auto out_of_bounds = *page.next;
    out_of_bounds.position = page.total;
    out_of_bounds.matches_consumed = page.total;
    request.cursor = out_of_bounds;
    require_error(fixture.query->query(query, request),
        workspace_error_code_t::invalid_argument,
        "out-of-bounds exact cursor succeeded");

    request.cursor = page.next;
    require_error(fixture.query->query(
        search_query_t{literal_search_query_t{"Alpha", true}}, request),
        workspace_error_code_t::stale_generation,
        "cursor was reused with another query");
}

void verify_production_variant_apis(fixture_t& fixture) {
    const auto telemetry_begin = fixture.telemetry->size();
    query_page_request_t literal_page;
    literal_page.limit = 2;
    const literal_search_query_t literal{"Needle", true};
    auto literal_result = require_value(
        fixture.query->query_literal(literal, literal_page),
        "named literal query failed");
    require(literal_result.total == 5 && literal_result.next,
        "named literal pagination diverged");
    const search_query_t literal_variant{literal};
    require(static_cast<bool>(fixture.query->validate_cursor(
        literal_variant, *literal_result.next)),
        "public cursor validator rejected an authentic cursor");
    auto forged = *literal_result.next;
    ++forged.integrity_tag;
    require_error(fixture.query->validate_cursor(literal_variant, forged),
        workspace_error_code_t::invalid_argument,
        "public cursor validator accepted a forged integrity tag");

    regex_search_query_t regex;
    regex.pattern = "^Needle payload$";
    auto regex_result = require_value(fixture.query->query_regex(regex),
        "named regex query failed");
    require(regex_result.total == 2, "named regex result diverged");

    byte_search_query_t bytes;
    bytes.pattern = {0xDEU, 0xADU, 0xBEU, 0xEFU};
    auto byte_result = require_value(fixture.query->query_bytes(bytes),
        "named byte query failed");
    require(!byte_result.hits.empty(), "named byte query returned no matches");

    instruction_search_query_t instruction;
    instruction.filter.opcode_id = 0xE8;
    auto instruction_result = require_value(
        fixture.query->query_instruction(instruction),
        "named instruction query failed");
    require(instruction_result.total == 2,
        "named instruction result diverged");

    entity_search_query_t entity;
    entity.filter.kind = search_entity_kind_t::string;
    auto entity_result = require_value(fixture.query->query_entity(entity),
        "named entity query failed");
    require(entity_result.total == 5, "named entity result diverged");

    address_search_query_t address;
    address.begin = relative_address(0x1000);
    address.end = relative_address(0x1100);
    auto address_result = require_value(fixture.query->query_address(address),
        "named address query failed");
    require(address_result.total == 4, "named address result diverged");

    const std::array<search_query_kind_t, 6> expected_kinds{
        search_query_kind_t::literal, search_query_kind_t::regex,
        search_query_kind_t::bytes, search_query_kind_t::instruction,
        search_query_kind_t::entity, search_query_kind_t::address};
    require(fixture.telemetry->size() == telemetry_begin + expected_kinds.size(),
        "named query telemetry emission count diverged");
    for (std::size_t index = 0; index < expected_kinds.size(); ++index) {
        const auto& event = (*fixture.telemetry)[telemetry_begin + index];
        require(event.kind == expected_kinds[index] &&
            event.outcome == query_outcome_t::success &&
            event.query_fingerprint != 0,
            "named query telemetry payload diverged");
    }
}

std::uint64_t p95(std::vector<std::uint64_t> values) {
    require(!values.empty(), "p95 requires telemetry values");
    std::sort(values.begin(), values.end());
    const auto rank = (values.size() * 95U + 99U) / 100U;
    return values[rank - 1U];
}

void verify_telemetry_cancellation_and_deadlines(fixture_t& fixture) {
    const auto before_success = fixture.telemetry->size();
    instruction_search_query_t opcode;
    opcode.filter.opcode_id = 0xE8;
    auto success = require_value(fixture.query->query(search_query_t{opcode}),
        "telemetry success query failed");
    require(success.total == 2 && fixture.telemetry->size() == before_success + 1,
        "success telemetry emission count diverged");
    const auto& success_event = (*fixture.telemetry)[before_success];
    require(success_event.kind == search_query_kind_t::instruction &&
        success_event.outcome == query_outcome_t::success &&
        success_event.query_fingerprint != 0 && success_event.matches == 2 &&
        success_event.returned == 2 && success_event.candidates_examined == 2 &&
        success_event.cancellation_checks == 2,
        "success telemetry payload diverged");

    cancellation_source_t cancelled;
    cancelled.request_cancel();
    const auto before_cancel = fixture.telemetry->size();
    require_error(fixture.query->query(
        search_query_t{literal_search_query_t{"Needle", true}}, {}, cancelled.token()),
        workspace_error_code_t::cancelled, "cancelled query succeeded");
    require(fixture.telemetry->size() == before_cancel + 1 &&
        (*fixture.telemetry)[before_cancel].outcome == query_outcome_t::cancelled,
        "cancellation telemetry diverged");

    cancellation_source_t expired(
        std::chrono::steady_clock::now() - std::chrono::milliseconds(1));
    const auto before_deadline = fixture.telemetry->size();
    require_error(fixture.query->query(
        search_query_t{literal_search_query_t{"Needle", true}}, {}, expired.token()),
        workspace_error_code_t::deadline_exceeded, "expired query deadline succeeded");
    require(fixture.telemetry->size() == before_deadline + 1 &&
        (*fixture.telemetry)[before_deadline].outcome == query_outcome_t::deadline,
        "deadline telemetry diverged");

    std::vector<std::uint64_t> latencies;
    const auto percentile_begin = fixture.telemetry->size();
    for (std::uint32_t index = 0; index < 20; ++index) {
        auto result = require_value(fixture.query->query(
            search_query_t{literal_search_query_t{"Needle", true}}),
            "p95 telemetry query failed");
        require(result.total == 5, "p95 telemetry query count diverged");
    }
    require(fixture.telemetry->size() == percentile_begin + 20,
        "p95 telemetry emission count diverged");
    for (std::size_t index = percentile_begin; index < fixture.telemetry->size(); ++index)
        latencies.push_back((*fixture.telemetry)[index].elapsed_ns);
    const auto percentile = p95(latencies);
    require(percentile >= *std::min_element(latencies.begin(), latencies.end()) &&
        percentile <= *std::max_element(latencies.begin(), latencies.end()),
        "p95 telemetry aggregation diverged");

    std::shared_ptr<const query_index_t> reentrant_index;
    bool entered = false;
    bool nested_ok = false;
    auto reentrant = require_value(query_index_t::build(fixture.search, fixture.provider,
        fixture.limits, [&](const query_telemetry_t&) {
            if (entered)
                return;
            entered = true;
            entity_search_query_t nested_query;
            nested_query.filter.kind = search_entity_kind_t::function;
            nested_ok = static_cast<bool>(reentrant_index->query(
                search_query_t{nested_query}));
        }), "reentrant telemetry index build failed");
    reentrant_index = reentrant;
    auto outer = require_value(reentrant->query(
        search_query_t{literal_search_query_t{"Needle", true}}),
        "reentrant telemetry outer query failed");
    require(outer.total == 5 && entered && nested_ok,
        "reentrant telemetry hook did not complete");

    auto throwing = require_value(query_index_t::build(fixture.search, fixture.provider,
        fixture.limits, [](const query_telemetry_t&) {
            throw std::runtime_error("telemetry sink failure");
        }), "throwing telemetry index build failed");
    auto throwing_result = require_value(throwing->query(
        search_query_t{literal_search_query_t{"Needle", true}}),
        "throwing telemetry sink escaped query boundary");
    require(throwing_result.total == 5, "throwing telemetry query count diverged");
}

void verify_bounds(fixture_t& fixture) {
    auto invalid_limits = fixture.limits;
    invalid_limits.max_page_size = 0;
    require_error(query_index_t::build(fixture.search, fixture.provider, invalid_limits),
        workspace_error_code_t::invalid_argument, "invalid query-index limits succeeded");

    require_error(query_index_t::build(std::shared_ptr<const search_index_t>{},
        fixture.provider, fixture.limits), workspace_error_code_t::invalid_argument,
        "null search index succeeded");
    require_error(query_index_t::build(search_generation_handle_t{}, fixture.provider,
        fixture.limits), workspace_error_code_t::stale_generation,
        "stale generation handle succeeded");

    require_error(fixture.query->query(
        search_query_t{literal_search_query_t{"", true}}),
        workspace_error_code_t::invalid_argument, "empty literal query succeeded");
    require_error(fixture.query->query(search_query_t{literal_search_query_t{
        std::string(fixture.limits.max_query_bytes + 1ULL, 'x'), true}}),
        workspace_error_code_t::invalid_argument, "oversized literal query succeeded");

    query_page_request_t zero_page;
    zero_page.limit = 0;
    require_error(fixture.query->query(
        search_query_t{literal_search_query_t{"Needle", true}}, zero_page),
        workspace_error_code_t::invalid_argument, "zero query page succeeded");
    query_page_request_t large_page;
    large_page.limit = fixture.limits.max_page_size + 1;
    require_error(fixture.query->query(
        search_query_t{literal_search_query_t{"Needle", true}}, large_page),
        workspace_error_code_t::invalid_argument, "oversized query page succeeded");

    regex_compile_options_t incompatible;
    incompatible.literal = true;
    incompatible.multiline = true;
    require_error(regex_query_t::compile("Needle", incompatible, fixture.limits.regex),
        workspace_error_code_t::invalid_argument,
        "incompatible literal-regex options succeeded");

    auto subject_limits = fixture.limits.regex;
    subject_limits.max_subject_bytes = 8;
    auto bounded_subject = require_value(regex_query_t::compile("Needle", {},
        subject_limits), "bounded-subject regex compilation failed");
    require_error(bounded_subject->match("prefix Needle suffix"),
        workspace_error_code_t::limit_exceeded,
        "oversized regex subject succeeded");

    search_entity_filter_t all;
    const auto past = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
    require_error(fixture.search->find_entity(all, 0, 1, {}, past),
        workspace_error_code_t::deadline_exceeded,
        "expired packed-index deadline succeeded");
    search_instruction_filter_t absent_instruction;
    absent_instruction.opcode_id = 0xFFFFFFFFU;
    require_error(fixture.search->find_instruction(absent_instruction, 0, 1, {}, past),
        workspace_error_code_t::deadline_exceeded,
        "expired zero-candidate packed-index query succeeded");
    auto exhausted = require_value(fixture.search->find_entity(all,
        fixture.search->record_count(), 1, {}),
        "packed-index terminal offset query failed");
    require(exhausted.total == fixture.search->record_count() &&
        exhausted.hits.empty() && !exhausted.truncated,
        "packed-index terminal offset bounds diverged");

    auto candidate_limits = fixture.limits;
    candidate_limits.max_regex_candidates = fixture.search->text_record_count() - 1;
    auto candidate_index = require_value(query_index_t::build(fixture.search,
        fixture.provider, candidate_limits), "regex-candidate limit index build failed");
    regex_search_query_t bounded_candidates;
    bounded_candidates.pattern = "Needle";
    require_error(candidate_index->query(search_query_t{bounded_candidates}),
        workspace_error_code_t::limit_exceeded,
        "regex candidate limit was not enforced");

    auto incomplete_snapshot = std::make_shared<analysis_snapshot_t>(*fixture.snapshot);
    auto incomplete_image = std::make_shared<workspace_image_t>(
        *incomplete_snapshot->normalized_image);
    incomplete_image->provider_content_hash = {};
    incomplete_snapshot->normalized_image = std::move(incomplete_image);
    auto incomplete_search = require_value(search_index_t::build(incomplete_snapshot,
        {}, {}, {}, std::make_shared<analysis_metrics_t>(kGeneration), search_limits(), {}),
        "incomplete-identity search build failed");
    require_error(query_index_t::build(incomplete_search, fixture.provider, fixture.limits),
        workspace_error_code_t::substitution_rejected,
        "incomplete provider identity accepted byte search");

    auto altered_bytes = fixture_bytes();
    altered_bytes[0] ^= 0x01U;
    auto altered_source = require_value(sealed_memory_provider_t::create(
        std::move(altered_bytes)), "altered fixture provider creation failed");
    auto altered_provider = require_value(provider_snapshot_t::capture(
        altered_source, kGeneration), "altered fixture provider capture failed");
    require_error(query_index_t::build(fixture.search, altered_provider, fixture.limits),
        workspace_error_code_t::substitution_rejected,
        "content-substituted byte provider was accepted");

    auto short_source = require_value(sealed_memory_provider_t::create(
        std::vector<std::uint8_t>(63, 0x90U)),
        "short fixture provider creation failed");
    auto short_provider = require_value(provider_snapshot_t::capture(
        short_source, kGeneration), "short fixture provider capture failed");
    require_error(query_index_t::build(fixture.search, short_provider, fixture.limits),
        workspace_error_code_t::substitution_rejected,
        "size-substituted byte provider was accepted");

    auto stale_provider = require_value(provider_snapshot_t::capture(
        fixture.source, kGeneration + 1), "stale fixture provider capture failed");
    require_error(query_index_t::build(fixture.search, stale_provider, fixture.limits),
        workspace_error_code_t::stale_generation,
        "cross-generation byte provider was accepted");
}

}

bool run_search_query_harness(std::string& failure) {
    try {
        auto fixture = make_fixture();
        verify_serialized_round_trip(fixture);
        verify_index_accounting(fixture);
        verify_literal_queries(fixture);
        verify_regex_queries(fixture);
        verify_byte_queries(fixture);
        verify_instruction_entity_address_queries(fixture);
        verify_cursor_validation(fixture);
        verify_production_variant_apis(fixture);
        verify_telemetry_cancellation_and_deadlines(fixture);
        verify_bounds(fixture);
        failure.clear();
        return true;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        failure = error.what();
        return false;
    } catch (...) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(
			"search/query harness failed with a non-standard exception");
        failure = "search/query harness failed with a non-standard exception";
        return false;
    }
}

}
