#include "../../src/core/analysis/workspace/c03_analysis_contracts.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace {

using namespace aida::analysis::c03;

static_assert(sizeof(workspace_id_t::bytes_t) == 16, "workspace identity width changed");
static_assert(sizeof(packed_analysis_id_t) == 8, "packed analysis id width changed");
static_assert(sizeof(decompiler_cache_namespace_t) == 16, "decompiler cache namespace width changed");
static_assert(c03_contract_schema_version == 3, "contract schema version changed");
static_assert(static_cast<std::uint16_t>(contract_schema_t::workspace_identity) == 1,
              "workspace schema value changed");
static_assert(static_cast<std::uint16_t>(contract_schema_t::immutable_publication) == 5,
              "publication schema value changed");
static_assert(static_cast<std::uint16_t>(contract_schema_t::static_provider_provenance) == 9,
              "static provider provenance schema value changed");
static_assert(static_cast<std::uint16_t>(contract_schema_t::live_target_identity) == 10,
              "live target identity schema value changed");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::generation_mismatch) == 4,
              "generation mismatch error value changed");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::resource_budget_exceeded) == 10,
              "resource budget error value changed");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::target_identity_provenance_mismatch) == 17,
              "target provenance mismatch error value changed");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::invalid_binary_format) == 18,
              "invalid binary format error value changed");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::invalid_metadata_revision) == 22,
              "invalid metadata revision error value changed");
static_assert(static_cast<std::uint16_t>(contract_error_code_t::invalid_decompiler_cache_namespace) == 23,
              "invalid decompiler cache namespace error value changed");

void require(bool condition, std::string_view message)
{
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		condition, message, __FILE__, __LINE__);
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename value_t>
value_t require_value(contract_result_t<value_t> result, std::string_view message)
{
	const bool accepted = static_cast<bool>(result);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		accepted, message, __FILE__, __LINE__);
    if (!accepted)
        throw std::runtime_error(std::string(message) + ":" + std::string(result.error().stable_code));
    return std::move(result).take_value();
}

workspace_contract_identity_t make_workspace(std::uint8_t seed)
{
    workspace_id_t::bytes_t bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    if (bytes[0] == 0)
        bytes[0] = 1;
    return require_value(workspace_contract_identity_t::make(require_value(
        workspace_id_t::from_bytes(bytes), "workspace id creation failed")),
        "workspace identity creation failed");
}

template <std::size_t size>
std::array<std::uint8_t, size> make_identity_bytes(std::uint8_t seed)
{
    std::array<std::uint8_t, size> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<std::uint8_t>(seed + index);
    if (bytes[0] == 0)
        bytes[0] = 1;
    return bytes;
}

static_provider_provenance_t make_static_provider_provenance(std::uint8_t seed)
{
    static_provider_provenance_t provenance;
    provenance.provider_kind = static_provider_kind_t::mapped_file;
    provenance.provider_identity = make_identity_bytes<32>(seed);
    provenance.provider_snapshot_generation = 0x1000ULL + seed;
    provenance.canonical_path_fingerprint = make_identity_bytes<32>(static_cast<std::uint8_t>(seed + 1));
    provenance.source_file_identity = make_identity_bytes<16>(static_cast<std::uint8_t>(seed + 2));
    provenance.source_length = 0x200000ULL + seed;
    provenance.last_write_identity = 0x300000ULL + seed;
    provenance.content_fingerprint = make_identity_bytes<32>(static_cast<std::uint8_t>(seed + 3));
    provenance.member_chain_fingerprint = make_identity_bytes<32>(static_cast<std::uint8_t>(seed + 4));
    provenance.image_mapping_fingerprint = make_identity_bytes<32>(static_cast<std::uint8_t>(seed + 5));
    return provenance;
}

live_target_identity_t make_live_target_identity(std::uint8_t seed)
{
    live_target_identity_t identity;
    identity.process_id = 1000U + seed;
    identity.process_creation_identity = 0x400000ULL + seed;
    identity.module_base = 0x180000000ULL + (static_cast<std::uint64_t>(seed) << 20U);
    identity.module_size = 0x200000ULL;
    identity.module_fingerprint = make_identity_bytes<32>(static_cast<std::uint8_t>(seed + 6));
    identity.capture_base = identity.module_base + 0x1000ULL;
    identity.capture_size = 0x4000ULL;
    identity.attach_generation = 0x500000ULL + seed;
    return identity;
}

target_contract_identity_t make_static_target(const workspace_contract_identity_t& workspace,
                                               std::uint64_t target_value, std::uint8_t seed,
                                               analysis_target_kind_t kind = analysis_target_kind_t::static_image)
{
    return require_value(target_contract_identity_t::make(
        workspace, require_value(target_id_t::from_value(target_value), "target id creation failed"), kind,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(seed)}, std::nullopt),
        "static target identity creation failed");
}

target_contract_identity_t make_static_target(const workspace_contract_identity_t& workspace,
                                               std::uint64_t target_value,
                                               static_provider_provenance_t provenance,
                                               analysis_target_kind_t kind = analysis_target_kind_t::static_image)
{
    return require_value(target_contract_identity_t::make(
        workspace, require_value(target_id_t::from_value(target_value), "target id creation failed"), kind,
        std::optional<static_provider_provenance_t>{provenance}, std::nullopt),
        "static target identity creation failed");
}

target_contract_identity_t make_live_target(const workspace_contract_identity_t& workspace,
                                             std::uint64_t target_value,
                                             live_target_identity_t live_identity)
{
    return require_value(target_contract_identity_t::make(
        workspace, require_value(target_id_t::from_value(target_value), "target id creation failed"),
        analysis_target_kind_t::live_module, std::nullopt,
        std::optional<live_target_identity_t>{live_identity}),
        "live target identity creation failed");
}

void require_invalid_static_provider(static_provider_provenance_t provenance,
                                     std::string_view expected_phase)
{
    const auto result = validate_static_provider_provenance(provenance);
    require(!result && result.error().code == contract_error_code_t::invalid_static_provider_provenance &&
            result.error().phase == expected_phase,
            "static provider provenance malformed field was accepted");
}

void require_invalid_live_identity(live_target_identity_t identity, std::string_view expected_phase)
{
    const auto result = validate_live_target_identity(identity);
    require(!result && result.error().code == contract_error_code_t::invalid_live_target_identity &&
            result.error().phase == expected_phase,
            "live target identity malformed field was accepted");
}

generation_contract_identity_t make_generation(const workspace_contract_identity_t& workspace,
                                                std::uint64_t target_value,
                                                std::uint64_t generation_value)
{
    const auto target = make_static_target(workspace, target_value, 17);
    return require_value(generation_contract_identity_t::make(
        target, require_value(generation_id_t::from_value(generation_value), "generation id creation failed")),
        "generation identity creation failed");
}

void verify_identity_equality()
{
    const auto first = make_workspace(11);
    const auto same = make_workspace(11);
    const auto different = make_workspace(12);
    require(first == same, "equal workspace identities diverged");
    require(first != different, "different workspace identities compared equal");

    const auto first_generation = make_generation(first, 0x1001, 7);
    const auto same_generation = make_generation(same, 0x1001, 7);
    const auto changed_target = make_generation(first, 0x1002, 7);
    const auto changed_generation = make_generation(first, 0x1001, 8);
    require(first_generation == same_generation, "equal generation identities diverged");
    require(first_generation != changed_target, "target identity was omitted from generation equality");
    require(first_generation != changed_generation,
            "generation number was omitted from generation equality");
}

void verify_target_provenance_contract()
{
    const auto workspace = make_workspace(21);
    const auto static_target = make_static_target(workspace, 0x1101, 31);
    require(static_target.valid() && static_target.static_provider_provenance() &&
            !static_target.live_identity() &&
            static_target.kind() == analysis_target_kind_t::static_image,
            "static target identity did not retain provider provenance");
    require(static_cast<bool>(validate_static_provider_provenance(
                *static_target.static_provider_provenance())),
            "static target provider provenance was rejected");

    const auto collection_target = make_static_target(
        workspace, 0x1102, 32, analysis_target_kind_t::collection_member);
    require(collection_target.valid() && collection_target.static_provider_provenance() &&
            collection_target.kind() == analysis_target_kind_t::collection_member,
            "collection target identity did not retain static provider provenance");

    const auto same_static_target = make_static_target(workspace, 0x1101, 31);
    require(static_target == same_static_target,
            "equal static target provider provenance identities diverged");
    auto changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.provider_kind = static_provider_kind_t::subrange;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static provider kind was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.provider_identity[0] ^= 0x7fU;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static provider identity was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.provider_snapshot_generation += 1;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static provider snapshot generation was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.canonical_path_fingerprint[0] ^= 0x7fU;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static canonical path provenance was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.source_file_identity[0] ^= 0x7fU;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static source file identity was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.source_length += 1;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static source length was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.last_write_identity += 1;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static last-write identity was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.content_fingerprint[0] ^= 0x7fU;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static content fingerprint was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.member_chain_fingerprint[0] ^= 0x7fU;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static member-chain provenance was omitted from target equality");
    changed_static_provenance = *static_target.static_provider_provenance();
    changed_static_provenance.image_mapping_fingerprint[0] ^= 0x7fU;
    require(static_target != make_static_target(workspace, 0x1101, changed_static_provenance),
            "static image mapping provenance was omitted from target equality");

    const auto live_identity = make_live_target_identity(41);
    const auto live_target = make_live_target(workspace, 0x1201, live_identity);
    require(live_target.valid() && live_target.live_identity() &&
            !live_target.static_provider_provenance() &&
            live_target.kind() == analysis_target_kind_t::live_module,
            "live target identity did not retain live provenance");
    require(static_cast<bool>(validate_live_target_identity(*live_target.live_identity())),
            "live target identity was rejected");

    auto changed_live_identity = live_identity;
    changed_live_identity.process_id += 1;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "live PID was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.process_creation_identity += 1;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "process creation identity was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.module_base += 0x1000ULL;
    changed_live_identity.capture_base += 0x1000ULL;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "module base was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.module_size += 0x1000ULL;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "module size was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.module_fingerprint[0] ^= 0x7fU;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "module fingerprint was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.capture_base += 0x1000ULL;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "capture base was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.capture_size += 0x1000ULL;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "capture size was omitted from target equality");
    changed_live_identity = live_identity;
    changed_live_identity.attach_generation += 1;
    require(live_target != make_live_target(workspace, 0x1201, changed_live_identity),
            "attach generation was omitted from target equality");
}

void verify_target_provenance_rejection()
{
    const auto workspace = make_workspace(22);
    const auto target = require_value(target_id_t::from_value(0x1301), "target id creation failed");

    auto static_provenance = make_static_provider_provenance(51);
    static_provenance.provider_kind = static_provider_kind_t::unknown;
    require_invalid_static_provider(static_provenance, "static_provider_kind");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.provider_kind = static_cast<static_provider_kind_t>(0xffU);
    require_invalid_static_provider(static_provenance, "static_provider_kind");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.provider_identity = {};
    require_invalid_static_provider(static_provenance, "static_provider_identity");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.provider_snapshot_generation = 0;
    require_invalid_static_provider(static_provenance, "static_provider_snapshot_generation");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.canonical_path_fingerprint = {};
    require_invalid_static_provider(static_provenance, "static_canonical_path");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.source_file_identity = {};
    require_invalid_static_provider(static_provenance, "static_source_file_identity");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.source_length = 0;
    require_invalid_static_provider(static_provenance, "static_source_length");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.last_write_identity = 0;
    require_invalid_static_provider(static_provenance, "static_last_write_identity");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.content_fingerprint = {};
    require_invalid_static_provider(static_provenance, "static_content_fingerprint");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.member_chain_fingerprint = {};
    require_invalid_static_provider(static_provenance, "static_member_chain");
    static_provenance = make_static_provider_provenance(51);
    static_provenance.image_mapping_fingerprint = {};
    require_invalid_static_provider(static_provenance, "static_image_mapping");
    const auto invalid_static_target = target_contract_identity_t::make(
        workspace, target, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{static_provenance}, std::nullopt);
    require(!invalid_static_target &&
            invalid_static_target.error().code == contract_error_code_t::invalid_static_provider_provenance &&
            invalid_static_target.error().phase == "static_image_mapping",
            "target factory accepted malformed static provider provenance");

    auto live_identity = make_live_target_identity(61);
    live_identity.process_id = 0;
    require_invalid_live_identity(live_identity, "live_process_id");
    live_identity = make_live_target_identity(61);
    live_identity.process_creation_identity = 0;
    require_invalid_live_identity(live_identity, "live_process_creation_identity");
    live_identity = make_live_target_identity(61);
    live_identity.module_base = 0;
    require_invalid_live_identity(live_identity, "live_module_range");
    live_identity = make_live_target_identity(61);
    live_identity.module_size = 0;
    require_invalid_live_identity(live_identity, "live_module_range");
    live_identity = make_live_target_identity(61);
    live_identity.module_fingerprint = {};
    require_invalid_live_identity(live_identity, "live_module_fingerprint");
    live_identity = make_live_target_identity(61);
    live_identity.capture_base = live_identity.module_base - 0x1000ULL;
    require_invalid_live_identity(live_identity, "live_capture_bounds");
    live_identity = make_live_target_identity(61);
    live_identity.capture_base = live_identity.module_base + live_identity.module_size - 0x1000ULL;
    live_identity.capture_size = 0x2000ULL;
    require_invalid_live_identity(live_identity, "live_capture_bounds");
    live_identity = make_live_target_identity(61);
    live_identity.capture_base = (std::numeric_limits<std::uint64_t>::max)() - 1ULL;
    live_identity.capture_size = 2;
    require_invalid_live_identity(live_identity, "live_capture_range");
    live_identity = make_live_target_identity(61);
    live_identity.attach_generation = 0;
    require_invalid_live_identity(live_identity, "live_attach_generation");
    const auto invalid_live_target = target_contract_identity_t::make(
        workspace, target, analysis_target_kind_t::live_module, std::nullopt,
        std::optional<live_target_identity_t>{live_identity});
    require(!invalid_live_target &&
            invalid_live_target.error().code == contract_error_code_t::invalid_live_target_identity &&
            invalid_live_target.error().phase == "live_attach_generation",
            "target factory accepted malformed live target identity");

    const auto static_payload = std::optional<static_provider_provenance_t>{
        make_static_provider_provenance(71)};
    const auto live_payload = std::optional<live_target_identity_t>{make_live_target_identity(71)};
    const auto static_without_static_payload = target_contract_identity_t::make(
        workspace, target, analysis_target_kind_t::static_image, std::nullopt, std::nullopt);
    require(!static_without_static_payload &&
            static_without_static_payload.error().code ==
                contract_error_code_t::target_identity_provenance_mismatch &&
            static_without_static_payload.error().expected ==
                static_cast<std::uint64_t>(analysis_target_kind_t::static_image) &&
            static_without_static_payload.error().actual == 0,
            "static target without static provenance was accepted");
    const auto live_with_static_payload = target_contract_identity_t::make(
        workspace, target, analysis_target_kind_t::live_module, static_payload, std::nullopt);
    require(!live_with_static_payload &&
            live_with_static_payload.error().code ==
                contract_error_code_t::target_identity_provenance_mismatch &&
            live_with_static_payload.error().expected ==
                static_cast<std::uint64_t>(analysis_target_kind_t::live_module) &&
            live_with_static_payload.error().actual == 1,
            "live target with static provenance was accepted");
    const auto static_with_both_payloads = target_contract_identity_t::make(
        workspace, target, analysis_target_kind_t::collection_member, static_payload, live_payload);
    require(!static_with_both_payloads &&
            static_with_both_payloads.error().code ==
                contract_error_code_t::target_identity_provenance_mismatch &&
            static_with_both_payloads.error().expected ==
                static_cast<std::uint64_t>(analysis_target_kind_t::collection_member) &&
            static_with_both_payloads.error().actual == 3,
            "static target with mixed provenance was accepted");
    const auto live_without_live_payload = target_contract_identity_t::make(
        workspace, target, analysis_target_kind_t::live_module, std::nullopt, std::nullopt);
    require(!live_without_live_payload &&
            live_without_live_payload.error().code ==
                contract_error_code_t::target_identity_provenance_mismatch &&
            live_without_live_payload.error().expected ==
                static_cast<std::uint64_t>(analysis_target_kind_t::live_module) &&
            live_without_live_payload.error().actual == 0,
            "live target without live provenance was accepted");
}

void verify_packed_id_contract()
{
    const auto id = require_value(packed_analysis_id_t::make(0x4a2b, 0x1030, 0xdecafbad),
                                  "packed id creation failed");
    require(id.value() == 0x4a2b1030decafbadULL, "packed id layout changed");
    require(id.parts() == packed_analysis_id_parts_t{0x4a2b, 0x1030, 0xdecafbad},
            "packed id decomposition changed");

    const auto domain_overflow = packed_analysis_id_t::make(0x10000, 0, 0);
    require(!domain_overflow && domain_overflow.error().code == contract_error_code_t::packed_id_overflow,
            "domain overflow did not report the deterministic packed-id error");
    const auto shard_overflow = packed_analysis_id_t::make(1, 0x10000, 0);
    require(!shard_overflow && shard_overflow.error().code == contract_error_code_t::packed_id_overflow,
            "shard overflow did not report the deterministic packed-id error");
    const auto ordinal_overflow = packed_analysis_id_t::make(1, 0, 0x100000000ULL);
    require(!ordinal_overflow && ordinal_overflow.error().code == contract_error_code_t::packed_id_overflow,
            "ordinal overflow did not report the deterministic packed-id error");
    const auto empty = packed_analysis_id_t::make(0, 0, 0);
    require(!empty && empty.error().code == contract_error_code_t::invalid_packed_id,
            "empty packed id was accepted");
    const auto missing_domain = packed_analysis_id_t::make(0, 1, 1);
    require(!missing_domain && missing_domain.error().code == contract_error_code_t::invalid_packed_id,
            "packed id without a domain was accepted");
}

void verify_publication_contract()
{
    const auto workspace = make_workspace(31);
    const auto generation_one = make_generation(workspace, 0x2001, 3);
    const auto generation_two = make_generation(workspace, 0x2001, 4);
    const auto snapshot = require_value(immutable_snapshot_contract_t::make(
        generation_one, 15, 9, 2), "immutable snapshot creation failed");

    const auto publication = require_value(immutable_publication_contract_t::make(
        generation_one, snapshot, publication_stage_t::baseline_ready, 10),
        "immutable publication creation failed");
    require(publication.snapshot() == snapshot &&
            publication.stage() == publication_stage_t::baseline_ready,
            "immutable publication did not retain the snapshot identity");

    const auto mismatch = immutable_publication_contract_t::make(
        generation_two, snapshot, publication_stage_t::baseline_ready, 11);
    require(!mismatch && mismatch.error().code == contract_error_code_t::generation_mismatch &&
            mismatch.error().expected == 4 && mismatch.error().actual == 3,
            "mixed-generation publication was not rejected deterministically");

    require(publication_stage_transition_allowed(publication_stage_t::none,
                                                 publication_stage_t::metadata_ready),
            "metadata publication transition was rejected");
    require(publication_stage_transition_allowed(publication_stage_t::metadata_ready,
                                                 publication_stage_t::baseline_ready),
            "baseline publication transition was rejected");
    const auto regression = validate_publication_stage_transition(
        publication_stage_t::baseline_ready, publication_stage_t::metadata_ready);
    require(!regression &&
            regression.error().code == contract_error_code_t::publication_transition_rejected,
            "publication stage regression was accepted");

    require(publication_stage_name(publication_stage_t::none) == "none",
            "publication stage name for none changed");
    require(publication_stage_name(publication_stage_t::metadata_ready) == "metadata_ready",
            "publication stage name for metadata_ready changed");
    require(publication_stage_name(publication_stage_t::baseline_ready) == "baseline_ready",
            "publication stage name for baseline_ready changed");
    require(publication_stage_name(publication_stage_t::retired) == "retired",
            "publication stage name for retired changed");

    require(publication_stage_transition_allowed(publication_stage_t::none,
                                                  publication_stage_t::baseline_ready),
            "none to baseline_ready transition was rejected");
    require(publication_stage_transition_allowed(publication_stage_t::metadata_ready,
                                                  publication_stage_t::retired),
            "metadata_ready to retired transition was rejected");
    require(publication_stage_transition_allowed(publication_stage_t::baseline_ready,
                                                  publication_stage_t::retired),
            "baseline_ready to retired transition was rejected");
    require(!publication_stage_transition_allowed(publication_stage_t::retired,
                                                   publication_stage_t::metadata_ready),
            "retired to metadata_ready transition was accepted");
    require(!publication_stage_transition_allowed(publication_stage_t::retired,
                                                   publication_stage_t::baseline_ready),
            "retired to baseline_ready transition was accepted");
}

void verify_resource_budget_contract()
{
    analysis_resource_budget_t budget;
    require(static_cast<bool>(validate_analysis_resource_budget(budget)),
            "default resource budget is invalid");

    analysis_resource_usage_t current;
    current.incremental_private_bytes = max_incremental_private_bytes - 1;
    const auto within_limit = reserve_analysis_resources(
        budget, current, analysis_resource_usage_t{1, 0, 0, 0, 0, 0, 0});
    require(within_limit && within_limit.value().incremental_private_bytes == max_incremental_private_bytes,
            "resource budget did not permit an exact cap reservation");

    const auto beyond_limit = reserve_analysis_resources(
        budget, current, analysis_resource_usage_t{2, 0, 0, 0, 0, 0, 0});
    require(!beyond_limit && beyond_limit.error().code == contract_error_code_t::resource_budget_exceeded,
            "resource budget overrun did not fail deterministically");

    current.incremental_private_bytes = (std::numeric_limits<std::uint64_t>::max)();
    const auto arithmetic_overflow = reserve_analysis_resources(
        budget, current, analysis_resource_usage_t{1, 0, 0, 0, 0, 0, 0});
    require(!arithmetic_overflow &&
            arithmetic_overflow.error().code == contract_error_code_t::arithmetic_overflow,
            "resource arithmetic overflow did not fail deterministically");

    budget.max_global_mapped_window_bytes = budget.max_workspace_mapped_window_bytes - 1;
    const auto invalid_budget = validate_analysis_resource_budget(budget);
    require(!invalid_budget && invalid_budget.error().code == contract_error_code_t::invalid_resource_budget,
            "incoherent resource budget was accepted");

    analysis_resource_budget_t clean_budget;

    {
        analysis_resource_usage_t cur;
        cur.workspace_mapped_window_bytes = max_workspace_mapped_window_bytes - 1;
        const auto ok = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 1, 0, 0, 0, 0, 0});
        require(ok && ok.value().workspace_mapped_window_bytes == max_workspace_mapped_window_bytes,
                "workspace mapped window budget did not permit an exact cap reservation");
        const auto over = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 2, 0, 0, 0, 0, 0});
        require(!over && over.error().code == contract_error_code_t::resource_budget_exceeded,
                "workspace mapped window budget overrun did not fail deterministically");
    }

    {
        analysis_resource_usage_t cur;
        cur.global_mapped_window_bytes = max_global_mapped_window_bytes - 1;
        const auto ok = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 1, 0, 0, 0, 0});
        require(ok && ok.value().global_mapped_window_bytes == max_global_mapped_window_bytes,
                "global mapped window budget did not permit an exact cap reservation");
        const auto over = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 2, 0, 0, 0, 0});
        require(!over && over.error().code == contract_error_code_t::resource_budget_exceeded,
                "global mapped window budget overrun did not fail deterministically");
    }

    {
        analysis_resource_usage_t cur;
        cur.workspace_spill_bytes = max_workspace_spill_bytes - 1;
        const auto ok = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 1, 0, 0, 0});
        require(ok && ok.value().workspace_spill_bytes == max_workspace_spill_bytes,
                "workspace spill budget did not permit an exact cap reservation");
        const auto over = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 2, 0, 0, 0});
        require(!over && over.error().code == contract_error_code_t::resource_budget_exceeded,
                "workspace spill budget overrun did not fail deterministically");
    }

    {
        analysis_resource_usage_t cur;
        cur.global_spill_bytes = max_global_spill_bytes - 1;
        const auto ok = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 0, 1, 0, 0});
        require(ok && ok.value().global_spill_bytes == max_global_spill_bytes,
                "global spill budget did not permit an exact cap reservation");
        const auto over = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 0, 2, 0, 0});
        require(!over && over.error().code == contract_error_code_t::resource_budget_exceeded,
                "global spill budget overrun did not fail deterministically");
    }

    {
        analysis_resource_usage_t cur;
        cur.workspace_cache_bytes = max_workspace_cache_bytes - 1;
        const auto ok = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 0, 0, 1, 0});
        require(ok && ok.value().workspace_cache_bytes == max_workspace_cache_bytes,
                "workspace cache budget did not permit an exact cap reservation");
        const auto over = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 0, 0, 2, 0});
        require(!over && over.error().code == contract_error_code_t::resource_budget_exceeded,
                "workspace cache budget overrun did not fail deterministically");
    }

    {
        analysis_resource_usage_t cur;
        cur.global_cache_bytes = max_global_cache_bytes - 1;
        const auto ok = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 0, 0, 0, 1});
        require(ok && ok.value().global_cache_bytes == max_global_cache_bytes,
                "global cache budget did not permit an exact cap reservation");
        const auto over = reserve_analysis_resources(
            clean_budget, cur, analysis_resource_usage_t{0, 0, 0, 0, 0, 0, 2});
        require(!over && over.error().code == contract_error_code_t::resource_budget_exceeded,
                "global cache budget overrun did not fail deterministically");
    }

    {
        analysis_resource_budget_t bad = clean_budget;
        bad.cancellation_checkpoint_milliseconds = 0;
        const auto result = validate_analysis_resource_budget(bad);
        require(!result && result.error().code == contract_error_code_t::invalid_resource_budget,
                "zero cancellation_checkpoint_milliseconds was accepted");
    }

    {
        analysis_resource_budget_t bad = clean_budget;
        bad.cancellation_checkpoint_milliseconds = max_cancellation_checkpoint_milliseconds + 1;
        const auto result = validate_analysis_resource_budget(bad);
        require(!result && result.error().code == contract_error_code_t::invalid_resource_budget,
                "cancellation_checkpoint_milliseconds exceeding max constant was accepted");
    }

    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_incremental_private_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_incremental_private_bytes was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_workspace_mapped_window_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_workspace_mapped_window_bytes was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_global_mapped_window_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_global_mapped_window_bytes was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_workspace_spill_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_workspace_spill_bytes was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_global_spill_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_global_spill_bytes was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_workspace_cache_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_workspace_cache_bytes was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_global_cache_bytes = 0;
        require(!validate_analysis_resource_budget(bad),
                "zero max_global_cache_bytes was accepted");
    }

    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_incremental_private_bytes = max_incremental_private_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_incremental_private_bytes exceeding max constant was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_workspace_mapped_window_bytes = max_workspace_mapped_window_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_workspace_mapped_window_bytes exceeding max constant was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_global_mapped_window_bytes = max_global_mapped_window_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_global_mapped_window_bytes exceeding max constant was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_workspace_spill_bytes = max_workspace_spill_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_workspace_spill_bytes exceeding max constant was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_global_spill_bytes = max_global_spill_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_global_spill_bytes exceeding max constant was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_workspace_cache_bytes = max_workspace_cache_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_workspace_cache_bytes exceeding max constant was accepted");
    }
    {
        analysis_resource_budget_t bad = clean_budget;
        bad.max_global_cache_bytes = max_global_cache_bytes + 1;
        require(!validate_analysis_resource_budget(bad),
                "max_global_cache_bytes exceeding max constant was accepted");
    }
}

void verify_cancellation_domains()
{
    const auto first_workspace = make_workspace(51);
    const auto second_workspace = make_workspace(61);
    const auto first_generation = make_generation(first_workspace, 0x3001, 1);
    const auto second_generation = make_generation(first_workspace, 0x3002, 1);
    const auto foreign_generation = make_generation(second_workspace, 0x3001, 1);

    const auto workspace_domain = require_value(
        cancellation_domain_t::for_workspace(first_workspace, 1), "workspace domain creation failed");
    require(static_cast<bool>(validate_cancellation_domain(workspace_domain, first_generation)),
            "workspace domain did not cover the workspace generation");
    require(!validate_cancellation_domain(workspace_domain, foreign_generation),
            "workspace domain crossed workspace identity boundaries");

    const auto target_domain = require_value(cancellation_domain_t::for_target(
        first_generation.target(), 2), "target domain creation failed");
    require(static_cast<bool>(validate_cancellation_domain(target_domain, first_generation)),
            "target domain did not cover its target generation");
    const auto target_mismatch = validate_cancellation_domain(target_domain, second_generation);
    require(!target_mismatch &&
            target_mismatch.error().code == contract_error_code_t::cancellation_domain_mismatch,
            "target domain crossed target identity boundaries");

    const auto generation_domain = require_value(cancellation_domain_t::for_generation(
        first_generation, 3), "generation domain creation failed");
    require(static_cast<bool>(validate_cancellation_domain(generation_domain, first_generation)),
            "generation domain did not cover its exact generation");
    require(!validate_cancellation_domain(generation_domain, second_generation),
            "generation domain crossed target or generation boundaries");
}

void verify_stable_schema_and_error_values()
{
    constexpr std::array<contract_schema_t, 10> schemas{
        contract_schema_t::workspace_identity,
        contract_schema_t::target_identity,
        contract_schema_t::generation_identity,
        contract_schema_t::immutable_snapshot,
        contract_schema_t::immutable_publication,
        contract_schema_t::packed_analysis_id,
        contract_schema_t::resource_budget,
        contract_schema_t::cancellation_domain,
        contract_schema_t::static_provider_provenance,
        contract_schema_t::live_target_identity};
    for (const auto schema : schemas) {
        require(contract_schema_version_for(schema) == c03_contract_schema_version &&
                contract_schema_name(schema) != "unknown",
                "stable schema mapping changed");
        require(static_cast<bool>(validate_contract_schema_version(
                    schema, c03_contract_schema_version)),
                "stable schema version was rejected");
    }

    const auto schema_mismatch = validate_contract_schema_version(
        contract_schema_t::immutable_publication, c03_contract_schema_version + 1);
    require(!schema_mismatch &&
            schema_mismatch.error().code == contract_error_code_t::serialization_schema_mismatch,
            "schema version mismatch was not rejected deterministically");

    const auto generation_error = make_contract_error(
        contract_error_code_t::generation_mismatch, "fixture", 4, 3);
    const auto repeat_generation_error = make_contract_error(
        contract_error_code_t::generation_mismatch, "fixture", 4, 3);
    require(generation_error == repeat_generation_error &&
            generation_error.stable_code == "C03_GENERATION_MISMATCH",
            "generation mismatch error is not deterministic");
    require(contract_error_code_name(contract_error_code_t::packed_id_overflow) ==
                "C03_PACKED_ID_OVERFLOW",
            "packed id overflow error code changed");
    require(contract_error_code_name(contract_error_code_t::invalid_workspace_identity) ==
                "C03_INVALID_WORKSPACE_IDENTITY",
            "invalid_workspace_identity error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_target_identity) ==
                "C03_INVALID_TARGET_IDENTITY",
            "invalid_target_identity error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_generation_identity) ==
                "C03_INVALID_GENERATION_IDENTITY",
            "invalid_generation_identity error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_publication_stage) ==
                "C03_INVALID_PUBLICATION_STAGE",
            "invalid_publication_stage error code name changed");
    require(contract_error_code_name(contract_error_code_t::publication_transition_rejected) ==
                "C03_PUBLICATION_TRANSITION_REJECTED",
            "publication_transition_rejected error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_packed_id) ==
                "C03_INVALID_PACKED_ID",
            "invalid_packed_id error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_resource_budget) ==
                "C03_INVALID_RESOURCE_BUDGET",
            "invalid_resource_budget error code name changed");
    require(contract_error_code_name(contract_error_code_t::resource_budget_exceeded) ==
                "C03_RESOURCE_BUDGET_EXCEEDED",
            "resource_budget_exceeded error code name changed");
    require(contract_error_code_name(contract_error_code_t::arithmetic_overflow) ==
                "C03_ARITHMETIC_OVERFLOW",
            "arithmetic_overflow error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_cancellation_domain) ==
                "C03_INVALID_CANCELLATION_DOMAIN",
            "invalid_cancellation_domain error code name changed");
    require(contract_error_code_name(contract_error_code_t::cancellation_domain_mismatch) ==
                "C03_CANCELLATION_DOMAIN_MISMATCH",
            "cancellation_domain_mismatch error code name changed");
    require(contract_error_code_name(contract_error_code_t::serialization_schema_mismatch) ==
                "C03_SERIALIZATION_SCHEMA_MISMATCH",
            "serialization_schema_mismatch error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_static_provider_provenance) ==
                "C03_INVALID_STATIC_PROVIDER_PROVENANCE",
            "invalid_static_provider_provenance error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_live_target_identity) ==
                "C03_INVALID_LIVE_TARGET_IDENTITY",
            "invalid_live_target_identity error code name changed");
    require(contract_error_code_name(contract_error_code_t::target_identity_provenance_mismatch) ==
                "C03_TARGET_IDENTITY_PROVENANCE_MISMATCH",
            "target_identity_provenance_mismatch error code name changed");
}

void verify_equality_operators()
{
    const auto workspace = make_workspace(71);
    const auto generation = make_generation(workspace, 0x4001, 5);

    const auto snapshot_a = require_value(immutable_snapshot_contract_t::make(
        generation, 10, 5, 3), "snapshot equality fixture creation failed");
    const auto snapshot_b = require_value(immutable_snapshot_contract_t::make(
        generation, 10, 5, 3), "snapshot equality fixture creation failed");
    require(snapshot_a == snapshot_b, "equal immutable snapshot contracts diverged");
    require(!(snapshot_a != snapshot_b), "equal immutable snapshot contracts compared unequal");
    const auto snapshot_diff_rev = require_value(immutable_snapshot_contract_t::make(
        generation, 11, 5, 3), "snapshot equality fixture creation failed");
    require(snapshot_a != snapshot_diff_rev,
            "snapshot revision was omitted from snapshot equality");
    const auto snapshot_diff_layout = require_value(immutable_snapshot_contract_t::make(
        generation, 10, 6, 3), "snapshot equality fixture creation failed");
    require(snapshot_a != snapshot_diff_layout,
            "layout revision was omitted from snapshot equality");
    const auto snapshot_diff_overlay = require_value(immutable_snapshot_contract_t::make(
        generation, 10, 5, 4), "snapshot equality fixture creation failed");
    require(snapshot_a != snapshot_diff_overlay,
            "overlay revision was omitted from snapshot equality");
    const auto other_generation = make_generation(workspace, 0x4002, 5);
    const auto snapshot_diff_gen = require_value(immutable_snapshot_contract_t::make(
        other_generation, 10, 5, 3), "snapshot equality fixture creation failed");
    require(snapshot_a != snapshot_diff_gen,
            "generation was omitted from snapshot equality");

    const auto publication_a = require_value(immutable_publication_contract_t::make(
        generation, snapshot_a, publication_stage_t::metadata_ready, 20),
        "publication equality fixture creation failed");
    const auto publication_b = require_value(immutable_publication_contract_t::make(
        generation, snapshot_a, publication_stage_t::metadata_ready, 20),
        "publication equality fixture creation failed");
    require(publication_a == publication_b,
            "equal immutable publication contracts diverged");
    require(!(publication_a != publication_b),
            "equal immutable publication contracts compared unequal");
    const auto publication_diff_stage = require_value(immutable_publication_contract_t::make(
        generation, snapshot_a, publication_stage_t::baseline_ready, 20),
        "publication equality fixture creation failed");
    require(publication_a != publication_diff_stage,
            "stage was omitted from publication equality");
    const auto publication_diff_rev = require_value(immutable_publication_contract_t::make(
        generation, snapshot_a, publication_stage_t::metadata_ready, 21),
        "publication equality fixture creation failed");
    require(publication_a != publication_diff_rev,
            "publication revision was omitted from publication equality");
    const auto publication_diff_snap = require_value(immutable_publication_contract_t::make(
        generation, snapshot_diff_rev, publication_stage_t::metadata_ready, 20),
        "publication equality fixture creation failed");
    require(publication_a != publication_diff_snap,
            "snapshot was omitted from publication equality");

    const auto packed_a = require_value(packed_analysis_id_t::make(1, 2, 3),
                                         "packed id equality fixture creation failed");
    const auto packed_b = require_value(packed_analysis_id_t::make(1, 2, 3),
                                         "packed id equality fixture creation failed");
    require(packed_a == packed_b, "equal packed analysis ids diverged");
    require(!(packed_a != packed_b), "equal packed analysis ids compared unequal");
    const auto packed_c = require_value(packed_analysis_id_t::make(1, 2, 4),
                                         "packed id equality fixture creation failed");
    require(packed_a != packed_c, "different packed analysis ids compared equal");

    const auto domain_a = require_value(cancellation_domain_t::for_workspace(workspace, 1),
                                         "cancellation domain equality fixture creation failed");
    const auto domain_b = require_value(cancellation_domain_t::for_workspace(workspace, 1),
                                         "cancellation domain equality fixture creation failed");
    require(domain_a == domain_b, "equal cancellation domains diverged");
    require(!(domain_a != domain_b), "equal cancellation domains compared unequal");
    const auto domain_diff_epoch = require_value(
        cancellation_domain_t::for_workspace(workspace, 2),
        "cancellation domain equality fixture creation failed");
    require(domain_a != domain_diff_epoch,
            "epoch was omitted from cancellation domain equality");
    const auto domain_diff_scope = require_value(cancellation_domain_t::for_target(
        generation.target(), 1), "cancellation domain equality fixture creation failed");
    require(domain_a != domain_diff_scope,
            "scope was omitted from cancellation domain equality");
}

void verify_primitive_id_rejection()
{
    const auto zero_workspace = workspace_id_t::from_bytes(workspace_id_t::bytes_t{});
    require(!zero_workspace &&
            zero_workspace.error().code == contract_error_code_t::invalid_workspace_identity,
            "all-zero workspace id bytes were accepted");

    const auto zero_target = target_id_t::from_value(0);
    require(!zero_target &&
            zero_target.error().code == contract_error_code_t::invalid_target_identity,
            "zero target id value was accepted");

    const auto zero_generation = generation_id_t::from_value(0);
    require(!zero_generation &&
            zero_generation.error().code == contract_error_code_t::invalid_generation_identity,
            "zero generation id value was accepted");
}

void verify_provider_kinds()
{
    const auto workspace = make_workspace(81);

    auto spill_provenance = make_static_provider_provenance(82);
    spill_provenance.provider_kind = static_provider_kind_t::spill;
    const auto spill_target = make_static_target(workspace, 0x1501, spill_provenance);
    require(spill_target.valid() &&
            spill_target.static_provider_provenance() &&
            spill_target.static_provider_provenance()->provider_kind == static_provider_kind_t::spill,
            "spill provider kind was not retained as a valid static target");
    require(static_cast<bool>(validate_static_provider_provenance(
                *spill_target.static_provider_provenance())),
            "spill provider provenance was rejected by the validator");

    auto streaming_provenance = make_static_provider_provenance(92);
    streaming_provenance.provider_kind = static_provider_kind_t::streaming;
    const auto streaming_target = make_static_target(workspace, 0x1502, streaming_provenance);
    require(streaming_target.valid() &&
            streaming_target.static_provider_provenance() &&
            streaming_target.static_provider_provenance()->provider_kind ==
                static_provider_kind_t::streaming,
            "streaming provider kind was not retained as a valid static target");
    require(static_cast<bool>(validate_static_provider_provenance(
                *streaming_target.static_provider_provenance())),
            "streaming provider provenance was rejected by the validator");
}

void verify_binary_identity_fields()
{
    const auto workspace = make_workspace(91);
    const auto target_id = require_value(target_id_t::from_value(0x5001), "target id creation failed");

    const auto static_target = require_value(target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x64,
        binary_mode_t::bit64, binary_endian_t::little),
        "binary identity target creation failed");
    require(static_target.valid(), "binary identity target was not valid");
    require(static_target.format() == binary_format_t::pe32_plus,
            "binary format was not retained");
    require(static_target.architecture() == binary_architecture_t::x64,
            "binary architecture was not retained");
    require(static_target.mode() == binary_mode_t::bit64,
            "binary mode was not retained");
    require(static_target.endian() == binary_endian_t::little,
            "binary endian was not retained");

    const auto unknown_format = target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::unknown, binary_architecture_t::x64,
        binary_mode_t::bit64, binary_endian_t::little);
    require(!unknown_format &&
            unknown_format.error().code == contract_error_code_t::invalid_binary_format,
            "unknown binary format was accepted");

    const auto unknown_arch = target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::unknown,
        binary_mode_t::bit64, binary_endian_t::little);
    require(!unknown_arch &&
            unknown_arch.error().code == contract_error_code_t::invalid_binary_architecture,
            "unknown binary architecture was accepted");

    const auto unknown_mode = target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x64,
        binary_mode_t::unknown, binary_endian_t::little);
    require(!unknown_mode &&
            unknown_mode.error().code == contract_error_code_t::invalid_binary_mode,
            "unknown binary mode was accepted");

    const auto unknown_endian = target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x64,
        binary_mode_t::bit64, binary_endian_t::unknown);
    require(!unknown_endian &&
            unknown_endian.error().code == contract_error_code_t::invalid_binary_endian,
            "unknown binary endian was accepted");

    const auto elf_target = require_value(target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(93)}, std::nullopt,
        binary_format_t::elf64, binary_architecture_t::aarch64,
        binary_mode_t::bit64, binary_endian_t::little),
        "elf binary identity target creation failed");
    require(static_target != elf_target,
            "different binary format was omitted from target equality");

    const auto x86_target = require_value(target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x86,
        binary_mode_t::bit64, binary_endian_t::little),
        "x86 binary identity target creation failed");
    require(static_target != x86_target,
            "different binary architecture was omitted from target equality");

    const auto bit32_target = require_value(target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x64,
        binary_mode_t::bit32, binary_endian_t::little),
        "bit32 binary identity target creation failed");
    require(static_target != bit32_target,
            "different binary mode was omitted from target equality");

    const auto big_endian_target = require_value(target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x64,
        binary_mode_t::bit64, binary_endian_t::big),
        "big endian binary identity target creation failed");
    require(static_target != big_endian_target,
            "different binary endian was omitted from target equality");

    const auto same_binary_target = require_value(target_contract_identity_t::make(
        workspace, target_id, analysis_target_kind_t::static_image,
        std::optional<static_provider_provenance_t>{make_static_provider_provenance(92)}, std::nullopt,
        binary_format_t::pe32_plus, binary_architecture_t::x64,
        binary_mode_t::bit64, binary_endian_t::little),
        "same binary identity target creation failed");
    require(static_target == same_binary_target,
            "equal binary identity targets diverged");

    require(is_known_binary_format(binary_format_t::pe32), "pe32 format was not known");
    require(is_known_binary_format(binary_format_t::pe32_plus), "pe32_plus format was not known");
    require(is_known_binary_format(binary_format_t::elf32), "elf32 format was not known");
    require(is_known_binary_format(binary_format_t::elf64), "elf64 format was not known");
    require(is_known_binary_format(binary_format_t::mach_o32), "mach_o32 format was not known");
    require(is_known_binary_format(binary_format_t::mach_o64), "mach_o64 format was not known");
    require(is_known_binary_format(binary_format_t::raw), "raw format was not known");
    require(!is_known_binary_format(binary_format_t::unknown), "unknown format was known");

    require(is_known_binary_architecture(binary_architecture_t::x86), "x86 architecture was not known");
    require(is_known_binary_architecture(binary_architecture_t::x64), "x64 architecture was not known");
    require(is_known_binary_architecture(binary_architecture_t::arm), "arm architecture was not known");
    require(is_known_binary_architecture(binary_architecture_t::aarch64), "aarch64 architecture was not known");
    require(is_known_binary_architecture(binary_architecture_t::mips), "mips architecture was not known");
    require(is_known_binary_architecture(binary_architecture_t::ppc), "ppc architecture was not known");
    require(is_known_binary_architecture(binary_architecture_t::riscv), "riscv architecture was not known");
    require(!is_known_binary_architecture(binary_architecture_t::unknown), "unknown architecture was known");

    require(is_known_binary_mode(binary_mode_t::bit32), "bit32 mode was not known");
    require(is_known_binary_mode(binary_mode_t::bit64), "bit64 mode was not known");
    require(is_known_binary_mode(binary_mode_t::thumb), "thumb mode was not known");
    require(!is_known_binary_mode(binary_mode_t::unknown), "unknown mode was known");

    require(is_known_binary_endian(binary_endian_t::little), "little endian was not known");
    require(is_known_binary_endian(binary_endian_t::big), "big endian was not known");
    require(is_known_binary_endian(binary_endian_t::mixed), "mixed endian was not known");
    require(!is_known_binary_endian(binary_endian_t::unknown), "unknown endian was known");

    require(contract_error_code_name(contract_error_code_t::invalid_binary_format) ==
                "C03_INVALID_BINARY_FORMAT",
            "invalid_binary_format error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_binary_architecture) ==
                "C03_INVALID_BINARY_ARCHITECTURE",
            "invalid_binary_architecture error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_binary_mode) ==
                "C03_INVALID_BINARY_MODE",
            "invalid_binary_mode error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_binary_endian) ==
                "C03_INVALID_BINARY_ENDIAN",
            "invalid_binary_endian error code name changed");
}

void verify_generation_metadata_fields()
{
    const auto workspace = make_workspace(101);
    const auto generation = make_generation(workspace, 0x6001, 9);

    decompiler_cache_namespace_t cache_ns = make_identity_bytes<16>(111);
    const auto snapshot = require_value(immutable_snapshot_contract_t::make(
        generation, 20, 10, 5, 7, cache_ns),
        "generation metadata snapshot creation failed");
    require(snapshot.valid(), "generation metadata snapshot was not valid");
    require(snapshot.metadata_revision() == 7,
            "metadata revision was not retained");
    require(snapshot.decompiler_cache_namespace() == cache_ns,
            "decompiler cache namespace was not retained");

    const auto zero_metadata = immutable_snapshot_contract_t::make(
        generation, 20, 10, 5, 0, cache_ns);
    require(!zero_metadata &&
            zero_metadata.error().code == contract_error_code_t::invalid_metadata_revision,
            "zero metadata revision was accepted");

    const auto zero_cache_ns = immutable_snapshot_contract_t::make(
        generation, 20, 10, 5, 7, decompiler_cache_namespace_t{});
    require(!zero_cache_ns &&
            zero_cache_ns.error().code == contract_error_code_t::invalid_decompiler_cache_namespace,
            "all-zero decompiler cache namespace was accepted");

    const auto same_snapshot = require_value(immutable_snapshot_contract_t::make(
        generation, 20, 10, 5, 7, cache_ns),
        "generation metadata snapshot creation failed");
    require(snapshot == same_snapshot,
            "equal generation metadata snapshots diverged");

    const auto diff_metadata = require_value(immutable_snapshot_contract_t::make(
        generation, 20, 10, 5, 8, cache_ns),
        "generation metadata snapshot creation failed");
    require(snapshot != diff_metadata,
            "metadata revision was omitted from snapshot equality");

    decompiler_cache_namespace_t other_cache_ns = make_identity_bytes<16>(222);
    const auto diff_cache_ns = require_value(immutable_snapshot_contract_t::make(
        generation, 20, 10, 5, 7, other_cache_ns),
        "generation metadata snapshot creation failed");
    require(snapshot != diff_cache_ns,
            "decompiler cache namespace was omitted from snapshot equality");

    require(decompiler_cache_namespace_present(cache_ns),
            "non-zero decompiler cache namespace was not present");
    require(!decompiler_cache_namespace_present(decompiler_cache_namespace_t{}),
            "all-zero decompiler cache namespace was present");

    require(contract_error_code_name(contract_error_code_t::invalid_metadata_revision) ==
                "C03_INVALID_METADATA_REVISION",
            "invalid_metadata_revision error code name changed");
    require(contract_error_code_name(contract_error_code_t::invalid_decompiler_cache_namespace) ==
                "C03_INVALID_DECOMPILER_CACHE_NAMESPACE",
            "invalid_decompiler_cache_namespace error code name changed");

    const auto default_snapshot = require_value(immutable_snapshot_contract_t::make(
        generation, 20, 10, 5),
        "default generation metadata snapshot creation failed");
    require(default_snapshot.valid(), "default generation metadata snapshot was not valid");
    require(default_snapshot.metadata_revision() == 1,
            "default metadata revision was not 1");
    require(default_snapshot.decompiler_cache_namespace() == default_decompiler_cache_namespace,
            "default decompiler cache namespace was not the default constant");
}

}

int main()
{
    try {
        verify_identity_equality();
        verify_target_provenance_contract();
        verify_target_provenance_rejection();
        verify_packed_id_contract();
        verify_publication_contract();
        verify_resource_budget_contract();
        verify_cancellation_domains();
        verify_stable_schema_and_error_values();
        verify_equality_operators();
        verify_primitive_id_rejection();
        verify_provider_kinds();
        verify_binary_identity_fields();
        verify_generation_metadata_fields();
        std::cout << "analysis contracts harness passed\n";
        return 0;
    } catch (const std::exception& error) {
		aida::analysis::c03_test::assertion_telemetry::record_exception(error.what());
        std::cerr << "analysis contracts harness failed: " << error.what() << '\n';
        return 1;
    }
}
