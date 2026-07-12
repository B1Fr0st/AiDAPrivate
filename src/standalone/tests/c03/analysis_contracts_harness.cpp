#include "../../src/core/analysis/workspace/c03_analysis_contracts.hpp"

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
static_assert(c03_contract_schema_version == 2, "contract schema version changed");
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

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

template <typename value_t>
value_t require_value(contract_result_t<value_t> result, std::string_view message)
{
    if (!result)
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
        std::cout << "analysis contracts harness passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "analysis contracts harness failed: " << error.what() << '\n';
        return 1;
    }
}
