#include "c03_analysis_contracts.hpp"

namespace aida::analysis::c03 {

namespace {

bool all_zero(const workspace_id_t::bytes_t& bytes) noexcept
{
    for (const auto byte : bytes) {
        if (byte != 0)
            return false;
    }
    return true;
}

constexpr bool checked_add(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& result) noexcept
{
    if (rhs > (std::numeric_limits<std::uint64_t>::max)() - lhs)
        return false;
    result = lhs + rhs;
    return true;
}

contract_result_t<void> validate_limit(std::uint64_t value, std::uint64_t limit,
                                       std::string_view phase) noexcept
{
    if (value > limit) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::resource_budget_exceeded, phase, limit, value));
    }
    return contract_result_t<void>::success();
}

contract_result_t<void> validate_usage(const analysis_resource_budget_t& budget,
                                       const analysis_resource_usage_t& usage) noexcept
{
    const auto private_result = validate_limit(
        usage.incremental_private_bytes, budget.max_incremental_private_bytes,
        "incremental_private_bytes");
    if (!private_result)
        return private_result;

    const auto workspace_windows = validate_limit(
        usage.workspace_mapped_window_bytes, budget.max_workspace_mapped_window_bytes,
        "workspace_mapped_window_bytes");
    if (!workspace_windows)
        return workspace_windows;

    const auto global_windows = validate_limit(
        usage.global_mapped_window_bytes, budget.max_global_mapped_window_bytes,
        "global_mapped_window_bytes");
    if (!global_windows)
        return global_windows;

    const auto workspace_spill = validate_limit(
        usage.workspace_spill_bytes, budget.max_workspace_spill_bytes, "workspace_spill_bytes");
    if (!workspace_spill)
        return workspace_spill;

    const auto global_spill = validate_limit(
        usage.global_spill_bytes, budget.max_global_spill_bytes, "global_spill_bytes");
    if (!global_spill)
        return global_spill;

    const auto workspace_cache = validate_limit(
        usage.workspace_cache_bytes, budget.max_workspace_cache_bytes, "workspace_cache_bytes");
    if (!workspace_cache)
        return workspace_cache;

    return validate_limit(usage.global_cache_bytes, budget.max_global_cache_bytes,
                          "global_cache_bytes");
}

contract_result_t<std::uint64_t> add_usage(std::uint64_t current, std::uint64_t requested,
                                           std::string_view phase) noexcept
{
    std::uint64_t result = 0;
    if (!checked_add(current, requested, result)) {
        return contract_result_t<std::uint64_t>::failure(make_contract_error(
            contract_error_code_t::arithmetic_overflow, phase, current, requested));
    }
    return contract_result_t<std::uint64_t>::success(result);
}

constexpr bool is_static_target_kind(analysis_target_kind_t kind) noexcept
{
    return kind == analysis_target_kind_t::static_image ||
        kind == analysis_target_kind_t::collection_member;
}

constexpr bool is_known_target_kind(analysis_target_kind_t kind) noexcept
{
    return is_static_target_kind(kind) || kind == analysis_target_kind_t::live_module;
}

std::uint64_t target_provenance_payload_mask(
    const std::optional<static_provider_provenance_t>& static_provider_provenance,
    const std::optional<live_target_identity_t>& live_identity) noexcept
{
    return (static_provider_provenance ? 1ULL : 0ULL) | (live_identity ? 2ULL : 0ULL);
}

}

std::string_view contract_error_code_name(contract_error_code_t code) noexcept
{
    switch (code) {
    case contract_error_code_t::none:
        return "C03_NONE";
    case contract_error_code_t::invalid_workspace_identity:
        return "C03_INVALID_WORKSPACE_IDENTITY";
    case contract_error_code_t::invalid_target_identity:
        return "C03_INVALID_TARGET_IDENTITY";
    case contract_error_code_t::invalid_generation_identity:
        return "C03_INVALID_GENERATION_IDENTITY";
    case contract_error_code_t::generation_mismatch:
        return "C03_GENERATION_MISMATCH";
    case contract_error_code_t::invalid_publication_stage:
        return "C03_INVALID_PUBLICATION_STAGE";
    case contract_error_code_t::publication_transition_rejected:
        return "C03_PUBLICATION_TRANSITION_REJECTED";
    case contract_error_code_t::packed_id_overflow:
        return "C03_PACKED_ID_OVERFLOW";
    case contract_error_code_t::invalid_packed_id:
        return "C03_INVALID_PACKED_ID";
    case contract_error_code_t::invalid_resource_budget:
        return "C03_INVALID_RESOURCE_BUDGET";
    case contract_error_code_t::resource_budget_exceeded:
        return "C03_RESOURCE_BUDGET_EXCEEDED";
    case contract_error_code_t::arithmetic_overflow:
        return "C03_ARITHMETIC_OVERFLOW";
    case contract_error_code_t::invalid_cancellation_domain:
        return "C03_INVALID_CANCELLATION_DOMAIN";
    case contract_error_code_t::cancellation_domain_mismatch:
        return "C03_CANCELLATION_DOMAIN_MISMATCH";
    case contract_error_code_t::serialization_schema_mismatch:
        return "C03_SERIALIZATION_SCHEMA_MISMATCH";
    case contract_error_code_t::invalid_static_provider_provenance:
        return "C03_INVALID_STATIC_PROVIDER_PROVENANCE";
    case contract_error_code_t::invalid_live_target_identity:
        return "C03_INVALID_LIVE_TARGET_IDENTITY";
    case contract_error_code_t::target_identity_provenance_mismatch:
        return "C03_TARGET_IDENTITY_PROVENANCE_MISMATCH";
    case contract_error_code_t::invalid_binary_format:
        return "C03_INVALID_BINARY_FORMAT";
    case contract_error_code_t::invalid_binary_architecture:
        return "C03_INVALID_BINARY_ARCHITECTURE";
    case contract_error_code_t::invalid_binary_mode:
        return "C03_INVALID_BINARY_MODE";
    case contract_error_code_t::invalid_binary_endian:
        return "C03_INVALID_BINARY_ENDIAN";
    case contract_error_code_t::invalid_metadata_revision:
        return "C03_INVALID_METADATA_REVISION";
    case contract_error_code_t::invalid_decompiler_cache_namespace:
        return "C03_INVALID_DECOMPILER_CACHE_NAMESPACE";
    }
    return "C03_UNKNOWN_ERROR";
}

contract_error_t make_contract_error(contract_error_code_t code, std::string_view phase,
                                     std::uint64_t expected, std::uint64_t actual) noexcept
{
    return contract_error_t{code, contract_error_code_name(code), phase, expected, actual};
}

std::uint32_t contract_schema_version_for(contract_schema_t schema) noexcept
{
    switch (schema) {
    case contract_schema_t::workspace_identity:
    case contract_schema_t::target_identity:
    case contract_schema_t::generation_identity:
    case contract_schema_t::immutable_snapshot:
    case contract_schema_t::immutable_publication:
    case contract_schema_t::packed_analysis_id:
    case contract_schema_t::resource_budget:
    case contract_schema_t::cancellation_domain:
    case contract_schema_t::static_provider_provenance:
    case contract_schema_t::live_target_identity:
        return c03_contract_schema_version;
    }
    return 0;
}

std::string_view contract_schema_name(contract_schema_t schema) noexcept
{
    switch (schema) {
    case contract_schema_t::workspace_identity:
        return "workspace_identity";
    case contract_schema_t::target_identity:
        return "target_identity";
    case contract_schema_t::generation_identity:
        return "generation_identity";
    case contract_schema_t::immutable_snapshot:
        return "immutable_snapshot";
    case contract_schema_t::immutable_publication:
        return "immutable_publication";
    case contract_schema_t::packed_analysis_id:
        return "packed_analysis_id";
    case contract_schema_t::resource_budget:
        return "resource_budget";
    case contract_schema_t::cancellation_domain:
        return "cancellation_domain";
    case contract_schema_t::static_provider_provenance:
        return "static_provider_provenance";
    case contract_schema_t::live_target_identity:
        return "live_target_identity";
    }
    return "unknown";
}

contract_result_t<void> validate_contract_schema_version(contract_schema_t schema,
                                                         std::uint32_t version) noexcept
{
    const auto expected = contract_schema_version_for(schema);
    if (expected == 0 || version != expected) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::serialization_schema_mismatch, "serialization_schema", expected,
            version));
    }
    return contract_result_t<void>::success();
}

contract_result_t<workspace_id_t> workspace_id_t::from_bytes(const bytes_t& bytes) noexcept
{
    if (all_zero(bytes)) {
        return contract_result_t<workspace_id_t>::failure(make_contract_error(
            contract_error_code_t::invalid_workspace_identity, "workspace_id"));
    }
    return contract_result_t<workspace_id_t>::success(workspace_id_t(bytes));
}

contract_result_t<target_id_t> target_id_t::from_value(std::uint64_t value) noexcept
{
    if (value == 0) {
        return contract_result_t<target_id_t>::failure(make_contract_error(
            contract_error_code_t::invalid_target_identity, "target_id"));
    }
    return contract_result_t<target_id_t>::success(target_id_t(value));
}

contract_result_t<generation_id_t> generation_id_t::from_value(std::uint64_t value) noexcept
{
    if (value == 0) {
        return contract_result_t<generation_id_t>::failure(make_contract_error(
            contract_error_code_t::invalid_generation_identity, "generation_id"));
    }
    return contract_result_t<generation_id_t>::success(generation_id_t(value));
}

contract_result_t<workspace_contract_identity_t>
workspace_contract_identity_t::make(const workspace_id_t& workspace) noexcept
{
    if (!workspace.valid()) {
        return contract_result_t<workspace_contract_identity_t>::failure(make_contract_error(
            contract_error_code_t::invalid_workspace_identity, "workspace_identity"));
    }
    return contract_result_t<workspace_contract_identity_t>::success(
        workspace_contract_identity_t(workspace));
}

contract_result_t<void> validate_static_provider_provenance(
    const static_provider_provenance_t& provenance) noexcept
{
    if (provenance.provider_kind != static_provider_kind_t::mapped_file &&
        provenance.provider_kind != static_provider_kind_t::subrange &&
        provenance.provider_kind != static_provider_kind_t::spill &&
        provenance.provider_kind != static_provider_kind_t::streaming) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_provider_kind"));
    }
    if (!identity_bytes_present(provenance.provider_identity)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_provider_identity"));
    }
    if (provenance.provider_snapshot_generation == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance,
            "static_provider_snapshot_generation"));
    }
    if (!identity_bytes_present(provenance.canonical_path_fingerprint)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_canonical_path"));
    }
    if (!identity_bytes_present(provenance.source_file_identity)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_source_file_identity"));
    }
    if (provenance.source_length == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_source_length"));
    }
    if (provenance.last_write_identity == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_last_write_identity"));
    }
    if (!identity_bytes_present(provenance.content_fingerprint)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_content_fingerprint"));
    }
    if (!identity_bytes_present(provenance.member_chain_fingerprint)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_member_chain"));
    }
    if (!identity_bytes_present(provenance.image_mapping_fingerprint)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_static_provider_provenance, "static_image_mapping"));
    }
    return contract_result_t<void>::success();
}

contract_result_t<void> validate_live_target_identity(
    const live_target_identity_t& identity) noexcept
{
    if (identity.process_id == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_process_id"));
    }
    if (identity.process_creation_identity == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_process_creation_identity"));
    }
    if (!range_is_present(identity.module_base, identity.module_size)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_module_range"));
    }
    if (!identity_bytes_present(identity.module_fingerprint)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_module_fingerprint"));
    }
    if (!range_is_present(identity.capture_base, identity.capture_size)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_capture_range"));
    }
    const auto module_end = identity.module_base + identity.module_size;
    const auto capture_end = identity.capture_base + identity.capture_size;
    if (identity.capture_base < identity.module_base || capture_end > module_end) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_capture_bounds"));
    }
    if (identity.attach_generation == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_live_target_identity, "live_attach_generation"));
    }
    return contract_result_t<void>::success();
}

contract_result_t<void> validate_binary_identity_fields(
    binary_format_t format, binary_architecture_t architecture,
    binary_mode_t mode, binary_endian_t endian) noexcept
{
    if (!is_known_binary_format(format)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_binary_format, "target_binary_format",
            0, static_cast<std::uint64_t>(format)));
    }
    if (!is_known_binary_architecture(architecture)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_binary_architecture, "target_binary_architecture",
            0, static_cast<std::uint64_t>(architecture)));
    }
    if (!is_known_binary_mode(mode)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_binary_mode, "target_binary_mode",
            0, static_cast<std::uint64_t>(mode)));
    }
    if (!is_known_binary_endian(endian)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_binary_endian, "target_binary_endian",
            0, static_cast<std::uint64_t>(endian)));
    }
    return contract_result_t<void>::success();
}

contract_result_t<target_contract_identity_t>
target_contract_identity_t::make(const workspace_contract_identity_t& workspace,
                                 const target_id_t& target, analysis_target_kind_t kind,
                                 std::optional<static_provider_provenance_t> static_provider_provenance,
                                 std::optional<live_target_identity_t> live_identity,
                                 binary_format_t format,
                                 binary_architecture_t architecture,
                                 binary_mode_t mode,
                                 binary_endian_t endian) noexcept
{
    if (!workspace.valid() || !target.valid() || !is_known_target_kind(kind)) {
        return contract_result_t<target_contract_identity_t>::failure(make_contract_error(
            contract_error_code_t::invalid_target_identity, "target_identity"));
    }
    const auto binary_result = validate_binary_identity_fields(format, architecture, mode, endian);
    if (!binary_result)
        return contract_result_t<target_contract_identity_t>::failure(binary_result.error());
    const auto payload_mask = target_provenance_payload_mask(static_provider_provenance, live_identity);
    if (is_static_target_kind(kind)) {
        if (!static_provider_provenance || live_identity) {
            return contract_result_t<target_contract_identity_t>::failure(make_contract_error(
                contract_error_code_t::target_identity_provenance_mismatch,
                "target_identity_provenance", static_cast<std::uint64_t>(kind), payload_mask));
        }
        const auto provenance_result = validate_static_provider_provenance(*static_provider_provenance);
        if (!provenance_result)
            return contract_result_t<target_contract_identity_t>::failure(provenance_result.error());
    } else {
        if (static_provider_provenance || !live_identity) {
            return contract_result_t<target_contract_identity_t>::failure(make_contract_error(
                contract_error_code_t::target_identity_provenance_mismatch,
                "target_identity_provenance", static_cast<std::uint64_t>(kind), payload_mask));
        }
        const auto live_result = validate_live_target_identity(*live_identity);
        if (!live_result)
            return contract_result_t<target_contract_identity_t>::failure(live_result.error());
    }
    return contract_result_t<target_contract_identity_t>::success(
        target_contract_identity_t(workspace, target, kind, std::move(static_provider_provenance),
                                   std::move(live_identity), format, architecture, mode, endian));
}

contract_result_t<generation_contract_identity_t>
generation_contract_identity_t::make(const target_contract_identity_t& target,
                                     const generation_id_t& generation) noexcept
{
    if (!target.valid() || !generation.valid()) {
        return contract_result_t<generation_contract_identity_t>::failure(make_contract_error(
            contract_error_code_t::invalid_generation_identity, "generation_identity"));
    }
    return contract_result_t<generation_contract_identity_t>::success(
        generation_contract_identity_t(target, generation));
}

std::string_view publication_stage_name(publication_stage_t stage) noexcept
{
    switch (stage) {
    case publication_stage_t::none:
        return "none";
    case publication_stage_t::metadata_ready:
        return "metadata_ready";
    case publication_stage_t::baseline_ready:
        return "baseline_ready";
    case publication_stage_t::retired:
        return "retired";
    }
    return "unknown";
}

bool publication_stage_transition_allowed(publication_stage_t from, publication_stage_t to) noexcept
{
    switch (from) {
    case publication_stage_t::none:
        return to == publication_stage_t::metadata_ready || to == publication_stage_t::baseline_ready;
    case publication_stage_t::metadata_ready:
        return to == publication_stage_t::baseline_ready || to == publication_stage_t::retired;
    case publication_stage_t::baseline_ready:
        return to == publication_stage_t::retired;
    case publication_stage_t::retired:
        return false;
    }
    return false;
}

contract_result_t<void> validate_publication_stage_transition(publication_stage_t from,
                                                              publication_stage_t to) noexcept
{
    if (publication_stage_name(from) == "unknown" || publication_stage_name(to) == "unknown") {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_publication_stage, "publication_stage",
            static_cast<std::uint64_t>(from), static_cast<std::uint64_t>(to)));
    }
    if (!publication_stage_transition_allowed(from, to)) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::publication_transition_rejected, "publication_transition",
            static_cast<std::uint64_t>(from), static_cast<std::uint64_t>(to)));
    }
    return contract_result_t<void>::success();
}

contract_result_t<immutable_snapshot_contract_t>
immutable_snapshot_contract_t::make(const generation_contract_identity_t& generation,
                                    std::uint64_t snapshot_revision,
                                    std::uint64_t layout_revision,
                                    std::uint64_t overlay_revision,
                                    std::uint64_t metadata_revision,
                                    decompiler_cache_namespace_t decompiler_cache_namespace) noexcept
{
    if (!generation.valid() || snapshot_revision == 0 || layout_revision == 0) {
        return contract_result_t<immutable_snapshot_contract_t>::failure(make_contract_error(
            contract_error_code_t::invalid_generation_identity, "immutable_snapshot"));
    }
    if (metadata_revision == 0) {
        return contract_result_t<immutable_snapshot_contract_t>::failure(make_contract_error(
            contract_error_code_t::invalid_metadata_revision, "immutable_snapshot_metadata_revision"));
    }
    if (!decompiler_cache_namespace_present(decompiler_cache_namespace)) {
        return contract_result_t<immutable_snapshot_contract_t>::failure(make_contract_error(
            contract_error_code_t::invalid_decompiler_cache_namespace,
            "immutable_snapshot_decompiler_cache_namespace"));
    }
    return contract_result_t<immutable_snapshot_contract_t>::success(
        immutable_snapshot_contract_t(generation, snapshot_revision, layout_revision, overlay_revision,
                                      metadata_revision, decompiler_cache_namespace));
}

contract_result_t<immutable_publication_contract_t>
immutable_publication_contract_t::make(const generation_contract_identity_t& expected_generation,
                                       const immutable_snapshot_contract_t& snapshot,
                                       publication_stage_t stage,
                                       std::uint64_t publication_revision) noexcept
{
    if (!expected_generation.valid() || !snapshot.valid() || publication_revision == 0) {
        return contract_result_t<immutable_publication_contract_t>::failure(make_contract_error(
            contract_error_code_t::invalid_generation_identity, "immutable_publication"));
    }
    if (snapshot.generation() != expected_generation) {
        return contract_result_t<immutable_publication_contract_t>::failure(make_contract_error(
            contract_error_code_t::generation_mismatch, "immutable_publication",
            expected_generation.generation_id().value(), snapshot.generation().generation_id().value()));
    }
    if (stage != publication_stage_t::metadata_ready && stage != publication_stage_t::baseline_ready) {
        return contract_result_t<immutable_publication_contract_t>::failure(make_contract_error(
            contract_error_code_t::invalid_publication_stage, "immutable_publication", 0,
            static_cast<std::uint64_t>(stage)));
    }
    return contract_result_t<immutable_publication_contract_t>::success(
        immutable_publication_contract_t(snapshot, stage, publication_revision));
}

contract_result_t<packed_analysis_id_t>
packed_analysis_id_t::make(std::uint64_t domain, std::uint64_t shard,
                           std::uint64_t ordinal) noexcept
{
    if (domain == 0) {
        return contract_result_t<packed_analysis_id_t>::failure(make_contract_error(
            contract_error_code_t::invalid_packed_id, "packed_analysis_id"));
    }
    if (domain > (std::numeric_limits<std::uint16_t>::max)()) {
        return contract_result_t<packed_analysis_id_t>::failure(make_contract_error(
            contract_error_code_t::packed_id_overflow, "packed_analysis_id",
            (std::numeric_limits<std::uint16_t>::max)(), domain));
    }
    if (shard > (std::numeric_limits<std::uint16_t>::max)()) {
        return contract_result_t<packed_analysis_id_t>::failure(make_contract_error(
            contract_error_code_t::packed_id_overflow, "packed_analysis_id",
            (std::numeric_limits<std::uint16_t>::max)(), shard));
    }
    if (ordinal > (std::numeric_limits<std::uint32_t>::max)()) {
        return contract_result_t<packed_analysis_id_t>::failure(make_contract_error(
            contract_error_code_t::packed_id_overflow, "packed_analysis_id",
            (std::numeric_limits<std::uint32_t>::max)(), ordinal));
    }
    const auto value = (domain << 48U) | (shard << 32U) | ordinal;
    return contract_result_t<packed_analysis_id_t>::success(packed_analysis_id_t(value));
}

contract_result_t<void> validate_analysis_resource_budget(
    const analysis_resource_budget_t& budget) noexcept
{
    if (budget.max_incremental_private_bytes == 0 ||
        budget.max_workspace_mapped_window_bytes == 0 ||
        budget.max_global_mapped_window_bytes == 0 || budget.max_workspace_spill_bytes == 0 ||
        budget.max_global_spill_bytes == 0 || budget.max_workspace_cache_bytes == 0 ||
        budget.max_global_cache_bytes == 0 || budget.cancellation_checkpoint_milliseconds == 0) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_resource_budget, "resource_budget"));
    }
    if (budget.max_incremental_private_bytes > max_incremental_private_bytes ||
        budget.max_workspace_mapped_window_bytes > max_workspace_mapped_window_bytes ||
        budget.max_global_mapped_window_bytes > max_global_mapped_window_bytes ||
        budget.max_workspace_spill_bytes > max_workspace_spill_bytes ||
        budget.max_global_spill_bytes > max_global_spill_bytes ||
        budget.max_workspace_cache_bytes > max_workspace_cache_bytes ||
        budget.max_global_cache_bytes > max_global_cache_bytes ||
        budget.cancellation_checkpoint_milliseconds > max_cancellation_checkpoint_milliseconds ||
        budget.max_workspace_mapped_window_bytes > budget.max_global_mapped_window_bytes ||
        budget.max_workspace_spill_bytes > budget.max_global_spill_bytes ||
        budget.max_workspace_cache_bytes > budget.max_global_cache_bytes) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_resource_budget, "resource_budget"));
    }
    return contract_result_t<void>::success();
}

contract_result_t<analysis_resource_usage_t> reserve_analysis_resources(
    const analysis_resource_budget_t& budget, const analysis_resource_usage_t& current,
    const analysis_resource_usage_t& requested) noexcept
{
    const auto budget_result = validate_analysis_resource_budget(budget);
    if (!budget_result)
        return contract_result_t<analysis_resource_usage_t>::failure(budget_result.error());

    analysis_resource_usage_t next;
    const auto private_bytes = add_usage(current.incremental_private_bytes,
                                         requested.incremental_private_bytes,
                                         "incremental_private_bytes");
    if (!private_bytes)
        return contract_result_t<analysis_resource_usage_t>::failure(private_bytes.error());
    next.incremental_private_bytes = private_bytes.value();

    const auto workspace_windows = add_usage(current.workspace_mapped_window_bytes,
                                             requested.workspace_mapped_window_bytes,
                                             "workspace_mapped_window_bytes");
    if (!workspace_windows)
        return contract_result_t<analysis_resource_usage_t>::failure(workspace_windows.error());
    next.workspace_mapped_window_bytes = workspace_windows.value();

    const auto global_windows = add_usage(current.global_mapped_window_bytes,
                                          requested.global_mapped_window_bytes,
                                          "global_mapped_window_bytes");
    if (!global_windows)
        return contract_result_t<analysis_resource_usage_t>::failure(global_windows.error());
    next.global_mapped_window_bytes = global_windows.value();

    const auto workspace_spill = add_usage(current.workspace_spill_bytes,
                                           requested.workspace_spill_bytes,
                                           "workspace_spill_bytes");
    if (!workspace_spill)
        return contract_result_t<analysis_resource_usage_t>::failure(workspace_spill.error());
    next.workspace_spill_bytes = workspace_spill.value();

    const auto global_spill = add_usage(current.global_spill_bytes, requested.global_spill_bytes,
                                        "global_spill_bytes");
    if (!global_spill)
        return contract_result_t<analysis_resource_usage_t>::failure(global_spill.error());
    next.global_spill_bytes = global_spill.value();

    const auto workspace_cache = add_usage(current.workspace_cache_bytes,
                                           requested.workspace_cache_bytes,
                                           "workspace_cache_bytes");
    if (!workspace_cache)
        return contract_result_t<analysis_resource_usage_t>::failure(workspace_cache.error());
    next.workspace_cache_bytes = workspace_cache.value();

    const auto global_cache = add_usage(current.global_cache_bytes, requested.global_cache_bytes,
                                        "global_cache_bytes");
    if (!global_cache)
        return contract_result_t<analysis_resource_usage_t>::failure(global_cache.error());
    next.global_cache_bytes = global_cache.value();

    const auto usage_result = validate_usage(budget, next);
    if (!usage_result)
        return contract_result_t<analysis_resource_usage_t>::failure(usage_result.error());
    return contract_result_t<analysis_resource_usage_t>::success(next);
}

contract_result_t<cancellation_domain_t>
cancellation_domain_t::for_workspace(const workspace_contract_identity_t& workspace,
                                     std::uint64_t epoch) noexcept
{
    if (!workspace.valid() || epoch == 0) {
        return contract_result_t<cancellation_domain_t>::failure(make_contract_error(
            contract_error_code_t::invalid_cancellation_domain, "workspace_cancellation_domain"));
    }
    return contract_result_t<cancellation_domain_t>::success(cancellation_domain_t(
        cancellation_domain_scope_t::workspace, workspace, std::nullopt, std::nullopt, epoch));
}

contract_result_t<cancellation_domain_t>
cancellation_domain_t::for_target(const target_contract_identity_t& target,
                                  std::uint64_t epoch) noexcept
{
    if (!target.valid() || epoch == 0) {
        return contract_result_t<cancellation_domain_t>::failure(make_contract_error(
            contract_error_code_t::invalid_cancellation_domain, "target_cancellation_domain"));
    }
    return contract_result_t<cancellation_domain_t>::success(cancellation_domain_t(
        cancellation_domain_scope_t::target, target.workspace(), target, std::nullopt, epoch));
}

contract_result_t<cancellation_domain_t>
cancellation_domain_t::for_generation(const generation_contract_identity_t& generation,
                                      std::uint64_t epoch) noexcept
{
    if (!generation.valid() || epoch == 0) {
        return contract_result_t<cancellation_domain_t>::failure(make_contract_error(
            contract_error_code_t::invalid_cancellation_domain, "generation_cancellation_domain"));
    }
    return contract_result_t<cancellation_domain_t>::success(cancellation_domain_t(
        cancellation_domain_scope_t::generation, generation.target().workspace(), generation.target(),
        generation, epoch));
}

contract_result_t<void> validate_cancellation_domain(
    const cancellation_domain_t& domain, const generation_contract_identity_t& generation) noexcept
{
    if (!domain.valid() || !generation.valid()) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::invalid_cancellation_domain, "cancellation_domain"));
    }
    const bool covers = domain.workspace() == generation.target().workspace() &&
        (domain.scope() == cancellation_domain_scope_t::workspace ||
         (domain.scope() == cancellation_domain_scope_t::target && domain.target() &&
          *domain.target() == generation.target()) ||
         (domain.scope() == cancellation_domain_scope_t::generation && domain.generation() &&
          *domain.generation() == generation));
    if (!covers) {
        return contract_result_t<void>::failure(make_contract_error(
            contract_error_code_t::cancellation_domain_mismatch, "cancellation_domain",
            domain.epoch(), generation.generation_id().value()));
    }
    return contract_result_t<void>::success();
}

}
