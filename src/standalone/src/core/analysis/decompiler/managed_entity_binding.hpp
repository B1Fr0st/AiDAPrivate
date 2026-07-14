#pragma once

#include "decompiler_contracts.hpp"
#include "../readers/managed/managed_reader_contracts.hpp"
#include "../workspace/workspace_identity.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

class analysis_workspace_t;
class pe_image_t;
struct analysis_publication_t;
struct analysis_snapshot_t;

namespace jvm_ssa {
struct jvm_method_input_t;
}

namespace dalvik_ssa {
struct dalvik_ssa_capture_t;
}

inline constexpr std::uint32_t managed_entity_binding_schema_version = 1;

struct managed_artifact_binding_record_t final {
    readers::managed::managed_artifact_kind_t kind =
        readers::managed::managed_artifact_kind_t::cli_metadata;
    sha256_digest_t artifact_hash;
    std::uint64_t provider_offset = 0;
    std::uint64_t provider_size = 0;
    std::uint32_t artifact_ordinal = 0;
    std::string assembly_identity;
    std::string module_name;
    std::string version;
    std::uint32_t first_method = 0;
    std::uint32_t method_count = 0;
};

struct managed_method_binding_record_t final {
    std::uint32_t artifact_index = 0;
    std::uint32_t entity_token = 0;
    std::uint32_t method_index = 0;
    std::uint64_t provider_code_offset = 0;
    std::uint64_t code_size = 0;
    decompiler_entity_key_t entity;
    bool has_body = false;
};

struct managed_artifact_record_index_t final {
    std::vector<managed_artifact_binding_record_t> artifacts;
    std::vector<managed_method_binding_record_t> methods;
};

struct managed_artifact_publication_t final {
    std::uint32_t schema_version = managed_entity_binding_schema_version;
    std::uint32_t reader_schema_version =
        readers::managed::managed_reader_schema_version;
    readers::managed::managed_reader_limits_t reader_limits;
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    sha256_digest_t provider_hash;
    std::string provider_source;
    std::uint64_t provider_size = 0;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::shared_ptr<const managed_artifact_record_index_t> records;

    const std::vector<managed_artifact_binding_record_t>& artifacts() const noexcept {
        static const std::vector<managed_artifact_binding_record_t> empty;
        return records ? records->artifacts : empty;
    }

    const std::vector<managed_method_binding_record_t>& methods() const noexcept {
        static const std::vector<managed_method_binding_record_t> empty;
        return records ? records->methods : empty;
    }

    bool coherent_with(const workspace_identity_t& identity,
                       const byte_provider_t& provider,
                       std::uint64_t expected_generation,
                       std::uint64_t expected_analysis_revision,
                       std::uint64_t expected_overlay_revision) const noexcept;
};

struct decompiler_entity_locator_t final {
    std::optional<std::uint64_t> address;
    std::optional<std::uint32_t> token;
    std::optional<std::uint32_t> artifact_ordinal;
    std::optional<decompiler_entity_kind_t> expected_kind;
};

struct generation_bound_decompiler_entity_t final {
    std::uint32_t schema_version = managed_entity_binding_schema_version;
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    sha256_digest_t provider_hash;
    sha256_digest_t artifact_hash;
    std::uint64_t provider_size = 0;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    std::uint64_t type_graph_revision = 0;
    std::uint32_t reader_schema_version = 0;
    std::optional<std::uint32_t> artifact_index;
    std::optional<std::uint32_t> method_index;
    decompiler_entity_key_t entity;
};

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
build_managed_artifact_publication(
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    const std::shared_ptr<const pe_image_t>& pe_image,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    const readers::managed::managed_reader_limits_t& limits = {},
    const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
rebind_managed_artifact_publication(
    const managed_artifact_publication_t& source,
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    const std::shared_ptr<const pe_image_t>& pe_image,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision,
    const cancellation_token_t& cancel = {});

workspace_result_t<generation_bound_decompiler_entity_t>
resolve_generation_bound_entity(
    const workspace_identity_t& identity,
    const analysis_publication_t& publication,
    const decompiler_entity_locator_t& locator,
    const cancellation_token_t& cancel = {});

workspace_result_t<void> validate_generation_bound_entity(
    const workspace_identity_t& identity,
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const std::vector<std::uint8_t>>>
capture_managed_artifact_snapshot(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    std::uint64_t maximum_bytes,
    const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const jvm_ssa::jvm_method_input_t>>
capture_jvm_entity_input(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    const decompiler_provider_identity_t& provider,
    const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const dalvik_ssa::dalvik_ssa_capture_t>>
capture_dalvik_entity_input(
    const analysis_publication_t& publication,
    const generation_bound_decompiler_entity_t& binding,
    const decompiler_provider_identity_t& provider,
    const cancellation_token_t& cancel = {});

}
