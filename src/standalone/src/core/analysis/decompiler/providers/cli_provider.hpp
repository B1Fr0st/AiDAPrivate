#pragma once

#include "../decompiler_contracts.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::managed_cli {

constexpr std::uint32_t k_managed_cli_worker_protocol_version = 3;
constexpr std::size_t k_managed_cli_maximum_module_bytes = 256U * 1024U * 1024U;

enum class module_source_kind_t : std::uint8_t {
    regular_file = 1,
    embedded_member = 2
};

struct module_source_t {
    module_source_kind_t kind = module_source_kind_t::regular_file;
    std::string logical_identity;
    std::string filesystem_path;
    sha256_digest_t module_hash;
    std::uint64_t module_size = 0;
};

struct immutable_module_snapshot_t {
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
    sha256_digest_t hash;

    bool valid() const noexcept {
        return bytes && !bytes->empty() &&
            bytes->size() <= k_managed_cli_maximum_module_bytes && !hash.empty();
    }
};

struct worker_identity_t {
    std::string provider_version;
    sha256_digest_t decompiler_assembly_hash;
    std::string worker_build_id;
    sha256_digest_t worker_build_hash;
    sha256_digest_t runtime_manifest_hash;
};

struct request_t {
    std::uint64_t sequence = 0;
    std::string request_id;
    module_source_t module_source;
    std::shared_ptr<const std::vector<std::uint8_t>> module_snapshot;
    decompiler_entity_key_t entity;
    sha256_digest_t entity_hash;
    std::uint64_t workspace_generation = 0;
    std::uint64_t type_graph_revision = 0;
    decompiler_profile_budget_t profile;
    worker_identity_t worker;
    sha256_digest_t contract_hash;
    sha256_digest_t cache_identity;
    sha256_digest_t request_binding_hash;
};

struct token_map_entry_t {
    std::uint32_t metadata_token = 0;
    std::string stable_identity;
    std::string declaring_type;
    std::string method_name;
    std::string method_signature;
    std::uint32_t generic_arity = 0;
    bool is_async = false;
    bool is_iterator = false;
    bool has_exception_regions = false;
};

struct analysis_t {
    provider_ir_t provider_ir;
    type_graph_t type_graph;
    std::uint64_t return_type_id = 0;
    std::string decompiled_source;
    sha256_digest_t decompiled_source_hash;
    std::vector<token_map_entry_t> token_map;
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct failure_t {
    std::vector<decompiler_diagnostic_t> diagnostics;
};

struct response_t {
    std::optional<analysis_t> analysis;
    std::optional<failure_t> failure;
};

workspace_result_t<request_t> make_request(std::uint64_t sequence,
                                           std::string request_id,
                                           std::string module_path,
                                           decompiler_entity_key_t entity,
                                           std::uint64_t workspace_generation,
                                           std::uint64_t type_graph_revision,
                                           decompiler_profile_budget_t profile,
                                           worker_identity_t worker,
                                           const cancellation_token_t& cancel = {});
workspace_result_t<request_t> make_embedded_request(
    std::uint64_t sequence,
    std::string request_id,
    std::string logical_identity,
    std::vector<std::uint8_t> module_bytes,
    decompiler_entity_key_t entity,
    std::uint64_t workspace_generation,
    std::uint64_t type_graph_revision,
    decompiler_profile_budget_t profile,
    worker_identity_t worker,
    const cancellation_token_t& cancel = {});
workspace_result_t<request_t> make_embedded_request(
    std::uint64_t sequence,
    std::string request_id,
    std::string logical_identity,
    immutable_module_snapshot_t module_snapshot,
    decompiler_entity_key_t entity,
    std::uint64_t workspace_generation,
    std::uint64_t type_graph_revision,
    decompiler_profile_budget_t profile,
    worker_identity_t worker,
    const cancellation_token_t& cancel = {});
workspace_result_t<immutable_module_snapshot_t> make_immutable_module_snapshot(
    std::vector<std::uint8_t> module_bytes,
    const cancellation_token_t& cancel = {});
workspace_result_t<request_t> bind_module_snapshot(
    const request_t& request,
    std::vector<std::uint8_t> module_bytes,
    const cancellation_token_t& cancel = {});
sha256_digest_t managed_cli_contract_hash();
workspace_result_t<std::string> serialize_request(const request_t& request);
workspace_result_t<std::string> serialize_cancellation(const request_t& request,
                                                        std::uint64_t sequence,
                                                        std::string stable_reason);
workspace_result_t<response_t> deserialize_response(const request_t& request,
                                                     const std::string& payload,
                                                     const cancellation_token_t& cancel = {});

}
