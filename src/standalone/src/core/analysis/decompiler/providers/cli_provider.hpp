#pragma once

#include "../decompiler_contracts.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis::managed_cli {

constexpr std::uint32_t k_managed_cli_worker_protocol_version = 1;

struct offline_package_t {
    std::string id;
    std::string version;
    std::string file_name;
    sha256_digest_t content_hash;
};

struct offline_lock_t {
    std::string package_root;
    std::string sdk_path;
    sha256_digest_t sdk_hash;
    std::vector<offline_package_t> packages;
};

struct worker_identity_t {
    std::string provider_version;
    sha256_digest_t decompiler_assembly_hash;
    std::string worker_build_id;
    sha256_digest_t worker_build_hash;
};

struct request_t {
    std::uint64_t sequence = 0;
    std::string request_id;
    std::string module_path;
    decompiler_entity_key_t entity;
    std::uint64_t workspace_generation = 0;
    decompiler_profile_budget_t profile;
    worker_identity_t worker;
    offline_lock_t offline_lock;
    sha256_digest_t offline_lock_hash;
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

workspace_result_t<sha256_digest_t> verify_offline_lock(const offline_lock_t& lock,
                                                        const cancellation_token_t& cancel = {});
workspace_result_t<request_t> make_request(std::uint64_t sequence,
                                           std::string request_id,
                                           std::string module_path,
                                           decompiler_entity_key_t entity,
                                           std::uint64_t workspace_generation,
                                           decompiler_profile_budget_t profile,
                                           worker_identity_t worker,
                                           offline_lock_t offline_lock,
                                           const cancellation_token_t& cancel = {});
workspace_result_t<std::vector<std::string>> make_worker_startup_arguments(
    const request_t& request,
    const cancellation_token_t& cancel = {});
workspace_result_t<std::string> serialize_request(const request_t& request);
workspace_result_t<std::string> serialize_cancellation(const request_t& request,
                                                        std::uint64_t sequence,
                                                        std::string stable_reason);
workspace_result_t<response_t> deserialize_response(const request_t& request,
                                                     const std::string& payload,
                                                     const cancellation_token_t& cancel = {});

}
