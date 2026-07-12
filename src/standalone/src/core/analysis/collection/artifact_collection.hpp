#pragma once

#include "../workspace/byte_provider.hpp"
#include "../workspace/workspace_types.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aida::analysis {

class member_graph_t;

enum class collection_kind_t : std::uint8_t {
    unknown = 0,
    zip_archive = 1,
    apk = 2,
    aab = 3,
    ipa = 4,
    jar = 5,
    fat_macho = 6,
    multi_binary_project = 7,
    companion_debug = 8,
    standalone_binary = 9
};

enum class collection_member_kind_t : std::uint8_t {
    unknown = 0,
    binary = 1,
    dex = 2,
    classfile = 3,
    native_library = 4,
    nested_archive = 5,
    debug_companion = 6,
    resource = 7,
    manifest = 8,
    fat_slice = 9
};

struct collection_provenance_link_t {
    std::string normalized_path;
    collection_kind_t kind = collection_kind_t::unknown;
    std::uint64_t container_offset = 0;
    std::uint64_t member_size = 0;
    std::uint32_t depth = 0;

    bool operator==(const collection_provenance_link_t& other) const noexcept {
        return normalized_path == other.normalized_path && kind == other.kind &&
            container_offset == other.container_offset && member_size == other.member_size &&
            depth == other.depth;
    }

    bool operator!=(const collection_provenance_link_t& other) const noexcept {
        return !(*this == other);
    }
};

struct collection_member_descriptor_t {
    std::string normalized_path;
    std::string display_name;
    collection_member_kind_t member_kind = collection_member_kind_t::unknown;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    abi_id_t abi = abi_id_t::unknown;
    std::uint64_t ordinal = 0;
    std::uint64_t container_offset = 0;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t depth = 0;
    bool compressed = false;
    bool is_nested_collection = false;
    std::optional<sha256_digest_t> content_hash;
    std::vector<collection_provenance_link_t> provenance_chain;
    provider_member_metadata_t provider_metadata;
    std::vector<std::string> duplicate_path_siblings;
    std::optional<std::string> companion_debug_path;
    std::optional<std::string> companion_binary_path;
};

struct collection_open_limits_t {
    std::uint32_t max_nesting_depth = 32;
    std::uint64_t max_member_count = 1000000;
    std::uint64_t max_collection_size = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_member_uncompressed_size = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_aggregate_uncompressed_size = 16ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_probe_bytes = 4ULL * 1024ULL * 1024ULL;
    std::chrono::milliseconds max_elapsed{60000};
    bool enable_companion_detection = true;
    bool enable_duplicate_name_tracking = true;
};

class artifact_collection_t final {
public:
    static workspace_result_t<std::shared_ptr<artifact_collection_t>>
        open(std::shared_ptr<const byte_provider_t> provider,
             collection_open_limits_t limits = {},
             const cancellation_token_t& cancel = {},
             std::shared_ptr<member_graph_t> graph = {},
             std::vector<collection_provenance_link_t> parent_provenance = {},
             std::uint64_t parent_graph_node = 0);

    ~artifact_collection_t();
    artifact_collection_t(const artifact_collection_t&) = delete;
    artifact_collection_t& operator=(const artifact_collection_t&) = delete;

    const byte_provider_identity_t& source_identity() const noexcept;
    const std::shared_ptr<const byte_provider_t>& source_provider() const noexcept;
    collection_kind_t kind() const noexcept;
    const collection_open_limits_t& limits() const noexcept;
    const std::vector<collection_member_descriptor_t>& members() const noexcept;
    const collection_member_descriptor_t* find_member(std::string_view normalized_path) const;
    const collection_member_descriptor_t* find_member_by_ordinal(std::uint64_t ordinal) const;
    std::size_t member_count() const noexcept;
    std::uint32_t depth() const noexcept;
    const std::vector<collection_provenance_link_t>& provenance() const noexcept;
    const std::shared_ptr<member_graph_t>& graph() const noexcept;
    std::uint64_t graph_node() const noexcept;

    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member(std::size_t member_index,
                    const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_member(std::string_view normalized_path,
                    const cancellation_token_t& cancel = {}) const;

    workspace_result_t<std::shared_ptr<artifact_collection_t>>
        open_child_collection(std::size_t member_index,
                              const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<artifact_collection_t>>
        open_child_collection(std::string_view normalized_path,
                              const cancellation_token_t& cancel = {}) const;

    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_companion_debug(std::size_t member_index,
                             const cancellation_token_t& cancel = {}) const;
    workspace_result_t<std::shared_ptr<byte_provider_t>>
        open_companion_binary(std::size_t member_index,
                              const cancellation_token_t& cancel = {}) const;

    workspace_result_t<void>
        verify_integrity(const cancellation_token_t& cancel = {}) const;
    bool integrity_verified() const noexcept;

    workspace_result_t<sha256_digest_t>
        compute_member_hash(std::size_t member_index,
                            const cancellation_token_t& cancel = {}) const;

    std::vector<std::string> duplicate_member_names() const;
    std::vector<const collection_member_descriptor_t*>
        members_with_name(std::string_view name) const;

    std::size_t active_child_count() const noexcept;
    bool has_unopened_members() const noexcept;

private:
    struct state_t;
    explicit artifact_collection_t(std::shared_ptr<state_t> state);
    std::shared_ptr<state_t> state_;
};

collection_kind_t detect_collection_kind(const byte_provider_t& provider,
                                         const cancellation_token_t& cancel = {});
std::string_view collection_kind_name(collection_kind_t kind) noexcept;
std::string_view collection_member_kind_name(collection_member_kind_t kind) noexcept;
format_id_t collection_kind_to_format_hint(collection_kind_t kind) noexcept;
bool collection_kind_is_zip_based(collection_kind_t kind) noexcept;
bool collection_kind_is_container(collection_kind_t kind) noexcept;
bool member_descriptor_is_nested_archive_candidate(const collection_member_descriptor_t& descriptor) noexcept;

}
