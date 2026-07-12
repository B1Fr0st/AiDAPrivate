#pragma once

#include "artifact_collection.hpp"

#include "../workspace/workspace_types.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace aida::analysis {

struct member_graph_limits_t {
    std::uint32_t max_depth = 64;
    std::uint64_t max_nodes = 1000000;
    std::uint64_t max_edges = 4000000;
    bool detect_cycles = true;
};

struct member_node_id_t {
    std::uint64_t value = 0;
    bool valid() const noexcept { return value != 0; }
    bool operator==(const member_node_id_t& other) const noexcept { return value == other.value; }
    bool operator!=(const member_node_id_t& other) const noexcept { return value != other.value; }
};

struct member_node_id_hash_t {
    std::size_t operator()(const member_node_id_t& id) const noexcept {
        return std::hash<std::uint64_t>{}(id.value);
    }
};

enum class member_node_kind_t : std::uint8_t {
    root_collection = 0,
    child_collection = 1,
    leaf_member = 2,
    companion_debug = 3
};

struct member_node_t {
    member_node_id_t id;
    member_node_id_t parent_id;
    member_node_kind_t kind = member_node_kind_t::leaf_member;
    collection_kind_t collection_kind = collection_kind_t::unknown;
    collection_member_kind_t member_kind = collection_member_kind_t::unknown;
    std::string normalized_path;
    std::string display_name;
    format_id_t format = format_id_t::unknown;
    architecture_id_t architecture = architecture_id_t::unknown;
    std::uint64_t ordinal = 0;
    std::uint64_t container_offset = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    std::uint32_t depth = 0;
    std::optional<sha256_digest_t> content_hash;
    std::vector<collection_provenance_link_t> provenance_chain;
    std::optional<std::string> companion_debug_path;
    std::optional<std::string> companion_binary_path;
    bool opened = false;
    bool hash_verified = false;
};

struct member_edge_t {
    member_node_id_t parent_id;
    member_node_id_t child_id;
    std::string edge_path;
    std::uint64_t container_offset = 0;
    std::uint64_t child_size = 0;
    std::uint32_t depth = 0;
};

class member_graph_t final {
public:
    member_graph_t();
    explicit member_graph_t(member_graph_limits_t limits);
    ~member_graph_t();
    member_graph_t(const member_graph_t&) = delete;
    member_graph_t& operator=(const member_graph_t&) = delete;

    workspace_result_t<member_node_id_t>
        register_root(collection_kind_t kind,
                      const byte_provider_identity_t& identity,
                      const std::vector<collection_provenance_link_t>& provenance);

    workspace_result_t<member_node_id_t>
        register_child(member_node_id_t parent_id,
                       const collection_member_descriptor_t& descriptor,
                       bool is_collection);

    workspace_result_t<member_node_id_t>
        register_companion(member_node_id_t parent_id,
                           const collection_member_descriptor_t& descriptor,
                           bool is_debug_companion);

    workspace_result_t<void>
        link_companion(member_node_id_t binary_id, member_node_id_t debug_id);

    const member_node_t* node(member_node_id_t id) const;
    std::vector<member_node_id_t> children(member_node_id_t parent_id) const;
    std::vector<member_node_id_t> children_by_name(member_node_id_t parent_id,
                                                    std::string_view name) const;
    const member_node_t* find_by_path(std::string_view full_path) const;
    std::vector<const member_node_t*> find_by_hash(const sha256_digest_t& hash) const;
    std::vector<member_node_id_t> path_to_root(member_node_id_t id) const;
    std::vector<member_node_id_t> descendants(member_node_id_t id) const;
    std::vector<member_node_id_t> all_nodes() const;

    std::vector<std::string> duplicate_names() const;
    std::vector<const member_node_t*> nodes_with_name(std::string_view name) const;

    std::size_t node_count() const noexcept;
    std::size_t edge_count() const noexcept;
    std::uint32_t max_depth() const noexcept;
    bool has_cycle() const noexcept;

    bool acquire_child_lock(member_node_id_t id);
    void release_child_lock(member_node_id_t id);
    std::size_t active_locks() const noexcept;

    workspace_result_t<void>
        traverse(member_node_id_t start,
                 const std::function<workspace_result_t<void>(const member_node_t&)>& visitor,
                 const cancellation_token_t& cancel = {}) const;

    void mark_opened(member_node_id_t id);
    void mark_hash_verified(member_node_id_t id, sha256_digest_t hash);

    std::vector<collection_provenance_link_t>
        provenance_chain(member_node_id_t id) const;

    const member_graph_limits_t& limits() const noexcept;

private:
    struct state_t;
    std::unique_ptr<state_t> state_;
};

}
