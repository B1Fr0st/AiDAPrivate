#include "member_graph.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace aida::analysis {

namespace {

workspace_error_t graph_error(workspace_error_code_t code, std::string message,
                              const char* phase) {
    return make_workspace_error(code, std::move(message), phase);
}

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase) {
    if (cancel.deadline_exceeded()) {
        auto error = graph_error(workspace_error_code_t::deadline_exceeded,
                                 "graph traversal deadline exceeded", phase);
        error.deadline = true;
        return error;
    }
    auto error = graph_error(workspace_error_code_t::cancelled,
                            "graph traversal cancelled", phase);
    error.cancellation = true;
    return error;
}

std::string build_full_path(const std::vector<collection_provenance_link_t>& provenance,
                            std::string_view member_path) {
    std::string result;
    for (const auto& link : provenance) {
        if (!link.normalized_path.empty()) {
            if (!result.empty())
                result += '/';
            result += link.normalized_path;
        }
    }
    if (!member_path.empty()) {
        if (!result.empty())
            result += '/';
        result += member_path;
    }
    return result;
}

std::string display_name_from_path(std::string_view path) noexcept {
    auto slash_pos = path.rfind('/');
    if (slash_pos == std::string_view::npos)
        return std::string(path);
    return std::string(path.substr(slash_pos + 1));
}

}

struct member_graph_t::state_t {
    member_graph_limits_t limits;
    std::vector<member_node_t> nodes;
    std::vector<member_edge_t> edges;
    std::unordered_map<std::uint64_t, std::vector<std::uint64_t>> children_map;
    std::unordered_map<std::string, std::uint64_t> path_index;
    std::unordered_map<sha256_digest_t, std::vector<std::uint64_t>, binary_id_hash_t> hash_index;
    std::unordered_map<std::string, std::vector<std::uint64_t>> name_index;
    std::unordered_set<std::uint64_t> locked_nodes;
    std::atomic<std::uint64_t> next_node_id{1};
    std::uint32_t max_depth_observed = 0;
    bool cycle_detected = false;
    mutable std::shared_mutex mutex;

    explicit state_t(member_graph_limits_t lim) : limits(std::move(lim)) {}

    member_node_id_t allocate_node() {
        member_node_id_t id;
        id.value = next_node_id.fetch_add(1, std::memory_order_acq_rel);
        return id;
    }

    bool would_create_cycle(std::uint64_t child_id, std::uint64_t parent_id) const {
        if (!limits.detect_cycles)
            return false;
        if (child_id == parent_id)
            return true;
        std::uint64_t current = parent_id;
        std::unordered_set<std::uint64_t> visited;
        while (current != 0) {
            if (current == child_id)
                return true;
            if (!visited.insert(current).second)
                return true;
            if (current >= nodes.size())
                break;
            current = nodes[current - 1].parent_id.value;
        }
        return false;
    }

    void rebuild_indices() {
        children_map.clear();
        path_index.clear();
        hash_index.clear();
        name_index.clear();
        max_depth_observed = 0;
        for (std::size_t i = 0; i < nodes.size(); ++i) {
            const auto& node = nodes[i];
            const std::uint64_t id_value = static_cast<std::uint64_t>(i + 1);
            if (node.parent_id.valid())
                children_map[node.parent_id.value].push_back(id_value);
            if (!node.normalized_path.empty()) {
                std::string full_path = node.normalized_path;
                if (path_index.find(full_path) == path_index.end())
                    path_index[full_path] = id_value;
            }
            if (node.content_hash.has_value())
                hash_index[*node.content_hash].push_back(id_value);
            name_index[node.display_name].push_back(id_value);
            if (node.depth > max_depth_observed)
                max_depth_observed = node.depth;
        }
    }
};

member_graph_t::member_graph_t()
    : state_(std::make_unique<state_t>(member_graph_limits_t{})) {}

member_graph_t::member_graph_t(member_graph_limits_t limits)
    : state_(std::make_unique<state_t>(std::move(limits))) {}

member_graph_t::~member_graph_t() = default;

workspace_result_t<member_node_id_t>
member_graph_t::register_root(collection_kind_t kind,
                              const byte_provider_identity_t& identity,
                              const std::vector<collection_provenance_link_t>& provenance) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    if (state_->nodes.size() >= state_->limits.max_nodes)
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::limit_exceeded,
                       "graph node count exceeds maximum",
                       "member_graph"));
    auto id = state_->allocate_node();
    member_node_t node;
    node.id = id;
    node.parent_id = {};
    node.kind = member_node_kind_t::root_collection;
    node.collection_kind = kind;
    node.normalized_path = identity.normalized_source;
    node.display_name = display_name_from_path(identity.normalized_source);
    node.uncompressed_size = identity.size;
    node.depth = 0;
    node.provenance_chain = provenance;
    state_->nodes.push_back(std::move(node));
    state_->rebuild_indices();
    return workspace_result_t<member_node_id_t>::success(id);
}

workspace_result_t<member_node_id_t>
member_graph_t::register_child(member_node_id_t parent_id,
                               const collection_member_descriptor_t& descriptor,
                               bool is_collection) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    if (!parent_id.valid() || parent_id.value > state_->nodes.size())
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::target_not_found,
                       "parent node not found in graph",
                       "member_graph"));
    if (state_->nodes.size() >= state_->limits.max_nodes)
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::limit_exceeded,
                       "graph node count exceeds maximum",
                       "member_graph"));
    if (state_->edges.size() >= state_->limits.max_edges)
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::limit_exceeded,
                       "graph edge count exceeds maximum",
                       "member_graph"));

    const auto& parent = state_->nodes[parent_id.value - 1];
    const std::uint32_t child_depth = parent.depth + 1;
    if (child_depth > state_->limits.max_depth)
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::limit_exceeded,
                       "graph depth exceeds maximum",
                       "member_graph"));

    auto id = state_->allocate_node();
    if (state_->would_create_cycle(id.value, parent_id.value)) {
        state_->cycle_detected = true;
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::target_conflict,
                       "registering child would create a cycle",
                       "member_graph"));
    }

    member_node_t node;
    node.id = id;
    node.parent_id = parent_id;
    node.kind = is_collection ? member_node_kind_t::child_collection
                              : member_node_kind_t::leaf_member;
    node.collection_kind = parent.collection_kind;
    node.member_kind = descriptor.member_kind;
    node.normalized_path = build_full_path(descriptor.provenance_chain,
                                           descriptor.normalized_path);
    node.display_name = descriptor.display_name;
    node.format = descriptor.format;
    node.architecture = descriptor.architecture;
    node.ordinal = descriptor.ordinal;
    node.container_offset = descriptor.container_offset;
    node.uncompressed_size = descriptor.uncompressed_size;
    node.crc32 = descriptor.crc32;
    node.depth = child_depth;
    node.content_hash = descriptor.content_hash;
    node.provenance_chain = descriptor.provenance_chain;
    node.companion_debug_path = descriptor.companion_debug_path;
    node.companion_binary_path = descriptor.companion_binary_path;

    member_edge_t edge;
    edge.parent_id = parent_id;
    edge.child_id = id;
    edge.edge_path = descriptor.normalized_path;
    edge.container_offset = descriptor.container_offset;
    edge.child_size = descriptor.uncompressed_size;
    edge.depth = child_depth;

    state_->nodes.push_back(std::move(node));
    state_->edges.push_back(std::move(edge));
    state_->rebuild_indices();
    return workspace_result_t<member_node_id_t>::success(id);
}

workspace_result_t<member_node_id_t>
member_graph_t::register_companion(member_node_id_t parent_id,
                                   const collection_member_descriptor_t& descriptor,
                                   bool is_debug_companion) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    if (!parent_id.valid() || parent_id.value > state_->nodes.size())
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::target_not_found,
                       "parent node not found in graph",
                       "member_graph"));
    if (state_->nodes.size() >= state_->limits.max_nodes)
        return workspace_result_t<member_node_id_t>::failure(
            graph_error(workspace_error_code_t::limit_exceeded,
                       "graph node count exceeds maximum",
                       "member_graph"));

    const auto& parent = state_->nodes[parent_id.value - 1];
    const std::uint32_t child_depth = parent.depth + 1;

    auto id = state_->allocate_node();

    member_node_t node;
    node.id = id;
    node.parent_id = parent_id;
    node.kind = is_debug_companion ? member_node_kind_t::companion_debug
                                   : member_node_kind_t::leaf_member;
    node.collection_kind = parent.collection_kind;
    node.member_kind = descriptor.member_kind;
    node.normalized_path = build_full_path(descriptor.provenance_chain,
                                           descriptor.normalized_path);
    node.display_name = descriptor.display_name;
    node.format = descriptor.format;
    node.architecture = descriptor.architecture;
    node.ordinal = descriptor.ordinal;
    node.container_offset = descriptor.container_offset;
    node.uncompressed_size = descriptor.uncompressed_size;
    node.crc32 = descriptor.crc32;
    node.depth = child_depth;
    node.content_hash = descriptor.content_hash;
    node.provenance_chain = descriptor.provenance_chain;
    node.companion_debug_path = descriptor.companion_debug_path;
    node.companion_binary_path = descriptor.companion_binary_path;

    member_edge_t edge;
    edge.parent_id = parent_id;
    edge.child_id = id;
    edge.edge_path = descriptor.normalized_path;
    edge.container_offset = descriptor.container_offset;
    edge.child_size = descriptor.uncompressed_size;
    edge.depth = child_depth;

    state_->nodes.push_back(std::move(node));
    state_->edges.push_back(std::move(edge));
    state_->rebuild_indices();
    return workspace_result_t<member_node_id_t>::success(id);
}

workspace_result_t<void>
member_graph_t::link_companion(member_node_id_t binary_id, member_node_id_t debug_id) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    if (!binary_id.valid() || binary_id.value > state_->nodes.size() ||
        !debug_id.valid() || debug_id.value > state_->nodes.size())
        return workspace_result_t<void>::failure(
            graph_error(workspace_error_code_t::target_not_found,
                       "companion link target not found",
                       "member_graph"));
    auto& binary_node = state_->nodes[binary_id.value - 1];
    auto& debug_node = state_->nodes[debug_id.value - 1];
    binary_node.companion_debug_path = debug_node.normalized_path;
    debug_node.companion_binary_path = binary_node.normalized_path;
    return workspace_result_t<void>::success();
}

const member_node_t* member_graph_t::node(member_node_id_t id) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    if (!id.valid() || id.value > state_->nodes.size())
        return nullptr;
    return &state_->nodes[id.value - 1];
}

std::vector<member_node_id_t>
member_graph_t::children(member_node_id_t parent_id) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<member_node_id_t> result;
    auto it = state_->children_map.find(parent_id.value);
    if (it != state_->children_map.end()) {
        for (auto child_value : it->second) {
            member_node_id_t child_id;
            child_id.value = child_value;
            result.push_back(child_id);
        }
    }
    return result;
}

std::vector<member_node_id_t>
member_graph_t::children_by_name(member_node_id_t parent_id,
                                  std::string_view name) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<member_node_id_t> result;
    auto it = state_->children_map.find(parent_id.value);
    if (it != state_->children_map.end()) {
        for (auto child_value : it->second) {
            if (child_value <= state_->nodes.size()) {
                const auto& child = state_->nodes[child_value - 1];
                if (child.display_name == name) {
                    member_node_id_t child_id;
                    child_id.value = child_value;
                    result.push_back(child_id);
                }
            }
        }
    }
    return result;
}

const member_node_t*
member_graph_t::find_by_path(std::string_view full_path) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    auto it = state_->path_index.find(std::string(full_path));
    if (it == state_->path_index.end())
        return nullptr;
    if (it->second > state_->nodes.size())
        return nullptr;
    return &state_->nodes[it->second - 1];
}

std::vector<const member_node_t*>
member_graph_t::find_by_hash(const sha256_digest_t& hash) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<const member_node_t*> result;
    auto it = state_->hash_index.find(hash);
    if (it != state_->hash_index.end()) {
        for (auto node_value : it->second) {
            if (node_value <= state_->nodes.size())
                result.push_back(&state_->nodes[node_value - 1]);
        }
    }
    return result;
}

std::vector<member_node_id_t>
member_graph_t::path_to_root(member_node_id_t id) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<member_node_id_t> result;
    std::uint64_t current = id.value;
    std::unordered_set<std::uint64_t> visited;
    while (current != 0 && current <= state_->nodes.size()) {
        if (!visited.insert(current).second)
            break;
        member_node_id_t node_id;
        node_id.value = current;
        result.push_back(node_id);
        current = state_->nodes[current - 1].parent_id.value;
    }
    std::reverse(result.begin(), result.end());
    return result;
}

std::vector<member_node_id_t>
member_graph_t::descendants(member_node_id_t id) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<member_node_id_t> result;
    std::vector<std::uint64_t> stack;
    stack.push_back(id.value);
    std::unordered_set<std::uint64_t> visited;
    while (!stack.empty()) {
        auto current = stack.back();
        stack.pop_back();
        if (!visited.insert(current).second)
            continue;
        member_node_id_t node_id;
        node_id.value = current;
        result.push_back(node_id);
        auto it = state_->children_map.find(current);
        if (it != state_->children_map.end()) {
            for (auto child : it->second)
                stack.push_back(child);
        }
    }
    return result;
}

std::vector<member_node_id_t>
member_graph_t::all_nodes() const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<member_node_id_t> result;
    result.reserve(state_->nodes.size());
    for (std::size_t i = 0; i < state_->nodes.size(); ++i) {
        member_node_id_t id;
        id.value = static_cast<std::uint64_t>(i + 1);
        result.push_back(id);
    }
    return result;
}

std::vector<std::string>
member_graph_t::duplicate_names() const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<std::string> result;
    for (const auto& [name, indices] : state_->name_index) {
        if (indices.size() > 1)
            result.push_back(name);
    }
    return result;
}

std::vector<const member_node_t*>
member_graph_t::nodes_with_name(std::string_view name) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    std::vector<const member_node_t*> result;
    auto it = state_->name_index.find(std::string(name));
    if (it != state_->name_index.end()) {
        for (auto node_value : it->second) {
            if (node_value <= state_->nodes.size())
                result.push_back(&state_->nodes[node_value - 1]);
        }
    }
    return result;
}

std::size_t member_graph_t::node_count() const noexcept {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    return state_->nodes.size();
}

std::size_t member_graph_t::edge_count() const noexcept {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    return state_->edges.size();
}

std::uint32_t member_graph_t::max_depth() const noexcept {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    return state_->max_depth_observed;
}

bool member_graph_t::has_cycle() const noexcept {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    return state_->cycle_detected;
}

bool member_graph_t::acquire_child_lock(member_node_id_t id) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    return state_->locked_nodes.insert(id.value).second;
}

void member_graph_t::release_child_lock(member_node_id_t id) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    state_->locked_nodes.erase(id.value);
}

std::size_t member_graph_t::active_locks() const noexcept {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    return state_->locked_nodes.size();
}

workspace_result_t<void>
member_graph_t::traverse(member_node_id_t start,
                         const std::function<workspace_result_t<void>(const member_node_t&)>& visitor,
                         const cancellation_token_t& cancel) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    if (!start.valid() || start.value > state_->nodes.size())
        return workspace_result_t<void>::failure(
            graph_error(workspace_error_code_t::target_not_found,
                       "traversal start node not found",
                       "member_graph"));
    std::vector<std::uint64_t> stack;
    stack.push_back(start.value);
    std::unordered_set<std::uint64_t> visited;
    std::uint32_t visit_count = 0;
    while (!stack.empty()) {
        if ((++visit_count & 255u) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(stop_error(cancel, "member_graph"));
        auto current = stack.back();
        stack.pop_back();
        if (!visited.insert(current).second)
            continue;
        if (current > state_->nodes.size())
            continue;
        const auto& node = state_->nodes[current - 1];
        auto result = visitor(node);
        if (!result)
            return result;
        auto it = state_->children_map.find(current);
        if (it != state_->children_map.end()) {
            for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit)
                stack.push_back(*rit);
        }
    }
    return workspace_result_t<void>::success();
}

void member_graph_t::mark_opened(member_node_id_t id) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    if (id.valid() && id.value <= state_->nodes.size())
        state_->nodes[id.value - 1].opened = true;
}

void member_graph_t::mark_hash_verified(member_node_id_t id, sha256_digest_t hash) {
    std::unique_lock<std::shared_mutex> lock(state_->mutex);
    if (id.valid() && id.value <= state_->nodes.size()) {
        auto& node = state_->nodes[id.value - 1];
        node.content_hash = hash;
        node.hash_verified = true;
        state_->hash_index[hash].push_back(id.value);
    }
}

std::vector<collection_provenance_link_t>
member_graph_t::provenance_chain(member_node_id_t id) const {
    std::shared_lock<std::shared_mutex> lock(state_->mutex);
    if (!id.valid() || id.value > state_->nodes.size())
        return {};
    return state_->nodes[id.value - 1].provenance_chain;
}

const member_graph_limits_t& member_graph_t::limits() const noexcept {
    return state_->limits;
}

}
