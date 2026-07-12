#include "workbench_contracts.h"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida {
namespace workbench {
namespace {

constexpr std::uint32_t k_min_left_rail_pixels = 40;
constexpr std::uint32_t k_max_left_rail_pixels = 96;
constexpr std::uint32_t k_min_navigator_pixels = 160;
constexpr std::uint32_t k_max_navigator_pixels = 720;
constexpr std::uint32_t k_min_inspector_pixels = 200;
constexpr std::uint32_t k_max_inspector_pixels = 720;
constexpr std::uint32_t k_min_bottom_panel_pixels = 120;
constexpr std::uint32_t k_max_bottom_panel_pixels = 560;
constexpr std::uint32_t k_min_tab_strip_pixels = 24;
constexpr std::uint32_t k_max_tab_strip_pixels = 64;
constexpr std::uint32_t k_min_toolbar_pixels = 24;
constexpr std::uint32_t k_max_toolbar_pixels = 64;
constexpr std::uint32_t k_min_splitter_pixels = 2;
constexpr std::uint32_t k_max_splitter_pixels = 12;
constexpr std::uint32_t k_min_document_width_pixels = 320;
constexpr std::uint32_t k_max_document_width_pixels = 4096;
constexpr std::uint32_t k_min_document_height_pixels = 200;
constexpr std::uint32_t k_max_document_height_pixels = 4096;
constexpr std::uint64_t k_fnv_offset_basis = 14695981039346656037ULL;
constexpr std::uint64_t k_fnv_prime = 1099511628211ULL;

workbench_error_t error(workbench_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

bool valid_document_kind(document_kind_t kind) noexcept
{
    return kind >= document_kind_t::binary && kind <= document_kind_t::diff;
}

bool valid_view_role(view_role_t role) noexcept
{
    return role <= view_role_t::transient;
}

bool valid_selection_kind(selection_kind_t kind) noexcept
{
    return kind <= selection_kind_t::source;
}

bool valid_synchronization_policy(view_synchronization_policy_t policy) noexcept
{
    return policy <= view_synchronization_policy_t::cursor_and_selection;
}

bool synchronization_policy_matches(view_synchronization_policy_t policy,
                                    std::uint64_t group) noexcept
{
    if (!valid_synchronization_policy(policy))
        return false;
    return policy == view_synchronization_policy_t::independent ? group == 0 : group != 0;
}

bool valid_navigation_origin(navigation_origin_t origin) noexcept
{
    return origin <= navigation_origin_t::mcp;
}

bool valid_split_node_kind(split_node_kind_t kind) noexcept
{
    return kind <= split_node_kind_t::branch;
}

bool valid_split_orientation(split_orientation_t orientation) noexcept
{
    return orientation <= split_orientation_t::vertical;
}

bool valid_panel_kind(panel_kind_t kind) noexcept
{
    return kind <= panel_kind_t::custom;
}

std::uint32_t clamp_dimension(std::uint32_t value, std::uint32_t minimum,
                              std::uint32_t maximum) noexcept
{
    return value < minimum ? minimum : (value > maximum ? maximum : value);
}

std::uint16_t clamp_ratio(std::uint16_t value) noexcept
{
    return value < k_split_ratio_min_basis_points ? k_split_ratio_min_basis_points :
        (value > k_split_ratio_max_basis_points ? k_split_ratio_max_basis_points : value);
}

bool navigation_event_equal(const navigation_event_t& lhs, const navigation_event_t& rhs)
{
    return lhs.id == rhs.id && lhs.workspace == rhs.workspace && lhs.has_source == rhs.has_source &&
           lhs.source.workspace == rhs.source.workspace && lhs.source.document == rhs.source.document &&
           lhs.source.view == rhs.source.view &&
           selection_context_equal(lhs.source.selection, rhs.source.selection) &&
           document_local_cursor_equal(lhs.source.cursor, rhs.source.cursor) &&
           lhs.source.synchronization_group == rhs.source.synchronization_group &&
           lhs.source.synchronization_policy == rhs.source.synchronization_policy &&
           document_identity_equal(lhs.target.document, rhs.target.document) &&
           selection_context_equal(lhs.target.selection, rhs.target.selection) &&
           document_local_cursor_equal(lhs.target.cursor, rhs.target.cursor) &&
           lhs.origin == rhs.origin && lhs.sequence == rhs.sequence &&
           lhs.request_focus == rhs.request_focus;
}

bool document_dto_equal(const document_persistence_dto_t& lhs,
                        const document_persistence_dto_t& rhs)
{
    return lhs.id == rhs.id && document_identity_equal(lhs.identity, rhs.identity) &&
           lhs.title == rhs.title && lhs.state_token == rhs.state_token &&
           document_local_state_equal(lhs.local_state, rhs.local_state) &&
           lhs.pinned == rhs.pinned && lhs.closeable == rhs.closeable;
}

bool view_dto_equal(const view_persistence_dto_t& lhs, const view_persistence_dto_t& rhs) noexcept
{
    return lhs.id == rhs.id && lhs.workspace == rhs.workspace && lhs.document == rhs.document &&
           lhs.role == rhs.role && lhs.synchronization_group == rhs.synchronization_group &&
           lhs.synchronization_policy == rhs.synchronization_policy &&
           lhs.focused == rhs.focused;
}

bool split_node_equal(const split_node_dto_t& lhs, const split_node_dto_t& rhs) noexcept
{
    return lhs.id == rhs.id && lhs.kind == rhs.kind && lhs.orientation == rhs.orientation &&
           lhs.ratio_basis_points == rhs.ratio_basis_points && lhs.view == rhs.view &&
           lhs.first == rhs.first && lhs.second == rhs.second;
}

bool panel_dto_equal(const panel_state_dto_t& lhs, const panel_state_dto_t& rhs)
{
    return lhs.id == rhs.id && lhs.workspace == rhs.workspace && lhs.kind == rhs.kind &&
           lhs.visible == rhs.visible && lhs.pinned == rhs.pinned &&
           lhs.extent_pixels == rhs.extent_pixels && lhs.selected_document == rhs.selected_document &&
           lhs.state_token == rhs.state_token && lhs.revision == rhs.revision;
}

bool layout_equal(const fixed_layout_constraints_t& lhs,
                  const fixed_layout_constraints_t& rhs) noexcept
{
    return lhs.left_rail_pixels == rhs.left_rail_pixels &&
           lhs.navigator_pixels == rhs.navigator_pixels &&
           lhs.inspector_pixels == rhs.inspector_pixels &&
           lhs.bottom_panel_pixels == rhs.bottom_panel_pixels &&
           lhs.tab_strip_pixels == rhs.tab_strip_pixels && lhs.toolbar_pixels == rhs.toolbar_pixels &&
           lhs.splitter_pixels == rhs.splitter_pixels &&
           lhs.minimum_document_width_pixels == rhs.minimum_document_width_pixels &&
           lhs.minimum_document_height_pixels == rhs.minimum_document_height_pixels;
}

bool event_vector_equal(const std::vector<navigation_event_t>& lhs,
                        const std::vector<navigation_event_t>& rhs)
{
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t index = 0; index < lhs.size(); ++index) {
        if (!navigation_event_equal(lhs[index], rhs[index]))
            return false;
    }
    return true;
}

bool history_equal(const navigation_history_dto_t& lhs, const navigation_history_dto_t& rhs)
{
    return lhs.workspace == rhs.workspace && lhs.capacity == rhs.capacity &&
           event_vector_equal(lhs.back, rhs.back) && event_vector_equal(lhs.forward, rhs.forward);
}

bool find_document(const std::vector<document_persistence_dto_t>& documents,
                   document_id_t id) noexcept
{
    return std::any_of(documents.begin(), documents.end(), [id](const auto& document) {
        return document.id == id;
    });
}

bool valid_document_text(const document_persistence_dto_t& document) noexcept
{
    return document.identity.provider_key.size() <= k_max_document_key_bytes &&
           document.title.size() <= k_max_document_title_bytes &&
           document.state_token.size() <= k_max_panel_state_bytes;
}

bool valid_panel_text(const panel_state_dto_t& panel) noexcept
{
    return panel.state_token.size() <= k_max_panel_state_bytes;
}

bool panel_extent_matches(const panel_state_dto_t& panel,
                          const fixed_layout_constraints_t& layout) noexcept
{
    switch (panel.kind) {
        case panel_kind_t::navigator:
            return panel.extent_pixels == layout.navigator_pixels;
        case panel_kind_t::inspector:
            return panel.extent_pixels == layout.inspector_pixels;
        case panel_kind_t::output:
        case panel_kind_t::diagnostics:
        case panel_kind_t::bookmarks:
        case panel_kind_t::progress:
            return panel.extent_pixels == layout.bottom_panel_pixels;
        case panel_kind_t::custom:
            return panel.extent_pixels == 0 ||
                   (panel.extent_pixels >= k_min_bottom_panel_pixels &&
                    panel.extent_pixels <= k_max_document_height_pixels);
    }
    return false;
}

void hash_byte(std::uint64_t& hash, std::uint8_t value) noexcept
{
    hash ^= value;
    hash *= k_fnv_prime;
}

void hash_u16(std::uint64_t& hash, std::uint16_t value) noexcept
{
    hash_byte(hash, static_cast<std::uint8_t>(value));
    hash_byte(hash, static_cast<std::uint8_t>(value >> 8U));
}

void hash_u32(std::uint64_t& hash, std::uint32_t value) noexcept
{
    for (std::uint32_t shift = 0; shift != 32; shift += 8)
        hash_byte(hash, static_cast<std::uint8_t>(value >> shift));
}

void hash_u64(std::uint64_t& hash, std::uint64_t value) noexcept
{
    for (std::uint32_t shift = 0; shift != 64; shift += 8)
        hash_byte(hash, static_cast<std::uint8_t>(value >> shift));
}

void hash_bool(std::uint64_t& hash, bool value) noexcept
{
    hash_byte(hash, value ? 1U : 0U);
}

void hash_string(std::uint64_t& hash, const std::string& value) noexcept
{
    hash_u64(hash, static_cast<std::uint64_t>(value.size()));
    for (const unsigned char byte : value)
        hash_byte(hash, byte);
}

void hash_selection(std::uint64_t& hash, const selection_context_t& selection) noexcept
{
    hash_byte(hash, static_cast<std::uint8_t>(selection.kind));
    hash_bool(hash, selection.has_address);
    hash_u64(hash, selection.address);
    hash_u64(hash, selection.extent);
    hash_string(hash, selection.entity_key);
}

void hash_cursor(std::uint64_t& hash, const document_local_cursor_t& cursor) noexcept
{
    hash_bool(hash, cursor.has_position);
    hash_u64(hash, cursor.position);
}

void hash_document_local_state(std::uint64_t& hash, const document_local_state_t& state) noexcept
{
    hash_cursor(hash, state.cursor);
    hash_selection(hash, state.selection);
}

void hash_identity(std::uint64_t& hash, const document_identity_t& identity) noexcept
{
    hash_u64(hash, identity.workspace.value);
    hash_byte(hash, static_cast<std::uint8_t>(identity.kind));
    hash_u64(hash, identity.object_id);
    hash_u64(hash, identity.variant_id);
    hash_string(hash, identity.provider_key);
    hash_bool(hash, identity.has_address);
    hash_u64(hash, identity.address);
}

void hash_event(std::uint64_t& hash, const navigation_event_t& event) noexcept
{
    hash_u64(hash, event.id.value);
    hash_u64(hash, event.workspace.value);
    hash_bool(hash, event.has_source);
    hash_u64(hash, event.source.workspace.value);
    hash_u64(hash, event.source.document.value);
    hash_u64(hash, event.source.view.value);
    hash_selection(hash, event.source.selection);
    hash_cursor(hash, event.source.cursor);
    hash_u64(hash, event.source.synchronization_group);
    hash_byte(hash, static_cast<std::uint8_t>(event.source.synchronization_policy));
    hash_identity(hash, event.target.document);
    hash_selection(hash, event.target.selection);
    hash_cursor(hash, event.target.cursor);
    hash_byte(hash, static_cast<std::uint8_t>(event.origin));
    hash_u64(hash, event.sequence);
    hash_bool(hash, event.request_focus);
}

}

bool document_identity_equal(const document_identity_t& lhs, const document_identity_t& rhs)
{
    return lhs.workspace == rhs.workspace && lhs.kind == rhs.kind && lhs.object_id == rhs.object_id &&
           lhs.variant_id == rhs.variant_id && lhs.provider_key == rhs.provider_key &&
           lhs.has_address == rhs.has_address && lhs.address == rhs.address;
}

bool document_identity_less(const document_identity_t& lhs, const document_identity_t& rhs)
{
    if (lhs.workspace != rhs.workspace)
        return lhs.workspace < rhs.workspace;
    if (lhs.kind != rhs.kind)
        return static_cast<std::uint8_t>(lhs.kind) < static_cast<std::uint8_t>(rhs.kind);
    if (lhs.object_id != rhs.object_id)
        return lhs.object_id < rhs.object_id;
    if (lhs.variant_id != rhs.variant_id)
        return lhs.variant_id < rhs.variant_id;
    if (lhs.provider_key != rhs.provider_key)
        return lhs.provider_key < rhs.provider_key;
    if (lhs.has_address != rhs.has_address)
        return !lhs.has_address;
    return lhs.address < rhs.address;
}

bool selection_context_equal(const selection_context_t& lhs, const selection_context_t& rhs)
{
    return lhs.kind == rhs.kind && lhs.has_address == rhs.has_address &&
           lhs.address == rhs.address && lhs.extent == rhs.extent &&
           lhs.entity_key == rhs.entity_key;
}

bool document_local_cursor_equal(const document_local_cursor_t& lhs,
                                 const document_local_cursor_t& rhs) noexcept
{
    return lhs.has_position == rhs.has_position && lhs.position == rhs.position;
}

bool document_local_state_equal(const document_local_state_t& lhs,
                                const document_local_state_t& rhs)
{
    return document_local_cursor_equal(lhs.cursor, rhs.cursor) &&
           selection_context_equal(lhs.selection, rhs.selection);
}

bool persistence_dto_equal(const workbench_persistence_dto_t& lhs,
                           const workbench_persistence_dto_t& rhs)
{
    workbench_persistence_dto_t canonical_lhs = lhs;
    workbench_persistence_dto_t canonical_rhs = rhs;
    if (!normalize_persistence_dto(canonical_lhs) || !normalize_persistence_dto(canonical_rhs))
        return false;
    if (canonical_lhs.schema_version != canonical_rhs.schema_version ||
        canonical_lhs.workspace != canonical_rhs.workspace ||
        canonical_lhs.revision != canonical_rhs.revision ||
        !layout_equal(canonical_lhs.layout, canonical_rhs.layout) ||
        canonical_lhs.split_tree.root != canonical_rhs.split_tree.root ||
        canonical_lhs.active_document != canonical_rhs.active_document ||
        canonical_lhs.documents.size() != canonical_rhs.documents.size() ||
        canonical_lhs.views.size() != canonical_rhs.views.size() ||
        canonical_lhs.split_tree.nodes.size() != canonical_rhs.split_tree.nodes.size() ||
        canonical_lhs.panels.size() != canonical_rhs.panels.size() ||
        !history_equal(canonical_lhs.history, canonical_rhs.history)) {
        return false;
    }
    for (std::size_t index = 0; index < canonical_lhs.documents.size(); ++index) {
        if (!document_dto_equal(canonical_lhs.documents[index], canonical_rhs.documents[index]))
            return false;
    }
    for (std::size_t index = 0; index < canonical_lhs.views.size(); ++index) {
        if (!view_dto_equal(canonical_lhs.views[index], canonical_rhs.views[index]))
            return false;
    }
    for (std::size_t index = 0; index < canonical_lhs.split_tree.nodes.size(); ++index) {
        if (!split_node_equal(canonical_lhs.split_tree.nodes[index],
                              canonical_rhs.split_tree.nodes[index])) {
            return false;
        }
    }
    for (std::size_t index = 0; index < canonical_lhs.panels.size(); ++index) {
        if (!panel_dto_equal(canonical_lhs.panels[index], canonical_rhs.panels[index]))
            return false;
    }
    return true;
}

workbench_error_t validate_document_identity(const document_identity_t& identity)
{
    if (!identity.workspace.valid())
        return error(workbench_error_code_t::invalid_workspace);
    if (!valid_document_kind(identity.kind) ||
        identity.provider_key.size() > k_max_document_key_bytes ||
        (identity.object_id == 0 && identity.provider_key.empty() && !identity.has_address)) {
        return error(workbench_error_code_t::invalid_document);
    }
    if (!identity.has_address && identity.address != 0)
        return error(workbench_error_code_t::invalid_document);
    return {};
}

workbench_error_t validate_selection_context(const selection_context_t& selection)
{
    if (!valid_selection_kind(selection.kind) || selection.entity_key.size() > k_max_document_key_bytes)
        return error(workbench_error_code_t::invalid_navigation);
    switch (selection.kind) {
        case selection_kind_t::none:
            return (!selection.has_address && selection.address == 0 && selection.extent == 0 &&
                    selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
        case selection_kind_t::address:
            return (selection.has_address && selection.extent == 0 && selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
        case selection_kind_t::entity:
        case selection_kind_t::source:
            return (!selection.has_address && selection.address == 0 && selection.extent == 0 &&
                    !selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
        case selection_kind_t::range:
            return (selection.has_address && selection.extent != 0 && selection.entity_key.empty())
                ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
    }
    return error(workbench_error_code_t::invalid_navigation);
}

workbench_error_t validate_document_local_cursor(const document_local_cursor_t& cursor)
{
    return !cursor.has_position && cursor.position != 0
        ? error(workbench_error_code_t::invalid_document_state) : workbench_error_t{};
}

workbench_error_t validate_document_local_state(const document_local_state_t& state)
{
    const auto cursor_result = validate_document_local_cursor(state.cursor);
    if (!cursor_result)
        return cursor_result;
    const auto selection_result = validate_selection_context(state.selection);
    return selection_result ? workbench_error_t{} :
        error(workbench_error_code_t::invalid_document_state);
}

workbench_error_t validate_workspace_view_context(const workspace_view_context_t& context)
{
    if (!context.workspace.valid())
        return error(workbench_error_code_t::invalid_workspace);
    if (!context.document.valid() || !context.view.valid())
        return error(workbench_error_code_t::invalid_view);
    if (!synchronization_policy_matches(context.synchronization_policy,
                                        context.synchronization_group)) {
        return error(workbench_error_code_t::invalid_synchronization_policy, context.view.value);
    }
    const auto selection_result = validate_selection_context(context.selection);
    if (!selection_result)
        return selection_result;
    const auto cursor_result = validate_document_local_cursor(context.cursor);
    return cursor_result ? workbench_error_t{} :
        error(workbench_error_code_t::invalid_document_state, context.document.value);
}

workbench_error_t validate_view_context(const view_context_t& context)
{
    return validate_workspace_view_context(context);
}

workbench_error_t validate_workspace_navigation_event(const workspace_navigation_event_t& event)
{
    if (!event.id.valid() || !event.workspace.valid() || event.sequence == 0 ||
        !valid_navigation_origin(event.origin)) {
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    }
    if (event.origin == navigation_origin_t::mcp && event.request_focus)
        return error(workbench_error_code_t::focus_forbidden, event.id.value);
    const auto target_result = validate_document_identity(event.target.document);
    if (!target_result)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    if (event.target.document.workspace != event.workspace)
        return error(workbench_error_code_t::workspace_mismatch, event.id.value);
    const auto selection_result = validate_selection_context(event.target.selection);
    if (!selection_result)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    const auto cursor_result = validate_document_local_cursor(event.target.cursor);
    if (!cursor_result)
        return error(workbench_error_code_t::invalid_document_state, event.id.value);
    if (!event.has_source)
        return {};
    const auto source_result = validate_workspace_view_context(event.source);
    if (!source_result)
        return error(workbench_error_code_t::invalid_navigation, event.id.value);
    return event.source.workspace == event.workspace
        ? workbench_error_t{} : error(workbench_error_code_t::workspace_mismatch, event.id.value);
}

workbench_error_t validate_navigation_event(const navigation_event_t& event)
{
    return validate_workspace_navigation_event(event);
}

workbench_error_t validate_split_tree(const split_tree_dto_t& tree,
                                      const std::vector<view_persistence_dto_t>& views)
{
    if (tree.nodes.empty())
        return tree.root.valid() ? error(workbench_error_code_t::invalid_split_tree) : workbench_error_t{};
    if (!tree.root.valid() || tree.nodes.size() > k_max_split_nodes_per_workspace)
        return error(workbench_error_code_t::invalid_split_tree, tree.root.value);

    std::unordered_map<std::uint64_t, std::size_t> indices;
    indices.reserve(tree.nodes.size());
    for (std::size_t index = 0; index < tree.nodes.size(); ++index) {
        const auto& node = tree.nodes[index];
        if (!node.id.valid() || !valid_split_node_kind(node.kind) ||
            !valid_split_orientation(node.orientation) || !indices.emplace(node.id.value, index).second) {
            return error(workbench_error_code_t::duplicate_identifier, node.id.value);
        }
        if (node.kind == split_node_kind_t::leaf) {
            if (!node.view.valid() || node.first.valid() || node.second.valid() ||
                node.orientation != split_orientation_t::horizontal ||
                node.ratio_basis_points != k_split_ratio_default_basis_points)
                return error(workbench_error_code_t::invalid_split_tree, node.id.value);
        } else if (node.view.valid() || !node.first.valid() || !node.second.valid() ||
                   node.first == node.second ||
                   node.ratio_basis_points < k_split_ratio_min_basis_points ||
                   node.ratio_basis_points > k_split_ratio_max_basis_points) {
            return error(workbench_error_code_t::invalid_split_tree, node.id.value);
        }
    }
    const auto root = indices.find(tree.root.value);
    if (root == indices.end())
        return error(workbench_error_code_t::invalid_split_tree, tree.root.value);

    std::vector<std::uint32_t> parents(tree.nodes.size(), 0);
    for (std::size_t index = 0; index < tree.nodes.size(); ++index) {
        const auto& node = tree.nodes[index];
        if (node.kind != split_node_kind_t::branch)
            continue;
        for (const auto child_id : {node.first, node.second}) {
            const auto child = indices.find(child_id.value);
            if (child == indices.end())
                return error(workbench_error_code_t::invalid_split_tree, child_id.value);
            if (++parents[child->second] != 1)
                return error(workbench_error_code_t::invalid_split_tree, child_id.value);
        }
    }
    if (parents[root->second] != 0)
        return error(workbench_error_code_t::invalid_split_tree, tree.root.value);
    for (std::size_t index = 0; index < parents.size(); ++index) {
        if (index != root->second && parents[index] != 1)
            return error(workbench_error_code_t::invalid_split_tree, tree.nodes[index].id.value);
    }

    std::unordered_set<std::uint64_t> known_views;
    known_views.reserve(views.size());
    for (const auto& view : views)
        known_views.insert(view.id.value);
    std::unordered_set<std::uint64_t> leaf_views;
    leaf_views.reserve(tree.nodes.size());
    std::vector<std::size_t> pending{root->second};
    std::vector<bool> reached(tree.nodes.size(), false);
    while (!pending.empty()) {
        const auto index = pending.back();
        pending.pop_back();
        if (reached[index])
            return error(workbench_error_code_t::invalid_split_tree, tree.nodes[index].id.value);
        reached[index] = true;
        const auto& node = tree.nodes[index];
        if (node.kind == split_node_kind_t::leaf) {
            if (known_views.find(node.view.value) == known_views.end() ||
                !leaf_views.insert(node.view.value).second) {
                return error(workbench_error_code_t::invalid_split_tree, node.view.value);
            }
            continue;
        }
        pending.push_back(indices.at(node.first.value));
        pending.push_back(indices.at(node.second.value));
    }
    for (std::size_t index = 0; index < reached.size(); ++index) {
        if (!reached[index])
            return error(workbench_error_code_t::invalid_split_tree, tree.nodes[index].id.value);
    }
    return {};
}

workbench_error_t validate_split_tree(const split_tree_dto_t& tree,
                                      const std::vector<view_persistence_dto_t>& views,
                                      const fixed_layout_constraints_t& constraints,
                                      layout_extent_t document_extent)
{
    const auto layout_result = validate_fixed_layout_constraints(constraints);
    if (!layout_result)
        return layout_result;
    const auto topology_result = validate_split_tree(tree, views);
    if (!topology_result || tree.nodes.empty())
        return topology_result;

    std::unordered_map<std::uint64_t, std::size_t> indices;
    indices.reserve(tree.nodes.size());
    for (std::size_t index = 0; index < tree.nodes.size(); ++index)
        indices.emplace(tree.nodes[index].id.value, index);

    struct pending_extent_t {
        std::size_t index = 0;
        layout_extent_t extent;
    };

    std::vector<pending_extent_t> pending{{indices.at(tree.root.value), document_extent}};
    while (!pending.empty()) {
        const auto current = pending.back();
        pending.pop_back();
        const auto& node = tree.nodes[current.index];
        if (node.kind == split_node_kind_t::leaf) {
            if (current.extent.width_pixels < constraints.minimum_document_width_pixels ||
                current.extent.height_pixels < constraints.minimum_document_height_pixels) {
                return error(workbench_error_code_t::invalid_split_tree, node.id.value);
            }
            continue;
        }

        const auto split_axis = node.orientation == split_orientation_t::horizontal
            ? current.extent.width_pixels : current.extent.height_pixels;
        if (split_axis <= constraints.splitter_pixels)
            return error(workbench_error_code_t::invalid_split_tree, node.id.value);

        const auto distributable = static_cast<std::uint64_t>(split_axis - constraints.splitter_pixels);
        const auto first_axis = static_cast<std::uint32_t>(
            distributable * node.ratio_basis_points / 10000U);
        const auto second_axis = static_cast<std::uint32_t>(distributable - first_axis);
        auto first_extent = current.extent;
        auto second_extent = current.extent;
        if (node.orientation == split_orientation_t::horizontal) {
            first_extent.width_pixels = first_axis;
            second_extent.width_pixels = second_axis;
        } else {
            first_extent.height_pixels = first_axis;
            second_extent.height_pixels = second_axis;
        }
        pending.push_back({indices.at(node.first.value), first_extent});
        pending.push_back({indices.at(node.second.value), second_extent});
    }
    return {};
}

void normalize_split_tree(split_tree_dto_t& tree) noexcept
{
    for (auto& node : tree.nodes) {
        if (node.kind == split_node_kind_t::branch) {
            node.ratio_basis_points = clamp_ratio(node.ratio_basis_points);
        } else if (node.kind == split_node_kind_t::leaf) {
            node.orientation = split_orientation_t::horizontal;
            node.ratio_basis_points = k_split_ratio_default_basis_points;
        }
    }
    std::sort(tree.nodes.begin(), tree.nodes.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.id < rhs.id;
    });
}

void normalize_fixed_layout_constraints(fixed_layout_constraints_t& constraints) noexcept
{
    constraints.left_rail_pixels = clamp_dimension(constraints.left_rail_pixels,
                                                   k_min_left_rail_pixels,
                                                   k_max_left_rail_pixels);
    constraints.navigator_pixels = clamp_dimension(constraints.navigator_pixels,
                                                   k_min_navigator_pixels,
                                                   k_max_navigator_pixels);
    constraints.inspector_pixels = clamp_dimension(constraints.inspector_pixels,
                                                   k_min_inspector_pixels,
                                                   k_max_inspector_pixels);
    constraints.bottom_panel_pixels = clamp_dimension(constraints.bottom_panel_pixels,
                                                      k_min_bottom_panel_pixels,
                                                      k_max_bottom_panel_pixels);
    constraints.tab_strip_pixels = clamp_dimension(constraints.tab_strip_pixels,
                                                   k_min_tab_strip_pixels,
                                                   k_max_tab_strip_pixels);
    constraints.toolbar_pixels = clamp_dimension(constraints.toolbar_pixels,
                                                 k_min_toolbar_pixels,
                                                 k_max_toolbar_pixels);
    constraints.splitter_pixels = clamp_dimension(constraints.splitter_pixels,
                                                  k_min_splitter_pixels,
                                                  k_max_splitter_pixels);
    constraints.minimum_document_width_pixels = clamp_dimension(
        constraints.minimum_document_width_pixels, k_min_document_width_pixels,
        k_max_document_width_pixels);
    constraints.minimum_document_height_pixels = clamp_dimension(
        constraints.minimum_document_height_pixels, k_min_document_height_pixels,
        k_max_document_height_pixels);
}

workbench_error_t validate_fixed_layout_constraints(const fixed_layout_constraints_t& constraints)
{
    const auto in_range = [](std::uint32_t value, std::uint32_t minimum, std::uint32_t maximum) noexcept {
        return value >= minimum && value <= maximum;
    };
    return in_range(constraints.left_rail_pixels, k_min_left_rail_pixels, k_max_left_rail_pixels) &&
           in_range(constraints.navigator_pixels, k_min_navigator_pixels, k_max_navigator_pixels) &&
           in_range(constraints.inspector_pixels, k_min_inspector_pixels, k_max_inspector_pixels) &&
           in_range(constraints.bottom_panel_pixels, k_min_bottom_panel_pixels,
                    k_max_bottom_panel_pixels) &&
           in_range(constraints.tab_strip_pixels, k_min_tab_strip_pixels, k_max_tab_strip_pixels) &&
           in_range(constraints.toolbar_pixels, k_min_toolbar_pixels, k_max_toolbar_pixels) &&
           in_range(constraints.splitter_pixels, k_min_splitter_pixels, k_max_splitter_pixels) &&
           in_range(constraints.minimum_document_width_pixels, k_min_document_width_pixels,
                    k_max_document_width_pixels) &&
           in_range(constraints.minimum_document_height_pixels, k_min_document_height_pixels,
                    k_max_document_height_pixels)
        ? workbench_error_t{} : error(workbench_error_code_t::invalid_layout);
}

layout_extent_t minimum_layout_extent(const fixed_layout_constraints_t& constraints) noexcept
{
    return {
        constraints.left_rail_pixels + constraints.navigator_pixels + constraints.inspector_pixels +
            constraints.minimum_document_width_pixels + constraints.splitter_pixels * 2U,
        constraints.toolbar_pixels + constraints.tab_strip_pixels +
            constraints.minimum_document_height_pixels + constraints.bottom_panel_pixels +
            constraints.splitter_pixels
    };
}

bool layout_extent_satisfies(const fixed_layout_constraints_t& constraints,
                             layout_extent_t available) noexcept
{
    const auto minimum = minimum_layout_extent(constraints);
    return available.width_pixels >= minimum.width_pixels &&
           available.height_pixels >= minimum.height_pixels;
}

workbench_error_t validate_persistence_dto(const workbench_persistence_dto_t& dto)
{
    if (dto.schema_version != k_workbench_contract_schema_version || !dto.workspace.valid() ||
        !dto.revision.valid()) {
        return error(workbench_error_code_t::invalid_persistence);
    }
    const auto layout_result = validate_fixed_layout_constraints(dto.layout);
    if (!layout_result)
        return layout_result;
    if (dto.documents.size() > k_max_documents_per_workspace ||
        dto.views.size() > k_max_views_per_workspace || dto.panels.size() > k_max_panels_per_workspace) {
        return error(workbench_error_code_t::invalid_persistence);
    }
    if (dto.documents.empty() || !dto.active_document.valid())
        return error(workbench_error_code_t::invalid_persistence, dto.active_document.value);

    std::unordered_set<std::uint64_t> document_ids;
    std::vector<document_identity_t> identities;
    document_ids.reserve(dto.documents.size());
    identities.reserve(dto.documents.size());
    for (const auto& document : dto.documents) {
        if (!document.id.valid() || !valid_document_text(document))
            return error(workbench_error_code_t::invalid_document, document.id.value);
        const auto identity_result = validate_document_identity(document.identity);
        if (!identity_result)
            return identity_result;
        const auto local_state_result = validate_document_local_state(document.local_state);
        if (!local_state_result)
            return error(workbench_error_code_t::invalid_document_state, document.id.value);
        if (document.identity.workspace != dto.workspace)
            return error(workbench_error_code_t::workspace_mismatch, document.id.value);
        if (!document_ids.insert(document.id.value).second)
            return error(workbench_error_code_t::duplicate_identifier, document.id.value);
        for (const auto& existing : identities) {
            if (document_identity_equal(existing, document.identity))
                return error(workbench_error_code_t::duplicate_identifier, document.id.value);
        }
        identities.push_back(document.identity);
    }
    if (!find_document(dto.documents, dto.active_document))
        return error(workbench_error_code_t::invalid_document, dto.active_document.value);

    std::unordered_set<std::uint64_t> view_ids;
    view_ids.reserve(dto.views.size());
    std::uint32_t focused_views = 0;
    for (const auto& view : dto.views) {
        if (!view.id.valid() || !view.document.valid() || !valid_view_role(view.role))
            return error(workbench_error_code_t::invalid_view, view.id.value);
        if (view.workspace != dto.workspace)
            return error(workbench_error_code_t::workspace_mismatch, view.id.value);
        if (!find_document(dto.documents, view.document))
            return error(workbench_error_code_t::invalid_document, view.document.value);
        if (!synchronization_policy_matches(view.synchronization_policy,
                                            view.synchronization_group)) {
            return error(workbench_error_code_t::invalid_synchronization_policy, view.id.value);
        }
        if (!view_ids.insert(view.id.value).second)
            return error(workbench_error_code_t::duplicate_identifier, view.id.value);
        focused_views += view.focused ? 1U : 0U;
        if (focused_views > 1)
            return error(workbench_error_code_t::invalid_view, view.id.value);
    }
    const auto split_result = validate_split_tree(dto.split_tree, dto.views);
    if (!split_result)
        return split_result;

    std::unordered_set<std::uint64_t> panel_ids;
    panel_ids.reserve(dto.panels.size());
    for (const auto& panel : dto.panels) {
        if (!panel.id.valid() || !panel.revision.valid() || !valid_panel_kind(panel.kind) ||
            !valid_panel_text(panel)) {
            return error(workbench_error_code_t::invalid_panel, panel.id.value);
        }
        if (panel.workspace != dto.workspace)
            return error(workbench_error_code_t::workspace_mismatch, panel.id.value);
        if (panel.revision.value > dto.revision.value ||
            !panel_extent_matches(panel, dto.layout) ||
            (panel.selected_document.valid() && !find_document(dto.documents, panel.selected_document)) ||
            !panel_ids.insert(panel.id.value).second) {
            return error(workbench_error_code_t::invalid_panel, panel.id.value);
        }
    }

    if (dto.history.workspace != dto.workspace || dto.history.capacity == 0 ||
        dto.history.capacity > k_max_history_capacity ||
        dto.history.back.size() + dto.history.forward.size() > dto.history.capacity) {
        return error(workbench_error_code_t::invalid_persistence);
    }
    std::unordered_set<std::uint64_t> history_ids;
    std::unordered_set<std::uint64_t> sequences;
    const auto validate_history_events = [&](const std::vector<navigation_event_t>& events) {
        for (const auto& event : events) {
            const auto result = validate_navigation_event(event);
            if (!result || event.workspace != dto.workspace ||
                !history_ids.insert(event.id.value).second ||
                !sequences.insert(event.sequence).second) {
                return false;
            }
        }
        return true;
    };
    return validate_history_events(dto.history.back) && validate_history_events(dto.history.forward)
        ? workbench_error_t{} : error(workbench_error_code_t::invalid_navigation);
}

workbench_error_t normalize_persistence_dto(workbench_persistence_dto_t& dto)
{
    normalize_fixed_layout_constraints(dto.layout);
    normalize_split_tree(dto.split_tree);
    dto.history.capacity = dto.history.capacity == 0 ? k_default_history_capacity :
        (dto.history.capacity > k_max_history_capacity ? k_max_history_capacity : dto.history.capacity);
    std::sort(dto.documents.begin(), dto.documents.end(), [](const auto& lhs, const auto& rhs) {
        if (document_identity_less(lhs.identity, rhs.identity))
            return true;
        if (document_identity_less(rhs.identity, lhs.identity))
            return false;
        return lhs.id < rhs.id;
    });
    std::sort(dto.views.begin(), dto.views.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.id < rhs.id;
    });
    std::sort(dto.panels.begin(), dto.panels.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.id < rhs.id;
    });
    return validate_persistence_dto(dto);
}

workbench_error_t next_workspace_revision(workspace_revision_t current,
                                          workspace_revision_t& output) noexcept
{
    if (!current.valid())
        return error(workbench_error_code_t::revision_mismatch);
    if (current.value == (std::numeric_limits<std::uint64_t>::max)())
        return error(workbench_error_code_t::revision_overflow, current.value);
    output = {current.value + 1U};
    return {};
}

bool revision_matches(workspace_revision_t expected, workspace_revision_t observed) noexcept
{
    return expected.valid() && observed.valid() && expected == observed;
}

workbench_error_t append_navigation_history(navigation_history_dto_t& history,
                                            const navigation_event_t& event)
{
    if (!history.workspace.valid() || history.capacity == 0 || history.capacity > k_max_history_capacity)
        return error(workbench_error_code_t::history_capacity);
    const auto event_result = validate_navigation_event(event);
    if (!event_result)
        return event_result;
    if (event.workspace != history.workspace)
        return error(workbench_error_code_t::workspace_mismatch, event.id.value);
    const auto matches = [&event](const navigation_event_t& existing) {
        return existing.id == event.id || existing.sequence == event.sequence;
    };
    if (std::any_of(history.back.begin(), history.back.end(), matches) ||
        std::any_of(history.forward.begin(), history.forward.end(), matches)) {
        return error(workbench_error_code_t::duplicate_identifier, event.id.value);
    }
    history.forward.clear();
    history.back.push_back(event);
    if (history.back.size() > history.capacity)
        history.back.erase(history.back.begin());
    return {};
}

workbench_error_t history_back(navigation_history_dto_t& history,
                               navigation_event_t& output)
{
    if (!history.workspace.valid() || history.capacity == 0 || history.capacity > k_max_history_capacity)
        return error(workbench_error_code_t::history_capacity);
    if (history.back.empty())
        return error(workbench_error_code_t::history_empty);
    output = history.back.back();
    history.back.pop_back();
    history.forward.push_back(output);
    return {};
}

workbench_error_t history_forward(navigation_history_dto_t& history,
                                  navigation_event_t& output)
{
    if (!history.workspace.valid() || history.capacity == 0 || history.capacity > k_max_history_capacity)
        return error(workbench_error_code_t::history_capacity);
    if (history.forward.empty())
        return error(workbench_error_code_t::history_empty);
    output = history.forward.back();
    history.forward.pop_back();
    history.back.push_back(output);
    return {};
}

persistence_fingerprint_t persistence_fingerprint(const workbench_persistence_dto_t& dto)
{
    workbench_persistence_dto_t canonical = dto;
    if (!normalize_persistence_dto(canonical))
        return {};
    std::uint64_t hash = k_fnv_offset_basis;
    hash_u32(hash, canonical.schema_version);
    hash_u64(hash, canonical.workspace.value);
    hash_u64(hash, canonical.revision.value);
    hash_u32(hash, canonical.layout.left_rail_pixels);
    hash_u32(hash, canonical.layout.navigator_pixels);
    hash_u32(hash, canonical.layout.inspector_pixels);
    hash_u32(hash, canonical.layout.bottom_panel_pixels);
    hash_u32(hash, canonical.layout.tab_strip_pixels);
    hash_u32(hash, canonical.layout.toolbar_pixels);
    hash_u32(hash, canonical.layout.splitter_pixels);
    hash_u32(hash, canonical.layout.minimum_document_width_pixels);
    hash_u32(hash, canonical.layout.minimum_document_height_pixels);
    hash_u64(hash, canonical.split_tree.root.value);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.split_tree.nodes.size()));
    for (const auto& node : canonical.split_tree.nodes) {
        hash_u64(hash, node.id.value);
        hash_byte(hash, static_cast<std::uint8_t>(node.kind));
        hash_byte(hash, static_cast<std::uint8_t>(node.orientation));
        hash_u16(hash, node.ratio_basis_points);
        hash_u64(hash, node.view.value);
        hash_u64(hash, node.first.value);
        hash_u64(hash, node.second.value);
    }
    hash_u64(hash, static_cast<std::uint64_t>(canonical.documents.size()));
    for (const auto& document : canonical.documents) {
        hash_u64(hash, document.id.value);
        hash_identity(hash, document.identity);
        hash_string(hash, document.title);
        hash_string(hash, document.state_token);
        hash_document_local_state(hash, document.local_state);
        hash_bool(hash, document.pinned);
        hash_bool(hash, document.closeable);
    }
    hash_u64(hash, canonical.active_document.value);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.views.size()));
    for (const auto& view : canonical.views) {
        hash_u64(hash, view.id.value);
        hash_u64(hash, view.workspace.value);
        hash_u64(hash, view.document.value);
        hash_byte(hash, static_cast<std::uint8_t>(view.role));
        hash_u64(hash, view.synchronization_group);
        hash_byte(hash, static_cast<std::uint8_t>(view.synchronization_policy));
        hash_bool(hash, view.focused);
    }
    hash_u64(hash, static_cast<std::uint64_t>(canonical.panels.size()));
    for (const auto& panel : canonical.panels) {
        hash_u64(hash, panel.id.value);
        hash_u64(hash, panel.workspace.value);
        hash_byte(hash, static_cast<std::uint8_t>(panel.kind));
        hash_bool(hash, panel.visible);
        hash_bool(hash, panel.pinned);
        hash_u32(hash, panel.extent_pixels);
        hash_u64(hash, panel.selected_document.value);
        hash_string(hash, panel.state_token);
        hash_u64(hash, panel.revision.value);
    }
    hash_u64(hash, canonical.history.workspace.value);
    hash_u32(hash, canonical.history.capacity);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.history.back.size()));
    for (const auto& event : canonical.history.back)
        hash_event(hash, event);
    hash_u64(hash, static_cast<std::uint64_t>(canonical.history.forward.size()));
    for (const auto& event : canonical.history.forward)
        hash_event(hash, event);
    return {hash};
}

}
}
