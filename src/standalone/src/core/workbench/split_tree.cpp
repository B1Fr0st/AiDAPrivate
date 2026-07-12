#include "split_tree.h"

#include <algorithm>
#include <unordered_map>

namespace aida {
namespace workbench {
namespace {

workbench_error_t error(workbench_error_code_t code, std::uint64_t subject = 0) noexcept
{
    return {code, subject};
}

bool valid_orientation(split_orientation_t orientation) noexcept
{
    return orientation == split_orientation_t::horizontal ||
           orientation == split_orientation_t::vertical;
}

bool view_exists(const split_tree_dto_t& tree, view_id_t view) noexcept
{
    return std::any_of(tree.nodes.begin(), tree.nodes.end(), [view](const split_node_dto_t& node) {
        return node.kind == split_node_kind_t::leaf && node.view == view;
    });
}

bool node_exists(const split_tree_dto_t& tree, split_node_id_t id) noexcept
{
    return std::any_of(tree.nodes.begin(), tree.nodes.end(), [id](const split_node_dto_t& node) {
        return node.id == id;
    });
}

std::unordered_map<std::uint64_t, std::size_t> node_indices(const split_tree_dto_t& tree)
{
    std::unordered_map<std::uint64_t, std::size_t> indices;
    indices.reserve(tree.nodes.size());
    for (std::size_t index = 0; index < tree.nodes.size(); ++index)
        indices.emplace(tree.nodes[index].id.value, index);
    return indices;
}

void normalize(split_tree_dto_t& tree) noexcept
{
    normalize_split_tree(tree);
}

}

workbench_error_t split_tree_find_leaf(const split_tree_dto_t& tree, view_id_t view,
                                       split_node_id_t& output) noexcept
{
    output = {};
    if (!view.valid())
        return error(workbench_error_code_t::invalid_view);
    for (const auto& node : tree.nodes) {
        if (node.kind == split_node_kind_t::leaf && node.view == view) {
            output = node.id;
            return {};
        }
    }
    return error(workbench_error_code_t::invalid_view, view.value);
}

workbench_error_t split_tree_swap_views(split_tree_dto_t& tree, view_id_t first,
                                        view_id_t second)
{
    if (!first.valid() || !second.valid() || first == second)
        return error(workbench_error_code_t::invalid_view, first.value);

    split_node_id_t first_leaf;
    const auto first_result = split_tree_find_leaf(tree, first, first_leaf);
    if (!first_result)
        return first_result;
    split_node_id_t second_leaf;
    const auto second_result = split_tree_find_leaf(tree, second, second_leaf);
    if (!second_result)
        return second_result;

    const auto indices = node_indices(tree);
    const auto first_index = indices.find(first_leaf.value);
    const auto second_index = indices.find(second_leaf.value);
    if (first_index == indices.end() || second_index == indices.end())
        return error(workbench_error_code_t::invalid_split_tree);
    std::swap(tree.nodes[first_index->second].view, tree.nodes[second_index->second].view);
    normalize(tree);
    return {};
}

workbench_error_t split_tree_split_view(split_tree_dto_t& tree, view_id_t source_view,
                                        view_id_t inserted_view, split_orientation_t orientation,
                                        std::uint16_t ratio_basis_points,
                                        split_node_id_t branch_id, split_node_id_t leaf_id,
                                        split_insert_result_t& output)
{
    output = {};
    if (!source_view.valid() || !inserted_view.valid() || !branch_id.valid() || !leaf_id.valid() ||
        source_view == inserted_view || branch_id == leaf_id || !valid_orientation(orientation) ||
        ratio_basis_points < k_split_ratio_min_basis_points ||
        ratio_basis_points > k_split_ratio_max_basis_points) {
        return error(workbench_error_code_t::invalid_split_tree, source_view.value);
    }
    if (tree.nodes.size() > k_max_split_nodes_per_workspace - 2U)
        return error(workbench_error_code_t::invalid_split_tree, tree.root.value);
    if (view_exists(tree, inserted_view) || node_exists(tree, branch_id) || node_exists(tree, leaf_id))
        return error(workbench_error_code_t::duplicate_identifier, inserted_view.value);

    split_node_id_t source_leaf;
    const auto source_result = split_tree_find_leaf(tree, source_view, source_leaf);
    if (!source_result)
        return source_result;

    split_node_dto_t inserted_leaf;
    inserted_leaf.id = leaf_id;
    inserted_leaf.kind = split_node_kind_t::leaf;
    inserted_leaf.view = inserted_view;

    split_node_dto_t branch;
    branch.id = branch_id;
    branch.kind = split_node_kind_t::branch;
    branch.orientation = orientation;
    branch.ratio_basis_points = ratio_basis_points;
    branch.first = source_leaf;
    branch.second = leaf_id;

    for (auto& node : tree.nodes) {
        if (node.kind != split_node_kind_t::branch)
            continue;
        if (node.first == source_leaf)
            node.first = branch_id;
        if (node.second == source_leaf)
            node.second = branch_id;
    }
    if (tree.root == source_leaf)
        tree.root = branch_id;
    tree.nodes.push_back(inserted_leaf);
    tree.nodes.push_back(branch);
    normalize(tree);
    output.branch = branch_id;
    output.leaf = leaf_id;
    return {};
}

workbench_error_t split_tree_remove_view(split_tree_dto_t& tree, view_id_t view)
{
    split_node_id_t removed_leaf;
    const auto leaf_result = split_tree_find_leaf(tree, view, removed_leaf);
    if (!leaf_result)
        return leaf_result;
    if (tree.root == removed_leaf)
        return error(workbench_error_code_t::invalid_split_tree, removed_leaf.value);

    split_node_id_t parent;
    split_node_id_t sibling;
    for (const auto& node : tree.nodes) {
        if (node.kind != split_node_kind_t::branch)
            continue;
        if (node.first == removed_leaf) {
            parent = node.id;
            sibling = node.second;
            break;
        }
        if (node.second == removed_leaf) {
            parent = node.id;
            sibling = node.first;
            break;
        }
    }
    if (!parent.valid() || !sibling.valid())
        return error(workbench_error_code_t::invalid_split_tree, removed_leaf.value);

    for (auto& node : tree.nodes) {
        if (node.kind != split_node_kind_t::branch)
            continue;
        if (node.first == parent)
            node.first = sibling;
        if (node.second == parent)
            node.second = sibling;
    }
    if (tree.root == parent)
        tree.root = sibling;

    tree.nodes.erase(std::remove_if(tree.nodes.begin(), tree.nodes.end(),
                                    [removed_leaf, parent](const split_node_dto_t& node) {
                                        return node.id == removed_leaf || node.id == parent;
                                    }),
                     tree.nodes.end());
    normalize(tree);

    const auto remaining_indices = node_indices(tree);
    if (remaining_indices.find(tree.root.value) == remaining_indices.end())
        return error(workbench_error_code_t::invalid_split_tree, tree.root.value);
    return {};
}

}
}
