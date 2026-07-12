#pragma once

#include "workbench_contracts.h"

#include <vector>

namespace aida {
namespace workbench {

struct split_insert_result_t {
    split_node_id_t branch;
    split_node_id_t leaf;
};

workbench_error_t split_tree_find_leaf(const split_tree_dto_t& tree, view_id_t view,
                                       split_node_id_t& output) noexcept;
workbench_error_t split_tree_swap_views(split_tree_dto_t& tree, view_id_t first,
                                        view_id_t second);
workbench_error_t split_tree_split_view(split_tree_dto_t& tree, view_id_t source_view,
                                        view_id_t inserted_view, split_orientation_t orientation,
                                        std::uint16_t ratio_basis_points,
                                        split_node_id_t branch_id, split_node_id_t leaf_id,
                                        split_insert_result_t& output);
workbench_error_t split_tree_remove_view(split_tree_dto_t& tree, view_id_t view);

}
}
