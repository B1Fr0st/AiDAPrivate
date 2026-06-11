#pragma once

#include "re_common.hpp"

namespace re::dx_hook
{
tool_result_t find_device_vtable(const json& params);
tool_result_t hook_manage(const json& params);
tool_result_t list_bound_cbuffers(const json& params);
tool_result_t identify_bone_buffer(const json& params);
tool_result_t map_resource_to_va(const json& params);
tool_result_t dump_render_targets(const json& params);
tool_result_t find_view_matrix(const json& params);
}
