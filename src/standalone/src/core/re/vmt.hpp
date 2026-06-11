#pragma once

#include "re_common.hpp"

namespace re::vmt
{
tool_result_t read(const json& params);
tool_result_t hook_manage(const json& params);
tool_result_t copy(const json& params);
tool_result_t find_slot_by_signature(const json& params);
tool_result_t scan_objects(const json& params);
}
