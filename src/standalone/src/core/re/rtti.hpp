#pragma once

#include "re_common.hpp"

namespace re::rtti
{
tool_result_t scan(const json& params);
tool_result_t find_type(const json& params);
tool_result_t list_hierarchy(const json& params);
tool_result_t find_constructor(const json& params);
}
