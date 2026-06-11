#pragma once

#include "re_common.hpp"

namespace re::struct_adv
{
tool_result_t observe(const json& params);
tool_result_t correlate(const json& params);
tool_result_t array_detect(const json& params);
tool_result_t compare_snapshots(const json& params);
}
