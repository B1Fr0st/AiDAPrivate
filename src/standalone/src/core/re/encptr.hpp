#pragma once

#include "re_common.hpp"

namespace re::encptr
{
tool_result_t scan_chain(const json& params);
tool_result_t detect_transform(const json& params);
tool_result_t emit_resolver(const json& params);
tool_result_t verify_stable(const json& params);
}
