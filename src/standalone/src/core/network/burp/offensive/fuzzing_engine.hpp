#pragma once

#include "../../../mcp/mcp_standalone.hpp"

namespace aida {
namespace burp {
namespace offensive {
namespace fuzzing {

mcp_standalone::tool_result_t start(const nlohmann::json& params);
mcp_standalone::tool_result_t stop(const nlohmann::json& params);
mcp_standalone::tool_result_t status(const nlohmann::json& params);
mcp_standalone::tool_result_t results(const nlohmann::json& params);
mcp_standalone::tool_result_t mutate(const nlohmann::json& params);
mcp_standalone::tool_result_t corpus_add(const nlohmann::json& params);
mcp_standalone::tool_result_t anomaly_analyze(const nlohmann::json& params);

}
}
}
}
