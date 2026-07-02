#pragma once

#include <cstddef>
#include <string>

#include <nlohmann/json.hpp>

#include "../mcp/mcp_standalone.hpp"

namespace aida {
namespace network {
namespace js_analysis_tools {

std::string sha256_hex(const std::string& value);
std::string redact_url_for_output(const std::string& url);
std::string redact_sensitive_values(const std::string& text);
nlohmann::json extract_endpoints_from_source(const std::string& source,
                                             const std::string& source_label,
                                             bool include_relative,
                                             std::size_t max_results);
nlohmann::json extract_redacted_secrets_from_source(const std::string& source,
                                                    const std::string& source_label,
                                                    double min_confidence,
                                                    std::size_t max_results,
                                                    const nlohmann::json& custom_patterns);
void register_js_analysis_tools(mcp_standalone::server_t& srv);

}
}
}
