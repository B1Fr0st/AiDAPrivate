#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace offensive {
namespace js_analysis {

nlohmann::json extract_endpoints(const nlohmann::json& params);
nlohmann::json extract_secrets(const nlohmann::json& params);
nlohmann::json source_map_analyze(const nlohmann::json& params);
nlohmann::json deobfuscate(const nlohmann::json& params);
nlohmann::json framework_detect(const nlohmann::json& params);
nlohmann::json dependency_audit(const nlohmann::json& params);
nlohmann::json get_status(const nlohmann::json& params);
nlohmann::json get_results(const nlohmann::json& params);
nlohmann::json report_context(const std::string& target_domain, const std::vector<std::string>& run_ids);
std::string last_error();

}
}
}
}
