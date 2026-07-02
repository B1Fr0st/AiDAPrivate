#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace offensive {
namespace recon {

nlohmann::json fingerprint(const nlohmann::json& params);
nlohmann::json waf_detect(const nlohmann::json& params);
nlohmann::json dns_enum(const nlohmann::json& params);
nlohmann::json s3_discovery(const nlohmann::json& params);
nlohmann::json cloud_metadata_test(const nlohmann::json& params);
nlohmann::json port_scan(const nlohmann::json& params);
nlohmann::json full_recon(const nlohmann::json& params);
nlohmann::json get_status(const nlohmann::json& params);
nlohmann::json report_context(const std::string& target_domain, const std::vector<std::string>& run_ids, bool include_recon);
std::string last_error();

}
}
}
}
