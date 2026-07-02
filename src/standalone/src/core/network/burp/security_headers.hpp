#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace security_headers {

nlohmann::json analyze_exchange(const exchange_observed_t& exchange, bool persist_findings);
nlohmann::json analyze_url(const std::string& target_url, bool check_all_paths, bool persist_findings, std::string& error);
nlohmann::json audit_cookies_for_host(const std::string& host, bool scan_all_paths, bool persist_findings, std::string& error);
std::string grade_for_score(int score);

}
}
}
