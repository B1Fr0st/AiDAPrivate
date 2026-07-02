#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace content_scanner {

nlohmann::json scan_exchange(const exchange_observed_t& exchange,
                             const std::vector<std::string>& categories,
                             bool persist_findings);
nlohmann::json scan_url(const std::string& target_url,
                        const std::vector<std::string>& categories,
                        bool persist_findings,
                        std::string& error);
nlohmann::json scan_captured(const std::string& host_filter,
                             const std::vector<std::string>& categories,
                             bool persist_findings);
nlohmann::json detect_backups(const std::string& target_url,
                              std::uint32_t max_probes,
                              bool persist_findings,
                              std::string& error);
nlohmann::json detect_source_exposure(const std::string& target_url,
                                      std::uint32_t max_probes,
                                      bool persist_findings,
                                      std::string& error);

}
}
}
