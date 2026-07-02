#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace tls_analyzer {

nlohmann::json analyze_host(const std::string& host,
                            std::uint16_t port,
                            bool check_chain,
                            bool check_ct_logs,
                            bool persist_findings,
                            std::string& error);

}
}
}
