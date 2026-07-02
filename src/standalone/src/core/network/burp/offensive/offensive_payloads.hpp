#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace offensive {
namespace payloads {

struct payload_entry_t
{
    std::string value;
    std::string set_id;
    std::string technique;
};

bool ensure_available();

std::vector<std::string> sqli_set_ids();
std::vector<std::string> xss_set_ids();

std::vector<payload_entry_t> sqli_payloads(const std::vector<std::string>& techniques,
                                           const std::string& dbms,
                                           std::size_t max_count);

std::vector<payload_entry_t> xss_payloads(const std::string& context,
                                          const std::string& filter,
                                          const std::string& marker,
                                          std::size_t max_count);

nlohmann::json inventory();

}
}
}
}
