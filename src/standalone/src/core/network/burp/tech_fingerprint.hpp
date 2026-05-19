#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace aida {
namespace burp {
namespace tech {

struct tech_t
{
    std::string name;
    std::string category;
    std::string version;
    std::string confidence_label;
};

struct host_inventory_t
{
    std::string                 host;
    std::vector<tech_t>         technologies;
};

bool initialize();
void shutdown();

std::vector<tech_t> fingerprint(const std::vector<std::pair<std::string, std::string>>& response_headers,
                                const std::vector<uint8_t>& response_body,
                                const std::string& url);

std::vector<host_inventory_t> inventory();
void                          clear_inventory();
std::string                   last_error();

}
}
}
