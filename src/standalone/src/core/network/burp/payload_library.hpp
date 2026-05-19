#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace payloads {

struct payload_set_t
{
    std::string              id;
    std::string              label;
    std::string              description;
    std::vector<std::string> entries;
    bool                     builtin = false;
};

bool                       initialize();
void                       shutdown();

const payload_set_t*       get(const std::string& id);
std::vector<std::string>   list_ids();
std::vector<payload_set_t> list_summaries();

std::vector<std::string>   entries(const std::string& id, size_t max_count = 0);
std::vector<std::string>   search(const std::string& query, const std::string& set_id = std::string());

bool                       add_custom_set(const std::string& id,
                                          const std::string& label,
                                          const std::string& description,
                                          const std::vector<std::string>& entries);
bool                       remove_custom_set(const std::string& id);
bool                       load_from_file(const std::string& path, const std::string& id);
bool                       export_to_file(const std::string& path, const std::string& id);

bool                       set_exists(const std::string& id);

std::string                storage_dir();

std::string                last_error();

}
}
}
