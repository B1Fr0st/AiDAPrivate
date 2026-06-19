#pragma once

#include <cstdint>
#include <mutex>
#include <regex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace scope {

enum class rule_kind_t : int
{
    include = 0,
    exclude = 1
};

struct rule_t
{
    uint64_t    id = 0;
    rule_kind_t kind = rule_kind_t::include;
    std::string protocol;
    std::string host_pattern;
    int         port = 0;
    std::string path_prefix;
    bool        enabled = true;
};

struct parsed_url_t
{
    std::string scheme;
    std::string host;
    uint16_t    port = 0;
    std::string path;
    bool        valid = false;
};

bool initialize();
void shutdown();

parsed_url_t parse_url(const std::string& url);
bool        in_scope(const std::string& url);
bool        in_scope_components(const std::string& scheme, const std::string& host, uint16_t port, const std::string& path);
uint64_t    add_include_rule(const std::string& protocol, const std::string& host_pattern, int port, const std::string& path_prefix);
uint64_t    add_exclude_rule(const std::string& protocol, const std::string& host_pattern, int port, const std::string& path_prefix);
uint64_t    add_rule(const rule_t& r);
bool        remove_rule(uint64_t rule_id);
bool        set_rule_enabled(uint64_t rule_id, bool enabled);
void        clear_all();
std::vector<rule_t> list_rules();
bool        load_from_disk();
bool        save_to_disk();
std::string storage_path();

nlohmann::json rule_to_json(const rule_t& r);
bool           rule_from_json(const nlohmann::json& j, rule_t& out);

void render(float pos_x, float pos_y, float width, float height,
            float alpha, float accent_r, float accent_g, float accent_b);

std::string last_error();

}
}
}
