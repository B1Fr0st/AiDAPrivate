#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace match_replace {

enum class match_kind_t : int
{
    request_url      = 0,
    request_headers  = 1,
    request_body     = 2,
    response_headers = 3,
    response_body    = 4,
    all              = 5
};

struct rule_t
{
    uint64_t        id = 0;
    std::string     label;
    match_kind_t    target = match_kind_t::request_url;
    std::string     match_regex;
    std::string     replacement;
    bool            regex = true;
    bool            case_insensitive = false;
    bool            active = true;
    std::string     host_filter;
    std::string     scheme_filter;
    uint64_t        hit_count = 0;
};

bool                 initialize();
void                 shutdown();

uint64_t             add(rule_t r);
bool                 update(const rule_t& r);
bool                 remove(uint64_t id);
std::vector<rule_t>  list();
void                 clear();
bool                 move(uint64_t id, int delta);

bool                 apply_request(std::vector<uint8_t>& raw_request, const std::string& host, const std::string& scheme);
bool                 apply_response(std::vector<uint8_t>& raw_response, const std::string& host, const std::string& scheme);

bool                 apply_text(std::string& text, match_kind_t target,
                                const std::string& host, const std::string& scheme,
                                size_t* rules_applied = nullptr);

bool                 test_rule(const rule_t& r, const std::string& sample, std::string& out);

bool                 save_to_disk();
bool                 load_from_disk();
std::string          storage_path();

const char*          target_label(match_kind_t k);
bool                 parse_target(const std::string& s, match_kind_t& out);

std::string          last_error();

}
}
}
