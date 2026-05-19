#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace aida {
namespace burp {
namespace session_handler {

struct extract_t
{
    std::string name;
    std::string from;
    std::string regex;
    int         group = 1;
};

struct macro_step_t
{
    std::string                 label;
    std::string                 scheme;
    std::string                 host;
    uint16_t                    port = 0;
    std::vector<uint8_t>        raw_request;
    int                         timeout_ms = 15000;
    std::vector<extract_t>      extracts;
};

struct macro_t
{
    uint64_t                                id = 0;
    std::string                             name;
    std::vector<macro_step_t>               steps;
    std::map<std::string, std::string>      last_extracted_values;
    uint64_t                                last_run_ms = 0;
    bool                                    ok_last_run = false;
};

enum class sh_match_t : int
{
    url_regex       = 0,
    response_status = 1,
    response_regex  = 2
};

struct session_rule_t
{
    uint64_t     id = 0;
    std::string  name;
    sh_match_t   match = sh_match_t::url_regex;
    std::string  match_pattern;
    int          match_status = 0;
    uint64_t     macro_id = 0;
    bool         replace_in_url = true;
    bool         replace_in_headers = true;
    bool         replace_in_body = true;
    bool         active = true;
};

bool                            initialize();
void                            shutdown();

uint64_t                        add_macro(macro_t m);
bool                            remove_macro(uint64_t id);
bool                            update_macro(const macro_t& m);
std::vector<macro_t>            list_macros();
bool                            get_macro(uint64_t id, macro_t& out);

bool                            run_macro(uint64_t id, std::map<std::string, std::string>& out_values);

uint64_t                        add_rule(session_rule_t r);
bool                            remove_rule(uint64_t id);
bool                            update_rule(const session_rule_t& r);
std::vector<session_rule_t>     list_rules();

bool                            apply_rules(std::vector<uint8_t>& raw_request,
                                            const std::string& url, int last_status);

const char*                     match_label(sh_match_t m);
bool                            parse_match(const std::string& s, sh_match_t& out);

std::string                     storage_path_macros();
std::string                     storage_path_rules();
bool                            save_to_disk();
bool                            load_from_disk();

std::string                     last_error();

}
}
}
