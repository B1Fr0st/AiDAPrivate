#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "burp_events.hpp"

namespace aida {
namespace burp {
namespace api_definition {

enum class api_format_t : int
{
    auto_detect    = 0,
    openapi_json   = 1,
    openapi_yaml   = 2,
    swagger_v2     = 3,
    postman_v2_1   = 4,
    har            = 5,
    graphql_sdl    = 6
};

struct api_request_template_t
{
    std::string                                       id;
    std::string                                       method;
    std::string                                       base_url;
    std::string                                       path;
    std::vector<std::pair<std::string, std::string>>  headers;
    std::vector<std::pair<std::string, std::string>>  path_params;
    std::vector<std::pair<std::string, std::string>>  query_params;
    std::vector<std::pair<std::string, std::string>>  body_params;
    std::string                                       body_template;
    std::string                                       auth_kind;
    std::string                                       description;
    std::string                                       summary;
    std::vector<std::string>                          tags;
};

struct api_collection_t
{
    uint64_t                                id = 0;
    std::string                             name;
    api_format_t                            format = api_format_t::openapi_json;
    std::string                             source_path;
    std::string                             base_url;
    std::vector<api_request_template_t>     requests;
    uint64_t                                imported_ms = 0;
};

bool        initialize();
void        shutdown();

uint64_t    import_from_file(const std::string& path, api_format_t hint);
uint64_t    import_from_text(const std::string& text, api_format_t format);
uint64_t    import_from_url(const std::string& url);

std::vector<api_collection_t>   list_collections();
bool                            get_collection(uint64_t id, api_collection_t& out);
bool                            remove_collection(uint64_t id);
size_t                          collection_count();
void                            clear_all();

std::vector<uint8_t> render_to_raw_request(const api_request_template_t& tpl,
                                            const std::map<std::string, std::string>& path_values,
                                            const std::map<std::string, std::string>& query_values,
                                            const std::map<std::string, std::string>& header_values,
                                            const std::string& body_override);

struct audit_result_t
{
    uint64_t    audit_id = 0;
    size_t      requests_sent = 0;
    size_t      requests_failed = 0;
    size_t      issues_raised = 0;
    std::string status;
};

bool audit_entire_collection(uint64_t collection_id,
                              const std::map<std::string, std::string>& auth_values,
                              audit_result_t& out);

api_format_t    detect_format_from_path(const std::string& path);
api_format_t    detect_format_from_text(const std::string& text);
const char*     format_label(api_format_t f);
bool            parse_format(const std::string& s, api_format_t& out);

nlohmann::json  collection_to_json(const api_collection_t& c);
nlohmann::json  template_to_json(const api_request_template_t& t);

std::string     last_error();

}
}
}
