#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace graphql {

struct gql_field_t
{
    std::string                                       name;
    std::string                                       type_str;
    std::vector<std::pair<std::string, std::string>>  args;
    std::string                                       description;
};

struct gql_type_t
{
    std::string                  name;
    std::string                  kind;
    std::vector<gql_field_t>     fields;
    std::vector<std::string>     interfaces;
    std::vector<std::string>     enum_values;
};

struct gql_schema_t
{
    std::vector<gql_type_t>  types;
    std::string              query_type;
    std::string              mutation_type;
    std::string              subscription_type;
};

bool introspect(const std::string& endpoint,
                const std::map<std::string, std::string>& headers,
                gql_schema_t& out,
                std::string& raw_response);

std::string build_example_query(const gql_schema_t& schema, const std::string& field_name, int depth);
std::string build_batched_query(const std::string& operation, size_t batch_count);
std::string beautify_query(const std::string& source);
std::string minify_query(const std::string& source);

bool send_query(const std::string& endpoint,
                const std::map<std::string, std::string>& headers,
                const std::string& query,
                const nlohmann::json& variables,
                nlohmann::json& response_json,
                std::string& raw_text);

nlohmann::json schema_to_json(const gql_schema_t& s);

std::string last_error();

bool        cache_schema(const std::string& endpoint, const gql_schema_t& schema);
bool        get_cached_schema(const std::string& endpoint, gql_schema_t& out);
bool        has_cached_schema(const std::string& endpoint);

}
}
}
