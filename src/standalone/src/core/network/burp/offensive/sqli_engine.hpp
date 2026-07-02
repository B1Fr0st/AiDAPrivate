#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace offensive {
namespace sqli {

struct engine_result_t
{
    bool ok = true;
    std::string message;
    std::string code;
    nlohmann::json data = nlohmann::json::object();
};

engine_result_t detect(const nlohmann::json& params);
engine_result_t enumerate_schemas(const nlohmann::json& params);
engine_result_t enumerate_tables(const nlohmann::json& params);
engine_result_t enumerate_columns(const nlohmann::json& params);
engine_result_t extract_data(const nlohmann::json& params);
engine_result_t os_command(const nlohmann::json& params);
engine_result_t waf_identify(const nlohmann::json& params);
engine_result_t waf_bypass(const nlohmann::json& params);
engine_result_t fingerprint_db(const nlohmann::json& params);
engine_result_t get_status(const nlohmann::json& params);
engine_result_t get_results(const nlohmann::json& params);

}
}
}
}
