#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace offensive {
namespace xss {

struct engine_result_t
{
    bool ok = true;
    std::string message;
    std::string code;
    nlohmann::json data = nlohmann::json::object();
};

engine_result_t detect(const nlohmann::json& params);
engine_result_t generate_payloads(const nlohmann::json& params);
engine_result_t test_csp_bypass(const nlohmann::json& params);
engine_result_t dom_analyze(const nlohmann::json& params);
engine_result_t stored_scan(const nlohmann::json& params);
engine_result_t context_probe(const nlohmann::json& params);
engine_result_t get_status(const nlohmann::json& params);
engine_result_t get_results(const nlohmann::json& params);

}
}
}
}
