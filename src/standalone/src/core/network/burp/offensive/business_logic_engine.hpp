#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {
namespace offensive {
namespace business_logic {

struct result_t
{
    bool success = false;
    std::string message;
    nlohmann::json data;
    std::string error_code;
};

result_t handle_action(const std::string& action, const nlohmann::json& payload);
result_t race_test(const nlohmann::json& payload);
result_t price_tamper(const nlohmann::json& payload);
result_t coupon_abuse(const nlohmann::json& payload);
result_t workflow_bypass(const nlohmann::json& payload);
result_t quantity_tamper(const nlohmann::json& payload);
result_t role_escalation(const nlohmann::json& payload);
result_t get_status(const nlohmann::json& payload);
result_t get_results(const nlohmann::json& payload);

}
}
}
}
