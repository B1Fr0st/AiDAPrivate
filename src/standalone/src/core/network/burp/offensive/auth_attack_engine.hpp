#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {
namespace offensive {
namespace auth_attack {

struct result_t
{
    bool success = false;
    std::string message;
    nlohmann::json data;
    std::string error_code;
};

result_t handle_action(const std::string& action, const nlohmann::json& payload);
result_t brute_force(const nlohmann::json& payload);
result_t credential_stuffing(const nlohmann::json& payload);
result_t session_analysis(const nlohmann::json& payload);
result_t idor_test(const nlohmann::json& payload);
result_t bola_test(const nlohmann::json& payload);
result_t password_policy(const nlohmann::json& payload);
result_t mfa_bypass_check(const nlohmann::json& payload);
result_t get_status(const nlohmann::json& payload);
result_t get_results(const nlohmann::json& payload);

}
}
}
}
