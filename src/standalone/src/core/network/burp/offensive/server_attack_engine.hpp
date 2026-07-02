#pragma once

#include <nlohmann/json.hpp>

#include <string>

namespace aida {
namespace burp {
namespace offensive {
namespace server_attack {

struct action_result_t
{
    bool success = false;
    std::string message;
    std::string code;
    nlohmann::json data = nlohmann::json::object();
};

action_result_t handle_action(const std::string& action, const nlohmann::json& payload);
action_result_t get_status(const nlohmann::json& payload);
action_result_t get_results(const nlohmann::json& payload);

}
}
}
}
