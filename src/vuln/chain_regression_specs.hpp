#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

struct chain_regression_spec_t
{
    std::string suite;
    std::string case_id;
    nlohmann::json document = nlohmann::json::object();
    nlohmann::json expected = nlohmann::json::object();
};

std::vector<chain_regression_spec_t> universal_chain_regression_specs();
std::vector<nlohmann::json> universal_chain_regression_documents();

}
}
}
