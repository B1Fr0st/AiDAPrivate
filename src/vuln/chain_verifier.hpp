#pragma once

#include <string>

#include <nlohmann/json.hpp>

#include "../multibinary_project.hpp"

namespace aida
{
namespace vuln
{
namespace chain_verifier
{

constexpr const char* k_project_chain_verifier_schema = "aida.multibinary.chain_verifier.v1";

multibinary::project_io_result_t verify_project_chain(const std::string& requested_project_id,
                                                      const nlohmann::json& chain,
                                                      const nlohmann::json& options = nlohmann::json::object());
multibinary::project_io_result_t run_case_study_regressions(const std::string& requested_project_id,
                                                            const nlohmann::json& payload);

}
}
}
