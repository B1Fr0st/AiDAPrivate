#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_binary_corpus.hpp"
#include "chain_model.hpp"
#include "chain_state.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

struct chain_document_t
{
    std::string schema = k_chain_document_schema;
    int version = k_chain_document_version;
    std::string chain_id;
    std::string title;
    target_model_t target;
    std::vector<corpus_record_t> corpus;
    nlohmann::json entry = nlohmann::json::object();
    nlohmann::json objects = nlohmann::json::array();
    nlohmann::json inputs = nlohmann::json::array();
    nlohmann::json events = nlohmann::json::array();
    std::vector<fact_t> facts;
    std::vector<assumption_t> assumptions;
    std::vector<link_spec_t> links;
    std::vector<objective_spec_t> objectives;
    verification_policy_t policies;
    trace_state_t initial_state;
    nlohmann::json metadata = nlohmann::json::object();
};

struct parse_chain_document_result_t
{
    bool ok = false;
    bool migrated = false;
    chain_document_t document;
    validation_result_t validation;
    nlohmann::json normalized = nlohmann::json::object();
};

nlohmann::json to_json(const chain_document_t& value);
bool from_json(const nlohmann::json& value, chain_document_t& out, validation_result_t& errors, const std::string& path);
parse_chain_document_result_t parse_chain_document(const nlohmann::json& value);
validation_result_t validate_chain_document(const chain_document_t& value);
nlohmann::json migrate_chain_document_json(const nlohmann::json& value, validation_result_t& errors);
nlohmann::json chain_document_json_schema();
validation_result_t chain_schema_self_check();

}
}
}
