#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "chain_report.hpp"
#include "chain_schema.hpp"

namespace aida
{
namespace vuln
{
namespace chain
{

struct chain_store_status_t
{
    bool ok = false;
    std::string action;
    std::string path;
    std::uint64_t bytes = 0;
    bool migrated = false;
    validation_result_t validation;
};

struct chain_document_load_result_t
{
    bool ok = false;
    bool migrated = false;
    std::string path;
    chain_document_t document;
    nlohmann::json raw = nlohmann::json::object();
    validation_result_t validation;
};

struct chain_report_load_result_t
{
    bool ok = false;
    std::string path;
    chain_report_t report;
    nlohmann::json raw = nlohmann::json::object();
    validation_result_t validation;
};

struct chain_ledger_record_t
{
    std::string record_id;
    std::string chain_id;
    std::string report_id;
    std::string document_id;
    chain_verdict_t verdict = chain_verdict_t::inconclusive;
    report_acceptance_t acceptance = report_acceptance_t::blocked;
    std::uint64_t updated_at_ms = 0;
    nlohmann::json summary = nlohmann::json::object();
};

struct chain_ledger_result_t
{
    bool ok = false;
    std::string action;
    std::uint64_t bytes = 0;
    std::uint64_t pages = 0;
    std::vector<chain_ledger_record_t> records;
    validation_result_t validation;
};

struct chain_json_record_load_result_t
{
    bool ok = false;
    std::string action;
    std::string path;
    nlohmann::json record = nlohmann::json::object();
    validation_result_t validation;
};

struct chain_json_record_list_result_t
{
    bool ok = false;
    std::string action;
    std::string path;
    std::uint64_t bytes = 0;
    std::vector<nlohmann::json> records;
    validation_result_t validation;
};

nlohmann::json to_json(const chain_store_status_t& value);
nlohmann::json to_json(const chain_document_load_result_t& value);
nlohmann::json to_json(const chain_report_load_result_t& value);
nlohmann::json to_json(const chain_ledger_record_t& value);
nlohmann::json to_json(const chain_ledger_result_t& value);
nlohmann::json to_json(const chain_json_record_load_result_t& value);
nlohmann::json to_json(const chain_json_record_list_result_t& value);

bool from_json(const nlohmann::json& value, chain_ledger_record_t& out, validation_result_t& errors, const std::string& path);

std::string chain_store_root();
std::string chain_project_root(const std::string& project_id);
std::string sanitize_store_component(const std::string& value);

chain_store_status_t save_chain_document(const std::string& project_id, const chain_document_t& document);
chain_document_load_result_t load_chain_document(const std::string& project_id, const std::string& chain_id);
chain_store_status_t save_chain_report(const std::string& project_id, const chain_report_t& report);
chain_report_load_result_t load_chain_report(const std::string& project_id, const std::string& report_id);
chain_store_status_t save_chain_job_record(const std::string& project_id, const std::string& job_id, const nlohmann::json& record);
chain_json_record_load_result_t load_chain_job_record(const std::string& project_id, const std::string& job_id);
chain_json_record_list_result_t list_chain_job_records(const std::string& project_id);
chain_store_status_t delete_chain_job_record(const std::string& project_id, const std::string& job_id);
chain_store_status_t save_chain_report_record(const std::string& project_id, const std::string& report_id, const nlohmann::json& record);
chain_json_record_load_result_t load_chain_report_record(const std::string& project_id, const std::string& report_id);
chain_json_record_list_result_t list_chain_report_records(const std::string& project_id);
chain_store_status_t delete_chain_report_record(const std::string& project_id, const std::string& report_id);

chain_ledger_record_t ledger_record_from_report(const chain_report_t& report);
chain_ledger_result_t chain_ledger_save(const chain_ledger_record_t& record);
chain_ledger_result_t chain_ledger_load();
chain_ledger_result_t chain_ledger_clear();
validation_result_t chain_store_self_check();

}
}
}
