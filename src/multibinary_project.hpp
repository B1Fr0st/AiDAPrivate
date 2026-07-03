#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "vuln/chain_binary_corpus.hpp"

namespace aida
{
namespace multibinary
{

constexpr const char* k_project_schema = "aida.multibinary.project";
constexpr const char* k_module_schema = "aida.multibinary.module";
constexpr int k_project_schema_version = 1;

struct project_io_result_t
{
    bool ok = false;
    std::string error_code;
    std::string error_message;
    nlohmann::json data = nlohmann::json::object();
};

struct project_lock_t
{
    std::string project_id;
    std::string lock_path;
    bool acquired = false;
    bool stale_recovered = false;
    std::string error_code;
    std::string error_message;

    project_lock_t() = default;
    explicit project_lock_t(std::string id);
    project_lock_t(const project_lock_t&) = delete;
    project_lock_t& operator=(const project_lock_t&) = delete;
    project_lock_t(project_lock_t&& other) noexcept;
    project_lock_t& operator=(project_lock_t&& other) noexcept;
    ~project_lock_t();

    bool acquire(bool force = false);
    void release();
};

std::uint64_t now_ms();
std::string stable_hash_hex(const std::string& text);
std::string sanitize_id_component(const std::string& text);
std::string canonical_module_id_from_hashes(const std::string& sha256,
                                             const std::string& md5,
                                             const std::string& canonical_name,
                                             const std::string& input_path);
std::string canonical_module_id_from_json(const nlohmann::json& module);
std::string projects_root();
std::string project_root(const std::string& project_id);
std::string default_project_id_for_current_idb();

bool ensure_project_dirs(const std::string& project_id, std::string* error = nullptr);
project_io_result_t load_project_manifest(const std::string& project_id);
project_io_result_t save_project_manifest(const std::string& project_id, const nlohmann::json& manifest);
project_io_result_t delete_project(const std::string& project_id);
project_io_result_t list_projects();
project_io_result_t project_status(const std::string& project_id);

nlohmann::json canonical_address_json(const std::string& module_id,
                                      std::uint64_t rva,
                                      std::uint64_t ea_hint = 0,
                                      const std::string& segment = std::string(),
                                      std::uint64_t segment_start_rva = 0,
                                      std::uint64_t segment_offset = 0,
                                      const std::string& confidence = "exact");
nlohmann::json canonical_address_from_chain(const vuln::chain::canonical_address_t& address);
nlohmann::json canonical_module_record_from_corpus(const vuln::chain::corpus_record_t& corpus,
                                                   const nlohmann::json& instance,
                                                   const nlohmann::json& extra = nlohmann::json::object());
nlohmann::json current_idb_inventory(bool include_segments,
                                     bool include_imports,
                                     bool include_entries,
                                     std::size_t max_rows);
nlohmann::json merge_inventory_documents(const nlohmann::json& local_inventory,
                                         const nlohmann::json& supplied);
nlohmann::json normalize_module_record(const nlohmann::json& module);
nlohmann::json merge_modules(const nlohmann::json& existing_modules,
                             const nlohmann::json& incoming_modules);
nlohmann::json missing_modules_from_imports(const nlohmann::json& modules);
project_io_result_t save_or_update_project(const std::string& requested_project_id,
                                           const nlohmann::json& modules,
                                           const nlohmann::json& options);
project_io_result_t bind_current_inventory_to_project(const std::string& requested_project_id,
                                                      const nlohmann::json& local_inventory,
                                                      const nlohmann::json& supplied_inventory,
                                                      const nlohmann::json& options);
project_io_result_t load_project_modules(const std::string& project_id);
project_io_result_t write_module_record(const std::string& project_id,
                                        const nlohmann::json& module);
nlohmann::json content_hash_summary(const nlohmann::json& value);

}
}
