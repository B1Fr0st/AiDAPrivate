#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "multibinary_project.hpp"

namespace aida
{
namespace multibinary
{

constexpr const char* k_index_schema = "aida.multibinary.index";
constexpr const char* k_cross_edges_schema = "aida.multibinary.cross_edges";

struct index_build_options_t
{
    bool force = false;
    std::size_t max_functions = 200000;
    std::size_t max_edges = 1000000;
    std::size_t max_imports = 100000;
    std::size_t max_exports = 100000;
    std::size_t page_size = 4096;
    std::size_t max_deep_summaries = 256;
};

index_build_options_t index_options_from_json(const nlohmann::json& value);
project_io_result_t build_current_module_index(const std::string& requested_project_id,
                                               const nlohmann::json& indices,
                                               const index_build_options_t& options);
project_io_result_t load_function_catalog(const std::string& project_id, const std::string& module_id);
project_io_result_t save_function_catalog(const std::string& project_id,
                                          const std::string& module_id,
                                          const nlohmann::json& catalog);
project_io_result_t resolve_project_cross_edges(const std::string& project_id);
project_io_result_t load_project_cross_edges(const std::string& project_id);
project_io_result_t resolve_project_reference(const std::string& project_id,
                                              const nlohmann::json& reference);
project_io_result_t load_index_page(const std::string& project_id,
                                    const std::string& module_id,
                                    const std::string& family,
                                    const std::string& cursor,
                                    std::size_t page_index);
project_io_result_t index_page_status(const std::string& project_id,
                                      const std::string& module_id = std::string());
project_io_result_t index_status(const std::string& project_id);

}
}
