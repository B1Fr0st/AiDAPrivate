#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace vuln_taxonomy {

struct cvss_result_t
{
    bool        valid = false;
    double      score = 0.0;
    std::string severity;
    std::string vector;
    std::string error;
};

struct taxonomy_mapping_t
{
    std::string              type_key;
    std::string              owasp_category;
    std::vector<std::string> cwe_ids;
    std::vector<std::string> cwe_names;
    std::string              default_cvss_vector;
};

cvss_result_t       calculate_cvss31(const std::string& vector);
std::string         cvss_severity(double score);
taxonomy_mapping_t  mapping_for_type(const std::string& type_key);
std::string         cwe_name(const std::string& cwe_id);
nlohmann::json      mapping_to_json(const taxonomy_mapping_t& mapping);
nlohmann::json      score_to_json(const std::string& type_key, const std::string& vector_override = std::string());

}
}
}
