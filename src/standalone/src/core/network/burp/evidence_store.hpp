#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida {
namespace burp {
namespace evidence_store {

enum class evidence_kind_t
{
    request_response,
    screenshot,
    file,
    timing
};

struct evidence_capture_t
{
    uint64_t              finding_id = 0;
    std::string           session_id;
    uint64_t              scan_id = 0;
    evidence_kind_t       kind = evidence_kind_t::request_response;
    std::string           request_raw;
    std::string           response_raw;
    std::string           marker;
    uint64_t              marker_offset_request = 0;
    uint64_t              marker_offset_response = 0;
    std::string           description;
    uint64_t              exchange_id = 0;
    std::string           file_name;
    std::string           source_path;
    std::vector<uint8_t>  bytes;
    nlohmann::json        timing_json = nlohmann::json::object();
    nlohmann::json        metadata_json = nlohmann::json::object();
};

struct evidence_record_t
{
    uint64_t       id = 0;
    uint64_t       finding_id = 0;
    std::string    session_id;
    uint64_t       scan_id = 0;
    evidence_kind_t kind = evidence_kind_t::request_response;
    std::string    request_raw;
    std::string    response_raw;
    std::string    marker;
    uint64_t       marker_offset_request = 0;
    uint64_t       marker_offset_response = 0;
    std::string    screenshot_path;
    std::string    file_path;
    std::string    content_sha256;
    nlohmann::json timing_json = nlohmann::json::object();
    std::string    description;
    uint64_t       exchange_id = 0;
    uint64_t       captured_ms = 0;
    nlohmann::json metadata_json = nlohmann::json::object();
};

bool                   initialize();
void                   shutdown();
bool                   capture(const evidence_capture_t& capture, evidence_record_t& out);
bool                   capture_request_response(uint64_t finding_id, const std::string& request_raw, const std::string& response_raw, evidence_record_t& out, const std::string& session_id = std::string(), uint64_t scan_id = 0);
bool                   capture_screenshot(uint64_t finding_id, const std::vector<uint8_t>& image_bytes, const std::string& file_name, evidence_record_t& out, const std::string& session_id = std::string());
bool                   capture_file(uint64_t finding_id, const std::vector<uint8_t>& file_bytes, const std::string& file_name, evidence_record_t& out, const std::string& session_id = std::string());
bool                   capture_timing(uint64_t finding_id, const nlohmann::json& timing_json, evidence_record_t& out, const std::string& session_id = std::string());
std::vector<evidence_record_t> list_for_finding(uint64_t finding_id);
bool                   get(uint64_t evidence_id, evidence_record_t& out);
nlohmann::json         summary_json(const evidence_record_t& record);
nlohmann::json         export_json(uint64_t finding_id);
std::string            last_error();
std::string            storage_dir();
std::string            kind_to_string(evidence_kind_t kind);
evidence_kind_t        kind_from_string(const std::string& kind);
std::string            sha256_hex(const std::string& input);
std::string            sha256_hex(const std::vector<uint8_t>& input);
std::string            redact_sensitive_text(const std::string& input, size_t max_chars = 0);
nlohmann::json         redact_sensitive_json(const nlohmann::json& input, size_t max_string_chars = 0);

}
}
}
