#pragma once

#include "diagnostics.hpp"
#include "instrumentation_provider.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace cert_intercept {

struct handoff_request_t {
    process_diagnostics_t diagnostics;
    std::vector<provider_status_t> provider_statuses;
    std::string target_label;
    std::string proxy_endpoint;
    std::string ca_cert_pem_path;
    std::string ca_cert_der_path;
    bool include_module_paths = true;
};

struct handoff_result_t {
    bool ok = false;
    std::filesystem::path directory;
    std::filesystem::path metadata_path;
    std::vector<std::filesystem::path> script_paths;
    std::string error;
};

std::filesystem::path default_handoff_root();
handoff_result_t generate_handoff(const handoff_request_t& request);

}
