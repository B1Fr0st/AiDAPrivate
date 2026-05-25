#pragma once

#include "../cert_generator.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace cert_intercept {
namespace profiles {

struct public_ca_export_t {
    bool ok = false;
    std::filesystem::path directory;
    std::filesystem::path pem_path;
    std::filesystem::path der_path;
    std::string error;
};

struct firefox_profile_status_t {
    bool ok = false;
    bool prepared = false;
    bool firefox_detected = false;
    bool ca_exported = false;
    bool enterprise_roots_enabled = false;
    bool policy_install_declared = false;
    bool proxy_configured = false;
    bool http3_disabled = false;
    bool profile_files_valid = false;
    bool ca_files_nonempty = false;
    bool current_user_ca_trusted = false;
    bool trust_readiness_verified = false;
    bool runtime_validation_performed = false;
    bool runtime_validation_valid = false;
    bool post_launch_profile_validated = false;
    bool launched = false;
    uint32_t launched_pid = 0;
    std::string firefox_path;
    std::filesystem::path profile_path;
    std::filesystem::path user_js_path;
    std::filesystem::path policies_path;
    std::filesystem::path ca_pem_path;
    std::filesystem::path ca_der_path;
    std::string proxy_endpoint;
    std::string launch_arguments;
    std::string error;
    std::vector<std::string> notes;
};

std::filesystem::path intercept_root();
std::filesystem::path ca_export_root();
std::filesystem::path firefox_profile_root();

bool detect_firefox_path(std::string& out_path);
public_ca_export_t export_public_ca_files(const cert_generator::root_ca_t& ca);
firefox_profile_status_t prepare_firefox_profile(const cert_generator::root_ca_t& ca,
                                                 const std::string& proxy_host,
                                                 uint16_t proxy_port);
firefox_profile_status_t inspect_firefox_profile();
firefox_profile_status_t launch_firefox_profile(const firefox_profile_status_t& prepared_status);

}
}
