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

std::filesystem::path intercept_root();
std::filesystem::path ca_export_root();
public_ca_export_t export_public_ca_files(const cert_generator::root_ca_t& ca);

}
}
