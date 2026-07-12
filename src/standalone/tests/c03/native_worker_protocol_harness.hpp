#pragma once

#include <filesystem>
#include <string>

namespace aida::analysis::c03_test {

struct native_worker_host_harness_paths_t {
    std::filesystem::path fake_worker_path;
    std::filesystem::path scratch_root;
};

bool run_native_worker_protocol_harness(std::string& failure);
bool run_native_worker_host_harness(const native_worker_host_harness_paths_t& paths, std::string& failure);

}
