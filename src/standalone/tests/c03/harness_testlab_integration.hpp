#pragma once

#include <filesystem>
#include <string>

namespace aida::analysis::c03_test {

struct testlab_integration_paths_t {
	std::filesystem::path fake_adapter_path;
	std::filesystem::path scratch_root;
};

bool run_testlab_integration_harness(const testlab_integration_paths_t& paths, std::string& failure);

}
