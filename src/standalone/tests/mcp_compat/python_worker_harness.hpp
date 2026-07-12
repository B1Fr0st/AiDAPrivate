#pragma once

#include <filesystem>
#include <string>

namespace aida::standalone::tests::mcp_compat {

bool run_python_worker_harness(std::string& failure, const std::filesystem::path& fake_worker_path);

}
