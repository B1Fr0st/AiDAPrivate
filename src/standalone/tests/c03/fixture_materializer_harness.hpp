#pragma once

#include <filesystem>
#include <string>

namespace aida::analysis::c03
{
    bool run_fixture_materializer_harness(const std::filesystem::path& repository_root,
        const std::filesystem::path& output_root, std::string& failure);
}
