#include "core/testlab/test_lab_features_c03_safe_headless.hpp"

#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: aida_c03_safe_headless_manifest_suite <approved-root>\n";
        return 2;
    }
    const auto root = std::filesystem::absolute(std::filesystem::u8path(argv[1])).lexically_normal();
    const auto loaded = test_lab::c03_safe_headless::load_manifest(
        root, root / "manifest.json");
    if (!loaded.accepted) {
        std::cerr << loaded.error << '\n';
        return 1;
    }
    const auto result = test_lab::c03_safe_headless::execute_manifest(root, loaded);
    std::cout << test_lab::c03_safe_headless::serialize_suite_result(result) << '\n';
    return result.not_run == 0 && result.missing == 0 && result.failed == 0 &&
        result.timed_out == 0 && result.crashed == 0 && result.cancelled == 0 &&
        result.malformed_result == 0 && result.integrity_failure == 0 &&
        result.passed == loaded.manifest.entries.size() ? 0 : 1;
}
