#include "decompiler_provider_matrix/provider_matrix.hpp"
#include "decompiler_quality_scorer_harness.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

std::filesystem::path absolute_path(const char* value) {
    std::error_code error;
    auto path = std::filesystem::absolute(std::filesystem::u8path(value), error);
    if (error || path.empty())
        throw std::runtime_error("quality pipeline path resolution failed");
    return path.lexically_normal();
}

std::uint64_t parse_deadline(const char* value) {
    std::uint64_t result = 0;
    const std::string_view text(value);
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        result < 1000 || result > 3600000)
        throw std::runtime_error("quality pipeline deadline is invalid");
    return result;
}

std::filesystem::path verified_file(const std::filesystem::path& path,
    const std::uint64_t maximum) {
    std::error_code error;
    const auto link_status = std::filesystem::symlink_status(path, error);
    if (error || std::filesystem::is_symlink(link_status))
        throw std::runtime_error("quality pipeline file is a symbolic link");
    const auto canonical = std::filesystem::canonical(path, error);
    if (error || !std::filesystem::is_regular_file(canonical, error) || error)
        throw std::runtime_error("quality pipeline file is missing or unsafe");
    const auto size = std::filesystem::file_size(canonical, error);
    if (error || size == 0 || size > maximum)
        throw std::runtime_error("quality pipeline file violates its size contract");
    return canonical;
}

std::filesystem::path current_executable() {
    std::vector<wchar_t> buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
        static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= static_cast<DWORD>(buffer.size()))
        throw std::runtime_error("quality pipeline executable identity is unavailable");
    return verified_file(std::filesystem::path(std::wstring(buffer.data(), length)),
        256ULL * 1024ULL * 1024ULL);
}

}

int main(int argc, char** argv) {
    try {
        if (argc != 7) {
            std::cerr << "usage: c03_decompiler_quality_pipeline <repository-root> <evidence-root> <runtime-root> <materialized-root> <output-root> <deadline-ms>\n";
            return 2;
        }
        const auto repository_root = absolute_path(argv[1]);
        const auto evidence_root = absolute_path(argv[2]);
        const auto runtime_root = absolute_path(argv[3]);
        const auto materialized_root = absolute_path(argv[4]);
        const auto output_root = absolute_path(argv[5]);
        const auto deadline_ms = parse_deadline(argv[6]);
        aida::analysis::c03::provider_matrix::matrix_config_t config;
        config.repository_root = repository_root;
        config.runtime_root = runtime_root;
        config.materialized_root = materialized_root;
        config.output_root = output_root;
        config.provider = aida::analysis::c03::provider_matrix::provider_selection_t::all;
        config.deadline_ms = deadline_ms;
        const auto matrix = aida::analysis::c03::provider_matrix::run(config);
        if (matrix.exit_code != 0) {
            std::cerr << matrix.error << '\n';
            return matrix.exit_code;
        }
        if (matrix.output_files.size() != 4)
            throw std::runtime_error("quality provider matrix returned an invalid output count");
        const std::set<std::filesystem::path> expected{
            verified_file(output_root / "materialization.receipt.json", 16ULL * 1024ULL * 1024ULL),
            verified_file(output_root / "candidate.results.json", 128ULL * 1024ULL * 1024ULL),
            verified_file(output_root / "ghidra-printc.results.json", 128ULL * 1024ULL * 1024ULL),
            verified_file(output_root / "aida-current.results.json", 128ULL * 1024ULL * 1024ULL)};
        std::set<std::filesystem::path> observed;
        for (const auto& path : matrix.output_files)
            observed.insert(verified_file(path, 128ULL * 1024ULL * 1024ULL));
        if (observed != expected)
            throw std::runtime_error("quality provider matrix returned a noncanonical output inventory");
        aida::analysis::c03::quality_harness_paths_t paths;
        paths.repository_root = repository_root;
        paths.evidence_root = evidence_root;
        paths.harness_binary = current_executable();
        paths.provider_matrix_binary = paths.harness_binary;
        paths.runtime_root = runtime_root;
        paths.candidate_results = output_root / "candidate.results.json";
        paths.ghidra_printc_results = output_root / "ghidra-printc.results.json";
        paths.aida_current_results = output_root / "aida-current.results.json";
        std::string failure;
        if (!aida::analysis::c03::run_decompiler_quality_scorer_harness(paths, failure)) {
            std::cerr << failure << '\n';
            return 1;
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 3;
    }
}
