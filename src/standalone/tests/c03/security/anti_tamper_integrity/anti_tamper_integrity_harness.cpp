#include "anti_tamper_integrity_harness.hpp"
#include "../../assertion_telemetry/assertion_telemetry.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace aida::c03::security
{
namespace
{
std::string read_source(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    const bool opened = static_cast<bool>(input);
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		opened, "anti-tamper policy source opened", __FILE__, __LINE__);
    if (!opened)
        throw std::runtime_error("source_open_failed:" + path.string());
    std::ostringstream content;
    content << input.rdbuf();
    const bool complete = input.good() || input.eof();
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		complete, "anti-tamper policy source read completed", __FILE__, __LINE__);
    if (!complete)
        throw std::runtime_error("source_read_failed:" + path.string());
    return content.str();
}

bool require_absent(const std::string& source, std::string_view token,
    std::string& failure)
{
    const bool absent = source.find(token) == std::string::npos;
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		absent, token, __FILE__, __LINE__);
    if (absent)
        return true;
    failure = "forbidden_source_token_present:" + std::string(token);
    return false;
}

bool require_present(const std::string& source, std::string_view token,
    std::string& failure)
{
    const bool present = source.find(token) != std::string::npos;
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		present, token, __FILE__, __LINE__);
    if (present)
        return true;
    failure = "required_source_token_missing:" + std::string(token);
    return false;
}
}

bool run_anti_tamper_integrity_harness(
    const std::filesystem::path& repository_root,
    std::string& failure)
{
    if (!run_self_guard_policy_cases(failure)
        || !run_prologue_policy_cases(failure)
        || !run_dma_policy_cases(failure)
        || !run_passive_probe_policy_cases(failure))
        return false;

    const auto anti_tamper_root = repository_root
        / "src/standalone/src/core/anti-tamper";
    const std::string anti_hook = read_source(anti_tamper_root / "anti_hook.hpp");
    const std::string re_detection = read_source(
        anti_tamper_root / "re_detection_engine.hpp");
    const std::string orchestrator = read_source(
        anti_tamper_root / "orchestrator.hpp");
    const std::string anti_dump = read_source(anti_tamper_root / "anti_dump.hpp");

    const std::string_view anti_hook_forbidden[] = {
        "veh_hook_AddVectoredExceptionHandler",
        "install_veh_insertion_protection",
        "iat[i] = reinterpret_cast<uintptr_t>(&veh_hook"
    };
    for (const auto token : anti_hook_forbidden)
        if (!require_absent(anti_hook, token, failure)) return false;

    const std::string_view re_detection_forbidden[] = {
        "install_window_api_iat_hooks",
        "remove_window_api_iat_hooks",
        "window_iat_hook_state_t",
        "iat_slot_FindWindow",
        "VirtualProtect("
    };
    for (const auto token : re_detection_forbidden)
        if (!require_absent(re_detection, token, failure)) return false;

    const std::string_view backup_forbidden[] = {
        "g_encrypted_header_backup",
        "g_header_backup_saved",
        "save_header_backup",
        "save_header_backup_ok"
    };
    for (const auto token : backup_forbidden)
        if (!require_absent(anti_dump, token, failure)) return false;

    const std::string_view anti_hook_required[] = {
        "prologue_evidence_matches_baseline",
        "b.hash, b.crc32",
        "kernel_read_prologue_hash",
        "veh_chain::verify_chain"
    };
    for (const auto token : anti_hook_required)
        if (!require_present(anti_hook, token, failure)) return false;

    const std::string_view re_detection_required[] = {
        "find_own_window_for_probe",
        "detect_findwindow_probe",
        "passive_window_probe_monitor_active"
    };
    for (const auto token : re_detection_required)
        if (!require_present(re_detection, token, failure)) return false;

    if (!require_absent(orchestrator, "hvci_active ? false", failure)
        || !require_absent(orchestrator, "skip_hypervisor_present", failure)
        || !require_present(orchestrator,
            "hvci_active iommu_enforcement_preserved", failure))
        return false;

    return true;
}
}

namespace
{
std::filesystem::path locate_repository_root(int argc, char** argv)
{
    if (argc > 1)
        return std::filesystem::weakly_canonical(argv[1]);

    std::filesystem::path candidates[] = {
        std::filesystem::current_path(),
        std::filesystem::absolute(std::filesystem::path(__FILE__))
    };
    for (auto candidate : candidates) {
        if (!std::filesystem::is_directory(candidate))
            candidate = candidate.parent_path();
        for (size_t depth = 0; depth < 16 && !candidate.empty(); ++depth) {
            if (std::filesystem::exists(candidate
                    / "src/standalone/src/core/anti-tamper/anti_hook.hpp"))
                return candidate;
            candidate = candidate.parent_path();
        }
    }
    throw std::runtime_error("repository_root_not_found");
}
}

int main(int argc, char** argv)
{
    try {
        std::string failure;
        const auto root = locate_repository_root(argc, argv);
        if (!aida::c03::security::run_anti_tamper_integrity_harness(root, failure)) {
            std::cerr << failure << '\n';
            return 1;
        }
        return 0;
    } catch (const std::exception& exception) {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(
			false, exception.what(), __FILE__, __LINE__);
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
