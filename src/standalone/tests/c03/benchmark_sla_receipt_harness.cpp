#include "benchmark_sla_receipt_harness.hpp"
#include "assertion_telemetry/assertion_telemetry.hpp"

#include "benchmark_sla_receipt.hpp"

#include <utility>

namespace aida::analysis::c03
{
bool run_benchmark_sla_receipt_harness(const std::filesystem::path& evidence_root,
    std::string_view input_path, bool not_run, std::string& receipt_json, std::string& failure)
{
    auto result = not_run ? build_benchmark_not_run_receipt(evidence_root, input_path) :
                            build_benchmark_sla_receipt(evidence_root, input_path);
    if (!result.ok) {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(false, result.error, __FILE__, __LINE__);
        receipt_json.clear();
        failure = std::move(result.error);
        return false;
    }
    receipt_json = result.receipt.dump(2);
    failure.clear();
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		true, "benchmark SLA receipt contract satisfied", __FILE__, __LINE__);
    return true;
}
}
