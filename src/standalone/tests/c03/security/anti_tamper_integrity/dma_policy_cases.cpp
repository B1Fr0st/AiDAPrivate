#include "anti_tamper_integrity_harness.hpp"

#include "../../../../src/core/anti-tamper/orchestrator.hpp"

namespace aida::c03::security
{
bool run_dma_policy_cases(std::string& failure)
{
    const auto without_hvci = anti_tamper::evaluate_dma_preflight_policy(
        false, true, false, false, false, 1);
    const auto with_hvci = anti_tamper::evaluate_dma_preflight_policy(
        true, true, false, false, false, 1);
    if (!record_policy_case(without_hvci.iommu_off && with_hvci.iommu_off
        && without_hvci.refuse_unprotected_unknown
        && with_hvci.refuse_unprotected_unknown,
        "hvci_suppressed_iommu_off_refusal", failure)) {
        return false;
    }

    const auto absent_iommu = anti_tamper::evaluate_dma_preflight_policy(
        true, false, false, false, false, 1);
    if (!record_policy_case(absent_iommu.iommu_off && absent_iommu.refuse_unprotected_unknown,
        "absent_iommu_did_not_refuse_unknown_dma", failure)) {
        return false;
    }

    const auto remapping_bypassed = anti_tamper::evaluate_dma_preflight_policy(
        true, true, true, false, true, 1);
    if (!record_policy_case(remapping_bypassed.iommu_bypassed
        && remapping_bypassed.refuse_unprotected_unknown,
        "remapping_bypass_did_not_refuse_unknown_dma", failure)) {
        return false;
    }

    const auto protected_single_unknown = anti_tamper::evaluate_dma_preflight_policy(
        true, true, true, false, false, 1);
    if (!record_policy_case(!protected_single_unknown.refuse_multiple_unknown
        && !protected_single_unknown.refuse_unprotected_unknown,
        "protected_single_unknown_was_misclassified", failure)) {
        return false;
    }

    const auto protected_multiple_unknown = anti_tamper::evaluate_dma_preflight_policy(
        false, true, true, false, false, 2);
    if (!record_policy_case(protected_multiple_unknown.refuse_multiple_unknown,
        "multiple_unknown_dma_devices_not_refused", failure)) {
        return false;
    }

    return true;
}
}
