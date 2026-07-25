#pragma once

#include <cstdint>

namespace anti_tamper {

struct dma_preflight_policy_result_t
{
    bool hvci_active;
    bool iommu_off;
    bool iommu_bypassed;
    bool refuse_multiple_unknown;
    bool refuse_unprotected_unknown;
};

constexpr dma_preflight_policy_result_t evaluate_dma_preflight_policy(
    bool hvci_active,
    bool iommu_present,
    bool vtd_enabled,
    bool amd_vi_enabled,
    bool remapping_bypassed,
    std::uint32_t unknown_clusters) noexcept
{
    const bool iommu_off = !iommu_present || (!vtd_enabled && !amd_vi_enabled);
    const bool iommu_bypassed = iommu_present && remapping_bypassed;
    return {
        hvci_active,
        iommu_off,
        iommu_bypassed,
        unknown_clusters >= 2,
        unknown_clusters >= 1 && (iommu_off || iommu_bypassed)
    };
}

}
