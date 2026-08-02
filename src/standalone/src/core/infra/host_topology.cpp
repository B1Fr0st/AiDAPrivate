#include "host_topology.hpp"

#include "../../helpers/diag_log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <atomic>
#include <memory>
#include <new>

namespace aida::infra::host_topology {

namespace {

std::uint32_t clamp_u32(std::uint32_t value, std::uint32_t low, std::uint32_t high) noexcept {
    if (value < low)
        return low;
    if (value > high)
        return high;
    return value;
}

std::uint32_t popcount_u64(std::uint64_t value) noexcept {
    std::uint32_t count = 0;
    while (value != 0) {
        value &= (value - 1ULL);
        ++count;
    }
    return count;
}

bool entry_size_sane(const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* info) noexcept {
    std::uint64_t count = 0;
    std::uint64_t element = 0;
    if (info->Relationship == RelationProcessorCore) {
        count = info->Processor.GroupCount;
        element = sizeof(GROUP_AFFINITY);
    } else if (info->Relationship == RelationGroup) {
        count = info->Group.ActiveGroupCount;
        element = sizeof(PROCESSOR_GROUP_INFO);
    } else {
        return true;
    }
    const std::uint64_t required = static_cast<std::uint64_t>(sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)) +
        (count > 0 ? (count - 1u) * element : 0u);
    return static_cast<std::uint64_t>(info->Size) >= required;
}

bool query_topology(topology_t& out, DWORD& gle, const char*& reason) noexcept {
    gle = 0;
    reason = "ok";
    DWORD length = 0;
    SetLastError(0);
    (void)GetLogicalProcessorInformationEx(RelationAll, nullptr, &length);
    const DWORD probe_gle = GetLastError();
    if (probe_gle != ERROR_INSUFFICIENT_BUFFER || length < sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)) {
        gle = probe_gle;
        reason = "size_probe_failed";
        return false;
    }
    std::unique_ptr<std::uint8_t[]> buffer(new (std::nothrow) std::uint8_t[length]);
    if (!buffer) {
        reason = "buffer_alloc_failed";
        return false;
    }
    SetLastError(0);
    if (GetLogicalProcessorInformationEx(RelationAll,
            reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.get()),
            &length) == FALSE) {
        gle = GetLastError();
        reason = "query_failed";
        return false;
    }
    std::uint32_t physical = 0;
    std::uint32_t numa = 0;
    std::uint32_t groups = 0;
    std::uint32_t group_logical = 0;
    bool smt = false;
    bool class_seen = false;
    BYTE max_class = 0;
    BYTE min_class = 0;
    std::uint64_t offset = 0;
    while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) <= length) {
        const auto* info = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.get() + offset);
        if (info->Size < sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) ||
            static_cast<std::uint64_t>(info->Size) > length - offset ||
            !entry_size_sane(info)) {
            reason = "insane_stride";
            return false;
        }
        switch (info->Relationship) {
        case RelationProcessorCore:
            ++physical;
            if (info->Processor.Flags == LTP_PC_SMT)
                smt = true;
            if (!class_seen) {
                max_class = info->Processor.EfficiencyClass;
                min_class = info->Processor.EfficiencyClass;
                class_seen = true;
            } else {
                if (info->Processor.EfficiencyClass > max_class)
                    max_class = info->Processor.EfficiencyClass;
                if (info->Processor.EfficiencyClass < min_class)
                    min_class = info->Processor.EfficiencyClass;
            }
            break;
        case RelationNumaNode:
            ++numa;
            break;
        case RelationGroup: {
            const WORD active = info->Group.ActiveGroupCount;
            if (active > groups)
                groups = active;
            for (WORD index = 0; index < active; ++index)
                group_logical += info->Group.GroupInfo[index].ActiveProcessorCount;
            break;
        }
        default:
            break;
        }
        offset += info->Size;
    }
    if (physical == 0) {
        reason = "insane_core_count";
        return false;
    }
    std::uint32_t logical = 0;
    std::uint32_t perf_cores = 0;
    std::uint32_t eff_cores = 0;
    std::uint32_t perf_logical = 0;
    offset = 0;
    while (offset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) <= length) {
        const auto* info = reinterpret_cast<const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.get() + offset);
        if (info->Relationship == RelationProcessorCore) {
            std::uint32_t logicals = 0;
            const WORD group_count = info->Processor.GroupCount;
            for (WORD index = 0; index < group_count; ++index)
                logicals += popcount_u64(static_cast<std::uint64_t>(info->Processor.GroupMask[index].Mask));
            if (logicals == 0) {
                reason = "insane_popcount";
                return false;
            }
            logical += logicals;
            if (info->Processor.EfficiencyClass == max_class) {
                ++perf_cores;
                perf_logical += logicals;
            } else {
                ++eff_cores;
            }
        }
        offset += info->Size;
    }
    if (logical < physical) {
        reason = "insane_logical_count";
        return false;
    }
    if (group_logical != 0 && group_logical != logical) {
        reason = "insane_group_mismatch";
        return false;
    }
    out.physical_cores = physical;
    out.performance_cores = perf_cores;
    out.efficient_cores = eff_cores;
    out.logical_cores = logical;
    out.performance_logical_cores = perf_logical;
    out.numa_nodes = numa != 0 ? numa : 1;
    out.processor_groups = groups != 0 ? groups : 1;
    out.hybrid = class_seen && (min_class != max_class);
    out.smt_present = smt;
    return true;
}

topology_t fallback_topology(const char* reason, DWORD gle) noexcept {
    topology_t topo{};
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (count == 0)
        count = 8;
    topo.physical_cores = count;
    topo.performance_cores = count;
    topo.efficient_cores = 0;
    topo.logical_cores = count;
    topo.performance_logical_cores = count;
    topo.numa_nodes = 1;
    topo.processor_groups = 1;
    topo.hybrid = false;
    topo.smt_present = false;
    diag::log_tagged_fmt("host_topology",
        "host_topology_fallback gle=%lu reason=%s",
        static_cast<unsigned long>(gle),
        reason != nullptr ? reason : "unknown");
    return topo;
}

topology_t build_topology() noexcept {
    topology_t topo{};
    DWORD gle = 0;
    const char* reason = "unknown";
    try {
        if (query_topology(topo, gle, reason))
            return topo;
    } catch (...) {
        gle = 0;
        reason = "exception";
    }
    return fallback_topology(reason, gle);
}

}

const topology_t& current() noexcept {
    static const topology_t cached = build_topology();
    return cached;
}

std::uint32_t recommended_compute_threads() noexcept {
    const topology_t& topo = current();
    const std::uint32_t basis = topo.hybrid ? topo.performance_logical_cores : topo.logical_cores;
    return clamp_u32(basis, 2u, 64u);
}

std::uint32_t recommended_io_threads() noexcept {
    return clamp_u32(current().physical_cores, 2u, 8u);
}

void log_topology_once() noexcept {
    static std::atomic<bool> emitted{false};
    bool expected = false;
    if (!emitted.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        return;
    const topology_t& topo = current();
    diag::log_tagged_fmt("host_topology",
        "host_topology physical=%u logical=%u perf=%u eff=%u hybrid=%u smt=%u numa=%u groups=%u recommended_compute=%u recommended_io=%u",
        static_cast<unsigned>(topo.physical_cores),
        static_cast<unsigned>(topo.logical_cores),
        static_cast<unsigned>(topo.performance_cores),
        static_cast<unsigned>(topo.efficient_cores),
        topo.hybrid ? 1u : 0u,
        topo.smt_present ? 1u : 0u,
        static_cast<unsigned>(topo.numa_nodes),
        static_cast<unsigned>(topo.processor_groups),
        static_cast<unsigned>(recommended_compute_threads()),
        static_cast<unsigned>(recommended_io_threads()));
}

}
