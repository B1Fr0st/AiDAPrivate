#pragma once

#include <cstdint>

namespace aida::infra::host_topology {

struct topology_t {
    std::uint32_t physical_cores = 0;
    std::uint32_t performance_cores = 0;
    std::uint32_t efficient_cores = 0;
    std::uint32_t logical_cores = 0;
    std::uint32_t performance_logical_cores = 0;
    std::uint32_t numa_nodes = 1;
    std::uint32_t processor_groups = 1;
    bool hybrid = false;
    bool smt_present = false;
};

const topology_t& current() noexcept;
std::uint32_t recommended_compute_threads() noexcept;
std::uint32_t recommended_io_threads() noexcept;
void log_topology_once() noexcept;

}
