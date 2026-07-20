#include "emulation_engine.hpp"

#ifdef __NT__

namespace emulation {
namespace {

constexpr const char* kSafeHeadlessEmulationError =
    "safe_headless_unsupported: emulation and target-code access are prohibited";

emulation_result_t make_unsupported_result()
{
    emulation_result_t result{};
    result.error = kSafeHeadlessEmulationError;
    return result;
}

}

std::vector<std::uint8_t> driver_read_bytes(
    std::uint64_t address,
    std::size_t size)
{
    static_cast<void>(address);
    static_cast<void>(size);
    return {};
}

std::vector<decoded_insn_t> driver_disassemble_range(
    std::uint64_t address,
    std::uint32_t size,
    std::uint32_t max_instructions)
{
    static_cast<void>(address);
    static_cast<void>(size);
    static_cast<void>(max_instructions);
    return {};
}

process_snapshot_t driver_snapshot(
    std::uint32_t pid,
    std::uint32_t tid,
    std::uint64_t region_base,
    std::uint64_t region_size,
    const emulation_config_t* config)
{
    static_cast<void>(region_base);
    static_cast<void>(region_size);
    static_cast<void>(config);
    process_snapshot_t snapshot{};
    snapshot.pid = pid;
    snapshot.tid = tid;
    snapshot.error = kSafeHeadlessEmulationError;
    return snapshot;
}

std::vector<decoded_insn_t> disassemble_range(
    const std::uint8_t* data,
    std::size_t data_size,
    std::uint64_t runtime_address,
    std::uint32_t max_instructions)
{
    static_cast<void>(data);
    static_cast<void>(data_size);
    static_cast<void>(runtime_address);
    static_cast<void>(max_instructions);
    return {};
}

emulation_result_t emulate_from_snapshot(
    const process_snapshot_t& snapshot,
    const emulation_config_t& config)
{
    static_cast<void>(snapshot);
    static_cast<void>(config);
    return make_unsupported_result();
}

emulation_result_t driver_snapshot_and_emulate(
    std::uint32_t pid,
    std::uint32_t tid,
    const emulation_config_t& config,
    std::uint64_t snapshot_base,
    std::uint64_t snapshot_size)
{
    static_cast<void>(pid);
    static_cast<void>(tid);
    static_cast<void>(config);
    static_cast<void>(snapshot_base);
    static_cast<void>(snapshot_size);
    return make_unsupported_result();
}

vm_analysis_result_t analyze_vm_trace(const emulation_result_t& result)
{
    static_cast<void>(result);
    vm_analysis_result_t analysis{};
    analysis.summary = kSafeHeadlessEmulationError;
    return analysis;
}

}

#endif
