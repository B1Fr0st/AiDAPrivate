#include "capstone_tile_decoder_harness.hpp"

#include "../../src/core/analysis/decode/capstone_tile_decoder.hpp"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis::c03 {
namespace {

using decode::capstone_tile_decoder_options_t;
using decode::capstone_tile_identity_t;
using decode::capstone_tile_result_t;
using decode::worker_owned_capstone_tile_decoder_t;

class mapped_fixture_t final {
public:
    explicit mapped_fixture_t(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.empty())
            throw std::runtime_error("Capstone tile fixture bytes are empty");
        const auto root = std::filesystem::temp_directory_path();
        path_ = root / ("aida-c03-capstone-tile-" +
                        std::to_string(static_cast<unsigned long>(GetCurrentProcessId())) + "-" +
                        std::to_string(static_cast<unsigned long long>(GetTickCount64())) + "-" +
                        std::to_string(next_id_++) + ".bin");
        std::ofstream output(path_, std::ios::binary | std::ios::trunc);
        if (!output)
            throw std::runtime_error("Capstone tile fixture file could not be created");
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        output.close();
        if (!output)
            throw std::runtime_error("Capstone tile fixture file could not be committed");
        auto opened = mapped_file_provider_t::open(path_.u8string());
        if (!opened)
            throw std::runtime_error("Capstone tile fixture provider could not be opened");
        provider_ = opened.take_value();
        auto captured = provider_snapshot_t::capture(provider_);
        if (!captured)
            throw std::runtime_error("Capstone tile fixture snapshot could not be captured");
        snapshot_ = captured.take_value();
    }

    ~mapped_fixture_t()
    {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    mapped_fixture_t(const mapped_fixture_t&) = delete;
    mapped_fixture_t& operator=(const mapped_fixture_t&) = delete;

    const provider_snapshot_t& snapshot() const noexcept { return *snapshot_; }

private:
    inline static std::uint64_t next_id_ = 0;
    std::filesystem::path path_;
    std::shared_ptr<mapped_file_provider_t> provider_;
    std::shared_ptr<provider_snapshot_t> snapshot_;
};

void require(bool condition, std::string_view message)
{
    if (!condition)
        throw std::runtime_error(std::string(message));
}

arch_decoder_key_t key(architecture_id_t architecture, architecture_mode_t mode,
                       endian_t endian, std::uint8_t width)
{
    arch_decoder_key_t result;
    result.architecture = architecture;
    result.mode = mode;
    result.endian = endian;
    result.abi = abi_id_t::unknown;
    result.address_width_bits = width;
    return result;
}

capstone_tile_identity_t identity(const arch_decoder_key_t& decoder_key,
                                  std::size_t byte_count, std::uint64_t snapshot_generation,
                                  std::uint64_t source_id = 1)
{
    capstone_tile_identity_t result;
    result.decoder_key = decoder_key;
    result.start.space = address_space_id_t::relative_virtual;
    result.start.value = 0;
    result.start.architecture = decoder_key.architecture;
    result.start.mode = decoder_key.mode;
    result.provider_offset = 0;
    result.runtime_address = 0x140000000ULL;
    result.image_base = 0x140000000ULL;
    result.image_size = std::max<std::uint64_t>(0x1000, byte_count);
    result.byte_count = byte_count;
    result.snapshot_generation = snapshot_generation;
    result.stable_source_id = source_id;
    result.provenance = fact_provenance_t::recursive_decode;
    result.confidence = 93;
    return result;
}

capstone_tile_result_t decode_fixture(const arch_decoder_key_t& decoder_key,
                                      const std::vector<std::uint8_t>& bytes,
                                      capstone_tile_decoder_options_t options = {})
{
    auto decoder = worker_owned_capstone_tile_decoder_t::create(decoder_key, options);
    require(static_cast<bool>(decoder), "Capstone tile decoder creation failed");
    mapped_fixture_t fixture(bytes);
    auto result = decoder.value()->decode_tile(
        fixture.snapshot(), identity(decoder_key, bytes.size(), fixture.snapshot().generation()));
    require(static_cast<bool>(result), "Capstone tile fixture decode failed");
    auto decoded = result.take_value();
    require(decoded.usage.snapshot_window_leases == 1 &&
                decoded.usage.snapshot_window_bytes == bytes.size(),
            "Capstone tile did not use one immutable snapshot window");
    return decoded;
}

void require_control(const arch_decoder_key_t& decoder_key,
                     const std::vector<std::uint8_t>& bytes,
                     std::uint32_t required_flow,
                     bool require_delay_slot)
{
    const auto result = decode_fixture(decoder_key, bytes);
    require(!result.instructions.empty(), "Capstone tile control fixture produced no instruction");
    const auto& instruction = result.instructions.front();
    require((instruction.flow_flags & required_flow) == required_flow,
            "Capstone tile control flow was not normalized");
    require(result.delay_slot_counts.size() == result.instructions.size(),
            "Capstone tile delay-slot column is not aligned with instructions");
    require(!require_delay_slot || result.delay_slot_counts.front() != 0,
            "Capstone tile delay-slot semantics were not preserved");
    require(instruction.operand_fact_begin <= result.operand_facts.size() &&
                instruction.operand_fact_count <= result.operand_facts.size() -
                    instruction.operand_fact_begin &&
                instruction.target_fact_begin <= result.target_facts.size() &&
                instruction.target_fact_count <= result.target_facts.size() -
                    instruction.target_fact_begin,
            "Capstone tile instruction facts were not normalized");
    if ((required_flow & (flow_branch | flow_call)) != 0) {
        require((instruction.flow_flags & flow_direct) != 0 && instruction.target_fact_count != 0,
                "Capstone tile direct control target was not normalized");
    }
    require(result.coverage.size() >= result.instructions.size(),
            "Capstone tile coverage did not preserve decoded records");
}

std::uint64_t mix(std::uint64_t value) noexcept
{
    value ^= value >> 30U;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27U;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31U;
    return value;
}

std::uint64_t combine(std::uint64_t seed, std::uint64_t value) noexcept
{
    return mix(seed ^ (mix(value) + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U)));
}

std::uint64_t result_hash(const capstone_tile_result_t& result) noexcept
{
    std::uint64_t value = decode::capstone_tile_identity_hash(result.identity);
    value = combine(value, result.usage.input_bytes);
    value = combine(value, result.usage.bytes_consumed);
    value = combine(value, result.usage.decoded_bytes);
    value = combine(value, result.usage.undecodable_bytes);
    value = combine(value, result.usage.decode_attempts);
    value = combine(value, result.usage.instructions);
    value = combine(value, result.usage.operand_facts);
    value = combine(value, result.usage.target_facts);
    value = combine(value, result.usage.coverage_spans);
    value = combine(value, result.usage.snapshot_window_leases);
    value = combine(value, result.usage.snapshot_window_bytes);
    for (std::size_t index = 0; index < result.instructions.size(); ++index) {
        const auto& instruction = result.instructions[index];
        value = combine(value, instruction.id);
        value = combine(value, static_cast<std::uint64_t>(instruction.address.space));
        value = combine(value, instruction.address.value);
        value = combine(value, static_cast<std::uint64_t>(instruction.address.architecture));
        value = combine(value, static_cast<std::uint64_t>(instruction.address.mode));
        value = combine(value, instruction.length);
        value = combine(value, instruction.mnemonic_id);
        value = combine(value, instruction.opcode_id);
        value = combine(value, instruction.flow_flags);
        value = combine(value, instruction.operand_fact_begin);
        value = combine(value, instruction.operand_fact_count);
        value = combine(value, instruction.target_fact_begin);
        value = combine(value, instruction.target_fact_count);
        value = combine(value, static_cast<std::uint64_t>(instruction.provenance));
        value = combine(value, instruction.confidence);
        value = combine(value, static_cast<std::uint64_t>(instruction.coverage));
        value = combine(value, instruction.stable_source_id);
        value = combine(value, result.delay_slot_counts[index]);
    }
    for (const auto& operand : result.operand_facts) {
        value = combine(value, operand.id);
        value = combine(value, operand.instruction_id);
        value = combine(value, operand.address_expression_id);
        value = combine(value, operand.operand_index);
        value = combine(value, operand.decoder_operand_id);
        value = combine(value, static_cast<std::uint64_t>(operand.kind));
        value = combine(value, operand.access);
        value = combine(value, operand.visibility);
        value = combine(value, operand.encoding);
        value = combine(value, operand.memory_type);
        value = combine(value, operand.access_width);
        value = combine(value, operand.bit_width);
        value = combine(value, operand.address_width_bits);
        value = combine(value, operand.access_count);
        value = combine(value, operand.element_width_bits);
        value = combine(value, operand.element_count);
        value = combine(value, operand.reg);
        value = combine(value, operand.segment_reg);
        value = combine(value, operand.base_reg);
        value = combine(value, operand.index_reg);
        value = combine(value, operand.scale);
        value = combine(value, operand.relative ? 1 : 0);
        value = combine(value, operand.signed_value ? 1 : 0);
        value = combine(value, operand.has_displacement ? 1 : 0);
        value = combine(value, operand.has_resolved_expression_value ? 1 : 0);
        value = combine(value, static_cast<std::uint64_t>(operand.displacement));
        value = combine(value, operand.immediate);
        value = combine(value, operand.resolved_expression_value);
        value = combine(value, operand.address_components);
        value = combine(value, static_cast<std::uint64_t>(operand.address_expression));
        value = combine(value, static_cast<std::uint64_t>(operand.address_resolution));
    }
    for (const auto& target : result.target_facts) {
        value = combine(value, target.instruction_id);
        value = combine(value, target.operand_fact_id);
        value = combine(value, target.address_expression_id);
        value = combine(value, static_cast<std::uint64_t>(target.target.space));
        value = combine(value, target.target.value);
        value = combine(value, static_cast<std::uint64_t>(target.target.architecture));
        value = combine(value, static_cast<std::uint64_t>(target.target.mode));
        value = combine(value, static_cast<std::uint64_t>(target.kind));
        value = combine(value, static_cast<std::uint64_t>(target.resolution));
        value = combine(value, target.operand_index);
        value = combine(value, target.access_width_bits);
        value = combine(value, target.access_count);
        value = combine(value, target.direct ? 1 : 0);
        value = combine(value, target.is_external ? 1 : 0);
    }
    for (const auto& span : result.coverage) {
        value = combine(value, static_cast<std::uint64_t>(span.start.space));
        value = combine(value, span.start.value);
        value = combine(value, static_cast<std::uint64_t>(span.start.architecture));
        value = combine(value, static_cast<std::uint64_t>(span.start.mode));
        value = combine(value, span.size);
        value = combine(value, static_cast<std::uint64_t>(span.reason));
        value = combine(value, static_cast<std::uint64_t>(span.provenance));
        value = combine(value, span.confidence);
        value = combine(value, span.detail_code);
    }
    return value;
}

void test_architecture_controls()
{
    const auto arm = key(architecture_id_t::arm, architecture_mode_t::arm_a32,
                         endian_t::little, 32);
    const auto thumb = key(architecture_id_t::arm, architecture_mode_t::arm_thumb,
                           endian_t::little, 32);
    const auto aarch64 = key(architecture_id_t::aarch64, architecture_mode_t::aarch64,
                             endian_t::little, 64);
    const auto mips32 = key(architecture_id_t::mips, architecture_mode_t::mips32,
                            endian_t::little, 32);
    const auto mips64 = key(architecture_id_t::mips64, architecture_mode_t::mips64,
                            endian_t::little, 64);
    const auto ppc32 = key(architecture_id_t::ppc, architecture_mode_t::ppc32,
                           endian_t::big, 32);
    const auto ppc64 = key(architecture_id_t::ppc64, architecture_mode_t::ppc64,
                           endian_t::big, 64);
    const auto riscv32 = key(architecture_id_t::riscv32, architecture_mode_t::riscv32,
                             endian_t::little, 32);
    const auto riscv64 = key(architecture_id_t::riscv64, architecture_mode_t::riscv64,
                             endian_t::little, 64);

    require_control(arm, {0x00, 0x00, 0x00, 0xea}, flow_branch, false);
    require_control(arm, {0x00, 0x00, 0x00, 0xeb}, flow_call, false);
    require_control(arm, {0x1e, 0xff, 0x2f, 0xe1}, flow_return, false);
    require_control(thumb, {0x00, 0xe0}, flow_branch, false);
    require_control(thumb, {0x00, 0xf0, 0x00, 0xf8}, flow_call, false);
    require_control(thumb, {0x70, 0x47}, flow_return, false);
    require_control(aarch64, {0x00, 0x00, 0x00, 0x14}, flow_branch, false);
    require_control(aarch64, {0x00, 0x00, 0x00, 0x94}, flow_call, false);
    require_control(aarch64, {0xc0, 0x03, 0x5f, 0xd6}, flow_return, false);
    require_control(mips32, {0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}, flow_branch, true);
    require_control(mips32, {0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00}, flow_call, true);
    require_control(mips32, {0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00}, flow_return, true);
    require_control(mips64, {0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}, flow_branch, true);
    require_control(mips64, {0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00}, flow_call, true);
    require_control(mips64, {0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00}, flow_return, true);
    require_control(ppc32, {0x48, 0x00, 0x00, 0x00}, flow_branch, false);
    require_control(ppc32, {0x48, 0x00, 0x00, 0x01}, flow_call, false);
    require_control(ppc32, {0x4e, 0x80, 0x00, 0x20}, flow_return, false);
    require_control(ppc64, {0x48, 0x00, 0x00, 0x00}, flow_branch, false);
    require_control(ppc64, {0x48, 0x00, 0x00, 0x01}, flow_call, false);
    require_control(ppc64, {0x4e, 0x80, 0x00, 0x20}, flow_return, false);
    require_control(riscv32, {0x63, 0x00, 0x00, 0x00}, flow_branch, false);
    require_control(riscv32, {0xef, 0x00, 0x00, 0x00}, flow_call, false);
    require_control(riscv32, {0x67, 0x80, 0x00, 0x00}, flow_return, false);
    require_control(riscv64, {0x63, 0x00, 0x00, 0x00}, flow_branch, false);
    require_control(riscv64, {0xef, 0x00, 0x00, 0x00}, flow_call, false);
    require_control(riscv64, {0x67, 0x80, 0x00, 0x00}, flow_return, false);
}

void test_mode_endian_identity()
{
    const auto arm_big = key(architecture_id_t::arm, architecture_mode_t::arm_a32,
                             endian_t::big, 32);
    const std::vector<std::uint8_t> arm_nop{0xe1, 0xa0, 0x00, 0x00};
    const auto result = decode_fixture(arm_big, arm_nop);
    require(result.identity.decoder_key == arm_big,
            "Capstone tile did not retain big-endian architecture identity");
    require(!result.instructions.empty(), "big-endian ARM tile produced no instruction");

    const std::vector<arch_decoder_key_t> big_endian_keys{
        arm_big,
        key(architecture_id_t::arm, architecture_mode_t::arm_thumb, endian_t::big, 32),
        key(architecture_id_t::aarch64, architecture_mode_t::aarch64, endian_t::big, 64),
        key(architecture_id_t::mips, architecture_mode_t::mips32, endian_t::big, 32),
        key(architecture_id_t::mips64, architecture_mode_t::mips64, endian_t::big, 64),
        key(architecture_id_t::ppc, architecture_mode_t::ppc32, endian_t::big, 32),
        key(architecture_id_t::ppc64, architecture_mode_t::ppc64, endian_t::big, 64),
        key(architecture_id_t::riscv32, architecture_mode_t::riscv32, endian_t::big, 32),
        key(architecture_id_t::riscv64, architecture_mode_t::riscv64, endian_t::big, 64)
    };
    for (const auto& big_endian_key : big_endian_keys) {
        auto decoder = worker_owned_capstone_tile_decoder_t::create(big_endian_key);
        require(static_cast<bool>(decoder), "big-endian Capstone tile decoder creation failed");
        mapped_fixture_t fixture(arm_nop);
        auto mismatched = identity(big_endian_key, arm_nop.size(), fixture.snapshot().generation());
        mismatched.decoder_key.endian = endian_t::little;
        const auto rejected = decoder.value()->decode_tile(fixture.snapshot(), mismatched);
        require(!rejected && rejected.error().code == workspace_error_code_t::invalid_argument,
                "Capstone tile accepted a mismatched endian identity");
    }
    auto decoder = worker_owned_capstone_tile_decoder_t::create(arm_big);
    require(static_cast<bool>(decoder), "big-endian ARM tile decoder creation failed");
    mapped_fixture_t fixture(arm_nop);
    auto mismatched = identity(arm_big, arm_nop.size(), fixture.snapshot().generation());
    mismatched.start.mode = architecture_mode_t::arm_thumb;
    const auto rejected = decoder.value()->decode_tile(fixture.snapshot(), mismatched);
    require(!rejected && rejected.error().code == workspace_error_code_t::invalid_argument,
            "Capstone tile accepted a mismatched architecture mode identity");

    auto stale = identity(arm_big, arm_nop.size(), fixture.snapshot().generation() + 1);
    const auto stale_rejected = decoder.value()->decode_tile(fixture.snapshot(), stale);
    require(!stale_rejected && stale_rejected.error().code == workspace_error_code_t::stale_generation,
            "Capstone tile accepted a stale provider snapshot generation");

    auto out_of_range = identity(arm_big, arm_nop.size() + 1, fixture.snapshot().generation());
    const auto range_rejected = decoder.value()->decode_tile(fixture.snapshot(), out_of_range);
    require(!range_rejected && range_rejected.error().code == workspace_error_code_t::out_of_range,
            "Capstone tile accepted an out-of-range provider window");
}

void test_malformed_progress_and_limits()
{
    const std::vector<arch_decoder_key_t> keys{
        key(architecture_id_t::arm, architecture_mode_t::arm_a32, endian_t::little, 32),
        key(architecture_id_t::arm, architecture_mode_t::arm_thumb, endian_t::little, 32),
        key(architecture_id_t::aarch64, architecture_mode_t::aarch64, endian_t::little, 64),
        key(architecture_id_t::mips, architecture_mode_t::mips32, endian_t::little, 32),
        key(architecture_id_t::mips64, architecture_mode_t::mips64, endian_t::little, 64),
        key(architecture_id_t::ppc, architecture_mode_t::ppc32, endian_t::big, 32),
        key(architecture_id_t::ppc64, architecture_mode_t::ppc64, endian_t::big, 64),
        key(architecture_id_t::riscv32, architecture_mode_t::riscv32, endian_t::little, 32),
        key(architecture_id_t::riscv64, architecture_mode_t::riscv64, endian_t::little, 64)
    };
    const std::vector<std::vector<std::uint8_t>> fixtures{
        {0x00, 0x00, 0xa0, 0xe1, 0xff},
        {0x00, 0xbf, 0xff},
        {0x1f, 0x20, 0x03, 0xd5, 0xff},
        {0x00, 0x00, 0x00, 0x00, 0xff},
        {0x00, 0x00, 0x00, 0x00, 0xff},
        {0x60, 0x00, 0x00, 0x00, 0xff},
        {0x60, 0x00, 0x00, 0x00, 0xff},
        {0x13, 0x00, 0x00, 0x00, 0xff},
        {0x13, 0x00, 0x00, 0x00, 0xff}
    };
    require(keys.size() == fixtures.size(), "Capstone malformed fixture matrix is inconsistent");
    for (std::size_t index = 0; index < keys.size(); ++index) {
        const auto result = decode_fixture(keys[index], fixtures[index]);
        require(!result.instructions.empty(), "Capstone malformed fixture lost valid prefix instruction");
        require(!result.coverage.empty() &&
                    result.coverage.back().reason == coverage_reason_t::undecodable &&
                    result.coverage.back().size == 1 && result.usage.undecodable_bytes == 1,
                "Capstone malformed fixture did not make deterministic forward progress");
    }
    auto options = capstone_tile_decoder_options_t{};
    options.tile_limits.maximum_consecutive_undecodable_bytes = 1;
    const auto arm = keys.front();
    auto decoder = worker_owned_capstone_tile_decoder_t::create(arm, options);
    require(static_cast<bool>(decoder), "bounded malformed ARM decoder creation failed");
    const std::vector<std::uint8_t> bounded{0x00, 0x00, 0xa0, 0xe1, 0xff, 0xff};
    mapped_fixture_t fixture(bounded);
    auto result = decoder.value()->decode_tile(
        fixture.snapshot(), identity(arm, bounded.size(), fixture.snapshot().generation()));
    require(!result && result.error().code == workspace_error_code_t::decode_failure,
            "Capstone malformed-byte bound was not enforced");
}

void test_deterministic_records_and_cancellation()
{
    const std::vector<arch_decoder_key_t> keys{
        key(architecture_id_t::arm, architecture_mode_t::arm_a32, endian_t::little, 32),
        key(architecture_id_t::arm, architecture_mode_t::arm_thumb, endian_t::little, 32),
        key(architecture_id_t::aarch64, architecture_mode_t::aarch64, endian_t::little, 64),
        key(architecture_id_t::mips, architecture_mode_t::mips32, endian_t::little, 32),
        key(architecture_id_t::mips64, architecture_mode_t::mips64, endian_t::little, 64),
        key(architecture_id_t::ppc, architecture_mode_t::ppc32, endian_t::big, 32),
        key(architecture_id_t::ppc64, architecture_mode_t::ppc64, endian_t::big, 64),
        key(architecture_id_t::riscv32, architecture_mode_t::riscv32, endian_t::little, 32),
        key(architecture_id_t::riscv64, architecture_mode_t::riscv64, endian_t::little, 64)
    };
    const std::vector<std::vector<std::uint8_t>> fixtures{
        {0x00, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1, 0xff},
        {0x00, 0xf0, 0x00, 0xf8, 0x70, 0x47, 0xff},
        {0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6, 0xff},
        {0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
         0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00, 0xff},
        {0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
         0x08, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00, 0xff},
        {0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20, 0xff},
        {0x48, 0x00, 0x00, 0x01, 0x4e, 0x80, 0x00, 0x20, 0xff},
        {0xef, 0x00, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00, 0xff},
        {0xef, 0x00, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00, 0xff}
    };
    require(keys.size() == fixtures.size(), "Capstone deterministic fixture matrix is inconsistent");
    for (std::size_t index = 0; index < keys.size(); ++index) {
        const auto first = decode_fixture(keys[index], fixtures[index], {});
        const auto second = decode_fixture(keys[index], fixtures[index], {});
        require(result_hash(first) == result_hash(second),
                "Capstone tile records are not deterministic across workers");
    }

    const auto mips = keys[3];
    const auto& bytes = fixtures[3];
    cancellation_source_t cancellation;
    cancellation.request_cancel();
    auto cancelled = worker_owned_capstone_tile_decoder_t::create(
        mips, {}, cancellation.token());
    require(!cancelled && cancelled.error().code == workspace_error_code_t::cancelled,
            "Capstone tile decoder creation ignored cancellation");

    cancellation_source_t active_cancellation;
    auto active_decoder = worker_owned_capstone_tile_decoder_t::create(
        mips, {}, active_cancellation.token());
    require(static_cast<bool>(active_decoder), "Capstone tile decoder creation for active cancellation failed");
    active_cancellation.request_cancel();
    mapped_fixture_t fixture(bytes);
    auto stopped = active_decoder.value()->decode_tile(
        fixture.snapshot(), identity(mips, bytes.size(), fixture.snapshot().generation()),
        active_cancellation.token());
    require(!stopped && stopped.error().code == workspace_error_code_t::cancelled,
            "Capstone tile decode ignored cancellation after worker creation");
}

}

bool run_capstone_tile_decoder_harness(std::string& failure)
{
    try {
        test_architecture_controls();
        test_mode_endian_identity();
        test_malformed_progress_and_limits();
        test_deterministic_records_and_cancellation();
        return true;
    } catch (const std::exception& error) {
        failure = error.what();
        return false;
    }
}

}

int main()
{
    std::string failure;
    return aida::analysis::c03::run_capstone_tile_decoder_harness(failure) ? 0 : 1;
}
