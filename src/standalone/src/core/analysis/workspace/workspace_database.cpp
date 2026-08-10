#include "workspace_database.hpp"

#include "checked_range.hpp"
#include "packed_page_codec.hpp"
#include "paged_fact_staging.hpp"
#include "paged_snapshot_view.hpp"
#include "sqlite_reader_pool.hpp"
#include "sqlite_statement_cache.hpp"
#include "../decompiler/managed_entity_binding.hpp"
#include "../../infra/taskflow_runtime.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <sqlite3.h>
#include <zstd.h>

#include <algorithm>
#include <charconv>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

#include <nlohmann/json.hpp>

namespace aida::analysis {

namespace {

constexpr std::uint32_t kInstructionBlobMagic = 0x49444941U;
constexpr std::size_t kInstructionBlobHeaderSize = 16;
constexpr std::size_t kInstructionBlobRecordSize = 53;
constexpr std::size_t kDatabaseRecordPollStride = 256;
constexpr std::size_t kDatabaseBlobCopyChunk = 4096;
constexpr std::uint64_t kMaximumInstructionChunkRecords = 1048576;
constexpr std::uint32_t kPackedBaselineDomainMagic = 0x44424941U;
constexpr std::uint32_t kPackedBaselineManifestMagic = 0x4d424941U;
constexpr std::uint16_t kPackedBaselinePayloadVersion = 1;
constexpr std::uint32_t kPackedBaselineRequiredDomains = 0x7FFFEU;

const std::array<std::uint32_t, 256>& managed_crc32c_table() noexcept {
    static const auto table = [] {
        std::array<std::uint32_t, 256> values{};
        for (std::uint32_t index = 0; index < values.size(); ++index) {
            std::uint32_t value = index;
            for (unsigned bit = 0; bit < 8; ++bit)
                value = (value >> 1U) ^
                    ((value & 1U) ? 0x82F63B78U : 0U);
            values[index] = value;
        }
        return values;
    }();
    return table;
}

std::uint32_t update_managed_crc32c(
    std::uint32_t state, const std::uint8_t* data, std::size_t size) noexcept {
    const auto& table = managed_crc32c_table();
    for (std::size_t index = 0; index < size; ++index)
        state = table[(state ^ data[index]) & 0xFFU] ^ (state >> 8U);
    return state;
}

workspace_error_t packed_baseline_error(workspace_error_code_t code,
                                        std::string message) {
    return make_workspace_error(code, std::move(message),
                                "workspace_database.packed_baseline");
}

workspace_error_t packed_baseline_cancelled(const cancellation_token_t& cancel) {
    auto error = packed_baseline_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        "packed baseline operation was cancelled");
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

class packed_payload_writer_t final {
public:
    using byte_sink_t = std::function<workspace_result_t<void>(
        const std::uint8_t*, std::size_t)>;
    using record_sink_t = std::function<workspace_result_t<void>(
        const std::optional<address_t>&)>;

    explicit packed_payload_writer_t(const cancellation_token_t& cancel)
        : cancel_(cancel) {}

    packed_payload_writer_t(const cancellation_token_t& cancel,
                            std::uint64_t maximum_bytes)
        : cancel_(cancel), maximum_bytes_(maximum_bytes) {}

    packed_payload_writer_t(const cancellation_token_t& cancel,
                            byte_sink_t byte_sink,
                            record_sink_t record_sink,
                            std::uint64_t maximum_bytes)
        : cancel_(cancel), byte_sink_(std::move(byte_sink)),
          record_sink_(std::move(record_sink)), maximum_bytes_(maximum_bytes) {}

    void u8(std::uint8_t value) { append(&value, sizeof(value)); }

    void u16(std::uint16_t value) {
        std::array<std::uint8_t, 2> bytes{
            static_cast<std::uint8_t>(value),
            static_cast<std::uint8_t>(value >> 8U)};
        append(bytes.data(), bytes.size());
    }

    void u32(std::uint32_t value) {
        std::array<std::uint8_t, 4> bytes{};
        for (unsigned shift = 0; shift < 32; shift += 8)
            bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
        append(bytes.data(), bytes.size());
    }

    void u64(std::uint64_t value) {
        std::array<std::uint8_t, 8> bytes{};
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
        append(bytes.data(), bytes.size());
    }

    void i64(std::int64_t value) {
        std::uint64_t bits = 0;
        static_assert(sizeof(bits) == sizeof(value));
        std::memcpy(&bits, &value, sizeof(bits));
        u64(bits);
    }

    void boolean(bool value) { u8(value ? 1U : 0U); }

    void bytes(const std::uint8_t* data, std::size_t size) {
        u64(size);
        append(data, size);
    }

    workspace_result_t<void> append_external(
        const std::uint8_t* data, std::size_t size) {
        append(data, size);
        if (error_)
            return workspace_result_t<void>::failure(*error_);
        return workspace_result_t<void>::success();
    }

    void begin_record(const std::optional<address_t>& address = std::nullopt) {
        if (error_)
            return;
        poll();
        if (error_)
            return;
        if (record_count_ == packed_generation_max_records) {
            error_ = packed_baseline_error(
                workspace_error_code_t::limit_exceeded,
                "packed baseline record count exceeds its bounded limit");
            return;
        }
        if (record_sink_) {
            auto accepted = record_sink_(address);
            if (!accepted) {
                error_ = accepted.error();
                return;
            }
        }
        ++record_count_;
    }

    template <std::size_t Size>
    void fixed_bytes(const std::array<std::uint8_t, Size>& bytes) {
        append(bytes.data(), bytes.size());
    }

    void string(const std::string& value) {
        bytes(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
    }

    void count(std::size_t value) { u64(static_cast<std::uint64_t>(value)); }

    bool failed() const noexcept { return error_.has_value(); }
    std::uint64_t size() const noexcept { return output_size_; }
    std::uint64_t record_count() const noexcept { return record_count_; }
    std::uint32_t checksum() const noexcept { return crc_state_ ^ 0xFFFFFFFFU; }

    workspace_result_t<std::vector<std::uint8_t>> finish() {
        if (!error_)
            poll();
        if (error_)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(*error_);
        return workspace_result_t<std::vector<std::uint8_t>>::success(
            std::move(output_));
    }

    workspace_result_t<void> finish_stream() {
        if (!error_)
            poll();
        if (error_)
            return workspace_result_t<void>::failure(*error_);
        return workspace_result_t<void>::success();
    }

private:
    void poll() {
        if (!error_ && cancel_.stop_requested())
            error_ = packed_baseline_cancelled(cancel_);
    }

    void append(const std::uint8_t* data, std::size_t size) {
        if (error_)
            return;
        if (!data && size != 0) {
            error_ = packed_baseline_error(
                workspace_error_code_t::invalid_argument,
                "packed baseline encoder received a null byte range");
            return;
        }
        if (maximum_bytes_ > packed_generation_max_payload_bytes ||
            output_size_ > maximum_bytes_ ||
            size > maximum_bytes_ - output_size_) {
            error_ = packed_baseline_error(
                workspace_error_code_t::limit_exceeded,
                "packed baseline domain exceeds its bounded payload limit");
            return;
        }
        crc_state_ = update_managed_crc32c(crc_state_, data, size);
        for (std::size_t offset = 0; offset < size;) {
            poll();
            if (error_)
                return;
            const auto end = (std::min)(size, offset + kDatabaseBlobCopyChunk);
            if (byte_sink_) {
                auto accepted = byte_sink_(data + offset, end - offset);
                if (!accepted) {
                    error_ = accepted.error();
                    return;
                }
            } else {
                output_.insert(output_.end(), data + offset, data + end);
            }
            output_size_ += end - offset;
            offset = end;
        }
    }

    const cancellation_token_t& cancel_;
    byte_sink_t byte_sink_;
    record_sink_t record_sink_;
    std::uint64_t maximum_bytes_ = packed_generation_max_payload_bytes;
    std::uint64_t output_size_ = 0;
    std::uint64_t record_count_ = 0;
    std::uint32_t crc_state_ = 0xFFFFFFFFU;
    std::vector<std::uint8_t> output_;
    std::optional<workspace_error_t> error_;
};

class packed_payload_reader_t final {
public:
    packed_payload_reader_t(const std::vector<std::uint8_t>& input,
                            const cancellation_token_t& cancel,
                            std::uint64_t maximum_records,
                            std::uint64_t* aggregate_records = nullptr)
        : input_(input), cancel_(cancel), maximum_records_(maximum_records),
          aggregate_records_(aggregate_records) {}

    std::uint8_t u8() {
        const auto* data = take(sizeof(std::uint8_t));
        return data ? data[0] : 0;
    }

    std::uint16_t u16() {
        const auto* data = take(sizeof(std::uint16_t));
        return data ? static_cast<std::uint16_t>(data[0]) |
                          static_cast<std::uint16_t>(data[1] << 8U)
                    : 0;
    }

    std::uint32_t u32() {
        const auto* data = take(sizeof(std::uint32_t));
        if (!data)
            return 0;
        std::uint32_t value = 0;
        for (unsigned shift = 0; shift < 32; shift += 8)
            value |= static_cast<std::uint32_t>(data[shift / 8]) << shift;
        return value;
    }

    std::uint64_t u64() {
        const auto* data = take(sizeof(std::uint64_t));
        if (!data)
            return 0;
        std::uint64_t value = 0;
        for (unsigned shift = 0; shift < 64; shift += 8)
            value |= static_cast<std::uint64_t>(data[shift / 8]) << shift;
        return value;
    }

    std::int64_t i64() {
        const auto bits = u64();
        std::int64_t value = 0;
        static_assert(sizeof(bits) == sizeof(value));
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    bool boolean() {
        const auto value = u8();
        if (value > 1U)
            fail("packed baseline boolean is not canonical");
        return value != 0;
    }

    std::vector<std::uint8_t> bytes() {
        const auto size = u64();
        if (failed())
            return {};
        if (size > remaining() ||
            size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
            fail("packed baseline byte range exceeds its domain boundary");
            return {};
        }
        std::vector<std::uint8_t> output;
        output.reserve(static_cast<std::size_t>(size));
        std::size_t copied = 0;
        while (copied < static_cast<std::size_t>(size)) {
            poll();
            if (failed())
                return {};
            const auto count = (std::min)(
                static_cast<std::size_t>(size) - copied,
                kDatabaseBlobCopyChunk);
            const auto* data = take(count);
            if (!data)
                return {};
            output.insert(output.end(), data, data + count);
            copied += count;
        }
        return output;
    }

    template <std::size_t Size>
    std::array<std::uint8_t, Size> fixed_bytes() {
        std::array<std::uint8_t, Size> output{};
        const auto* data = take(Size);
        if (data)
            std::memcpy(output.data(), data, Size);
        return output;
    }

    std::string string() {
        auto value = bytes();
        if (failed())
            return {};
        if (value.empty())
            return {};
        return std::string(reinterpret_cast<const char*>(value.data()), value.size());
    }

    std::string bounded_string(std::uint64_t maximum_bytes) {
        const auto size = u64();
        if (failed())
            return {};
        if (size > maximum_bytes || size > remaining() ||
            size > static_cast<std::uint64_t>(
                       (std::numeric_limits<std::size_t>::max)())) {
            fail("packed baseline string exceeds its bounded domain");
            return {};
        }
        const auto* data = take(static_cast<std::size_t>(size));
        return data
            ? std::string(reinterpret_cast<const char*>(data),
                          static_cast<std::size_t>(size))
            : std::string{};
    }

    std::size_t count() {
        const auto value = u64();
        if (failed())
            return 0;
        if (value > maximum_records_ || value > remaining() ||
            (aggregate_records_ &&
             (*aggregate_records_ > maximum_records_ ||
              value > maximum_records_ - *aggregate_records_)) ||
            value > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
            fail("packed baseline record count exceeds its bounded domain");
            return 0;
        }
        if (aggregate_records_)
            *aggregate_records_ += value;
        return static_cast<std::size_t>(value);
    }

    std::uint64_t remaining_bytes() const noexcept {
        return remaining();
    }

    std::size_t offset() const noexcept {
        return offset_;
    }

    void skip_bytes(std::uint64_t size) {
        if (failed())
            return;
        if (size > remaining() ||
            size > static_cast<std::uint64_t>(
                (std::numeric_limits<std::size_t>::max)())) {
            fail("packed baseline byte range exceeds its domain boundary");
            return;
        }
        std::uint64_t skipped = 0;
        while (skipped < size) {
            const auto count = static_cast<std::size_t>((std::min)(
                size - skipped,
                static_cast<std::uint64_t>(kDatabaseBlobCopyChunk)));
            if (!take(count))
                return;
            skipped += count;
        }
    }

    bool failed() const noexcept { return error_.has_value(); }

    void reject(std::string message) { fail(std::move(message)); }

    workspace_result_t<void> finish() {
        if (!error_)
            poll();
        if (!error_ && offset_ != input_.size())
            fail("packed baseline domain contains trailing bytes");
        if (error_)
            return workspace_result_t<void>::failure(*error_);
        return workspace_result_t<void>::success();
    }

private:
    std::uint64_t remaining() const noexcept {
        return static_cast<std::uint64_t>(input_.size() - offset_);
    }

    void poll() {
        if (!error_ && cancel_.stop_requested())
            error_ = packed_baseline_cancelled(cancel_);
    }

    void fail(std::string message) {
        if (!error_)
            error_ = packed_baseline_error(workspace_error_code_t::integrity_failure,
                                           std::move(message));
    }

    const std::uint8_t* take(std::size_t size) {
        if (error_)
            return nullptr;
        poll();
        if (error_)
            return nullptr;
        if (size > input_.size() - offset_) {
            fail("packed baseline domain is truncated");
            return nullptr;
        }
        const auto* result = input_.data() + offset_;
        offset_ += size;
        return result;
    }

    const std::vector<std::uint8_t>& input_;
    const cancellation_token_t& cancel_;
    std::uint64_t maximum_records_ = 0;
    std::uint64_t* aggregate_records_ = nullptr;
    std::size_t offset_ = 0;
    std::optional<workspace_error_t> error_;
};

void write_domain_header(packed_payload_writer_t& writer,
                         packed_page_type_t domain) {
    writer.u32(kPackedBaselineDomainMagic);
    writer.u16(kPackedBaselinePayloadVersion);
    writer.u16(static_cast<std::uint16_t>(domain));
}

void read_domain_header(packed_payload_reader_t& reader,
                        packed_page_type_t expected_domain) {
    if (reader.u32() != kPackedBaselineDomainMagic ||
        reader.u16() != kPackedBaselinePayloadVersion ||
        reader.u16() != static_cast<std::uint16_t>(expected_domain)) {
        reader.reject("packed baseline domain header is invalid");
    }
}

void write_address(packed_payload_writer_t& writer, const address_t& address) {
    writer.u8(static_cast<std::uint8_t>(address.space));
    writer.u8(static_cast<std::uint8_t>(address.architecture));
    writer.u8(static_cast<std::uint8_t>(address.mode));
    writer.u8(0);
    writer.u32(0);
    writer.u64(address.value);
}

address_t read_address(packed_payload_reader_t& reader) {
    address_t address;
    address.space = static_cast<address_space_id_t>(reader.u8());
    address.architecture = static_cast<architecture_id_t>(reader.u8());
    address.mode = static_cast<architecture_mode_t>(reader.u8());
    const auto reserved_byte = reader.u8();
    const auto reserved_word = reader.u32();
    address.value = reader.u64();
    if (reserved_byte != 0 || reserved_word != 0)
        reader.reject("packed baseline address reserved bytes are non-zero");
    return address;
}

void write_optional_address(packed_payload_writer_t& writer,
                            const std::optional<address_t>& address) {
    writer.boolean(address.has_value());
    if (address)
        write_address(writer, *address);
}

std::optional<address_t> read_optional_address(packed_payload_reader_t& reader) {
    if (!reader.boolean())
        return std::nullopt;
    return read_address(reader);
}

void write_optional_entity(packed_payload_writer_t& writer,
                           const std::optional<entity_id_t>& entity) {
    writer.boolean(entity.has_value());
    if (entity)
        writer.u64(*entity);
}

std::optional<entity_id_t> read_optional_entity(packed_payload_reader_t& reader) {
    if (!reader.boolean())
        return std::nullopt;
    return reader.u64();
}

void write_instruction(packed_payload_writer_t& writer,
                       const instruction_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.address);
    writer.u8(record.length);
    writer.u16(record.mnemonic_id);
    writer.u32(record.opcode_id);
    writer.u32(record.flow_flags);
    writer.u32(record.operand_fact_begin);
    writer.u16(record.operand_fact_count);
    writer.u32(record.target_fact_begin);
    writer.u16(record.target_fact_count);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.u8(static_cast<std::uint8_t>(record.coverage));
    writer.u64(record.stable_source_id);
}

void write_operand(packed_payload_writer_t& writer,
                   const operand_fact_t& record) {
    writer.u64(record.id);
    writer.u64(record.instruction_id);
    writer.u64(record.address_expression_id);
    writer.u8(record.operand_index);
    writer.u8(record.decoder_operand_id);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(record.access);
    writer.u8(record.visibility);
    writer.u8(record.encoding);
    writer.u8(record.memory_type);
    writer.u8(record.access_width);
    writer.u16(record.bit_width);
    writer.u16(record.access_width_bits);
    writer.u16(record.access_count);
    writer.u16(record.element_width_bits);
    writer.u16(record.element_count);
    writer.u16(record.address_width_bits);
    writer.u16(record.reg);
    writer.u16(record.segment_reg);
    writer.u16(record.base_reg);
    writer.u16(record.index_reg);
    writer.u8(record.scale);
    writer.boolean(record.relative);
    writer.boolean(record.signed_value);
    writer.boolean(record.has_displacement);
    writer.boolean(record.has_resolved_expression_value);
    writer.i64(record.displacement);
    writer.u64(record.immediate);
    writer.u64(record.resolved_expression_value);
    writer.u16(record.address_components);
    writer.u8(static_cast<std::uint8_t>(record.address_expression));
    writer.u8(static_cast<std::uint8_t>(record.address_resolution));
}

void snapshot_repair_operand_instruction_ordinals(
    analysis_snapshot_t& snapshot) noexcept {
    bool any_sentinel = false;
    for (const auto& hot : snapshot.operand_facts.hot) {
        if (hot.instruction_ordinal == 0xFFFFFFFFU) {
            any_sentinel = true;
            break;
        }
    }
    if (!any_sentinel)
        return;
    std::uint64_t operand_cursor = 0;
    for (std::size_t ordinal = 0; ordinal < snapshot.instructions.size(); ++ordinal) {
        const auto& instruction = snapshot.instructions[ordinal];
        const auto begin = instruction.operand_fact_begin;
        const auto end = (std::max<std::uint64_t>)(
            static_cast<std::uint64_t>(begin),
            static_cast<std::uint64_t>(begin) + instruction.operand_fact_count);
        operand_cursor = (std::max)(operand_cursor,
                                    static_cast<std::uint64_t>(begin));
        while (operand_cursor < end &&
               operand_cursor < snapshot.operand_facts.hot.size()) {
            snapshot.operand_facts.hot[static_cast<std::size_t>(operand_cursor)]
                .instruction_ordinal = static_cast<std::uint32_t>(ordinal);
            ++operand_cursor;
        }
    }
}

void snapshot_operand_append(analysis_snapshot_t& snapshot,
                             const operand_fact_t& record) {
    std::uint32_t instruction_ordinal = 0xFFFFFFFFU;
    if ((record.instruction_id >> 56U) == (instruction_entity_tag >> 56U) &&
        (record.instruction_id & entity_ordinal_mask) != 0) {
        instruction_ordinal = static_cast<std::uint32_t>(
            (record.instruction_id & entity_ordinal_mask) - 1ULL);
    }
    auto parts = operand_fact_split(record, instruction_ordinal);
    if (parts.has_cold) {
        snapshot.operand_facts.cold.push_back(parts.cold);
        parts.hot.cold_index =
            static_cast<std::uint32_t>(snapshot.operand_facts.cold.size());
    }
    snapshot.operand_facts.hot.push_back(parts.hot);
}

void write_target(packed_payload_writer_t& writer,
                  const target_fact_t& record) {
    writer.u64(record.instruction_id);
    writer.u64(record.operand_fact_id);
    writer.u64(record.address_expression_id);
    write_address(writer, record.target);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(static_cast<std::uint8_t>(record.resolution));
    writer.u8(record.operand_index);
    writer.u16(record.access_width_bits);
    writer.u16(record.access_count);
    writer.boolean(record.direct);
    writer.boolean(record.is_external);
}

void write_block(packed_payload_writer_t& writer,
                 const basic_block_record_t& record) {
    writer.u64(record.id);
    writer.u64(record.function_id);
    write_address(writer, record.start);
    write_address(writer, record.end);
    writer.u32(record.first_instruction);
    writer.u32(record.instruction_count);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_function_chunk(packed_payload_writer_t& writer,
                          const function_chunk_record_t& record) {
    writer.u64(record.id);
    writer.u64(record.function_id);
    write_address(writer, record.start);
    write_address(writer, record.end);
    writer.u32(record.first_block);
    writer.u32(record.block_count);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.boolean(record.cold);
    writer.boolean(record.shared);
}

void write_function_membership(
    packed_payload_writer_t& writer,
    const function_block_membership_record_t& record) {
    writer.u64(record.function_id);
    writer.u64(record.chunk_id);
    writer.u64(record.block_id);
    writer.u32(record.block_index);
    writer.u32(record.ordinal);
    writer.boolean(record.shared);
}

void write_function(packed_payload_writer_t& writer,
                    const function_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.start);
    write_address(writer, record.end);
    writer.u32(record.first_block);
    writer.u32(record.block_count);
    writer.u32(record.first_chunk);
    writer.u32(record.chunk_count);
    writer.u32(record.first_block_membership);
    writer.u32(record.block_membership_count);
    write_optional_entity(writer, record.symbol_id);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.boolean(record.thunk);
    writer.boolean(record.noreturn);
    writer.count(record.chunks.size());
    for (const auto& chunk : record.chunks) {
        writer.u64(chunk.rva_start);
        writer.u64(chunk.rva_end);
        writer.u8(chunk.chunk_kind);
    }
}

void write_edge(packed_payload_writer_t& writer,
                const edge_record_t& record) {
    writer.u64(record.id);
    writer.u64(record.source_entity);
    write_optional_entity(writer, record.target_entity);
    write_address(writer, record.source);
    write_address(writer, record.target);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_xref(packed_payload_writer_t& writer,
                const xref_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.source);
    write_address(writer, record.target);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_string_record(packed_payload_writer_t& writer,
                         const string_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.address);
    writer.u64(record.byte_length);
    writer.u8(static_cast<std::uint8_t>(record.encoding));
    writer.string(record.value);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_symbol(packed_payload_writer_t& writer,
                  const symbol_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.address);
    writer.string(record.name);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_coverage(packed_payload_writer_t& writer,
                    const coverage_span_t& record) {
    write_address(writer, record.start);
    writer.u64(record.size);
    writer.u8(static_cast<std::uint8_t>(record.reason));
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.u32(record.detail_code);
}

void write_address_expression(packed_payload_writer_t& writer,
                              const address_expression_record_t& record) {
    writer.u16(record.components);
    writer.u16(record.base_reg);
    writer.u16(record.index_reg);
    writer.u16(record.segment_reg);
    writer.u8(record.kind);
    writer.u8(record.resolution);
    writer.u8(record.scale);
    writer.u8(record.disp_class);
}

void write_data_candidate(packed_payload_writer_t& writer,
                          const data_candidate_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.address);
    writer.u64(record.size);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    write_optional_address(writer, record.target);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_data_pointer(packed_payload_writer_t& writer,
                        const data_pointer_fact_t& record) {
    writer.u64(record.id);
    write_address(writer, record.slot);
    write_address(writer, record.target);
    writer.u8(static_cast<std::uint8_t>(record.candidate_kind));
    writer.u8(static_cast<std::uint8_t>(record.encoding));
    writer.u8(record.width_bytes);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_data_conflict(packed_payload_writer_t& writer,
                         const data_candidate_conflict_t& record) {
    writer.u64(record.id);
    write_address(writer, record.address);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    write_optional_address(writer, record.selected_target);
    write_optional_address(writer, record.rejected_target);
    writer.u8(static_cast<std::uint8_t>(record.selected_provenance));
    writer.u8(static_cast<std::uint8_t>(record.rejected_provenance));
    writer.u8(record.selected_confidence);
    writer.u8(record.rejected_confidence);
}

void write_symbol_type_candidate(
    packed_payload_writer_t& writer,
    const symbol_type_candidate_record_t& record) {
    writer.u64(record.id);
    write_optional_address(writer, record.address);
    write_optional_address(writer, record.related_address);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.string(record.display_name);
    writer.string(record.canonical_type);
    writer.string(record.source_key);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.boolean(record.explicitly_unknown);
}

void write_type_reference(packed_payload_writer_t& writer,
                          const type_reference_fact_t& record) {
    writer.u64(record.id);
    write_optional_address(writer, record.source);
    write_optional_address(writer, record.target);
    writer.u64(record.source_entity);
    writer.u64(record.target_entity);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.string(record.source_key);
}

void write_metadata_conflict(packed_payload_writer_t& writer,
                             const metadata_conflict_record_t& record) {
    writer.u64(record.id);
    write_optional_address(writer, record.address);
    writer.string(record.identity);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.string(record.selected_value);
    writer.string(record.rejected_value);
    writer.u8(static_cast<std::uint8_t>(record.selected_provenance));
    writer.u8(static_cast<std::uint8_t>(record.rejected_provenance));
    writer.u8(record.selected_confidence);
    writer.u8(record.rejected_confidence);
}

void write_call_quality(packed_payload_writer_t& writer,
                        const call_graph_quality_t& quality) {
    writer.u8(static_cast<std::uint8_t>(quality.provenance));
    writer.u8(quality.confidence);
    writer.u32(quality.contributor_count);
    writer.boolean(quality.conflicted);
}

void write_call_node(packed_payload_writer_t& writer,
                     const call_graph_node_record_t& record) {
    writer.u64(record.function_id);
    write_address(writer, record.address);
    writer.u64(record.incoming_edges);
    writer.u64(record.outgoing_edges);
    writer.u64(record.indirect_edges);
    writer.u64(record.unresolved_sites);
}

void write_call_site(packed_payload_writer_t& writer,
                     const recovered_call_site_t& record) {
    writer.u64(record.id);
    writer.u64(record.source_function_id);
    writer.u64(record.source_block_id);
    writer.u64(record.instruction_id);
    write_address(writer, record.address);
    writer.u32(record.first_candidate);
    writer.u32(record.candidate_count);
    writer.boolean(record.indirect);
    writer.boolean(record.tail_call);
    writer.boolean(record.unresolved);
}

void write_call_candidate(packed_payload_writer_t& writer,
                          const recovered_call_candidate_t& record) {
    writer.u64(record.id);
    writer.u64(record.call_site_id);
    write_address(writer, record.target);
    write_optional_entity(writer, record.target_function_id);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    write_call_quality(writer, record.quality);
    writer.u64(record.stable_source_id);
    writer.u32(record.rank);
    writer.boolean(record.external_target);
}

void write_call_edge(packed_payload_writer_t& writer,
                     const call_graph_edge_record_t& record) {
    writer.u64(record.id);
    writer.u64(record.call_site_id);
    writer.u64(record.source_function_id);
    writer.u64(record.source_block_id);
    write_optional_entity(writer, record.target_function_id);
    write_address(writer, record.call_site);
    write_address(writer, record.target);
    writer.u8(static_cast<std::uint8_t>(record.resolution));
    write_call_quality(writer, record.quality);
    writer.u32(record.candidate_rank);
    writer.boolean(record.external_target);
    writer.boolean(record.target_noreturn);
}

void write_call_conflict(packed_payload_writer_t& writer,
                         const call_graph_conflict_t& record) {
    writer.u64(record.id);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.u64(record.instruction_id);
    writer.u64(record.source_function_id);
    writer.u64(record.call_site_rva);
    writer.u64(record.selected_target_rva);
    writer.u64(record.competing_target_rva);
    writer.u64(record.selected_target_function_id);
    writer.u64(record.competing_target_function_id);
}

void write_switch(packed_payload_writer_t& writer,
                  const switch_record_t& record) {
    writer.u64(record.id);
    writer.u64(record.function_id);
    write_address(writer, record.dispatch);
    write_address(writer, record.table);
    write_optional_address(writer, record.default_target);
    writer.count(record.case_targets.size());
    for (const auto& target : record.case_targets)
        write_address(writer, target);
    writer.u8(record.entry_size);
    writer.boolean(record.relative_entries);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
}

void write_search_type(packed_payload_writer_t& writer,
                       const type_candidate_record_t& record) {
    writer.u64(record.id);
    write_address(writer, record.address);
    writer.u8(static_cast<std::uint8_t>(record.kind));
    writer.string(record.display_name);
    writer.string(record.canonical_type);
    writer.u8(static_cast<std::uint8_t>(record.provenance));
    writer.u8(record.confidence);
    writer.boolean(record.explicitly_unknown);
}

instruction_record_t read_instruction(packed_payload_reader_t& reader) {
    instruction_record_t record;
    record.id = reader.u64();
    record.address = read_address(reader);
    record.length = reader.u8();
    record.mnemonic_id = reader.u16();
    record.opcode_id = reader.u32();
    record.flow_flags = reader.u32();
    record.operand_fact_begin = reader.u32();
    record.operand_fact_count = reader.u16();
    record.target_fact_begin = reader.u32();
    record.target_fact_count = reader.u16();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.coverage = static_cast<coverage_reason_t>(reader.u8());
    record.stable_source_id = reader.u64();
    return record;
}

operand_fact_t read_operand(packed_payload_reader_t& reader) {
    operand_fact_t record;
    record.id = reader.u64();
    record.instruction_id = reader.u64();
    record.address_expression_id = reader.u64();
    record.operand_index = reader.u8();
    record.decoder_operand_id = reader.u8();
    record.kind = static_cast<operand_kind_t>(reader.u8());
    record.access = reader.u8();
    record.visibility = reader.u8();
    record.encoding = reader.u8();
    record.memory_type = reader.u8();
    record.access_width = reader.u8();
    record.bit_width = reader.u16();
    record.access_width_bits = reader.u16();
    record.access_count = reader.u16();
    record.element_width_bits = reader.u16();
    record.element_count = reader.u16();
    record.address_width_bits = reader.u16();
    record.reg = reader.u16();
    record.segment_reg = reader.u16();
    record.base_reg = reader.u16();
    record.index_reg = reader.u16();
    record.scale = reader.u8();
    record.relative = reader.boolean();
    record.signed_value = reader.boolean();
    record.has_displacement = reader.boolean();
    record.has_resolved_expression_value = reader.boolean();
    record.displacement = reader.i64();
    record.immediate = reader.u64();
    record.resolved_expression_value = reader.u64();
    record.address_components = reader.u16();
    record.address_expression =
        static_cast<address_expression_kind_t>(reader.u8());
    record.address_resolution = static_cast<target_resolution_t>(reader.u8());
    return record;
}

target_fact_t read_target(packed_payload_reader_t& reader) {
    target_fact_t record;
    record.instruction_id = reader.u64();
    record.operand_fact_id = reader.u64();
    record.address_expression_id = reader.u64();
    record.target = read_address(reader);
    record.kind = static_cast<target_kind_record_t>(reader.u8());
    record.resolution = static_cast<target_resolution_t>(reader.u8());
    record.operand_index = reader.u8();
    record.access_width_bits = reader.u16();
    record.access_count = reader.u16();
    record.direct = reader.boolean();
    record.is_external = reader.boolean();
    return record;
}

basic_block_record_t read_block(packed_payload_reader_t& reader) {
    basic_block_record_t record;
    record.id = reader.u64();
    record.function_id = reader.u64();
    record.start = read_address(reader);
    record.end = read_address(reader);
    record.first_instruction = reader.u32();
    record.instruction_count = reader.u32();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

function_chunk_record_t read_function_chunk(packed_payload_reader_t& reader) {
    function_chunk_record_t record;
    record.id = reader.u64();
    record.function_id = reader.u64();
    record.start = read_address(reader);
    record.end = read_address(reader);
    record.first_block = reader.u32();
    record.block_count = reader.u32();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.cold = reader.boolean();
    record.shared = reader.boolean();
    return record;
}

function_block_membership_record_t read_function_membership(
    packed_payload_reader_t& reader) {
    function_block_membership_record_t record;
    record.function_id = reader.u64();
    record.chunk_id = reader.u64();
    record.block_id = reader.u64();
    record.block_index = reader.u32();
    record.ordinal = reader.u32();
    record.shared = reader.boolean();
    return record;
}

function_record_t read_function(packed_payload_reader_t& reader) {
    function_record_t record;
    record.id = reader.u64();
    record.start = read_address(reader);
    record.end = read_address(reader);
    record.first_block = reader.u32();
    record.block_count = reader.u32();
    record.first_chunk = reader.u32();
    record.chunk_count = reader.u32();
    record.first_block_membership = reader.u32();
    record.block_membership_count = reader.u32();
    record.symbol_id = read_optional_entity(reader);
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.thunk = reader.boolean();
    record.noreturn = reader.boolean();
    const auto chunk_count = reader.count();
    record.chunks.reserve(chunk_count);
    for (std::size_t index = 0; index < chunk_count; ++index) {
        address_range_t chunk;
        chunk.rva_start = reader.u64();
        chunk.rva_end = reader.u64();
        chunk.chunk_kind = reader.u8();
        record.chunks.push_back(chunk);
    }
    return record;
}

edge_record_t read_edge(packed_payload_reader_t& reader) {
    edge_record_t record;
    record.id = reader.u64();
    record.source_entity = reader.u64();
    record.target_entity = read_optional_entity(reader);
    record.source = read_address(reader);
    record.target = read_address(reader);
    record.kind = static_cast<edge_kind_t>(reader.u8());
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

xref_record_t read_xref(packed_payload_reader_t& reader) {
    xref_record_t record;
    record.id = reader.u64();
    record.source = read_address(reader);
    record.target = read_address(reader);
    record.kind = static_cast<xref_kind_t>(reader.u8());
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

string_record_t read_string_record(packed_payload_reader_t& reader) {
    string_record_t record;
    record.id = reader.u64();
    record.address = read_address(reader);
    record.byte_length = reader.u64();
    record.encoding = static_cast<string_encoding_t>(reader.u8());
    record.value = reader.string();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

symbol_record_t read_symbol(packed_payload_reader_t& reader) {
    symbol_record_t record;
    record.id = reader.u64();
    record.address = read_address(reader);
    record.name = reader.string();
    record.kind = static_cast<symbol_kind_t>(reader.u8());
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

coverage_span_t read_coverage(packed_payload_reader_t& reader) {
    coverage_span_t record;
    record.start = read_address(reader);
    record.size = reader.u64();
    record.reason = static_cast<coverage_reason_t>(reader.u8());
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.detail_code = reader.u32();
    return record;
}

address_expression_record_t read_address_expression(packed_payload_reader_t& reader) {
    address_expression_record_t record;
    record.components = reader.u16();
    record.base_reg = reader.u16();
    record.index_reg = reader.u16();
    record.segment_reg = reader.u16();
    record.kind = reader.u8();
    record.resolution = reader.u8();
    record.scale = reader.u8();
    record.disp_class = reader.u8();
    return record;
}

data_candidate_record_t read_data_candidate(packed_payload_reader_t& reader) {
    data_candidate_record_t record;
    record.id = reader.u64();
    record.address = read_address(reader);
    record.size = reader.u64();
    record.kind = static_cast<data_candidate_kind_t>(reader.u8());
    record.target = read_optional_address(reader);
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

data_pointer_fact_t read_data_pointer(packed_payload_reader_t& reader) {
    data_pointer_fact_t record;
    record.id = reader.u64();
    record.slot = read_address(reader);
    record.target = read_address(reader);
    record.candidate_kind = static_cast<data_candidate_kind_t>(reader.u8());
    record.encoding = static_cast<data_pointer_encoding_t>(reader.u8());
    record.width_bytes = reader.u8();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

data_candidate_conflict_t read_data_conflict(
    packed_payload_reader_t& reader) {
    data_candidate_conflict_t record;
    record.id = reader.u64();
    record.address = read_address(reader);
    record.kind = static_cast<data_candidate_kind_t>(reader.u8());
    record.selected_target = read_optional_address(reader);
    record.rejected_target = read_optional_address(reader);
    record.selected_provenance = static_cast<fact_provenance_t>(reader.u8());
    record.rejected_provenance = static_cast<fact_provenance_t>(reader.u8());
    record.selected_confidence = reader.u8();
    record.rejected_confidence = reader.u8();
    return record;
}

symbol_type_candidate_record_t read_symbol_type_candidate(
    packed_payload_reader_t& reader) {
    symbol_type_candidate_record_t record;
    record.id = reader.u64();
    record.address = read_optional_address(reader);
    record.related_address = read_optional_address(reader);
    record.kind = static_cast<symbol_type_candidate_kind_t>(reader.u8());
    record.display_name = reader.string();
    record.canonical_type = reader.string();
    record.source_key = reader.string();
    record.provenance = static_cast<metadata_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.explicitly_unknown = reader.boolean();
    return record;
}

type_reference_fact_t read_type_reference(packed_payload_reader_t& reader) {
    type_reference_fact_t record;
    record.id = reader.u64();
    record.source = read_optional_address(reader);
    record.target = read_optional_address(reader);
    record.source_entity = reader.u64();
    record.target_entity = reader.u64();
    record.kind = static_cast<type_reference_kind_t>(reader.u8());
    record.provenance = static_cast<metadata_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.source_key = reader.string();
    return record;
}

metadata_conflict_record_t read_metadata_conflict(
    packed_payload_reader_t& reader) {
    metadata_conflict_record_t record;
    record.id = reader.u64();
    record.address = read_optional_address(reader);
    record.identity = reader.string();
    record.kind = static_cast<metadata_conflict_kind_t>(reader.u8());
    record.selected_value = reader.string();
    record.rejected_value = reader.string();
    record.selected_provenance = static_cast<metadata_provenance_t>(reader.u8());
    record.rejected_provenance = static_cast<metadata_provenance_t>(reader.u8());
    record.selected_confidence = reader.u8();
    record.rejected_confidence = reader.u8();
    return record;
}

call_graph_quality_t read_call_quality(packed_payload_reader_t& reader) {
    call_graph_quality_t quality;
    quality.provenance = static_cast<fact_provenance_t>(reader.u8());
    quality.confidence = reader.u8();
    quality.contributor_count = reader.u32();
    quality.conflicted = reader.boolean();
    return quality;
}

call_graph_node_record_t read_call_node(packed_payload_reader_t& reader) {
    call_graph_node_record_t record;
    record.function_id = reader.u64();
    record.address = read_address(reader);
    record.incoming_edges = reader.u64();
    record.outgoing_edges = reader.u64();
    record.indirect_edges = reader.u64();
    record.unresolved_sites = reader.u64();
    return record;
}

recovered_call_site_t read_call_site(packed_payload_reader_t& reader) {
    recovered_call_site_t record;
    record.id = reader.u64();
    record.source_function_id = reader.u64();
    record.source_block_id = reader.u64();
    record.instruction_id = reader.u64();
    record.address = read_address(reader);
    record.first_candidate = reader.u32();
    record.candidate_count = reader.u32();
    record.indirect = reader.boolean();
    record.tail_call = reader.boolean();
    record.unresolved = reader.boolean();
    return record;
}

recovered_call_candidate_t read_call_candidate(
    packed_payload_reader_t& reader) {
    recovered_call_candidate_t record;
    record.id = reader.u64();
    record.call_site_id = reader.u64();
    record.target = read_address(reader);
    record.target_function_id = read_optional_entity(reader);
    record.kind = static_cast<indirect_call_candidate_kind_t>(reader.u8());
    record.quality = read_call_quality(reader);
    record.stable_source_id = reader.u64();
    record.rank = reader.u32();
    record.external_target = reader.boolean();
    return record;
}

call_graph_edge_record_t read_call_edge(packed_payload_reader_t& reader) {
    call_graph_edge_record_t record;
    record.id = reader.u64();
    record.call_site_id = reader.u64();
    record.source_function_id = reader.u64();
    record.source_block_id = reader.u64();
    record.target_function_id = read_optional_entity(reader);
    record.call_site = read_address(reader);
    record.target = read_address(reader);
    record.resolution = static_cast<call_graph_resolution_t>(reader.u8());
    record.quality = read_call_quality(reader);
    record.candidate_rank = reader.u32();
    record.external_target = reader.boolean();
    record.target_noreturn = reader.boolean();
    return record;
}

call_graph_conflict_t read_call_conflict(packed_payload_reader_t& reader) {
    call_graph_conflict_t record;
    record.id = reader.u64();
    record.kind = static_cast<call_graph_conflict_kind_t>(reader.u8());
    record.instruction_id = reader.u64();
    record.source_function_id = reader.u64();
    record.call_site_rva = reader.u64();
    record.selected_target_rva = reader.u64();
    record.competing_target_rva = reader.u64();
    record.selected_target_function_id = reader.u64();
    record.competing_target_function_id = reader.u64();
    return record;
}

switch_record_t read_switch(packed_payload_reader_t& reader) {
    switch_record_t record;
    record.id = reader.u64();
    record.function_id = reader.u64();
    record.dispatch = read_address(reader);
    record.table = read_address(reader);
    record.default_target = read_optional_address(reader);
    const auto case_count = reader.count();
    record.case_targets.reserve(case_count);
    for (std::size_t index = 0; index < case_count; ++index)
        record.case_targets.push_back(read_address(reader));
    record.entry_size = reader.u8();
    record.relative_entries = reader.boolean();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    return record;
}

type_candidate_record_t read_search_type(packed_payload_reader_t& reader) {
    type_candidate_record_t record;
    record.id = reader.u64();
    record.address = read_address(reader);
    record.kind = static_cast<type_candidate_kind_t>(reader.u8());
    record.display_name = reader.string();
    record.canonical_type = reader.string();
    record.provenance = static_cast<fact_provenance_t>(reader.u8());
    record.confidence = reader.u8();
    record.explicitly_unknown = reader.boolean();
    return record;
}

workspace_error_t database_error(sqlite3* database, int status, std::string message,
                                 const char* phase) {
    auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
                                      std::move(message), phase);
    error.sqlite_status = status;
    if (database) {
        error.details.emplace_back("sqlite_primary_status",
                                   std::to_string(sqlite3_errcode(database)));
        error.details.emplace_back("sqlite_extended_status",
                                   std::to_string(sqlite3_extended_errcode(database)));
        const char* detail = sqlite3_errmsg(database);
        if (detail && *detail)
            error.details.emplace_back("sqlite_message", detail);
    }
    return error;
}

workspace_result_t<void> exec_sql(sqlite3* database, const char* sql, const char* phase) {
    char* detail = nullptr;
    const int status = sqlite3_exec(database, sql, nullptr, nullptr, &detail);
    if (status == SQLITE_OK)
        return workspace_result_t<void>::success();
    std::string message = "SQLite statement failed";
    if (detail && *detail)
        message += std::string(": ") + detail;
    sqlite3_free(detail);
    return workspace_result_t<void>::failure(
        database_error(database, status, std::move(message), phase));
}

class statement_t final {
public:
    statement_t() = default;
    ~statement_t() {
        release_current();
    }
    statement_t(const statement_t&) = delete;
    statement_t& operator=(const statement_t&) = delete;

    workspace_result_t<void> prepare(sqlite3* database, const char* sql,
                                     const char* phase) {
        release_current();
        std::shared_ptr<sqlite_statement_cache_t> cache;
        try {
            cache = sqlite_statement_cache_lookup(database);
        } catch (...) {
            cache.reset();
        }
        if (cache) {
            int status = SQLITE_OK;
            sqlite3_stmt* cached = nullptr;
            try {
                cached = cache->acquire(database, sql, status);
            } catch (...) {
                cached = nullptr;
                status = SQLITE_OK;
            }
            if (cached) {
                std::string sql_key;
                try {
                    sql_key = sql;
                } catch (...) {
                    sqlite3_finalize(cached);
                    cached = nullptr;
                }
                if (cached) {
                    statement_ = cached;
                    cache_ = std::move(cache);
                    cache_sql_ = std::move(sql_key);
                    database_ = database;
                    phase_ = phase;
                    return workspace_result_t<void>::success();
                }
            }
            if (status != SQLITE_OK) {
                return workspace_result_t<void>::failure(
                    database_error(database, status,
                                   "failed to prepare SQLite statement", phase));
            }
        }
        const int status = sqlite3_prepare_v3(database, sql, -1,
                                              SQLITE_PREPARE_PERSISTENT,
                                              &statement_, nullptr);
        if (status != SQLITE_OK) {
            return workspace_result_t<void>::failure(
                database_error(database, status, "failed to prepare SQLite statement", phase));
        }
        database_ = database;
        phase_ = phase;
        return workspace_result_t<void>::success();
    }

    sqlite3_stmt* get() const noexcept { return statement_; }

    workspace_result_t<void> bind_int(int index, std::int64_t value) {
        return bind_status(sqlite3_bind_int64(statement_, index, value));
    }

    workspace_result_t<void> bind_uint(int index, std::uint64_t value) {
        std::int64_t encoded = 0;
        static_assert(sizeof(encoded) == sizeof(value));
        std::memcpy(&encoded, &value, sizeof(encoded));
        return bind_int(index, encoded);
    }

    workspace_result_t<void> bind_text(int index, const std::string& value) {
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return workspace_result_t<void>::failure(
                database_error(database_, SQLITE_TOOBIG, "text value exceeds SQLite limit", phase_));
        }
        return bind_status(sqlite3_bind_text(statement_, index, value.data(),
                                             static_cast<int>(value.size()), SQLITE_TRANSIENT));
    }

    workspace_result_t<void> bind_blob(int index, const void* data, std::size_t size) {
        if (size > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
            return workspace_result_t<void>::failure(
                database_error(database_, SQLITE_TOOBIG, "blob value exceeds SQLite limit", phase_));
        }
        if (size != 0 && !data) {
            return workspace_result_t<void>::failure(
                database_error(database_, SQLITE_MISUSE,
                               "blob value is null with a non-zero size", phase_));
        }
        return bind_status(size == 0
            ? sqlite3_bind_zeroblob(statement_, index, 0)
            : sqlite3_bind_blob(statement_, index, data,
                                static_cast<int>(size), SQLITE_TRANSIENT));
    }

    workspace_result_t<void> bind_null(int index) {
        return bind_status(sqlite3_bind_null(statement_, index));
    }

    workspace_result_t<void> step_done() {
        const int status = sqlite3_step(statement_);
        if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(
                database_error(database_, status, "SQLite write did not complete", phase_));
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> reset() {
        int status = sqlite3_reset(statement_);
        if (status == SQLITE_OK)
            status = sqlite3_clear_bindings(statement_);
        return bind_status(status);
    }

private:
    workspace_result_t<void> bind_status(int status) {
        if (status == SQLITE_OK)
            return workspace_result_t<void>::success();
        return workspace_result_t<void>::failure(
            database_error(database_, status, "SQLite statement binding failed", phase_));
    }

    void release_current() noexcept {
        if (!statement_)
            return;
        if (cache_) {
            try {
                cache_->release(cache_sql_, statement_);
                statement_ = nullptr;
            } catch (...) {
                sqlite3_finalize(statement_);
                statement_ = nullptr;
            }
            cache_.reset();
            cache_sql_.clear();
        } else {
            sqlite3_finalize(statement_);
            statement_ = nullptr;
        }
    }

    sqlite3* database_ = nullptr;
    sqlite3_stmt* statement_ = nullptr;
    const char* phase_ = "workspace_database";
    std::shared_ptr<sqlite_statement_cache_t> cache_;
    std::string cache_sql_;
};

int sqlite_cancel_progress(void* context) noexcept {
    const auto* cancel = static_cast<const cancellation_token_t*>(context);
    return cancel && cancel->stop_requested() ? 1 : 0;
}

class sqlite_progress_guard_t final {
public:
    sqlite_progress_guard_t(sqlite3* database,
                            const cancellation_token_t& cancel)
        : database_(database) {
        sqlite3_progress_handler(database_, 4096, sqlite_cancel_progress,
                                 const_cast<cancellation_token_t*>(&cancel));
    }

    ~sqlite_progress_guard_t() {
        reset();
    }

    void reset() noexcept {
        if (!database_)
            return;
        sqlite3_progress_handler(database_, 0, nullptr, nullptr);
        database_ = nullptr;
    }

    sqlite_progress_guard_t(const sqlite_progress_guard_t&) = delete;
    sqlite_progress_guard_t& operator=(const sqlite_progress_guard_t&) = delete;

private:
    sqlite3* database_ = nullptr;
};

workspace_error_t database_cancellation_error(
    const cancellation_token_t& cancel, std::string message,
    const char* phase) {
    auto error = make_workspace_error(
        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                   : workspace_error_code_t::cancelled,
        std::move(message), phase);
    error.deadline = cancel.deadline_exceeded();
    error.cancellation = !error.deadline;
    return error;
}

workspace_result_t<void> copy_blob_cancellable(
    std::vector<std::uint8_t>& output, const void* data, std::size_t size,
    const cancellation_token_t& cancel, const char* phase) {
    if (size != 0 && !data) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "persisted blob pointer is null", phase));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "persisted blob copy was cancelled", phase));
    }
    output.resize(size);
    const auto* input = static_cast<const std::uint8_t*>(data);
    for (std::size_t offset = 0; offset < size;
         offset += kDatabaseBlobCopyChunk) {
        if (cancel.stop_requested()) {
            output.clear();
            return workspace_result_t<void>::failure(database_cancellation_error(
                cancel, "persisted blob copy was cancelled", phase));
        }
        const std::size_t chunk =
            (std::min)(kDatabaseBlobCopyChunk, size - offset);
        std::memcpy(output.data() + offset, input + offset, chunk);
    }
    if (cancel.stop_requested()) {
        output.clear();
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "persisted blob copy was cancelled", phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> bind_address(statement_t& statement, int first,
                                      const address_t& address) {
    auto result = statement.bind_int(first, static_cast<std::int64_t>(address.space));
    if (!result) return result;
    result = statement.bind_uint(first + 1, address.value);
    if (!result) return result;
    result = statement.bind_int(first + 2, static_cast<std::int64_t>(address.architecture));
    if (!result) return result;
    return statement.bind_int(first + 3, static_cast<std::int64_t>(address.mode));
}

workspace_result_t<void> bind_optional_address(
    statement_t& statement, int first,
    const std::optional<address_t>& address) {
    if (address)
        return bind_address(statement, first, *address);
    for (int offset = 0; offset < 4; ++offset) {
        auto result = statement.bind_null(first + offset);
        if (!result)
            return result;
    }
    return workspace_result_t<void>::success();
}

address_t read_address(sqlite3_stmt* statement, int first) {
    address_t result;
    result.space = static_cast<address_space_id_t>(sqlite3_column_int(statement, first));
    result.value = static_cast<std::uint64_t>(sqlite3_column_int64(statement, first + 1));
    result.architecture = static_cast<architecture_id_t>(sqlite3_column_int(statement, first + 2));
    result.mode = static_cast<architecture_mode_t>(sqlite3_column_int(statement, first + 3));
    return result;
}

std::optional<address_t> read_optional_address(sqlite3_stmt* statement,
                                               int first) {
    if (sqlite3_column_type(statement, first) == SQLITE_NULL)
        return std::nullopt;
    return read_address(statement, first);
}

std::string column_text(sqlite3_stmt* statement, int index) {
    const unsigned char* value = sqlite3_column_text(statement, index);
    const int bytes = sqlite3_column_bytes(statement, index);
    if (!value || bytes <= 0)
        return {};
    return std::string(reinterpret_cast<const char*>(value), static_cast<std::size_t>(bytes));
}

void append_u8(std::vector<std::uint8_t>& output, std::uint8_t value) {
    output.push_back(value);
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

workspace_result_t<std::uint8_t> read_u8(const std::uint8_t*& cursor,
                                         const std::uint8_t* end) {
    if (cursor == end) {
        return workspace_result_t<std::uint8_t>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk is truncated", "workspace_database"));
    }
    return workspace_result_t<std::uint8_t>::success(*cursor++);
}

template <typename T>
workspace_result_t<T> read_unsigned_le(const std::uint8_t*& cursor,
                                       const std::uint8_t* end) {
    if (static_cast<std::size_t>(end - cursor) < sizeof(T)) {
        return workspace_result_t<T>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk is truncated", "workspace_database"));
    }
    T result = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index)
        result |= static_cast<T>(cursor[index]) << (index * 8);
    cursor += sizeof(T);
    return workspace_result_t<T>::success(result);
}

std::vector<std::uint8_t> encode_instruction_chunk(
    const std::vector<instruction_record_t>& instructions,
    std::size_t begin, std::size_t end) {
    std::vector<std::uint8_t> output;
    output.reserve(kInstructionBlobHeaderSize +
                   (end - begin) * kInstructionBlobRecordSize);
    append_u32(output, kInstructionBlobMagic);
    append_u32(output, workspace_instruction_blob_version);
    append_u64(output, static_cast<std::uint64_t>(end - begin));
    for (std::size_t index = begin; index < end; ++index) {
        const auto& record = instructions[index];
        append_u64(output, record.id);
        append_u8(output, static_cast<std::uint8_t>(record.address.space));
        append_u64(output, record.address.value);
        append_u8(output, static_cast<std::uint8_t>(record.address.architecture));
        append_u8(output, static_cast<std::uint8_t>(record.address.mode));
        append_u8(output, record.length);
        append_u16(output, record.mnemonic_id);
        append_u32(output, record.opcode_id);
        append_u32(output, record.flow_flags);
        append_u32(output, record.operand_fact_begin);
        append_u16(output, record.operand_fact_count);
        append_u32(output, record.target_fact_begin);
        append_u16(output, record.target_fact_count);
        append_u8(output, static_cast<std::uint8_t>(record.provenance));
        append_u8(output, record.confidence);
        append_u8(output, static_cast<std::uint8_t>(record.coverage));
        append_u64(output, record.stable_source_id);
    }
    return output;
}

workspace_result_t<void> decode_instruction_chunk(
    const void* data, std::size_t size,
    std::vector<instruction_record_t>& output,
    std::uint64_t max_records, std::uint64_t max_chunk_records,
    const cancellation_token_t& cancel) {
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "instruction chunk decode was cancelled",
            "workspace_database.load.instructions"));
    }
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    const auto* end = cursor + size;
    auto magic = read_unsigned_le<std::uint32_t>(cursor, end);
    if (!magic || magic.value() != kInstructionBlobMagic) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk magic is invalid", "workspace_database"));
    }
    auto version = read_unsigned_le<std::uint32_t>(cursor, end);
    if (!version || version.value() == 0 ||
        version.value() > workspace_instruction_blob_version) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk version is unsupported", "workspace_database"));
    }
    auto count_result = read_unsigned_le<std::uint64_t>(cursor, end);
    if (!count_result || count_result.value() == 0 ||
        count_result.value() > max_chunk_records) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk record count is invalid", "workspace_database"));
    }
    const std::uint64_t count = count_result.value();
    std::uint64_t encoded_records_size = 0;
    if (!checked_mul_u64(count, kInstructionBlobRecordSize,
                         encoded_records_size) ||
        encoded_records_size != static_cast<std::uint64_t>(end - cursor)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk record payload is malformed",
                                 "workspace_database"));
    }
    if (output.size() > max_records || count > max_records - output.size()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "persisted instructions exceed the reopen budget",
            "workspace_database.load.instructions"));
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "instruction chunk decode was cancelled",
            "workspace_database.load.instructions"));
    }
    output.reserve(output.size() + static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        if (index % kDatabaseRecordPollStride == 0 &&
            cancel.stop_requested()) {
            return workspace_result_t<void>::failure(database_cancellation_error(
                cancel, "instruction chunk decode was cancelled",
                "workspace_database.load.instructions"));
        }
        instruction_record_t record;
        auto id = read_unsigned_le<std::uint64_t>(cursor, end); if (!id) return workspace_result_t<void>::failure(id.error());
        auto space = read_u8(cursor, end); if (!space) return workspace_result_t<void>::failure(space.error());
        auto value = read_unsigned_le<std::uint64_t>(cursor, end); if (!value) return workspace_result_t<void>::failure(value.error());
        auto architecture = read_u8(cursor, end); if (!architecture) return workspace_result_t<void>::failure(architecture.error());
        auto mode = read_u8(cursor, end); if (!mode) return workspace_result_t<void>::failure(mode.error());
        auto length = read_u8(cursor, end); if (!length) return workspace_result_t<void>::failure(length.error());
        auto mnemonic = read_unsigned_le<std::uint16_t>(cursor, end); if (!mnemonic) return workspace_result_t<void>::failure(mnemonic.error());
        auto opcode = read_unsigned_le<std::uint32_t>(cursor, end); if (!opcode) return workspace_result_t<void>::failure(opcode.error());
        auto flow = read_unsigned_le<std::uint32_t>(cursor, end); if (!flow) return workspace_result_t<void>::failure(flow.error());
        auto operand_begin = read_unsigned_le<std::uint32_t>(cursor, end); if (!operand_begin) return workspace_result_t<void>::failure(operand_begin.error());
        auto operand_count = read_unsigned_le<std::uint16_t>(cursor, end); if (!operand_count) return workspace_result_t<void>::failure(operand_count.error());
        auto target_begin = read_unsigned_le<std::uint32_t>(cursor, end); if (!target_begin) return workspace_result_t<void>::failure(target_begin.error());
        auto target_count = read_unsigned_le<std::uint16_t>(cursor, end); if (!target_count) return workspace_result_t<void>::failure(target_count.error());
        auto provenance = read_u8(cursor, end); if (!provenance) return workspace_result_t<void>::failure(provenance.error());
        auto confidence = read_u8(cursor, end); if (!confidence) return workspace_result_t<void>::failure(confidence.error());
        auto coverage = read_u8(cursor, end); if (!coverage) return workspace_result_t<void>::failure(coverage.error());
        auto source = read_unsigned_le<std::uint64_t>(cursor, end); if (!source) return workspace_result_t<void>::failure(source.error());
        record.id = id.value();
        record.address.space = static_cast<address_space_id_t>(space.value());
        record.address.value = value.value();
        record.address.architecture = static_cast<architecture_id_t>(architecture.value());
        record.address.mode = static_cast<architecture_mode_t>(mode.value());
        record.length = length.value();
        record.mnemonic_id = mnemonic.value();
        record.opcode_id = opcode.value();
        record.flow_flags = flow.value();
        record.operand_fact_begin = operand_begin.value();
        record.operand_fact_count = operand_count.value();
        record.target_fact_begin = target_begin.value();
        record.target_fact_count = target_count.value();
        record.provenance = static_cast<fact_provenance_t>(provenance.value());
        record.confidence = confidence.value();
        record.coverage = static_cast<coverage_reason_t>(coverage.value());
        record.stable_source_id = source.value();
        output.push_back(record);
    }
    if (cancel.stop_requested()) {
        return workspace_result_t<void>::failure(database_cancellation_error(
            cancel, "instruction chunk decode was cancelled",
            "workspace_database.load.instructions"));
    }
    if (cursor != end) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "instruction chunk contains trailing data", "workspace_database"));
    }
    return workspace_result_t<void>::success();
}

constexpr std::uint32_t kFactChunkBlobMagic = 0x4B484346U;
constexpr std::uint32_t kFactChunkBlobVersion = 1;
constexpr std::uint64_t kFactChunkEdgeRecordBytes = 49;

void append_fact_chunk_header(std::vector<std::uint8_t>& output,
                              std::uint64_t count, std::uint64_t stride) {
    append_u32(output, kFactChunkBlobMagic);
    append_u32(output, kFactChunkBlobVersion);
    append_u64(output, count);
    append_u64(output, stride);
}

std::vector<std::uint8_t> encode_edge_chunk_record(const edge_record_t& record) {
    std::vector<std::uint8_t> output;
    output.reserve(static_cast<std::size_t>(kFactChunkEdgeRecordBytes));
    append_u64(output, record.id);
    append_u64(output, record.source_entity);
    append_u64(output, record.target_entity.has_value() ? *record.target_entity : 0);
    append_u8(output, static_cast<std::uint8_t>(record.source.space));
    append_u64(output, record.source.value);
    append_u8(output, static_cast<std::uint8_t>(record.source.architecture));
    append_u8(output, static_cast<std::uint8_t>(record.source.mode));
    append_u8(output, static_cast<std::uint8_t>(record.target.space));
    append_u64(output, record.target.value);
    append_u8(output, static_cast<std::uint8_t>(record.target.architecture));
    append_u8(output, static_cast<std::uint8_t>(record.target.mode));
    append_u8(output, static_cast<std::uint8_t>(record.kind));
    append_u8(output, static_cast<std::uint8_t>(record.provenance));
    append_u8(output, record.confidence);
    return output;
}

edge_record_t decode_edge_chunk_record(const std::uint8_t* data) {
    edge_record_t record;
    const auto* cursor = data;
    std::uint64_t raw = 0;
    std::memcpy(&raw, cursor, sizeof(raw)); cursor += sizeof(raw);
    record.id = raw;
    std::memcpy(&raw, cursor, sizeof(raw)); cursor += sizeof(raw);
    record.source_entity = raw;
    std::memcpy(&raw, cursor, sizeof(raw)); cursor += sizeof(raw);
    if (raw != 0)
        record.target_entity = raw;
    record.source.space = static_cast<address_space_id_t>(*cursor++);
    std::memcpy(&raw, cursor, sizeof(raw)); cursor += sizeof(raw);
    record.source.value = raw;
    record.source.architecture = static_cast<architecture_id_t>(*cursor++);
    record.source.mode = static_cast<architecture_mode_t>(*cursor++);
    record.target.space = static_cast<address_space_id_t>(*cursor++);
    std::memcpy(&raw, cursor, sizeof(raw)); cursor += sizeof(raw);
    record.target.value = raw;
    record.target.architecture = static_cast<architecture_id_t>(*cursor++);
    record.target.mode = static_cast<architecture_mode_t>(*cursor++);
    record.kind = static_cast<edge_kind_t>(*cursor++);
    record.provenance = static_cast<fact_provenance_t>(*cursor++);
    record.confidence = *cursor++;
    return record;
}

workspace_result_t<void> decode_fact_chunk_envelope(
    const void* data, std::size_t size, std::uint64_t expected_stride,
    std::uint64_t max_chunk_records, std::uint64_t& count_out,
    const std::uint8_t*& records_out, const char* phase) {
    const auto* cursor = static_cast<const std::uint8_t*>(data);
    const auto* end = cursor + size;
    auto magic = read_unsigned_le<std::uint32_t>(cursor, end);
    if (!magic || magic.value() != kFactChunkBlobMagic) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "fact chunk magic is invalid", phase));
    }
    auto version = read_unsigned_le<std::uint32_t>(cursor, end);
    if (!version || version.value() == 0 ||
        version.value() > kFactChunkBlobVersion) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "fact chunk version is unsupported", phase));
    }
    auto count_result = read_unsigned_le<std::uint64_t>(cursor, end);
    if (!count_result || count_result.value() == 0 ||
        count_result.value() > max_chunk_records) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "fact chunk record count is invalid", phase));
    }
    auto stride_result = read_unsigned_le<std::uint64_t>(cursor, end);
    if (!stride_result || stride_result.value() != expected_stride) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "fact chunk record stride is invalid", phase));
    }
    const std::uint64_t count = count_result.value();
    std::uint64_t encoded_records_size = 0;
    if (!checked_mul_u64(count, expected_stride, encoded_records_size) ||
        encoded_records_size != static_cast<std::uint64_t>(end - cursor)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "fact chunk record payload is malformed", phase));
    }
    count_out = count;
    records_out = cursor;
    return workspace_result_t<void>::success();
}

workspace_result_t<std::string> database_path_for(const workspace_identity_t& identity) {
    PWSTR raw = nullptr;
    const HRESULT status = SHGetKnownFolderPath(FOLDERID_RoamingAppData,
                                                KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(status) || !raw) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "unable to resolve roaming application data directory",
                                          "workspace_database");
        error.win32_status = static_cast<std::uint32_t>(status);
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    std::filesystem::path root(raw);
    CoTaskMemFree(raw);
    root /= L"AiDA";
    root /= L"analysis";
    root /= std::filesystem::u8path(identity.content_hash().to_hex());
    std::error_code filesystem_error;
    std::filesystem::create_directories(root, filesystem_error);
    if (filesystem_error) {
        auto error = make_workspace_error(workspace_error_code_t::io_failure,
                                          "unable to create analysis database directory",
                                          "workspace_database");
        error.provider_status = filesystem_error.value();
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    root /= std::filesystem::u8path(identity.load_profile_hash().to_hex() + ".aida.db");
    return workspace_result_t<std::string>::success(root.u8string());
}

workspace_result_t<void> begin_immediate(sqlite3* database, const char* phase) {
    return exec_sql(database, "BEGIN IMMEDIATE", phase);
}

workspace_result_t<void> rollback(sqlite3* database, const char* phase) {
    return exec_sql(database, "ROLLBACK", phase);
}

workspace_result_t<void> commit(sqlite3* database, const char* phase) {
    return exec_sql(database, "COMMIT", phase);
}

workspace_result_t<void> create_schema_v1(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY NOT NULL,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS workspace_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),binary_id BLOB NOT NULL UNIQUE,bin_name TEXT NOT NULL,source_path TEXT NOT NULL,member_path TEXT,content_hash BLOB NOT NULL,load_profile_hash BLOB NOT NULL,target_kind INTEGER NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,abi INTEGER NOT NULL,endian INTEGER NOT NULL,image_base INTEGER NOT NULL,process_pid INTEGER,process_creation INTEGER,process_path TEXT,module_base INTEGER,module_size INTEGER,module_name TEXT,module_path TEXT,module_hash BLOB);
CREATE TABLE IF NOT EXISTS analysis_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,baseline_complete INTEGER NOT NULL,settings_json TEXT NOT NULL,metrics_json TEXT NOT NULL,updated_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS segments(segment_id INTEGER PRIMARY KEY,name TEXT NOT NULL,virtual_address INTEGER NOT NULL,virtual_size INTEGER NOT NULL,raw_offset INTEGER NOT NULL,raw_size INTEGER NOT NULL,characteristics INTEGER NOT NULL,readable INTEGER NOT NULL,writable INTEGER NOT NULL,executable INTEGER NOT NULL,discardable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS instruction_chunks(chunk_id INTEGER PRIMARY KEY,start_value INTEGER NOT NULL,end_value INTEGER NOT NULL,record_count INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS instruction_chunks_range ON instruction_chunks(start_value,end_value);
CREATE TABLE IF NOT EXISTS operand_facts(instruction_id INTEGER NOT NULL,operand_index INTEGER NOT NULL,kind INTEGER NOT NULL,access INTEGER NOT NULL,bit_width INTEGER NOT NULL,reg INTEGER NOT NULL,base_reg INTEGER NOT NULL,index_reg INTEGER NOT NULL,scale INTEGER NOT NULL,relative INTEGER NOT NULL,signed_value INTEGER NOT NULL,displacement INTEGER NOT NULL,immediate INTEGER NOT NULL,PRIMARY KEY(instruction_id,operand_index));
CREATE TABLE IF NOT EXISTS target_facts(instruction_id INTEGER NOT NULL,target_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,direct INTEGER NOT NULL,PRIMARY KEY(instruction_id,target_index));
CREATE INDEX IF NOT EXISTS target_facts_address ON target_facts(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS functions(entity_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,symbol_id INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,thunk INTEGER NOT NULL,noreturn INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS functions_address ON functions(start_space,start_value,start_arch,start_mode,end_value);
CREATE TABLE IF NOT EXISTS blocks(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_instruction INTEGER NOT NULL,instruction_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS blocks_function ON blocks(function_id,start_value);
CREATE TABLE IF NOT EXISTS edges(entity_id INTEGER PRIMARY KEY,source_entity INTEGER NOT NULL,target_entity INTEGER,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS edges_source ON edges(source_entity,kind);
CREATE INDEX IF NOT EXISTS edges_target ON edges(target_entity,kind);
CREATE TABLE IF NOT EXISTS xrefs(entity_id INTEGER PRIMARY KEY,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS xrefs_source ON xrefs(source_space,source_value,source_arch,source_mode);
CREATE INDEX IF NOT EXISTS xrefs_target ON xrefs(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS strings(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,byte_length INTEGER NOT NULL,encoding INTEGER NOT NULL,value TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS strings_address ON strings(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS symbols(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,name TEXT NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS symbols_address ON symbols(address_space,address_value,address_arch,address_mode);
CREATE INDEX IF NOT EXISTS symbols_name ON symbols(name);
CREATE TABLE IF NOT EXISTS coverage(span_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,size INTEGER NOT NULL,reason INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,detail_code INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS coverage_range ON coverage(start_space,start_value,start_arch,start_mode);
)SQL", "workspace_database.migrate_v1");
}

workspace_result_t<void> create_schema_v2(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS overlay_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,history_cursor INTEGER NOT NULL,next_transaction_id INTEGER NOT NULL,history_epoch INTEGER NOT NULL,updated_utc_ms INTEGER NOT NULL);
INSERT OR IGNORE INTO overlay_state(singleton,revision,history_cursor,next_transaction_id,history_epoch,updated_utc_ms) VALUES(1,0,0,1,1,0);
CREATE TABLE IF NOT EXISTS overlay_transactions(transaction_id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,history_epoch INTEGER NOT NULL,history_ordinal INTEGER NOT NULL,idempotency_key TEXT,request_hash TEXT NOT NULL,committed_utc_ms INTEGER NOT NULL,applied INTEGER NOT NULL,abandoned INTEGER NOT NULL,result_json TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS overlay_transactions_history ON overlay_transactions(history_epoch,history_ordinal);
CREATE TABLE IF NOT EXISTS overlay_operations(transaction_id INTEGER NOT NULL,operation_index INTEGER NOT NULL,kind INTEGER NOT NULL,entity_key TEXT NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,before_json TEXT,after_json TEXT NOT NULL,PRIMARY KEY(transaction_id,operation_index),FOREIGN KEY(transaction_id) REFERENCES overlay_transactions(transaction_id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS overlay_operations_entity ON overlay_operations(entity_key,transaction_id);
CREATE TABLE IF NOT EXISTS overlay_items(entity_key TEXT PRIMARY KEY NOT NULL,kind INTEGER NOT NULL,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,payload_json TEXT NOT NULL,updated_revision INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS overlay_items_address ON overlay_items(address_space,address_value,address_arch,address_mode,kind);
CREATE TABLE IF NOT EXISTS overlay_history_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,event_kind INTEGER NOT NULL,source_transaction_id INTEGER NOT NULL,resulting_revision INTEGER NOT NULL,history_epoch INTEGER NOT NULL,history_cursor INTEGER NOT NULL,created_utc_ms INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS overlay_idempotency(idempotency_key TEXT PRIMARY KEY NOT NULL,request_hash TEXT NOT NULL,result_json TEXT NOT NULL,transaction_id INTEGER NOT NULL,created_utc_ms INTEGER NOT NULL,FOREIGN KEY(transaction_id) REFERENCES overlay_transactions(transaction_id));
)SQL", "workspace_database.migrate_v2");
}

workspace_result_t<void> create_schema_v3(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS decompiler_cache(cache_key TEXT PRIMARY KEY NOT NULL,binary_id BLOB NOT NULL,format INTEGER NOT NULL,architecture INTEGER NOT NULL,abi INTEGER NOT NULL,engine_version TEXT NOT NULL,schema_version INTEGER NOT NULL,specification_version TEXT NOT NULL,settings_hash TEXT NOT NULL,function_id INTEGER NOT NULL,function_rva INTEGER NOT NULL,function_content_hash BLOB NOT NULL,overlay_revision INTEGER NOT NULL,generation INTEGER NOT NULL,function_name TEXT NOT NULL,result_json TEXT NOT NULL,created_utc_ms INTEGER NOT NULL,last_access_utc_ms INTEGER NOT NULL,result_bytes INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS decompiler_cache_function ON decompiler_cache(function_rva,overlay_revision,generation);
)SQL", "workspace_database.migrate_v3");
}

workspace_result_t<void> create_schema_v4(sqlite3* database) {
    return exec_sql(database, R"SQL(
CREATE TABLE IF NOT EXISTS data_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS data_candidates_address ON data_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS switches(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,dispatch_space INTEGER NOT NULL,dispatch_value INTEGER NOT NULL,dispatch_arch INTEGER NOT NULL,dispatch_mode INTEGER NOT NULL,table_space INTEGER NOT NULL,table_value INTEGER NOT NULL,table_arch INTEGER NOT NULL,table_mode INTEGER NOT NULL,default_space INTEGER,default_value INTEGER,default_arch INTEGER,default_mode INTEGER,entry_size INTEGER NOT NULL,relative_entries INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS switches_function ON switches(function_id,dispatch_value);
CREATE TABLE IF NOT EXISTS switch_cases(switch_id INTEGER NOT NULL,case_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,PRIMARY KEY(switch_id,case_index),FOREIGN KEY(switch_id) REFERENCES switches(entity_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS type_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS type_candidates_address ON type_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS search_index_blob(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
)SQL", "workspace_database.migrate_v4");
}

workspace_result_t<void> create_schema_v5(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE operand_facts ADD COLUMN segment_reg INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_state ADD COLUMN commit_token TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS workspace_commit_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),active_slot INTEGER NOT NULL CHECK(active_slot IN (0,1)),committed_token TEXT NOT NULL,committed_generation INTEGER NOT NULL,committed_analysis_revision INTEGER NOT NULL,committed_overlay_revision INTEGER NOT NULL,candidate_slot INTEGER CHECK(candidate_slot IN (0,1)),candidate_token TEXT,candidate_generation INTEGER,candidate_analysis_revision INTEGER,candidate_overlay_revision INTEGER,candidate_ready INTEGER NOT NULL CHECK(candidate_ready IN (0,1)),updated_utc_ms INTEGER NOT NULL);
INSERT OR IGNORE INTO workspace_commit_state(singleton,active_slot,committed_token,committed_generation,committed_analysis_revision,committed_overlay_revision,candidate_slot,candidate_token,candidate_generation,candidate_analysis_revision,candidate_overlay_revision,candidate_ready,updated_utc_ms) VALUES(1,0,'',0,0,0,NULL,NULL,NULL,NULL,NULL,0,0);
CREATE TABLE IF NOT EXISTS alternate_analysis_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,baseline_complete INTEGER NOT NULL,settings_json TEXT NOT NULL,metrics_json TEXT NOT NULL,updated_utc_ms INTEGER NOT NULL,commit_token TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_segments(segment_id INTEGER PRIMARY KEY,name TEXT NOT NULL,virtual_address INTEGER NOT NULL,virtual_size INTEGER NOT NULL,raw_offset INTEGER NOT NULL,raw_size INTEGER NOT NULL,characteristics INTEGER NOT NULL,readable INTEGER NOT NULL,writable INTEGER NOT NULL,executable INTEGER NOT NULL,discardable INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alternate_instruction_chunks(chunk_id INTEGER PRIMARY KEY,start_value INTEGER NOT NULL,end_value INTEGER NOT NULL,record_count INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_instruction_chunks_range ON alternate_instruction_chunks(start_value,end_value);
CREATE TABLE IF NOT EXISTS alternate_operand_facts(instruction_id INTEGER NOT NULL,operand_index INTEGER NOT NULL,kind INTEGER NOT NULL,access INTEGER NOT NULL,bit_width INTEGER NOT NULL,reg INTEGER NOT NULL,segment_reg INTEGER NOT NULL,base_reg INTEGER NOT NULL,index_reg INTEGER NOT NULL,scale INTEGER NOT NULL,relative INTEGER NOT NULL,signed_value INTEGER NOT NULL,displacement INTEGER NOT NULL,immediate INTEGER NOT NULL,PRIMARY KEY(instruction_id,operand_index));
CREATE TABLE IF NOT EXISTS alternate_target_facts(instruction_id INTEGER NOT NULL,target_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,direct INTEGER NOT NULL,PRIMARY KEY(instruction_id,target_index));
CREATE INDEX IF NOT EXISTS alternate_target_facts_address ON alternate_target_facts(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS alternate_functions(entity_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,symbol_id INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,thunk INTEGER NOT NULL,noreturn INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_functions_address ON alternate_functions(start_space,start_value,start_arch,start_mode,end_value);
CREATE TABLE IF NOT EXISTS alternate_blocks(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_instruction INTEGER NOT NULL,instruction_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_blocks_function ON alternate_blocks(function_id,start_value);
CREATE TABLE IF NOT EXISTS alternate_edges(entity_id INTEGER PRIMARY KEY,source_entity INTEGER NOT NULL,target_entity INTEGER,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_edges_source ON alternate_edges(source_entity,kind);
CREATE INDEX IF NOT EXISTS alternate_edges_target ON alternate_edges(target_entity,kind);
CREATE TABLE IF NOT EXISTS alternate_xrefs(entity_id INTEGER PRIMARY KEY,source_space INTEGER NOT NULL,source_value INTEGER NOT NULL,source_arch INTEGER NOT NULL,source_mode INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_xrefs_source ON alternate_xrefs(source_space,source_value,source_arch,source_mode);
CREATE INDEX IF NOT EXISTS alternate_xrefs_target ON alternate_xrefs(target_space,target_value,target_arch,target_mode);
CREATE TABLE IF NOT EXISTS alternate_strings(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,byte_length INTEGER NOT NULL,encoding INTEGER NOT NULL,value TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_strings_address ON alternate_strings(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS alternate_symbols(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,name TEXT NOT NULL,kind INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_symbols_address ON alternate_symbols(address_space,address_value,address_arch,address_mode);
CREATE INDEX IF NOT EXISTS alternate_symbols_name ON alternate_symbols(name);
CREATE TABLE IF NOT EXISTS alternate_coverage(span_id INTEGER PRIMARY KEY,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,size INTEGER NOT NULL,reason INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,detail_code INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_coverage_range ON alternate_coverage(start_space,start_value,start_arch,start_mode);
CREATE TABLE IF NOT EXISTS alternate_data_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,size INTEGER NOT NULL,kind INTEGER NOT NULL,target_space INTEGER,target_value INTEGER,target_arch INTEGER,target_mode INTEGER,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_data_candidates_address ON alternate_data_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS alternate_switches(entity_id INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,dispatch_space INTEGER NOT NULL,dispatch_value INTEGER NOT NULL,dispatch_arch INTEGER NOT NULL,dispatch_mode INTEGER NOT NULL,table_space INTEGER NOT NULL,table_value INTEGER NOT NULL,table_arch INTEGER NOT NULL,table_mode INTEGER NOT NULL,default_space INTEGER,default_value INTEGER,default_arch INTEGER,default_mode INTEGER,entry_size INTEGER NOT NULL,relative_entries INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_switches_function ON alternate_switches(function_id,dispatch_value);
CREATE TABLE IF NOT EXISTS alternate_switch_cases(switch_id INTEGER NOT NULL,case_index INTEGER NOT NULL,target_space INTEGER NOT NULL,target_value INTEGER NOT NULL,target_arch INTEGER NOT NULL,target_mode INTEGER NOT NULL,PRIMARY KEY(switch_id,case_index),FOREIGN KEY(switch_id) REFERENCES alternate_switches(entity_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS alternate_type_candidates(entity_id INTEGER PRIMARY KEY,address_space INTEGER NOT NULL,address_value INTEGER NOT NULL,address_arch INTEGER NOT NULL,address_mode INTEGER NOT NULL,kind INTEGER NOT NULL,display_name TEXT NOT NULL,canonical_type TEXT NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,explicitly_unknown INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_type_candidates_address ON alternate_type_candidates(address_space,address_value,address_arch,address_mode);
CREATE TABLE IF NOT EXISTS alternate_search_index_blob(singleton INTEGER PRIMARY KEY CHECK(singleton=1),generation INTEGER NOT NULL,analysis_revision INTEGER NOT NULL,overlay_revision INTEGER NOT NULL,blob_version INTEGER NOT NULL,payload BLOB NOT NULL);
)SQL", "workspace_database.migrate_v5");
}

workspace_result_t<void> create_schema_v6(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE workspace_identity ADD COLUMN architecture_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE decompiler_cache ADD COLUMN architecture_mode INTEGER NOT NULL DEFAULT 0;
ALTER TABLE decompiler_cache ADD COLUMN endian INTEGER NOT NULL DEFAULT 0;
)SQL", "workspace_database.migrate_v6");
}

workspace_result_t<void> create_schema_v7(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE operand_facts ADD COLUMN entity_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN decoder_operand_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN visibility INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN encoding INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN memory_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN access_width INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN element_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN element_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN has_displacement INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN has_resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_components INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_expression INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operand_facts ADD COLUMN address_resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE target_facts ADD COLUMN operand_fact_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE target_facts ADD COLUMN operand_index INTEGER NOT NULL DEFAULT 255;
ALTER TABLE target_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE target_facts ADD COLUMN is_external INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN first_chunk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN chunk_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN first_block_membership INTEGER NOT NULL DEFAULT 0;
ALTER TABLE functions ADD COLUMN block_membership_count INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS function_chunks(chunk_index INTEGER PRIMARY KEY,entity_id INTEGER NOT NULL UNIQUE,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,cold INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS function_chunks_function ON function_chunks(function_id,chunk_index);
CREATE TABLE IF NOT EXISTS function_block_memberships(membership_index INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,chunk_id INTEGER NOT NULL,block_id INTEGER NOT NULL,block_index INTEGER NOT NULL,ordinal INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS function_block_memberships_function_ordinal ON function_block_memberships(function_id,ordinal);
CREATE INDEX IF NOT EXISTS function_block_memberships_chunk ON function_block_memberships(chunk_id,block_index);
ALTER TABLE alternate_operand_facts ADD COLUMN entity_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN decoder_operand_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN visibility INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN encoding INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN memory_type INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN access_width INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN element_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN element_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN has_displacement INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN has_resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN resolved_expression_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_components INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_expression INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_operand_facts ADD COLUMN address_resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE alternate_target_facts ADD COLUMN operand_fact_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN address_expression_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN resolution INTEGER NOT NULL DEFAULT 4;
ALTER TABLE alternate_target_facts ADD COLUMN operand_index INTEGER NOT NULL DEFAULT 255;
ALTER TABLE alternate_target_facts ADD COLUMN access_width_bits INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN access_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_target_facts ADD COLUMN is_external INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN first_chunk INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN chunk_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN first_block_membership INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alternate_functions ADD COLUMN block_membership_count INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS alternate_function_chunks(chunk_index INTEGER PRIMARY KEY,entity_id INTEGER NOT NULL UNIQUE,function_id INTEGER NOT NULL,start_space INTEGER NOT NULL,start_value INTEGER NOT NULL,start_arch INTEGER NOT NULL,start_mode INTEGER NOT NULL,end_space INTEGER NOT NULL,end_value INTEGER NOT NULL,end_arch INTEGER NOT NULL,end_mode INTEGER NOT NULL,first_block INTEGER NOT NULL,block_count INTEGER NOT NULL,provenance INTEGER NOT NULL,confidence INTEGER NOT NULL,cold INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS alternate_function_chunks_function ON alternate_function_chunks(function_id,chunk_index);
CREATE TABLE IF NOT EXISTS alternate_function_block_memberships(membership_index INTEGER PRIMARY KEY,function_id INTEGER NOT NULL,chunk_id INTEGER NOT NULL,block_id INTEGER NOT NULL,block_index INTEGER NOT NULL,ordinal INTEGER NOT NULL,shared INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS alternate_function_block_memberships_function_ordinal ON alternate_function_block_memberships(function_id,ordinal);
CREATE INDEX IF NOT EXISTS alternate_function_block_memberships_chunk ON alternate_function_block_memberships(chunk_id,block_index);
)SQL", "workspace_database.migrate_v7");
}

workspace_result_t<void> create_schema_v8(sqlite3* database) {
    return exec_sql(database, R"SQL(
ALTER TABLE decompiler_cache ADD COLUMN analysis_revision INTEGER NOT NULL DEFAULT 0;
)SQL", "workspace_database.migrate_v8");
}

workspace_result_t<void> migrate_schema(sqlite3* database,
                                        bool& invalidate_derived_facts) {
    invalidate_derived_facts = false;
    std::uint32_t version = 0;
    {
        statement_t query;
        auto prepared = query.prepare(database, "PRAGMA user_version",
                                      "workspace_database.schema");
        if (!prepared)
            return prepared;
        const int status = sqlite3_step(query.get());
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(
                database_error(database, status,
                               "unable to query workspace schema version",
                               "workspace_database.schema"));
        }
        version = static_cast<std::uint32_t>(sqlite3_column_int(query.get(), 0));
    }
    if (version > workspace_database_schema_version) {
        return workspace_result_t<void>::failure(
            database_error(database, SQLITE_MISMATCH,
                           "workspace database schema is newer than this engine",
                           "workspace_database.schema"));
    }
    const bool ensure_existing = version == workspace_database_schema_version;
    invalidate_derived_facts = version > 0 && version < 6;
    while (version < workspace_database_schema_version) {
        auto begin = begin_immediate(database, "workspace_database.schema");
        if (!begin) return begin;
        workspace_result_t<void> migrated = workspace_result_t<void>::success();
        if (version == 0) migrated = create_schema_v1(database);
        else if (version == 1) migrated = create_schema_v2(database);
        else if (version == 2) migrated = create_schema_v3(database);
        else if (version == 3) migrated = create_schema_v4(database);
        else if (version == 4) migrated = create_schema_v5(database);
        else if (version == 5) migrated = create_schema_v6(database);
        else if (version == 6) migrated = create_schema_v7(database);
        else if (version == 7) migrated = create_schema_v8(database);
        else if (version == 8) migrated = create_schema_v9(database);
        else if (version == 9) migrated = create_schema_v10(database);
        else if (version == 10) migrated = create_schema_v11(database);
        if (!migrated) {
            rollback(database, "workspace_database.schema");
            return migrated;
        }
        ++version;
        const std::string set_version = "PRAGMA user_version=" + std::to_string(version);
        auto set_result = exec_sql(database, set_version.c_str(), "workspace_database.schema");
        if (!set_result) {
            rollback(database, "workspace_database.schema");
            return set_result;
        }
        auto committed = commit(database, "workspace_database.schema");
        if (!committed) {
            rollback(database, "workspace_database.schema");
            return committed;
        }
    }
    if (ensure_existing) {
        auto begin = begin_immediate(database, "workspace_database.schema");
        if (!begin)
            return begin;
        auto ensured = create_schema_v11(database);
        if (!ensured) {
            rollback(database, "workspace_database.schema");
            return ensured;
        }
        auto committed = commit(database, "workspace_database.schema");
        if (!committed) {
            rollback(database, "workspace_database.schema");
            return committed;
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<std::optional<std::string>> metadata_value(sqlite3* database,
                                                              const std::string& key) {
    statement_t statement;
    auto result = statement.prepare(database, "SELECT value FROM metadata WHERE key=?1",
                                    "workspace_database.metadata");
    if (!result) return workspace_result_t<std::optional<std::string>>::failure(result.error());
    result = statement.bind_text(1, key);
    if (!result) return workspace_result_t<std::optional<std::string>>::failure(result.error());
    const int status = sqlite3_step(statement.get());
    if (status == SQLITE_DONE)
        return workspace_result_t<std::optional<std::string>>::success(std::nullopt);
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::optional<std::string>>::failure(
            database_error(database, status, "unable to read workspace metadata",
                           "workspace_database.metadata"));
    }
    return workspace_result_t<std::optional<std::string>>::success(
        std::optional<std::string>(column_text(statement.get(), 0)));
}

workspace_result_t<void> set_metadata(sqlite3* database, const std::string& key,
                                      const std::string& value) {
    statement_t statement;
    auto result = statement.prepare(database,
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        "workspace_database.metadata");
    if (!result) return result;
    result = statement.bind_text(1, key); if (!result) return result;
    result = statement.bind_text(2, value); if (!result) return result;
    return statement.step_done();
}

workspace_result_t<void> bind_identity(sqlite3* database,
                                      const workspace_identity_t& identity) {
    statement_t statement;
    auto result = statement.prepare(database, R"SQL(
INSERT INTO workspace_identity(singleton,binary_id,bin_name,source_path,member_path,content_hash,load_profile_hash,target_kind,format,architecture,architecture_mode,abi,endian,image_base,process_pid,process_creation,process_path,module_base,module_size,module_name,module_path,module_hash)
VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
ON CONFLICT(singleton) DO UPDATE SET binary_id=excluded.binary_id,bin_name=excluded.bin_name,source_path=excluded.source_path,member_path=excluded.member_path,content_hash=excluded.content_hash,load_profile_hash=excluded.load_profile_hash,target_kind=excluded.target_kind,format=excluded.format,architecture=excluded.architecture,architecture_mode=excluded.architecture_mode,abi=excluded.abi,endian=excluded.endian,image_base=excluded.image_base,process_pid=excluded.process_pid,process_creation=excluded.process_creation,process_path=excluded.process_path,module_base=excluded.module_base,module_size=excluded.module_size,module_name=excluded.module_name,module_path=excluded.module_path,module_hash=excluded.module_hash
)SQL", "workspace_database.identity");
    if (!result) return result;
    result = statement.bind_blob(1, identity.binary_id().bytes.data(), identity.binary_id().bytes.size()); if (!result) return result;
    result = statement.bind_text(2, identity.bin_name()); if (!result) return result;
    result = statement.bind_text(3, identity.normalized_source_path()); if (!result) return result;
    if (identity.normalized_member_path()) result = statement.bind_text(4, *identity.normalized_member_path()); else result = statement.bind_null(4); if (!result) return result;
    result = statement.bind_blob(5, identity.content_hash().bytes.data(), identity.content_hash().bytes.size()); if (!result) return result;
    result = statement.bind_blob(6, identity.load_profile_hash().bytes.data(), identity.load_profile_hash().bytes.size()); if (!result) return result;
    result = statement.bind_int(7, static_cast<std::int64_t>(identity.target_kind())); if (!result) return result;
    result = statement.bind_int(8, static_cast<std::int64_t>(identity.format())); if (!result) return result;
    result = statement.bind_int(9, static_cast<std::int64_t>(identity.architecture())); if (!result) return result;
    result = statement.bind_int(10, static_cast<std::int64_t>(identity.architecture_mode())); if (!result) return result;
    result = statement.bind_int(11, static_cast<std::int64_t>(identity.abi())); if (!result) return result;
    result = statement.bind_int(12, static_cast<std::int64_t>(identity.endian())); if (!result) return result;
    result = statement.bind_uint(13, identity.image_base()); if (!result) return result;
    if (identity.process()) {
        result = statement.bind_int(14, identity.process()->pid); if (!result) return result;
        result = statement.bind_uint(15, identity.process()->creation_time_100ns); if (!result) return result;
        result = statement.bind_text(16, identity.process()->normalized_process_path); if (!result) return result;
    } else {
        result = statement.bind_null(14); if (!result) return result;
        result = statement.bind_null(15); if (!result) return result;
        result = statement.bind_null(16); if (!result) return result;
    }
    if (identity.module()) {
        result = statement.bind_uint(17, identity.module()->base); if (!result) return result;
        result = statement.bind_uint(18, identity.module()->size); if (!result) return result;
        result = statement.bind_text(19, identity.module()->normalized_name); if (!result) return result;
        result = statement.bind_text(20, identity.module()->normalized_path); if (!result) return result;
        if (identity.module()->content_hash)
            result = statement.bind_blob(21, identity.module()->content_hash->bytes.data(), identity.module()->content_hash->bytes.size());
        else result = statement.bind_null(21);
        if (!result) return result;
    } else {
        for (int index = 17; index <= 21; ++index) {
            result = statement.bind_null(index);
            if (!result) return result;
        }
    }
    return statement.step_done();
}

workspace_result_t<void> initialize_identity_and_versions(
    sqlite3* database, const workspace_database_options_t& options,
    std::uint64_t& cache_invalidations,
    bool schema_requires_invalidation) {
    auto begin = begin_immediate(database, "workspace_database.open");
    if (!begin) return begin;

    auto stored_id = metadata_value(database, "binary_id");
    if (!stored_id) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(stored_id.error());
    }
    const std::string current_id = options.identity->binary_id().to_hex();
    if (stored_id.value() && *stored_id.value() != current_id) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "database identity does not match workspace identity",
                                 "workspace_database.open"));
    }

    {
    statement_t identity_query;
    auto identity_prepared = identity_query.prepare(database,
        "SELECT binary_id,content_hash,load_profile_hash FROM workspace_identity WHERE singleton=1",
        "workspace_database.open");
    if (!identity_prepared) {
        rollback(database, "workspace_database.open");
        return identity_prepared;
    }
    const int identity_status = sqlite3_step(identity_query.get());
    if (identity_status == SQLITE_ROW) {
        const void* stored_binary = sqlite3_column_blob(identity_query.get(), 0);
        const int stored_binary_size = sqlite3_column_bytes(identity_query.get(), 0);
        const void* stored_content = sqlite3_column_blob(identity_query.get(), 1);
        const int stored_content_size = sqlite3_column_bytes(identity_query.get(), 1);
        const void* stored_profile = sqlite3_column_blob(identity_query.get(), 2);
        const int stored_profile_size = sqlite3_column_bytes(identity_query.get(), 2);
        if (!stored_binary || stored_binary_size != static_cast<int>(options.identity->binary_id().bytes.size()) ||
            !stored_content || stored_content_size != static_cast<int>(options.identity->content_hash().bytes.size()) ||
            !stored_profile || stored_profile_size != static_cast<int>(options.identity->load_profile_hash().bytes.size()) ||
            std::memcmp(stored_binary, options.identity->binary_id().bytes.data(), options.identity->binary_id().bytes.size()) != 0 ||
            std::memcmp(stored_content, options.identity->content_hash().bytes.data(), options.identity->content_hash().bytes.size()) != 0 ||
            std::memcmp(stored_profile, options.identity->load_profile_hash().bytes.data(), options.identity->load_profile_hash().bytes.size()) != 0) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted workspace identity row does not match the requested identity",
                "workspace_database.open"));
        }
    } else if (identity_status != SQLITE_DONE) {
        auto error = database_error(database, identity_status,
                                    "unable to read persisted workspace identity",
                                    "workspace_database.open");
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(std::move(error));
    }
    }

    bool invalidate = schema_requires_invalidation;
    auto stored_schema = metadata_value(database, "schema_version");
    if (!stored_schema) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(stored_schema.error());
    }
    if (stored_schema.value() &&
        *stored_schema.value() != std::to_string(workspace_database_schema_version) &&
        schema_requires_invalidation)
        invalidate = true;
    const std::array<std::pair<const char*, std::string>, 3> versions{{
        {"engine_version", options.versions.engine_version},
        {"specification_version", options.versions.specification_version},
        {"analysis_settings_hash", options.versions.analysis_settings_hash}
    }};
    for (const auto& version : versions) {
        auto stored = metadata_value(database, version.first);
        if (!stored) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(stored.error());
        }
        if (stored.value() && *stored.value() != version.second)
            invalidate = true;
    }
    for (const auto& identity_value : std::array<std::pair<const char*, std::string>, 2>{{
             {"content_hash", options.identity->content_hash().to_hex()},
             {"load_profile_hash", options.identity->load_profile_hash().to_hex()}}}) {
        auto stored = metadata_value(database, identity_value.first);
        if (!stored) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(stored.error());
        }
        if (stored.value() && *stored.value() != identity_value.second) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted content identity metadata is inconsistent",
                "workspace_database.open"));
        }
    }

    auto invalidation_value = metadata_value(database, "cache_invalidations");
    if (!invalidation_value) {
        rollback(database, "workspace_database.open");
        return workspace_result_t<void>::failure(invalidation_value.error());
    }
    if (invalidation_value.value()) {
        const auto& text = *invalidation_value.value();
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                            cache_invalidations, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
            rollback(database, "workspace_database.open");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "cache invalidation metadata is malformed",
                "workspace_database.open"));
        }
    }

    if (invalidate) {
        auto cleared = exec_sql(database, R"SQL(
DELETE FROM call_graph_conflicts;DELETE FROM call_graph_edges;DELETE FROM call_candidates;DELETE FROM call_sites;DELETE FROM call_graph_nodes;DELETE FROM call_graph_state;DELETE FROM data_pointer_facts;DELETE FROM data_conflicts;DELETE FROM rich_data_candidates;DELETE FROM type_references;DELETE FROM metadata_conflicts;DELETE FROM symbol_type_candidates;DELETE FROM switch_cases;DELETE FROM switches;DELETE FROM segments;DELETE FROM instruction_chunks;DELETE FROM operand_facts;DELETE FROM operand_fact_chunks;DELETE FROM target_facts;DELETE FROM target_fact_chunks;DELETE FROM function_block_memberships;DELETE FROM function_chunks;DELETE FROM functions;DELETE FROM blocks;DELETE FROM edges;DELETE FROM edge_chunks;DELETE FROM xrefs;DELETE FROM xref_chunks;DELETE FROM strings;DELETE FROM symbols;DELETE FROM coverage;DELETE FROM data_candidates;DELETE FROM type_candidates;DELETE FROM search_index_blob;DELETE FROM analysis_state;
DELETE FROM alternate_call_graph_conflicts;DELETE FROM alternate_call_graph_edges;DELETE FROM alternate_call_candidates;DELETE FROM alternate_call_sites;DELETE FROM alternate_call_graph_nodes;DELETE FROM alternate_call_graph_state;DELETE FROM alternate_data_pointer_facts;DELETE FROM alternate_data_conflicts;DELETE FROM alternate_rich_data_candidates;DELETE FROM alternate_type_references;DELETE FROM alternate_metadata_conflicts;DELETE FROM alternate_symbol_type_candidates;DELETE FROM alternate_switch_cases;DELETE FROM alternate_switches;DELETE FROM alternate_segments;DELETE FROM alternate_instruction_chunks;DELETE FROM alternate_operand_facts;DELETE FROM alternate_operand_fact_chunks;DELETE FROM alternate_target_facts;DELETE FROM alternate_target_fact_chunks;DELETE FROM alternate_function_block_memberships;DELETE FROM alternate_function_chunks;DELETE FROM alternate_functions;DELETE FROM alternate_blocks;DELETE FROM alternate_edges;DELETE FROM alternate_edge_chunks;DELETE FROM alternate_xrefs;DELETE FROM alternate_xref_chunks;DELETE FROM alternate_strings;DELETE FROM alternate_symbols;DELETE FROM alternate_coverage;DELETE FROM alternate_data_candidates;DELETE FROM alternate_type_candidates;DELETE FROM alternate_search_index_blob;DELETE FROM alternate_analysis_state;
UPDATE workspace_commit_state SET active_slot=0,committed_token='',committed_generation=0,committed_analysis_revision=0,committed_overlay_revision=0,candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=0 WHERE singleton=1;
DELETE FROM packed_page_index;DELETE FROM packed_pages;DELETE FROM packed_generations;
DELETE FROM decompiler_cache;DELETE FROM decompiler_cache_v9;
)SQL", "workspace_database.invalidate");
        if (!cleared) {
            rollback(database, "workspace_database.open");
            return cleared;
        }
        ++cache_invalidations;
    }

    auto identity_result = bind_identity(database, *options.identity);
    if (!identity_result) {
        rollback(database, "workspace_database.open");
        return identity_result;
    }
    auto set_result = set_metadata(database, "binary_id", current_id);
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    for (const auto& version : versions) {
        set_result = set_metadata(database, version.first, version.second);
        if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    }
    set_result = set_metadata(database, "content_hash",
                              options.identity->content_hash().to_hex());
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    set_result = set_metadata(database, "load_profile_hash",
                              options.identity->load_profile_hash().to_hex());
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    set_result = set_metadata(database, "schema_version",
                              std::to_string(workspace_database_schema_version));
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    set_result = set_metadata(database, "cache_invalidations",
                              std::to_string(cache_invalidations));
    if (!set_result) { rollback(database, "workspace_database.open"); return set_result; }
    auto committed = commit(database, "workspace_database.open");
    if (!committed) {
        rollback(database, "workspace_database.open");
        return committed;
    }
    return workspace_result_t<void>::success();
}

std::uint64_t utc_ms() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

bool image_matches_identity(const pe_image_t& image,
                            const workspace_identity_t& identity) noexcept {
    return image.format() == identity.format() &&
           image.architecture() == identity.architecture() &&
           image.architecture_mode() == identity.architecture_mode() &&
           image.abi() == identity.abi() &&
           image.endian() == identity.endian() &&
           image.image_base() == identity.image_base();
}

bool image_matches_identity(const workspace_image_t& image,
                            const workspace_identity_t& identity) {
    const auto validation = validate_workspace_image(image, {}, true);
    if (!validation || image.format != identity.format() ||
        image.architecture != identity.architecture() ||
        image.architecture_mode != identity.architecture_mode() ||
        image.abi != identity.abi() || image.endian != identity.endian() ||
        image.image_base != identity.image_base() ||
        image.workspace_binary_id != identity.binary_id() ||
        image.provider_content_hash != identity.content_hash())
        return false;
    if (identity.target_kind() != target_kind_t::static_file)
        return true;
    const auto member_separator = image.provider_source.find("#member:");
    const std::string provider_source = member_separator == std::string::npos
        ? image.provider_source : image.provider_source.substr(0, member_separator);
    return normalize_target_name(provider_source) ==
               normalize_target_name(identity.normalized_source_path()) &&
           (identity.normalized_member_path().has_value() == image.member.has_value()) &&
           (!image.member || image.member->normalized_member_path ==
                                 *identity.normalized_member_path());
}

bool image_matches_persistence_identity(
    const workspace_image_t& image,
    const workspace_identity_t& identity,
    std::uint64_t generation,
    std::uint64_t overlay_revision) {
    if (image_matches_identity(image, identity))
        return true;
    const auto validation = validate_workspace_image(image, {}, true);
    if (!validation || identity.target_kind() != target_kind_t::static_file ||
        generation <= 1 || overlay_revision == 0 ||
        image.format != identity.format() ||
        image.architecture != identity.architecture() ||
        image.architecture_mode != identity.architecture_mode() ||
        image.abi != identity.abi() || image.endian != identity.endian() ||
        image.image_base != identity.image_base() ||
        image.workspace_binary_id != identity.binary_id() ||
        image.provider_content_hash.empty() || image.provider_size == 0 ||
        (identity.normalized_member_path().has_value() != image.member.has_value()) ||
        (image.member && image.member->normalized_member_path !=
                             *identity.normalized_member_path()))
        return false;
    const std::string expected_source =
        "overlay://" + identity.binary_id().to_hex() +
        "/generation/" + std::to_string(generation) +
        "/revision/" + std::to_string(overlay_revision);
    return image.provider_source == expected_source;
}

struct commit_state_record_t {
    std::uint8_t active_slot = 0;
    std::string committed_token;
    std::uint64_t committed_generation = 0;
    std::uint64_t committed_analysis_revision = 0;
    std::uint64_t committed_overlay_revision = 0;
    std::optional<std::uint8_t> candidate_slot;
    std::optional<std::string> candidate_token;
    std::optional<std::uint64_t> candidate_generation;
    std::optional<std::uint64_t> candidate_analysis_revision;
    std::optional<std::uint64_t> candidate_overlay_revision;
    bool candidate_ready = false;
};

bool valid_candidate_token(const std::string& token) noexcept {
    if (token.size() != 32)
        return false;
    return std::all_of(token.begin(), token.end(), [](unsigned char value) {
        return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f');
    });
}

workspace_result_t<std::string> generate_candidate_token() {
    std::array<std::uint8_t, 16> bytes{};
    const NTSTATUS status = BCryptGenRandom(nullptr, bytes.data(),
        static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        auto error = make_workspace_error(workspace_error_code_t::persistence_failure,
            "unable to generate a persistence candidate token",
            "workspace_database.candidate");
        error.provider_status = static_cast<std::int64_t>(status);
        return workspace_result_t<std::string>::failure(std::move(error));
    }
    static constexpr char digits[] = "0123456789abcdef";
    std::string token;
    token.resize(bytes.size() * 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        token[index * 2] = digits[bytes[index] >> 4];
        token[index * 2 + 1] = digits[bytes[index] & 0x0fU];
    }
    return workspace_result_t<std::string>::success(std::move(token));
}

std::string slot_table(std::uint8_t slot, const char* table) {
    return slot == 0 ? std::string(table) : std::string("alternate_") + table;
}

workspace_result_t<commit_state_record_t> read_commit_state(
    sqlite3* database, const char* phase) {
    statement_t statement;
    auto prepared = statement.prepare(database,
        "SELECT active_slot,committed_token,committed_generation,committed_analysis_revision,committed_overlay_revision,candidate_slot,candidate_token,candidate_generation,candidate_analysis_revision,candidate_overlay_revision,candidate_ready FROM workspace_commit_state WHERE singleton=1",
        phase);
    if (!prepared)
        return workspace_result_t<commit_state_record_t>::failure(prepared.error());
    const int status = sqlite3_step(statement.get());
    if (status != SQLITE_ROW) {
        return workspace_result_t<commit_state_record_t>::failure(database_error(
            database, status, "workspace commit-state row is missing", phase));
    }
    const auto active_slot = sqlite3_column_int64(statement.get(), 0);
    const auto committed_generation = sqlite3_column_int64(statement.get(), 2);
    const auto committed_analysis_revision = sqlite3_column_int64(statement.get(), 3);
    const auto committed_overlay_revision = sqlite3_column_int64(statement.get(), 4);
    const auto ready = sqlite3_column_int64(statement.get(), 10);
    if ((active_slot != 0 && active_slot != 1) || committed_generation < 0 ||
        committed_analysis_revision < 0 || committed_overlay_revision < 0 ||
        (ready != 0 && ready != 1)) {
        return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace commit-state values are malformed", phase));
    }
    commit_state_record_t result;
    result.active_slot = static_cast<std::uint8_t>(active_slot);
    result.committed_token = column_text(statement.get(), 1);
    result.committed_generation = static_cast<std::uint64_t>(committed_generation);
    result.committed_analysis_revision = static_cast<std::uint64_t>(committed_analysis_revision);
    result.committed_overlay_revision = static_cast<std::uint64_t>(committed_overlay_revision);
    result.candidate_ready = ready != 0;
    if ((result.committed_token.empty() &&
         (result.committed_generation != 0 ||
          result.committed_analysis_revision != 0 ||
          result.committed_overlay_revision != 0)) ||
        (!result.committed_token.empty() &&
         (!valid_candidate_token(result.committed_token) ||
          result.committed_generation == 0))) {
        return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace promoted commit identity is malformed", phase));
    }
    const bool candidate_columns_present =
        sqlite3_column_type(statement.get(), 5) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 6) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 7) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 8) != SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 9) != SQLITE_NULL;
    const bool candidate_columns_absent =
        sqlite3_column_type(statement.get(), 5) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 6) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 7) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 8) == SQLITE_NULL &&
        sqlite3_column_type(statement.get(), 9) == SQLITE_NULL;
    if ((result.candidate_ready && !candidate_columns_present) ||
        (!result.candidate_ready && !candidate_columns_absent)) {
        return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "workspace candidate-state columns are inconsistent", phase));
    }
    if (result.candidate_ready) {
        const auto candidate_slot = sqlite3_column_int64(statement.get(), 5);
        const auto candidate_generation = sqlite3_column_int64(statement.get(), 7);
        const auto candidate_analysis_revision = sqlite3_column_int64(statement.get(), 8);
        const auto candidate_overlay_revision = sqlite3_column_int64(statement.get(), 9);
        const std::string candidate_token = column_text(statement.get(), 6);
        if ((candidate_slot != 0 && candidate_slot != 1) ||
            candidate_slot == active_slot || candidate_generation <= 0 ||
            candidate_analysis_revision < 0 || candidate_overlay_revision < 0 ||
            !valid_candidate_token(candidate_token)) {
            return workspace_result_t<commit_state_record_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "workspace persistence candidate is malformed", phase));
        }
        result.candidate_slot = static_cast<std::uint8_t>(candidate_slot);
        result.candidate_token = candidate_token;
        result.candidate_generation = static_cast<std::uint64_t>(candidate_generation);
        result.candidate_analysis_revision =
            static_cast<std::uint64_t>(candidate_analysis_revision);
        result.candidate_overlay_revision =
            static_cast<std::uint64_t>(candidate_overlay_revision);
    }
    return workspace_result_t<commit_state_record_t>::success(std::move(result));
}

workspace_result_t<void> clear_snapshot_slot(sqlite3* database, std::uint8_t slot,
                                             const char* phase) {
    static constexpr std::array<const char*, 31> tables{{
        "call_graph_conflicts", "call_graph_edges", "call_candidates",
        "call_sites", "call_graph_nodes", "call_graph_state",
        "data_pointer_facts", "data_conflicts", "rich_data_candidates",
        "type_references", "metadata_conflicts", "symbol_type_candidates",
        "switch_cases", "switches", "segments", "instruction_chunks",
        "operand_facts", "target_facts", "function_block_memberships",
        "function_chunks", "functions", "blocks", "edges", "xrefs", "strings",
        "symbols", "coverage", "data_candidates", "type_candidates",
        "search_index_blob", "analysis_state"
    }};
    std::string sql;
    for (const char* table : tables)
        sql += "DELETE FROM " + slot_table(slot, table) + ';';
    return exec_sql(database, sql.c_str(), phase);
}

workspace_result_t<std::uint64_t> database_page_size(sqlite3* database) {
    statement_t statement;
    auto prepared = statement.prepare(database, "PRAGMA page_size",
                                      "workspace_database.metrics");
    if (!prepared)
        return workspace_result_t<std::uint64_t>::failure(prepared.error());
    const int status = sqlite3_step(statement.get());
    if (status != SQLITE_ROW) {
        return workspace_result_t<std::uint64_t>::failure(database_error(
            database, status, "unable to query SQLite page size",
            "workspace_database.metrics"));
    }
    const std::int64_t value = sqlite3_column_int64(statement.get(), 0);
    if (value <= 0) {
        return workspace_result_t<std::uint64_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "SQLite reported an invalid database page size",
            "workspace_database.metrics"));
    }
    return workspace_result_t<std::uint64_t>::success(
        static_cast<std::uint64_t>(value));
}

void saturating_atomic_add(std::atomic<std::uint64_t>& destination,
                           std::uint64_t increment) noexcept {
    std::uint64_t current = destination.load(std::memory_order_relaxed);
    for (;;) {
        const std::uint64_t next = increment > (std::numeric_limits<std::uint64_t>::max)() - current
            ? (std::numeric_limits<std::uint64_t>::max)()
            : current + increment;
        if (destination.compare_exchange_weak(current, next,
                                              std::memory_order_release,
                                              std::memory_order_relaxed))
            return;
    }
}

template <typename Binder>
workspace_result_t<void> insert_many(sqlite3* database, const std::string& sql,
                                     std::size_t count, Binder binder,
                                     const cancellation_token_t& cancel,
                                     const char* phase) {
    statement_t statement;
    auto result = statement.prepare(database, sql.c_str(), phase);
    if (!result) return result;
    for (std::size_t index = 0; index < count; ++index) {
        if ((index & 255U) == 0 && cancel.stop_requested()) {
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "persistence batch cancelled", phase);
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        result = binder(statement, index);
        if (!result) return result;
        result = statement.step_done();
        if (!result) return result;
        result = statement.reset();
        if (!result) return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> persist_extended_snapshot_rows(
    sqlite3* database, std::uint8_t target_slot,
    const analysis_snapshot_t& snapshot,
    const cancellation_token_t& cancel) {
    statement_t call_graph_state;
    auto result = call_graph_state.prepare(database,
        ("INSERT INTO " + slot_table(target_slot, "call_graph_state") +
         "(singleton,indirect_site_count,unresolved_site_count,bounded) VALUES(1,?1,?2,?3)").c_str(),
        "workspace_database.persist.call_graph_state");
    if (!result) return result;
    result = call_graph_state.bind_uint(1, snapshot.call_graph.indirect_site_count); if (!result) return result;
    result = call_graph_state.bind_uint(2, snapshot.call_graph.unresolved_site_count); if (!result) return result;
    result = call_graph_state.bind_int(3, snapshot.call_graph.bounded ? 1 : 0); if (!result) return result;
    result = call_graph_state.step_done();
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_graph_nodes") +
        "(function_id,address_space,address_value,address_arch,address_mode,incoming_edges,outgoing_edges,indirect_edges,unresolved_sites) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        snapshot.call_graph.nodes.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.nodes[index];
            auto current = statement.bind_uint(1, record.function_id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_uint(6, record.incoming_edges); if (!current) return current;
            current = statement.bind_uint(7, record.outgoing_edges); if (!current) return current;
            current = statement.bind_uint(8, record.indirect_edges); if (!current) return current;
            return statement.bind_uint(9, record.unresolved_sites);
        }, cancel, "workspace_database.persist.call_graph_nodes");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_sites") +
        "(entity_id,source_function_id,source_block_id,instruction_id,address_space,address_value,address_arch,address_mode,first_candidate,candidate_count,indirect,tail_call,unresolved) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        snapshot.call_graph.call_sites.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.call_sites[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.source_function_id); if (!current) return current;
            current = statement.bind_uint(3, record.source_block_id); if (!current) return current;
            current = statement.bind_uint(4, record.instruction_id); if (!current) return current;
            current = bind_address(statement, 5, record.address); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(record.first_candidate)); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.candidate_count)); if (!current) return current;
            current = statement.bind_int(11, record.indirect ? 1 : 0); if (!current) return current;
            current = statement.bind_int(12, record.tail_call ? 1 : 0); if (!current) return current;
            return statement.bind_int(13, record.unresolved ? 1 : 0);
        }, cancel, "workspace_database.persist.call_sites");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_candidates") +
        "(entity_id,call_site_id,target_space,target_value,target_arch,target_mode,target_function_id,kind,provenance,confidence,contributor_count,conflicted,stable_source_id,rank,external_target) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        snapshot.call_graph.candidates.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.candidates[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.call_site_id); if (!current) return current;
            current = bind_address(statement, 3, record.target); if (!current) return current;
            current = record.target_function_id
                ? statement.bind_uint(7, *record.target_function_id)
                : statement.bind_null(7);
            if (!current) return current;
            current = statement.bind_int(8, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(record.quality.provenance)); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.quality.confidence)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.quality.contributor_count)); if (!current) return current;
            current = statement.bind_int(12, record.quality.conflicted ? 1 : 0); if (!current) return current;
            current = statement.bind_uint(13, record.stable_source_id); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.rank)); if (!current) return current;
            return statement.bind_int(15, record.external_target ? 1 : 0);
        }, cancel, "workspace_database.persist.call_candidates");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_graph_edges") +
        "(entity_id,call_site_id,source_function_id,source_block_id,target_function_id,call_site_space,call_site_value,call_site_arch,call_site_mode,target_space,target_value,target_arch,target_mode,resolution,provenance,confidence,contributor_count,conflicted,candidate_rank,external_target,target_noreturn) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
        snapshot.call_graph.edges.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.edges[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.call_site_id); if (!current) return current;
            current = statement.bind_uint(3, record.source_function_id); if (!current) return current;
            current = statement.bind_uint(4, record.source_block_id); if (!current) return current;
            current = record.target_function_id
                ? statement.bind_uint(5, *record.target_function_id)
                : statement.bind_null(5);
            if (!current) return current;
            current = bind_address(statement, 6, record.call_site); if (!current) return current;
            current = bind_address(statement, 10, record.target); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.resolution)); if (!current) return current;
            current = statement.bind_int(15, static_cast<std::int64_t>(record.quality.provenance)); if (!current) return current;
            current = statement.bind_int(16, static_cast<std::int64_t>(record.quality.confidence)); if (!current) return current;
            current = statement.bind_int(17, static_cast<std::int64_t>(record.quality.contributor_count)); if (!current) return current;
            current = statement.bind_int(18, record.quality.conflicted ? 1 : 0); if (!current) return current;
            current = statement.bind_int(19, static_cast<std::int64_t>(record.candidate_rank)); if (!current) return current;
            current = statement.bind_int(20, record.external_target ? 1 : 0); if (!current) return current;
            return statement.bind_int(21, record.target_noreturn ? 1 : 0);
        }, cancel, "workspace_database.persist.call_graph_edges");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "call_graph_conflicts") +
        "(entity_id,kind,instruction_id,source_function_id,call_site_rva,selected_target_rva,competing_target_rva,selected_target_function_id,competing_target_function_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        snapshot.call_graph.conflicts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.call_graph.conflicts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_int(2, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_uint(3, record.instruction_id); if (!current) return current;
            current = statement.bind_uint(4, record.source_function_id); if (!current) return current;
            current = statement.bind_uint(5, record.call_site_rva); if (!current) return current;
            current = statement.bind_uint(6, record.selected_target_rva); if (!current) return current;
            current = statement.bind_uint(7, record.competing_target_rva); if (!current) return current;
            current = statement.bind_uint(8, record.selected_target_function_id); if (!current) return current;
            return statement.bind_uint(9, record.competing_target_function_id);
        }, cancel, "workspace_database.persist.call_graph_conflicts");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "rich_data_candidates") +
        "(entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        snapshot.rich_facts.data_candidates.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.data_candidates[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_uint(6, record.size); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = bind_optional_address(statement, 8, record.target); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_int(13, static_cast<std::int64_t>(record.confidence));
        }, cancel, "workspace_database.persist.rich_data_candidates");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "data_pointer_facts") +
        "(entity_id,slot_space,slot_value,slot_arch,slot_mode,target_space,target_value,target_arch,target_mode,candidate_kind,encoding,width_bytes,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        snapshot.rich_facts.data_pointer_facts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.data_pointer_facts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.slot); if (!current) return current;
            current = bind_address(statement, 6, record.target); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.candidate_kind)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.encoding)); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.width_bytes)); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_int(14, static_cast<std::int64_t>(record.confidence));
        }, cancel, "workspace_database.persist.data_pointer_facts");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "data_conflicts") +
        "(entity_id,address_space,address_value,address_arch,address_mode,kind,selected_target_space,selected_target_value,selected_target_arch,selected_target_mode,rejected_target_space,rejected_target_value,rejected_target_arch,rejected_target_mode,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        snapshot.rich_facts.data_conflicts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.data_conflicts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_int(6, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = bind_optional_address(statement, 7, record.selected_target); if (!current) return current;
            current = bind_optional_address(statement, 11, record.rejected_target); if (!current) return current;
            current = statement.bind_int(15, static_cast<std::int64_t>(record.selected_provenance)); if (!current) return current;
            current = statement.bind_int(16, static_cast<std::int64_t>(record.rejected_provenance)); if (!current) return current;
            current = statement.bind_int(17, static_cast<std::int64_t>(record.selected_confidence)); if (!current) return current;
            return statement.bind_int(18, static_cast<std::int64_t>(record.rejected_confidence));
        }, cancel, "workspace_database.persist.data_conflicts");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "symbol_type_candidates") +
        "(entity_id,address_space,address_value,address_arch,address_mode,related_space,related_value,related_arch,related_mode,kind,display_name,canonical_type,source_key,provenance,confidence,explicitly_unknown) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        snapshot.rich_facts.type_candidates.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.type_candidates[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_optional_address(statement, 2, record.address); if (!current) return current;
            current = bind_optional_address(statement, 6, record.related_address); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_text(11, record.display_name); if (!current) return current;
            current = statement.bind_text(12, record.canonical_type); if (!current) return current;
            current = statement.bind_text(13, record.source_key); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_int(15, static_cast<std::int64_t>(record.confidence)); if (!current) return current;
            return statement.bind_int(16, record.explicitly_unknown ? 1 : 0);
        }, cancel, "workspace_database.persist.symbol_type_candidates");
    if (!result) return result;

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "type_references") +
        "(entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,source_entity,target_entity,kind,provenance,confidence,source_key) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        snapshot.rich_facts.type_references.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.type_references[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_optional_address(statement, 2, record.source); if (!current) return current;
            current = bind_optional_address(statement, 6, record.target); if (!current) return current;
            current = statement.bind_uint(10, record.source_entity); if (!current) return current;
            current = statement.bind_uint(11, record.target_entity); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.confidence)); if (!current) return current;
            return statement.bind_text(15, record.source_key);
        }, cancel, "workspace_database.persist.type_references");
    if (!result) return result;

    return insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "metadata_conflicts") +
        "(entity_id,address_space,address_value,address_arch,address_mode,identity,kind,selected_value,rejected_value,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        snapshot.rich_facts.metadata_conflicts.size(),
        [&](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.rich_facts.metadata_conflicts[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_optional_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_text(6, record.identity); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_text(8, record.selected_value); if (!current) return current;
            current = statement.bind_text(9, record.rejected_value); if (!current) return current;
            current = statement.bind_int(10, static_cast<std::int64_t>(record.selected_provenance)); if (!current) return current;
            current = statement.bind_int(11, static_cast<std::int64_t>(record.rejected_provenance)); if (!current) return current;
            current = statement.bind_int(12, static_cast<std::int64_t>(record.selected_confidence)); if (!current) return current;
            return statement.bind_int(13, static_cast<std::int64_t>(record.rejected_confidence));
        }, cancel, "workspace_database.persist.metadata_conflicts");
}

workspace_result_t<void> stage_managed_publication_domain(
    sqlite3* database,
    const analysis_snapshot_t& snapshot,
    const managed_artifact_publication_t& managed_publication,
    const workspace_database_options_t& options,
    const std::string& candidate_token,
    std::uint64_t prior_records,
    const cancellation_token_t& cancel,
    persistence_commit_metrics_t* commit_metrics);

using fact_chunk_record_encode_t = std::function<std::vector<std::uint8_t>(std::size_t)>;
using fact_chunk_record_key_t = std::function<std::uint64_t(std::size_t)>;

workspace_result_t<void> persist_fact_chunks(
    sqlite3* database, std::uint8_t target_slot, const char* table,
    std::uint64_t record_total, std::size_t chunk_records,
    std::uint64_t record_stride, const fact_chunk_record_encode_t& encode,
    const fact_chunk_record_key_t& key, const char* phase,
    const cancellation_token_t& cancel) {
    if (record_total == 0)
        return workspace_result_t<void>::success();
    statement_t chunk_statement;
    const std::string chunk_insert = "INSERT INTO " +
        slot_table(target_slot, table) +
        "(chunk_id,start_value,end_value,record_count,blob_version,payload) VALUES(?1,?2,?3,?4,?5,?6)";
    auto prepared = chunk_statement.prepare(database, chunk_insert.c_str(), phase);
    if (!prepared)
        return prepared;
    std::uint64_t chunk_id = 1;
    for (std::size_t begin_index = 0; begin_index < record_total;
         begin_index += chunk_records) {
        if (cancel.stop_requested()) {
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "fact chunk persistence cancelled", phase);
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const std::size_t end_index = static_cast<std::size_t>((std::min)(
            record_total, static_cast<std::uint64_t>(begin_index + chunk_records)));
        std::vector<std::uint8_t> payload;
        const std::size_t count = end_index - begin_index;
        payload.reserve(24 + count * record_stride);
        append_fact_chunk_header(payload, count, record_stride);
        for (std::size_t index = begin_index; index < end_index; ++index) {
            auto record_bytes = encode(index);
            if (record_bytes.size() != record_stride) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "fact chunk record encoder returned an irregular record", phase));
            }
            payload.insert(payload.end(), record_bytes.begin(), record_bytes.end());
        }
        auto result = chunk_statement.bind_uint(1, chunk_id++);
        if (!result) return result;
        result = chunk_statement.bind_uint(2, key(begin_index));
        if (!result) return result;
        result = chunk_statement.bind_uint(3, key(end_index - 1));
        if (!result) return result;
        result = chunk_statement.bind_uint(4, count);
        if (!result) return result;
        result = chunk_statement.bind_uint(5, kFactChunkBlobVersion);
        if (!result) return result;
        result = chunk_statement.bind_blob(6, payload.data(), payload.size());
        if (!result) return result;
        result = chunk_statement.step_done();
        if (!result) return result;
        result = chunk_statement.reset();
        if (!result) return result;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> persist_snapshot_impl(
    sqlite3* database, const analysis_snapshot_t& snapshot,
    const persisted_search_products_t* search_products,
    const std::shared_ptr<const managed_artifact_publication_t>& managed_publication,
    const workspace_database_options_t& options,
    const std::string& settings_json, const std::string& metrics_json,
    const std::string& candidate_token,
    const cancellation_token_t& cancel,
    persistence_commit_metrics_t* commit_metrics) {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(cancel.deadline_exceeded()
                                              ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                                          "snapshot persistence cancelled",
                                          "workspace_database.persist");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!valid_candidate_token(candidate_token)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot persistence candidate token is malformed",
            "workspace_database.persist"));
    }
    if (search_products &&
        (search_products->generation != snapshot.generation ||
         search_products->analysis_revision != snapshot.analysis_revision ||
         search_products->overlay_revision != snapshot.overlay_revision)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "search products do not match snapshot generation and revisions",
                                 "workspace_database.persist"));
    }
    if (managed_publication &&
        (managed_publication->generation != snapshot.generation ||
         managed_publication->analysis_revision != snapshot.analysis_revision ||
         managed_publication->overlay_revision != snapshot.overlay_revision ||
         managed_publication->binary_id != snapshot.binary_id ||
         managed_publication->load_profile_hash != snapshot.load_profile_hash ||
         !snapshot.normalized_image ||
         managed_publication->provider_hash !=
             snapshot.normalized_image->provider_content_hash ||
         managed_publication->provider_source !=
             snapshot.normalized_image->provider_source ||
         managed_publication->provider_size !=
             snapshot.normalized_image->provider_size)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "managed publication does not match snapshot generation and identity",
                                 "workspace_database.persist"));
    }
    const std::vector<data_candidate_record_t>* persisted_data_candidates = nullptr;
    const std::vector<switch_record_t>* persisted_switches = nullptr;
    const std::vector<type_candidate_record_t>* persisted_types = nullptr;
    if (search_products) {
        if (search_products->live_index) {
            persisted_data_candidates =
                &search_products->live_index->data_candidates();
            persisted_switches = &search_products->live_index->switches();
            persisted_types = &search_products->live_index->types();
        } else {
            persisted_data_candidates = &search_products->data_candidates;
            persisted_switches = &search_products->switches;
            persisted_types = &search_products->types;
        }
    }
    constexpr std::size_t json_limit = 16U << 20;
    if (settings_json.size() > json_limit || metrics_json.size() > json_limit ||
        nlohmann::json::parse(settings_json, nullptr, false).is_discarded() ||
        nlohmann::json::parse(metrics_json, nullptr, false).is_discarded()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "analysis settings or metrics JSON is invalid or exceeds its limit",
            "workspace_database.persist"));
    }
    std::uint64_t fact_records = 0;
    auto add_records = [&](std::uint64_t count) {
        if (count > options.max_persisted_fact_records - fact_records)
            return false;
        fact_records += count;
        return true;
    };
    if (!add_records(snapshot.instructions.size()) ||
        !add_records(snapshot.operand_facts.size()) ||
        !add_records(snapshot.target_facts.size()) ||
        !add_records(snapshot.function_chunks.size()) ||
        !add_records(snapshot.function_block_memberships.size()) ||
        !add_records(snapshot.functions.size()) ||
        !add_records(snapshot.blocks.size()) ||
        !add_records(snapshot.edges.size()) ||
        !add_records(snapshot.call_graph.nodes.size()) ||
        !add_records(snapshot.call_graph.call_sites.size()) ||
        !add_records(snapshot.call_graph.candidates.size()) ||
        !add_records(snapshot.call_graph.edges.size()) ||
        !add_records(snapshot.call_graph.conflicts.size()) ||
        !add_records(snapshot.xrefs.size()) ||
        !add_records(snapshot.strings.size()) ||
        !add_records(snapshot.symbols.size()) ||
        !add_records(snapshot.rich_facts.data_candidates.size()) ||
        !add_records(snapshot.rich_facts.data_pointer_facts.size()) ||
        !add_records(snapshot.rich_facts.data_conflicts.size()) ||
        !add_records(snapshot.rich_facts.type_candidates.size()) ||
        !add_records(snapshot.rich_facts.type_references.size()) ||
        !add_records(snapshot.rich_facts.metadata_conflicts.size()) ||
        !add_records(snapshot.coverage.size())) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "analysis snapshot exceeds the persisted fact-record budget",
            "workspace_database.persist"));
    }
    if (search_products) {
        if (search_products->search_index_blob.size() > workspace_search_blob_limit ||
            !add_records(persisted_data_candidates->size()) ||
            !add_records(persisted_switches->size()) ||
            !add_records(persisted_types->size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "search products exceed the persistence budget",
                "workspace_database.persist"));
        }
        for (const auto& item : *persisted_switches) {
            if (!add_records(item.case_targets.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "switch cases exceed the persisted fact-record budget",
                    "workspace_database.persist"));
            }
        }
    }

    std::uint64_t logical_bytes = 0;
    auto add_logical_bytes = [&](std::uint64_t value) {
        return checked_add_u64(logical_bytes, value, logical_bytes);
    };
    auto add_vector_storage = [&](std::uint64_t count, std::uint64_t element_size) {
        std::uint64_t bytes = 0;
        return checked_mul_u64(count, element_size, bytes) && add_logical_bytes(bytes);
    };
    if (!add_logical_bytes(settings_json.size()) ||
        !add_logical_bytes(metrics_json.size()) ||
!add_vector_storage(snapshot.instructions.size(), sizeof(instruction_record_t)) ||
!add_vector_storage(snapshot.operand_facts.hot.size(), sizeof(operand_fact_hot_t)) ||
!add_vector_storage(snapshot.operand_facts.cold.size(), sizeof(operand_fact_cold_t)) ||
!add_vector_storage(snapshot.target_facts.size(), sizeof(target_fact_t)) ||
        !add_vector_storage(snapshot.function_chunks.size(), sizeof(function_chunk_record_t)) ||
        !add_vector_storage(snapshot.function_block_memberships.size(),
                            sizeof(function_block_membership_record_t)) ||
        !add_vector_storage(snapshot.functions.size(), sizeof(function_record_t)) ||
        !add_vector_storage(snapshot.blocks.size(), sizeof(basic_block_record_t)) ||
        !add_vector_storage(snapshot.edges.size(), sizeof(edge_record_t)) ||
        !add_vector_storage(snapshot.call_graph.nodes.size(),
                            sizeof(call_graph_node_record_t)) ||
        !add_vector_storage(snapshot.call_graph.call_sites.size(),
                            sizeof(recovered_call_site_t)) ||
        !add_vector_storage(snapshot.call_graph.candidates.size(),
                            sizeof(recovered_call_candidate_t)) ||
        !add_vector_storage(snapshot.call_graph.edges.size(),
                            sizeof(call_graph_edge_record_t)) ||
        !add_vector_storage(snapshot.call_graph.conflicts.size(),
                            sizeof(call_graph_conflict_t)) ||
        !add_vector_storage(snapshot.xrefs.size(), sizeof(xref_record_t)) ||
        !add_vector_storage(snapshot.strings.size(), sizeof(string_record_t)) ||
        !add_vector_storage(snapshot.symbols.size(), sizeof(symbol_record_t)) ||
        !add_vector_storage(snapshot.rich_facts.data_candidates.size(),
                            sizeof(data_candidate_record_t)) ||
        !add_vector_storage(snapshot.rich_facts.data_pointer_facts.size(),
                            sizeof(data_pointer_fact_t)) ||
        !add_vector_storage(snapshot.rich_facts.data_conflicts.size(),
                            sizeof(data_candidate_conflict_t)) ||
        !add_vector_storage(snapshot.rich_facts.type_candidates.size(),
                            sizeof(symbol_type_candidate_record_t)) ||
        !add_vector_storage(snapshot.rich_facts.type_references.size(),
                            sizeof(type_reference_fact_t)) ||
        !add_vector_storage(snapshot.rich_facts.metadata_conflicts.size(),
                            sizeof(metadata_conflict_record_t)) ||
        !add_vector_storage(snapshot.coverage.size(), sizeof(coverage_span_t))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "snapshot logical payload size overflows",
            "workspace_database.persist"));
    }
    for (const auto& record : snapshot.strings) {
        if (!add_logical_bytes(record.value.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "string logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.symbols) {
        if (!add_logical_bytes(record.name.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "symbol logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.rich_facts.type_candidates) {
        if (!add_logical_bytes(record.display_name.size()) ||
            !add_logical_bytes(record.canonical_type.size()) ||
            !add_logical_bytes(record.source_key.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "rich type-candidate logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.rich_facts.type_references) {
        if (!add_logical_bytes(record.source_key.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "type-reference logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    for (const auto& record : snapshot.rich_facts.metadata_conflicts) {
        if (!add_logical_bytes(record.identity.size()) ||
            !add_logical_bytes(record.selected_value.size()) ||
            !add_logical_bytes(record.rejected_value.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "metadata-conflict logical payload size overflows",
                "workspace_database.persist"));
        }
    }
    std::uint64_t logical_rows = fact_records;
    const auto account_regions = [&](const auto& regions) -> workspace_result_t<void> {
        if (!add_vector_storage(regions.size(), sizeof(typename std::decay_t<decltype(regions)>::value_type)) ||
            !checked_add_u64(logical_rows, regions.size(), logical_rows)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "segment logical payload size overflows",
                "workspace_database.persist"));
        }
        for (const auto& region : regions) {
            if (!add_logical_bytes(region.name.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "segment name logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        return workspace_result_t<void>::success();
    };
    const auto account_pe_sections = [&](const std::vector<pe_section_t>& sections)
        -> workspace_result_t<void> {
        if (!add_vector_storage(sections.size(), sizeof(pe_section_t)) ||
            !checked_add_u64(logical_rows, sections.size(), logical_rows)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "segment logical payload size overflows",
                "workspace_database.persist"));
        }
        for (const auto& section : sections) {
            if (!add_logical_bytes(section.name.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "segment name logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        return workspace_result_t<void>::success();
    };
    if (snapshot.normalized_image) {
        auto accounted = snapshot.normalized_image->sections.empty()
            ? account_regions(snapshot.normalized_image->segments)
            : account_regions(snapshot.normalized_image->sections);
        if (!accounted)
            return accounted;
    } else if (snapshot.image) {
        auto accounted = account_pe_sections(snapshot.image->sections());
        if (!accounted)
            return accounted;
    }
    if (search_products) {
        if (!add_vector_storage(persisted_data_candidates->size(),
                                sizeof(data_candidate_record_t)) ||
            !add_vector_storage(persisted_switches->size(), sizeof(switch_record_t)) ||
            !add_vector_storage(persisted_types->size(), sizeof(type_candidate_record_t)) ||
            !add_logical_bytes(search_products->search_index_blob.size())) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "search-product logical payload size overflows",
                "workspace_database.persist"));
        }
        for (const auto& record : *persisted_switches) {
            if (!add_vector_storage(record.case_targets.size(), sizeof(address_t))) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "switch-case logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        for (const auto& record : *persisted_types) {
            if (!add_logical_bytes(record.display_name.size()) ||
                !add_logical_bytes(record.canonical_type.size())) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "type logical payload size overflows",
                    "workspace_database.persist"));
            }
        }
        if (!search_products->search_index_blob.empty() &&
            !checked_add_u64(logical_rows, 1, logical_rows)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "search-index logical row count overflows",
                "workspace_database.persist"));
        }
    }
    if (!checked_add_u64(logical_rows, 2, logical_rows)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "snapshot state logical row count overflows",
            "workspace_database.persist"));
    }

    auto page_size_result = database_page_size(database);
    if (!page_size_result)
        return workspace_result_t<void>::failure(page_size_result.error());
    int cache_writes_before = 0;
    int ignored_highwater = 0;
    const int before_status = sqlite3_db_status(
        database, SQLITE_DBSTATUS_CACHE_WRITE, &cache_writes_before,
        &ignored_highwater, 0);
    if (before_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, before_status,
            "unable to query SQLite cache-write counter",
            "workspace_database.metrics"));
    }
    const auto commit_started = std::chrono::steady_clock::now();

    auto begin = begin_immediate(database, "workspace_database.persist");
    if (!begin) return begin;
    auto commit_state = read_commit_state(database, "workspace_database.persist");
    if (!commit_state) {
        rollback(database, "workspace_database.persist");
        return workspace_result_t<void>::failure(commit_state.error());
    }
    if (commit_state.value().candidate_ready ||
        commit_state.value().committed_generation > snapshot.generation ||
        (commit_state.value().committed_generation == snapshot.generation &&
         commit_state.value().committed_analysis_revision > snapshot.analysis_revision)) {
        rollback(database, "workspace_database.persist");
        return workspace_result_t<void>::failure(make_workspace_error(
            commit_state.value().candidate_ready
                ? workspace_error_code_t::revision_conflict
                : workspace_error_code_t::stale_generation,
            commit_state.value().candidate_ready
                ? "another snapshot candidate is already pending"
                : "snapshot is older than the committed analysis state",
            "workspace_database.persist"));
    }
    const std::uint8_t target_slot =
        static_cast<std::uint8_t>(1U - commit_state.value().active_slot);
    auto result = clear_snapshot_slot(database, target_slot,
                                      "workspace_database.persist");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    if (snapshot.normalized_image) {
        const auto insert_regions = [&](const auto& regions) {
            return insert_many(database,
                "INSERT INTO " + slot_table(target_slot, "segments") + "(segment_id,name,virtual_address,virtual_size,raw_offset,raw_size,characteristics,readable,writable,executable,discardable) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                regions.size(), [&regions](statement_t& statement, std::size_t index) {
                    const auto& region = regions[index];
                    auto current = statement.bind_uint(1, region.index); if (!current) return current;
                    current = statement.bind_text(2, region.name); if (!current) return current;
                    current = statement.bind_uint(3, region.virtual_address); if (!current) return current;
                    current = statement.bind_uint(4, region.virtual_size); if (!current) return current;
                    current = statement.bind_uint(5, region.file_offset); if (!current) return current;
                    current = statement.bind_uint(6, region.file_size); if (!current) return current;
                    current = statement.bind_uint(7, region.flags); if (!current) return current;
                    current = statement.bind_int(8, (region.permissions & image_permission_read) != 0 ? 1 : 0); if (!current) return current;
                    current = statement.bind_int(9, (region.permissions & image_permission_write) != 0 ? 1 : 0); if (!current) return current;
                    current = statement.bind_int(10, (region.permissions & image_permission_execute) != 0 ? 1 : 0); if (!current) return current;
                    return statement.bind_int(11, (region.permissions & image_permission_discardable) != 0 ? 1 : 0);
                }, cancel, "workspace_database.persist.segments");
        };
        result = snapshot.normalized_image->sections.empty()
            ? insert_regions(snapshot.normalized_image->segments)
            : insert_regions(snapshot.normalized_image->sections);
        if (!result) { rollback(database, "workspace_database.persist"); return result; }
    } else if (snapshot.image) {
        const auto& sections = snapshot.image->sections();
        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "segments") + "(segment_id,name,virtual_address,virtual_size,raw_offset,raw_size,characteristics,readable,writable,executable,discardable) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            sections.size(), [&sections](statement_t& statement, std::size_t index) {
                const auto& section = sections[index];
                auto current = statement.bind_uint(1, section.index); if (!current) return current;
                current = statement.bind_text(2, section.name); if (!current) return current;
                current = statement.bind_uint(3, section.virtual_address); if (!current) return current;
                current = statement.bind_uint(4, section.virtual_size); if (!current) return current;
                current = statement.bind_uint(5, section.raw_offset); if (!current) return current;
                current = statement.bind_uint(6, section.raw_size); if (!current) return current;
                current = statement.bind_uint(7, section.characteristics); if (!current) return current;
                current = statement.bind_int(8, section.readable ? 1 : 0); if (!current) return current;
                current = statement.bind_int(9, section.writable ? 1 : 0); if (!current) return current;
                current = statement.bind_int(10, section.executable ? 1 : 0); if (!current) return current;
                return statement.bind_int(11, section.discardable ? 1 : 0);
            }, cancel, "workspace_database.persist.segments");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }
    }

    const std::size_t chunk_records = static_cast<std::size_t>((std::max<std::uint64_t>)(1, options.instruction_chunk_records));
    statement_t chunk_statement;
    const std::string chunk_insert = "INSERT INTO " +
        slot_table(target_slot, "instruction_chunks") +
        "(chunk_id,start_value,end_value,record_count,blob_version,payload) VALUES(?1,?2,?3,?4,?5,?6)";
    result = chunk_statement.prepare(database, chunk_insert.c_str(),
        "workspace_database.persist.instructions");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }
    std::uint64_t chunk_id = 1;
    for (std::size_t begin_index = 0; begin_index < snapshot.instructions.size(); begin_index += chunk_records) {
        if (cancel.stop_requested()) {
            rollback(database, "workspace_database.persist");
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "instruction persistence cancelled",
                                              "workspace_database.persist.instructions");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const std::size_t end_index = (std::min)(snapshot.instructions.size(), begin_index + chunk_records);
        auto payload = encode_instruction_chunk(snapshot.instructions, begin_index, end_index);
        const std::uint64_t start_value = snapshot.instructions[begin_index].address.value;
        std::uint64_t end_value = snapshot.instructions[end_index - 1].address.value;
        if (!checked_add_u64(end_value, snapshot.instructions[end_index - 1].length, end_value)) {
            rollback(database, "workspace_database.persist");
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "instruction range overflows address space",
                                     "workspace_database.persist.instructions"));
        }
        result = chunk_statement.bind_uint(1, chunk_id++); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(2, start_value); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(3, end_value); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(4, end_index - begin_index); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_uint(5, workspace_instruction_blob_version); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.bind_blob(6, payload.data(), payload.size()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        result = chunk_statement.reset(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    }

    result = persist_fact_chunks(database, target_slot, "operand_fact_chunks",
        snapshot.operand_facts.size(), chunk_records, packed_operand_stream_record_bytes,
        [&snapshot](std::size_t index) {
            return encode_packed_operand_record(operand_fact_materialize(
                snapshot.operand_facts, index, snapshot.instructions));
        },
        [&snapshot](std::size_t index) {
            const auto& hot = snapshot.operand_facts.hot[index];
            return hot.instruction_ordinal != 0xFFFFFFFFU
                ? static_cast<std::uint64_t>(hot.instruction_ordinal)
                : static_cast<std::uint64_t>(index);
        },
        "workspace_database.persist.operands", cancel);
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    if (search_products) {
        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "data_candidates") + "(entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            persisted_data_candidates->size(), [persisted_data_candidates](statement_t& statement, std::size_t index) {
                const auto& record = (*persisted_data_candidates)[index];
                auto current = statement.bind_uint(1, record.id); if (!current) return current;
                current = bind_address(statement, 2, record.address); if (!current) return current;
                current = statement.bind_uint(6, record.size); if (!current) return current;
                current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
                if (record.target) current = bind_address(statement, 8, *record.target);
                else {
                    for (int column = 8; column <= 11; ++column) {
                        current = statement.bind_null(column);
                        if (!current) return current;
                    }
                }
                if (!current) return current;
                current = statement.bind_int(12, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
                return statement.bind_uint(13, record.confidence);
            }, cancel, "workspace_database.persist.data_candidates");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }

        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "switches") + "(entity_id,function_id,dispatch_space,dispatch_value,dispatch_arch,dispatch_mode,table_space,table_value,table_arch,table_mode,default_space,default_value,default_arch,default_mode,entry_size,relative_entries,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            persisted_switches->size(), [persisted_switches](statement_t& statement, std::size_t index) {
                const auto& record = (*persisted_switches)[index];
                auto current = statement.bind_uint(1, record.id); if (!current) return current;
                current = statement.bind_uint(2, record.function_id); if (!current) return current;
                current = bind_address(statement, 3, record.dispatch); if (!current) return current;
                current = bind_address(statement, 7, record.table); if (!current) return current;
                if (record.default_target) current = bind_address(statement, 11, *record.default_target);
                else {
                    for (int column = 11; column <= 14; ++column) {
                        current = statement.bind_null(column);
                        if (!current) return current;
                    }
                }
                if (!current) return current;
                current = statement.bind_uint(15, record.entry_size); if (!current) return current;
                current = statement.bind_int(16, record.relative_entries ? 1 : 0); if (!current) return current;
                current = statement.bind_int(17, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
                return statement.bind_uint(18, record.confidence);
            }, cancel, "workspace_database.persist.switches");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }

        std::size_t switch_case_count = 0;
        for (const auto& record : *persisted_switches) {
            if (record.case_targets.size() > (std::numeric_limits<std::size_t>::max)() - switch_case_count) {
                rollback(database, "workspace_database.persist");
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow, "switch case count overflows",
                    "workspace_database.persist.switch_cases"));
            }
            switch_case_count += record.case_targets.size();
        }
        statement_t case_statement;
        const std::string case_insert = "INSERT INTO " +
            slot_table(target_slot, "switch_cases") +
            "(switch_id,case_index,target_space,target_value,target_arch,target_mode) VALUES(?1,?2,?3,?4,?5,?6)";
        result = case_statement.prepare(database, case_insert.c_str(),
            "workspace_database.persist.switch_cases");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }
        std::size_t inserted_cases = 0;
        for (const auto& record : *persisted_switches) {
            for (std::size_t index = 0; index < record.case_targets.size(); ++index) {
                if ((inserted_cases++ & 255U) == 0 && cancel.stop_requested()) {
                    rollback(database, "workspace_database.persist");
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::cancelled, "switch persistence cancelled",
                        "workspace_database.persist.switch_cases"));
                }
                result = case_statement.bind_uint(1, record.id); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = case_statement.bind_uint(2, index); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = bind_address(case_statement, 3, record.case_targets[index]); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = case_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
                result = case_statement.reset(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            }
        }
        if (switch_case_count > options.max_persisted_fact_records) {
            rollback(database, "workspace_database.persist");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "switch cases exceed the persisted fact-record budget",
                "workspace_database.persist.switch_cases"));
        }

        result = insert_many(database,
            "INSERT INTO " + slot_table(target_slot, "type_candidates") + "(entity_id,address_space,address_value,address_arch,address_mode,kind,display_name,canonical_type,provenance,confidence,explicitly_unknown) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            persisted_types->size(), [persisted_types](statement_t& statement, std::size_t index) {
                const auto& record = (*persisted_types)[index];
                auto current = statement.bind_uint(1, record.id); if (!current) return current;
                current = bind_address(statement, 2, record.address); if (!current) return current;
                current = statement.bind_int(6, static_cast<std::int64_t>(record.kind)); if (!current) return current;
                current = statement.bind_text(7, record.display_name); if (!current) return current;
                current = statement.bind_text(8, record.canonical_type); if (!current) return current;
                current = statement.bind_int(9, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
                current = statement.bind_uint(10, record.confidence); if (!current) return current;
                return statement.bind_int(11, record.explicitly_unknown ? 1 : 0);
            }, cancel, "workspace_database.persist.type_candidates");
        if (!result) { rollback(database, "workspace_database.persist"); return result; }

        if (!search_products->search_index_blob.empty()) {
            statement_t blob_statement;
            const std::string blob_insert = "INSERT INTO " +
                slot_table(target_slot, "search_index_blob") +
                "(singleton,generation,analysis_revision,overlay_revision,blob_version,payload) VALUES(1,?1,?2,?3,?4,?5)";
            result = blob_statement.prepare(database, blob_insert.c_str(),
                "workspace_database.persist.search_index");
            if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(1, search_products->generation); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(2, search_products->analysis_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(3, search_products->overlay_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_uint(4, search_products->search_index_blob_version); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.bind_blob(5, search_products->search_index_blob.data(), search_products->search_index_blob.size()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
            result = blob_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
        }
    }

    result = persist_fact_chunks(database, target_slot, "target_fact_chunks",
        snapshot.target_facts.size(), chunk_records, packed_target_stream_record_bytes,
        [&snapshot](std::size_t index) {
            return encode_packed_target_record(snapshot.target_facts[index]);
        },
        [&snapshot](std::size_t index) {
            return snapshot.target_facts[index].instruction_id;
        },
        "workspace_database.persist.targets", cancel);
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "functions") + "(entity_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,first_chunk,chunk_count,first_block_membership,block_membership_count,symbol_id,provenance,confidence,thunk,noreturn) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        snapshot.functions.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.functions[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.start); if (!current) return current;
            current = bind_address(statement, 6, record.end); if (!current) return current;
            current = statement.bind_uint(10, record.first_block); if (!current) return current;
            current = statement.bind_uint(11, record.block_count); if (!current) return current;
            current = statement.bind_uint(12, record.first_chunk); if (!current) return current;
            current = statement.bind_uint(13, record.chunk_count); if (!current) return current;
            current = statement.bind_uint(14, record.first_block_membership); if (!current) return current;
            current = statement.bind_uint(15, record.block_membership_count); if (!current) return current;
            if (record.symbol_id) current = statement.bind_uint(16, *record.symbol_id); else current = statement.bind_null(16); if (!current) return current;
            current = statement.bind_int(17, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_uint(18, record.confidence); if (!current) return current;
            current = statement.bind_int(19, record.thunk ? 1 : 0); if (!current) return current;
            return statement.bind_int(20, record.noreturn ? 1 : 0);
        }, cancel, "workspace_database.persist.functions");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "blocks") + "(entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_instruction,instruction_count,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        snapshot.blocks.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.blocks[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = statement.bind_uint(2, record.function_id); if (!current) return current;
            current = bind_address(statement, 3, record.start); if (!current) return current;
            current = bind_address(statement, 7, record.end); if (!current) return current;
            current = statement.bind_uint(11, record.first_instruction); if (!current) return current;
            current = statement.bind_uint(12, record.instruction_count); if (!current) return current;
            current = statement.bind_int(13, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(14, record.confidence);
        }, cancel, "workspace_database.persist.blocks");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "function_chunks") + "(chunk_index,entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,provenance,confidence,cold,shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        snapshot.function_chunks.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.function_chunks[index];
            auto current = statement.bind_uint(1, index + 1); if (!current) return current;
            current = statement.bind_uint(2, record.id); if (!current) return current;
            current = statement.bind_uint(3, record.function_id); if (!current) return current;
            current = bind_address(statement, 4, record.start); if (!current) return current;
            current = bind_address(statement, 8, record.end); if (!current) return current;
            current = statement.bind_uint(12, record.first_block); if (!current) return current;
            current = statement.bind_uint(13, record.block_count); if (!current) return current;
            current = statement.bind_int(14, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_uint(15, record.confidence); if (!current) return current;
            current = statement.bind_int(16, record.cold ? 1 : 0); if (!current) return current;
            return statement.bind_int(17, record.shared ? 1 : 0);
        }, cancel, "workspace_database.persist.function_chunks");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "function_block_memberships") + "(membership_index,function_id,chunk_id,block_id,block_index,ordinal,shared) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        snapshot.function_block_memberships.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.function_block_memberships[index];
            auto current = statement.bind_uint(1, index + 1); if (!current) return current;
            current = statement.bind_uint(2, record.function_id); if (!current) return current;
            current = statement.bind_uint(3, record.chunk_id); if (!current) return current;
            current = statement.bind_uint(4, record.block_id); if (!current) return current;
            current = statement.bind_uint(5, record.block_index); if (!current) return current;
            current = statement.bind_uint(6, record.ordinal); if (!current) return current;
            return statement.bind_int(7, record.shared ? 1 : 0);
        }, cancel, "workspace_database.persist.function_block_memberships");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = persist_fact_chunks(database, target_slot, "edge_chunks",
        snapshot.edges.size(), chunk_records, kFactChunkEdgeRecordBytes,
        [&snapshot](std::size_t index) {
            return encode_edge_chunk_record(snapshot.edges[index]);
        },
        [&snapshot](std::size_t index) {
            return snapshot.edges[index].source.value;
        },
        "workspace_database.persist.edges", cancel);
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = persist_fact_chunks(database, target_slot, "xref_chunks",
        snapshot.xrefs.size(), chunk_records, packed_xref_stream_record_bytes,
        [&snapshot](std::size_t index) {
            return encode_packed_xref_record(snapshot.xrefs[index]);
        },
        [&snapshot](std::size_t index) {
            return snapshot.xrefs[index].source.value;
        },
        "workspace_database.persist.xrefs", cancel);
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "strings") + "(entity_id,address_space,address_value,address_arch,address_mode,byte_length,encoding,value,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        snapshot.strings.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.strings[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_uint(6, record.byte_length); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.encoding)); if (!current) return current;
            current = statement.bind_text(8, record.value); if (!current) return current;
            current = statement.bind_int(9, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(10, record.confidence);
        }, cancel, "workspace_database.persist.strings");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "symbols") + "(entity_id,address_space,address_value,address_arch,address_mode,name,kind,provenance,confidence) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        snapshot.symbols.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.symbols[index];
            auto current = statement.bind_uint(1, record.id); if (!current) return current;
            current = bind_address(statement, 2, record.address); if (!current) return current;
            current = statement.bind_text(6, record.name); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.kind)); if (!current) return current;
            current = statement.bind_int(8, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            return statement.bind_uint(9, record.confidence);
        }, cancel, "workspace_database.persist.symbols");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = insert_many(database,
        "INSERT INTO " + slot_table(target_slot, "coverage") + "(span_id,start_space,start_value,start_arch,start_mode,size,reason,provenance,confidence,detail_code) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        snapshot.coverage.size(), [&snapshot](statement_t& statement, std::size_t index) {
            const auto& record = snapshot.coverage[index];
            auto current = statement.bind_uint(1, index + 1); if (!current) return current;
            current = bind_address(statement, 2, record.start); if (!current) return current;
            current = statement.bind_uint(6, record.size); if (!current) return current;
            current = statement.bind_int(7, static_cast<std::int64_t>(record.reason)); if (!current) return current;
            current = statement.bind_int(8, static_cast<std::int64_t>(record.provenance)); if (!current) return current;
            current = statement.bind_uint(9, record.confidence); if (!current) return current;
            return statement.bind_uint(10, record.detail_code);
        }, cancel, "workspace_database.persist.coverage");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    result = persist_extended_snapshot_rows(database, target_slot, snapshot, cancel);
    if (!result) { rollback(database, "workspace_database.persist"); return result; }

    statement_t state_statement;
    const std::string state_upsert = "INSERT INTO " +
        slot_table(target_slot, "analysis_state") +
        "(singleton,generation,analysis_revision,overlay_revision,baseline_complete,settings_json,metrics_json,updated_utc_ms,commit_token) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,baseline_complete=excluded.baseline_complete,settings_json=excluded.settings_json,metrics_json=excluded.metrics_json,updated_utc_ms=excluded.updated_utc_ms,commit_token=excluded.commit_token";
    result = state_statement.prepare(database, state_upsert.c_str(),
                                     "workspace_database.persist.state");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(1, snapshot.generation); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(2, snapshot.analysis_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(3, snapshot.overlay_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_int(4, snapshot.baseline_complete ? 1 : 0); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_text(5, settings_json); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_text(6, metrics_json); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_uint(7, utc_ms()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.bind_text(8, candidate_token); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = state_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }

    statement_t candidate_statement;
    result = candidate_statement.prepare(database,
        "UPDATE workspace_commit_state SET candidate_slot=?1,candidate_token=?2,candidate_generation=?3,candidate_analysis_revision=?4,candidate_overlay_revision=?5,candidate_ready=1,updated_utc_ms=?6 WHERE singleton=1 AND active_slot=?7 AND candidate_ready=0",
        "workspace_database.persist.candidate");
    if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(1, target_slot); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_text(2, candidate_token); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(3, snapshot.generation); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(4, snapshot.analysis_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(5, snapshot.overlay_revision); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(6, utc_ms()); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.bind_uint(7, commit_state.value().active_slot); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    result = candidate_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist"); return result; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.persist");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "workspace commit slot changed during candidate persistence",
            "workspace_database.persist.candidate"));
    }

    auto committed = commit(database, "workspace_database.persist");
    if (!committed) {
        rollback(database, "workspace_database.persist");
        return committed;
    }
    int log_frames = 0;
    int checkpointed_frames = 0;
    const int checkpoint_status = sqlite3_wal_checkpoint_v2(
        database, "main", SQLITE_CHECKPOINT_PASSIVE, &log_frames, &checkpointed_frames);
    if (checkpoint_status != SQLITE_OK && checkpoint_status != SQLITE_BUSY) {
        return workspace_result_t<void>::failure(
            database_error(database, checkpoint_status,
                           "snapshot committed but passive WAL checkpoint failed",
                           "workspace_database.checkpoint"));
    }
    int cache_writes_after = 0;
    const int after_status = sqlite3_db_status(
        database, SQLITE_DBSTATUS_CACHE_WRITE, &cache_writes_after,
        &ignored_highwater, 0);
    if (after_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, after_status,
            "snapshot committed but SQLite cache-write accounting failed",
            "workspace_database.metrics"));
    }
    const std::uint64_t written_pages = cache_writes_after >= cache_writes_before
        ? static_cast<std::uint64_t>(cache_writes_after - cache_writes_before)
        : static_cast<std::uint64_t>(cache_writes_after);
    std::uint64_t page_write_bytes = 0;
    if (!checked_mul_u64(written_pages, page_size_result.value(), page_write_bytes)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "snapshot committed but SQLite page-write accounting overflowed",
            "workspace_database.metrics"));
    }
    if (commit_metrics) {
        commit_metrics->logical_bytes = logical_bytes;
        commit_metrics->rows = logical_rows;
        commit_metrics->page_write_bytes = page_write_bytes;
        commit_metrics->elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - commit_started).count());
    }
    if (managed_publication) {
        auto staged = stage_managed_publication_domain(
            database, snapshot, *managed_publication, options,
            candidate_token, fact_records, cancel, commit_metrics);
        if (!staged)
            return staged;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> configure_connection(sqlite3* database,
                                              const workspace_database_options_t& options,
                                              bool writer) {
    sqlite3_extended_result_codes(database, 1);
    const int busy_status = sqlite3_busy_timeout(database,
        static_cast<int>((std::min<std::uint32_t>)(options.busy_timeout_ms, 60000)));
    if (busy_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(
            database_error(database, busy_status, "unable to configure bounded SQLite busy timeout",
                           "workspace_database.open"));
    }
    auto configured = exec_sql(database, "PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;",
                               "workspace_database.open");
    if (!configured) return configured;
    if (!writer) {
        configured = exec_sql(database, "PRAGMA mmap_size=4398046511104",
                              "workspace_database.open_reader");
        if (!configured) return configured;
        return exec_sql(database, "PRAGMA query_only=ON", "workspace_database.open_reader");
    }
    configured = exec_sql(database,
        "PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA temp_store=MEMORY;PRAGMA cache_size=-262144;",
        "workspace_database.open");
    if (!configured) return configured;
    const int checkpoint_status = sqlite3_wal_autocheckpoint(
        database, static_cast<int>((std::min<std::uint32_t>)(
            options.passive_checkpoint_pages, 1000000U)));
    if (checkpoint_status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, checkpoint_status,
            "unable to configure bounded WAL auto-checkpointing",
            "workspace_database.open"));
    }
    statement_t journal;
    configured = journal.prepare(database, "PRAGMA journal_mode", "workspace_database.open");
    if (!configured) return configured;
    const int status = sqlite3_step(journal.get());
    if (status != SQLITE_ROW || column_text(journal.get(), 0) != "wal") {
        return workspace_result_t<void>::failure(
            database_error(database, status, "SQLite database did not enter WAL mode",
                           "workspace_database.open"));
    }
    statement_t synchronous;
    configured = synchronous.prepare(database, "PRAGMA synchronous",
                                     "workspace_database.open");
    if (!configured) return configured;
    const int synchronous_status = sqlite3_step(synchronous.get());
    if (synchronous_status != SQLITE_ROW ||
        sqlite3_column_int(synchronous.get(), 0) != 2) {
        return workspace_result_t<void>::failure(database_error(
            database, synchronous_status,
            "SQLite database did not enter FULL synchronous mode",
            "workspace_database.open"));
    }
    return workspace_result_t<void>::success();
}

int final_passive_checkpoint(sqlite3* database) noexcept {
    int status = sqlite3_wal_checkpoint_v2(
        database, "main", SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    if (status == SQLITE_INTERRUPT && sqlite3_is_interrupted(database) == 0) {
        status = sqlite3_wal_checkpoint_v2(
            database, "main", SQLITE_CHECKPOINT_PASSIVE, nullptr, nullptr);
    }
    return status;
}

workspace_result_t<sqlite3*> open_reader_connection(
    const std::string& path, const workspace_database_options_t& options) {
    sqlite3* database = nullptr;
    const int status = sqlite3_open_v2(path.c_str(), &database,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI, nullptr);
    if (status != SQLITE_OK) {
        auto error = database_error(database, status, "unable to open workspace read connection",
                                    "workspace_database.read");
        if (database)
            sqlite3_close_v2(database);
        return workspace_result_t<sqlite3*>::failure(std::move(error));
    }
    auto configured = configure_connection(database, options, false);
    if (!configured) {
        sqlite3_close_v2(database);
        return workspace_result_t<sqlite3*>::failure(configured.error());
    }
    return workspace_result_t<sqlite3*>::success(database);
}

workspace_result_t<void> set_writer_synchronous(sqlite3* database, int mode,
                                                const char* phase) {
    const std::string sql = "PRAGMA synchronous=" + std::to_string(mode);
    return exec_sql(database, sql.c_str(), phase);
}

}

namespace {

template <typename Record, typename Reader>
workspace_result_t<Record> decode_packed_record_impl(
    const std::uint8_t* data, std::size_t size, Reader read) {
    if (!data || size == 0) {
        return workspace_result_t<Record>::failure(packed_baseline_error(
            workspace_error_code_t::invalid_argument,
            "packed record decode received an empty byte range"));
    }
    const std::vector<std::uint8_t> bytes(data, data + size);
    cancellation_token_t cancel;
    packed_payload_reader_t reader(bytes, cancel, 1);
    Record record = read(reader);
    if (reader.failed())
        return workspace_result_t<Record>::failure(reader.finish().error());
    return workspace_result_t<Record>::success(std::move(record));
}

}

workspace_result_t<instruction_record_t> decode_packed_instruction_record(
    const std::uint8_t* data, std::size_t size) {
    return decode_packed_record_impl<instruction_record_t>(data, size,
        [](packed_payload_reader_t& reader) { return read_instruction(reader); });
}

workspace_result_t<operand_fact_t> decode_packed_operand_record(
    const std::uint8_t* data, std::size_t size) {
    return decode_packed_record_impl<operand_fact_t>(data, size,
        [](packed_payload_reader_t& reader) { return read_operand(reader); });
}

workspace_result_t<target_fact_t> decode_packed_target_record(
    const std::uint8_t* data, std::size_t size) {
    return decode_packed_record_impl<target_fact_t>(data, size,
        [](packed_payload_reader_t& reader) { return read_target(reader); });
}

workspace_result_t<edge_record_t> decode_packed_edge_record(
    const std::uint8_t* data, std::size_t size) {
    return decode_packed_record_impl<edge_record_t>(data, size,
        [](packed_payload_reader_t& reader) { return read_edge(reader); });
}

workspace_result_t<xref_record_t> decode_packed_xref_record(
    const std::uint8_t* data, std::size_t size) {
    return decode_packed_record_impl<xref_record_t>(data, size,
        [](packed_payload_reader_t& reader) { return read_xref(reader); });
}

namespace {

template <typename Writer>
std::vector<std::uint8_t> encode_packed_record_impl(Writer write) {
    std::vector<std::uint8_t> bytes;
    cancellation_token_t cancel;
    packed_payload_writer_t writer(cancel,
        [&bytes](const std::uint8_t* data, std::size_t size) {
            bytes.insert(bytes.end(), data, data + size);
            return workspace_result_t<void>::success();
        }, {}, packed_page_max_payload);
    write(writer);
    auto finished = writer.finish_stream();
    (void)finished;
    return bytes;
}

}

std::vector<std::uint8_t> encode_packed_instruction_record(
    const instruction_record_t& record) {
    return encode_packed_record_impl(
        [&](packed_payload_writer_t& writer) { write_instruction(writer, record); });
}

std::vector<std::uint8_t> encode_packed_operand_record(const operand_fact_t& record) {
    return encode_packed_record_impl(
        [&](packed_payload_writer_t& writer) { write_operand(writer, record); });
}

std::vector<std::uint8_t> encode_packed_target_record(const target_fact_t& record) {
    return encode_packed_record_impl(
        [&](packed_payload_writer_t& writer) { write_target(writer, record); });
}

std::vector<std::uint8_t> encode_packed_xref_record(const xref_record_t& record) {
    return encode_packed_record_impl(
        [&](packed_payload_writer_t& writer) { write_xref(writer, record); });
}

std::array<std::uint8_t, packed_domain_stream_header_bytes>
encode_packed_domain_stream_header(packed_page_type_t domain,
                                   std::uint64_t record_count) {
    std::array<std::uint8_t, packed_domain_stream_header_bytes> bytes{};
    cancellation_token_t cancel;
    std::vector<std::uint8_t> out;
    packed_payload_writer_t writer(cancel,
        [&out](const std::uint8_t* data, std::size_t size) {
            out.insert(out.end(), data, data + size);
            return workspace_result_t<void>::success();
        }, {}, packed_page_max_payload);
    write_domain_header(writer, domain);
    writer.count(record_count);
    auto finished = writer.finish_stream();
    (void)finished;
    const auto copy = (std::min)(out.size(), bytes.size());
    std::memcpy(bytes.data(), out.data(), copy);
    return bytes;
}

struct workspace_database_t::connection_state_t {
    sqlite3* writer = nullptr;
    std::string path;
    mutable std::mutex close_mutex;
    mutable std::timed_mutex writer_mutex;
    std::atomic<bool> open{false};
    std::atomic<std::uint64_t> persisted_generation{0};
    std::atomic<std::uint64_t> persisted_analysis_revision{0};
    std::atomic<std::uint64_t> persisted_overlay_revision{0};
    std::atomic<std::uint64_t> candidate_generation{0};
    std::atomic<std::uint64_t> candidate_analysis_revision{0};
    std::atomic<std::uint64_t> candidate_overlay_revision{0};
    std::atomic<bool> candidate_pending{false};
    std::atomic<std::uint64_t> cache_invalidations{0};
    std::atomic<std::uint64_t> last_commit_logical_bytes{0};
    std::atomic<std::uint64_t> cumulative_logical_bytes{0};
    std::atomic<std::uint64_t> last_commit_rows{0};
    std::atomic<std::uint64_t> cumulative_rows{0};
    std::atomic<std::uint64_t> last_commit_page_write_bytes{0};
    std::atomic<std::uint64_t> cumulative_page_write_bytes{0};
    std::atomic<std::uint64_t> last_commit_elapsed_us{0};
    mutable std::mutex staging_mutex;
    std::weak_ptr<workspace_snapshot_staging_t> active_staging;
    std::atomic<std::uint64_t> staging_resident_bytes{0};
    std::atomic<std::uint64_t> cumulative_pages_written{0};
    std::atomic<std::uint64_t> wal_bytes_peak{0};
    std::atomic<std::uint64_t> last_commit_pages_v3{0};
    std::atomic<std::uint64_t> cumulative_pages_v3{0};
    std::atomic<std::uint64_t> last_commit_page_stored_bytes{0};
    std::atomic<std::uint64_t> cumulative_page_stored_bytes{0};
    std::atomic<std::uint64_t> last_commit_page_logical_bytes{0};
    std::atomic<std::uint64_t> cumulative_page_logical_bytes{0};
    std::atomic<std::uint64_t> pdb_modules_stored{0};
    std::atomic<std::uint64_t> pdb_modules_skipped{0};
    std::atomic<std::uint64_t> pdb_modules_loaded{0};
    std::shared_ptr<sqlite_statement_cache_t> writer_statements;
    std::shared_ptr<sqlite_reader_pool_t> reader_pool;
    std::atomic<bool> coalesce_group_active{false};
    std::atomic<std::uint64_t> coalesce_owner_tid{0};
    std::unique_ptr<sqlite_progress_guard_t> coalesce_progress;

    ~connection_state_t() {
        std::lock_guard<std::mutex> lock(close_mutex);
        std::lock_guard<std::timed_mutex> writer_lock(writer_mutex);
        coalesce_progress.reset();
        if (reader_pool)
            reader_pool->close();
        if (writer) {
            if (writer_statements) {
                sqlite_statement_cache_unregister(writer);
                writer_statements.reset();
            }
            final_passive_checkpoint(writer);
            sqlite3_close_v2(writer);
            writer = nullptr;
        }
        open.store(false, std::memory_order_release);
    }
};

namespace {

persistence_operation_t make_cache_write_operation(
    const std::shared_ptr<workspace_database_t::connection_state_t>& state,
    std::function<workspace_result_t<void>(sqlite3*, const cancellation_token_t&)>
        operation) {
    return [state, operation = std::move(operation)](
               const cancellation_token_t& token) mutable -> workspace_result_t<void> {
        const std::uint64_t self_tid = static_cast<std::uint64_t>(GetCurrentThreadId());
        if (state->coalesce_group_active.load(std::memory_order_acquire) &&
            state->coalesce_owner_tid.load(std::memory_order_acquire) == self_tid &&
            state->writer) {
            return operation(state->writer, token);
        }
        std::lock_guard<std::timed_mutex> writer_lock(state->writer_mutex);
        if (!state->open.load(std::memory_order_acquire) || !state->writer) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::workspace_closing,
                                     "workspace database is closed",
                                     "workspace_database.write"));
        }
        sqlite_progress_guard_t progress(state->writer, token);
        auto result = operation(state->writer, token);
        if (!result && token.stop_requested()) {
            auto error = make_workspace_error(
                token.deadline_exceeded()
                    ? workspace_error_code_t::deadline_exceeded
                    : workspace_error_code_t::cancelled,
                "workspace database write was cancelled",
                "workspace_database.write");
            error.deadline = token.deadline_exceeded();
            error.cancellation = !error.deadline;
            error.details.emplace_back("sqlite_write_error",
                                       result.error().stable_code());
            return workspace_result_t<void>::failure(std::move(error));
        }
        return result;
    };
}

void install_writer_coalescing(
    const std::shared_ptr<persistence_queue_t>& queue,
    const std::shared_ptr<workspace_database_t::connection_state_t>& state) {
    persistence_coalesce_hooks_t hooks;
    hooks.begin_group = [state](const cancellation_token_t& token)
        -> workspace_result_t<void> {
        state->writer_mutex.lock();
        if (!state->open.load(std::memory_order_acquire) || !state->writer) {
            state->writer_mutex.unlock();
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::workspace_closing,
                                     "workspace database is closed",
                                     "workspace_database.coalesce"));
        }
        auto lowered = set_writer_synchronous(state->writer, 1,
                                              "workspace_database.coalesce");
        if (!lowered) {
            state->writer_mutex.unlock();
            return lowered;
        }
        auto begun = begin_immediate(state->writer, "workspace_database.coalesce");
        if (!begun) {
            set_writer_synchronous(state->writer, 2, "workspace_database.coalesce");
            state->writer_mutex.unlock();
            return begun;
        }
        state->coalesce_progress =
            std::make_unique<sqlite_progress_guard_t>(state->writer, token);
        state->coalesce_owner_tid.store(
            static_cast<std::uint64_t>(GetCurrentThreadId()),
            std::memory_order_release);
        state->coalesce_group_active.store(true, std::memory_order_release);
        return workspace_result_t<void>::success();
    };
    hooks.end_group = [state](bool commit_flag) -> workspace_result_t<void> {
        state->coalesce_progress.reset();
        workspace_result_t<void> result = workspace_result_t<void>::success();
        if (commit_flag) {
            result = commit(state->writer, "workspace_database.coalesce");
            if (!result)
                rollback(state->writer, "workspace_database.coalesce");
        } else {
            result = rollback(state->writer, "workspace_database.coalesce");
        }
        auto restored = set_writer_synchronous(state->writer, 2,
                                               "workspace_database.coalesce");
        state->coalesce_group_active.store(false, std::memory_order_release);
        state->coalesce_owner_tid.store(0, std::memory_order_release);
        state->writer_mutex.unlock();
        if (!result)
            return result;
        return restored;
    };
    queue->set_coalesce_hooks(std::move(hooks));
}

}

namespace {

struct managed_domain_strings_t final {
    std::vector<std::string> values;
    std::unordered_map<std::string, std::uint32_t> references;
    std::vector<std::string> entities;
};

workspace_result_t<managed_domain_strings_t> collect_managed_domain_strings(
    const managed_artifact_publication_t& publication,
    const cancellation_token_t& cancel) {
    managed_domain_strings_t result;
    if (!publication.records || publication.artifacts().empty() ||
        publication.artifacts().size() > managed_publication_max_artifacts ||
        publication.methods().size() > managed_publication_max_methods) {
        return workspace_result_t<managed_domain_strings_t>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication record count exceeds its bounded domain"));
    }
    try {
        std::set<std::string> ordered_values;
        result.entities.reserve(publication.methods().size());
        ordered_values.insert(publication.provider_source);
        std::uint64_t string_bytes = publication.provider_source.size();
        for (std::size_t index = 0; index < publication.artifacts().size(); ++index) {
            if ((index & 255U) == 0 && cancel.stop_requested())
                return workspace_result_t<managed_domain_strings_t>::failure(
                    packed_baseline_cancelled(cancel));
            const auto& artifact = publication.artifacts()[index];
            const std::array<const std::string*, 3> strings{
                &artifact.assembly_identity, &artifact.module_name,
                &artifact.version};
            for (const auto* value : strings) {
                if (value->size() > managed_publication_max_single_string_bytes ||
                    !checked_add_u64(string_bytes, value->size(), string_bytes) ||
                    string_bytes > managed_publication_max_string_bytes) {
                    return workspace_result_t<managed_domain_strings_t>::failure(
                        packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                              "managed publication strings exceed their bounded domain"));
                }
                ordered_values.insert(*value);
            }
        }
        std::unordered_set<std::string> entity_identities;
        entity_identities.reserve(publication.methods().size());
        for (std::size_t index = 0; index < publication.methods().size(); ++index) {
            if ((index & 255U) == 0 && cancel.stop_requested())
                return workspace_result_t<managed_domain_strings_t>::failure(
                    packed_baseline_cancelled(cancel));
            const auto& method = publication.methods()[index];
            if (!validate_decompiler_entity_key(method.entity).valid()) {
                return workspace_result_t<managed_domain_strings_t>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                                          "managed publication contains an invalid entity key"));
            }
            auto encoded = serialize_decompiler_entity_key(method.entity);
            if (encoded.empty() ||
                encoded.size() > managed_publication_max_single_string_bytes ||
                !entity_identities.insert(encoded).second ||
                !checked_add_u64(string_bytes, encoded.size(), string_bytes) ||
                string_bytes > managed_publication_max_string_bytes) {
                return workspace_result_t<managed_domain_strings_t>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                                          "managed publication entity identities are noncanonical"));
            }
            ordered_values.insert(encoded);
            result.entities.push_back(std::move(encoded));
        }
        if (ordered_values.empty() ||
            ordered_values.size() > managed_publication_max_strings) {
            return workspace_result_t<managed_domain_strings_t>::failure(
                packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                      "managed publication string table exceeds its bounded domain"));
        }
        result.values.reserve(ordered_values.size());
        result.references.reserve(ordered_values.size());
        std::uint32_t index = 0;
        for (const auto& value : ordered_values) {
            if ((index & 255U) == 0 && cancel.stop_requested())
                return workspace_result_t<managed_domain_strings_t>::failure(
                    packed_baseline_cancelled(cancel));
            result.references.emplace(value, index++);
            result.values.push_back(value);
        }
        return workspace_result_t<managed_domain_strings_t>::success(
            std::move(result));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<managed_domain_strings_t>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication string-table allocation failed"));
    } catch (const std::exception&) {
        return workspace_result_t<managed_domain_strings_t>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "managed publication entity serialization failed"));
    }
}

void write_managed_reader_limits(
    packed_payload_writer_t& writer,
    const readers::managed::managed_reader_limits_t& limits) {
    writer.u64(limits.max_metadata_bytes);
    writer.u32(limits.max_types);
    writer.u32(limits.max_methods);
    writer.u32(limits.max_fields);
    writer.u32(limits.max_member_references);
    writer.u32(limits.max_annotations);
    writer.u32(limits.max_resources);
    writer.u32(limits.max_exception_regions);
    writer.u32(limits.max_code_ranges);
    writer.u64(limits.max_code_bytes);
    writer.u64(limits.max_string_bytes);
    writer.u32(limits.max_dex_files);
    writer.u32(limits.max_constant_pool_entries);
    writer.u32(limits.max_table_rows);
    writer.u32(limits.max_generic_params);
}

bool managed_reader_limits_bounded(
    const readers::managed::managed_reader_limits_t& limits) noexcept {
    return limits.valid() &&
        limits.max_metadata_bytes <= managed_publication_max_payload_bytes &&
        limits.max_types <= managed_publication_max_methods &&
        limits.max_methods <= managed_publication_max_methods &&
        limits.max_fields <= managed_publication_max_methods &&
        limits.max_member_references <= managed_publication_max_methods &&
        limits.max_annotations <= managed_publication_max_methods &&
        limits.max_resources <= managed_publication_max_methods &&
        limits.max_exception_regions <= managed_publication_max_methods &&
        limits.max_code_ranges <= managed_publication_max_methods &&
        limits.max_code_bytes <= managed_publication_max_payload_bytes &&
        limits.max_string_bytes <= managed_publication_max_string_bytes &&
        limits.max_dex_files <= managed_publication_max_artifacts &&
        limits.max_constant_pool_entries <= 65535U &&
        limits.max_table_rows <= managed_publication_max_methods &&
        limits.max_generic_params <= managed_publication_max_methods;
}

readers::managed::managed_reader_limits_t read_managed_reader_limits(
    packed_payload_reader_t& reader) {
    readers::managed::managed_reader_limits_t limits;
    limits.max_metadata_bytes = reader.u64();
    limits.max_types = reader.u32();
    limits.max_methods = reader.u32();
    limits.max_fields = reader.u32();
    limits.max_member_references = reader.u32();
    limits.max_annotations = reader.u32();
    limits.max_resources = reader.u32();
    limits.max_exception_regions = reader.u32();
    limits.max_code_ranges = reader.u32();
    limits.max_code_bytes = reader.u64();
    limits.max_string_bytes = reader.u64();
    limits.max_dex_files = reader.u32();
    limits.max_constant_pool_entries = reader.u32();
    limits.max_table_rows = reader.u32();
    limits.max_generic_params = reader.u32();
    if (!managed_reader_limits_bounded(limits))
        reader.reject("managed publication reader limits are invalid");
    return limits;
}

workspace_result_t<void> validate_managed_publication_for_encoding(
    const managed_artifact_publication_t& publication,
    const cancellation_token_t& cancel) {
    if (publication.schema_version != managed_entity_binding_schema_version ||
        publication.reader_schema_version !=
            readers::managed::managed_reader_schema_version ||
        !managed_reader_limits_bounded(publication.reader_limits) ||
        publication.binary_id.empty() ||
        publication.load_profile_hash.empty() || publication.provider_hash.empty() ||
        publication.provider_source.empty() ||
        publication.provider_source.size() >
            managed_publication_max_single_string_bytes ||
        publication.provider_size == 0 ||
        publication.generation == 0 || publication.analysis_revision == 0 ||
        !publication.records || publication.artifacts().empty() ||
        publication.artifacts().size() > managed_publication_max_artifacts ||
        publication.artifacts().size() >
            static_cast<std::uint64_t>(
                publication.reader_limits.max_dex_files) + 1ULL ||
        publication.methods().size() > managed_publication_max_methods) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "managed publication identity is incomplete"));
    }
    std::uint64_t declared_method_limit = 0;
    if (!checked_mul_u64(publication.reader_limits.max_methods,
                         publication.reader_limits.max_dex_files,
                         declared_method_limit) ||
        publication.methods().size() > declared_method_limit) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication exceeds its reader method budget"));
    }
    std::uint64_t expected_method = 0;
    std::unordered_set<std::uint32_t> artifact_ordinals;
    try {
        artifact_ordinals.reserve(publication.artifacts().size());
        for (std::size_t index = 0;
             index < publication.artifacts().size(); ++index) {
            if ((index & 255U) == 0 && cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    packed_baseline_cancelled(cancel));
            const auto& artifact = publication.artifacts()[index];
            const auto kind = static_cast<std::uint8_t>(artifact.kind);
            if (kind > static_cast<std::uint8_t>(
                           readers::managed::managed_artifact_kind_t::multidex_container) ||
                artifact.artifact_hash.empty() || artifact.provider_size == 0 ||
                artifact.provider_offset > publication.provider_size ||
                artifact.provider_size >
                    publication.provider_size - artifact.provider_offset ||
                artifact.method_count > publication.reader_limits.max_methods ||
                artifact.first_method != expected_method ||
                !artifact_ordinals.insert(artifact.artifact_ordinal).second ||
                !checked_add_u64(expected_method, artifact.method_count,
                                 expected_method) ||
                expected_method > publication.methods().size()) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "managed artifact records are noncanonical"));
            }
        }
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed artifact validation allocation failed"));
    }
    if (expected_method != publication.methods().size()) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "managed artifact method ranges are incomplete"));
    }
    for (std::size_t index = 0; index < publication.methods().size(); ++index) {
        if ((index & 255U) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                packed_baseline_cancelled(cancel));
        const auto& method = publication.methods()[index];
        if (method.artifact_index >= publication.artifacts().size()) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "managed method references an invalid artifact"));
        }
        const auto& artifact = publication.artifacts()[method.artifact_index];
        if (index < artifact.first_method ||
            index >= static_cast<std::uint64_t>(artifact.first_method) +
                         artifact.method_count ||
            method.method_index >= artifact.method_count ||
            method.provider_code_offset < artifact.provider_offset ||
            method.provider_code_offset > artifact.provider_offset +
                                              artifact.provider_size ||
            method.code_size > artifact.provider_offset + artifact.provider_size -
                                   method.provider_code_offset ||
            method.has_body != (method.code_size != 0)) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "managed method records are inconsistent"));
        }
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> write_managed_publication_domain_stream(
    const managed_artifact_publication_t& publication,
    packed_payload_writer_t& writer,
    const cancellation_token_t& cancel) {
    auto validated = validate_managed_publication_for_encoding(publication, cancel);
    if (!validated)
        return validated;
    auto strings = collect_managed_domain_strings(publication, cancel);
    if (!strings)
        return workspace_result_t<void>::failure(strings.error());
    const auto reference = [&](const std::string& value) {
        const auto found = strings.value().references.find(value);
        return found == strings.value().references.end()
            ? (std::numeric_limits<std::uint32_t>::max)() : found->second;
    };
    write_domain_header(writer, packed_page_type_t::managed_publication);
    writer.u32(managed_publication_domain_magic);
    writer.u16(managed_publication_domain_version);
    writer.u16(0);
    writer.u32(publication.schema_version);
    writer.u32(publication.reader_schema_version);
    write_managed_reader_limits(writer, publication.reader_limits);
    writer.fixed_bytes(publication.binary_id.bytes);
    writer.fixed_bytes(publication.load_profile_hash.bytes);
    writer.fixed_bytes(publication.provider_hash.bytes);
    writer.u64(publication.provider_size);
    writer.u64(publication.generation);
    writer.u64(publication.analysis_revision);
    writer.u64(publication.overlay_revision);
    writer.u32(static_cast<std::uint32_t>(strings.value().values.size()));
    for (const auto& value : strings.value().values) {
        writer.begin_record();
        writer.string(value);
    }
    writer.u32(reference(publication.provider_source));
    writer.u32(static_cast<std::uint32_t>(publication.artifacts().size()));
    writer.u32(static_cast<std::uint32_t>(publication.methods().size()));
    for (const auto& value : publication.artifacts()) {
        writer.begin_record();
        writer.u8(static_cast<std::uint8_t>(value.kind));
    }
    for (const auto& value : publication.artifacts())
        writer.fixed_bytes(value.artifact_hash.bytes);
    for (const auto& value : publication.artifacts())
        writer.u64(value.provider_offset);
    for (const auto& value : publication.artifacts())
        writer.u64(value.provider_size);
    for (const auto& value : publication.artifacts())
        writer.u32(value.artifact_ordinal);
    for (const auto& value : publication.artifacts())
        writer.u32(reference(value.assembly_identity));
    for (const auto& value : publication.artifacts())
        writer.u32(reference(value.module_name));
    for (const auto& value : publication.artifacts())
        writer.u32(reference(value.version));
    for (const auto& value : publication.artifacts())
        writer.u32(value.first_method);
    for (const auto& value : publication.artifacts())
        writer.u32(value.method_count);
    for (const auto& value : publication.methods()) {
        writer.begin_record();
        writer.u32(value.artifact_index);
    }
    for (const auto& value : publication.methods())
        writer.u32(value.entity_token);
    for (const auto& value : publication.methods())
        writer.u32(value.method_index);
    for (const auto& value : publication.methods())
        writer.u64(value.provider_code_offset);
    for (const auto& value : publication.methods())
        writer.u64(value.code_size);
    for (std::size_t index = 0; index < publication.methods().size(); ++index)
        writer.u32(reference(strings.value().entities[index]));
    for (const auto& value : publication.methods())
        writer.boolean(value.has_body);
    const auto checksum = writer.checksum();
    writer.u32(checksum);
    return writer.finish_stream();
}

workspace_result_t<void> write_packed_baseline_domain_stream(
    packed_page_type_t domain,
    const analysis_snapshot_t& snapshot,
    const persisted_search_products_t& search_products,
    packed_payload_writer_t& writer,
    const cancellation_token_t& cancel) {
    write_domain_header(writer, domain);
    const auto begin = [&](const std::optional<address_t>& address = std::nullopt) {
        writer.begin_record(address);
    };
    switch (domain) {
    case packed_page_type_t::instructions:
        writer.count(snapshot.instructions.size());
        for (const auto& record : snapshot.instructions) {
            begin(record.address);
            write_instruction(writer, record);
        }
        writer.count(snapshot.delay_slot_counts.size());
        for (const auto value : snapshot.delay_slot_counts) {
            begin();
            writer.u8(value);
        }
        break;
    case packed_page_type_t::operands:
        writer.count(snapshot.operand_facts.size());
        for (std::uint64_t ordinal = 0; ordinal < snapshot.operand_facts.size();
             ++ordinal) {
            begin();
            write_operand(writer, operand_fact_materialize(
                snapshot.operand_facts, ordinal, snapshot.instructions));
        }
        break;
    case packed_page_type_t::target_facts:
        writer.count(snapshot.target_facts.size());
        for (const auto& record : snapshot.target_facts) {
            begin(record.target);
            write_target(writer, record);
        }
        break;
    case packed_page_type_t::edges:
        writer.count(snapshot.edges.size());
        for (const auto& record : snapshot.edges) {
            begin(record.source);
            write_edge(writer, record);
        }
        break;
    case packed_page_type_t::strings:
        writer.count(snapshot.strings.size());
        for (const auto& record : snapshot.strings) {
            begin(record.address);
            write_string_record(writer, record);
        }
        break;
    case packed_page_type_t::symbols:
        writer.count(snapshot.symbols.size());
        for (const auto& record : snapshot.symbols) {
            begin(record.address);
            write_symbol(writer, record);
        }
        break;
    case packed_page_type_t::address_expressions:
        writer.count(snapshot.address_expressions.size());
        for (const auto& record : snapshot.address_expressions) {
            begin();
            write_address_expression(writer, record);
        }
        break;
    case packed_page_type_t::basic_blocks:
        writer.count(snapshot.blocks.size());
        for (const auto& record : snapshot.blocks) {
            begin(record.start);
            write_block(writer, record);
        }
        break;
    case packed_page_type_t::functions:
        writer.count(snapshot.functions.size());
        for (const auto& record : snapshot.functions) {
            begin(record.start);
            if (record.chunks.empty() && record.chunk_count != 0) {
                function_record_t materialized = record;
                const auto ranges = snapshot.function_chunks_of(record);
                materialized.chunks.assign(ranges.begin(), ranges.end());
                write_function(writer, materialized);
            } else {
                write_function(writer, record);
            }
        }
        break;
    case packed_page_type_t::function_chunks:
        writer.count(snapshot.function_chunks.size());
        for (const auto& record : snapshot.function_chunks) {
            begin(record.start);
            write_function_chunk(writer, record);
        }
        writer.count(snapshot.function_block_memberships.size());
        for (const auto& record : snapshot.function_block_memberships) {
            begin();
            write_function_membership(writer, record);
        }
        break;
    case packed_page_type_t::xrefs:
        writer.count(snapshot.xrefs.size());
        for (const auto& record : snapshot.xrefs) {
            begin(record.source);
            write_xref(writer, record);
        }
        break;
    case packed_page_type_t::coverage:
        writer.count(snapshot.coverage.size());
        for (const auto& record : snapshot.coverage) {
            begin(record.start);
            write_coverage(writer, record);
        }
        break;
    case packed_page_type_t::search_index: {
        const auto& data_candidates = search_products.live_index
            ? search_products.live_index->data_candidates()
            : search_products.data_candidates;
        const auto& switches = search_products.live_index
            ? search_products.live_index->switches()
            : search_products.switches;
        const auto& types = search_products.live_index
            ? search_products.live_index->types()
            : search_products.types;
        writer.count(data_candidates.size());
        for (const auto& record : data_candidates) {
            begin(record.address);
            write_data_candidate(writer, record);
        }
        writer.count(switches.size());
        for (const auto& record : switches) {
            begin(record.dispatch);
            write_switch(writer, record);
        }
        writer.count(types.size());
        for (const auto& record : types) {
            begin(record.address);
            write_search_type(writer, record);
        }
        if (search_products.live_index) {
            auto serialized_size =
                search_products.live_index->serialized_size(cancel);
            if (!serialized_size)
                return workspace_result_t<void>::failure(
                    serialized_size.error());
            writer.u32(search_index_t::serialized_version);
            writer.u64(serialized_size.value());
            std::uint64_t written = 0;
            auto serialized = search_products.live_index->serialize_to(
                [&](const std::uint8_t* data, std::size_t size) {
                    auto appended = writer.append_external(data, size);
                    if (!appended)
                        return appended;
                    std::uint64_t updated = 0;
                    if (!checked_add_u64(written, size, updated) ||
                        updated > serialized_size.value()) {
                        return workspace_result_t<void>::failure(
                            packed_baseline_error(
                                workspace_error_code_t::integrity_failure,
                                "serialized search stream exceeds its declared size"));
                    }
                    written = updated;
                    return workspace_result_t<void>::success();
                }, cancel);
            if (!serialized)
                return serialized;
            if (written != serialized_size.value()) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "serialized search stream is shorter than its declared size"));
            }
        } else {
            writer.u32(search_products.search_index_blob_version);
            writer.bytes(search_products.search_index_blob.data(),
                         search_products.search_index_blob.size());
        }
        break;
    }
    case packed_page_type_t::call_graph:
        writer.count(snapshot.call_graph.nodes.size());
        for (const auto& record : snapshot.call_graph.nodes) {
            begin(record.address);
            write_call_node(writer, record);
        }
        writer.count(snapshot.call_graph.call_sites.size());
        for (const auto& record : snapshot.call_graph.call_sites) {
            begin(record.address);
            write_call_site(writer, record);
        }
        writer.count(snapshot.call_graph.candidates.size());
        for (const auto& record : snapshot.call_graph.candidates) {
            begin(record.target);
            write_call_candidate(writer, record);
        }
        writer.count(snapshot.call_graph.edges.size());
        for (const auto& record : snapshot.call_graph.edges) {
            begin(record.call_site);
            write_call_edge(writer, record);
        }
        writer.count(snapshot.call_graph.conflicts.size());
        for (const auto& record : snapshot.call_graph.conflicts) {
            begin();
            write_call_conflict(writer, record);
        }
        writer.u64(snapshot.call_graph.indirect_site_count);
        writer.u64(snapshot.call_graph.unresolved_site_count);
        writer.boolean(snapshot.call_graph.bounded);
        break;
    case packed_page_type_t::pointer_facts:
        writer.count(snapshot.rich_facts.data_candidates.size());
        for (const auto& record : snapshot.rich_facts.data_candidates) {
            begin(record.address);
            write_data_candidate(writer, record);
        }
        writer.count(snapshot.rich_facts.data_pointer_facts.size());
        for (const auto& record : snapshot.rich_facts.data_pointer_facts) {
            begin(record.slot);
            write_data_pointer(writer, record);
        }
        writer.count(snapshot.rich_facts.data_conflicts.size());
        for (const auto& record : snapshot.rich_facts.data_conflicts) {
            begin(record.address);
            write_data_conflict(writer, record);
        }
        break;
    case packed_page_type_t::type_references:
        writer.count(snapshot.rich_facts.type_references.size());
        for (const auto& record : snapshot.rich_facts.type_references) {
            begin(record.source);
            write_type_reference(writer, record);
        }
        break;
    case packed_page_type_t::metadata_conflicts:
        writer.count(snapshot.rich_facts.metadata_conflicts.size());
        for (const auto& record : snapshot.rich_facts.metadata_conflicts) {
            begin(record.address);
            write_metadata_conflict(writer, record);
        }
        break;
    case packed_page_type_t::symbol_type_candidates:
        writer.count(snapshot.rich_facts.type_candidates.size());
        for (const auto& record : snapshot.rich_facts.type_candidates) {
            begin(record.address);
            write_symbol_type_candidate(writer, record);
        }
        break;
    default:
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::invalid_argument,
                                  "packed baseline domain is unsupported"));
    }
    return writer.finish_stream();
}

struct staged_page_t {
    std::uint32_t ordinal_begin = 0;
    std::uint32_t record_count = 0;
    std::uint64_t address_value_min = 0;
    std::uint64_t address_value_max = 0;
    std::vector<std::uint8_t> payload;
};

using staged_page_emit_t = std::function<workspace_result_t<void>(
    const packed_record_page_prefix_t&, std::vector<std::uint8_t>)>;

class packed_domain_page_buffer_t final {
public:
    packed_domain_page_buffer_t(
        std::uint32_t page_size,
        staged_page_emit_t emit,
        const packed_publish_stop_predicate_t& stop_requested)
        : emit_(std::move(emit)), stop_requested_(stop_requested),
          content_capacity_(page_size - packed_page_header_size -
                            packed_record_page_prefix_size) {
        content_.reserve(content_capacity_);
    }

    workspace_result_t<void> append(const std::uint8_t* data,
                                    std::size_t size) {
        if (!data && size != 0)
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::invalid_argument,
                                      "packed page stream received a null byte range"));
        for (std::size_t offset = 0; offset < size;) {
            if (stop_requested_ && stop_requested_())
            {
                auto error = packed_baseline_error(
                    workspace_error_code_t::cancelled,
                    "packed page stream was cancelled");
                error.cancellation = true;
                return workspace_result_t<void>::failure(std::move(error));
            }
            if (content_.size() == content_capacity_) {
                auto flushed = flush();
                if (!flushed)
                    return flushed;
            }
            const auto count = (std::min)(
                size - offset, content_capacity_ - content_.size());
            content_.insert(content_.end(), data + offset,
                            data + offset + count);
            offset += count;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> begin_record(
        const std::optional<address_t>& address) {
        if (content_.size() == content_capacity_) {
            auto flushed = flush();
            if (!flushed)
                return flushed;
        }
        if (page_record_count_ == (std::numeric_limits<std::uint32_t>::max)() ||
            records_started_ == (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::range_overflow,
                                      "packed page record ordinal overflows"));
        }
        ++page_record_count_;
        ++records_started_;
        if (address) {
            if (!address_seen_) {
                address_min_ = address->value;
                address_max_ = address->value;
                address_seen_ = true;
            } else {
                address_min_ = (std::min)(address_min_, address->value);
                address_max_ = (std::max)(address_max_, address->value);
            }
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> finish() {
        if (!content_.empty())
            return flush();
        return workspace_result_t<void>::success();
    }

private:
    workspace_result_t<void> flush() {
        if (content_.empty())
            return workspace_result_t<void>::success();
        packed_record_page_prefix_t prefix;
        prefix.ordinal_begin = page_ordinal_begin_;
        prefix.record_count = page_record_count_;
        if (address_seen_) {
            prefix.address_value_min = address_min_;
            prefix.address_value_max = address_max_;
        }
        const auto encoded_prefix = prefix.encode();
        std::vector<std::uint8_t> payload;
        payload.reserve(encoded_prefix.size() + content_.size());
        payload.insert(payload.end(), encoded_prefix.begin(), encoded_prefix.end());
        payload.insert(payload.end(), content_.begin(), content_.end());
        auto emitted = emit_(prefix, std::move(payload));
        if (!emitted)
            return emitted;
        page_ordinal_begin_ = records_started_;
        page_record_count_ = 0;
        address_seen_ = false;
        address_min_ = 0;
        address_max_ = 0;
        content_.clear();
        return workspace_result_t<void>::success();
    }

    staged_page_emit_t emit_;
    const packed_publish_stop_predicate_t& stop_requested_;
    std::size_t content_capacity_ = 0;
    std::vector<std::uint8_t> content_;
    std::uint32_t page_ordinal_begin_ = 0;
    std::uint32_t page_record_count_ = 0;
    std::uint32_t records_started_ = 0;
    bool address_seen_ = false;
    std::uint64_t address_min_ = 0;
    std::uint64_t address_max_ = 0;
};

class packed_baseline_page_stream_t final {
public:
    packed_baseline_page_stream_t(
        packed_page_type_t domain,
        const packed_page_encode_options_t& options,
        std::uint32_t global_page_count,
        std::uint32_t& next_page_index,
        const packed_page_stream_sink_t& sink,
        const packed_publish_stop_predicate_t& stop_requested)
        : domain_(domain), options_(options),
          global_page_count_(global_page_count),
          next_page_index_(next_page_index), sink_(sink),
          stop_requested_(stop_requested),
          buffer_(options.page_size,
                  [this](const packed_record_page_prefix_t& prefix,
                         std::vector<std::uint8_t> payload) {
                      return emit_page(prefix, std::move(payload));
                  },
                  stop_requested) {
    }

    workspace_result_t<void> append(const std::uint8_t* data,
                                    std::size_t size) {
        return buffer_.append(data, size);
    }

    workspace_result_t<void> begin_record(
        const std::optional<address_t>& address) {
        return buffer_.begin_record(address);
    }

    workspace_result_t<void> finish() {
        return buffer_.finish();
    }

private:
    workspace_result_t<void> emit_page(
        const packed_record_page_prefix_t& prefix,
        std::vector<std::uint8_t> payload) {
        if (next_page_index_ >= global_page_count_)
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "packed page stream emitted too many pages"));
        packed_page_t page;
        page.header.generation = options_.generation;
        page.header.analysis_revision = options_.analysis_revision;
        page.header.overlay_revision = options_.overlay_revision;
        page.header.page_type = static_cast<std::uint32_t>(domain_);
        page.header.page_index = next_page_index_;
        page.header.page_count = global_page_count_;
        page.payload = std::move(payload);
        auto sealed = packed_page_codec_t::seal_page(page, stop_requested_);
        if (!sealed)
            return sealed;
        packed_page_row_t row;
        row.generation = page.header.generation;
        row.page_index = page.header.page_index;
        row.page_count = page.header.page_count;
        row.page_type = page.header.page_type;
        row.payload_length = page.header.payload_length;
        row.checksum = page.header.checksum;
        row.payload = std::move(page.payload);
        packed_page_index_row_t index;
        index.generation = row.generation;
        index.domain = static_cast<std::uint16_t>(domain_);
        index.ordinal_begin = prefix.ordinal_begin;
        index.count = prefix.record_count;
        index.page_index = row.page_index;
        index.address_value_min = prefix.address_value_min;
        index.address_value_max = prefix.address_value_max;
        auto accepted = sink_(std::move(row), std::move(index));
        if (!accepted)
            return accepted;
        ++next_page_index_;
        return workspace_result_t<void>::success();
    }

    packed_page_type_t domain_;
    packed_page_encode_options_t options_;
    std::uint32_t global_page_count_ = 0;
    std::uint32_t& next_page_index_;
    const packed_page_stream_sink_t& sink_;
    const packed_publish_stop_predicate_t& stop_requested_;
    packed_domain_page_buffer_t buffer_;
};

workspace_result_t<void> stage_managed_publication_domain(
    sqlite3* database,
    const analysis_snapshot_t& snapshot,
    const managed_artifact_publication_t& managed_publication,
    const workspace_database_options_t& options,
    const std::string& candidate_token,
    std::uint64_t prior_records,
    const cancellation_token_t& cancel,
    persistence_commit_metrics_t* commit_metrics) {
    if (options.packed_stream_page_size <
            packed_page_header_size + packed_record_page_prefix_size + 16U ||
        options.packed_stream_page_size >
            packed_page_header_size + packed_page_max_payload ||
        options.packed_generation_quota_bytes == 0 ||
        options.packed_generation_quota_bytes >
            packed_generation_max_payload_bytes) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::invalid_argument,
                                  "managed packed stream options are invalid"));
    }
    const std::uint64_t content_capacity =
        options.packed_stream_page_size - packed_page_header_size -
        packed_record_page_prefix_size;
    packed_payload_writer_t measurement_writer(
        cancel,
        [](const std::uint8_t*, std::size_t) {
            return workspace_result_t<void>::success();
        }, {}, managed_publication_max_payload_bytes);
    auto measured = write_managed_publication_domain_stream(
        managed_publication, measurement_writer, cancel);
    if (!measured)
        return measured;
    const auto domain_bytes = measurement_writer.size();
    const auto domain_records = measurement_writer.record_count();
    const std::uint64_t pages = domain_bytes == 0 ? 1ULL :
        1ULL + (domain_bytes - 1ULL) / content_capacity;
    std::uint64_t total_payload_bytes = 0;
    if (pages == 0 || pages > packed_generation_max_pages ||
        !checked_mul_u64(pages, packed_record_page_prefix_size,
                         total_payload_bytes) ||
        !checked_add_u64(total_payload_bytes, domain_bytes,
                         total_payload_bytes) ||
        total_payload_bytes > options.packed_generation_quota_bytes ||
        prior_records > options.max_persisted_fact_records ||
        domain_records > options.max_persisted_fact_records - prior_records) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication exceeds its packed staging budget"));
    }
    auto manifest = encode_packed_baseline_manifest(
        snapshot, candidate_token, cancel);
    if (!manifest)
        return workspace_result_t<void>::failure(manifest.error());
    packed_generation_stream_descriptor_t descriptor;
    descriptor.generation.generation = snapshot.generation;
    descriptor.generation.analysis_revision = snapshot.analysis_revision;
    descriptor.generation.overlay_revision = snapshot.overlay_revision;
    descriptor.generation.shard_count = 1;
    descriptor.generation.total_payload_bytes = total_payload_bytes;
    descriptor.generation.total_records = domain_records;
    descriptor.generation.created_utc_ms = utc_ms();
    descriptor.generation.payload_blob = manifest.take_value();
    descriptor.page_count = static_cast<std::uint32_t>(pages);
    descriptor.payload_quota_bytes = options.packed_generation_quota_bytes;
    packed_page_encode_options_t page_options;
    page_options.page_size = options.packed_stream_page_size;
    page_options.generation = snapshot.generation;
    page_options.analysis_revision = snapshot.analysis_revision;
    page_options.overlay_revision = snapshot.overlay_revision;
    const auto started = std::chrono::steady_clock::now();
    const packed_page_stream_producer_t producer =
        [&](const packed_page_stream_sink_t& sink,
            const packed_publish_stop_predicate_t& stop_requested)
            -> workspace_result_t<void> {
        std::uint32_t next_page_index = 0;
        packed_baseline_page_stream_t pages_stream(
            packed_page_type_t::managed_publication, page_options,
            descriptor.page_count, next_page_index, sink, stop_requested);
        packed_payload_writer_t writer(
            cancel,
            [&](const std::uint8_t* data, std::size_t size) {
                return pages_stream.append(data, size);
            },
            [&](const std::optional<address_t>& address) {
                return pages_stream.begin_record(address);
            }, managed_publication_max_payload_bytes);
        auto written = write_managed_publication_domain_stream(
            managed_publication, writer, cancel);
        if (!written)
            return written;
        if (writer.size() != domain_bytes ||
            writer.record_count() != domain_records) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "managed publication changed during staging"));
        }
        auto finished = pages_stream.finish();
        if (!finished)
            return finished;
        if (next_page_index != descriptor.page_count) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "managed publication page count changed during staging"));
        }
        return workspace_result_t<void>::success();
    };
    auto staged = stage_packed_generation_stream_atomic(
        database, descriptor, candidate_token, producer,
        [&cancel] { return cancel.stop_requested(); });
    if (!staged)
        return staged;
    if (commit_metrics) {
        std::uint64_t updated_bytes = 0;
        std::uint64_t updated_rows = 0;
        if (!checked_add_u64(commit_metrics->logical_bytes,
                             descriptor.generation.total_payload_bytes +
                                 descriptor.generation.payload_blob.size(),
                             updated_bytes) ||
            !checked_add_u64(commit_metrics->rows,
                             static_cast<std::uint64_t>(descriptor.page_count) * 2ULL + 1ULL,
                             updated_rows)) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::range_overflow,
                                      "managed persistence metrics overflowed"));
        }
        commit_metrics->logical_bytes = updated_bytes;
        commit_metrics->rows = updated_rows;
        commit_metrics->elapsed_us += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
    }
    return workspace_result_t<void>::success();
}

constexpr std::uint32_t kBaselineStagedDomainMask = 0x7DFFEU;
constexpr std::uint32_t kSearchIndexDomainMask = 1U << 13U;
constexpr std::uint32_t kManagedPublicationDomainMask = 1U << 19U;
constexpr std::uint32_t kAllStagingDomainBits = 0xFFFFEU;
constexpr std::uint64_t kStagingSpillChunkWalBytes = 64ULL << 20;
constexpr std::size_t kFinalizeSealRingCapacity = 256;
constexpr std::uint32_t kFinalizeChunkMaxPages = 256;
constexpr std::uint64_t kFinalizeChunkMaxWalBytes = 64ULL << 20;
constexpr std::uint32_t kFinalizeMaxRetries = 3;
constexpr std::uint64_t kFinalizeManifestWireFixedBytes = 109;
constexpr std::uint32_t kReopenParallelMinPages = 64;
constexpr std::uint64_t kReopenStrideMinRecords = 1ULL << 16;
constexpr std::uint64_t kReopenStrideLaneRecords = 1ULL << 15;
constexpr std::uint64_t kPackedInstructionRecordBytes = 58;
constexpr std::uint64_t kPackedOperandRecordBytes = 85;
constexpr std::uint64_t kPackedTargetRecordBytes = 49;
constexpr std::uint64_t kPackedEdgeRecordMinBytes = 52;
constexpr std::uint64_t kPackedEdgeRecordMaxBytes = 60;
constexpr std::uint64_t kPackedXrefRecordBytes = 43;
constexpr std::uint64_t kPackedAddressExpressionRecordBytes = 12;
constexpr std::uint64_t kPackedBasicBlockRecordBytes = 58;
constexpr std::uint64_t kPackedFunctionRecordMinBytes = 77;
constexpr std::uint64_t kPackedFunctionChunkRecordBytes = 60;
constexpr std::uint64_t kPackedFunctionMembershipRecordBytes = 33;
constexpr std::uint64_t kPackedCoverageRecordBytes = 31;
constexpr std::uint64_t kManagedDomainWireFixedBytes = 244;
constexpr std::uint64_t kManagedArtifactWireBytes = 73;
constexpr std::uint64_t kManagedMethodWireBytes = 33;
constexpr std::uint64_t kManagedEntityKeyWireFixedBytes = 29;
constexpr std::uint64_t kManagedNativeIdentityWireBytes = 56;
constexpr std::uint64_t kManagedCliIdentityWireBytes = 40;
constexpr std::uint64_t kManagedJvmIdentityWireBytes = 40;
constexpr std::uint64_t kManagedDalvikIdentityWireBytes = 44;
constexpr std::uint64_t kPackedStringLengthPrefixBytes = 8;

}

struct workspace_snapshot_staging_t::state_t {
    struct domain_state_t {
        mutable std::mutex mutex;
        std::deque<staged_page_t> pages;
        std::uint64_t resident_bytes = 0;
        std::uint64_t spilled_pages = 0;
        std::uint64_t records = 0;
        std::uint64_t payload_bytes = 0;
        std::uint64_t serialize_us = 0;
        bool complete = false;
    };

    ~state_t() {
        release_resident_accounting();
    }

    void release_resident_accounting() noexcept {
        const auto locked = conn.lock();
        if (!locked)
            return;
        std::uint64_t resident = 0;
        for (auto& domain : domains) {
            std::lock_guard<std::mutex> lock(domain.mutex);
            resident += domain.resident_bytes;
            domain.resident_bytes = 0;
        }
        if (resident == 0)
            return;
        std::uint64_t current =
            locked->staging_resident_bytes.load(std::memory_order_relaxed);
        for (;;) {
            const std::uint64_t next = current > resident ? current - resident : 0;
            if (locked->staging_resident_bytes.compare_exchange_weak(
                    current, next, std::memory_order_release,
                    std::memory_order_relaxed))
                return;
        }
    }

    void record_failure(workspace_error_t error) {
        {
            std::lock_guard<std::mutex> lock(failure_mutex);
            if (!failure)
                failure = std::move(error);
        }
        failed.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(spill_mutex);
            spill_requested = true;
        }
        spill_cv.notify_all();
    }

    workspace_error_t current_failure() {
        std::lock_guard<std::mutex> lock(failure_mutex);
        if (failure)
            return *failure;
        return packed_baseline_error(
            workspace_error_code_t::persistence_failure,
            "snapshot staging failed without a recorded error");
    }

    std::string token;
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    bool baseline_complete = false;
    std::shared_ptr<const analysis_snapshot_t> snapshot;
    std::string settings_json;
    std::string metrics_json;
    std::shared_ptr<const workspace_persistence_candidate_t> candidate;
    std::weak_ptr<workspace_database_t::connection_state_t> conn;
    std::array<domain_state_t, 20> domains{};
    std::atomic<std::uint32_t> staged_mask{0};
    std::atomic<bool> failed{false};
    std::atomic<bool> finalized{false};
    mutable std::mutex failure_mutex;
    std::optional<workspace_error_t> failure;
    std::mutex spill_mutex;
    std::condition_variable spill_cv;
    bool spill_requested = false;
};

namespace {

workspace_result_t<void> bind_committed_page_source(
    sqlite3* database,
    workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    const packed_generation_record_t& generation_record,
    const cancellation_token_t& cancel);

workspace_result_t<void> spill_staging_domain(
    sqlite3* database,
    workspace_database_t::connection_state_t& conn,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    std::size_t domain_index,
    const cancellation_token_t& cancel) {
    auto& domain_state = staging->domains[domain_index];
    std::deque<staged_page_t> pages;
    std::uint64_t first_page_index = 0;
    std::uint64_t resident_bytes = 0;
    {
        std::lock_guard<std::mutex> lock(domain_state.mutex);
        if (domain_state.pages.empty())
            return workspace_result_t<void>::success();
        pages = std::move(domain_state.pages);
        domain_state.pages.clear();
        resident_bytes = domain_state.resident_bytes;
        first_page_index = domain_state.spilled_pages;
        domain_state.spilled_pages += pages.size();
        domain_state.resident_bytes = 0;
    }
    conn.staging_resident_bytes.fetch_sub(resident_bytes, std::memory_order_acq_rel);
    auto result = set_writer_synchronous(database, 1, "workspace_database.staging.spill");
    if (!result)
        return result;
    std::uint64_t next_page_index = first_page_index;
    std::size_t position = 0;
    while (result && position < pages.size()) {
        if (cancel.stop_requested())
            result = workspace_result_t<void>::failure(
                packed_baseline_cancelled(cancel));
        if (!result)
            break;
        auto begun = begin_immediate(database, "workspace_database.staging.spill");
        if (!begun) {
            result = begun;
            break;
        }
        std::uint64_t chunk_bytes = 0;
        while (result && position < pages.size()) {
            const auto& page = pages[position];
            const auto page_bytes = static_cast<std::uint64_t>(page.payload.size());
            if (chunk_bytes != 0 && chunk_bytes + page_bytes > kStagingSpillChunkWalBytes)
                break;
            packed_generation_staging_row_t row;
            row.generation = staging->generation;
            row.domain = static_cast<std::uint16_t>(domain_index);
            row.domain_page_index = static_cast<std::uint32_t>(next_page_index);
            row.ordinal_begin = page.ordinal_begin;
            row.record_count = page.record_count;
            row.address_value_min = page.address_value_min;
            row.address_value_max = page.address_value_max;
            row.payload = page.payload;
            result = write_packed_generation_staging_page(database, row);
            if (!result)
                break;
            ++next_page_index;
            ++position;
            chunk_bytes += page_bytes;
        }
        if (result) {
            auto committed = commit(database, "workspace_database.staging.spill");
            if (!committed) {
                rollback(database, "workspace_database.staging.spill");
                result = committed;
            }
        } else {
            rollback(database, "workspace_database.staging.spill");
        }
    }
    auto restored = set_writer_synchronous(database, 2, "workspace_database.staging.spill");
    if (!result)
        return result;
    if (!restored)
        return restored;
    return workspace_result_t<void>::success();
}

workspace_result_t<void> service_staging_spill(
    sqlite3* database,
    workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    const cancellation_token_t& cancel) {
    const std::uint64_t budget = options.packed_staging_memory_budget_bytes;
    for (;;) {
        {
            std::lock_guard<std::mutex> spill_lock(staging->spill_mutex);
            if (!staging->spill_requested &&
                conn.staging_resident_bytes.load(std::memory_order_acquire) <= budget)
                return workspace_result_t<void>::success();
            staging->spill_requested = false;
        }
        std::size_t victim = (std::numeric_limits<std::size_t>::max)();
        std::uint64_t victim_bytes = 0;
        for (std::size_t index = 1; index < staging->domains.size(); ++index) {
            auto& domain_state = staging->domains[index];
            std::lock_guard<std::mutex> lock(domain_state.mutex);
            if (!domain_state.pages.empty() && domain_state.resident_bytes > victim_bytes) {
                victim = index;
                victim_bytes = domain_state.resident_bytes;
            }
        }
        if (victim == (std::numeric_limits<std::size_t>::max)())
            return workspace_result_t<void>::success();
        auto spilled = spill_staging_domain(database, conn, staging, victim, cancel);
        if (!spilled) {
            staging->record_failure(spilled.error());
            return spilled;
        }
        staging->spill_cv.notify_all();
        if (conn.staging_resident_bytes.load(std::memory_order_acquire) <= budget)
            return workspace_result_t<void>::success();
    }
}

workspace_result_t<void> serialize_staging_domain(
    workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    packed_page_type_t domain,
    const persisted_search_products_t* search_products,
    const std::shared_ptr<const managed_artifact_publication_t>& managed_publication,
    const cancellation_token_t& cancel) {
    const auto encoded = static_cast<std::uint32_t>(domain);
    if (encoded < static_cast<std::uint32_t>(packed_page_type_t::instructions) ||
        encoded > static_cast<std::uint32_t>(packed_page_last_data_type) ||
        !staging->snapshot) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::invalid_argument,
                                  "snapshot staging domain is unsupported"));
    }
    auto& domain_state = staging->domains[encoded];
    {
        std::lock_guard<std::mutex> lock(domain_state.mutex);
        if (domain_state.complete) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "snapshot staging domain was serialized twice"));
        }
    }
    const auto started = std::chrono::steady_clock::now();
    const std::uint64_t budget = options.packed_staging_memory_budget_bytes;
    const packed_publish_stop_predicate_t stop_predicate = [&cancel] {
        return cancel.stop_requested();
    };
    const auto prestaged_domain = [](packed_page_type_t page_domain)
        -> std::optional<fact_domain_t> {
        switch (page_domain) {
        case packed_page_type_t::instructions:
            return fact_domain_t::instructions;
        case packed_page_type_t::operands:
            return fact_domain_t::operand_facts;
        case packed_page_type_t::target_facts:
            return fact_domain_t::target_facts;
        default:
            return std::nullopt;
        }
    }(domain);
    if (prestaged_domain && staging->snapshot->paged_staging &&
        staging->snapshot->paged_domain_counts[static_cast<std::size_t>(
            *prestaged_domain)] != 0) {
        const auto fact_domain = *prestaged_domain;
        auto source = staging->snapshot->paged_staging;
        auto contiguous = source->validate_contiguous(fact_domain);
        if (!contiguous)
            return contiguous;
        auto copied = source->for_each_page(fact_domain,
            [&conn, staging, &domain_state, budget, &cancel](
                const paged_fact_page_meta_t& meta,
                const std::vector<std::uint8_t>& payload)
                -> workspace_result_t<void> {
                staged_page_t page;
                page.ordinal_begin =
                    static_cast<std::uint32_t>(meta.ordinal_begin);
                page.record_count = meta.record_count;
                page.address_value_min = meta.address_value_min;
                page.address_value_max = meta.address_value_max;
                const auto page_bytes =
                    static_cast<std::uint64_t>(payload.size());
                page.payload = payload;
                {
                    std::lock_guard<std::mutex> lock(domain_state.mutex);
                    domain_state.pages.push_back(std::move(page));
                    domain_state.resident_bytes += page_bytes;
                    domain_state.records += meta.record_count;
                    domain_state.payload_bytes += page_bytes;
                }
                conn.staging_resident_bytes.fetch_add(page_bytes,
                                                    std::memory_order_acq_rel);
                std::unique_lock<std::mutex> spill_lock(staging->spill_mutex);
                while (!staging->failed.load(std::memory_order_acquire) &&
                       conn.staging_resident_bytes.load(std::memory_order_acquire) >
                           budget &&
                       !cancel.stop_requested()) {
                    staging->spill_requested = true;
                    staging->spill_cv.wait_for(spill_lock,
                                               std::chrono::milliseconds(10));
                }
                if (staging->failed.load(std::memory_order_acquire))
                    return workspace_result_t<void>::failure(
                        staging->current_failure());
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        packed_baseline_cancelled(cancel));
                return workspace_result_t<void>::success();
            }, cancel);
        if (!copied)
            return copied;
        const auto elapsed = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
        std::lock_guard<std::mutex> lock(domain_state.mutex);
        domain_state.serialize_us = elapsed;
        domain_state.complete = true;
        return workspace_result_t<void>::success();
    }
    packed_domain_page_buffer_t buffer(
        options.packed_stream_page_size,
        [&conn, staging, &domain_state, budget, &cancel](
            const packed_record_page_prefix_t& prefix, std::vector<std::uint8_t> payload)
            -> workspace_result_t<void> {
            staged_page_t page;
            page.ordinal_begin = prefix.ordinal_begin;
            page.record_count = prefix.record_count;
            page.address_value_min = prefix.address_value_min;
            page.address_value_max = prefix.address_value_max;
            const auto page_bytes = static_cast<std::uint64_t>(payload.size());
            page.payload = std::move(payload);
            {
                std::lock_guard<std::mutex> lock(domain_state.mutex);
                domain_state.pages.push_back(std::move(page));
                domain_state.resident_bytes += page_bytes;
                domain_state.records += prefix.record_count;
                domain_state.payload_bytes += page_bytes;
            }
            conn.staging_resident_bytes.fetch_add(page_bytes, std::memory_order_acq_rel);
            std::unique_lock<std::mutex> spill_lock(staging->spill_mutex);
            while (!staging->failed.load(std::memory_order_acquire) &&
                   conn.staging_resident_bytes.load(std::memory_order_acquire) > budget &&
                   !cancel.stop_requested()) {
                staging->spill_requested = true;
                staging->spill_cv.wait_for(spill_lock, std::chrono::milliseconds(10));
            }
            if (staging->failed.load(std::memory_order_acquire))
                return workspace_result_t<void>::failure(staging->current_failure());
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    packed_baseline_cancelled(cancel));
            return workspace_result_t<void>::success();
        },
        stop_predicate);
    packed_payload_writer_t writer(
        cancel,
        [&buffer](const std::uint8_t* data, std::size_t size) {
            return buffer.append(data, size);
        },
        [&buffer](const std::optional<address_t>& address) {
            return buffer.begin_record(address);
        },
        domain == packed_page_type_t::managed_publication
            ? managed_publication_max_payload_bytes
            : options.packed_generation_quota_bytes);
    workspace_result_t<void> written = workspace_result_t<void>::success();
    if (domain == packed_page_type_t::managed_publication) {
        if (!managed_publication) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::invalid_argument,
                                      "managed publication staging requires its publication"));
        }
        written = write_managed_publication_domain_stream(
            *managed_publication, writer, cancel);
    } else {
        written = write_packed_baseline_domain_stream(
            domain, *staging->snapshot, *search_products, writer, cancel);
    }
    if (!written)
        return written;
    auto finished = buffer.finish();
    if (!finished)
        return finished;
    const auto elapsed = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started).count());
    std::lock_guard<std::mutex> lock(domain_state.mutex);
    domain_state.serialize_us = elapsed;
    domain_state.complete = true;
    return workspace_result_t<void>::success();
}

void release_handed_off_paged_domains(
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging) noexcept {
    if (!staging->snapshot || !staging->snapshot->paged_staging)
        return;
    for (std::size_t index = 0; index < fact_domain_count; ++index) {
        if (staging->snapshot->paged_domain_counts[index] == 0)
            continue;
        staging->snapshot->paged_staging->release(
            static_cast<fact_domain_t>(index));
    }
}

workspace_result_t<void> run_staging_serialization(
    sqlite3* database,
    workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    std::uint32_t domain_mask,
    const persisted_search_products_t* search_products,
    const std::shared_ptr<const managed_artifact_publication_t>& managed_publication,
    const cancellation_token_t& cancel) {
    if (domain_mask == 0 || (domain_mask & ~kAllStagingDomainBits) != 0) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::invalid_argument,
                                  "snapshot staging domain mask is invalid"));
    }
    persisted_search_products_t empty_products;
    if (!search_products)
        search_products = &empty_products;
    aida::infra::taskflow_runtime::graph_descriptor_t graph;
    graph.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    graph.owner_subsystem = "analysis_persistence";
    graph.label = "analysis.persistence.stage_domains";
    graph.phase = "persistence";
    graph.priority = 2;
    std::uint64_t node_id = 0;
    for (std::uint32_t encoded = 1;
         encoded <= static_cast<std::uint32_t>(packed_page_last_data_type);
         ++encoded) {
        const std::uint32_t bit = 1U << encoded;
        if ((domain_mask & bit) == 0)
            continue;
        const auto domain = static_cast<packed_page_type_t>(encoded);
        aida::infra::taskflow_runtime::graph_node_descriptor_t node;
        node.node_id = ++node_id;
        node.label = "analysis.persistence.stage_domain";
        node.cancellable_body = [&conn, &options, staging, domain, search_products,
                                 &managed_publication, &cancel](
            const aida::infra::taskflow_runtime::cancellation_token_t&) {
            if (staging->failed.load(std::memory_order_acquire))
                return;
            auto result = serialize_staging_domain(
                conn, options, staging, domain, search_products,
                managed_publication, cancel);
            if (!result)
                staging->record_failure(result.error());
        };
        graph.nodes.push_back(std::move(node));
    }
    auto submission = aida::infra::taskflow_runtime::submit_graph(std::move(graph));
    if (!submission.submitted) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(
                workspace_error_code_t::persistence_failure,
                std::string("snapshot staging dispatch was rejected: ") +
                    submission.reject_reason));
    }
    for (;;) {
        const auto waited = aida::infra::taskflow_runtime::wait_for(
            submission.handle, 25);
        if (waited.completed)
            break;
        if (cancel.stop_requested())
            aida::infra::taskflow_runtime::cancel(submission.handle);
        auto serviced = service_staging_spill(database, conn, options, staging, cancel);
        if (!serviced)
            return serviced;
    }
    auto serviced = service_staging_spill(database, conn, options, staging, cancel);
    if (!serviced)
        return serviced;
    if (staging->failed.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(staging->current_failure());
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(packed_baseline_cancelled(cancel));
    staging->staged_mask.fetch_or(domain_mask, std::memory_order_acq_rel);
    return workspace_result_t<void>::success();
}

struct finalize_seal_job_t {
    std::uint32_t page_index = 0;
    std::uint32_t page_type = 0;
    staged_page_t page;
};

struct finalize_sealed_page_t {
    packed_page_row_t row;
    packed_page_index_row_t index;
};

template <typename Item>
class bounded_seal_ring_t final {
public:
    bounded_seal_ring_t(std::size_t capacity,
                        std::atomic<std::uint64_t>* occupancy_gauge,
                        std::uint64_t (*item_bytes)(const Item&) noexcept)
        : capacity_(capacity), occupancy_gauge_(occupancy_gauge),
          item_bytes_(item_bytes) {}

    ~bounded_seal_ring_t() { release_occupancy(); }

    bounded_seal_ring_t(const bounded_seal_ring_t&) = delete;
    bounded_seal_ring_t& operator=(const bounded_seal_ring_t&) = delete;

    bool push(Item item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [&] { return items_.size() < capacity_ || closed_; });
        if (closed_)
            return false;
        const std::uint64_t bytes = item_bytes_(item);
        if (occupancy_gauge_ && bytes != 0)
            occupancy_gauge_->fetch_add(bytes, std::memory_order_acq_rel);
        items_.push_back(std::move(item));
        not_empty_.notify_one();
        return true;
    }

    bool pop(Item& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [&] { return !items_.empty() || closed_; });
        if (items_.empty())
            return false;
        item = std::move(items_.front());
        items_.pop_front();
        const std::uint64_t bytes = item_bytes_(item);
        if (occupancy_gauge_ && bytes != 0)
            occupancy_gauge_->fetch_sub(bytes, std::memory_order_acq_rel);
        not_full_.notify_one();
        return true;
    }

    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        not_full_.notify_all();
        not_empty_.notify_all();
    }

private:
    void release_occupancy() noexcept {
        if (!occupancy_gauge_)
            return;
        std::uint64_t bytes = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& item : items_)
                bytes += item_bytes_(item);
            items_.clear();
        }
        if (bytes != 0)
            occupancy_gauge_->fetch_sub(bytes, std::memory_order_acq_rel);
    }

    std::mutex mutex_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
    std::deque<Item> items_;
    std::size_t capacity_ = 0;
    std::atomic<std::uint64_t>* occupancy_gauge_ = nullptr;
    std::uint64_t (*item_bytes_)(const Item&) noexcept = nullptr;
    bool closed_ = false;
};

std::uint64_t estimate_managed_publication_wire_bytes(
    const managed_artifact_publication_t& publication) noexcept {
    std::uint64_t total = kManagedDomainWireFixedBytes;
    const auto add = [&total](std::uint64_t value) {
        if (!checked_add_u64(total, value, total))
            total = (std::numeric_limits<std::uint64_t>::max)();
    };
    add(kPackedStringLengthPrefixBytes +
        static_cast<std::uint64_t>(publication.provider_source.size()));
    for (const auto& artifact : publication.artifacts()) {
        add(kManagedArtifactWireBytes + 3U * kPackedStringLengthPrefixBytes);
        add(static_cast<std::uint64_t>(artifact.assembly_identity.size()));
        add(static_cast<std::uint64_t>(artifact.module_name.size()));
        add(static_cast<std::uint64_t>(artifact.version.size()));
    }
    for (const auto& method : publication.methods()) {
        add(kManagedMethodWireBytes + kManagedEntityKeyWireFixedBytes);
        std::visit([&add](const auto& identity) {
            using identity_t = std::decay_t<decltype(identity)>;
            if constexpr (std::is_same_v<identity_t,
                                         native_decompiler_entity_identity_t>) {
                add(kManagedNativeIdentityWireBytes + kPackedStringLengthPrefixBytes);
                add(static_cast<std::uint64_t>(identity.canonical_symbol.size()));
            } else if constexpr (std::is_same_v<identity_t,
                                                cli_decompiler_entity_identity_t>) {
                add(kManagedCliIdentityWireBytes + 5U * kPackedStringLengthPrefixBytes);
                add(static_cast<std::uint64_t>(identity.assembly_identity.size()));
                add(static_cast<std::uint64_t>(identity.module_name.size()));
                add(static_cast<std::uint64_t>(identity.declaring_type.size()));
                add(static_cast<std::uint64_t>(identity.method_name.size()));
                add(static_cast<std::uint64_t>(identity.method_signature.size()));
            } else if constexpr (std::is_same_v<identity_t,
                                                jvm_decompiler_entity_identity_t>) {
                add(kManagedJvmIdentityWireBytes + 3U * kPackedStringLengthPrefixBytes);
                add(static_cast<std::uint64_t>(identity.class_internal_name.size()));
                add(static_cast<std::uint64_t>(identity.method_name.size()));
                add(static_cast<std::uint64_t>(identity.method_descriptor.size()));
            } else {
                add(kManagedDalvikIdentityWireBytes + 3U * kPackedStringLengthPrefixBytes);
                add(static_cast<std::uint64_t>(identity.class_descriptor.size()));
                add(static_cast<std::uint64_t>(identity.method_name.size()));
                add(static_cast<std::uint64_t>(identity.prototype.size()));
            }
        }, method.entity.identity);
    }
    return total;
}

struct staging_finalize_totals_t {
    std::uint32_t page_count = 0;
    std::uint32_t shard_count = 0;
    std::uint64_t total_payload_bytes = 0;
    std::uint64_t total_records = 0;
};

workspace_result_t<void> run_staging_finalize(
    sqlite3* database,
    workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    const persisted_search_products_t& search_products,
    const std::shared_ptr<const managed_artifact_publication_t>& managed_publication,
    persistence_commit_metrics_t* commit_metrics,
    const cancellation_token_t& cancel) {
    constexpr std::size_t json_limit = 16U << 20;
    const auto finalize_started = std::chrono::steady_clock::now();
    if (staging->failed.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(staging->current_failure());
    if (staging->finalized.load(std::memory_order_acquire)) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::revision_conflict,
                                  "snapshot staging is already finalized"));
    }
    if (!staging->snapshot || !valid_candidate_token(staging->token) ||
        staging->settings_json.size() > json_limit ||
        staging->metrics_json.size() > json_limit ||
        nlohmann::json::parse(staging->settings_json, nullptr, false).is_discarded() ||
        nlohmann::json::parse(staging->metrics_json, nullptr, false).is_discarded()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "complete packed snapshot input is invalid",
                                 "workspace_database.persist.packed"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(packed_baseline_cancelled(cancel));
    if (staging->baseline_complete) {
        if (search_products.generation != staging->generation ||
            search_products.analysis_revision != staging->analysis_revision ||
            search_products.overlay_revision != staging->overlay_revision) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                                     "search products do not match the snapshot revisions",
                                     "workspace_database.persist"));
        }
        if (!search_products.live_index ||
            !search_products.live_index->matches(staging->snapshot) ||
            !search_products.data_candidates.empty() ||
            !search_products.switches.empty() ||
            !search_products.types.empty() ||
            search_products.search_index_blob_version != 0 ||
            !search_products.search_index_blob.empty()) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "snapshot persistence received an ambiguous or mismatched live search index",
                    "workspace_database.persist"));
        }
    } else if (search_products.generation != 0 ||
               search_products.analysis_revision != 0 ||
               search_products.overlay_revision != 0 ||
               search_products.live_index ||
               !search_products.data_candidates.empty() ||
               !search_products.switches.empty() ||
               !search_products.types.empty() ||
               search_products.search_index_blob_version != 0 ||
               !search_products.search_index_blob.empty()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "search products require a complete baseline snapshot",
                                 "workspace_database.persist"));
    }
    if (managed_publication &&
        (managed_publication->generation != staging->generation ||
         managed_publication->analysis_revision != staging->analysis_revision ||
         managed_publication->overlay_revision != staging->overlay_revision ||
         managed_publication->binary_id != staging->snapshot->binary_id ||
         managed_publication->load_profile_hash !=
             staging->snapshot->load_profile_hash ||
         !staging->snapshot->normalized_image ||
         managed_publication->provider_hash !=
             staging->snapshot->normalized_image->provider_content_hash ||
         managed_publication->provider_source !=
             staging->snapshot->normalized_image->provider_source ||
         managed_publication->provider_size !=
             staging->snapshot->normalized_image->provider_size)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "managed publication does not match snapshot generation and identity",
                                 "workspace_database.persist"));
    }
    auto commit_state = read_commit_state(
        database, "workspace_database.persist.packed");
    if (!commit_state)
        return workspace_result_t<void>::failure(commit_state.error());
    if (commit_state.value().candidate_ready ||
        commit_state.value().committed_generation > staging->generation ||
        (commit_state.value().committed_generation == staging->generation &&
         commit_state.value().committed_analysis_revision >
             staging->analysis_revision)) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "packed snapshot conflicts with current persistence state",
                                 "workspace_database.persist.packed"));
    }
    std::uint32_t g8_mask = 0;
    if (staging->baseline_complete &&
        (staging->staged_mask.load(std::memory_order_acquire) &
         kSearchIndexDomainMask) == 0)
        g8_mask |= kSearchIndexDomainMask;
    if (managed_publication &&
        (staging->staged_mask.load(std::memory_order_acquire) &
         kManagedPublicationDomainMask) == 0)
        g8_mask |= kManagedPublicationDomainMask;
    if (g8_mask != 0) {
        auto staged_g8 = run_staging_serialization(
            database, conn, options, staging, g8_mask, &search_products,
            managed_publication, cancel);
        if (!staged_g8)
            return staged_g8;
    }
    const std::uint32_t staged_mask =
        staging->staged_mask.load(std::memory_order_acquire);
    const std::uint32_t required_mask = staging->baseline_complete
        ? kPackedBaselineRequiredDomains : 0U;
    if ((staged_mask & required_mask) != required_mask ||
        (managed_publication &&
         (staged_mask & kManagedPublicationDomainMask) == 0) ||
        (!staging->baseline_complete && !managed_publication)) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "snapshot staging completed with an incomplete domain set"));
    }
    staging_finalize_totals_t totals;
    std::uint64_t serialize_us = 0;
    for (std::uint32_t encoded = 1;
         encoded <= static_cast<std::uint32_t>(packed_page_last_data_type);
         ++encoded) {
        if ((staged_mask & (1U << encoded)) == 0)
            continue;
        auto& domain_state = staging->domains[encoded];
        std::lock_guard<std::mutex> lock(domain_state.mutex);
        const std::uint64_t pages =
            domain_state.spilled_pages + domain_state.pages.size();
        if (pages == 0 || pages > packed_generation_max_pages ||
            pages > (std::numeric_limits<std::uint32_t>::max)() ||
            domain_state.payload_bytes > packed_generation_max_payload_bytes) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "snapshot staging domain totals are inconsistent"));
        }
        std::uint64_t updated_payload = 0;
        std::uint64_t updated_records = 0;
        std::uint64_t updated_pages = 0;
        if (!checked_add_u64(totals.total_payload_bytes,
                             domain_state.payload_bytes, updated_payload) ||
            updated_payload > options.packed_generation_quota_bytes ||
            !checked_add_u64(totals.total_records, domain_state.records,
                             updated_records) ||
            updated_records > packed_generation_max_records ||
            !checked_add_u64(static_cast<std::uint64_t>(totals.page_count),
                             pages, updated_pages) ||
            updated_pages > packed_generation_max_pages) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                      "packed baseline stream exceeds its page, record, or byte quota"));
        }
        totals.total_payload_bytes = updated_payload;
        totals.total_records = updated_records;
        totals.page_count = static_cast<std::uint32_t>(updated_pages);
        ++totals.shard_count;
        serialize_us += domain_state.serialize_us;
    }
    if (totals.page_count == 0 || totals.shard_count == 0) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "snapshot staging produced no pages"));
    }
    if (totals.total_records > options.max_persisted_fact_records) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "packed baseline exceeds the persisted fact-record budget"));
    }
    auto manifest = encode_packed_baseline_manifest(
        *staging->snapshot, staging->token, cancel);
    if (!manifest)
        return workspace_result_t<void>::failure(manifest.error());
    packed_generation_record_t generation_record;
    generation_record.generation = staging->generation;
    generation_record.analysis_revision = staging->analysis_revision;
    generation_record.overlay_revision = staging->overlay_revision;
    generation_record.shard_count = static_cast<std::uint16_t>(totals.shard_count);
    generation_record.total_payload_bytes = totals.total_payload_bytes;
    generation_record.total_records = totals.total_records;
    generation_record.batch_checksum = 0;
    generation_record.created_utc_ms = utc_ms();
    generation_record.committed = false;
    generation_record.payload_blob = manifest.take_value();
    std::vector<std::uint8_t> checksum_bytes(
        static_cast<std::size_t>(totals.page_count) * 4U, 0);
    bool pages_already_staged = false;
    std::uint64_t sealed_stored_bytes = 0;
    std::uint64_t sealed_pages_v3 = 0;
    {
        auto existing = read_packed_generation(
            database, staging->generation, false,
            [&cancel] { return cancel.stop_requested(); });
        if (!existing)
            return workspace_result_t<void>::failure(existing.error());
        if (existing.value()) {
            if (existing.value()->committed ||
                existing.value()->analysis_revision != staging->analysis_revision ||
                existing.value()->overlay_revision != staging->overlay_revision ||
                existing.value()->shard_count != generation_record.shard_count ||
                existing.value()->total_payload_bytes != totals.total_payload_bytes ||
                existing.value()->total_records != totals.total_records) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "existing staged packed generation is inconsistent with the finalized stream"));
            }
            statement_t checksums;
            auto prepared = checksums.prepare(database,
                "SELECT page_index,checksum FROM packed_pages WHERE generation=?1 ORDER BY page_index",
                "workspace_database.persist.packed");
            if (!prepared)
                return prepared;
            auto bound = checksums.bind_uint(1, staging->generation);
            if (!bound)
                return bound;
            std::uint32_t expected_index = 0;
            for (;;) {
                const int status = sqlite3_step(checksums.get());
                if (status == SQLITE_DONE)
                    break;
                if (status != SQLITE_ROW) {
                    return workspace_result_t<void>::failure(database_error(
                        database, status, "unable to re-read staged page checksums",
                        "workspace_database.persist.packed"));
                }
                const auto page_index = static_cast<std::uint32_t>(
                    sqlite3_column_int64(checksums.get(), 0));
                const auto page_checksum = static_cast<std::uint32_t>(
                    sqlite3_column_int64(checksums.get(), 1));
                if (page_index != expected_index ||
                    expected_index >= totals.page_count) {
                    return workspace_result_t<void>::failure(
                        packed_baseline_error(
                            workspace_error_code_t::integrity_failure,
                            "existing staged packed pages are not contiguous"));
                }
                for (unsigned shift = 0; shift < 32; shift += 8) {
                    checksum_bytes[static_cast<std::size_t>(page_index) * 4U +
                                   shift / 8U] =
                        static_cast<std::uint8_t>(page_checksum >> shift);
                }
                ++expected_index;
            }
            if (expected_index != totals.page_count) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "existing staged packed generation has an inconsistent page count"));
            }
            {
                statement_t stored_totals;
                auto prepared_totals = stored_totals.prepare(database,
                    "SELECT COALESCE(SUM(payload_length),0),COALESCE(SUM(CASE WHEN logical_length IS NULL OR logical_length=0 THEN 0 ELSE 1 END),0) FROM packed_pages WHERE generation=?1",
                    "workspace_database.persist.packed");
                if (!prepared_totals)
                    return prepared_totals;
                auto bound_totals = stored_totals.bind_uint(1, staging->generation);
                if (!bound_totals)
                    return bound_totals;
                const int totals_status = sqlite3_step(stored_totals.get());
                if (totals_status != SQLITE_ROW) {
                    return workspace_result_t<void>::failure(database_error(
                        database, totals_status,
                        "unable to re-read staged page byte totals",
                        "workspace_database.persist.packed"));
                }
                const auto stored_bytes =
                    sqlite3_column_int64(stored_totals.get(), 0);
                const auto stored_v3 =
                    sqlite3_column_int64(stored_totals.get(), 1);
                if (stored_bytes < 0 || stored_v3 < 0) {
                    return workspace_result_t<void>::failure(
                        packed_baseline_error(
                            workspace_error_code_t::integrity_failure,
                            "existing staged packed generation byte totals are invalid"));
                }
                sealed_stored_bytes = static_cast<std::uint64_t>(stored_bytes);
                sealed_pages_v3 = static_cast<std::uint64_t>(stored_v3);
            }
            pages_already_staged = true;
        }
    }
    auto page_size = database_page_size(database);
    if (!page_size)
        return workspace_result_t<void>::failure(page_size.error());
    int writes_before = 0;
    int highwater = 0;
    int status = sqlite3_db_status(database, SQLITE_DBSTATUS_CACHE_WRITE,
                                   &writes_before, &highwater, 0);
    if (status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, status, "unable to read packed persistence write counter",
            "workspace_database.persist.packed"));
    }
    std::uint64_t db_write_us = 0;
    std::uint64_t seal_us = 0;
    if (!pages_already_staged) {
        bounded_seal_ring_t<finalize_seal_job_t> work_ring(
            kFinalizeSealRingCapacity, &conn.staging_resident_bytes,
            +[](const finalize_seal_job_t& job) noexcept {
                return static_cast<std::uint64_t>(job.page.payload.size());
            });
        bounded_seal_ring_t<finalize_sealed_page_t> sealed_ring(
            kFinalizeSealRingCapacity, &conn.staging_resident_bytes,
            +[](const finalize_sealed_page_t& item) noexcept {
                return static_cast<std::uint64_t>(item.row.payload.size());
            });
        const auto seal_started = std::chrono::steady_clock::now();
        aida::infra::taskflow_runtime::graph_descriptor_t graph;
        graph.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        graph.owner_subsystem = "analysis_persistence";
        graph.label = "analysis.persistence.finalize_seal";
        graph.phase = "persistence";
        graph.priority = 2;
        std::uint64_t node_id = 0;
        {
            aida::infra::taskflow_runtime::graph_node_descriptor_t feeder;
            feeder.node_id = ++node_id;
            feeder.label = "analysis.persistence.finalize_feed";
            feeder.cancellable_body = [&conn, &options, staging, staged_mask,
                                       &totals, &work_ring, &cancel](
                const aida::infra::taskflow_runtime::cancellation_token_t&) {
                std::uint32_t next_page_index = 0;
                sqlite3* staging_reader = nullptr;
                bool aborted = false;
                for (std::uint32_t encoded = 1;
                     encoded <= static_cast<std::uint32_t>(packed_page_last_data_type) &&
                     !aborted; ++encoded) {
                    if ((staged_mask & (1U << encoded)) == 0)
                        continue;
                    if (cancel.stop_requested() ||
                        staging->failed.load(std::memory_order_acquire))
                        break;
                    auto& domain_state = staging->domains[encoded];
                    std::uint64_t spilled_pages = 0;
                    std::uint64_t expected_pages = 0;
                    {
                        std::lock_guard<std::mutex> lock(domain_state.mutex);
                        spilled_pages = domain_state.spilled_pages;
                        expected_pages =
                            domain_state.spilled_pages + domain_state.pages.size();
                    }
                    const std::uint32_t domain_feed_begin = next_page_index;
                    if (spilled_pages != 0) {
                        if (!staging_reader) {
                            auto opened = open_reader_connection(conn.path, options);
                            if (!opened) {
                                staging->record_failure(opened.error());
                                aborted = true;
                                break;
                            }
                            staging_reader = opened.take_value();
                        }
                        std::uint64_t seen = 0;
                        auto visited = visit_packed_generation_staging(
                            staging_reader, staging->generation,
                            static_cast<std::uint16_t>(encoded),
                            [&](packed_generation_staging_row_t row)
                                -> workspace_result_t<void> {
                                staged_page_t page;
                                page.ordinal_begin = row.ordinal_begin;
                                page.record_count = row.record_count;
                                page.address_value_min = row.address_value_min;
                                page.address_value_max = row.address_value_max;
                                page.payload = std::move(row.payload);
                                finalize_seal_job_t job;
                                job.page_index = next_page_index;
                                job.page_type = encoded;
                                job.page = std::move(page);
                                ++next_page_index;
                                ++seen;
                                if (!work_ring.push(std::move(job))) {
                                    return workspace_result_t<void>::failure(
                                        packed_baseline_error(
                                            workspace_error_code_t::cancelled,
                                            "seal pipeline closed while feeding spilled pages"));
                                }
                                return workspace_result_t<void>::success();
                            },
                            [&cancel, staging] {
                                return cancel.stop_requested() ||
                                       staging->failed.load(std::memory_order_acquire);
                            });
                        if (!visited) {
                            staging->record_failure(visited.error());
                            aborted = true;
                            break;
                        }
                        if (seen != spilled_pages) {
                            staging->record_failure(packed_baseline_error(
                                workspace_error_code_t::integrity_failure,
                                "spilled staging pages are inconsistent with the staged totals"));
                            aborted = true;
                            break;
                        }
                    }
                    for (;;) {
                        staged_page_t page;
                        std::uint64_t page_bytes = 0;
                        {
                            std::lock_guard<std::mutex> lock(domain_state.mutex);
                            if (domain_state.pages.empty())
                                break;
                            page = std::move(domain_state.pages.front());
                            domain_state.pages.pop_front();
                            page_bytes = static_cast<std::uint64_t>(page.payload.size());
                            domain_state.resident_bytes =
                                domain_state.resident_bytes > page_bytes
                                    ? domain_state.resident_bytes - page_bytes
                                    : 0;
                        }
                        finalize_seal_job_t job;
                        job.page_index = next_page_index;
                        job.page_type = encoded;
                        job.page = std::move(page);
                        ++next_page_index;
                        const bool pushed = work_ring.push(std::move(job));
                        conn.staging_resident_bytes.fetch_sub(
                            page_bytes, std::memory_order_acq_rel);
                        if (!pushed) {
                            aborted = true;
                            break;
                        }
                    }
                    if (!aborted &&
                        next_page_index - domain_feed_begin != expected_pages) {
                        staging->record_failure(packed_baseline_error(
                            workspace_error_code_t::integrity_failure,
                            "staged domain page count changed during finalize"));
                        aborted = true;
                    }
                }
                if (staging_reader)
                    sqlite3_close_v2(staging_reader);
                work_ring.close();
                if (!aborted &&
                    !staging->failed.load(std::memory_order_acquire) &&
                    next_page_index != totals.page_count) {
                    staging->record_failure(packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "packed baseline page count changed during finalize"));
                }
            };
            graph.nodes.push_back(std::move(feeder));
        }
        const auto hardware = std::thread::hardware_concurrency();
        const std::uint32_t seal_workers = static_cast<std::uint32_t>(
            (std::max)(2U, (std::min)(16U, hardware == 0 ? 2U : hardware)));
        const int seal_compression_level =
            static_cast<int>(options.packed_page_compression_level);
        for (std::uint32_t worker = 0; worker < seal_workers; ++worker) {
            aida::infra::taskflow_runtime::graph_node_descriptor_t node;
            node.node_id = ++node_id;
            node.label = "analysis.persistence.finalize_seal_page";
            node.cancellable_body = [staging, &totals, &work_ring, &sealed_ring,
                                     &cancel, seal_compression_level](
                const aida::infra::taskflow_runtime::cancellation_token_t&) {
                for (;;) {
                    if (staging->failed.load(std::memory_order_acquire))
                        break;
                    finalize_seal_job_t job;
                    if (!work_ring.pop(job))
                        break;
                    packed_page_t page;
                    page.header.generation = staging->generation;
                    page.header.analysis_revision = staging->analysis_revision;
                    page.header.overlay_revision = staging->overlay_revision;
                    page.header.page_type = job.page_type;
                    page.header.page_index = job.page_index;
                    page.header.page_count = totals.page_count;
                    page.payload = std::move(job.page.payload);
                    const std::uint32_t logical_length =
                        static_cast<std::uint32_t>(page.payload.size());
                    auto sealed = packed_page_codec_t::seal_page_v3(
                        page, seal_compression_level, [&cancel, staging] {
                            return cancel.stop_requested() ||
                                   staging->failed.load(std::memory_order_acquire);
                        });
                    if (!sealed) {
                        staging->record_failure(sealed.error());
                        work_ring.close();
                        break;
                    }
                    packed_page_row_t row;
                    row.generation = page.header.generation;
                    row.page_index = page.header.page_index;
                    row.page_count = page.header.page_count;
                    row.page_type = page.header.page_type;
                    row.payload_length = page.header.payload_length;
                    row.logical_length =
                        page.header.version == packed_page_blob_version_v3
                            ? logical_length
                            : 0U;
                    row.checksum = page.header.checksum;
                    row.payload = std::move(page.payload);
                    packed_page_index_row_t index;
                    index.generation = row.generation;
                    index.domain = static_cast<std::uint16_t>(job.page_type);
                    index.ordinal_begin = job.page.ordinal_begin;
                    index.count = job.page.record_count;
                    index.page_index = row.page_index;
                    index.address_value_min = job.page.address_value_min;
                    index.address_value_max = job.page.address_value_max;
                    finalize_sealed_page_t output;
                    output.row = std::move(row);
                    output.index = std::move(index);
                    if (!sealed_ring.push(std::move(output)))
                        break;
                }
            };
            graph.nodes.push_back(std::move(node));
        }
        auto submission = aida::infra::taskflow_runtime::submit_graph(std::move(graph));
        if (!submission.submitted) {
            work_ring.close();
            sealed_ring.close();
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::persistence_failure,
                    std::string("packed finalize seal dispatch was rejected: ") +
                        submission.reject_reason));
        }
        statement_t page_statement;
        auto prepared = page_statement.prepare(database, R"SQL(
INSERT INTO packed_pages(generation,page_index,page_count,page_type,payload_length,checksum,payload,logical_length)
VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
)SQL", "workspace_database.persist.packed.page");
        if (!prepared) {
            work_ring.close();
            sealed_ring.close();
            aida::infra::taskflow_runtime::cancel(submission.handle);
            return prepared;
        }
        statement_t index_statement;
        prepared = index_statement.prepare(database, R"SQL(
INSERT INTO packed_page_index(generation,domain,ordinal_begin,count,page_index,address_value_min,address_value_max)
VALUES(?1,?2,?3,?4,?5,?6,?7)
)SQL", "workspace_database.persist.packed.index");
        if (!prepared) {
            work_ring.close();
            sealed_ring.close();
            aida::infra::taskflow_runtime::cancel(submission.handle);
            return prepared;
        }
        std::uint32_t consumed = 0;
        bool chunk_open = false;
        std::uint32_t chunk_pages = 0;
        std::uint64_t chunk_bytes = 0;
        bool generation_row_written = false;
        std::chrono::steady_clock::time_point chunk_started{};
        std::optional<workspace_error_t> pipeline_error;
        const auto open_chunk = [&]() -> workspace_result_t<void> {
            if (chunk_open)
                return workspace_result_t<void>::success();
            auto sync_normal = set_writer_synchronous(
                database, 1, "workspace_database.persist.packed.chunk");
            if (!sync_normal)
                return sync_normal;
            auto begun = begin_immediate(database, "workspace_database.persist.packed.chunk");
            if (!begun) {
                set_writer_synchronous(
                    database, 2, "workspace_database.persist.packed.chunk");
                return begun;
            }
            if (!generation_row_written) {
                auto written = write_packed_generation(database, generation_record);
                if (!written) {
                    rollback(database, "workspace_database.persist.packed.chunk");
                    set_writer_synchronous(
                        database, 2, "workspace_database.persist.packed.chunk");
                    return written;
                }
                generation_row_written = true;
            }
            chunk_open = true;
            chunk_started = std::chrono::steady_clock::now();
            return workspace_result_t<void>::success();
        };
        const auto flush_chunk = [&]() -> workspace_result_t<void> {
            if (!chunk_open)
                return workspace_result_t<void>::success();
            auto committed = commit(database, "workspace_database.persist.packed.chunk");
            db_write_us += static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - chunk_started).count());
            auto restored = set_writer_synchronous(
                database, 2, "workspace_database.persist.packed.chunk");
            chunk_open = false;
            chunk_pages = 0;
            chunk_bytes = 0;
            if (!committed) {
                rollback(database, "workspace_database.persist.packed.chunk");
                return committed;
            }
            if (!restored)
                return restored;
            return workspace_result_t<void>::success();
        };
        while (consumed < totals.page_count) {
            if (cancel.stop_requested()) {
                pipeline_error = packed_baseline_cancelled(cancel);
                break;
            }
            if (staging->failed.load(std::memory_order_acquire)) {
                pipeline_error = staging->current_failure();
                break;
            }
            finalize_sealed_page_t item;
            if (!sealed_ring.pop(item)) {
                if (staging->failed.load(std::memory_order_acquire))
                    pipeline_error = staging->current_failure();
                else
                    pipeline_error = packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "seal pipeline closed before every staged page was sealed");
                break;
            }
            auto opened = open_chunk();
            if (!opened) {
                pipeline_error = opened.error();
                break;
            }
            auto result = page_statement.bind_uint(1, item.row.generation);
            if (result) result = page_statement.bind_int(2, item.row.page_index);
            if (result) result = page_statement.bind_int(3, item.row.page_count);
            if (result) result = page_statement.bind_int(4, item.row.page_type);
            if (result) result = page_statement.bind_int(5, item.row.payload_length);
            if (result) result = page_statement.bind_int(6, item.row.checksum);
            if (result) result = page_statement.bind_blob(7, item.row.payload.data(),
                                                          item.row.payload.size());
            if (result) {
                result = item.row.logical_length != 0
                    ? page_statement.bind_int(
                          8, static_cast<std::int64_t>(item.row.logical_length))
                    : page_statement.bind_null(8);
            }
            if (result) result = page_statement.step_done();
            if (result) result = page_statement.reset();
            if (result) result = index_statement.bind_uint(1, item.index.generation);
            if (result) result = index_statement.bind_int(2, item.index.domain);
            if (result) result = index_statement.bind_int(3, item.index.ordinal_begin);
            if (result) result = index_statement.bind_int(4, item.index.count);
            if (result) result = index_statement.bind_int(5, item.index.page_index);
            if (result) result = index_statement.bind_uint(6, item.index.address_value_min);
            if (result) result = index_statement.bind_uint(7, item.index.address_value_max);
            if (result) result = index_statement.step_done();
            if (result) result = index_statement.reset();
            if (!result) {
                pipeline_error = result.error();
                break;
            }
            for (unsigned shift = 0; shift < 32; shift += 8) {
                checksum_bytes[static_cast<std::size_t>(item.row.page_index) * 4U +
                               shift / 8U] =
                    static_cast<std::uint8_t>(item.row.checksum >> shift);
            }
            ++consumed;
            ++chunk_pages;
            chunk_bytes += item.row.payload_length;
            sealed_stored_bytes += item.row.payload_length;
            sealed_pages_v3 += item.row.logical_length != 0 ? 1ULL : 0ULL;
            if (chunk_pages >= kFinalizeChunkMaxPages ||
                chunk_bytes >= kFinalizeChunkMaxWalBytes) {
                auto flushed = flush_chunk();
                if (!flushed) {
                    pipeline_error = flushed.error();
                    break;
                }
            }
        }
        auto flushed = flush_chunk();
        if (!flushed && !pipeline_error)
            pipeline_error = flushed.error();
        sealed_ring.close();
        work_ring.close();
        if (pipeline_error)
            aida::infra::taskflow_runtime::cancel(submission.handle);
        for (;;) {
            const auto waited = aida::infra::taskflow_runtime::wait_for(
                submission.handle, 50);
            if (waited.completed)
                break;
            if (cancel.stop_requested() || pipeline_error)
                aida::infra::taskflow_runtime::cancel(submission.handle);
        }
        seal_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - seal_started).count());
        if (staging->failed.load(std::memory_order_acquire) && !pipeline_error)
            pipeline_error = staging->current_failure();
        if (pipeline_error)
            return workspace_result_t<void>::failure(*pipeline_error);
        if (consumed != totals.page_count) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "seal pipeline sealed an inconsistent number of pages"));
        }
        seal_us = seal_us > db_write_us ? seal_us - db_write_us : 0;
    }
    auto batch_checksum = crc32c_cancellable(
        checksum_bytes.data(), checksum_bytes.size(),
        [&cancel] { return cancel.stop_requested(); });
    if (!batch_checksum)
        return workspace_result_t<void>::failure(batch_checksum.error());
    {
        statement_t synchronous;
        auto prepared = synchronous.prepare(database, "PRAGMA synchronous",
                                            "workspace_database.persist.packed");
        if (!prepared)
            return prepared;
        const int sync_status = sqlite3_step(synchronous.get());
        if (sync_status != SQLITE_ROW ||
            sqlite3_column_int(synchronous.get(), 0) != 2) {
            return workspace_result_t<void>::failure(database_error(
                database, sync_status,
                "SQLite writer connection left FULL synchronous mode before the marker transaction",
                "workspace_database.persist.packed"));
        }
    }
    auto begun = begin_immediate(database, "workspace_database.persist.packed");
    if (!begun)
        return begun;
    auto marker_state = read_commit_state(
        database, "workspace_database.persist.packed");
    if (!marker_state) {
        rollback(database, "workspace_database.persist.packed");
        return workspace_result_t<void>::failure(marker_state.error());
    }
    if (marker_state.value().candidate_ready ||
        marker_state.value().committed_generation > staging->generation ||
        (marker_state.value().committed_generation == staging->generation &&
         marker_state.value().committed_analysis_revision >
             staging->analysis_revision)) {
        rollback(database, "workspace_database.persist.packed");
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "packed snapshot conflicts with current persistence state",
                                 "workspace_database.persist.packed"));
    }
    const auto target_slot = static_cast<std::uint8_t>(
        1U - marker_state.value().active_slot);
    auto result = clear_snapshot_slot(
        database, target_slot, "workspace_database.persist.packed");
    if (!result) {
        rollback(database, "workspace_database.persist.packed");
        return result;
    }
    statement_t state_statement;
    const std::string state_sql = "INSERT INTO " +
        slot_table(target_slot, "analysis_state") +
        "(singleton,generation,analysis_revision,overlay_revision,baseline_complete,settings_json,metrics_json,updated_utc_ms,commit_token) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,analysis_revision=excluded.analysis_revision,overlay_revision=excluded.overlay_revision,baseline_complete=excluded.baseline_complete,settings_json=excluded.settings_json,metrics_json=excluded.metrics_json,updated_utc_ms=excluded.updated_utc_ms,commit_token=excluded.commit_token";
    result = state_statement.prepare(database, state_sql.c_str(),
                                     "workspace_database.persist.packed.state");
    if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_uint(1, staging->generation); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_uint(2, staging->analysis_revision); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_uint(3, staging->overlay_revision); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_int(4, staging->baseline_complete ? 1 : 0); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_text(5, staging->settings_json); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_text(6, staging->metrics_json); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_uint(7, utc_ms()); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.bind_text(8, staging->token); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = state_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    statement_t checksum_statement;
    result = checksum_statement.prepare(database,
        "UPDATE packed_generations SET batch_checksum=?1 WHERE generation=?2 AND committed=0 AND total_payload_bytes=?3 AND total_records=?4",
        "workspace_database.persist.packed.checksum");
    if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = checksum_statement.bind_int(1, static_cast<std::int64_t>(batch_checksum.value())); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = checksum_statement.bind_uint(2, staging->generation); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = checksum_statement.bind_uint(3, totals.total_payload_bytes); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = checksum_statement.bind_uint(4, totals.total_records); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = checksum_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.persist.packed");
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "packed stream manifest was not finalized"));
    }
    result = delete_packed_generation_staging(database, staging->generation);
    if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    statement_t candidate_statement;
    result = candidate_statement.prepare(database,
        "UPDATE workspace_commit_state SET candidate_slot=?1,candidate_token=?2,candidate_generation=?3,candidate_analysis_revision=?4,candidate_overlay_revision=?5,candidate_ready=1,updated_utc_ms=?6 WHERE singleton=1 AND active_slot=?7 AND candidate_ready=0",
        "workspace_database.persist.packed.candidate");
    if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_uint(1, target_slot); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_text(2, staging->token); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_uint(3, staging->generation); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_uint(4, staging->analysis_revision); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_uint(5, staging->overlay_revision); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_uint(6, utc_ms()); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.bind_uint(7, marker_state.value().active_slot); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    result = candidate_statement.step_done(); if (!result) { rollback(database, "workspace_database.persist.packed"); return result; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.persist.packed");
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::revision_conflict,
                                 "packed snapshot candidate changed before staging",
                                 "workspace_database.persist.packed"));
    }
    auto committed = commit(database, "workspace_database.persist.packed");
    if (!committed) {
        rollback(database, "workspace_database.persist.packed");
        return committed;
    }
    int log_frames = 0;
    int checkpointed_frames = 0;
    const int checkpoint_status = sqlite3_wal_checkpoint_v2(
        database, "main", SQLITE_CHECKPOINT_PASSIVE, &log_frames, &checkpointed_frames);
    if (checkpoint_status != SQLITE_OK && checkpoint_status != SQLITE_BUSY) {
        return workspace_result_t<void>::failure(
            database_error(database, checkpoint_status,
                           "snapshot committed but passive WAL checkpoint failed",
                           "workspace_database.checkpoint"));
    }
    auto bound_page_source = bind_committed_page_source(
        database, conn, options, staging, generation_record, cancel);
    if (!bound_page_source)
        return workspace_result_t<void>::failure(bound_page_source.error());
    release_handed_off_paged_domains(staging);
    int writes_after = 0;
    status = sqlite3_db_status(database, SQLITE_DBSTATUS_CACHE_WRITE,
                               &writes_after, &highwater, 0);
    if (status != SQLITE_OK) {
        return workspace_result_t<void>::failure(database_error(
            database, status, "unable to read packed persistence write counter",
            "workspace_database.persist.packed"));
    }
    staging->finalized.store(true, std::memory_order_release);
    conn.candidate_generation.store(staging->generation, std::memory_order_release);
    conn.candidate_analysis_revision.store(staging->analysis_revision,
                                           std::memory_order_release);
    conn.candidate_overlay_revision.store(staging->overlay_revision,
                                          std::memory_order_release);
    conn.candidate_pending.store(true, std::memory_order_release);
    conn.cumulative_pages_written.fetch_add(totals.page_count,
                                            std::memory_order_acq_rel);
    conn.last_commit_pages_v3.store(sealed_pages_v3, std::memory_order_release);
    conn.last_commit_page_stored_bytes.store(sealed_stored_bytes,
                                             std::memory_order_release);
    conn.last_commit_page_logical_bytes.store(totals.total_payload_bytes,
                                              std::memory_order_release);
    saturating_atomic_add(conn.cumulative_pages_v3, sealed_pages_v3);
    saturating_atomic_add(conn.cumulative_page_stored_bytes,
                          sealed_stored_bytes);
    saturating_atomic_add(conn.cumulative_page_logical_bytes,
                          totals.total_payload_bytes);
    {
        std::lock_guard<std::mutex> lock(conn.staging_mutex);
        auto current = conn.active_staging.lock();
        if (current && current->state_.get() == staging.get())
            conn.active_staging.reset();
    }
    if (commit_metrics) {
        const auto written_pages = writes_after >= writes_before
            ? static_cast<std::uint64_t>(writes_after - writes_before)
            : static_cast<std::uint64_t>(writes_after);
        const auto elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - finalize_started).count());
        if (!checked_mul_u64(written_pages, page_size.value(),
                             commit_metrics->page_write_bytes) ||
            !checked_add_u64(totals.total_payload_bytes +
                                 generation_record.payload_blob.size() +
                                 staging->settings_json.size() +
                                 staging->metrics_json.size(),
                             0ULL, commit_metrics->logical_bytes) ||
            !checked_add_u64(
                static_cast<std::uint64_t>(totals.page_count) * 2ULL + 3ULL,
                0ULL, commit_metrics->rows)) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "packed persistence metrics overflow",
                                     "workspace_database.persist.packed"));
        }
        commit_metrics->elapsed_us = elapsed_us;
        commit_metrics->finalize_us = elapsed_us;
        commit_metrics->stage_serialize_us = serialize_us;
        commit_metrics->stage_seal_us = seal_us;
        commit_metrics->stage_db_write_us = db_write_us;
        commit_metrics->pages = totals.page_count;
        commit_metrics->staged_bytes = totals.total_payload_bytes;
        publish_commit_metrics(conn, *commit_metrics);
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> recover_workspace_persistence_state(
    sqlite3* database, const commit_state_record_t& commit_state) {
    bool staging_present = false;
    std::vector<std::uint64_t> uncommitted;
    {
        statement_t query;
        auto prepared = query.prepare(database,
            "SELECT generation FROM packed_generations WHERE committed=0",
            "workspace_database.open.recovery");
        if (!prepared)
            return prepared;
        for (;;) {
            const int status = sqlite3_step(query.get());
            if (status == SQLITE_DONE)
                break;
            if (status != SQLITE_ROW) {
                return workspace_result_t<void>::failure(database_error(
                    database, status, "unable to enumerate uncommitted packed generations",
                    "workspace_database.open.recovery"));
            }
            uncommitted.push_back(static_cast<std::uint64_t>(
                sqlite3_column_int64(query.get(), 0)));
        }
    }
    {
        statement_t query;
        auto prepared = query.prepare(database,
            "SELECT 1 FROM packed_generation_staging LIMIT 1",
            "workspace_database.open.recovery");
        if (!prepared)
            return prepared;
        const int status = sqlite3_step(query.get());
        if (status == SQLITE_ROW)
            staging_present = true;
        else if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(database_error(
                database, status, "unable to probe packed staging rows",
                "workspace_database.open.recovery"));
        }
    }
    if (!commit_state.candidate_ready && uncommitted.empty() && !staging_present)
        return workspace_result_t<void>::success();
    auto begun = begin_immediate(database, "workspace_database.open.recovery");
    if (!begun)
        return begun;
    if (commit_state.candidate_ready) {
        auto rolled_back = rollback_packed_generation(
            database, *commit_state.candidate_generation);
        if (!rolled_back) {
            rollback(database, "workspace_database.open.recovery");
            return rolled_back;
        }
        auto cleared = clear_snapshot_slot(
            database, *commit_state.candidate_slot,
            "workspace_database.open.recovery");
        if (!cleared) {
            rollback(database, "workspace_database.open.recovery");
            return cleared;
        }
        auto staging_deleted = delete_packed_generation_staging(
            database, *commit_state.candidate_generation);
        if (!staging_deleted) {
            rollback(database, "workspace_database.open.recovery");
            return staging_deleted;
        }
        statement_t discard;
        auto prepared = discard.prepare(database,
            "UPDATE workspace_commit_state SET candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=?1 WHERE singleton=1",
            "workspace_database.open.recovery");
        if (!prepared) { rollback(database, "workspace_database.open.recovery"); return prepared; }
        auto result = discard.bind_uint(1, utc_ms());
        if (!result) { rollback(database, "workspace_database.open.recovery"); return result; }
        result = discard.step_done();
        if (!result) { rollback(database, "workspace_database.open.recovery"); return result; }
    }
    for (const auto generation : uncommitted) {
        auto rolled_back = rollback_packed_generation(database, generation);
        if (!rolled_back) {
            rollback(database, "workspace_database.open.recovery");
            return rolled_back;
        }
    }
    auto collected = gc_packed_generation_staging(database);
    if (!collected) {
        rollback(database, "workspace_database.open.recovery");
        return collected;
    }
    auto committed = commit(database, "workspace_database.open.recovery");
    if (!committed) {
        rollback(database, "workspace_database.open.recovery");
        return committed;
    }
    return workspace_result_t<void>::success();
}

}


workspace_result_t<std::vector<std::uint8_t>>
encode_managed_publication_domain(
    const managed_artifact_publication_t& publication,
    const cancellation_token_t& cancel) {
    try {
        packed_payload_writer_t writer(
            cancel, managed_publication_max_payload_bytes);
        auto written = write_managed_publication_domain_stream(
            publication, writer, cancel);
        if (!written)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                written.error());
        return writer.finish();
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication encoding allocation failed"));
    } catch (const std::exception&) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "managed publication encoding failed"));
    }
}

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
decode_managed_publication_domain(
    const std::vector<std::uint8_t>& payload,
    const workspace_identity_t& identity,
    const byte_provider_t& provider,
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision,
    std::uint64_t maximum_payload_bytes,
    const cancellation_token_t& cancel) {
    if (payload.size() < 4U || payload.size() > maximum_payload_bytes ||
        maximum_payload_bytes == 0 ||
        maximum_payload_bytes > managed_publication_max_payload_bytes) {
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication domain exceeds its reopen budget"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            packed_baseline_cancelled(cancel));
    try {
        const auto payload_size = payload.size() - 4U;
        auto actual_checksum = crc32c_cancellable(
            payload.data(), payload_size,
            [&cancel] { return cancel.stop_requested(); });
        if (!actual_checksum && cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                packed_baseline_cancelled(cancel));
        if (!actual_checksum)
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                actual_checksum.error());
        const auto expected_checksum =
            static_cast<std::uint32_t>(payload[payload_size]) |
            (static_cast<std::uint32_t>(payload[payload_size + 1U]) << 8U) |
            (static_cast<std::uint32_t>(payload[payload_size + 2U]) << 16U) |
            (static_cast<std::uint32_t>(payload[payload_size + 3U]) << 24U);
        if (actual_checksum.value() != expected_checksum) {
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                                      "managed publication domain checksum is invalid"));
        }
        packed_payload_reader_t reader(
            payload, cancel, managed_publication_max_methods +
                                 managed_publication_max_artifacts +
                                 managed_publication_max_strings);
        read_domain_header(reader, packed_page_type_t::managed_publication);
        if (reader.u32() != managed_publication_domain_magic ||
            reader.u16() != managed_publication_domain_version ||
            reader.u16() != 0) {
            reader.reject("managed publication domain header is invalid");
        }
        auto publication = std::make_shared<managed_artifact_publication_t>();
        publication->schema_version = reader.u32();
        publication->reader_schema_version = reader.u32();
        publication->reader_limits = read_managed_reader_limits(reader);
        publication->binary_id.bytes = reader.fixed_bytes<32>();
        publication->load_profile_hash.bytes = reader.fixed_bytes<32>();
        publication->provider_hash.bytes = reader.fixed_bytes<32>();
        publication->provider_size = reader.u64();
        publication->generation = reader.u64();
        publication->analysis_revision = reader.u64();
        publication->overlay_revision = reader.u64();
        const auto string_count = reader.u32();
        if (string_count == 0 ||
            string_count > managed_publication_max_strings)
            reader.reject("managed publication string count is invalid");
        std::uint64_t minimum_string_bytes = 0;
        if (!checked_mul_u64(string_count, sizeof(std::uint64_t),
                             minimum_string_bytes) ||
            !checked_add_u64(minimum_string_bytes, 16U,
                             minimum_string_bytes) ||
            minimum_string_bytes > reader.remaining_bytes())
            reader.reject("managed publication string table is truncated");
        if (reader.failed()) {
            auto rejected = reader.finish();
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                rejected.error());
        }
        std::vector<std::string> strings;
        strings.reserve((std::min<std::uint32_t>)(string_count, 1U << 20));
        std::uint64_t string_bytes = 0;
        for (std::uint32_t index = 0; index < string_count; ++index) {
            auto value = reader.bounded_string(
                managed_publication_max_single_string_bytes);
            if (value.size() > managed_publication_max_single_string_bytes ||
                !checked_add_u64(string_bytes, value.size(), string_bytes) ||
                string_bytes > managed_publication_max_string_bytes ||
                (index != 0 && !(strings.back() < value))) {
                reader.reject("managed publication string table is noncanonical");
            }
            strings.push_back(std::move(value));
        }
        const auto string_at = [&](std::uint32_t reference)
            -> const std::string* {
            if (reference >= strings.size()) {
                reader.reject("managed publication string reference is invalid");
                return nullptr;
            }
            return &strings[reference];
        };
        const auto provider_source = string_at(reader.u32());
        if (provider_source)
            publication->provider_source = *provider_source;
        const auto artifact_count = reader.u32();
        const auto method_count = reader.u32();
        std::uint64_t declared_method_limit = 0;
        if (!checked_mul_u64(publication->reader_limits.max_methods,
                             publication->reader_limits.max_dex_files,
                             declared_method_limit))
            reader.reject("managed publication reader method limit overflows");
        if (artifact_count == 0 ||
            artifact_count > managed_publication_max_artifacts ||
            method_count > managed_publication_max_methods ||
            artifact_count > publication->reader_limits.max_dex_files + 1ULL ||
            method_count > declared_method_limit) {
            reader.reject("managed publication record count is invalid");
        }
        std::uint64_t minimum_artifact_bytes = 0;
        std::uint64_t minimum_method_bytes = 0;
        std::uint64_t minimum_record_bytes = 4;
        if (!checked_mul_u64(artifact_count, 73U,
                             minimum_artifact_bytes) ||
            !checked_mul_u64(method_count, 33U,
                             minimum_method_bytes) ||
            !checked_add_u64(minimum_record_bytes, minimum_artifact_bytes,
                             minimum_record_bytes) ||
            !checked_add_u64(minimum_record_bytes, minimum_method_bytes,
                             minimum_record_bytes) ||
            minimum_record_bytes > reader.remaining_bytes())
            reader.reject("managed publication record columns are truncated");
        if (reader.failed()) {
            auto rejected = reader.finish();
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                rejected.error());
        }
        auto records = std::make_shared<managed_artifact_record_index_t>();
        records->artifacts.resize(artifact_count);
        records->methods.resize(method_count);
        for (auto& value : records->artifacts)
            value.kind = static_cast<readers::managed::managed_artifact_kind_t>(
                reader.u8());
        for (auto& value : records->artifacts)
            value.artifact_hash.bytes = reader.fixed_bytes<32>();
        for (auto& value : records->artifacts)
            value.provider_offset = reader.u64();
        for (auto& value : records->artifacts)
            value.provider_size = reader.u64();
        for (auto& value : records->artifacts)
            value.artifact_ordinal = reader.u32();
        for (auto& value : records->artifacts) {
            const auto text = string_at(reader.u32());
            if (text)
                value.assembly_identity = *text;
        }
        for (auto& value : records->artifacts) {
            const auto text = string_at(reader.u32());
            if (text)
                value.module_name = *text;
        }
        for (auto& value : records->artifacts) {
            const auto text = string_at(reader.u32());
            if (text)
                value.version = *text;
        }
        for (auto& value : records->artifacts)
            value.first_method = reader.u32();
        for (auto& value : records->artifacts)
            value.method_count = reader.u32();
        for (auto& value : records->methods)
            value.artifact_index = reader.u32();
        for (auto& value : records->methods)
            value.entity_token = reader.u32();
        for (auto& value : records->methods)
            value.method_index = reader.u32();
        for (auto& value : records->methods)
            value.provider_code_offset = reader.u64();
        for (auto& value : records->methods)
            value.code_size = reader.u64();
        std::unordered_set<std::string> entity_identities;
        entity_identities.reserve(method_count);
        for (auto& value : records->methods) {
            const auto text = string_at(reader.u32());
            if (!text || !entity_identities.insert(*text).second) {
                reader.reject("managed publication entity reference is noncanonical");
                continue;
            }
            auto decoded = deserialize_decompiler_entity_key(*text);
            if (!decoded.valid()) {
                reader.reject("managed publication entity key is invalid");
                continue;
            }
            value.entity = std::move(*decoded.value);
        }
        for (auto& value : records->methods)
            value.has_body = reader.boolean();
        if (reader.u32() != expected_checksum)
            reader.reject("managed publication terminal checksum is inconsistent");
        auto finished = reader.finish();
        if (!finished)
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                finished.error());
        publication->records = std::static_pointer_cast<
            const managed_artifact_record_index_t>(std::move(records));
        auto validated = validate_managed_publication_for_encoding(
            *publication, cancel);
        if (!validated)
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                validated.error());
        const auto& provider_identity = provider.identity();
        if (publication->binary_id != identity.binary_id() ||
            publication->load_profile_hash != identity.load_profile_hash() ||
            publication->provider_source != provider_identity.normalized_source ||
            publication->provider_size != provider.size() ||
            provider_identity.size != provider.size() ||
            (provider_identity.content_sha256 &&
             publication->provider_hash != *provider_identity.content_sha256) ||
            (!provider_identity.content_sha256 &&
             (expected_overlay_revision != 0 ||
              publication->provider_hash != identity.content_hash())) ||
            publication->generation != expected_generation ||
            publication->analysis_revision != expected_analysis_revision ||
            publication->overlay_revision != expected_overlay_revision ||
            !publication->coherent_with(
                identity, provider, expected_generation,
                expected_analysis_revision, expected_overlay_revision)) {
            return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
                packed_baseline_error(workspace_error_code_t::target_conflict,
                                      "managed publication does not match the reopened workspace"));
        }
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
            std::static_pointer_cast<const managed_artifact_publication_t>(
                std::move(publication)));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                                  "managed publication reopen allocation failed"));
    } catch (const std::exception&) {
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                                  "managed publication reopen failed"));
    }
}

workspace_result_t<std::vector<std::uint8_t>> encode_packed_baseline_manifest(
    const analysis_snapshot_t& snapshot,
    const std::string& candidate_token,
    const cancellation_token_t& cancel) {
    if (snapshot.generation == 0 ||
        (!candidate_token.empty() && !valid_candidate_token(candidate_token))) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(
                workspace_error_code_t::invalid_argument,
                "packed baseline manifest identity is invalid"));
    }
    packed_payload_writer_t writer(cancel);
    writer.u32(kPackedBaselineManifestMagic);
    writer.u16(kPackedBaselinePayloadVersion);
    writer.u16(static_cast<std::uint16_t>(workspace_schema_v9_version));
    writer.u64(snapshot.generation);
    writer.u64(snapshot.analysis_revision);
    writer.u64(snapshot.overlay_revision);
    writer.boolean(snapshot.baseline_complete);
    writer.fixed_bytes(snapshot.binary_id.bytes);
    writer.fixed_bytes(snapshot.load_profile_hash.bytes);
    writer.u32(kPackedBaselineRequiredDomains);
    writer.string(candidate_token);
    return writer.finish();
}

workspace_result_t<std::shared_ptr<search_index_t>> restore_persisted_search_index(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    persisted_search_products_t products,
    std::shared_ptr<analysis_metrics_t> metrics,
    const search_index_limits_t& limits,
    const cancellation_token_t& cancel) {
    if (!snapshot || products.live_index ||
        products.generation != snapshot->generation ||
        products.analysis_revision != snapshot->analysis_revision ||
        products.overlay_revision != snapshot->overlay_revision ||
        products.search_index_blob_version != search_index_t::serialized_version ||
        products.search_index_blob.empty() ||
        products.search_index_blob.size() > workspace_search_blob_limit) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                                 "persisted search index identity or payload is invalid",
                                 "workspace_database.restore_search"));
    }
    return search_index_t::restore(
        std::move(snapshot), std::move(products.data_candidates),
        std::move(products.switches), std::move(products.types),
        std::move(metrics), limits, products.search_index_blob, cancel);
}

workspace_result_t<void> migrate_workspace_database_schema(
    sqlite3* database, bool& invalidate_derived_facts) {
    if (!database) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "workspace schema migration requires an open database",
                                 "workspace_database.schema"));
    }
    return migrate_schema(database, invalidate_derived_facts);
}

namespace {

void publish_commit_metrics(workspace_database_t::connection_state_t& state,
                            const persistence_commit_metrics_t& metrics) noexcept {
    state.last_commit_logical_bytes.store(metrics.logical_bytes,
                                          std::memory_order_release);
    state.last_commit_rows.store(metrics.rows, std::memory_order_release);
    state.last_commit_page_write_bytes.store(metrics.page_write_bytes,
                                             std::memory_order_release);
    state.last_commit_elapsed_us.store(metrics.elapsed_us, std::memory_order_release);
    saturating_atomic_add(state.cumulative_logical_bytes, metrics.logical_bytes);
    saturating_atomic_add(state.cumulative_rows, metrics.rows);
    saturating_atomic_add(state.cumulative_page_write_bytes, metrics.page_write_bytes);
}

struct packed_baseline_manifest_t {
    std::uint64_t generation = 0;
    std::uint64_t analysis_revision = 0;
    std::uint64_t overlay_revision = 0;
    bool baseline_complete = false;
    binary_id_t binary_id;
    sha256_digest_t load_profile_hash;
    std::uint32_t required_domains = 0;
    std::string candidate_token;
};

workspace_result_t<packed_baseline_manifest_t> decode_packed_baseline_manifest(
    const std::vector<std::uint8_t>& payload,
    const cancellation_token_t& cancel) {
    packed_payload_reader_t reader(payload, cancel, 1);
    if (reader.u32() != kPackedBaselineManifestMagic ||
        reader.u16() != kPackedBaselinePayloadVersion ||
        reader.u16() != workspace_schema_v9_version) {
        reader.reject("packed baseline manifest header is invalid");
    }
    packed_baseline_manifest_t manifest;
    manifest.generation = reader.u64();
    manifest.analysis_revision = reader.u64();
    manifest.overlay_revision = reader.u64();
    manifest.baseline_complete = reader.boolean();
    manifest.binary_id.bytes = reader.fixed_bytes<32>();
    manifest.load_profile_hash.bytes = reader.fixed_bytes<32>();
    manifest.required_domains = reader.u32();
    manifest.candidate_token = reader.string();
    auto finished = reader.finish();
    if (!finished)
        return workspace_result_t<packed_baseline_manifest_t>::failure(
            finished.error());
    if (manifest.generation == 0 ||
        manifest.required_domains != kPackedBaselineRequiredDomains ||
        (!manifest.candidate_token.empty() &&
         !valid_candidate_token(manifest.candidate_token))) {
        return workspace_result_t<packed_baseline_manifest_t>::failure(
            packed_baseline_error(
                workspace_error_code_t::integrity_failure,
                "packed baseline manifest invariants are invalid"));
    }
    return workspace_result_t<packed_baseline_manifest_t>::success(
        std::move(manifest));
}

struct decoded_packed_baseline_t {
    std::shared_ptr<analysis_snapshot_t> snapshot;
    paged_domain_revision_tag_t revision_tag;
};

workspace_result_t<std::vector<std::uint8_t>> read_packed_domain_payload(
    sqlite3* database, const packed_generation_record_t& generation,
    packed_page_type_t domain,
    std::uint64_t maximum_bytes, const cancellation_token_t& cancel) {
    std::vector<std::uint8_t> payload;
    std::uint64_t expected_ordinal = 0;
    auto visited = visit_packed_domain_pages(
        database, generation.generation, domain,
        [&](const packed_page_row_t& page,
            const packed_page_index_row_t& index) -> workspace_result_t<void> {
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    packed_baseline_cancelled(cancel));
            if (index.ordinal_begin != expected_ordinal ||
                !checked_add_u64(expected_ordinal, index.count,
                                 expected_ordinal)) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "packed domain record ordinals are not contiguous"));
            }
            const std::uint8_t* content_data = nullptr;
            std::size_t content_size = 0;
            std::vector<std::uint8_t> decompressed;
            if (page.logical_length == 0) {
                content_data = page.payload.data() + packed_record_page_prefix_size;
                content_size = page.payload.size() - packed_record_page_prefix_size;
            } else {
                packed_page_t decoded_page;
                decoded_page.header.generation = page.generation;
                decoded_page.header.analysis_revision = generation.analysis_revision;
                decoded_page.header.overlay_revision = generation.overlay_revision;
                decoded_page.header.version = packed_page_blob_version_v3;
                decoded_page.header.page_type = page.page_type;
                decoded_page.header.page_index = page.page_index;
                decoded_page.header.page_count = page.page_count;
                decoded_page.header.payload_length = page.payload_length;
                decoded_page.header.checksum = page.checksum;
                decoded_page.payload = page.payload;
                auto content = packed_page_codec_t::decode_page_content(
                    decoded_page, [&cancel] { return cancel.stop_requested(); });
                if (!content)
                    return workspace_result_t<void>::failure(content.error());
                decompressed = std::move(content.value());
                content_data = decompressed.data();
                content_size = decompressed.size();
            }
            std::uint64_t updated = 0;
            if (!checked_add_u64(payload.size(), content_size, updated) ||
                updated > maximum_bytes ||
                updated > static_cast<std::uint64_t>(
                    (std::numeric_limits<std::size_t>::max)())) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::limit_exceeded,
                        "packed domain exceeds its bounded reopen budget"));
            }
            try {
                payload.reserve(static_cast<std::size_t>(updated));
                payload.insert(payload.end(), content_data,
                               content_data + content_size);
            } catch (const std::bad_alloc&) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::limit_exceeded,
                        "packed domain reopen allocation failed"));
            }
            return workspace_result_t<void>::success();
        }, [&cancel] { return cancel.stop_requested(); });
    if (!visited)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            visited.error());
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::move(payload));
}

workspace_result_t<persisted_search_products_t>
decode_packed_search_products_payload(
    const packed_baseline_manifest_t& manifest,
    std::vector<std::uint8_t> payload,
    std::uint64_t maximum_records,
    const cancellation_token_t& cancel) {
    persisted_search_products_t products;
    products.generation = manifest.generation;
    products.analysis_revision = manifest.analysis_revision;
    products.overlay_revision = manifest.overlay_revision;
    std::uint64_t decoded_records = 0;
    std::size_t blob_offset = 0;
    std::uint64_t blob_size = 0;
    {
        packed_payload_reader_t reader(payload, cancel, maximum_records,
                                       &decoded_records);
        read_domain_header(reader, packed_page_type_t::search_index);
        const auto data_count = reader.count();
        products.data_candidates.reserve(data_count);
        for (std::size_t index = 0; index < data_count; ++index)
            products.data_candidates.push_back(read_data_candidate(reader));
        const auto switch_count = reader.count();
        products.switches.reserve(switch_count);
        for (std::size_t index = 0; index < switch_count; ++index)
            products.switches.push_back(read_switch(reader));
        const auto type_count = reader.count();
        products.types.reserve(type_count);
        for (std::size_t index = 0; index < type_count; ++index)
            products.types.push_back(read_search_type(reader));
        products.search_index_blob_version = reader.u32();
        blob_size = reader.u64();
        blob_offset = reader.offset();
        if (products.search_index_blob_version != search_index_t::serialized_version ||
            blob_size == 0 || blob_size > workspace_search_blob_limit ||
            blob_size != reader.remaining_bytes()) {
            reader.reject(
                "packed search-index blob is absent or exceeds its bounded limit");
        }
        reader.skip_bytes(blob_size);
        auto finished = reader.finish();
        if (!finished)
            return workspace_result_t<persisted_search_products_t>::failure(
                finished.error());
    }
    if (blob_offset > payload.size() ||
        blob_size != payload.size() - blob_offset) {
        return workspace_result_t<persisted_search_products_t>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed search-index blob boundary changed during decode"));
    }
    payload.erase(payload.begin(), payload.begin() +
        static_cast<std::ptrdiff_t>(blob_offset));
    products.search_index_blob = std::move(payload);
    return workspace_result_t<persisted_search_products_t>::success(
        std::move(products));
}



workspace_result_t<void> decode_packed_domain_into(
    packed_page_type_t domain,
    const std::vector<std::uint8_t>& payload,
    analysis_snapshot_t& snapshot_ref,
    std::uint64_t maximum_records,
    std::uint64_t* aggregate_records,
    const cancellation_token_t& cancel) {
    if (domain < packed_page_type_t::instructions ||
        domain > packed_page_baseline_last_data_type ||
        domain == packed_page_type_t::search_index) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::invalid_argument,
                                  "packed baseline reopen domain is unsupported"));
    }
    auto* snapshot = &snapshot_ref;
    std::uint64_t& decoded_records = *aggregate_records;
    const auto finish_domain = [&](packed_payload_reader_t& reader) {
        return reader.finish();
    };

    if (domain == packed_page_type_t::instructions) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::instructions);
        const auto count = reader.count();
        snapshot->instructions.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->instructions.push_back(read_instruction(reader));
        const auto delay_count = reader.count();
        snapshot->delay_slot_counts.reserve(delay_count);
        for (std::size_t index = 0; index < delay_count; ++index)
            snapshot->delay_slot_counts.push_back(reader.u8());
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::operands) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::operands);
        const auto count = reader.count();
        snapshot->operand_facts.hot.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot_operand_append(*snapshot, read_operand(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::target_facts) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::target_facts);
        const auto count = reader.count();
        snapshot->target_facts.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->target_facts.push_back(read_target(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::edges) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::edges);
        const auto count = reader.count();
        snapshot->edges.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->edges.push_back(read_edge(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::strings) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::strings);
        const auto count = reader.count();
        snapshot->strings.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->strings.push_back(read_string_record(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::symbols) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::symbols);
        const auto count = reader.count();
        snapshot->symbols.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->symbols.push_back(read_symbol(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::address_expressions) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::address_expressions);
        const auto count = reader.count();
        snapshot->address_expressions.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->address_expressions.push_back(read_address_expression(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::basic_blocks) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::basic_blocks);
        const auto count = reader.count();
        snapshot->blocks.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->blocks.push_back(read_block(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::functions) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::functions);
        const auto count = reader.count();
        snapshot->functions.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->functions.push_back(read_function(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::function_chunks) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::function_chunks);
        const auto chunk_count = reader.count();
        snapshot->function_chunks.reserve(chunk_count);
        for (std::size_t index = 0; index < chunk_count; ++index)
            snapshot->function_chunks.push_back(read_function_chunk(reader));
        const auto membership_count = reader.count();
        snapshot->function_block_memberships.reserve(membership_count);
        for (std::size_t index = 0; index < membership_count; ++index)
            snapshot->function_block_memberships.push_back(
                read_function_membership(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::xrefs) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::xrefs);
        const auto count = reader.count();
        snapshot->xrefs.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->xrefs.push_back(read_xref(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::coverage) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::coverage);
        const auto count = reader.count();
        snapshot->coverage.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->coverage.push_back(read_coverage(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::call_graph) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::call_graph);
        const auto node_count = reader.count();
        snapshot->call_graph.nodes.reserve(node_count);
        for (std::size_t index = 0; index < node_count; ++index)
            snapshot->call_graph.nodes.push_back(read_call_node(reader));
        const auto site_count = reader.count();
        snapshot->call_graph.call_sites.reserve(site_count);
        for (std::size_t index = 0; index < site_count; ++index)
            snapshot->call_graph.call_sites.push_back(read_call_site(reader));
        const auto candidate_count = reader.count();
        snapshot->call_graph.candidates.reserve(candidate_count);
        for (std::size_t index = 0; index < candidate_count; ++index)
            snapshot->call_graph.candidates.push_back(read_call_candidate(reader));
        const auto edge_count = reader.count();
        snapshot->call_graph.edges.reserve(edge_count);
        for (std::size_t index = 0; index < edge_count; ++index)
            snapshot->call_graph.edges.push_back(read_call_edge(reader));
        const auto conflict_count = reader.count();
        snapshot->call_graph.conflicts.reserve(conflict_count);
        for (std::size_t index = 0; index < conflict_count; ++index)
            snapshot->call_graph.conflicts.push_back(read_call_conflict(reader));
        snapshot->call_graph.indirect_site_count = reader.u64();
        snapshot->call_graph.unresolved_site_count = reader.u64();
        snapshot->call_graph.bounded = reader.boolean();
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::pointer_facts) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::pointer_facts);
        const auto data_count = reader.count();
        snapshot->rich_facts.data_candidates.reserve(data_count);
        for (std::size_t index = 0; index < data_count; ++index)
            snapshot->rich_facts.data_candidates.push_back(
                read_data_candidate(reader));
        const auto pointer_count = reader.count();
        snapshot->rich_facts.data_pointer_facts.reserve(pointer_count);
        for (std::size_t index = 0; index < pointer_count; ++index)
            snapshot->rich_facts.data_pointer_facts.push_back(
                read_data_pointer(reader));
        const auto conflict_count = reader.count();
        snapshot->rich_facts.data_conflicts.reserve(conflict_count);
        for (std::size_t index = 0; index < conflict_count; ++index)
            snapshot->rich_facts.data_conflicts.push_back(
                read_data_conflict(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::type_references) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::type_references);
        const auto count = reader.count();
        snapshot->rich_facts.type_references.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->rich_facts.type_references.push_back(
                read_type_reference(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::metadata_conflicts) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::metadata_conflicts);
        const auto count = reader.count();
        snapshot->rich_facts.metadata_conflicts.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->rich_facts.metadata_conflicts.push_back(
                read_metadata_conflict(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }
    if (domain == packed_page_type_t::symbol_type_candidates) {
        packed_payload_reader_t reader(payload, cancel, maximum_records, &decoded_records);
        read_domain_header(reader, packed_page_type_t::symbol_type_candidates);
        const auto count = reader.count();
        snapshot->rich_facts.type_candidates.reserve(count);
        for (std::size_t index = 0; index < count; ++index)
            snapshot->rich_facts.type_candidates.push_back(
                read_symbol_type_candidate(reader));
        auto finished = finish_domain(reader);
        if (!finished)
            return workspace_result_t<void>::failure(
                finished.error());
    }

    return workspace_result_t<void>::success();
}

const std::vector<std::vector<packed_page_type_t>>& packed_reopen_domain_tasks() {
    static const std::vector<std::vector<packed_page_type_t>> tasks = {
        {packed_page_type_t::instructions},
        {packed_page_type_t::operands},
        {packed_page_type_t::target_facts},
        {packed_page_type_t::edges},
        {packed_page_type_t::strings},
        {packed_page_type_t::symbols},
        {packed_page_type_t::address_expressions,
         packed_page_type_t::coverage,
         packed_page_type_t::metadata_conflicts},
        {packed_page_type_t::basic_blocks},
        {packed_page_type_t::functions},
        {packed_page_type_t::function_chunks},
        {packed_page_type_t::xrefs},
        {packed_page_type_t::call_graph},
        {packed_page_type_t::pointer_facts},
        {packed_page_type_t::type_references},
        {packed_page_type_t::symbol_type_candidates},
    };
    return tasks;
}

struct packed_domain_decode_result_t {
    analysis_snapshot_t snapshot;
    std::uint64_t decoded_records = 0;
    std::uint32_t domain_mask = 0;
    std::optional<workspace_error_t> error;
};

struct packed_domain_page_stats_t {
    bool present = false;
    std::uint32_t page_count = 0;
    std::uint64_t logical_bytes = 0;
};

workspace_result_t<void> read_packed_domain_page_stats(
    sqlite3* database, std::uint64_t generation,
    std::array<packed_domain_page_stats_t, 20>& stats,
    const cancellation_token_t& cancel) {
    statement_t statement;
    auto prepared = statement.prepare(database, R"SQL(
SELECT page_type,COUNT(*),COALESCE(SUM(COALESCE(NULLIF(logical_length,0),payload_length)),0)
FROM packed_pages WHERE generation=?1 GROUP BY page_type
)SQL", "workspace_database.load.packed_stats");
    if (!prepared)
        return prepared;
    auto bound = statement.bind_uint(1, generation);
    if (!bound)
        return bound;
    for (;;) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(
                packed_baseline_cancelled(cancel));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(database_error(
                database, status, "unable to read packed domain page statistics",
                "workspace_database.load.packed_stats"));
        }
        const auto page_type = sqlite3_column_int64(statement.get(), 0);
        const auto page_count = sqlite3_column_int64(statement.get(), 1);
        const auto logical_bytes = sqlite3_column_int64(statement.get(), 2);
        if (page_type < static_cast<std::int64_t>(packed_page_type_t::instructions) ||
            page_type > static_cast<std::int64_t>(packed_page_last_data_type) ||
            page_count <= 0 ||
            page_count > static_cast<std::int64_t>(packed_generation_max_pages) ||
            logical_bytes < 0) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "packed domain page statistics are inconsistent"));
        }
        auto& entry = stats[static_cast<std::size_t>(page_type)];
        entry.present = true;
        entry.page_count = static_cast<std::uint32_t>(page_count);
        entry.logical_bytes = static_cast<std::uint64_t>(logical_bytes);
    }
    return workspace_result_t<void>::success();
}

std::uint64_t reopen_resident_projection_bytes(
    packed_page_type_t domain, std::uint64_t logical_bytes) noexcept {
    std::uint64_t numerator = 1;
    std::uint64_t denominator = 1;
    switch (domain) {
    case packed_page_type_t::instructions:
        numerator = static_cast<std::uint64_t>(sizeof(instruction_record_t)) + 1;
        denominator = kPackedInstructionRecordBytes + 1;
        break;
    case packed_page_type_t::operands:
        numerator = static_cast<std::uint64_t>(sizeof(operand_fact_hot_t)) +
            static_cast<std::uint64_t>(sizeof(operand_fact_cold_t));
        denominator = kPackedOperandRecordBytes;
        break;
    case packed_page_type_t::target_facts:
        numerator = static_cast<std::uint64_t>(sizeof(target_fact_t));
        denominator = kPackedTargetRecordBytes;
        break;
    case packed_page_type_t::edges:
        numerator = static_cast<std::uint64_t>(sizeof(edge_record_t));
        denominator = kPackedEdgeRecordMinBytes;
        break;
    case packed_page_type_t::xrefs:
        numerator = static_cast<std::uint64_t>(sizeof(xref_record_t));
        denominator = kPackedXrefRecordBytes;
        break;
    default:
        return logical_bytes;
    }
    const std::uint64_t scaled =
        logical_bytes > (0xFFFFFFFFFFFFFFFFULL / numerator)
            ? 0xFFFFFFFFFFFFFFFFULL
            : logical_bytes * numerator;
    const std::uint64_t quotient = scaled / denominator;
    if (scaled - quotient * denominator != 0 &&
        quotient < 0xFFFFFFFFFFFFFFFFULL)
        return quotient + 1;
    return quotient;
}

workspace_result_t<std::vector<std::uint8_t>> reopen_paged_delay_slot_tail(
    const paged_domain_source_t& source, std::uint64_t instruction_total,
    std::uint64_t stream_bytes, std::uint64_t maximum_records,
    const cancellation_token_t& cancel) {
    if (instruction_total == 0 || instruction_total > maximum_records)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged instruction domain record count is inconsistent"));
    std::uint64_t record_bytes = 0;
    std::uint64_t tail_offset = 0;
    if (!checked_mul_u64(instruction_total, kPackedInstructionRecordBytes,
            record_bytes) ||
        !checked_add_u64(packed_domain_stream_header_bytes, record_bytes,
            tail_offset) ||
        tail_offset > stream_bytes ||
        stream_bytes - tail_offset < sizeof(std::uint64_t) ||
        stream_bytes - tail_offset > sizeof(std::uint64_t) + instruction_total)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged instruction delay-slot tail is out of range"));
    const std::uint64_t tail_span = stream_bytes - tail_offset;
    std::uint64_t accumulated = 0;
    std::uint64_t page_ordinal = source.page_count(fact_domain_t::instructions);
    std::vector<std::vector<std::uint8_t>> tail_pages;
    try {
        while (accumulated < tail_span) {
            if (page_ordinal == 0)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                        "packed paged instruction delay-slot tail is truncated"));
            --page_ordinal;
            auto content = source.fetch_page_content(
                fact_domain_t::instructions, page_ordinal, cancel);
            if (!content)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    content.error());
            const auto page_bytes =
                static_cast<std::uint64_t>(content.value().size());
            if (page_bytes > stream_bytes - accumulated)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                        "packed paged instruction domain content grew during reopen"));
            accumulated += page_bytes;
            tail_pages.push_back(content.take_value());
        }
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                "packed paged instruction delay-slot tail allocation failed"));
    }
    if (page_ordinal == 0 && accumulated != stream_bytes)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged instruction domain content does not match its index"));
    std::vector<std::uint8_t> tail;
    try {
        tail.resize(static_cast<std::size_t>(tail_span));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::limit_exceeded,
                "packed paged instruction delay-slot tail allocation failed"));
    }
    std::uint64_t written = 0;
    for (auto page = tail_pages.rbegin();
         page != tail_pages.rend() && written < tail_span; ++page) {
        const std::uint64_t take = (std::min)(
            static_cast<std::uint64_t>(page->size()), tail_span - written);
        std::memcpy(tail.data() + tail_span - written - take,
                    page->data() + page->size() - take,
                    static_cast<std::size_t>(take));
        written += take;
    }
    if (written != tail_span)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged instruction delay-slot tail is truncated"));
    std::uint64_t tail_records = 0;
    packed_payload_reader_t reader(tail, cancel, maximum_records, &tail_records);
    const auto count = reader.count();
    std::vector<std::uint8_t> values;
    if (count != 0) {
        if (static_cast<std::uint64_t>(count) != instruction_total)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                packed_baseline_error(workspace_error_code_t::integrity_failure,
                    "packed paged instruction delay-slot count does not align with instructions"));
        try {
            values.reserve(count);
            for (std::size_t index = 0; index < count; ++index)
                values.push_back(reader.u8());
        } catch (const std::bad_alloc&) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                packed_baseline_error(workspace_error_code_t::limit_exceeded,
                    "packed paged instruction delay-slot tail allocation failed"));
        }
    }
    auto finished = reader.finish();
    if (!finished)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(
            finished.error());
    return workspace_result_t<std::vector<std::uint8_t>>::success(
        std::move(values));
}

class packed_reopen_admission_t final {
public:
    explicit packed_reopen_admission_t(std::uint64_t budget) : budget_(budget) {}

    packed_reopen_admission_t(const packed_reopen_admission_t&) = delete;
    packed_reopen_admission_t& operator=(const packed_reopen_admission_t&) = delete;

    class permit_t final {
    public:
        permit_t(packed_reopen_admission_t& gate, std::uint64_t bytes)
            : gate_(&gate), bytes_(bytes) {
            std::unique_lock<std::mutex> lock(gate.mutex_);
            gate.cv_.wait(lock, [&] {
                return gate.admitted_bytes_ == 0 ||
                       (gate.admitted_bytes_ <= gate.budget_ &&
                        bytes <= gate.budget_ - gate.admitted_bytes_);
            });
            gate.admitted_bytes_ += bytes;
        }

        ~permit_t() {
            std::lock_guard<std::mutex> lock(gate_->mutex_);
            gate_->admitted_bytes_ -= bytes_;
            gate_->cv_.notify_all();
        }

        permit_t(const permit_t&) = delete;
        permit_t& operator=(const permit_t&) = delete;

    private:
        packed_reopen_admission_t* gate_;
        std::uint64_t bytes_;
    };

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::uint64_t admitted_bytes_ = 0;
    std::uint64_t budget_ = 0;
};

struct packed_domain_range_output_t {
    std::vector<std::uint8_t> bytes;
    std::uint64_t first_ordinal = 0;
    std::uint64_t next_ordinal = 0;
    std::uint32_t pages_seen = 0;
    paged_domain_revision_tag_t revision_tag;
    std::optional<workspace_error_t> error;
};

workspace_result_t<void> read_packed_domain_page_range(
    sqlite3* database, const packed_generation_record_t& generation,
    packed_page_type_t domain, std::uint32_t page_begin, std::uint32_t page_end,
    packed_domain_range_output_t& output, std::uint64_t maximum_bytes,
    const cancellation_token_t& cancel) {
    const auto encoded_domain = static_cast<std::uint32_t>(domain);
    output.revision_tag.generation = generation.generation;
    output.revision_tag.analysis_revision = generation.analysis_revision;
    output.revision_tag.overlay_revision = generation.overlay_revision;
    statement_t statement;
    auto prepared = statement.prepare(database, R"SQL(
SELECT p.generation,p.page_index,p.page_count,p.page_type,p.payload_length,p.checksum,p.payload,
       i.domain,i.ordinal_begin,i.count,i.address_value_min,i.address_value_max,p.logical_length
FROM packed_pages p
JOIN packed_page_index i ON i.generation=p.generation AND i.page_index=p.page_index
JOIN packed_generations g ON g.generation=p.generation AND g.committed=1
WHERE p.generation=?1 AND p.page_type=?2 AND p.page_index>=?3 AND p.page_index<?4
ORDER BY p.page_index
)SQL", "workspace_database.load.packed_range");
    if (!prepared)
        return prepared;
    auto result = statement.bind_uint(1, generation.generation);
    if (result) result = statement.bind_int(2, encoded_domain);
    if (result) result = statement.bind_int(3, page_begin);
    if (result) result = statement.bind_int(4, page_end);
    if (!result)
        return result;
    bool first_page = true;
    std::uint64_t accumulated_bytes = 0;
    for (;;) {
        if (cancel.stop_requested())
            return workspace_result_t<void>::failure(
                packed_baseline_cancelled(cancel));
        const int status = sqlite3_step(statement.get());
        if (status == SQLITE_DONE)
            break;
        if (status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(database_error(
                database, status, "unable to read packed domain page range",
                "workspace_database.load.packed_range"));
        }
        packed_page_row_t page;
        page.generation = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 0));
        page.page_index = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 1));
        page.page_count = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 2));
        page.page_type = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 3));
        page.payload_length = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 4));
        page.checksum = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 5));
        const void* blob = sqlite3_column_blob(statement.get(), 6);
        const int blob_size = sqlite3_column_bytes(statement.get(), 6);
        packed_page_index_row_t index;
        index.generation = page.generation;
        index.domain = static_cast<std::uint16_t>(
            sqlite3_column_int(statement.get(), 7));
        index.ordinal_begin = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 8));
        index.count = static_cast<std::uint32_t>(
            sqlite3_column_int64(statement.get(), 9));
        index.page_index = page.page_index;
        index.address_value_min = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 10));
        index.address_value_max = static_cast<std::uint64_t>(
            sqlite3_column_int64(statement.get(), 11));
        std::uint32_t logical_length = 0;
        if (sqlite3_column_type(statement.get(), 12) != SQLITE_NULL) {
            const auto declared_logical_length =
                sqlite3_column_int64(statement.get(), 12);
            if (declared_logical_length <
                    static_cast<std::int64_t>(packed_record_page_prefix_size) ||
                declared_logical_length >
                    static_cast<std::int64_t>(packed_page_max_payload)) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "packed domain page logical length is invalid"));
            }
            logical_length = static_cast<std::uint32_t>(declared_logical_length);
        }
        page.logical_length = logical_length;
        if (blob_size < static_cast<int>(packed_record_page_prefix_size) ||
            blob_size > static_cast<int>(packed_page_max_payload) || !blob ||
            page.payload_length != static_cast<std::uint32_t>(blob_size) ||
            page.page_index != page_begin + output.pages_seen ||
            page.page_type != encoded_domain) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "packed domain page range row is malformed"));
        }
        page.payload.assign(static_cast<const std::uint8_t*>(blob),
                            static_cast<const std::uint8_t*>(blob) + blob_size);
        auto prefix = packed_record_page_prefix_t::decode(
            page.payload.data(), page.payload.size());
        if (!prefix || index.domain != encoded_domain ||
            index.ordinal_begin != prefix->ordinal_begin ||
            index.count != prefix->record_count ||
            index.address_value_min != prefix->address_value_min ||
            index.address_value_max != prefix->address_value_max) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "packed domain page range index is inconsistent"));
        }
        packed_page_t decoded_page;
        decoded_page.header.generation = page.generation;
        decoded_page.header.analysis_revision = generation.analysis_revision;
        decoded_page.header.overlay_revision = generation.overlay_revision;
        decoded_page.header.version = logical_length != 0
            ? packed_page_blob_version_v3 : packed_page_blob_version;
        decoded_page.header.page_type = page.page_type;
        decoded_page.header.page_index = page.page_index;
        decoded_page.header.page_count = page.page_count;
        decoded_page.header.payload_length = page.payload_length;
        decoded_page.header.checksum = page.checksum;
        decoded_page.payload = std::move(page.payload);
        auto content = packed_page_codec_t::decode_page_content(
            decoded_page, [&cancel] { return cancel.stop_requested(); });
        if (!content)
            return workspace_result_t<void>::failure(content.error());
        if (logical_length != 0 &&
            content.value().size() + packed_record_page_prefix_size !=
                logical_length) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "packed domain page logical length does not match its frame"));
        }
        if (first_page) {
            output.first_ordinal = index.ordinal_begin;
            output.next_ordinal = index.ordinal_begin;
            first_page = false;
        }
        if (index.ordinal_begin != output.next_ordinal ||
            !checked_add_u64(output.next_ordinal, index.count,
                             output.next_ordinal)) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "packed domain record ordinals are not contiguous"));
        }
        if (!checked_add_u64(accumulated_bytes, content.value().size(),
                             accumulated_bytes) ||
            accumulated_bytes > maximum_bytes ||
            accumulated_bytes > static_cast<std::uint64_t>(
                (std::numeric_limits<std::size_t>::max)())) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::limit_exceeded,
                    "packed domain exceeds its bounded reopen budget"));
        }
        try {
            output.bytes.reserve(accumulated_bytes);
            output.bytes.insert(
                output.bytes.end(),
                std::make_move_iterator(content.value().begin()),
                std::make_move_iterator(content.value().end()));
        } catch (const std::bad_alloc&) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::limit_exceeded,
                    "packed domain reopen allocation failed"));
        }
        ++output.pages_seen;
    }
    if (page_begin + output.pages_seen != page_end) {
        return workspace_result_t<void>::failure(
            packed_baseline_error(
                workspace_error_code_t::integrity_failure,
                "packed domain page range is truncated"));
    }
    return workspace_result_t<void>::success();
}

struct packed_stride_segment_t {
    std::uint64_t count = 0;
    std::uint64_t stride = 0;
    std::uint64_t byte_offset = 0;
};

struct packed_stride_layout_t {
    std::array<packed_stride_segment_t, 2> segments{};
    std::size_t segment_count = 0;
};

std::optional<packed_stride_layout_t> packed_domain_stride_layout(
    packed_page_type_t domain, const std::vector<std::uint8_t>& payload,
    std::uint64_t maximum_records, const cancellation_token_t& cancel) {
    packed_stride_layout_t layout;
    packed_payload_reader_t reader(payload, cancel, maximum_records);
    read_domain_header(reader, domain);
    if (reader.failed())
        return std::nullopt;
    const auto single_segment = [&](std::uint64_t stride) -> bool {
        const auto count = reader.count();
        if (reader.failed())
            return false;
        std::uint64_t expected = 0;
        if (!checked_mul_u64(count, stride, expected) ||
            expected != reader.remaining_bytes())
            return false;
        layout.segments[0] = {count, stride,
                              static_cast<std::uint64_t>(reader.offset())};
        layout.segment_count = 1;
        return true;
    };
    const auto dual_segment = [&](std::uint64_t first_stride,
                                  std::uint64_t second_stride) -> bool {
        const auto count = reader.count();
        if (reader.failed())
            return false;
        std::uint64_t first_bytes = 0;
        if (!checked_mul_u64(count, first_stride, first_bytes))
            return false;
        layout.segments[0] = {count, first_stride,
                              static_cast<std::uint64_t>(reader.offset())};
        reader.skip_bytes(first_bytes);
        if (reader.failed())
            return false;
        const auto second_offset = static_cast<std::uint64_t>(reader.offset());
        const auto second_count = reader.count();
        if (reader.failed())
            return false;
        std::uint64_t second_bytes = 0;
        if (!checked_mul_u64(second_count, second_stride, second_bytes) ||
            second_bytes != reader.remaining_bytes())
            return false;
        layout.segments[1] = {second_count, second_stride,
                              second_offset + sizeof(std::uint64_t)};
        layout.segment_count = 2;
        return true;
    };
    bool laid_out = false;
    switch (domain) {
    case packed_page_type_t::instructions:
        laid_out = dual_segment(kPackedInstructionRecordBytes, 1);
        break;
    case packed_page_type_t::operands:
        laid_out = single_segment(kPackedOperandRecordBytes);
        break;
    case packed_page_type_t::target_facts:
        laid_out = single_segment(kPackedTargetRecordBytes);
        break;
    case packed_page_type_t::edges: {
        const auto count = reader.count();
        if (reader.failed() || count == 0)
            return std::nullopt;
        const std::uint64_t remaining = reader.remaining_bytes();
        if (remaining % count != 0)
            return std::nullopt;
        const std::uint64_t stride = remaining / count;
        if (stride != kPackedEdgeRecordMinBytes &&
            stride != kPackedEdgeRecordMaxBytes)
            return std::nullopt;
        layout.segments[0] = {count, stride,
                              static_cast<std::uint64_t>(reader.offset())};
        layout.segment_count = 1;
        laid_out = true;
        break;
    }
    case packed_page_type_t::basic_blocks:
        laid_out = single_segment(kPackedBasicBlockRecordBytes);
        break;
    case packed_page_type_t::functions: {
        const auto count = reader.count();
        if (reader.failed() || count == 0)
            return std::nullopt;
        const std::uint64_t remaining = reader.remaining_bytes();
        if (remaining % count != 0)
            return std::nullopt;
        const std::uint64_t stride = remaining / count;
        if (stride < kPackedFunctionRecordMinBytes)
            return std::nullopt;
        layout.segments[0] = {count, stride,
                              static_cast<std::uint64_t>(reader.offset())};
        layout.segment_count = 1;
        laid_out = true;
        break;
    }
    case packed_page_type_t::function_chunks:
        laid_out = dual_segment(kPackedFunctionChunkRecordBytes,
                                kPackedFunctionMembershipRecordBytes);
        break;
    case packed_page_type_t::xrefs:
        laid_out = single_segment(kPackedXrefRecordBytes);
        break;
    case packed_page_type_t::address_expressions:
        laid_out = single_segment(kPackedAddressExpressionRecordBytes);
        break;
    case packed_page_type_t::coverage:
        laid_out = single_segment(kPackedCoverageRecordBytes);
        break;
    default:
        return std::nullopt;
    }
    if (!laid_out)
        return std::nullopt;
    std::uint64_t total_records = 0;
    bool engaged = false;
    for (std::size_t segment = 0; segment < layout.segment_count; ++segment) {
        if (!checked_add_u64(total_records, layout.segments[segment].count,
                             total_records) ||
            total_records > maximum_records)
            return std::nullopt;
        if (layout.segments[segment].count >= kReopenStrideMinRecords)
            engaged = true;
    }
    if (!engaged)
        return std::nullopt;
    return layout;
}

workspace_result_t<void> decode_packed_domain_segment_range(
    packed_page_type_t domain, std::size_t segment_index,
    const std::vector<std::uint8_t>& payload,
    const packed_stride_segment_t& segment,
    std::uint64_t ordinal_begin, std::uint64_t ordinal_end,
    std::uint64_t maximum_records, analysis_snapshot_t& output,
    std::uint64_t& decoded_records,
    const cancellation_token_t& cancel) {
    std::uint64_t sub_records = 0;
    packed_payload_reader_t reader(payload, cancel, maximum_records,
                                   &sub_records);
    reader.skip_bytes(segment.byte_offset + ordinal_begin * segment.stride);
    if (reader.failed())
        return reader.finish();
    std::uint64_t ordinal_current = ordinal_begin;
    const auto misaligned = []() {
        return workspace_result_t<void>::failure(
            packed_baseline_error(
                workspace_error_code_t::integrity_failure,
                "packed domain stride decode lost record alignment"));
    };
    const auto aligned = [&]() {
        return !reader.failed() &&
               reader.offset() == segment.byte_offset +
                   (ordinal_current + 1ULL) * segment.stride;
    };
    switch (domain) {
    case packed_page_type_t::instructions:
        if (segment_index == 0) {
            output.instructions.reserve(ordinal_end - ordinal_begin);
            for (; ordinal_current < ordinal_end; ++ordinal_current) {
                output.instructions.push_back(read_instruction(reader));
                if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
            }
        } else {
            output.delay_slot_counts.reserve(ordinal_end - ordinal_begin);
            for (; ordinal_current < ordinal_end; ++ordinal_current) {
                output.delay_slot_counts.push_back(reader.u8());
                if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
            }
        }
        break;
    case packed_page_type_t::operands:
        output.operand_facts.hot.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            snapshot_operand_append(output, read_operand(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::target_facts:
        output.target_facts.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.target_facts.push_back(read_target(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::edges:
        output.edges.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.edges.push_back(read_edge(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::basic_blocks:
        output.blocks.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.blocks.push_back(read_block(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::functions:
        output.functions.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.functions.push_back(read_function(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::function_chunks:
        if (segment_index == 0) {
            output.function_chunks.reserve(ordinal_end - ordinal_begin);
            for (; ordinal_current < ordinal_end; ++ordinal_current) {
                output.function_chunks.push_back(read_function_chunk(reader));
                if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
            }
        } else {
            output.function_block_memberships.reserve(ordinal_end - ordinal_begin);
            for (; ordinal_current < ordinal_end; ++ordinal_current) {
                output.function_block_memberships.push_back(
                    read_function_membership(reader));
                if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
            }
        }
        break;
    case packed_page_type_t::xrefs:
        output.xrefs.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.xrefs.push_back(read_xref(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::address_expressions:
        output.address_expressions.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.address_expressions.push_back(read_address_expression(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    case packed_page_type_t::coverage:
        output.coverage.reserve(ordinal_end - ordinal_begin);
        for (; ordinal_current < ordinal_end; ++ordinal_current) {
            output.coverage.push_back(read_coverage(reader));
            if (!aligned()) return reader.failed() ? reader.finish() : misaligned();
        }
        break;
    default:
        return workspace_result_t<void>::failure(
            packed_baseline_error(workspace_error_code_t::invalid_argument,
                                  "packed baseline stride domain is unsupported"));
    }
    decoded_records = (ordinal_end - ordinal_begin) + sub_records;
    return workspace_result_t<void>::success();
}

std::optional<packed_page_type_t> paged_view_packed_domain(
    fact_domain_t domain) noexcept {
    switch (domain) {
    case fact_domain_t::instructions:
        return packed_page_type_t::instructions;
    case fact_domain_t::operand_facts:
        return packed_page_type_t::operands;
    case fact_domain_t::target_facts:
        return packed_page_type_t::target_facts;
    case fact_domain_t::edges:
        return packed_page_type_t::edges;
    case fact_domain_t::xrefs:
        return packed_page_type_t::xrefs;
    default:
        return std::nullopt;
    }
}

std::optional<fact_domain_t> paged_view_fact_domain(
    packed_page_type_t domain) noexcept {
    switch (domain) {
    case packed_page_type_t::instructions:
        return fact_domain_t::instructions;
    case packed_page_type_t::operands:
        return fact_domain_t::operand_facts;
    case packed_page_type_t::target_facts:
        return fact_domain_t::target_facts;
    case packed_page_type_t::edges:
        return fact_domain_t::edges;
    case packed_page_type_t::xrefs:
        return fact_domain_t::xrefs;
    default:
        return std::nullopt;
    }
}

class database_page_source_t final : public paged_domain_source_t {
public:
    database_page_source_t(
        std::string path, workspace_database_options_t options,
        packed_generation_record_t generation,
        std::array<std::vector<packed_page_index_row_t>, 20> domain_pages,
        std::array<std::uint64_t, 20> domain_records,
        std::array<std::uint64_t, 20> logical_bytes,
        std::uint64_t content_page_bytes,
        bool require_committed_generation = true)
        : path_(std::move(path)), options_(std::move(options)),
          generation_(std::move(generation)),
          domain_pages_(std::move(domain_pages)),
          domain_records_(std::move(domain_records)),
          logical_bytes_(std::move(logical_bytes)),
          content_page_bytes_(content_page_bytes),
          require_committed_generation_(require_committed_generation) {}

    ~database_page_source_t() override {
        if (reader_connection_ != nullptr) {
            sqlite_statement_cache_unregister(reader_connection_);
            reader_statements_.reset();
            sqlite3_close_v2(reader_connection_);
            reader_connection_ = nullptr;
        }
    }

    std::uint64_t record_count(fact_domain_t domain) const noexcept override {
        const auto packed = paged_view_packed_domain(domain);
        if (!packed)
            return 0;
        return domain_records_[static_cast<std::size_t>(*packed)];
    }

    std::uint64_t page_count(fact_domain_t domain) const noexcept override {
        const auto packed = paged_view_packed_domain(domain);
        if (!packed)
            return 0;
        return domain_pages_[static_cast<std::size_t>(*packed)].size();
    }

    std::uint64_t content_page_bytes() const noexcept override {
        return content_page_bytes_;
    }

    std::uint64_t total_content_bytes(fact_domain_t domain) const noexcept override {
        const auto packed = paged_view_packed_domain(domain);
        if (!packed)
            return 0;
        return logical_bytes_[static_cast<std::size_t>(*packed)];
    }

    workspace_result_t<paged_fact_page_meta_t> page_meta(
        fact_domain_t domain, std::uint64_t page_ordinal,
        const cancellation_token_t& cancel) const override {
        if (cancel.stop_requested())
            return workspace_result_t<paged_fact_page_meta_t>::failure(
                packed_baseline_cancelled(cancel));
        const auto packed = paged_view_packed_domain(domain);
        if (!packed) {
            return workspace_result_t<paged_fact_page_meta_t>::failure(
                packed_baseline_error(workspace_error_code_t::invalid_argument,
                    "database page source domain is unsupported"));
        }
        const auto& rows = domain_pages_[static_cast<std::size_t>(*packed)];
        if (page_ordinal >= rows.size()) {
            return workspace_result_t<paged_fact_page_meta_t>::failure(
                packed_baseline_error(workspace_error_code_t::range_overflow,
                    "database page source page ordinal is out of range"));
        }
        const auto& row = rows[static_cast<std::size_t>(page_ordinal)];
        paged_fact_page_meta_t meta;
        meta.ordinal_begin = row.ordinal_begin;
        meta.record_count = row.count;
        meta.address_value_min = row.address_value_min;
        meta.address_value_max = row.address_value_max;
        return workspace_result_t<paged_fact_page_meta_t>::success(meta);
    }

    workspace_result_t<std::vector<std::uint8_t>> fetch_page_content(
        fact_domain_t domain, std::uint64_t page_ordinal,
        const cancellation_token_t& cancel) const override {
        if (cancel.stop_requested()) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                packed_baseline_cancelled(cancel));
        }
        const auto packed = paged_view_packed_domain(domain);
        if (!packed) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                packed_baseline_error(workspace_error_code_t::invalid_argument,
                    "database page source domain is unsupported"));
        }
        const auto& rows = domain_pages_[static_cast<std::size_t>(*packed)];
        if (page_ordinal >= rows.size()) {
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                packed_baseline_error(workspace_error_code_t::range_overflow,
                    "database page source page ordinal is out of range"));
        }
        const std::uint32_t page_index =
            rows[static_cast<std::size_t>(page_ordinal)].page_index;
        packed_page_t decoded_page;
        std::int64_t logical_length = 0;
        {
            std::lock_guard<std::mutex> connection_lock(connection_mutex_);
            if (reader_connection_ == nullptr) {
                auto opened = open_reader_connection(path_, options_);
                if (!opened)
                    return workspace_result_t<std::vector<std::uint8_t>>::failure(
                        opened.error());
                reader_connection_ = opened.take_value();
                reader_statements_ = std::make_shared<sqlite_statement_cache_t>(8);
                sqlite_statement_cache_register(reader_connection_,
                                                reader_statements_);
            }
            sqlite3* database = reader_connection_;
            statement_t statement;
            auto prepared = require_committed_generation_
                ? statement.prepare(database, R"SQL(
SELECT p.page_count,p.payload_length,p.checksum,p.payload,COALESCE(p.logical_length,0)
FROM packed_pages p
JOIN packed_generations g ON g.generation=p.generation AND g.committed=1
WHERE p.generation=?1 AND p.page_index=?2
)SQL", "workspace_database.load.packed_page")
                : statement.prepare(database, R"SQL(
SELECT p.page_count,p.payload_length,p.checksum,p.payload,COALESCE(p.logical_length,0)
FROM packed_pages p
WHERE p.generation=?1 AND p.page_index=?2
)SQL", "workspace_database.load.packed_page");
            if (!prepared)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    prepared.error());
            auto bound = statement.bind_uint(1, generation_.generation);
            if (bound)
                bound = statement.bind_uint(2, page_index);
            if (!bound)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(bound.error());
            const int status = sqlite3_step(statement.get());
            if (status != SQLITE_ROW)
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                        "database page source page is missing"));
            decoded_page.header.generation = generation_.generation;
            decoded_page.header.analysis_revision = generation_.analysis_revision;
            decoded_page.header.overlay_revision = generation_.overlay_revision;
            decoded_page.header.page_count = static_cast<std::uint32_t>(
                sqlite3_column_int64(statement.get(), 0));
            decoded_page.header.payload_length = static_cast<std::uint32_t>(
                sqlite3_column_int64(statement.get(), 1));
            decoded_page.header.checksum = static_cast<std::uint32_t>(
                sqlite3_column_int64(statement.get(), 2));
            const void* blob = sqlite3_column_blob(statement.get(), 3);
            const int blob_size = sqlite3_column_bytes(statement.get(), 3);
            logical_length = sqlite3_column_int64(statement.get(), 4);
            decoded_page.header.page_type = static_cast<std::uint32_t>(*packed);
            decoded_page.header.page_index = page_index;
            if (!blob || blob_size < static_cast<int>(packed_record_page_prefix_size) ||
                blob_size > static_cast<int>(packed_page_max_payload) ||
                decoded_page.header.payload_length != static_cast<std::uint32_t>(blob_size) ||
                logical_length < 0 ||
                logical_length > static_cast<std::int64_t>(packed_page_max_payload))
                return workspace_result_t<std::vector<std::uint8_t>>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                        "database page source page row is malformed"));
            decoded_page.payload.assign(static_cast<const std::uint8_t*>(blob),
                                        static_cast<const std::uint8_t*>(blob) + blob_size);
        }
        decoded_page.header.version = logical_length == 0
            ? packed_page_blob_version
            : packed_page_blob_version_v3;
        auto decoded_content = packed_page_codec_t::decode_page_content(
            decoded_page, [&cancel] { return cancel.stop_requested(); });
        if (!decoded_content)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(
                decoded_content.error());
        return workspace_result_t<std::vector<std::uint8_t>>::success(
            decoded_content.take_value());
    }

private:
    std::string path_;
    workspace_database_options_t options_;
    packed_generation_record_t generation_;
    std::array<std::vector<packed_page_index_row_t>, 20> domain_pages_;
    std::array<std::uint64_t, 20> domain_records_;
    std::array<std::uint64_t, 20> logical_bytes_{};
    std::uint64_t content_page_bytes_ = 0;
    bool require_committed_generation_ = true;
    mutable std::mutex connection_mutex_;
    mutable sqlite3* reader_connection_ = nullptr;
    mutable std::shared_ptr<sqlite_statement_cache_t> reader_statements_;
};

workspace_result_t<std::uint64_t> read_paged_domain_stream_record_count(
    sqlite3* database, const packed_generation_record_t& generation,
    std::uint32_t encoded_domain, std::uint32_t first_page_index,
    const cancellation_token_t& cancel) {
    statement_t statement;
    auto prepared = statement.prepare(database,
        "SELECT payload,COALESCE(logical_length,0),checksum,payload_length,page_count FROM packed_pages WHERE generation=?1 AND page_index=?2",
        "workspace_database.load.packed_page");
    if (!prepared)
        return workspace_result_t<std::uint64_t>::failure(prepared.error());
    auto bound = statement.bind_uint(1, generation.generation);
    if (bound)
        bound = statement.bind_uint(2, first_page_index);
    if (!bound)
        return workspace_result_t<std::uint64_t>::failure(bound.error());
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        return workspace_result_t<std::uint64_t>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged domain first page is missing"));
    }
    const void* blob = sqlite3_column_blob(statement.get(), 0);
    const int blob_size = sqlite3_column_bytes(statement.get(), 0);
    const auto logical_length = sqlite3_column_int64(statement.get(), 1);
    const auto stored_checksum = static_cast<std::uint32_t>(
        sqlite3_column_int64(statement.get(), 2));
    const auto stored_payload_length = static_cast<std::uint32_t>(
        sqlite3_column_int64(statement.get(), 3));
    const auto stored_page_count = static_cast<std::uint32_t>(
        sqlite3_column_int64(statement.get(), 4));
    if (!blob || blob_size <
            static_cast<int>(packed_record_page_prefix_size +
                             packed_domain_stream_header_bytes) ||
        blob_size > static_cast<int>(packed_page_max_payload) ||
        stored_payload_length != static_cast<std::uint32_t>(blob_size) ||
        logical_length < 0 ||
        logical_length > static_cast<std::int64_t>(packed_page_max_payload)) {
        return workspace_result_t<std::uint64_t>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged domain first page is truncated"));
    }
    packed_page_t page;
    page.header.generation = generation.generation;
    page.header.analysis_revision = generation.analysis_revision;
    page.header.overlay_revision = generation.overlay_revision;
    page.header.version = logical_length == 0
        ? packed_page_blob_version
        : packed_page_blob_version_v3;
    page.header.page_type = encoded_domain;
    page.header.page_index = first_page_index;
    page.header.page_count = stored_page_count;
    page.header.payload_length = stored_payload_length;
    page.header.checksum = stored_checksum;
    page.payload.assign(static_cast<const std::uint8_t*>(blob),
                        static_cast<const std::uint8_t*>(blob) + blob_size);
    auto decoded = packed_page_codec_t::decode_page_content(
        page, [&cancel] { return cancel.stop_requested(); });
    if (!decoded)
        return workspace_result_t<std::uint64_t>::failure(decoded.error());
    if (decoded.value().size() < packed_domain_stream_header_bytes) {
        return workspace_result_t<std::uint64_t>::failure(
            packed_baseline_error(workspace_error_code_t::integrity_failure,
                "packed paged domain first page header is truncated"));
    }
    std::uint64_t record_count = 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
        record_count |= static_cast<std::uint64_t>(
            decoded.value()[8 + shift / 8]) << shift;
    }
    return workspace_result_t<std::uint64_t>::success(record_count);
}

workspace_result_t<void> bind_committed_page_source(
    sqlite3* database,
    workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const std::shared_ptr<workspace_snapshot_staging_t::state_t>& staging,
    const packed_generation_record_t& generation_record,
    const cancellation_token_t& cancel) {
    std::array<bool, 20> domain_paged{};
    bool any_paged = false;
    for (std::size_t index = 0; index < fact_domain_count; ++index) {
        if (staging->snapshot->paged_domain_counts[index] == 0)
            continue;
        const auto packed = paged_view_packed_domain(
            static_cast<fact_domain_t>(index));
        if (!packed)
            continue;
        domain_paged[static_cast<std::size_t>(*packed)] = true;
        any_paged = true;
    }
    if (!any_paged)
        return workspace_result_t<void>::success();
    std::array<packed_domain_page_stats_t, 20> domain_stats{};
    auto stats = read_packed_domain_page_stats(
        database, staging->generation, domain_stats, cancel);
    if (!stats)
        return workspace_result_t<void>::failure(stats.error());
    auto index_rows = read_packed_page_index(
        database, staging->generation, false,
        [&cancel] { return cancel.stop_requested(); });
    if (!index_rows)
        return workspace_result_t<void>::failure(index_rows.error());
    std::array<std::vector<packed_page_index_row_t>, 20> page_rows{};
    std::array<std::uint64_t, 20> domain_records{};
    std::array<std::uint64_t, 20> domain_content_bytes{};
    for (auto& row : index_rows.value()) {
        const auto fact_domain = paged_view_fact_domain(
            static_cast<packed_page_type_t>(row.domain));
        if (!fact_domain || !domain_paged[static_cast<std::size_t>(row.domain)])
            continue;
        page_rows[static_cast<std::size_t>(row.domain)].push_back(row);
    }
    for (std::size_t encoded = 1; encoded < page_rows.size(); ++encoded) {
        if (!domain_paged[encoded])
            continue;
        auto& rows = page_rows[encoded];
        std::sort(rows.begin(), rows.end(),
            [](const packed_page_index_row_t& lhs,
               const packed_page_index_row_t& rhs) {
                return lhs.ordinal_begin < rhs.ordinal_begin;
            });
        std::uint64_t expected_ordinal = 0;
        bool contiguous = true;
        for (const auto& row : rows) {
            if (row.ordinal_begin != expected_ordinal) {
                contiguous = false;
                break;
            }
            expected_ordinal += row.count;
        }
        if (!contiguous || rows.empty() || !domain_stats[encoded].present) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "committed packed paged domain page index is inconsistent"));
        }
        const auto fact_domain = *paged_view_fact_domain(
            static_cast<packed_page_type_t>(encoded));
        auto record_count = read_paged_domain_stream_record_count(
            database, generation_record, static_cast<std::uint32_t>(encoded),
            rows.front().page_index, cancel);
        if (!record_count)
            return workspace_result_t<void>::failure(record_count.error());
        if (record_count.value() != staging->snapshot->paged_domain_counts[
                static_cast<std::size_t>(fact_domain)]) {
            return workspace_result_t<void>::failure(
                packed_baseline_error(
                    workspace_error_code_t::integrity_failure,
                    "committed packed paged domain record count is inconsistent"));
        }
        domain_records[encoded] = record_count.value();
        const auto logical = domain_stats[encoded].logical_bytes;
        const auto prefixes = static_cast<std::uint64_t>(rows.size()) *
            packed_record_page_prefix_size;
        domain_content_bytes[encoded] = logical >= prefixes ? logical - prefixes : 0;
    }
    auto committed_page_source = std::shared_ptr<const paged_domain_source_t>(
        new database_page_source_t(conn.path, options, generation_record,
                                   std::move(page_rows),
                                   std::move(domain_records),
                                   std::move(domain_content_bytes),
                                   options.packed_stream_page_size -
                                       packed_page_header_size -
                                       packed_record_page_prefix_size,
                                   false));
    std::atomic_store_explicit(&staging->snapshot->persisted_page_source.source,
                               std::move(committed_page_source),
                               std::memory_order_release);
    return workspace_result_t<void>::success();
}

workspace_result_t<decoded_packed_baseline_t> decode_packed_baseline_generation(
    const workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    const packed_generation_record_t& generation,
    std::shared_ptr<const workspace_image_t> normalized_image,
    std::shared_ptr<const pe_image_t> pe_adapter,
    const workspace_identity_t& identity,
    std::uint64_t maximum_records,
    std::uint64_t maximum_domain_bytes,
    const cancellation_token_t& cancel) {
    auto decoded_manifest = decode_packed_baseline_manifest(
        generation.payload_blob, cancel);
    if (!decoded_manifest)
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            decoded_manifest.error());
    auto manifest = decoded_manifest.take_value();
    if (manifest.generation != generation.generation ||
        manifest.analysis_revision != generation.analysis_revision ||
        manifest.overlay_revision != generation.overlay_revision ||
        (generation.shard_count !=
             static_cast<std::uint16_t>(packed_page_baseline_last_data_type) &&
         generation.shard_count !=
             static_cast<std::uint16_t>(packed_page_last_data_type)) ||
        generation.total_records > maximum_records ||
        generation.total_payload_bytes > maximum_domain_bytes) {
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            packed_baseline_error(
                workspace_error_code_t::integrity_failure,
                "packed baseline generation metadata is inconsistent"));
    }
    if (manifest.generation == 0 ||
        !manifest.binary_id.constant_time_equal(identity.binary_id()) ||
        !manifest.load_profile_hash.constant_time_equal(
            identity.load_profile_hash()) ||
        manifest.required_domains != kPackedBaselineRequiredDomains) {
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            packed_baseline_error(
                workspace_error_code_t::target_conflict,
                "packed baseline manifest does not match the workspace identity"));
    }
    const auto& tasks = packed_reopen_domain_tasks();
    const auto hardware = std::thread::hardware_concurrency();
    const std::uint32_t reopen_lanes =
        (std::max)(2U, (std::min)(16U, hardware == 0 ? 2U : hardware));
    constexpr std::uint32_t baseline_domain_count =
        static_cast<std::uint32_t>(packed_page_baseline_last_data_type);
    std::array<packed_domain_page_stats_t, 20> domain_stats{};
    {
        auto stats_connection = open_reader_connection(conn.path, options);
        if (!stats_connection) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                stats_connection.error());
        }
        sqlite3* stats_database = stats_connection.take_value();
        auto stats = read_packed_domain_page_stats(
            stats_database, generation.generation, domain_stats, cancel);
        sqlite3_close_v2(stats_database);
        if (!stats) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                stats.error());
        }
    }
    std::array<bool, 20> domain_materialized{};
    bool any_materialized = false;
    for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
         ++encoded) {
        if (static_cast<packed_page_type_t>(encoded) ==
            packed_page_type_t::search_index)
            continue;
        domain_materialized[encoded] =
            domain_stats[encoded].present &&
            domain_stats[encoded].page_count >= kReopenParallelMinPages;
        any_materialized = any_materialized || domain_materialized[encoded];
    }
    std::array<fact_domain_projection_t, fact_domain_count> reopen_projections{};
    for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
         ++encoded) {
        const auto fact_domain =
            paged_view_fact_domain(static_cast<packed_page_type_t>(encoded));
        if (!fact_domain || !domain_stats[encoded].present)
            continue;
        reopen_projections[static_cast<std::size_t>(*fact_domain)] = {
            1, reopen_resident_projection_bytes(
                   static_cast<packed_page_type_t>(encoded),
                   domain_stats[encoded].logical_bytes)};
    }
    const auto reopen_plan = fact_residency_select(reopen_projections,
        fact_resident_budget_bytes(host_memory_envelope()));
    std::array<bool, 20> domain_paged{};
    bool any_paged = false;
    for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
         ++encoded) {
        const auto fact_domain =
            paged_view_fact_domain(static_cast<packed_page_type_t>(encoded));
        if (!fact_domain || !domain_stats[encoded].present)
            continue;
        if (reopen_plan.domains[static_cast<std::size_t>(*fact_domain)].mode ==
            fact_residency_mode_t::paged) {
            domain_paged[encoded] = true;
            any_paged = true;
            if (domain_materialized[encoded]) {
                domain_materialized[encoded] = false;
                any_materialized = false;
                for (std::uint32_t probe = 1; probe <= baseline_domain_count;
                     ++probe) {
                    if (static_cast<packed_page_type_t>(probe) ==
                        packed_page_type_t::search_index)
                        continue;
                    if (domain_materialized[probe]) {
                        any_materialized = true;
                        break;
                    }
                }
            }
        }
    }
    std::shared_ptr<const paged_domain_source_t> reopen_page_source;
    std::array<std::uint64_t, 20> reopen_domain_records{};
    std::array<std::uint64_t, 20> reopen_domain_content_bytes{};
    std::vector<std::uint8_t> reopen_delay_slot_counts;
    if (any_paged) {
        std::array<std::vector<packed_page_index_row_t>, 20> page_rows{};
        std::array<std::uint64_t, 20> page_records{};
        std::array<std::uint64_t, 20> page_logical{};
        auto index_connection = open_reader_connection(conn.path, options);
        if (!index_connection) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                index_connection.error());
        }
        sqlite3* index_database = index_connection.take_value();
        auto index_rows = read_packed_page_index(
            index_database, generation.generation, true,
            [&cancel] { return cancel.stop_requested(); });
        if (!index_rows) {
            sqlite3_close_v2(index_database);
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                index_rows.error());
        }
        for (auto& row : index_rows.value()) {
            const auto fact_domain = paged_view_fact_domain(
                static_cast<packed_page_type_t>(row.domain));
            if (!fact_domain ||
                !domain_paged[static_cast<std::size_t>(row.domain)])
                continue;
            page_rows[static_cast<std::size_t>(row.domain)].push_back(row);
        }
        for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
             ++encoded) {
            if (!domain_paged[encoded])
                continue;
            auto& rows = page_rows[encoded];
            std::sort(rows.begin(), rows.end(),
                [](const packed_page_index_row_t& lhs,
                   const packed_page_index_row_t& rhs) {
                    return lhs.ordinal_begin < rhs.ordinal_begin;
                });
            std::uint64_t expected_ordinal = 0;
            bool contiguous = true;
            for (const auto& row : rows) {
                if (row.ordinal_begin != expected_ordinal) {
                    contiguous = false;
                    break;
                }
                expected_ordinal += row.count;
            }
            if (!contiguous) {
                sqlite3_close_v2(index_database);
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "packed paged domain page index is not contiguous"));
            }
            if (rows.empty()) {
                sqlite3_close_v2(index_database);
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "packed paged domain has no page index rows"));
            }
            auto record_count_result = read_paged_domain_stream_record_count(
                index_database, generation, static_cast<std::uint32_t>(encoded),
                rows.front().page_index, cancel);
            if (!record_count_result) {
                sqlite3_close_v2(index_database);
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    record_count_result.error());
            }
            const auto record_count = record_count_result.value();
            page_records[encoded] = record_count;
            const auto logical = domain_stats[encoded].logical_bytes;
            const auto prefixes = static_cast<std::uint64_t>(rows.size()) *
                packed_record_page_prefix_size;
            page_logical[encoded] = logical >= prefixes ? logical - prefixes : 0;
            reopen_domain_records[encoded] = record_count;
            reopen_domain_content_bytes[encoded] = page_logical[encoded];
        }
        sqlite3_close_v2(index_database);
        reopen_page_source = std::shared_ptr<const paged_domain_source_t>(
            new database_page_source_t(conn.path, options, generation,
                                       std::move(page_rows),
                                       std::move(reopen_domain_records),
                                       std::move(reopen_domain_content_bytes),
                                       options.packed_stream_page_size -
                                           packed_page_header_size -
                                           packed_record_page_prefix_size));
        if (domain_paged[static_cast<std::uint32_t>(
                packed_page_type_t::instructions)]) {
            auto delay_tail = reopen_paged_delay_slot_tail(
                *reopen_page_source,
                reopen_page_source->record_count(fact_domain_t::instructions),
                reopen_page_source->total_content_bytes(
                    fact_domain_t::instructions),
                maximum_records, cancel);
            if (!delay_tail)
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    delay_tail.error());
            reopen_delay_slot_counts = delay_tail.take_value();
        }
    }
    std::array<std::vector<std::uint8_t>, 20> domain_payloads;
    if (any_materialized) {
        std::array<std::vector<packed_domain_range_output_t>, 20> range_outputs;
        packed_reopen_admission_t admission(options.reopen_range_budget_bytes);
        aida::infra::taskflow_runtime::graph_descriptor_t range_graph;
        range_graph.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        range_graph.owner_subsystem = "analysis_persistence";
        range_graph.label = "analysis.persistence.reopen_pages";
        range_graph.phase = "persistence";
        range_graph.priority = 2;
        std::uint64_t range_node_id = 0;
        for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
             ++encoded) {
            if (!domain_materialized[encoded])
                continue;
            const auto& stat = domain_stats[encoded];
            const std::uint32_t range_count = static_cast<std::uint32_t>(
                (std::min<std::uint64_t>)(reopen_lanes,
                    (stat.page_count + kReopenParallelMinPages - 1ULL) /
                        kReopenParallelMinPages));
            const auto domain = static_cast<packed_page_type_t>(encoded);
            auto& outputs = range_outputs[encoded];
            outputs.resize(range_count);
            for (std::uint32_t range = 0; range < range_count; ++range) {
                const std::uint32_t page_begin =
                    stat.page_count * range / range_count;
                const std::uint32_t page_end =
                    stat.page_count * (range + 1U) / range_count;
                const std::uint64_t estimate =
                    stat.logical_bytes * (page_end - page_begin) /
                        stat.page_count + packed_page_max_payload;
                auto& output = outputs[range];
                aida::infra::taskflow_runtime::graph_node_descriptor_t node;
                node.node_id = ++range_node_id;
                node.label = "analysis.persistence.reopen_page_range";
                node.cancellable_body = [&conn, &options, &generation, domain,
                                         page_begin, page_end, estimate,
                                         maximum_domain_bytes, &cancel,
                                         &admission, &output](
                    const aida::infra::taskflow_runtime::cancellation_token_t&) {
                    packed_reopen_admission_t::permit_t permit(
                        admission, estimate);
                    if (cancel.stop_requested()) {
                        output.error = packed_baseline_cancelled(cancel);
                        return;
                    }
                    auto opened = open_reader_connection(conn.path, options);
                    if (!opened) {
                        output.error = opened.error();
                        return;
                    }
                    sqlite3* database = opened.take_value();
                    auto read = read_packed_domain_page_range(
                        database, generation, domain, page_begin, page_end,
                        output, maximum_domain_bytes, cancel);
                    sqlite3_close_v2(database);
                    if (!read)
                        output.error = read.error();
                };
                range_graph.nodes.push_back(std::move(node));
            }
        }
        auto range_submission = aida::infra::taskflow_runtime::submit_graph(
            std::move(range_graph));
        if (!range_submission.submitted) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                packed_baseline_error(
                    workspace_error_code_t::persistence_failure,
                    std::string("packed baseline reopen page dispatch was rejected: ") +
                        range_submission.reject_reason));
        }
        for (;;) {
            const auto waited = aida::infra::taskflow_runtime::wait_for(
                range_submission.handle, 50);
            if (waited.completed)
                break;
            if (cancel.stop_requested())
                aida::infra::taskflow_runtime::cancel(range_submission.handle);
        }
        for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
             ++encoded) {
            if (!domain_materialized[encoded])
                continue;
            const auto& stat = domain_stats[encoded];
            const auto& outputs = range_outputs[encoded];
            const std::uint32_t range_count =
                static_cast<std::uint32_t>(outputs.size());
            auto& payload = domain_payloads[encoded];
            std::uint64_t expected_ordinal = 0;
            std::uint32_t pages_seen = 0;
            std::uint64_t total_bytes = 0;
            try {
                payload.reserve(static_cast<std::size_t>(
                    (std::min)(stat.logical_bytes, maximum_domain_bytes)));
            } catch (const std::bad_alloc&) {
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::limit_exceeded,
                        "packed domain reopen allocation failed"));
            }
            for (std::uint32_t range = 0; range < range_count; ++range) {
                auto& output = outputs[range];
                if (output.error) {
                    return workspace_result_t<decoded_packed_baseline_t>::failure(
                        *output.error);
                }
                const std::uint32_t expected_pages =
                    stat.page_count * (range + 1U) / range_count -
                    stat.page_count * range / range_count;
                if (output.pages_seen != expected_pages ||
                    (range == 0 && output.first_ordinal != 0) ||
                    output.first_ordinal != expected_ordinal) {
                    return workspace_result_t<decoded_packed_baseline_t>::failure(
                        packed_baseline_error(
                            workspace_error_code_t::integrity_failure,
                            "packed domain page ranges are not contiguous"));
                }
                expected_ordinal = output.next_ordinal;
                pages_seen += output.pages_seen;
                if (!checked_add_u64(total_bytes, output.bytes.size(),
                                     total_bytes) ||
                    total_bytes > maximum_domain_bytes) {
                    return workspace_result_t<decoded_packed_baseline_t>::failure(
                        packed_baseline_error(
                            workspace_error_code_t::limit_exceeded,
                            "packed domain exceeds its bounded reopen budget"));
                }
                try {
                    payload.insert(
                        payload.end(),
                        std::make_move_iterator(output.bytes.begin()),
                        std::make_move_iterator(output.bytes.end()));
                } catch (const std::bad_alloc&) {
                    return workspace_result_t<decoded_packed_baseline_t>::failure(
                        packed_baseline_error(
                            workspace_error_code_t::limit_exceeded,
                            "packed domain reopen allocation failed"));
                }
            }
            if (pages_seen != stat.page_count) {
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::integrity_failure,
                        "packed domain page count changed during reopen"));
            }
        }
        if (cancel.stop_requested()) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                packed_baseline_cancelled(cancel));
        }
    }
    std::vector<std::shared_ptr<packed_domain_decode_result_t>> group_results;
    std::array<std::vector<std::shared_ptr<packed_domain_decode_result_t>>, 20>
        domain_units;
    aida::infra::taskflow_runtime::graph_descriptor_t graph;
    graph.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    graph.owner_subsystem = "analysis_persistence";
    graph.label = "analysis.persistence.reopen_domains";
    graph.phase = "persistence";
    graph.priority = 2;
    std::uint64_t node_id = 0;
    for (std::size_t task_index = 0; task_index < tasks.size(); ++task_index) {
        std::vector<packed_page_type_t> remaining;
        std::uint32_t remaining_mask = 0;
        for (const auto domain : tasks[task_index]) {
            if (!domain_materialized[static_cast<std::uint32_t>(domain)] &&
                !domain_paged[static_cast<std::uint32_t>(domain)]) {
                remaining.push_back(domain);
                remaining_mask |= 1U << static_cast<std::uint32_t>(domain);
            }
        }
        if (remaining.empty())
            continue;
        auto result = std::make_shared<packed_domain_decode_result_t>();
        result->domain_mask = remaining_mask;
        group_results.push_back(result);
        aida::infra::taskflow_runtime::graph_node_descriptor_t node;
        node.node_id = ++node_id;
        node.label = "analysis.persistence.reopen_domain";
        node.cancellable_body = [&conn, &options, &generation, maximum_records,
                                 maximum_domain_bytes, &cancel, remaining,
                                 result](
            const aida::infra::taskflow_runtime::cancellation_token_t&) {
            auto opened = open_reader_connection(conn.path, options);
            if (!opened) {
                result->error = opened.error();
                return;
            }
            sqlite3* database = opened.take_value();
            for (const auto domain : remaining) {
                if (cancel.stop_requested()) {
                    result->error = packed_baseline_cancelled(cancel);
                    break;
                }
                auto payload = read_packed_domain_payload(
                    database, generation, domain, maximum_domain_bytes, cancel);
                if (!payload) {
                    result->error = payload.error();
                    break;
                }
                auto decoded = decode_packed_domain_into(
                    domain, payload.value(), result->snapshot, maximum_records,
                    &result->decoded_records, cancel);
                if (!decoded) {
                    result->error = decoded.error();
                    break;
                }
            }
            sqlite3_close_v2(database);
        };
        graph.nodes.push_back(std::move(node));
    }
    for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
         ++encoded) {
        if (!domain_materialized[encoded])
            continue;
        const auto domain = static_cast<packed_page_type_t>(encoded);
        const std::uint32_t mask = 1U << encoded;
        const auto& payload = domain_payloads[encoded];
        auto& units = domain_units[encoded];
        auto layout = packed_domain_stride_layout(
            domain, payload, maximum_records, cancel);
        if (!layout) {
            auto result = std::make_shared<packed_domain_decode_result_t>();
            result->domain_mask = mask;
            units.push_back(result);
            aida::infra::taskflow_runtime::graph_node_descriptor_t node;
            node.node_id = ++node_id;
            node.label = "analysis.persistence.reopen_domain";
            node.cancellable_body = [domain, &payload, maximum_records, &cancel,
                                     result](
                const aida::infra::taskflow_runtime::cancellation_token_t&) {
                auto decoded = decode_packed_domain_into(
                    domain, payload, result->snapshot, maximum_records,
                    &result->decoded_records, cancel);
                if (!decoded)
                    result->error = decoded.error();
            };
            graph.nodes.push_back(std::move(node));
            continue;
        }
        for (std::size_t segment_index = 0;
             segment_index < layout->segment_count; ++segment_index) {
            const auto segment = layout->segments[segment_index];
            const std::uint64_t lane_count =
                segment.count >= kReopenStrideMinRecords
                    ? (std::min<std::uint64_t>)(reopen_lanes,
                          (std::max<std::uint64_t>)(
                              1ULL, segment.count / kReopenStrideLaneRecords))
                    : 1ULL;
            for (std::uint64_t lane = 0; lane < lane_count; ++lane) {
                const std::uint64_t ordinal_begin =
                    segment.count * lane / lane_count;
                const std::uint64_t ordinal_end =
                    segment.count * (lane + 1ULL) / lane_count;
                auto result = std::make_shared<packed_domain_decode_result_t>();
                result->domain_mask = mask;
                units.push_back(result);
                aida::infra::taskflow_runtime::graph_node_descriptor_t node;
                node.node_id = ++node_id;
                node.label = "analysis.persistence.reopen_domain_records";
                node.cancellable_body = [domain, segment_index, &payload,
                                         segment, ordinal_begin, ordinal_end,
                                         maximum_records, &cancel, result](
                    const aida::infra::taskflow_runtime::cancellation_token_t&) {
                    try {
                        auto decoded = decode_packed_domain_segment_range(
                            domain, segment_index, payload, segment,
                            ordinal_begin, ordinal_end, maximum_records,
                            result->snapshot, result->decoded_records, cancel);
                        if (!decoded)
                            result->error = decoded.error();
                    } catch (const std::bad_alloc&) {
                        result->error = packed_baseline_error(
                            workspace_error_code_t::limit_exceeded,
                            "packed domain reopen allocation failed");
                    }
                };
                graph.nodes.push_back(std::move(node));
            }
        }
    }
    if (graph.nodes.empty()) {
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            packed_baseline_error(
                workspace_error_code_t::integrity_failure,
                "packed baseline reopen produced no domain work"));
    }
    auto submission = aida::infra::taskflow_runtime::submit_graph(std::move(graph));
    if (!submission.submitted) {
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            packed_baseline_error(
                workspace_error_code_t::persistence_failure,
                std::string("packed baseline reopen dispatch was rejected: ") +
                    submission.reject_reason));
    }
    for (;;) {
        const auto waited = aida::infra::taskflow_runtime::wait_for(
            submission.handle, 50);
        if (waited.completed)
            break;
        if (cancel.stop_requested())
            aida::infra::taskflow_runtime::cancel(submission.handle);
    }
    std::array<std::shared_ptr<packed_domain_decode_result_t>, 20>
        domain_fallback;
    for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
         ++encoded) {
        const auto& units = domain_units[encoded];
        if (units.size() <= 1)
            continue;
        bool unit_failed = false;
        for (const auto& unit : units) {
            if (unit->error) {
                unit_failed = true;
                break;
            }
        }
        if (!unit_failed)
            continue;
        if (cancel.stop_requested()) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                packed_baseline_cancelled(cancel));
        }
        auto fallback = std::make_shared<packed_domain_decode_result_t>();
        fallback->domain_mask = 1U << encoded;
        auto decoded = decode_packed_domain_into(
            static_cast<packed_page_type_t>(encoded), domain_payloads[encoded],
            fallback->snapshot, maximum_records, &fallback->decoded_records,
            cancel);
        if (!decoded) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                decoded.error());
        }
        domain_fallback[encoded] = fallback;
    }
    std::vector<const packed_domain_decode_result_t*> merge_sources;
    merge_sources.reserve(group_results.size() + 64U);
    for (const auto& result : group_results)
        merge_sources.push_back(result.get());
    for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
         ++encoded) {
        if (!domain_materialized[encoded])
            continue;
        if (domain_fallback[encoded]) {
            merge_sources.push_back(domain_fallback[encoded].get());
            continue;
        }
        for (const auto& unit : domain_units[encoded])
            merge_sources.push_back(unit.get());
    }
    auto snapshot = std::make_shared<analysis_snapshot_t>();
    snapshot->binary_id = manifest.binary_id;
    snapshot->load_profile_hash = manifest.load_profile_hash;
    snapshot->generation = manifest.generation;
    snapshot->analysis_revision = manifest.analysis_revision;
    snapshot->overlay_revision = manifest.overlay_revision;
    snapshot->baseline_complete = manifest.baseline_complete;
    snapshot->normalized_image = std::move(normalized_image);
    snapshot->image = std::move(pe_adapter);
    std::uint64_t decoded_records = 0;
    constexpr std::uint32_t call_graph_mask =
        1U << static_cast<std::uint32_t>(packed_page_type_t::call_graph);
    for (const auto* result : merge_sources) {
        if (result->error) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                *result->error);
        }
        if (!checked_add_u64(decoded_records, result->decoded_records,
                             decoded_records)) {
            return workspace_result_t<decoded_packed_baseline_t>::failure(
                packed_baseline_error(
                    workspace_error_code_t::limit_exceeded,
                    "packed baseline record count overflows its reopen budget"));
        }
        auto& source = result->snapshot;
        const auto merge_into = [](auto& destination, auto& source_vector) {
            if (destination.empty())
                destination = std::move(source_vector);
            else
                destination.insert(destination.end(),
                    std::make_move_iterator(source_vector.begin()),
                    std::make_move_iterator(source_vector.end()));
        };
        merge_into(snapshot->instructions, source.instructions);
        merge_into(snapshot->delay_slot_counts, source.delay_slot_counts);
        {
            const std::size_t cold_base = snapshot->operand_facts.cold.size();
            const std::size_t hot_begin = snapshot->operand_facts.hot.size();
            merge_into(snapshot->operand_facts.hot, source.operand_facts.hot);
            merge_into(snapshot->operand_facts.cold, source.operand_facts.cold);
            if (cold_base != 0) {
                for (std::size_t index = hot_begin;
                     index < snapshot->operand_facts.hot.size(); ++index) {
                    auto& hot = snapshot->operand_facts.hot[index];
                    if (hot.cold_index != 0) {
                        hot.cold_index = static_cast<std::uint32_t>(
                            cold_base + hot.cold_index);
                    }
                }
            }
        }
        merge_into(snapshot->target_facts, source.target_facts);
        merge_into(snapshot->edges, source.edges);
        merge_into(snapshot->strings, source.strings);
        merge_into(snapshot->symbols, source.symbols);
        merge_into(snapshot->blocks, source.blocks);
        merge_into(snapshot->functions, source.functions);
        merge_into(snapshot->function_chunks, source.function_chunks);
        merge_into(snapshot->function_block_memberships,
                   source.function_block_memberships);
        merge_into(snapshot->xrefs, source.xrefs);
        merge_into(snapshot->address_expressions, source.address_expressions);
        merge_into(snapshot->coverage, source.coverage);
        merge_into(snapshot->call_graph.nodes, source.call_graph.nodes);
        merge_into(snapshot->call_graph.call_sites, source.call_graph.call_sites);
        merge_into(snapshot->call_graph.candidates, source.call_graph.candidates);
        merge_into(snapshot->call_graph.edges, source.call_graph.edges);
        merge_into(snapshot->call_graph.conflicts, source.call_graph.conflicts);
        merge_into(snapshot->rich_facts.data_candidates,
                   source.rich_facts.data_candidates);
        merge_into(snapshot->rich_facts.data_pointer_facts,
                   source.rich_facts.data_pointer_facts);
        merge_into(snapshot->rich_facts.data_conflicts,
                   source.rich_facts.data_conflicts);
        merge_into(snapshot->rich_facts.type_references,
                   source.rich_facts.type_references);
        merge_into(snapshot->rich_facts.metadata_conflicts,
                   source.rich_facts.metadata_conflicts);
        merge_into(snapshot->rich_facts.type_candidates,
                   source.rich_facts.type_candidates);
        if ((result->domain_mask & call_graph_mask) != 0) {
            snapshot->call_graph.indirect_site_count =
                source.call_graph.indirect_site_count;
            snapshot->call_graph.unresolved_site_count =
                source.call_graph.unresolved_site_count;
            snapshot->call_graph.bounded = source.call_graph.bounded;
        }
    }
    if (decoded_records > maximum_records) {
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            packed_baseline_error(
                workspace_error_code_t::limit_exceeded,
                "packed baseline record count exceeds its bounded reopen budget"));
    }
    {
        std::uint64_t total_chunks = 0;
        for (const auto& function : snapshot->functions)
            total_chunks += function.chunks.size();
        if (total_chunks != 0) {
            snapshot->function_chunk_ranges.reserve(
                static_cast<std::size_t>(total_chunks));
            for (auto& function : snapshot->functions) {
                if (function.chunks.empty())
                    continue;
                if (static_cast<std::uint64_t>(function.first_chunk) !=
                    snapshot->function_chunk_ranges.size() ||
                    function.chunk_count != function.chunks.size())
                    continue;
                for (const auto& range : function.chunks)
                    snapshot->function_chunk_ranges.push_back(range);
                std::vector<address_range_t>().swap(function.chunks);
            }
            std::uint64_t remaining_chunk_bytes = 0;
            bool chunk_bytes_overflow = false;
            for (const auto& function : snapshot->functions) {
                std::uint64_t bytes = 0;
                if (!checked_mul_u64(
                        static_cast<std::uint64_t>(function.chunks.capacity()),
                        static_cast<std::uint64_t>(sizeof(address_range_t)), bytes) ||
                    !checked_add_u64(remaining_chunk_bytes, bytes,
                                     remaining_chunk_bytes)) {
                    chunk_bytes_overflow = true;
                    break;
                }
            }
            if (chunk_bytes_overflow) {
                return workspace_result_t<decoded_packed_baseline_t>::failure(
                    packed_baseline_error(
                        workspace_error_code_t::range_overflow,
                        "analysis memory accounting overflows"));
            }
            snapshot->function_chunk_bytes = remaining_chunk_bytes;
        }
    }
    if (any_paged) {
        snapshot->residency_plan = reopen_plan;
        snapshot->persisted_page_source.source = reopen_page_source;
        if (!reopen_delay_slot_counts.empty())
            snapshot->delay_slot_counts = std::move(reopen_delay_slot_counts);
        for (std::uint32_t encoded = 1; encoded <= baseline_domain_count;
             ++encoded) {
            if (!domain_paged[encoded])
                continue;
            const auto fact_domain =
                paged_view_fact_domain(static_cast<packed_page_type_t>(encoded));
            snapshot->paged_domain_counts[static_cast<std::size_t>(
                *fact_domain)] = reopen_domain_records[encoded];
        }
    }
    snapshot_repair_operand_instruction_ordinals(*snapshot);
    auto validated = validate_analysis_snapshot(
        *snapshot, snapshot->baseline_complete, cancel);
    if (!validated)
        return workspace_result_t<decoded_packed_baseline_t>::failure(
            validated.error());
    decoded_packed_baseline_t decoded;
    decoded.snapshot = std::move(snapshot);
    decoded.revision_tag.generation = generation.generation;
    decoded.revision_tag.analysis_revision = generation.analysis_revision;
    decoded.revision_tag.overlay_revision = generation.overlay_revision;
    return workspace_result_t<decoded_packed_baseline_t>::success(
        std::move(decoded));
}


workspace_result_t<void> await_persistence_completion(
    const persistence_ticket_t& ticket,
    const cancellation_token_t& cancel,
    const char* phase) {
    if (!ticket.accepted || !ticket.completion.valid()) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "workspace persistence queue rejected the packed generation",
            phase));
    }
    static_cast<void>(cancel);
    ticket.completion.wait();
    try {
        const auto& completed = ticket.completion.get();
        if (!completed)
            return workspace_result_t<void>::failure(completed.error());
    } catch (const std::exception& exception) {
        auto error = make_workspace_error(
            workspace_error_code_t::persistence_failure,
            "packed-generation persistence completion failed", phase);
        error.details.emplace_back("exception", exception.what());
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

}

workspace_persistence_candidate_t::workspace_persistence_candidate_t(
    std::weak_ptr<workspace_database_t> database,
    std::string token,
    std::uint64_t generation,
    std::uint64_t analysis_revision,
    std::uint64_t overlay_revision)
    : database_(std::move(database)),
      token_(std::move(token)),
      generation_(generation),
      analysis_revision_(analysis_revision),
      overlay_revision_(overlay_revision) {
}

const std::string& workspace_persistence_candidate_t::token() const noexcept {
    return token_;
}

std::uint64_t workspace_persistence_candidate_t::generation() const noexcept {
    return generation_;
}

std::uint64_t workspace_persistence_candidate_t::analysis_revision() const noexcept {
    return analysis_revision_;
}

std::uint64_t workspace_persistence_candidate_t::overlay_revision() const noexcept {
    return overlay_revision_;
}

bool workspace_persistence_candidate_t::packed_generation_required() const noexcept {
    return packed_generation_required_.load(std::memory_order_acquire);
}

workspace_result_t<void> workspace_persistence_candidate_t::finalize(
    const cancellation_token_t& cancel) const {
    auto database = database_.lock();
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is no longer available",
            "workspace_database.candidate.finalize"));
    }
    return database->finalize_candidate(*this, cancel);
}

workspace_result_t<void> workspace_persistence_candidate_t::discard(
    const cancellation_token_t& cancel) const {
    auto database = database_.lock();
    if (!database) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is no longer available",
            "workspace_database.candidate.discard"));
    }
    return database->discard_candidate(*this, cancel);
}

workspace_snapshot_staging_t::workspace_snapshot_staging_t(
    std::shared_ptr<state_t> state)
    : state_(std::move(state)) {
}

std::uint32_t workspace_snapshot_staging_t::staged_domain_mask() const noexcept {
    return state_->staged_mask.load(std::memory_order_acquire);
}

workspace_result_t<void> workspace_snapshot_staging_t::set_metrics_json(
    std::string metrics_json) {
    if (state_->finalized.load(std::memory_order_acquire)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "snapshot staging is already finalized",
            "workspace_database.persist"));
    }
    if (state_->failed.load(std::memory_order_acquire))
        return workspace_result_t<void>::failure(state_->current_failure());
    state_->metrics_json = std::move(metrics_json);
    return workspace_result_t<void>::success();
}

void workspace_snapshot_staging_t::expect_complete_baseline() noexcept {
    state_->baseline_complete = true;
}

void workspace_snapshot_staging_t::discard(workspace_error_t error) noexcept {
    try {
        state_->record_failure(std::move(error));
    } catch (...) {
    }
}

std::string decompiler_cache_key_t::canonical() const {
    std::ostringstream output;
    const bool legacy_pe = endian == endian_t::little &&
        ((format == format_id_t::pe32 && architecture == architecture_id_t::x86 &&
          (architecture_mode == architecture_mode_t::unknown ||
           architecture_mode == architecture_mode_t::x86_32) &&
          abi == abi_id_t::windows_x86) ||
         (format == format_id_t::pe32_plus && architecture == architecture_id_t::x86_64 &&
          (architecture_mode == architecture_mode_t::unknown ||
           architecture_mode == architecture_mode_t::x86_64) &&
          abi == abi_id_t::windows_x64));
    output << binary_id.to_hex() << '|'
           << static_cast<unsigned>(format) << '|'
           << static_cast<unsigned>(architecture) << '|';
    if (!legacy_pe)
        output << static_cast<unsigned>(architecture_mode) << '|';
    output << static_cast<unsigned>(abi) << '|';
    if (!legacy_pe)
        output << static_cast<unsigned>(endian) << '|';
    output
           << engine_version.size() << ':' << engine_version << '|'
           << schema_version << '|'
           << specification_version.size() << ':' << specification_version << '|'
           << analysis_settings_hash.size() << ':' << analysis_settings_hash << '|'
           << function_id << '|' << function_rva << '|'
           << function_content_hash.to_hex() << '|'
           << analysis_revision << '|'
           << overlay_revision << '|' << generation;
    return output.str();
}

workspace_result_t<std::shared_ptr<workspace_database_t>>
workspace_database_t::open(workspace_database_options_t options) {
    if (!options.identity || options.identity->binary_id().empty() ||
        options.versions.engine_version.empty() ||
        options.versions.specification_version.empty() ||
        options.versions.analysis_settings_hash.empty() ||
        options.candidate_operation_timeout_ms == 0 ||
        options.passive_checkpoint_pages == 0 ||
        options.instruction_chunk_records == 0 ||
        options.instruction_chunk_records > kMaximumInstructionChunkRecords ||
        options.max_persisted_fact_records == 0 ||
        options.packed_generation_quota_bytes == 0 ||
        options.packed_generation_quota_bytes > packed_generation_max_payload_bytes ||
        options.packed_stream_page_size <
            packed_page_header_size + packed_record_page_prefix_size + 16U ||
        options.packed_stream_page_size >
            packed_page_header_size + packed_page_max_payload ||
        options.packed_staging_memory_budget_bytes <
            4ULL * packed_page_max_payload ||
        options.packed_staging_memory_budget_bytes >
            packed_generation_max_payload_bytes ||
        options.packed_page_compression_level >
            static_cast<std::uint32_t>(ZSTD_maxCLevel()) ||
        options.reopen_range_budget_bytes < 64ULL << 20 ||
        options.pdb_persistence_max_stored_bytes == 0 ||
        options.pdb_persistence_max_stored_bytes >
            pdb_symbol_modules_max_stored_bytes) {
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "database identity, versions, checkpoint, and chunk limits are required",
                                 "workspace_database.open"));
    }
    if (sqlite3_libversion_number() != SQLITE_VERSION_NUMBER ||
        SQLITE_VERSION_NUMBER != 3053003) {
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            make_workspace_error(workspace_error_code_t::persistence_failure,
                                 "SQLite runtime/header version does not match pinned 3.53.3",
                                 "workspace_database.open"));
    }
    auto path_result = database_path_for(*options.identity);
    if (!path_result)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(path_result.error());

    auto state = std::make_shared<connection_state_t>();
    state->path = path_result.take_value();
    sqlite3* database = nullptr;
    const int open_status = sqlite3_open_v2(state->path.c_str(), &database,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_URI,
        nullptr);
    if (open_status != SQLITE_OK) {
        auto error = database_error(database, open_status,
                                    "unable to open workspace database",
                                    "workspace_database.open");
        if (database)
            sqlite3_close_v2(database);
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(std::move(error));
    }
    state->writer = database;
    auto configured = configure_connection(database, options, true);
    if (!configured)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(configured.error());
    bool schema_requires_invalidation = false;
    auto migrated = migrate_workspace_database_schema(
        database, schema_requires_invalidation);
    if (!migrated)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(migrated.error());
    std::uint64_t invalidations = 0;
    auto identity_result = initialize_identity_and_versions(
        database, options, invalidations, schema_requires_invalidation);
    if (!identity_result)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(identity_result.error());
    auto commit_state = read_commit_state(database, "workspace_database.open");
    if (!commit_state)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            commit_state.error());
    auto recovered = recover_workspace_persistence_state(database, commit_state.value());
    if (!recovered)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            recovered.error());
    commit_state = read_commit_state(database, "workspace_database.open");
    if (!commit_state)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            commit_state.error());
    state->cache_invalidations.store(invalidations, std::memory_order_release);
    state->persisted_generation.store(commit_state.value().committed_generation,
                                      std::memory_order_release);
    state->persisted_analysis_revision.store(
        commit_state.value().committed_analysis_revision,
        std::memory_order_release);
    state->persisted_overlay_revision.store(
        commit_state.value().committed_overlay_revision,
        std::memory_order_release);
    state->open.store(true, std::memory_order_release);

    state->writer_statements = std::make_shared<sqlite_statement_cache_t>(64);
    sqlite_statement_cache_register(state->writer, state->writer_statements);

    sqlite_reader_pool_options_t reader_pool_options;
    reader_pool_options.acquire_timeout = std::chrono::milliseconds(
        (std::min<std::uint32_t>)(options.busy_timeout_ms, 60000));
    const std::string reader_path = state->path;
    const workspace_database_options_t reader_options = options;
    auto reader_pool = sqlite_reader_pool_t::create(
        [reader_path, reader_options]() {
            return open_reader_connection(reader_path, reader_options);
        },
        reader_pool_options);
    if (!reader_pool) {
        sqlite_statement_cache_unregister(state->writer);
        state->writer_statements.reset();
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(
            reader_pool.error());
    }
    state->reader_pool = reader_pool.take_value();

    auto queue_result = persistence_queue_t::create(options.identity->binary_id(),
                                                     options.queue_limits);
    if (!queue_result)
        return workspace_result_t<std::shared_ptr<workspace_database_t>>::failure(queue_result.error());
    auto queue = queue_result.take_value();
    install_writer_coalescing(queue, state);
    auto result = std::shared_ptr<workspace_database_t>(
        new workspace_database_t(std::move(options), std::move(state), std::move(queue)));
    return workspace_result_t<std::shared_ptr<workspace_database_t>>::success(std::move(result));
}

workspace_database_t::workspace_database_t(workspace_database_options_t options,
                                           std::shared_ptr<connection_state_t> state,
                                           std::shared_ptr<persistence_queue_t> queue)
    : options_(std::move(options)), state_(std::move(state)), queue_(std::move(queue)) {
}

workspace_database_t::~workspace_database_t() {
    request_cancel();
}

const std::string& workspace_database_t::path() const noexcept {
    return state_->path;
}

const workspace_database_options_t& workspace_database_t::options() const noexcept {
    return options_;
}

std::shared_ptr<persistence_queue_t> workspace_database_t::queue() const noexcept {
    return queue_;
}

persistence_ticket_t workspace_database_t::enqueue_write(std::string label,
                                                         writer_operation_t operation,
                                                         cancellation_token_t cancel,
                                                         std::uint64_t reservation_bytes,
                                                         persistence_priority_t priority) {
    auto state = state_;
    return queue_->enqueue(std::move(label),
        [state, operation = std::move(operation)](const cancellation_token_t& token) mutable {
            std::lock_guard<std::timed_mutex> writer_lock(state->writer_mutex);
            if (!state->open.load(std::memory_order_acquire) || !state->writer) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::workspace_closing,
                                         "workspace database is closed",
                                         "workspace_database.write"));
            }
            sqlite_progress_guard_t progress(state->writer, token);
            auto result = operation(state->writer, token);
            if (!result && token.stop_requested()) {
                auto error = make_workspace_error(
                    token.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "workspace database write was cancelled",
                    "workspace_database.write");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                error.details.emplace_back("sqlite_write_error",
                                           result.error().stable_code());
                return workspace_result_t<void>::failure(std::move(error));
            }
            return result;
        }, std::move(cancel), reservation_bytes, priority);
}

persistence_ticket_t workspace_database_t::persist_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    return persist_snapshot(
        std::move(snapshot),
        std::shared_ptr<const managed_artifact_publication_t>{},
        std::move(analysis_settings_json), std::move(analysis_metrics_json),
        std::move(cancel));
}

persistence_ticket_t workspace_database_t::persist_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    std::shared_ptr<const managed_artifact_publication_t> managed_publication,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    if (!snapshot) {
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "analysis snapshot is null",
                                         "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    if (snapshot->baseline_complete) {
        return queue_->enqueue("analysis.persistence.missing_search_products",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::invalid_argument,
                    "complete baseline persistence requires its search products",
                    "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    const bool image_matches = snapshot->normalized_image
        ? image_matches_persistence_identity(
              *snapshot->normalized_image, *options_.identity,
              snapshot->generation, snapshot->overlay_revision)
        : snapshot->image && image_matches_identity(*snapshot->image, *options_.identity);
    if (!image_matches) {
        return queue_->enqueue("analysis.persistence.identity_conflict",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_conflict,
                    "analysis snapshot image identity does not match the database",
                    "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    auto validated = validate_analysis_snapshot(*snapshot, snapshot->baseline_complete, cancel);
    if (!validated) {
        const auto error = validated.error();
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    auto candidate_token_result = generate_candidate_token();
    if (!candidate_token_result) {
        const auto error = candidate_token_result.error();
        return queue_->enqueue("analysis.persistence.candidate_token_failure",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    auto state = state_;
    auto options = options_;
    const std::uint64_t generation = snapshot->generation;
    const std::uint64_t analysis_revision = snapshot->analysis_revision;
    const std::uint64_t overlay_revision = snapshot->overlay_revision;
    const std::string candidate_token = candidate_token_result.take_value();
    auto mutable_candidate = std::shared_ptr<workspace_persistence_candidate_t>(
        new workspace_persistence_candidate_t(weak_from_this(), candidate_token,
            generation, analysis_revision, overlay_revision));
    mutable_candidate->packed_generation_required_.store(
        snapshot->baseline_complete || static_cast<bool>(managed_publication),
        std::memory_order_release);
    auto candidate = std::shared_ptr<const workspace_persistence_candidate_t>(
        std::move(mutable_candidate));
    auto commit_measurement = std::make_shared<persistence_commit_metrics_t>();
    auto ticket = enqueue_write("analysis.persistence.snapshot",
        [state, options = std::move(options), snapshot = std::move(snapshot),
         managed = std::move(managed_publication),
         settings = std::move(analysis_settings_json), metrics = std::move(analysis_metrics_json),
         generation, analysis_revision, overlay_revision, candidate_token,
         commit_measurement]
        (sqlite3* database, const cancellation_token_t& token) mutable {
            auto result = persist_snapshot_impl(database, *snapshot, nullptr, managed, options,
                                                settings, metrics, candidate_token, token,
                                                commit_measurement.get());
            if (result) {
                state->candidate_generation.store(generation, std::memory_order_release);
                state->candidate_analysis_revision.store(analysis_revision, std::memory_order_release);
                state->candidate_overlay_revision.store(overlay_revision, std::memory_order_release);
                state->candidate_pending.store(true, std::memory_order_release);
                publish_commit_metrics(*state, *commit_measurement);
            }
            return result;
        }, std::move(cancel),
        static_cast<std::uint64_t>(options_.packed_stream_page_size) * 4ULL,
        persistence_priority_t::baseline_chain);
    ticket.commit_metrics = std::move(commit_measurement);
    ticket.snapshot_candidate = std::move(candidate);
    return ticket;
}

persistence_ticket_t workspace_database_t::persist_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    persisted_search_products_t search_products,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    return persist_snapshot(
        std::move(snapshot), std::move(search_products),
        std::shared_ptr<const managed_artifact_publication_t>{},
        std::move(analysis_settings_json), std::move(analysis_metrics_json),
        std::move(cancel));
}

persistence_ticket_t workspace_database_t::persist_snapshot(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    persisted_search_products_t search_products,
    std::shared_ptr<const managed_artifact_publication_t> managed_publication,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    if (!snapshot) {
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                                         "analysis snapshot is null",
                                         "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    const bool image_matches = snapshot->normalized_image
        ? image_matches_persistence_identity(
              *snapshot->normalized_image, *options_.identity,
              snapshot->generation, snapshot->overlay_revision)
        : snapshot->image && image_matches_identity(*snapshot->image, *options_.identity);
    if (!image_matches) {
        return queue_->enqueue("analysis.persistence.identity_conflict",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_conflict,
                    "analysis snapshot image identity does not match the database",
                    "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    auto validated = validate_analysis_snapshot(*snapshot, snapshot->baseline_complete, cancel);
    if (!validated) {
        const auto error = validated.error();
        return queue_->enqueue("analysis.persistence.invalid_snapshot",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    if (search_products.generation != snapshot->generation ||
        search_products.analysis_revision != snapshot->analysis_revision ||
        search_products.overlay_revision != snapshot->overlay_revision) {
        return queue_->enqueue("analysis.persistence.stale_search_products",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::stale_generation,
                                         "search products do not match the snapshot revisions",
                                         "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    if ((snapshot->baseline_complete && !search_products.live_index) ||
        (search_products.live_index &&
         (!search_products.live_index->matches(snapshot) ||
          !search_products.data_candidates.empty() ||
          !search_products.switches.empty() ||
          !search_products.types.empty() ||
          search_products.search_index_blob_version != 0 ||
          !search_products.search_index_blob.empty()))) {
        return queue_->enqueue("analysis.persistence.invalid_packed_search",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                        "snapshot persistence received an ambiguous or mismatched live search index",
                        "workspace_database.persist"));
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    if (snapshot->baseline_complete) {
        auto begin_ticket = begin_snapshot_staging(std::move(snapshot),
            std::move(analysis_settings_json), std::move(analysis_metrics_json),
            cancel);
        if (!begin_ticket.accepted || !begin_ticket.staging ||
            !begin_ticket.completion.valid())
            return begin_ticket;
        auto staging_handle = begin_ticket.staging;
        auto stage_ticket = stage_snapshot_domains(
            staging_handle, kBaselineStagedDomainMask, cancel);
        if (!stage_ticket.accepted)
            return stage_ticket;
        return finalize_snapshot_staging(
            staging_handle, std::move(search_products),
            std::move(managed_publication), std::move(cancel));
    }
    auto candidate_token_result = generate_candidate_token();
    if (!candidate_token_result) {
        const auto error = candidate_token_result.error();
        return queue_->enqueue("analysis.persistence.candidate_token_failure",
            [error](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(error);
            }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    }
    auto state = state_;
    auto options = options_;
    const std::uint64_t generation = snapshot->generation;
    const std::uint64_t analysis_revision = snapshot->analysis_revision;
    const std::uint64_t overlay_revision = snapshot->overlay_revision;
    const std::string candidate_token = candidate_token_result.take_value();
    auto mutable_candidate = std::shared_ptr<workspace_persistence_candidate_t>(
        new workspace_persistence_candidate_t(weak_from_this(), candidate_token,
            generation, analysis_revision, overlay_revision));
    mutable_candidate->packed_generation_required_.store(
        snapshot->baseline_complete || static_cast<bool>(managed_publication),
        std::memory_order_release);
    auto candidate = std::shared_ptr<const workspace_persistence_candidate_t>(
        std::move(mutable_candidate));
    auto commit_measurement = std::make_shared<persistence_commit_metrics_t>();
    auto ticket = enqueue_write("analysis.persistence.snapshot_products",
        [state, options = std::move(options), snapshot = std::move(snapshot),
         managed = std::move(managed_publication),
         products = std::move(search_products), settings = std::move(analysis_settings_json),
         metrics = std::move(analysis_metrics_json), generation, analysis_revision,
         overlay_revision, candidate_token, commit_measurement]
        (sqlite3* database, const cancellation_token_t& token) mutable {
            auto result = persist_snapshot_impl(database, *snapshot, &products, managed, options,
                                                settings, metrics, candidate_token, token,
                                                commit_measurement.get());
            if (result) {
                state->candidate_generation.store(generation, std::memory_order_release);
                state->candidate_analysis_revision.store(analysis_revision, std::memory_order_release);
                state->candidate_overlay_revision.store(overlay_revision, std::memory_order_release);
                state->candidate_pending.store(true, std::memory_order_release);
                publish_commit_metrics(*state, *commit_measurement);
            }
            return result;
        }, std::move(cancel),
        static_cast<std::uint64_t>(options_.packed_stream_page_size) * 4ULL,
        persistence_priority_t::baseline_chain);
    ticket.commit_metrics = std::move(commit_measurement);
    ticket.snapshot_candidate = std::move(candidate);
    return ticket;
}

struct staging_finalize_chain_t {
    std::promise<workspace_result_t<void>> promise;
    std::shared_ptr<persistence_commit_metrics_t> metrics =
        std::make_shared<persistence_commit_metrics_t>();
    std::atomic<unsigned> retries{0};
    std::atomic<bool> completed{false};

    void complete(workspace_result_t<void> result) {
        if (completed.exchange(true, std::memory_order_acq_rel))
            return;
        try {
            promise.set_value(std::move(result));
        } catch (...) {
        }
    }
};

persistence_ticket_t workspace_database_t::begin_snapshot_staging(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    std::string analysis_settings_json,
    std::string analysis_metrics_json,
    cancellation_token_t cancel) {
    persistence_ticket_t ticket;
    const auto fail_ticket = [&ticket](workspace_error_t error) {
        std::promise<workspace_result_t<void>> promise;
        ticket.completion = promise.get_future().share();
        promise.set_value(workspace_result_t<void>::failure(std::move(error)));
        return ticket;
    };
    if (!snapshot) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "analysis snapshot is null", "workspace_database.persist"));
    }
    const bool image_matches = snapshot->normalized_image
        ? image_matches_persistence_identity(
              *snapshot->normalized_image, *options_.identity,
              snapshot->generation, snapshot->overlay_revision)
        : snapshot->image && image_matches_identity(*snapshot->image, *options_.identity);
    if (!image_matches) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::target_conflict,
            "analysis snapshot image identity does not match the database",
            "workspace_database.persist"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "snapshot staging was cancelled before it began",
            "workspace_database.persist");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return fail_ticket(std::move(error));
    }
    if (!state_->open.load(std::memory_order_acquire)) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "workspace database is closed", "workspace_database.persist"));
    }
    auto candidate_token_result = generate_candidate_token();
    if (!candidate_token_result)
        return fail_ticket(candidate_token_result.error());
    auto staging_state = std::make_shared<workspace_snapshot_staging_t::state_t>();
    staging_state->token = candidate_token_result.take_value();
    staging_state->generation = snapshot->generation;
    staging_state->analysis_revision = snapshot->analysis_revision;
    staging_state->overlay_revision = snapshot->overlay_revision;
    staging_state->baseline_complete = snapshot->baseline_complete;
    staging_state->snapshot = std::move(snapshot);
    staging_state->settings_json = std::move(analysis_settings_json);
    staging_state->metrics_json = std::move(analysis_metrics_json);
    staging_state->conn = state_;
    auto mutable_candidate = std::shared_ptr<workspace_persistence_candidate_t>(
        new workspace_persistence_candidate_t(weak_from_this(), staging_state->token,
            staging_state->generation, staging_state->analysis_revision,
            staging_state->overlay_revision));
    mutable_candidate->packed_generation_required_.store(
        staging_state->baseline_complete, std::memory_order_release);
    staging_state->candidate = std::shared_ptr<const workspace_persistence_candidate_t>(
        std::move(mutable_candidate));
    auto staging_handle = std::shared_ptr<workspace_snapshot_staging_t>(
        new workspace_snapshot_staging_t(std::move(staging_state)));
    {
        std::lock_guard<std::mutex> lock(state_->staging_mutex);
        auto current = state_->active_staging.lock();
        if (current &&
            !current->state_->finalized.load(std::memory_order_acquire) &&
            !current->state_->failed.load(std::memory_order_acquire)) {
            return fail_ticket(make_workspace_error(
                workspace_error_code_t::revision_conflict,
                "another snapshot staging is already active",
                "workspace_database.persist"));
        }
        state_->active_staging = staging_handle;
    }
    std::promise<workspace_result_t<void>> promise;
    ticket.completion = promise.get_future().share();
    promise.set_value(workspace_result_t<void>::success());
    ticket.accepted = true;
    ticket.staging = std::move(staging_handle);
    ticket.snapshot_candidate = ticket.staging->state_->candidate;
    return ticket;
}

persistence_ticket_t workspace_database_t::stage_snapshot_domains(
    const std::shared_ptr<workspace_snapshot_staging_t>& staging,
    std::uint32_t domain_mask,
    cancellation_token_t cancel) {
    persistence_ticket_t ticket;
    const auto fail_ticket = [&ticket](workspace_error_t error) {
        std::promise<workspace_result_t<void>> promise;
        ticket.completion = promise.get_future().share();
        promise.set_value(workspace_result_t<void>::failure(std::move(error)));
        return ticket;
    };
    if (!staging || !staging->state_) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging handle is null", "workspace_database.persist"));
    }
    auto staging_state = staging->state_;
    if (staging_state->conn.lock() != state_) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging belongs to a different database",
            "workspace_database.persist"));
    }
    if (staging_state->failed.load(std::memory_order_acquire))
        return fail_ticket(staging_state->current_failure());
    if (staging_state->finalized.load(std::memory_order_acquire)) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "snapshot staging is already finalized", "workspace_database.persist"));
    }
    if (domain_mask == 0 || (domain_mask & ~kAllStagingDomainBits) != 0) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging domain mask is invalid", "workspace_database.persist"));
    }
    if ((domain_mask &
         (kSearchIndexDomainMask | kManagedPublicationDomainMask)) != 0) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "search-index and managed-publication domains stage at finalize",
            "workspace_database.persist"));
    }
    if (!staging_state->baseline_complete) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging domains require a complete baseline snapshot",
            "workspace_database.persist"));
    }
    if ((staging_state->staged_mask.load(std::memory_order_acquire) & domain_mask) != 0) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging domains were already staged",
            "workspace_database.persist"));
    }
    auto state = state_;
    auto options = options_;
    auto op_ticket = enqueue_write("analysis.persistence.stage_domains",
        [state, options, staging_state, domain_mask](
            sqlite3* database, const cancellation_token_t& token) mutable {
            return run_staging_serialization(database, *state, options, staging_state,
                                             domain_mask, nullptr, nullptr, token);
        }, std::move(cancel), 0, persistence_priority_t::baseline_chain);
    op_ticket.staging = staging;
    return op_ticket;
}

persistence_ticket_t workspace_database_t::finalize_snapshot_staging(
    const std::shared_ptr<workspace_snapshot_staging_t>& staging,
    persisted_search_products_t search_products,
    std::shared_ptr<const managed_artifact_publication_t> managed_publication,
    cancellation_token_t cancel) {
    persistence_ticket_t ticket;
    const auto fail_ticket = [&ticket](workspace_error_t error) {
        std::promise<workspace_result_t<void>> promise;
        ticket.completion = promise.get_future().share();
        promise.set_value(workspace_result_t<void>::failure(std::move(error)));
        return ticket;
    };
    if (!staging || !staging->state_) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging handle is null", "workspace_database.persist"));
    }
    auto staging_state = staging->state_;
    if (staging_state->conn.lock() != state_) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "snapshot staging belongs to a different database",
            "workspace_database.persist"));
    }
    if (staging_state->failed.load(std::memory_order_acquire))
        return fail_ticket(staging_state->current_failure());
    if (staging_state->finalized.load(std::memory_order_acquire)) {
        return fail_ticket(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "snapshot staging is already finalized", "workspace_database.persist"));
    }
    if (staging_state->candidate) {
        staging_state->candidate->packed_generation_required_.store(
            staging_state->baseline_complete ||
                static_cast<bool>(managed_publication),
            std::memory_order_release);
    }
    std::uint64_t staged_bytes = 0;
    for (const auto& domain : staging_state->domains) {
        std::lock_guard<std::mutex> lock(domain.mutex);
        staged_bytes = domain.payload_bytes >
                (std::numeric_limits<std::uint64_t>::max)() - staged_bytes
            ? (std::numeric_limits<std::uint64_t>::max)()
            : staged_bytes + domain.payload_bytes;
    }
    std::uint64_t finalize_estimate = kFinalizeManifestWireFixedBytes;
    if (!checked_add_u64(finalize_estimate,
                         kPackedStringLengthPrefixBytes +
                             static_cast<std::uint64_t>(staging_state->token.size()),
                         finalize_estimate))
        finalize_estimate = (std::numeric_limits<std::uint64_t>::max)();
    if (managed_publication &&
        !checked_add_u64(finalize_estimate,
                         estimate_managed_publication_wire_bytes(
                             *managed_publication),
                         finalize_estimate))
        finalize_estimate = (std::numeric_limits<std::uint64_t>::max)();
    staged_bytes = (std::max)(staged_bytes, finalize_estimate);
    staged_bytes = (std::min)(staged_bytes, options_.queue_limits.max_pending_bytes);
    auto chain = std::make_shared<staging_finalize_chain_t>();
    auto products_shared = std::make_shared<persisted_search_products_t>(
        std::move(search_products));
    auto managed_shared = std::move(managed_publication);
    std::weak_ptr<workspace_database_t> weak_self = weak_from_this();
    auto operation = std::make_shared<writer_operation_t>();
    *operation = [weak_self, chain, staging_state, products_shared, managed_shared,
                  cancel, staged_bytes, operation](
        sqlite3* database, const cancellation_token_t& token) mutable
        -> workspace_result_t<void> {
        auto self = weak_self.lock();
        if (!self) {
            auto error = make_workspace_error(
                workspace_error_code_t::workspace_closing,
                "workspace database is closed", "workspace_database.persist");
            chain->complete(workspace_result_t<void>::failure(error));
            return workspace_result_t<void>::failure(std::move(error));
        }
        const unsigned prior_retries =
            chain->retries.load(std::memory_order_acquire);
        if (prior_retries != 0) {
            const auto backoff_deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(250);
            while (std::chrono::steady_clock::now() < backoff_deadline &&
                   !token.stop_requested())
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        auto result = run_staging_finalize(
            database, *self->state_, self->options_, staging_state,
            *products_shared, managed_shared, chain->metrics.get(), token);
        if (!result &&
            result.error().code == workspace_error_code_t::revision_conflict &&
            !token.stop_requested() && prior_retries < kFinalizeMaxRetries) {
            chain->retries.store(prior_retries + 1, std::memory_order_release);
            chain->metrics->finalize_retries = prior_retries + 1;
            auto reticket = self->enqueue_write("analysis.persistence.finalize",
                *operation, cancel, staged_bytes,
                persistence_priority_t::baseline_chain);
            if (reticket.accepted)
                return workspace_result_t<void>::success();
            if (reticket.completion.valid()) {
                chain->complete(reticket.completion.get());
                return reticket.completion.get();
            }
            auto error = make_workspace_error(
                workspace_error_code_t::persistence_failure,
                "packed finalize retry was rejected by the persistence queue",
                "workspace_database.persist");
            chain->complete(workspace_result_t<void>::failure(error));
            return workspace_result_t<void>::failure(std::move(error));
        }
        chain->complete(result);
        return result;
    };
    auto op_ticket = enqueue_write("analysis.persistence.finalize", *operation,
        std::move(cancel), staged_bytes, persistence_priority_t::baseline_chain);
    if (!op_ticket.accepted && op_ticket.completion.valid())
        chain->complete(op_ticket.completion.get());
    ticket.accepted = op_ticket.accepted;
    ticket.sequence = op_ticket.sequence;
    ticket.completion = chain->promise.get_future().share();
    ticket.commit_metrics = chain->metrics;
    ticket.snapshot_candidate = staging_state->candidate;
    ticket.staging = staging;
    return ticket;
}

workspace_result_t<void> workspace_database_t::with_reader(
    const reader_operation_t& operation,
    const cancellation_token_t& cancel) const {
    const auto cancelled = [&] {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workspace database read was cancelled",
            "workspace_database.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    };
    if (cancel.stop_requested())
        return cancelled();
    if (!state_->open.load(std::memory_order_acquire) || !state_->reader_pool) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::workspace_closing,
                                 "workspace database is closed",
                                 "workspace_database.read"));
    }
    auto lease_result = state_->reader_pool->acquire(cancel);
    if (!lease_result) {
        if (cancel.stop_requested())
            return cancelled();
        return workspace_result_t<void>::failure(lease_result.error());
    }
    auto lease = lease_result.take_value();
    sqlite3* database = lease.get();
    sqlite_progress_guard_t progress(database, cancel);
    auto begun = exec_sql(database, "BEGIN", "workspace_database.read");
    if (!begun) {
        progress.reset();
        if (cancel.stop_requested())
            return cancelled();
        return begun;
    }
    auto result = operation(database);
    if (!result && cancel.stop_requested())
        result = cancelled();
    if (result) {
        auto committed = exec_sql(database, "COMMIT", "workspace_database.read");
        if (!committed) {
            exec_sql(database, "ROLLBACK", "workspace_database.read");
            result = cancel.stop_requested() ? cancelled() : committed;
        }
    } else {
        exec_sql(database, "ROLLBACK", "workspace_database.read");
    }
    progress.reset();
    return result;
}

workspace_result_t<void> workspace_database_t::finalize_candidate(
    const workspace_persistence_candidate_t& candidate,
    const cancellation_token_t& cancel) {
    if (!valid_candidate_token(candidate.token_) || candidate.generation_ == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "persistence candidate identity is malformed",
            "workspace_database.candidate.finalize"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate finalization was cancelled before promotion",
            "workspace_database.candidate.finalize");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto local_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(options_.candidate_operation_timeout_ms);
    const auto lock_deadline = cancel.deadline()
        ? (std::min)(local_deadline, *cancel.deadline()) : local_deadline;
    std::unique_lock<std::timed_mutex> writer_lock(state_->writer_mutex,
                                                   std::defer_lock);
    if (!writer_lock.try_lock_until(lock_deadline)) {
        auto error = make_workspace_error(
            cancel.cancellation_requested() ? workspace_error_code_t::cancelled
                                            : workspace_error_code_t::deadline_exceeded,
            "persistence writer was unavailable before the finalization deadline",
            "workspace_database.candidate.finalize");
        error.cancellation = cancel.cancellation_requested();
        error.deadline = !error.cancellation;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate finalization was cancelled before promotion",
            "workspace_database.candidate.finalize");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!state_->open.load(std::memory_order_acquire) || !state_->writer) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is closed",
            "workspace_database.candidate.finalize"));
    }
    sqlite3* database = state_->writer;
    auto begun = begin_immediate(database,
                                 "workspace_database.candidate.finalize");
    if (!begun)
        return begun;
    auto state = read_commit_state(database,
                                   "workspace_database.candidate.finalize");
    if (!state) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(state.error());
    }
    const auto committed_matches = [&] {
        return state.value().committed_token == candidate.token_ &&
               state.value().committed_generation == candidate.generation_ &&
               state.value().committed_analysis_revision ==
                   candidate.analysis_revision_ &&
               state.value().committed_overlay_revision ==
                   candidate.overlay_revision_;
    };
    if (state.value().committed_token == candidate.token_) {
        rollback(database, "workspace_database.candidate.finalize");
        if (!committed_matches()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "promoted candidate token has inconsistent revisions",
                "workspace_database.candidate.finalize"));
        }
        state_->persisted_generation.store(candidate.generation_,
                                           std::memory_order_release);
        state_->persisted_analysis_revision.store(candidate.analysis_revision_,
                                                  std::memory_order_release);
        state_->persisted_overlay_revision.store(candidate.overlay_revision_,
                                                 std::memory_order_release);
        state_->candidate_pending.store(false, std::memory_order_release);
        state_->candidate_generation.store(0, std::memory_order_release);
        state_->candidate_analysis_revision.store(0, std::memory_order_release);
        state_->candidate_overlay_revision.store(0, std::memory_order_release);
        {
            std::lock_guard<std::mutex> staging_lock(state_->staging_mutex);
            auto staging = state_->active_staging.lock();
            if (staging && staging->state_->token == candidate.token_) {
                staging->state_->finalized.store(true, std::memory_order_release);
                state_->active_staging.reset();
            }
        }
        return workspace_result_t<void>::success();
    }
    if (!state.value().candidate_ready ||
        state.value().candidate_token != candidate.token_ ||
        state.value().candidate_generation != candidate.generation_ ||
        state.value().candidate_analysis_revision != candidate.analysis_revision_ ||
        state.value().candidate_overlay_revision != candidate.overlay_revision_ ||
        !state.value().candidate_slot) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "persistence candidate is no longer the pending workspace candidate",
            "workspace_database.candidate.finalize"));
    }
    const std::uint8_t candidate_slot = *state.value().candidate_slot;
    statement_t slot_state;
    const std::string slot_state_select =
        "SELECT generation,analysis_revision,overlay_revision,commit_token FROM " +
        slot_table(candidate_slot, "analysis_state") + " WHERE singleton=1";
    auto current = slot_state.prepare(database, slot_state_select.c_str(),
                                      "workspace_database.candidate.finalize");
    if (!current) {
        rollback(database, "workspace_database.candidate.finalize");
        return current;
    }
    const int slot_status = sqlite3_step(slot_state.get());
    if (slot_status != SQLITE_ROW ||
        static_cast<std::uint64_t>(sqlite3_column_int64(slot_state.get(), 0)) !=
            candidate.generation_ ||
        static_cast<std::uint64_t>(sqlite3_column_int64(slot_state.get(), 1)) !=
            candidate.analysis_revision_ ||
        static_cast<std::uint64_t>(sqlite3_column_int64(slot_state.get(), 2)) !=
            candidate.overlay_revision_ ||
        column_text(slot_state.get(), 3) != candidate.token_) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "candidate fact slot does not match its promotion marker",
            "workspace_database.candidate.finalize"));
    }
    if (candidate.packed_generation_required()) {
        auto packed = read_packed_generation(
            database, candidate.generation_, false,
            [&cancel] { return cancel.stop_requested(); });
        if (!packed) {
            rollback(database, "workspace_database.candidate.finalize");
            return workspace_result_t<void>::failure(packed.error());
        }
        if (!packed.value() || packed.value()->committed ||
            packed.value()->analysis_revision != candidate.analysis_revision_ ||
            packed.value()->overlay_revision != candidate.overlay_revision_) {
            rollback(database, "workspace_database.candidate.finalize");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "candidate packed generation is missing or revision-inconsistent",
                "workspace_database.candidate.finalize"));
        }
        auto manifest = decode_packed_baseline_manifest(
            packed.value()->payload_blob, cancel);
        if (!manifest || manifest.value().candidate_token != candidate.token_) {
            rollback(database, "workspace_database.candidate.finalize");
            return manifest
                ? workspace_result_t<void>::failure(make_workspace_error(
                      workspace_error_code_t::integrity_failure,
                      "candidate packed generation token is inconsistent",
                      "workspace_database.candidate.finalize"))
                : workspace_result_t<void>::failure(manifest.error());
        }
        const auto baseline_domains = static_cast<std::uint16_t>(
            packed_page_baseline_last_data_type);
        if ((manifest.value().baseline_complete &&
             packed.value()->shard_count != baseline_domains &&
             packed.value()->shard_count != baseline_domains + 1U) ||
            (!manifest.value().baseline_complete &&
             packed.value()->shard_count != 1U)) {
            rollback(database, "workspace_database.candidate.finalize");
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "candidate packed domain set is inconsistent",
                "workspace_database.candidate.finalize"));
        }
        auto packed_published = options_.packed_finalize_full_revalidation
            ? aida::analysis::publish_packed_generation(
                  database, candidate.generation_,
                  [&cancel] { return cancel.stop_requested(); })
            : aida::analysis::publish_packed_generation_metadata(
                  database, candidate.generation_,
                  [&cancel] { return cancel.stop_requested(); });
        if (!packed_published) {
            rollback(database, "workspace_database.candidate.finalize");
            return packed_published;
        }
    }
    statement_t promote;
    current = promote.prepare(database,
        "UPDATE workspace_commit_state SET active_slot=?1,committed_token=?2,committed_generation=?3,committed_analysis_revision=?4,committed_overlay_revision=?5,candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=?6 WHERE singleton=1 AND candidate_ready=1 AND candidate_token=?2",
        "workspace_database.candidate.finalize");
    if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(1, candidate_slot); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_text(2, candidate.token_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(3, candidate.generation_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(4, candidate.analysis_revision_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(5, candidate.overlay_revision_); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.bind_uint(6, utc_ms()); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    current = promote.step_done(); if (!current) { rollback(database, "workspace_database.candidate.finalize"); return current; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.candidate.finalize");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "persistence candidate changed during promotion",
            "workspace_database.candidate.finalize"));
    }
    auto committed = commit(database, "workspace_database.candidate.finalize");
    if (!committed) {
        rollback(database, "workspace_database.candidate.finalize");
        return committed;
    }
    state_->persisted_generation.store(candidate.generation_,
                                       std::memory_order_release);
    state_->persisted_analysis_revision.store(candidate.analysis_revision_,
                                              std::memory_order_release);
    state_->persisted_overlay_revision.store(candidate.overlay_revision_,
                                             std::memory_order_release);
    state_->candidate_pending.store(false, std::memory_order_release);
    state_->candidate_generation.store(0, std::memory_order_release);
    state_->candidate_analysis_revision.store(0, std::memory_order_release);
    state_->candidate_overlay_revision.store(0, std::memory_order_release);
    {
        std::lock_guard<std::mutex> staging_lock(state_->staging_mutex);
        auto staging = state_->active_staging.lock();
        if (staging && staging->state_->token == candidate.token_) {
            staging->state_->finalized.store(true, std::memory_order_release);
            state_->active_staging.reset();
        }
    }
    return workspace_result_t<void>::success();
}

void workspace_database_t::acknowledge_promoted_candidate(
    const workspace_persistence_candidate_t& candidate) noexcept {
    state_->persisted_generation.store(candidate.generation_, std::memory_order_release);
    state_->persisted_analysis_revision.store(
        candidate.analysis_revision_, std::memory_order_release);
    state_->persisted_overlay_revision.store(
        candidate.overlay_revision_, std::memory_order_release);
    state_->candidate_pending.store(false, std::memory_order_release);
    state_->candidate_generation.store(0, std::memory_order_release);
    state_->candidate_analysis_revision.store(0, std::memory_order_release);
    state_->candidate_overlay_revision.store(0, std::memory_order_release);
}

workspace_result_t<void> workspace_database_t::discard_candidate(
    const workspace_persistence_candidate_t& candidate,
    const cancellation_token_t& cancel) {
    if (!valid_candidate_token(candidate.token_) || candidate.generation_ == 0) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::invalid_argument,
            "persistence candidate identity is malformed",
            "workspace_database.candidate.discard"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate discard was cancelled before mutation",
            "workspace_database.candidate.discard");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto local_deadline = std::chrono::steady_clock::now() +
        std::chrono::milliseconds(options_.candidate_operation_timeout_ms);
    const auto lock_deadline = cancel.deadline()
        ? (std::min)(local_deadline, *cancel.deadline()) : local_deadline;
    std::unique_lock<std::timed_mutex> writer_lock(state_->writer_mutex,
                                                   std::defer_lock);
    if (!writer_lock.try_lock_until(lock_deadline)) {
        auto error = make_workspace_error(
            cancel.cancellation_requested() ? workspace_error_code_t::cancelled
                                            : workspace_error_code_t::deadline_exceeded,
            "persistence writer was unavailable before the discard deadline",
            "workspace_database.candidate.discard");
        error.cancellation = cancel.cancellation_requested();
        error.deadline = !error.cancellation;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "persistence candidate discard was cancelled before mutation",
            "workspace_database.candidate.discard");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }
    if (!state_->open.load(std::memory_order_acquire) || !state_->writer) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::workspace_closing,
            "persistence database is closed",
            "workspace_database.candidate.discard"));
    }
    sqlite3* database = state_->writer;
    auto begun = begin_immediate(database,
                                 "workspace_database.candidate.discard");
    if (!begun)
        return begun;
    auto state = read_commit_state(database,
                                   "workspace_database.candidate.discard");
    if (!state) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::failure(state.error());
    }
    if (state.value().committed_token == candidate.token_) {
        const bool revisions_match =
            state.value().committed_generation == candidate.generation_ &&
            state.value().committed_analysis_revision ==
                candidate.analysis_revision_ &&
            state.value().committed_overlay_revision == candidate.overlay_revision_;
        rollback(database, "workspace_database.candidate.discard");
        if (!revisions_match) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "promoted candidate token has inconsistent revisions",
                "workspace_database.candidate.discard"));
        }
        return workspace_result_t<void>::success();
    }
    if (!state.value().candidate_ready) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::success();
    }
    if (state.value().candidate_token != candidate.token_ ||
        state.value().candidate_generation != candidate.generation_ ||
        state.value().candidate_analysis_revision != candidate.analysis_revision_ ||
        state.value().candidate_overlay_revision != candidate.overlay_revision_ ||
        !state.value().candidate_slot) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "a different persistence candidate is pending",
            "workspace_database.candidate.discard"));
    }
    if (candidate.packed_generation_required()) {
        auto rolled_back = rollback_packed_generation(
            database, candidate.generation_);
        if (!rolled_back) {
            rollback(database, "workspace_database.candidate.discard");
            return rolled_back;
        }
    }
    auto cleared = clear_snapshot_slot(database, *state.value().candidate_slot,
                                       "workspace_database.candidate.discard");
    if (!cleared) {
        rollback(database, "workspace_database.candidate.discard");
        return cleared;
    }
    auto staging_deleted = delete_packed_generation_staging(
        database, candidate.generation_);
    if (!staging_deleted) {
        rollback(database, "workspace_database.candidate.discard");
        return staging_deleted;
    }
    statement_t discard;
    auto current = discard.prepare(database,
        "UPDATE workspace_commit_state SET candidate_slot=NULL,candidate_token=NULL,candidate_generation=NULL,candidate_analysis_revision=NULL,candidate_overlay_revision=NULL,candidate_ready=0,updated_utc_ms=?1 WHERE singleton=1 AND candidate_ready=1 AND candidate_token=?2",
        "workspace_database.candidate.discard");
    if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    current = discard.bind_uint(1, utc_ms()); if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    current = discard.bind_text(2, candidate.token_); if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    current = discard.step_done(); if (!current) { rollback(database, "workspace_database.candidate.discard"); return current; }
    if (sqlite3_changes(database) != 1) {
        rollback(database, "workspace_database.candidate.discard");
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::revision_conflict,
            "persistence candidate changed during discard",
            "workspace_database.candidate.discard"));
    }
    auto committed = commit(database, "workspace_database.candidate.discard");
    if (!committed) {
        rollback(database, "workspace_database.candidate.discard");
        return committed;
    }
    state_->candidate_pending.store(false, std::memory_order_release);
    state_->candidate_generation.store(0, std::memory_order_release);
    state_->candidate_analysis_revision.store(0, std::memory_order_release);
    state_->candidate_overlay_revision.store(0, std::memory_order_release);
    {
        std::lock_guard<std::mutex> staging_lock(state_->staging_mutex);
        auto staging = state_->active_staging.lock();
        if (staging && staging->state_->token == candidate.token_) {
            staging->state_->record_failure(make_workspace_error(
                workspace_error_code_t::cancelled,
                "snapshot staging candidate was discarded",
                "workspace_database.candidate.discard"));
            state_->active_staging.reset();
        }
    }
    return workspace_result_t<void>::success();
}

namespace {

struct relational_group_output_t {
    analysis_snapshot_t snapshot;
    std::uint64_t total_rows = 0;
};

template <typename Reader>
workspace_result_t<void> read_snapshot_fact_rows(
    sqlite3* database, const std::string& sql, const char* phase,
    std::uint64_t& total_rows, std::uint64_t maximum_records,
    const cancellation_token_t& cancel, Reader reader) {
    statement_t statement;
    auto prepared = statement.prepare(database, sql.c_str(), phase);
    if (!prepared) return prepared;
    std::size_t row = 0;
    for (;;) {
        if ((row++ & 255U) == 0 && cancel.stop_requested()) {
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "snapshot reopen cancelled", phase);
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const int step_status = sqlite3_step(statement.get());
        if (step_status == SQLITE_DONE)
            return workspace_result_t<void>::success();
        if (step_status != SQLITE_ROW)
            return workspace_result_t<void>::failure(database_error(database, step_status,
                "unable to read persisted fact row", phase));
        if (++total_rows > maximum_records) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "persisted fact rows exceed the reopen budget", phase));
        }
        auto row_result = reader(statement.get());
        if (!row_result) return row_result;
    }
}

using fact_chunk_record_reader_t =
    std::function<workspace_result_t<void>(const std::uint8_t*)>;

workspace_result_t<bool> read_snapshot_fact_chunks(
    sqlite3* database, std::uint8_t active_slot, const char* table,
    std::uint64_t record_stride, std::uint64_t max_chunk_records,
    std::uint64_t& total_rows, std::uint64_t maximum_records,
    const cancellation_token_t& cancel, const char* phase,
    const fact_chunk_record_reader_t& record_reader) {
    std::uint64_t chunk_rows = 0;
    {
        statement_t count_statement;
        const std::string count_sql = "SELECT COUNT(*) FROM " +
            slot_table(active_slot, table);
        auto prepared = count_statement.prepare(database, count_sql.c_str(), phase);
        if (!prepared)
            return workspace_result_t<bool>::failure(prepared.error());
        const int status = sqlite3_step(count_statement.get());
        if (status != SQLITE_ROW)
            return workspace_result_t<bool>::failure(database_error(
                database, status, "unable to count persisted fact chunks", phase));
        chunk_rows = static_cast<std::uint64_t>(
            sqlite3_column_int64(count_statement.get(), 0));
    }
    if (chunk_rows == 0)
        return workspace_result_t<bool>::success(false);
    statement_t statement;
    const std::string sql = "SELECT payload FROM " +
        slot_table(active_slot, table) + " ORDER BY chunk_id";
    auto prepared = statement.prepare(database, sql.c_str(), phase);
    if (!prepared)
        return workspace_result_t<bool>::failure(prepared.error());
    std::size_t row = 0;
    for (;;) {
        if ((row++ & 255U) == 0 && cancel.stop_requested()) {
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "snapshot reopen cancelled", phase);
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<bool>::failure(std::move(error));
        }
        const int step_status = sqlite3_step(statement.get());
        if (step_status == SQLITE_DONE)
            break;
        if (step_status != SQLITE_ROW)
            return workspace_result_t<bool>::failure(database_error(
                database, step_status, "unable to read persisted fact chunk", phase));
        const void* payload = sqlite3_column_blob(statement.get(), 0);
        const int bytes = sqlite3_column_bytes(statement.get(), 0);
        if (!payload || bytes <= 0) {
            return workspace_result_t<bool>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted fact chunk is empty", phase));
        }
        std::uint64_t count = 0;
        const std::uint8_t* records = nullptr;
        auto envelope = decode_fact_chunk_envelope(
            payload, static_cast<std::size_t>(bytes), record_stride,
            max_chunk_records, count, records, phase);
        if (!envelope)
            return workspace_result_t<bool>::failure(envelope.error());
        if (count > maximum_records - (std::min)(total_rows, maximum_records) ||
            total_rows + count > maximum_records) {
            return workspace_result_t<bool>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "persisted fact rows exceed the reopen budget", phase));
        }
        total_rows += count;
        for (std::uint64_t index = 0; index < count; ++index) {
            if ((index & 1023ULL) == 0 && cancel.stop_requested()) {
                auto error = make_workspace_error(cancel.deadline_exceeded()
                                                      ? workspace_error_code_t::deadline_exceeded
                                                      : workspace_error_code_t::cancelled,
                                                  "snapshot reopen cancelled", phase);
                error.deadline = cancel.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<bool>::failure(std::move(error));
            }
            auto decoded = record_reader(records + index * record_stride);
            if (!decoded)
                return workspace_result_t<bool>::failure(decoded.error());
        }
    }
    return workspace_result_t<bool>::success(true);
}

struct relational_group_task_t {
    relational_group_output_t output;
    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> instruction_blobs;
    std::optional<workspace_error_t> error;
};

workspace_result_t<void> load_relational_instruction_blobs(
    sqlite3* database, std::uint8_t active_slot, relational_group_task_t& task,
    const cancellation_token_t& cancel) {
    statement_t statement;
    auto prepared = statement.prepare(database,
        "SELECT chunk_id,payload FROM " + slot_table(active_slot, "instruction_chunks") + " ORDER BY chunk_id",
        "workspace_database.load.instructions");
    if (!prepared) return prepared;
    constexpr std::uint64_t kChunkBlobLimit =
        kMaximumInstructionChunkRecords * kInstructionBlobRecordSize +
        kInstructionBlobHeaderSize;
    std::size_t row = 0;
    for (;;) {
        if ((row++ & 255U) == 0 && cancel.stop_requested()) {
            auto error = make_workspace_error(cancel.deadline_exceeded()
                                                  ? workspace_error_code_t::deadline_exceeded
                                                  : workspace_error_code_t::cancelled,
                                              "snapshot reopen cancelled",
                                              "workspace_database.load.instructions");
            error.deadline = cancel.deadline_exceeded();
            error.cancellation = !error.deadline;
            return workspace_result_t<void>::failure(std::move(error));
        }
        const int step_status = sqlite3_step(statement.get());
        if (step_status == SQLITE_DONE)
            return workspace_result_t<void>::success();
        if (step_status != SQLITE_ROW) {
            return workspace_result_t<void>::failure(database_error(database, step_status,
                "unable to read persisted fact row", "workspace_database.load.instructions"));
        }
        const auto chunk_id = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
        const void* payload = sqlite3_column_blob(statement.get(), 1);
        const int bytes = sqlite3_column_bytes(statement.get(), 1);
        if (!payload || bytes <= 0) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted instruction chunk is empty", "workspace_database.load.instructions"));
        }
        if (static_cast<std::uint64_t>(bytes) > kChunkBlobLimit) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "persisted instruction chunk exceeds its bounded size",
                "workspace_database.load.instructions"));
        }
        const auto* begin = static_cast<const std::uint8_t*>(payload);
        std::vector<std::uint8_t> blob(begin, begin + bytes);
        task.instruction_blobs.emplace_back(chunk_id, std::move(blob));
    }
}

workspace_result_t<void> load_relational_operands_targets(
    sqlite3* database, std::uint8_t active_slot, relational_group_output_t& output,
    std::uint64_t maximum_records, const cancellation_token_t& cancel) {
    auto& loaded = output.snapshot;
    auto operand_chunks = read_snapshot_fact_chunks(
        database, active_slot, "operand_fact_chunks",
        packed_operand_stream_record_bytes, kMaximumInstructionChunkRecords,
        output.total_rows, maximum_records, cancel,
        "workspace_database.load.operands",
        [&loaded](const std::uint8_t* record_bytes) -> workspace_result_t<void> {
            auto decoded = decode_packed_operand_record(
                record_bytes, packed_operand_stream_record_bytes);
            if (!decoded)
                return workspace_result_t<void>::failure(decoded.error());
            snapshot_operand_append(*loaded, decoded.take_value());
            return workspace_result_t<void>::success();
        });
    if (!operand_chunks)
        return workspace_result_t<void>::failure(operand_chunks.error());
    auto target_chunks = read_snapshot_fact_chunks(
        database, active_slot, "target_fact_chunks",
        packed_target_stream_record_bytes, kMaximumInstructionChunkRecords,
        output.total_rows, maximum_records, cancel,
        "workspace_database.load.targets",
        [&loaded](const std::uint8_t* record_bytes) -> workspace_result_t<void> {
            auto decoded = decode_packed_target_record(
                record_bytes, packed_target_stream_record_bytes);
            if (!decoded)
                return workspace_result_t<void>::failure(decoded.error());
            loaded->target_facts.push_back(decoded.take_value());
            return workspace_result_t<void>::success();
        });
    if (!target_chunks)
        return workspace_result_t<void>::failure(target_chunks.error());
    workspace_result_t<void> result = workspace_result_t<void>::success();
    if (!operand_chunks.value())
        result = read_snapshot_fact_rows(database,
        "SELECT instruction_id,operand_index,entity_id,address_expression_id,decoder_operand_id,kind,access,visibility,encoding,memory_type,access_width,bit_width,access_width_bits,access_count,element_width_bits,element_count,address_width_bits,reg,segment_reg,base_reg,index_reg,scale,relative,signed_value,has_displacement,has_resolved_expression_value,displacement,immediate,resolved_expression_value,address_components,address_expression,address_resolution FROM " + slot_table(active_slot, "operand_facts") + " ORDER BY instruction_id,operand_index",
        "workspace_database.load.operands", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            const std::int64_t segment_register = sqlite3_column_int64(statement, 18);
            if (segment_register < 0 ||
                segment_register > (std::numeric_limits<std::uint16_t>::max)()) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "persisted operand segment register is outside the compact IR range",
                    "workspace_database.load.operands"));
            }
            operand_fact_t fact;
            fact.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            fact.operand_index = static_cast<std::uint8_t>(sqlite3_column_int(statement, 1));
            fact.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            fact.address_expression_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
            fact.decoder_operand_id = static_cast<std::uint8_t>(sqlite3_column_int(statement, 4));
            fact.kind = static_cast<operand_kind_t>(sqlite3_column_int(statement, 5));
            fact.access = static_cast<std::uint8_t>(sqlite3_column_int(statement, 6));
            fact.visibility = static_cast<std::uint8_t>(sqlite3_column_int(statement, 7));
            fact.encoding = static_cast<std::uint8_t>(sqlite3_column_int(statement, 8));
            fact.memory_type = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
            fact.access_width = static_cast<std::uint8_t>(sqlite3_column_int(statement, 10));
            fact.bit_width = static_cast<std::uint16_t>(sqlite3_column_int(statement, 11));
            fact.access_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 12));
            fact.access_count = static_cast<std::uint16_t>(sqlite3_column_int(statement, 13));
            fact.element_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 14));
            fact.element_count = static_cast<std::uint16_t>(sqlite3_column_int(statement, 15));
            fact.address_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 16));
            fact.reg = static_cast<std::uint16_t>(sqlite3_column_int(statement, 17));
            fact.segment_reg = static_cast<std::uint16_t>(segment_register);
            fact.base_reg = static_cast<std::uint16_t>(sqlite3_column_int(statement, 19));
            fact.index_reg = static_cast<std::uint16_t>(sqlite3_column_int(statement, 20));
            fact.scale = static_cast<std::uint8_t>(sqlite3_column_int(statement, 21));
            fact.relative = sqlite3_column_int(statement, 22) != 0;
            fact.signed_value = sqlite3_column_int(statement, 23) != 0;
            fact.has_displacement = sqlite3_column_int(statement, 24) != 0;
            fact.has_resolved_expression_value = sqlite3_column_int(statement, 25) != 0;
            fact.displacement = sqlite3_column_int64(statement, 26);
            fact.immediate = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 27));
            fact.resolved_expression_value = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 28));
            fact.address_components = static_cast<std::uint16_t>(sqlite3_column_int(statement, 29));
            fact.address_expression = static_cast<address_expression_kind_t>(sqlite3_column_int(statement, 30));
            fact.address_resolution = static_cast<target_resolution_t>(sqlite3_column_int(statement, 31));
            snapshot_operand_append(*loaded, fact);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    if (!target_chunks.value())
        result = read_snapshot_fact_rows(database,
        "SELECT instruction_id,operand_fact_id,address_expression_id,target_space,target_value,target_arch,target_mode,kind,resolution,operand_index,access_width_bits,access_count,direct,is_external FROM " + slot_table(active_slot, "target_facts") + " ORDER BY instruction_id,target_index",
        "workspace_database.load.targets", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            target_fact_t fact;
            fact.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            fact.operand_fact_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            fact.address_expression_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            fact.target = read_address(statement, 3);
            fact.kind = static_cast<target_kind_record_t>(sqlite3_column_int(statement, 7));
            fact.resolution = static_cast<target_resolution_t>(sqlite3_column_int(statement, 8));
            fact.operand_index = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
            fact.access_width_bits = static_cast<std::uint16_t>(sqlite3_column_int(statement, 10));
            fact.access_count = static_cast<std::uint16_t>(sqlite3_column_int(statement, 11));
            fact.direct = sqlite3_column_int(statement, 12) != 0;
            fact.is_external = sqlite3_column_int(statement, 13) != 0;
            loaded->target_facts.push_back(fact);
            return workspace_result_t<void>::success();
        });
    return result;
}

workspace_result_t<void> load_relational_functions_blocks(
    sqlite3* database, std::uint8_t active_slot, relational_group_output_t& output,
    std::uint64_t maximum_records, const cancellation_token_t& cancel) {
    auto& loaded = output.snapshot;
    auto result = read_snapshot_fact_rows(database,
        "SELECT entity_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,first_chunk,chunk_count,first_block_membership,block_membership_count,symbol_id,provenance,confidence,thunk,noreturn FROM " + slot_table(active_slot, "functions") + " ORDER BY start_value,entity_id",
        "workspace_database.load.functions", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            function_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.start = read_address(statement, 1);
            record.end = read_address(statement, 5);
            record.first_block = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 9));
            record.block_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
            record.first_chunk = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 11));
            record.chunk_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 12));
            record.first_block_membership = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 13));
            record.block_membership_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 14));
            if (sqlite3_column_type(statement, 15) != SQLITE_NULL)
                record.symbol_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 15));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 16));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 17));
            record.thunk = sqlite3_column_int(statement, 18) != 0;
            record.noreturn = sqlite3_column_int(statement, 19) != 0;
            loaded->functions.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_instruction,instruction_count,provenance,confidence FROM " + slot_table(active_slot, "blocks") + " ORDER BY start_value,entity_id",
        "workspace_database.load.blocks", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            basic_block_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            record.start = read_address(statement, 2);
            record.end = read_address(statement, 6);
            record.first_instruction = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
            record.instruction_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 11));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
            loaded->blocks.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,function_id,start_space,start_value,start_arch,start_mode,end_space,end_value,end_arch,end_mode,first_block,block_count,provenance,confidence,cold,shared FROM " + slot_table(active_slot, "function_chunks") + " ORDER BY chunk_index",
        "workspace_database.load.function_chunks", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            function_chunk_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            record.start = read_address(statement, 2);
            record.end = read_address(statement, 6);
            record.first_block = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
            record.block_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 11));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
            record.cold = sqlite3_column_int(statement, 14) != 0;
            record.shared = sqlite3_column_int(statement, 15) != 0;
            loaded->function_chunks.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT function_id,chunk_id,block_id,block_index,ordinal,shared FROM " + slot_table(active_slot, "function_block_memberships") + " ORDER BY membership_index",
        "workspace_database.load.function_block_memberships", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            function_block_membership_record_t record;
            record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.chunk_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            record.block_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            record.block_index = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 3));
            record.ordinal = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 4));
            record.shared = sqlite3_column_int(statement, 5) != 0;
            loaded->function_block_memberships.push_back(record);
            return workspace_result_t<void>::success();
        });
    return result;
}

workspace_result_t<void> load_relational_edges_xrefs_call_graph(
    sqlite3* database, std::uint8_t active_slot, relational_group_output_t& output,
    std::uint64_t maximum_records, const cancellation_token_t& cancel) {
    auto& loaded = output.snapshot;
    auto edge_chunks = read_snapshot_fact_chunks(
        database, active_slot, "edge_chunks", kFactChunkEdgeRecordBytes,
        kMaximumInstructionChunkRecords, output.total_rows, maximum_records, cancel,
        "workspace_database.load.edges",
        [&loaded](const std::uint8_t* record_bytes) -> workspace_result_t<void> {
            loaded->edges.push_back(decode_edge_chunk_record(record_bytes));
            return workspace_result_t<void>::success();
        });
    if (!edge_chunks)
        return workspace_result_t<void>::failure(edge_chunks.error());
    auto xref_chunks = read_snapshot_fact_chunks(
        database, active_slot, "xref_chunks", packed_xref_stream_record_bytes,
        kMaximumInstructionChunkRecords, output.total_rows, maximum_records, cancel,
        "workspace_database.load.xrefs",
        [&loaded](const std::uint8_t* record_bytes) -> workspace_result_t<void> {
            auto decoded = decode_packed_xref_record(
                record_bytes, packed_xref_stream_record_bytes);
            if (!decoded)
                return workspace_result_t<void>::failure(decoded.error());
            loaded->xrefs.push_back(decoded.take_value());
            return workspace_result_t<void>::success();
        });
    if (!xref_chunks)
        return workspace_result_t<void>::failure(xref_chunks.error());
    workspace_result_t<void> result = workspace_result_t<void>::success();
    if (!edge_chunks.value())
        result = read_snapshot_fact_rows(database,
        "SELECT entity_id,source_entity,target_entity,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,kind,provenance,confidence FROM " + slot_table(active_slot, "edges") + " ORDER BY source_value,target_value,entity_id",
        "workspace_database.load.edges", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            edge_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.source_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            if (sqlite3_column_type(statement, 2) != SQLITE_NULL)
                record.target_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            record.source = read_address(statement, 3);
            record.target = read_address(statement, 7);
            record.kind = static_cast<edge_kind_t>(sqlite3_column_int(statement, 11));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
            loaded->edges.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    if (!xref_chunks.value())
        result = read_snapshot_fact_rows(database,
        "SELECT entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,kind,provenance,confidence FROM " + slot_table(active_slot, "xrefs") + " ORDER BY source_value,target_value,entity_id",
        "workspace_database.load.xrefs", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            xref_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.source = read_address(statement, 1);
            record.target = read_address(statement, 5);
            record.kind = static_cast<xref_kind_t>(sqlite3_column_int(statement, 9));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 10));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
            loaded->xrefs.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    {
        statement_t call_graph_state;
        const std::string call_graph_state_sql =
            "SELECT indirect_site_count,unresolved_site_count,bounded FROM " +
            slot_table(active_slot, "call_graph_state") + " WHERE singleton=1";
        result = call_graph_state.prepare(database, call_graph_state_sql.c_str(),
            "workspace_database.load.call_graph_state");
        if (!result) return result;
        const int status = sqlite3_step(call_graph_state.get());
        if (status == SQLITE_ROW) {
            loaded->call_graph.indirect_site_count = static_cast<std::uint64_t>(
                sqlite3_column_int64(call_graph_state.get(), 0));
            loaded->call_graph.unresolved_site_count = static_cast<std::uint64_t>(
                sqlite3_column_int64(call_graph_state.get(), 1));
            loaded->call_graph.bounded = sqlite3_column_int(call_graph_state.get(), 2) != 0;
        } else if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(database_error(
                database, status, "unable to read call-graph state",
                "workspace_database.load.call_graph_state"));
        }
    }
    result = read_snapshot_fact_rows(database,
        "SELECT function_id,address_space,address_value,address_arch,address_mode,incoming_edges,outgoing_edges,indirect_edges,unresolved_sites FROM " + slot_table(active_slot, "call_graph_nodes") + " ORDER BY address_value,function_id",
        "workspace_database.load.call_graph_nodes", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            call_graph_node_record_t record;
            record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_address(statement, 1);
            record.incoming_edges = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
            record.outgoing_edges = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 6));
            record.indirect_edges = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 7));
            record.unresolved_sites = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 8));
            loaded->call_graph.nodes.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,source_function_id,source_block_id,instruction_id,address_space,address_value,address_arch,address_mode,first_candidate,candidate_count,indirect,tail_call,unresolved FROM " + slot_table(active_slot, "call_sites") + " ORDER BY entity_id",
        "workspace_database.load.call_sites", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            recovered_call_site_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.source_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            record.source_block_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            record.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
            record.address = read_address(statement, 4);
            record.first_candidate = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 8));
            record.candidate_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 9));
            record.indirect = sqlite3_column_int(statement, 10) != 0;
            record.tail_call = sqlite3_column_int(statement, 11) != 0;
            record.unresolved = sqlite3_column_int(statement, 12) != 0;
            loaded->call_graph.call_sites.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,call_site_id,target_space,target_value,target_arch,target_mode,target_function_id,kind,provenance,confidence,contributor_count,conflicted,stable_source_id,rank,external_target FROM " + slot_table(active_slot, "call_candidates") + " ORDER BY entity_id",
        "workspace_database.load.call_candidates", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            recovered_call_candidate_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.call_site_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            record.target = read_address(statement, 2);
            if (sqlite3_column_type(statement, 6) != SQLITE_NULL)
                record.target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 6));
            record.kind = static_cast<indirect_call_candidate_kind_t>(sqlite3_column_int(statement, 7));
            record.quality.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 8));
            record.quality.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
            record.quality.contributor_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 10));
            record.quality.conflicted = sqlite3_column_int(statement, 11) != 0;
            record.stable_source_id = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 12));
            record.rank = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 13));
            record.external_target = sqlite3_column_int(statement, 14) != 0;
            loaded->call_graph.candidates.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,call_site_id,source_function_id,source_block_id,target_function_id,call_site_space,call_site_value,call_site_arch,call_site_mode,target_space,target_value,target_arch,target_mode,resolution,provenance,confidence,contributor_count,conflicted,candidate_rank,external_target,target_noreturn FROM " + slot_table(active_slot, "call_graph_edges") + " ORDER BY entity_id",
        "workspace_database.load.call_graph_edges", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            call_graph_edge_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.call_site_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
            record.source_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            record.source_block_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
            if (sqlite3_column_type(statement, 4) != SQLITE_NULL)
                record.target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 4));
            record.call_site = read_address(statement, 5);
            record.target = read_address(statement, 9);
            record.resolution = static_cast<call_graph_resolution_t>(sqlite3_column_int(statement, 13));
            record.quality.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 14));
            record.quality.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 15));
            record.quality.contributor_count = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 16));
            record.quality.conflicted = sqlite3_column_int(statement, 17) != 0;
            record.candidate_rank = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 18));
            record.external_target = sqlite3_column_int(statement, 19) != 0;
            record.target_noreturn = sqlite3_column_int(statement, 20) != 0;
            loaded->call_graph.edges.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,kind,instruction_id,source_function_id,call_site_rva,selected_target_rva,competing_target_rva,selected_target_function_id,competing_target_function_id FROM " + slot_table(active_slot, "call_graph_conflicts") + " ORDER BY entity_id",
        "workspace_database.load.call_graph_conflicts", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            call_graph_conflict_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.kind = static_cast<call_graph_conflict_kind_t>(sqlite3_column_int(statement, 1));
            record.instruction_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 2));
            record.source_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 3));
            record.call_site_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 4));
            record.selected_target_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
            record.competing_target_rva = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 6));
            record.selected_target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 7));
            record.competing_target_function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 8));
            loaded->call_graph.conflicts.push_back(record);
            return workspace_result_t<void>::success();
        });
    return result;
}

workspace_result_t<void> load_relational_strings_symbols_coverage_rich(
    sqlite3* database, std::uint8_t active_slot, relational_group_output_t& output,
    std::uint64_t maximum_records, const cancellation_token_t& cancel) {
    auto& loaded = output.snapshot;
    auto result = read_snapshot_fact_rows(database,
        "SELECT entity_id,address_space,address_value,address_arch,address_mode,byte_length,encoding,value,provenance,confidence FROM " + slot_table(active_slot, "strings") + " ORDER BY address_value,entity_id",
        "workspace_database.load.strings", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            string_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_address(statement, 1);
            record.byte_length = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
            record.encoding = static_cast<string_encoding_t>(sqlite3_column_int(statement, 6));
            record.value = column_text(statement, 7);
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 8));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
            loaded->strings.push_back(std::move(record));
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,address_space,address_value,address_arch,address_mode,name,kind,provenance,confidence FROM " + slot_table(active_slot, "symbols") + " ORDER BY address_value,name,entity_id",
        "workspace_database.load.symbols", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            symbol_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_address(statement, 1);
            record.name = column_text(statement, 5);
            record.kind = static_cast<symbol_kind_t>(sqlite3_column_int(statement, 6));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 7));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 8));
            loaded->symbols.push_back(std::move(record));
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence FROM " + slot_table(active_slot, "rich_data_candidates") + " ORDER BY entity_id",
        "workspace_database.load.rich_data_candidates", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            data_candidate_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_address(statement, 1);
            record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
            record.kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 6));
            record.target = read_optional_address(statement, 7);
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 11));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
            loaded->rich_facts.data_candidates.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,slot_space,slot_value,slot_arch,slot_mode,target_space,target_value,target_arch,target_mode,candidate_kind,encoding,width_bytes,provenance,confidence FROM " + slot_table(active_slot, "data_pointer_facts") + " ORDER BY entity_id",
        "workspace_database.load.data_pointer_facts", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            data_pointer_fact_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.slot = read_address(statement, 1);
            record.target = read_address(statement, 5);
            record.candidate_kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 9));
            record.encoding = static_cast<data_pointer_encoding_t>(sqlite3_column_int(statement, 10));
            record.width_bytes = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 12));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
            loaded->rich_facts.data_pointer_facts.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,address_space,address_value,address_arch,address_mode,kind,selected_target_space,selected_target_value,selected_target_arch,selected_target_mode,rejected_target_space,rejected_target_value,rejected_target_arch,rejected_target_mode,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence FROM " + slot_table(active_slot, "data_conflicts") + " ORDER BY entity_id",
        "workspace_database.load.data_conflicts", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            data_candidate_conflict_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_address(statement, 1);
            record.kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 5));
            record.selected_target = read_optional_address(statement, 6);
            record.rejected_target = read_optional_address(statement, 10);
            record.selected_provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 14));
            record.rejected_provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 15));
            record.selected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 16));
            record.rejected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 17));
            loaded->rich_facts.data_conflicts.push_back(record);
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,address_space,address_value,address_arch,address_mode,related_space,related_value,related_arch,related_mode,kind,display_name,canonical_type,source_key,provenance,confidence,explicitly_unknown FROM " + slot_table(active_slot, "symbol_type_candidates") + " ORDER BY entity_id",
        "workspace_database.load.symbol_type_candidates", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            symbol_type_candidate_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_optional_address(statement, 1);
            record.related_address = read_optional_address(statement, 5);
            record.kind = static_cast<symbol_type_candidate_kind_t>(sqlite3_column_int(statement, 9));
            record.display_name = column_text(statement, 10);
            record.canonical_type = column_text(statement, 11);
            record.source_key = column_text(statement, 12);
            record.provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 13));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 14));
            record.explicitly_unknown = sqlite3_column_int(statement, 15) != 0;
            loaded->rich_facts.type_candidates.push_back(std::move(record));
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,source_space,source_value,source_arch,source_mode,target_space,target_value,target_arch,target_mode,source_entity,target_entity,kind,provenance,confidence,source_key FROM " + slot_table(active_slot, "type_references") + " ORDER BY entity_id",
        "workspace_database.load.type_references", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            type_reference_fact_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.source = read_optional_address(statement, 1);
            record.target = read_optional_address(statement, 5);
            record.source_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 9));
            record.target_entity = static_cast<entity_id_t>(sqlite3_column_int64(statement, 10));
            record.kind = static_cast<type_reference_kind_t>(sqlite3_column_int(statement, 11));
            record.provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 12));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 13));
            record.source_key = column_text(statement, 14);
            loaded->rich_facts.type_references.push_back(std::move(record));
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT entity_id,address_space,address_value,address_arch,address_mode,identity,kind,selected_value,rejected_value,selected_provenance,rejected_provenance,selected_confidence,rejected_confidence FROM " + slot_table(active_slot, "metadata_conflicts") + " ORDER BY entity_id",
        "workspace_database.load.metadata_conflicts", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            metadata_conflict_record_t record;
            record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
            record.address = read_optional_address(statement, 1);
            record.identity = column_text(statement, 5);
            record.kind = static_cast<metadata_conflict_kind_t>(sqlite3_column_int(statement, 6));
            record.selected_value = column_text(statement, 7);
            record.rejected_value = column_text(statement, 8);
            record.selected_provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 9));
            record.rejected_provenance = static_cast<metadata_provenance_t>(sqlite3_column_int(statement, 10));
            record.selected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 11));
            record.rejected_confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
            loaded->rich_facts.metadata_conflicts.push_back(std::move(record));
            return workspace_result_t<void>::success();
        });
    if (!result) return result;
    result = read_snapshot_fact_rows(database,
        "SELECT start_space,start_value,start_arch,start_mode,size,reason,provenance,confidence,detail_code FROM " + slot_table(active_slot, "coverage") + " ORDER BY start_value,span_id",
        "workspace_database.load.coverage", output.total_rows, maximum_records, cancel,
        [&](sqlite3_stmt* statement) -> workspace_result_t<void> {
            coverage_span_t record;
            record.start = read_address(statement, 0);
            record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 4));
            record.reason = static_cast<coverage_reason_t>(sqlite3_column_int(statement, 5));
            record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 6));
            record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 7));
            record.detail_code = static_cast<std::uint32_t>(sqlite3_column_int64(statement, 8));
            loaded->coverage.push_back(record);
            return workspace_result_t<void>::success();
        });
    return result;
}

void run_relational_group_task(
    const workspace_database_t::connection_state_t& conn,
    const workspace_database_options_t& options,
    std::uint8_t active_slot,
    int group_index,
    const cancellation_token_t& cancel,
    const std::shared_ptr<relational_group_task_t>& task) {
    auto opened = open_reader_connection(conn.path, options);
    if (!opened) {
        task->error = opened.error();
        return;
    }
    sqlite3* database = opened.take_value();
    auto result = exec_sql(database, "BEGIN", "workspace_database.load.group");
    if (result) {
        switch (group_index) {
        case 0:
            result = load_relational_instruction_blobs(database, active_slot, *task, cancel);
            break;
        case 1:
            result = load_relational_operands_targets(
                database, active_slot, task->output, options.max_persisted_fact_records, cancel);
            break;
        case 2:
            result = load_relational_functions_blocks(
                database, active_slot, task->output, options.max_persisted_fact_records, cancel);
            break;
        case 3:
            result = load_relational_edges_xrefs_call_graph(
                database, active_slot, task->output, options.max_persisted_fact_records, cancel);
            break;
        default:
            result = load_relational_strings_symbols_coverage_rich(
                database, active_slot, task->output, options.max_persisted_fact_records, cancel);
            break;
        }
    }
    if (result) {
        auto committed = exec_sql(database, "COMMIT", "workspace_database.load.group");
        if (!committed) {
            exec_sql(database, "ROLLBACK", "workspace_database.load.group");
            result = committed;
        }
    } else {
        exec_sql(database, "ROLLBACK", "workspace_database.load.group");
    }
    sqlite3_close_v2(database);
    if (!result)
        task->error = result.error();
}

}

workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>
workspace_database_t::load_snapshot(std::shared_ptr<const pe_image_t> image,
                                    const cancellation_token_t& cancel) {
    return load_snapshot(std::shared_ptr<const workspace_image_t>{}, std::move(image), cancel);
}

workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>
workspace_database_t::load_snapshot(std::shared_ptr<const workspace_image_t> image,
                                    std::shared_ptr<const pe_image_t> pe_adapter,
                                    const cancellation_token_t& cancel) {
    const auto committed_generation =
        state_->persisted_generation.load(std::memory_order_acquire);
    const auto committed_analysis_revision =
        state_->persisted_analysis_revision.load(std::memory_order_acquire);
    const auto committed_overlay_revision =
        state_->persisted_overlay_revision.load(std::memory_order_acquire);
    if ((image && !image_matches_persistence_identity(
                      *image, *options_.identity, committed_generation,
                      committed_overlay_revision)) ||
        (pe_adapter && !image_matches_identity(*pe_adapter, *options_.identity))) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::target_conflict,
                "requested image identity does not match the workspace database",
                "workspace_database.load"));
    }
    if (committed_generation != 0) {
        std::optional<decoded_packed_baseline_t> packed_decoded;
        std::optional<packed_generation_record_t> packed_record;
        auto packed_read = with_reader(
            [&](sqlite3* database) -> workspace_result_t<void> {
                auto record = read_packed_generation(
                    database, committed_generation, true,
                    [&cancel] { return cancel.stop_requested(); });
                if (!record)
                    return workspace_result_t<void>::failure(record.error());
                if (!record.value())
                    return workspace_result_t<void>::success();
                auto manifest = decode_packed_baseline_manifest(
                    record.value()->payload_blob, cancel);
                if (!manifest)
                    return workspace_result_t<void>::failure(manifest.error());
                if (!manifest.value().baseline_complete) {
                    if (record.value()->shard_count != 1U)
                        return workspace_result_t<void>::failure(
                            packed_baseline_error(
                                workspace_error_code_t::integrity_failure,
                                "partial packed generation has an invalid domain count"));
                    return workspace_result_t<void>::success();
                }
                packed_record = std::move(*record.value());
                return workspace_result_t<void>::success();
            }, cancel);
        if (!packed_read) {
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                packed_read.error());
        }
        if (packed_record) {
            auto decoded = decode_packed_baseline_generation(
                *state_, options_, *packed_record, std::move(image),
                std::move(pe_adapter), *options_.identity,
                options_.max_persisted_fact_records,
                options_.packed_generation_quota_bytes, cancel);
            if (!decoded) {
                return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                    decoded.error());
            }
            packed_decoded = decoded.take_value();
        }
        if (packed_decoded) {
            if (packed_decoded->snapshot->generation != committed_generation ||
                packed_decoded->snapshot->analysis_revision !=
                    committed_analysis_revision ||
                packed_decoded->snapshot->overlay_revision !=
                    committed_overlay_revision ||
                state_->persisted_generation.load(std::memory_order_acquire) !=
                    committed_generation ||
                state_->persisted_analysis_revision.load(
                    std::memory_order_acquire) != committed_analysis_revision ||
                state_->persisted_overlay_revision.load(
                    std::memory_order_acquire) != committed_overlay_revision) {
                return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                    make_workspace_error(
                        workspace_error_code_t::stale_generation,
                        "packed baseline changed during reopen",
                        "workspace_database.load.packed"));
            }
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(
                std::shared_ptr<const analysis_snapshot_t>(
                    std::move(packed_decoded->snapshot)));
        }
    }
    auto loaded = std::make_shared<analysis_snapshot_t>();
    loaded->binary_id = options_.identity->binary_id();
    loaded->load_profile_hash = options_.identity->load_profile_hash();
    loaded->normalized_image = std::move(image);
    loaded->image = std::move(pe_adapter);
    bool found = false;
    std::uint8_t active_slot = 0;
    auto result = with_reader([&](sqlite3* database) -> workspace_result_t<void> {
        auto commit_state = read_commit_state(database, "workspace_database.load");
        if (!commit_state)
            return workspace_result_t<void>::failure(commit_state.error());
        if (commit_state.value().committed_token.empty())
            return workspace_result_t<void>::success();
        active_slot = commit_state.value().active_slot;
        statement_t state_statement;
        const std::string state_select = "SELECT generation,analysis_revision,overlay_revision,baseline_complete,commit_token FROM " +
            slot_table(active_slot, "analysis_state") + " WHERE singleton=1";
        auto current = state_statement.prepare(database, state_select.c_str(),
            "workspace_database.load");
        if (!current) return current;
        int status = sqlite3_step(state_statement.get());
        if (status == SQLITE_DONE)
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "promoted analysis slot has no state row",
                "workspace_database.load"));
        if (status != SQLITE_ROW)
            return workspace_result_t<void>::failure(database_error(database, status,
                "unable to read analysis state", "workspace_database.load"));
        found = true;
        loaded->generation = static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 0));
        loaded->analysis_revision = static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 1));
        loaded->overlay_revision = static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 2));
        loaded->baseline_complete = sqlite3_column_int(state_statement.get(), 3) != 0;
        if (column_text(state_statement.get(), 4) !=
                commit_state.value().committed_token ||
            loaded->generation != commit_state.value().committed_generation ||
            loaded->analysis_revision !=
                commit_state.value().committed_analysis_revision ||
            loaded->overlay_revision !=
                commit_state.value().committed_overlay_revision) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "active analysis slot does not match the promoted commit marker",
                "workspace_database.load"));
        }

        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(result.error());
    if (!found)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success({});
    std::array<std::shared_ptr<relational_group_task_t>, 5> group_tasks;
    aida::infra::taskflow_runtime::graph_descriptor_t group_graph;
    group_graph.domain = aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
    group_graph.owner_subsystem = "analysis_persistence";
    group_graph.label = "analysis.persistence.reopen_relational";
    group_graph.phase = "persistence";
    group_graph.priority = 2;
    for (int group_index = 0; group_index < 5; ++group_index) {
        auto task = std::make_shared<relational_group_task_t>();
        group_tasks[static_cast<std::size_t>(group_index)] = task;
        aida::infra::taskflow_runtime::graph_node_descriptor_t node;
        node.node_id = static_cast<std::uint64_t>(group_index) + 1;
        node.label = "analysis.persistence.reopen_relational_group";
        node.cancellable_body = [state = state_, options = options_, active_slot,
                                 group_index, &cancel, task](
            const aida::infra::taskflow_runtime::cancellation_token_t&) {
            run_relational_group_task(*state, options, active_slot, group_index,
                                      cancel, task);
        };
        group_graph.nodes.push_back(std::move(node));
    }
    auto group_submission = aida::infra::taskflow_runtime::submit_graph(
        std::move(group_graph));
    if (!group_submission.submitted) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(
                workspace_error_code_t::persistence_failure,
                std::string("relational reopen dispatch was rejected: ") +
                    group_submission.reject_reason,
                "workspace_database.load"));
    }
    for (;;) {
        const auto waited = aida::infra::taskflow_runtime::wait_for(
            group_submission.handle, 50);
        if (waited.completed)
            break;
        if (cancel.stop_requested())
            aida::infra::taskflow_runtime::cancel(group_submission.handle);
    }
    std::uint64_t total_rows = 0;
    for (const auto& task : group_tasks) {
        if (task->error) {
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                *task->error);
        }
        if (!checked_add_u64(total_rows, task->output.total_rows, total_rows)) {
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                                     "persisted fact row accounting overflowed",
                                     "workspace_database.load"));
        }
    }
    auto& instruction_blobs = group_tasks[0]->instruction_blobs;
    std::uint64_t instruction_records = 0;
    if (!instruction_blobs.empty()) {
        const auto hardware = std::thread::hardware_concurrency();
        const std::size_t range_count = (std::min<std::size_t>)(
            instruction_blobs.size(),
            static_cast<std::size_t>((std::max)(
                2U, (std::min)(16U, hardware == 0 ? 2U : hardware))));
        std::vector<std::vector<std::vector<instruction_record_t>>> chunk_outputs(
            range_count);
        std::vector<std::optional<workspace_error_t>> range_errors(range_count);
        aida::infra::taskflow_runtime::graph_descriptor_t decode_graph;
        decode_graph.domain =
            aida::infra::taskflow_runtime::executor_domain_t::feature_worker;
        decode_graph.owner_subsystem = "analysis_persistence";
        decode_graph.label = "analysis.persistence.reopen_instructions";
        decode_graph.phase = "persistence";
        decode_graph.priority = 2;
        for (std::size_t range = 0; range < range_count; ++range) {
            aida::infra::taskflow_runtime::graph_node_descriptor_t node;
            node.node_id = static_cast<std::uint64_t>(range) + 1;
            node.label = "analysis.persistence.reopen_instruction_chunks";
            node.cancellable_body = [&instruction_blobs, range, range_count,
                                     &chunk_outputs, &range_errors,
                                     maximum = options_.max_persisted_fact_records,
                                     &cancel](
                const aida::infra::taskflow_runtime::cancellation_token_t&) {
                auto& outputs = chunk_outputs[range];
                for (std::size_t index = range; index < instruction_blobs.size();
                     index += range_count) {
                    if (cancel.stop_requested()) {
                        range_errors[range] = packed_baseline_cancelled(cancel);
                        return;
                    }
                    outputs.emplace_back();
                    auto decoded = decode_instruction_chunk(
                        instruction_blobs[index].second.data(),
                        instruction_blobs[index].second.size(), outputs.back(),
                        maximum, kMaximumInstructionChunkRecords, cancel);
                    if (!decoded) {
                        range_errors[range] = decoded.error();
                        return;
                    }
                }
            };
            decode_graph.nodes.push_back(std::move(node));
        }
        auto decode_submission = aida::infra::taskflow_runtime::submit_graph(
            std::move(decode_graph));
        if (!decode_submission.submitted) {
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                make_workspace_error(
                    workspace_error_code_t::persistence_failure,
                    std::string("instruction reopen dispatch was rejected: ") +
                        decode_submission.reject_reason,
                    "workspace_database.load"));
        }
        for (;;) {
            const auto waited = aida::infra::taskflow_runtime::wait_for(
                decode_submission.handle, 50);
            if (waited.completed)
                break;
            if (cancel.stop_requested())
                aida::infra::taskflow_runtime::cancel(decode_submission.handle);
        }
        for (const auto& error : range_errors) {
            if (error) {
                return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                    *error);
            }
        }
        for (const auto& outputs : chunk_outputs) {
            for (const auto& records : outputs) {
                if (!checked_add_u64(instruction_records, records.size(),
                                     instruction_records)) {
                    return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                        make_workspace_error(workspace_error_code_t::range_overflow,
                                             "persisted instruction accounting overflowed",
                                             "workspace_database.load.instructions"));
                }
            }
        }
        if (instruction_records >
                options_.max_persisted_fact_records - (std::min)(total_rows, options_.max_persisted_fact_records) ||
            !checked_add_u64(total_rows, instruction_records, total_rows)) {
            return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "persisted instructions exceed the reopen budget",
                                     "workspace_database.load.instructions"));
        }
        loaded->instructions.reserve(static_cast<std::size_t>(instruction_records));
        for (std::size_t index = 0; index < instruction_blobs.size(); ++index) {
            const std::size_t range = index % range_count;
            const std::size_t ordinal = index / range_count;
            auto& records = chunk_outputs[range][ordinal];
            loaded->instructions.insert(loaded->instructions.end(),
                std::make_move_iterator(records.begin()),
                std::make_move_iterator(records.end()));
        }
    }
    if (total_rows > options_.max_persisted_fact_records) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "persisted fact rows exceed the reopen budget",
                                 "workspace_database.load"));
    }
    loaded->operand_facts = std::move(group_tasks[1]->output.snapshot.operand_facts);
    loaded->target_facts = std::move(group_tasks[1]->output.snapshot.target_facts);
    loaded->functions = std::move(group_tasks[2]->output.snapshot.functions);
    loaded->blocks = std::move(group_tasks[2]->output.snapshot.blocks);
    loaded->function_chunks = std::move(group_tasks[2]->output.snapshot.function_chunks);
    loaded->function_block_memberships =
        std::move(group_tasks[2]->output.snapshot.function_block_memberships);
    loaded->edges = std::move(group_tasks[3]->output.snapshot.edges);
    loaded->xrefs = std::move(group_tasks[3]->output.snapshot.xrefs);
    loaded->call_graph = std::move(group_tasks[3]->output.snapshot.call_graph);
    loaded->strings = std::move(group_tasks[4]->output.snapshot.strings);
    loaded->symbols = std::move(group_tasks[4]->output.snapshot.symbols);
    loaded->coverage = std::move(group_tasks[4]->output.snapshot.coverage);
    loaded->rich_facts = std::move(group_tasks[4]->output.snapshot.rich_facts);
    snapshot_repair_operand_instruction_ordinals(*loaded);
    auto recheck = with_reader([&](sqlite3* database) -> workspace_result_t<void> {
        auto commit_state = read_commit_state(database, "workspace_database.load");
        if (!commit_state)
            return workspace_result_t<void>::failure(commit_state.error());
        if (commit_state.value().committed_token.empty() ||
            commit_state.value().active_slot != active_slot ||
            commit_state.value().committed_generation != loaded->generation ||
            commit_state.value().committed_analysis_revision !=
                loaded->analysis_revision ||
            commit_state.value().committed_overlay_revision != loaded->overlay_revision) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "persisted analysis changed during reopen",
                "workspace_database.load"));
        }
        statement_t state_statement;
        const std::string state_select =
            "SELECT generation,analysis_revision,overlay_revision,commit_token FROM " +
            slot_table(active_slot, "analysis_state") + " WHERE singleton=1";
        auto current = state_statement.prepare(database, state_select.c_str(),
            "workspace_database.load");
        if (!current) return current;
        const int status = sqlite3_step(state_statement.get());
        if (status != SQLITE_ROW ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 0)) !=
                loaded->generation ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 1)) !=
                loaded->analysis_revision ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 2)) !=
                loaded->overlay_revision ||
            column_text(state_statement.get(), 3) !=
                commit_state.value().committed_token) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "persisted analysis slot changed during reopen",
                "workspace_database.load"));
        }
        return workspace_result_t<void>::success();
    }, cancel);
    if (!recheck)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            recheck.error());

    auto validated = validate_analysis_snapshot(*loaded, loaded->baseline_complete, cancel);
    if (!validated)
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(validated.error());
    state_->persisted_generation.store(loaded->generation, std::memory_order_release);
    state_->persisted_analysis_revision.store(loaded->analysis_revision, std::memory_order_release);
    state_->persisted_overlay_revision.store(loaded->overlay_revision, std::memory_order_release);

    if (!loaded->baseline_complete) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::success(
            std::shared_ptr<const analysis_snapshot_t>(std::move(loaded)));
    }

    auto products = load_search_products(
        loaded->generation, loaded->analysis_revision, loaded->overlay_revision,
        cancel);
    if (!products) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            products.error());
    }
    auto migration_products = products.take_value();
    auto migration_index = search_index_t::build(
        std::shared_ptr<const analysis_snapshot_t>(loaded),
        std::move(migration_products.data_candidates),
        std::move(migration_products.switches),
        std::move(migration_products.types),
        std::make_shared<analysis_metrics_t>(loaded->generation), {}, cancel);
    if (!migration_index) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            migration_index.error());
    }
    migration_products.search_index_blob_version = 0;
    std::vector<std::uint8_t>().swap(
        migration_products.search_index_blob);
    migration_products.live_index = migration_index.take_value();
    auto ticket = persist_snapshot(
        std::shared_ptr<const analysis_snapshot_t>(loaded),
        std::move(migration_products), "{}", "{}", cancel);
    if (!ticket.accepted || !ticket.completion.valid() ||
        !ticket.snapshot_candidate ||
        !ticket.snapshot_candidate->packed_generation_required()) {
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            make_workspace_error(
                workspace_error_code_t::persistence_failure,
                "legacy baseline migration was not accepted as a packed candidate",
                "workspace_database.load.migrate_packed"));
    }
    auto published = await_persistence_completion(
        ticket, cancel, "workspace_database.load.migrate_packed");
    if (!published) {
        ticket.snapshot_candidate->discard();
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            published.error());
    }
    auto finalized = ticket.snapshot_candidate->finalize(cancel);
    if (!finalized) {
        ticket.snapshot_candidate->discard();
        return workspace_result_t<std::shared_ptr<const analysis_snapshot_t>>::failure(
            finalized.error());
    }
    return load_snapshot(loaded->normalized_image, loaded->image, cancel);
}

workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>
workspace_database_t::load_managed_publication(
    std::shared_ptr<const byte_provider_t> provider,
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision,
    const cancellation_token_t& cancel) const {
    if (!provider || expected_generation == 0 ||
        expected_analysis_revision == 0 ||
        state_->persisted_generation.load(std::memory_order_acquire) !=
            expected_generation ||
        state_->persisted_analysis_revision.load(std::memory_order_acquire) !=
            expected_analysis_revision ||
        state_->persisted_overlay_revision.load(std::memory_order_acquire) !=
            expected_overlay_revision) {
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "managed publication reopen identity is stale",
                                 "workspace_database.load.managed"));
    }
    std::shared_ptr<const managed_artifact_publication_t> publication;
    auto loaded = with_reader(
        [&](sqlite3* database) -> workspace_result_t<void> {
            auto generation = read_packed_generation(
                database, expected_generation, true,
                [&cancel] { return cancel.stop_requested(); });
            if (!generation)
                return workspace_result_t<void>::failure(generation.error());
            if (!generation.value())
                return workspace_result_t<void>::success();
            auto manifest = decode_packed_baseline_manifest(
                generation.value()->payload_blob, cancel);
            if (!manifest)
                return workspace_result_t<void>::failure(manifest.error());
            if (manifest.value().generation != expected_generation ||
                manifest.value().analysis_revision != expected_analysis_revision ||
                manifest.value().overlay_revision != expected_overlay_revision ||
                generation.value()->analysis_revision != expected_analysis_revision ||
                generation.value()->overlay_revision != expected_overlay_revision) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(workspace_error_code_t::stale_generation,
                                          "managed packed generation revision is stale"));
            }
            const auto baseline_domains = static_cast<std::uint16_t>(
                packed_page_baseline_last_data_type);
            bool managed_expected = false;
            if (manifest.value().baseline_complete) {
                if (generation.value()->shard_count == baseline_domains)
                    return workspace_result_t<void>::success();
                if (generation.value()->shard_count != baseline_domains + 1U) {
                    return workspace_result_t<void>::failure(
                        packed_baseline_error(workspace_error_code_t::integrity_failure,
                                              "complete packed generation has an invalid domain count"));
                }
                managed_expected = true;
            } else {
                if (generation.value()->shard_count != 1U) {
                    return workspace_result_t<void>::failure(
                        packed_baseline_error(workspace_error_code_t::integrity_failure,
                                              "partial managed generation has an invalid domain count"));
                }
                managed_expected = true;
            }
            if (!managed_expected)
                return workspace_result_t<void>::success();
            auto payload = read_packed_domain_payload(
                database, *generation.value(),
                packed_page_type_t::managed_publication,
                managed_publication_max_payload_bytes, cancel);
            if (!payload)
                return workspace_result_t<void>::failure(payload.error());
            if (payload.value().empty()) {
                return workspace_result_t<void>::failure(
                    packed_baseline_error(workspace_error_code_t::integrity_failure,
                                          "managed publication domain is empty"));
            }
            auto decoded = decode_managed_publication_domain(
                payload.value(), *options_.identity, *provider,
                expected_generation, expected_analysis_revision,
                expected_overlay_revision,
                managed_publication_max_payload_bytes, cancel);
            if (!decoded)
                return workspace_result_t<void>::failure(decoded.error());
            publication = decoded.take_value();
            return workspace_result_t<void>::success();
        }, cancel);
    if (!loaded)
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            loaded.error());
    if (state_->persisted_generation.load(std::memory_order_acquire) !=
            expected_generation ||
        state_->persisted_analysis_revision.load(std::memory_order_acquire) !=
            expected_analysis_revision ||
        state_->persisted_overlay_revision.load(std::memory_order_acquire) !=
            expected_overlay_revision) {
        return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::failure(
            make_workspace_error(workspace_error_code_t::stale_generation,
                                 "managed publication changed during reopen",
                                 "workspace_database.load.managed"));
    }
    return workspace_result_t<std::shared_ptr<const managed_artifact_publication_t>>::success(
        std::move(publication));
}

workspace_result_t<persisted_search_products_t>
workspace_database_t::load_search_products(
    std::uint64_t expected_generation,
    std::uint64_t expected_analysis_revision,
    std::uint64_t expected_overlay_revision,
    const cancellation_token_t& cancel) const {
    if (state_->persisted_generation.load(std::memory_order_acquire) !=
            expected_generation ||
        state_->persisted_analysis_revision.load(std::memory_order_acquire) !=
            expected_analysis_revision ||
        state_->persisted_overlay_revision.load(std::memory_order_acquire) !=
            expected_overlay_revision) {
        return workspace_result_t<persisted_search_products_t>::failure(
            make_workspace_error(
                workspace_error_code_t::stale_generation,
                "requested search products are not the committed workspace revision",
                "workspace_database.load_search.packed"));
    }
    if (expected_generation != 0) {
        std::optional<persisted_search_products_t> packed_products;
        auto packed_read = with_reader(
            [&](sqlite3* database) -> workspace_result_t<void> {
                auto record = read_packed_generation(
                    database, expected_generation, true,
                    [&cancel] { return cancel.stop_requested(); });
                if (!record)
                    return workspace_result_t<void>::failure(record.error());
                if (!record.value())
                    return workspace_result_t<void>::success();
                auto manifest = decode_packed_baseline_manifest(
                    record.value()->payload_blob, cancel);
                if (!manifest)
                    return workspace_result_t<void>::failure(manifest.error());
                if (manifest.value().generation != expected_generation ||
                    manifest.value().analysis_revision != expected_analysis_revision ||
                    manifest.value().overlay_revision != expected_overlay_revision ||
                    !manifest.value().binary_id.constant_time_equal(
                        options_.identity->binary_id()) ||
                    !manifest.value().load_profile_hash.constant_time_equal(
                        options_.identity->load_profile_hash())) {
                    return workspace_result_t<void>::failure(
                        make_workspace_error(workspace_error_code_t::target_conflict,
                                             "packed search manifest identity is inconsistent",
                                             "workspace_database.load_search.packed"));
                }
                if (!manifest.value().baseline_complete)
                    return workspace_result_t<void>::success();
                auto payload = read_packed_domain_payload(
                    database, *record.value(),
                    packed_page_type_t::search_index,
                    options_.packed_generation_quota_bytes, cancel);
                if (!payload)
                    return workspace_result_t<void>::failure(payload.error());
                auto decoded = decode_packed_search_products_payload(
                    manifest.value(), payload.take_value(),
                    options_.max_persisted_fact_records, cancel);
                if (!decoded)
                    return workspace_result_t<void>::failure(decoded.error());
                packed_products = decoded.take_value();
                return workspace_result_t<void>::success();
            }, cancel);
        if (!packed_read)
            return workspace_result_t<persisted_search_products_t>::failure(
                packed_read.error());
        if (packed_products) {
            if (state_->persisted_generation.load(std::memory_order_acquire) !=
                    expected_generation ||
                state_->persisted_analysis_revision.load(
                    std::memory_order_acquire) != expected_analysis_revision ||
                state_->persisted_overlay_revision.load(
                    std::memory_order_acquire) != expected_overlay_revision) {
                return workspace_result_t<persisted_search_products_t>::failure(
                    make_workspace_error(workspace_error_code_t::stale_generation,
                                         "packed search products changed during reopen",
                                         "workspace_database.load_search.packed"));
            }
            return workspace_result_t<persisted_search_products_t>::success(
                std::move(*packed_products));
        }
    }
    persisted_search_products_t products;
    products.generation = expected_generation;
    products.analysis_revision = expected_analysis_revision;
    products.overlay_revision = expected_overlay_revision;
    auto result = with_reader([&](sqlite3* database) -> workspace_result_t<void> {
        auto commit_state = read_commit_state(database,
                                              "workspace_database.load_search");
        if (!commit_state)
            return workspace_result_t<void>::failure(commit_state.error());
        if (commit_state.value().committed_token.empty()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::target_not_found,
                "persisted analysis products are not available",
                "workspace_database.load_search"));
        }
        const std::uint8_t active_slot = commit_state.value().active_slot;
        statement_t state_statement;
        const std::string state_select = "SELECT generation,analysis_revision,overlay_revision,commit_token FROM " +
            slot_table(active_slot, "analysis_state") + " WHERE singleton=1";
        auto current = state_statement.prepare(database, state_select.c_str(),
            "workspace_database.load_search");
        if (!current) return current;
        int status = sqlite3_step(state_statement.get());
        if (status != SQLITE_ROW) {
            if (status == SQLITE_DONE) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::target_not_found,
                    "persisted analysis products are not available",
                    "workspace_database.load_search"));
            }
            return workspace_result_t<void>::failure(database_error(database, status,
                "unable to read persisted analysis product revision",
                "workspace_database.load_search"));
        }
        if (column_text(state_statement.get(), 3) !=
                commit_state.value().committed_token ||
            commit_state.value().committed_generation != expected_generation ||
            commit_state.value().committed_analysis_revision != expected_analysis_revision ||
            commit_state.value().committed_overlay_revision != expected_overlay_revision ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 0)) != expected_generation ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 1)) != expected_analysis_revision ||
            static_cast<std::uint64_t>(sqlite3_column_int64(state_statement.get(), 2)) != expected_overlay_revision) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "persisted analysis products do not match requested revisions",
                "workspace_database.load_search"));
        }

        std::uint64_t total_rows = 0;
        auto read_rows = [&](const std::string& sql, const char* phase, auto reader) -> workspace_result_t<void> {
            statement_t statement;
            auto prepared = statement.prepare(database, sql.c_str(), phase);
            if (!prepared) return prepared;
            std::size_t row = 0;
            for (;;) {
                if ((row++ & 255U) == 0 && cancel.stop_requested()) {
                    auto error = make_workspace_error(cancel.deadline_exceeded()
                                                          ? workspace_error_code_t::deadline_exceeded
                                                          : workspace_error_code_t::cancelled,
                                                      "search product reopen cancelled", phase);
                    error.deadline = cancel.deadline_exceeded();
                    error.cancellation = !error.deadline;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                const int step_status = sqlite3_step(statement.get());
                if (step_status == SQLITE_DONE)
                    return workspace_result_t<void>::success();
                if (step_status != SQLITE_ROW)
                    return workspace_result_t<void>::failure(database_error(database, step_status,
                        "unable to read search product row", phase));
                if (++total_rows > options_.max_persisted_fact_records) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::limit_exceeded,
                        "persisted search rows exceed the reopen budget", phase));
                }
                auto row_result = reader(statement.get());
                if (!row_result) return row_result;
            }
        };

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,size,kind,target_space,target_value,target_arch,target_mode,provenance,confidence FROM " + slot_table(active_slot, "data_candidates") + " ORDER BY address_value,entity_id",
            "workspace_database.load_search.data", [&](sqlite3_stmt* statement) {
                data_candidate_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.size = static_cast<std::uint64_t>(sqlite3_column_int64(statement, 5));
                record.kind = static_cast<data_candidate_kind_t>(sqlite3_column_int(statement, 6));
                if (sqlite3_column_type(statement, 7) != SQLITE_NULL)
                    record.target = read_address(statement, 7);
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 11));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 12));
                products.data_candidates.push_back(record);
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,function_id,dispatch_space,dispatch_value,dispatch_arch,dispatch_mode,table_space,table_value,table_arch,table_mode,default_space,default_value,default_arch,default_mode,entry_size,relative_entries,provenance,confidence FROM " + slot_table(active_slot, "switches") + " ORDER BY dispatch_value,entity_id",
            "workspace_database.load_search.switches", [&](sqlite3_stmt* statement) {
                switch_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.function_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 1));
                record.dispatch = read_address(statement, 2);
                record.table = read_address(statement, 6);
                if (sqlite3_column_type(statement, 10) != SQLITE_NULL)
                    record.default_target = read_address(statement, 10);
                record.entry_size = static_cast<std::uint8_t>(sqlite3_column_int(statement, 14));
                record.relative_entries = sqlite3_column_int(statement, 15) != 0;
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 16));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 17));
                products.switches.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        std::unordered_map<entity_id_t, std::size_t> switch_indexes;
        for (std::size_t index = 0; index < products.switches.size(); ++index)
            switch_indexes.emplace(products.switches[index].id, index);
        current = read_rows("SELECT switch_id,target_space,target_value,target_arch,target_mode FROM " + slot_table(active_slot, "switch_cases") + " ORDER BY switch_id,case_index",
            "workspace_database.load_search.switch_cases", [&](sqlite3_stmt* statement) {
                const entity_id_t switch_id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                auto found = switch_indexes.find(switch_id);
                if (found == switch_indexes.end()) {
                    return workspace_result_t<void>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "switch case references a missing switch",
                        "workspace_database.load_search.switch_cases"));
                }
                products.switches[found->second].case_targets.push_back(read_address(statement, 1));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        current = read_rows("SELECT entity_id,address_space,address_value,address_arch,address_mode,kind,display_name,canonical_type,provenance,confidence,explicitly_unknown FROM " + slot_table(active_slot, "type_candidates") + " ORDER BY address_value,entity_id",
            "workspace_database.load_search.types", [&](sqlite3_stmt* statement) {
                type_candidate_record_t record;
                record.id = static_cast<entity_id_t>(sqlite3_column_int64(statement, 0));
                record.address = read_address(statement, 1);
                record.kind = static_cast<type_candidate_kind_t>(sqlite3_column_int(statement, 5));
                record.display_name = column_text(statement, 6);
                record.canonical_type = column_text(statement, 7);
                record.provenance = static_cast<fact_provenance_t>(sqlite3_column_int(statement, 8));
                record.confidence = static_cast<std::uint8_t>(sqlite3_column_int(statement, 9));
                record.explicitly_unknown = sqlite3_column_int(statement, 10) != 0;
                products.types.push_back(std::move(record));
                return workspace_result_t<void>::success();
            });
        if (!current) return current;

        statement_t blob_statement;
        const std::string blob_select = "SELECT generation,analysis_revision,overlay_revision,blob_version,length(payload),payload FROM " +
            slot_table(active_slot, "search_index_blob") + " WHERE singleton=1";
        current = blob_statement.prepare(database, blob_select.c_str(),
            "workspace_database.load_search.blob");
        if (!current) return current;
        status = sqlite3_step(blob_statement.get());
        if (status == SQLITE_ROW) {
            if (static_cast<std::uint64_t>(sqlite3_column_int64(blob_statement.get(), 0)) != expected_generation ||
                static_cast<std::uint64_t>(sqlite3_column_int64(blob_statement.get(), 1)) != expected_analysis_revision ||
                static_cast<std::uint64_t>(sqlite3_column_int64(blob_statement.get(), 2)) != expected_overlay_revision) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::stale_generation,
                    "persisted search index blob revision is stale",
                    "workspace_database.load_search.blob"));
            }
            products.search_index_blob_version = static_cast<std::uint32_t>(sqlite3_column_int(blob_statement.get(), 3));
            const auto declared_bytes = sqlite3_column_int64(blob_statement.get(), 4);
            if (declared_bytes < 0 ||
                static_cast<std::uint64_t>(declared_bytes) > workspace_search_blob_limit) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "persisted search index blob exceeds its reopen budget",
                    "workspace_database.load_search.blob"));
            }
            const void* payload = sqlite3_column_blob(blob_statement.get(), 5);
            const int bytes = sqlite3_column_bytes(blob_statement.get(), 5);
            if (bytes < 0 || bytes != declared_bytes || (bytes > 0 && !payload)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "persisted search index blob is malformed",
                    "workspace_database.load_search.blob"));
            }
            if (bytes > 0) {
                if (cancel.stop_requested()) {
                    auto error = make_workspace_error(
                        cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                                   : workspace_error_code_t::cancelled,
                        "search index blob read was cancelled",
                        "workspace_database.load_search.blob");
                    error.deadline = cancel.deadline_exceeded();
                    error.cancellation = !error.deadline;
                    return workspace_result_t<void>::failure(std::move(error));
                }
                auto copied = copy_blob_cancellable(
                    products.search_index_blob, payload,
                    static_cast<std::size_t>(bytes), cancel,
                    "workspace_database.load_search.blob");
                if (!copied)
                    return copied;
            }
        } else if (status != SQLITE_DONE) {
            return workspace_result_t<void>::failure(database_error(database, status,
                "unable to read search index blob", "workspace_database.load_search.blob"));
        }
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<persisted_search_products_t>::failure(result.error());
    return workspace_result_t<persisted_search_products_t>::success(std::move(products));
}

persistence_ticket_t workspace_database_t::store_decompiler_cache(
    decompiler_cache_record_t record, cancellation_token_t cancel) {
    if (record.key.engine_version.size() > 65536 ||
        record.key.specification_version.size() > 65536 ||
        record.key.analysis_settings_hash.size() > 65536 ||
        record.function_name.size() > 4096 || record.result_json.empty() ||
        record.result_json.size() > workspace_decompiler_cache_record_limit ||
        record.result_bytes != record.result_json.size()) {
        return queue_->enqueue("analysis.persistence.decompiler_cache.invalid",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "decompiler cache record exceeds its integrity or size limits",
                    "workspace_database.decompiler_cache"));
            }, std::move(cancel));
    }
    const auto canonical = record.key.canonical();
    if (canonical.empty() || canonical.size() > 16384) {
        return queue_->enqueue("analysis.persistence.decompiler_cache.invalid_key",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "decompiler cache canonical key exceeds its size limit",
                    "workspace_database.decompiler_cache"));
            }, std::move(cancel));
    }
    const std::uint64_t record_json_bytes =
        static_cast<std::uint64_t>(record.result_json.size());
    return queue_->enqueue("analysis.persistence.decompiler_cache.store",
        make_cache_write_operation(state_,
            [record = std::move(record), canonical](sqlite3* database,
                                                    const cancellation_token_t& token) {
            if (token.stop_requested()) {
                auto error = make_workspace_error(token.deadline_exceeded()
                                                      ? workspace_error_code_t::deadline_exceeded
                                                      : workspace_error_code_t::cancelled,
                                                  "decompiler cache write cancelled",
                                                  "workspace_database.decompiler_cache");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<void>::failure(std::move(error));
            }
            decompiler_cache_v9_record_t persisted;
            persisted.cache_key = canonical;
            persisted.binary_id = record.key.binary_id;
            persisted.format = record.key.format;
            persisted.architecture = record.key.architecture;
            persisted.architecture_mode = record.key.architecture_mode;
            persisted.abi = record.key.abi;
            persisted.endian = record.key.endian;
            persisted.engine_version = record.key.engine_version;
            persisted.schema_version = record.key.schema_version;
            persisted.specification_version = record.key.specification_version;
            persisted.settings_hash = record.key.analysis_settings_hash;
            persisted.function_id = record.key.function_id;
            persisted.function_rva = record.key.function_rva;
            persisted.function_rva_address = {
                address_space_id_t::relative_virtual,
                record.key.function_rva,
                record.key.architecture,
                record.key.architecture_mode};
            persisted.function_content_hash = record.key.function_content_hash;
            persisted.analysis_revision = record.key.analysis_revision;
            persisted.overlay_revision = record.key.overlay_revision;
            persisted.generation = record.key.generation;
            persisted.function_name = record.function_name;
            persisted.result_json = record.result_json;
            persisted.created_utc_ms = record.created_utc_ms;
            persisted.last_access_utc_ms = record.last_access_utc_ms;
            persisted.result_bytes = record.result_bytes;
            persisted.cache_key_version = decompiler_cache_v9_key_version;
            return write_decompiler_cache_v9(database, persisted);
        }),
        std::move(cancel),
        static_cast<std::uint64_t>(record_json_bytes),
        persistence_priority_t::deferred, true);
}

workspace_result_t<std::optional<decompiler_cache_record_t>>
workspace_database_t::load_decompiler_cache(const decompiler_cache_key_t& key,
                                            const cancellation_token_t& cancel) const {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(cancel.deadline_exceeded()
                                              ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                                          "decompiler cache read cancelled",
                                          "workspace_database.decompiler_cache");
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(std::move(error));
    }
    if (key.engine_version.size() > 65536 ||
        key.specification_version.size() > 65536 ||
        key.analysis_settings_hash.size() > 65536) {
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler cache lookup metadata exceeds its size limit",
                                 "workspace_database.decompiler_cache"));
    }
    std::optional<decompiler_cache_record_t> record;
    const std::string canonical = key.canonical();
    if (canonical.empty() || canonical.size() > 16384) {
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler cache lookup key exceeds its size limit",
                                 "workspace_database.decompiler_cache"));
    }
    auto result = with_reader([&](sqlite3* database) {
        auto persisted = read_decompiler_cache_v9(database, canonical);
        if (!persisted)
            return workspace_result_t<void>::failure(persisted.error());
        if (!persisted.value())
            return workspace_result_t<void>::success();
        const auto& stored = *persisted.value();
        const bool key_matches =
            stored.binary_id == key.binary_id &&
            stored.format == key.format &&
            stored.architecture == key.architecture &&
            stored.architecture_mode == key.architecture_mode &&
            stored.abi == key.abi && stored.endian == key.endian &&
            stored.engine_version == key.engine_version &&
            stored.schema_version == key.schema_version &&
            stored.specification_version == key.specification_version &&
            stored.settings_hash == key.analysis_settings_hash &&
            stored.function_id == key.function_id &&
            stored.function_rva == key.function_rva &&
            stored.function_rva_address.space == address_space_id_t::relative_virtual &&
            stored.function_rva_address.value == key.function_rva &&
            stored.function_rva_address.architecture == key.architecture &&
            stored.function_rva_address.mode == key.architecture_mode &&
            stored.function_content_hash == key.function_content_hash &&
            stored.analysis_revision == key.analysis_revision &&
            stored.overlay_revision == key.overlay_revision &&
            stored.generation == key.generation &&
            stored.cache_key_version == decompiler_cache_v9_key_version;
        if (!key_matches) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "persisted decompiler cache key metadata is inconsistent",
                "workspace_database.decompiler_cache"));
        }
        decompiler_cache_record_t found;
        found.key = key;
        found.function_name = stored.function_name;
        found.result_json = stored.result_json;
        found.created_utc_ms = stored.created_utc_ms;
        found.last_access_utc_ms = stored.last_access_utc_ms;
        found.result_bytes = stored.result_bytes;
        record = std::move(found);
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::optional<decompiler_cache_record_t>>::failure(result.error());
    return workspace_result_t<std::optional<decompiler_cache_record_t>>::success(std::move(record));
}

persistence_ticket_t workspace_database_t::invalidate_decompiler_cache(
    std::optional<std::uint64_t> function_rva,
    std::optional<std::uint64_t> minimum_overlay_revision,
    cancellation_token_t cancel) {
    auto state = state_;
    return queue_->enqueue("analysis.persistence.decompiler_cache.invalidate",
        make_cache_write_operation(state,
            [state, function_rva, minimum_overlay_revision](sqlite3* database,
                                                            const cancellation_token_t&) {
            std::string sql = "DELETE FROM decompiler_cache_v9 WHERE 1=1";
            if (function_rva) sql += " AND function_rva=?1";
            if (minimum_overlay_revision) sql += function_rva
                ? " AND overlay_revision>=?2" : " AND overlay_revision>=?1";
            statement_t statement;
            auto result = statement.prepare(database, sql.c_str(),
                                            "workspace_database.decompiler_cache");
            if (!result) return result;
            int index = 1;
            if (function_rva) { result = statement.bind_uint(index++, *function_rva); if (!result) return result; }
            if (minimum_overlay_revision) { result = statement.bind_uint(index, *minimum_overlay_revision); if (!result) return result; }
            result = statement.step_done();
            if (result)
                state->cache_invalidations.fetch_add(1, std::memory_order_acq_rel);
            return result;
        }),
        std::move(cancel), 0, persistence_priority_t::deferred, true);
}


persistence_ticket_t workspace_database_t::store_workbench_state(
    workbench_state_record_t record, cancellation_token_t cancel) {
    const std::uint64_t workbench_payload_bytes =
        static_cast<std::uint64_t>(record.payload_json.size());
    return enqueue_write("analysis.persistence.workbench.store",
        [record = std::move(record)](sqlite3* database,
                                     const cancellation_token_t& token) {
            if (token.stop_requested()) {
                auto error = make_workspace_error(
                    token.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                              : workspace_error_code_t::cancelled,
                    "workbench state write was cancelled",
                    "workspace_database.workbench.store");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<void>::failure(std::move(error));
            }
            return write_workbench_state(database, record);
        }, std::move(cancel), workbench_payload_bytes);
}

workspace_result_t<std::optional<workbench_state_record_t>>
workspace_database_t::load_workbench_state(
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workbench state read was cancelled",
            "workspace_database.workbench.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            std::move(error));
    }
    std::optional<workbench_state_record_t> record;
    auto result = with_reader([&](sqlite3* database) {
        auto read = read_workbench_state(database);
        if (!read)
            return workspace_result_t<void>::failure(read.error());
        record = read.take_value();
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            result.error());
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "workbench state read was cancelled",
            "workspace_database.workbench.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<workbench_state_record_t>>::failure(
            std::move(error));
    }
    return workspace_result_t<std::optional<workbench_state_record_t>>::success(
        std::move(record));
}

persistence_ticket_t workspace_database_t::checkpoint(bool truncate,
                                                       cancellation_token_t cancel) {
    return enqueue_write("analysis.persistence.checkpoint",
        [truncate](sqlite3* database, const cancellation_token_t&) {
            int log_frames = 0;
            int checkpointed_frames = 0;
            const int status = sqlite3_wal_checkpoint_v2(database, "main",
                truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE,
                &log_frames, &checkpointed_frames);
            if (status == SQLITE_OK || (!truncate && status == SQLITE_BUSY))
                return workspace_result_t<void>::success();
            return workspace_result_t<void>::failure(database_error(database, status,
                "WAL checkpoint failed", "workspace_database.checkpoint"));
        }, std::move(cancel));
}

persistence_ticket_t workspace_database_t::store_pipeline_cache(
    decompiler_pipeline_cache_v1_row_t record,
    cancellation_token_t cancel) {
    if (record.cache_key.empty() || record.cache_key.size() > 16384 ||
        record.workspace_id.empty() || record.workspace_id.size() > 4096 ||
        record.stage < 0 || record.stage > 16 ||
        record.value.empty() ||
        record.value.size() > workspace_decompiler_cache_record_limit ||
        record.diagnostics.size() > workspace_decompiler_cache_record_limit) {
        return queue_->enqueue("analysis.persistence.pipeline_cache.invalid",
            [](const cancellation_token_t&) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "decompiler pipeline cache record exceeds its integrity or size limits",
                    "workspace_database.pipeline_cache"));
            }, std::move(cancel));
    }
    const std::uint64_t reservation =
        static_cast<std::uint64_t>(record.cache_key.size()) +
        static_cast<std::uint64_t>(record.value.size()) +
        static_cast<std::uint64_t>(record.diagnostics.size());
    return queue_->enqueue("analysis.persistence.pipeline_cache.store",
        make_cache_write_operation(state_,
            [record = std::move(record)](sqlite3* database,
                                         const cancellation_token_t& token) {
            if (token.stop_requested()) {
                auto error = make_workspace_error(
                    token.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "decompiler pipeline cache write cancelled",
                    "workspace_database.pipeline_cache");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<void>::failure(std::move(error));
            }
            return write_pipeline_cache_v1(database, record);
        }),
        std::move(cancel), reservation,
        persistence_priority_t::deferred, true);
}

workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>
workspace_database_t::load_pipeline_cache(
    const std::vector<std::uint8_t>& canonical_key,
    const cancellation_token_t& cancel) const {
    if (canonical_key.empty() || canonical_key.size() > 16384) {
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "decompiler pipeline cache lookup key exceeds its size limit",
                                 "workspace_database.pipeline_cache"));
    }
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "decompiler pipeline cache read cancelled",
            "workspace_database.pipeline_cache");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            std::move(error));
    }
    std::optional<decompiler_pipeline_cache_v1_row_t> record;
    auto result = with_reader([&](sqlite3* database) {
        auto read = read_pipeline_cache_v1(database, canonical_key);
        if (!read)
            return workspace_result_t<void>::failure(read.error());
        record = read.take_value();
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::failure(
            result.error());
    return workspace_result_t<std::optional<decompiler_pipeline_cache_v1_row_t>>::success(
        std::move(record));
}

persistence_ticket_t workspace_database_t::invalidate_pipeline_cache(
    std::optional<std::vector<std::uint64_t>> function_rvas,
    cancellation_token_t cancel) {
    auto state = state_;
    const std::string workspace_id = options_.identity->binary_id().to_hex();
    return queue_->enqueue("analysis.persistence.pipeline_cache.invalidate",
        make_cache_write_operation(state,
            [state, workspace_id, function_rvas = std::move(function_rvas)](
                sqlite3* database, const cancellation_token_t&) {
            workspace_result_t<void> result = workspace_result_t<void>::success();
            if (function_rvas) {
                result = delete_pipeline_cache_v1_functions(
                    database, workspace_id, *function_rvas);
            } else {
                result = delete_pipeline_cache_v1(database, workspace_id);
            }
            if (result)
                state->cache_invalidations.fetch_add(1, std::memory_order_acq_rel);
            return result;
        }),
        std::move(cancel), 0, persistence_priority_t::deferred, true);
}

persistence_ticket_t workspace_database_t::store_pdb_symbol_modules(
    pdb_symbol_module_record_t record, cancellation_token_t cancel) {
    auto state = state_;
    const std::uint64_t reservation_bytes =
        static_cast<std::uint64_t>(record.payload.size()) +
        (record.source_lines
             ? static_cast<std::uint64_t>(record.source_lines->size()) : 0ULL);
    const std::uint64_t stored_cap = options_.pdb_persistence_max_stored_bytes;
    return queue_->enqueue("analysis.persistence.pdb_modules.store",
        make_cache_write_operation(state,
            [state, record = std::move(record), stored_cap](
                sqlite3* database, const cancellation_token_t& token) {
            const auto stop = [&token] { return token.stop_requested(); };
            if (stop()) {
                auto error = make_workspace_error(
                    token.deadline_exceeded()
                        ? workspace_error_code_t::deadline_exceeded
                        : workspace_error_code_t::cancelled,
                    "pdb symbol module store was cancelled",
                    "workspace_database.pdb_modules.store");
                error.deadline = token.deadline_exceeded();
                error.cancellation = !error.deadline;
                return workspace_result_t<void>::failure(std::move(error));
            }
            std::uint64_t other_stored_bytes = 0;
            {
                statement_t caps;
                auto prepared = caps.prepare(database,
                    "SELECT COALESCE(SUM(length(payload)+COALESCE(length(source_lines),0)),0) FROM pdb_symbol_modules WHERE module_key<>?1",
                    "workspace_database.pdb_modules.store");
                if (!prepared)
                    return prepared;
                auto bound = caps.bind_text(1, record.module_key);
                if (!bound)
                    return bound;
                const int status = sqlite3_step(caps.get());
                if (status != SQLITE_ROW) {
                    return workspace_result_t<void>::failure(database_error(
                        database, status,
                        "unable to bound pdb symbol module stored bytes",
                        "workspace_database.pdb_modules.store"));
                }
                const auto other_bytes = sqlite3_column_int64(caps.get(), 0);
                if (other_bytes < 0) {
                    return workspace_result_t<void>::failure(
                        make_workspace_error(
                            workspace_error_code_t::integrity_failure,
                            "pdb symbol module stored byte total is invalid",
                            "workspace_database.pdb_modules.store"));
                }
                other_stored_bytes = static_cast<std::uint64_t>(other_bytes);
            }
            std::uint64_t prospective_bytes = 0;
            if (!checked_add_u64(
                    other_stored_bytes,
                    static_cast<std::uint64_t>(record.payload.size()) +
                        (record.source_lines
                             ? static_cast<std::uint64_t>(
                                   record.source_lines->size())
                             : 0ULL) +
                        128ULL,
                    prospective_bytes)) {
                state->pdb_modules_skipped.fetch_add(
                    1, std::memory_order_acq_rel);
                return workspace_result_t<void>::success();
            }
            if (prospective_bytes > stored_cap) {
                state->pdb_modules_skipped.fetch_add(
                    1, std::memory_order_acq_rel);
                return workspace_result_t<void>::success();
            }
            auto written = write_pdb_symbol_module(database, record, stop);
            if (!written)
                return workspace_result_t<void>::failure(written.error());
            if (written.value()) {
                state->pdb_modules_stored.fetch_add(
                    1, std::memory_order_acq_rel);
            } else {
                state->pdb_modules_skipped.fetch_add(
                    1, std::memory_order_acq_rel);
            }
            return workspace_result_t<void>::success();
        }),
        std::move(cancel), reservation_bytes,
        persistence_priority_t::deferred, true);
}

workspace_result_t<std::vector<pdb_symbol_module_record_t>>
workspace_database_t::load_pdb_symbol_modules(
    const cancellation_token_t& cancel) const {
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "pdb symbol module read was cancelled",
            "workspace_database.pdb_modules.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::vector<pdb_symbol_module_record_t>>::failure(
            std::move(error));
    }
    std::vector<pdb_symbol_module_record_t> records;
    auto result = with_reader([&](sqlite3* database) {
        auto read = read_pdb_symbol_modules(
            database, [&cancel] { return cancel.stop_requested(); });
        if (!read)
            return workspace_result_t<void>::failure(read.error());
        records = read.take_value();
        return workspace_result_t<void>::success();
    }, cancel);
    if (!result)
        return workspace_result_t<std::vector<pdb_symbol_module_record_t>>::failure(
            result.error());
    if (cancel.stop_requested()) {
        auto error = make_workspace_error(
            cancel.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                       : workspace_error_code_t::cancelled,
            "pdb symbol module read was cancelled",
            "workspace_database.pdb_modules.read");
        error.deadline = cancel.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<std::vector<pdb_symbol_module_record_t>>::failure(
            std::move(error));
    }
    state_->pdb_modules_loaded.fetch_add(
        static_cast<std::uint64_t>(records.size()), std::memory_order_acq_rel);
    return workspace_result_t<std::vector<pdb_symbol_module_record_t>>::success(
        std::move(records));
}

workspace_database_snapshot_t workspace_database_t::snapshot() const {
    workspace_database_snapshot_t result;
    result.path = state_->path;
    result.schema_version = workspace_database_schema_version;
    result.persisted_generation = state_->persisted_generation.load(std::memory_order_acquire);
    result.persisted_analysis_revision = state_->persisted_analysis_revision.load(std::memory_order_acquire);
    result.persisted_overlay_revision = state_->persisted_overlay_revision.load(std::memory_order_acquire);
    result.cache_invalidations = state_->cache_invalidations.load(std::memory_order_acquire);
    result.last_commit_logical_bytes = state_->last_commit_logical_bytes.load(std::memory_order_acquire);
    result.cumulative_logical_bytes = state_->cumulative_logical_bytes.load(std::memory_order_acquire);
    result.last_commit_rows = state_->last_commit_rows.load(std::memory_order_acquire);
    result.cumulative_rows = state_->cumulative_rows.load(std::memory_order_acquire);
    result.last_commit_page_write_bytes = state_->last_commit_page_write_bytes.load(std::memory_order_acquire);
    result.cumulative_page_write_bytes = state_->cumulative_page_write_bytes.load(std::memory_order_acquire);
    result.last_commit_elapsed_us = state_->last_commit_elapsed_us.load(std::memory_order_acquire);
    result.candidate_generation = state_->candidate_generation.load(std::memory_order_acquire);
    result.candidate_analysis_revision = state_->candidate_analysis_revision.load(std::memory_order_acquire);
    result.candidate_overlay_revision = state_->candidate_overlay_revision.load(std::memory_order_acquire);
    result.candidate_pending = state_->candidate_pending.load(std::memory_order_acquire);
    result.open = state_->open.load(std::memory_order_acquire);
    result.staging_bytes = state_->staging_resident_bytes.load(std::memory_order_acquire);
    {
        std::lock_guard<std::mutex> staging_lock(state_->staging_mutex);
        auto staging = state_->active_staging.lock();
        result.staging_active = static_cast<bool>(staging);
        if (staging) {
            std::uint32_t mask = staging->staged_domain_mask();
            std::uint64_t domains = 0;
            while (mask != 0) {
                domains += mask & 1U;
                mask >>= 1U;
            }
            result.staging_domains = domains;
        }
    }
    result.cumulative_pages_written = state_->cumulative_pages_written.load(std::memory_order_acquire);
    result.last_commit_pages_v3 = state_->last_commit_pages_v3.load(std::memory_order_acquire);
    result.cumulative_pages_v3 = state_->cumulative_pages_v3.load(std::memory_order_acquire);
    result.last_commit_page_stored_bytes = state_->last_commit_page_stored_bytes.load(std::memory_order_acquire);
    result.cumulative_page_stored_bytes = state_->cumulative_page_stored_bytes.load(std::memory_order_acquire);
    result.last_commit_page_logical_bytes = state_->last_commit_page_logical_bytes.load(std::memory_order_acquire);
    result.cumulative_page_logical_bytes = state_->cumulative_page_logical_bytes.load(std::memory_order_acquire);
    result.pdb_modules_stored = state_->pdb_modules_stored.load(std::memory_order_acquire);
    result.pdb_modules_skipped = state_->pdb_modules_skipped.load(std::memory_order_acquire);
    result.pdb_modules_loaded = state_->pdb_modules_loaded.load(std::memory_order_acquire);
    std::error_code error;
    result.database_bytes = std::filesystem::file_size(std::filesystem::u8path(state_->path), error);
    if (error) result.database_bytes = 0;
    error.clear();
    result.wal_bytes = std::filesystem::file_size(std::filesystem::u8path(state_->path + "-wal"), error);
    if (error) result.wal_bytes = 0;
    std::uint64_t peak = state_->wal_bytes_peak.load(std::memory_order_relaxed);
    while (result.wal_bytes > peak &&
           !state_->wal_bytes_peak.compare_exchange_weak(
               peak, result.wal_bytes, std::memory_order_release,
               std::memory_order_relaxed)) {
    }
    result.wal_bytes_peak = state_->wal_bytes_peak.load(std::memory_order_acquire);
    workspace_io_metrics().set(
        workspace_io_metric_t::statement_cache_hits,
        global_statement_cache_hits().load(std::memory_order_relaxed));
    workspace_io_metrics().set(
        workspace_io_metric_t::statement_cache_misses,
        global_statement_cache_misses().load(std::memory_order_relaxed));
    return result;
}

void workspace_database_t::request_cancel() noexcept {
    auto state = state_;
    if (state) {
        state->open.store(false, std::memory_order_release);
        try {
            std::lock_guard<std::mutex> close_lock(state->close_mutex);
            if (state->writer)
                sqlite3_interrupt(state->writer);
        } catch (...) {
        }
    }
    if (queue_)
        queue_->request_cancel();
}

workspace_result_t<void>
workspace_database_t::drain(std::chrono::steady_clock::time_point deadline) {
    if (queue_) {
        auto result = queue_->drain(deadline);
        if (!result) return result;
    }
    std::lock_guard<std::mutex> lock(state_->close_mutex);
    std::lock_guard<std::timed_mutex> writer_lock(state_->writer_mutex);
    state_->coalesce_progress.reset();
    if (state_->reader_pool)
        state_->reader_pool->close();
    if (state_->writer) {
        if (state_->writer_statements) {
            sqlite_statement_cache_unregister(state_->writer);
            state_->writer_statements.reset();
        }
        const int checkpoint_status = final_passive_checkpoint(state_->writer);
        if (checkpoint_status != SQLITE_OK && checkpoint_status != SQLITE_BUSY) {
            return workspace_result_t<void>::failure(database_error(state_->writer,
                checkpoint_status,
                "final passive WAL checkpoint failed with SQLite status " +
                    std::to_string(checkpoint_status) + " (" +
                    sqlite3_errstr(checkpoint_status) + ")",
                "workspace_database.close"));
        }
        const int close_status = sqlite3_close_v2(state_->writer);
        if (close_status != SQLITE_OK) {
            return workspace_result_t<void>::failure(database_error(state_->writer,
                close_status, "workspace database close failed", "workspace_database.close"));
        }
        state_->writer = nullptr;
        state_->open.store(false, std::memory_order_release);
    }
    return workspace_result_t<void>::success();
}

}
