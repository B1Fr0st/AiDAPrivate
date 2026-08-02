#include "decode_materializer.hpp"

#include "checked_range.hpp"
#include "fact_residency.hpp"
#include "paged_fact_staging.hpp"
#include "parallel_pass.hpp"
#include "snapshot_tables.hpp"
#include "workspace_database.hpp"

#include "../analysis_budget.hpp"
#include "../packed_analysis_store.hpp"
#include "../tile_decode_orchestrator.hpp"
#include "../working_set_governor.hpp"

#include "compact_ir.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace aida::analysis {

namespace {

constexpr std::uint64_t kCancellationStride = 256;
constexpr std::uint64_t kOperandProjectedRecordBytes = 45;

workspace_error_t materialize_cancellation_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "baseline analysis deadline exceeded", "decode_merge");
        error.deadline = true;
        error.cancellation = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "baseline analysis cancelled", "decode_merge");
    error.cancellation = true;
    return error;
}

workspace_error_t materialize_integrity_error(std::string message) {
    return make_workspace_error(workspace_error_code_t::integrity_failure,
        std::move(message), "decode_merge");
}

workspace_error_t materialize_limit_error(const char* message) {
    return make_workspace_error(workspace_error_code_t::limit_exceeded,
        message, "decode_merge");
}

workspace_result_t<std::uint32_t> resolve_instruction_owner(
    std::uint64_t packed_id, std::uint16_t shard_id, std::uint64_t instruction_count,
    const char* row_kind) {
    const auto domain = packed_id >> 48U;
    const auto shard = static_cast<std::uint16_t>((packed_id >> 32U) & 0xffffULL);
    const auto ordinal = packed_id & 0xffffffffULL;
    if (packed_id == 0 ||
        domain != static_cast<std::uint64_t>(packed_entity_domain_t::instruction) ||
        ordinal == 0 || ordinal > instruction_count) {
        std::string message = "tile decode ";
        message += row_kind;
        message += " references an unknown instruction";
        return workspace_result_t<std::uint32_t>::failure(
            materialize_integrity_error(std::move(message)));
    }
    if (shard != shard_id) {
        std::string message = "tile decode ";
        message += row_kind;
        message += " references an instruction outside its shard";
        return workspace_result_t<std::uint32_t>::failure(
            materialize_integrity_error(std::move(message)));
    }
    return workspace_result_t<std::uint32_t>::success(
        static_cast<std::uint32_t>(ordinal - 1ULL));
}

workspace_result_t<std::uint64_t> resolve_packed_ordinal(
    std::uint64_t packed_id, packed_entity_domain_t expected_domain,
    std::uint16_t shard_id, std::uint64_t row_count, const char* row_kind) {
    if (packed_id == 0)
        return workspace_result_t<std::uint64_t>::success(0);
    const auto domain = packed_id >> 48U;
    const auto shard = static_cast<std::uint16_t>((packed_id >> 32U) & 0xffffULL);
    const auto ordinal = packed_id & 0xffffffffULL;
    if (domain != static_cast<std::uint64_t>(expected_domain) ||
        shard != shard_id || ordinal == 0 || ordinal > row_count) {
        std::string message = "tile decode ";
        message += row_kind;
        message += " references an unknown packed entity";
        return workspace_result_t<std::uint64_t>::failure(
            materialize_integrity_error(std::move(message)));
    }
    return workspace_result_t<std::uint64_t>::success(ordinal);
}

struct shard_base_ordinals_t {
    std::vector<std::uint64_t> instruction_bases;
    std::vector<std::uint64_t> operand_bases;
    std::vector<std::uint64_t> target_bases;
    std::vector<std::uint64_t> expression_bases;
    std::uint64_t instruction_total = 0;
    std::uint64_t operand_total = 0;
    std::uint64_t target_total = 0;
    std::uint64_t expression_total = 0;
};

workspace_result_t<shard_base_ordinals_t> compute_shard_bases(
    const std::vector<packed_analysis_shard_t>& shards) {
    shard_base_ordinals_t bases;
    bases.instruction_bases.reserve(shards.size());
    bases.operand_bases.reserve(shards.size());
    bases.target_bases.reserve(shards.size());
    bases.expression_bases.reserve(shards.size());
    for (const auto& shard : shards) {
        bases.instruction_bases.push_back(bases.instruction_total);
        bases.operand_bases.push_back(bases.operand_total);
        bases.target_bases.push_back(bases.target_total);
        bases.expression_bases.push_back(bases.expression_total);
        if (!checked_add_u64(bases.instruction_total,
                static_cast<std::uint64_t>(shard.instruction_count()),
                bases.instruction_total) ||
            !checked_add_u64(bases.operand_total,
                static_cast<std::uint64_t>(shard.operand_count()),
                bases.operand_total) ||
            !checked_add_u64(bases.target_total,
                static_cast<std::uint64_t>(shard.target_fact_count()),
                bases.target_total) ||
            !checked_add_u64(bases.expression_total,
                static_cast<std::uint64_t>(shard.address_expression_count()),
                bases.expression_total)) {
            return workspace_result_t<shard_base_ordinals_t>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "tile decode merge accounting overflows", "decode_merge"));
        }
    }
    return workspace_result_t<shard_base_ordinals_t>::success(std::move(bases));
}

std::uint8_t displacement_width_class(std::int64_t displacement) noexcept {
    if (displacement == 0)
        return 0;
    if (displacement >= -128 && displacement <= 127)
        return 1;
    if (displacement >= -32768 && displacement <= 32767)
        return 2;
    if (displacement >= -2147483648LL && displacement <= 2147483647LL)
        return 3;
    return 4;
}

void fill_hot_from_view(const packed_operand_view_t& view,
                        std::uint32_t instruction_ordinal,
                        operand_fact_hot_t& hot) noexcept {
    hot.value = view.has_displacement
        ? static_cast<std::uint64_t>(view.displacement)
        : view.immediate;
    hot.instruction_ordinal = instruction_ordinal;
    hot.cold_index = 0;
    hot.reg = view.reg;
    hot.base_reg = view.base_reg;
    hot.index_reg = view.index_reg;
    std::uint16_t flags = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(view.kind) & 0x7U) << operand_hot_kind_shift);
    flags |= static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(view.access) & 0xFU) << operand_hot_access_shift);
    flags |= static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(view.scale) & 0xFU) << operand_hot_scale_shift);
    if (view.relative)
        flags |= static_cast<std::uint16_t>(1U << operand_hot_relative_bit);
    if (view.signed_value)
        flags |= static_cast<std::uint16_t>(1U << operand_hot_signed_bit);
    if (view.has_displacement)
        flags |= static_cast<std::uint16_t>(1U << operand_hot_displacement_bit);
    if (view.memory_type <= 3U) {
        flags |= static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(view.memory_type) & 0x3U)
            << operand_hot_memory_type_shift);
        hot.memory_type_wide = 0;
    } else {
        hot.memory_type_wide = view.memory_type;
    }
    hot.flags = flags;
    hot.operand_index = view.operand_index;
    hot.access_width = view.access_width;
    hot.segment_reg = static_cast<std::uint8_t>(view.segment_reg & 0xFFU);
    hot.segment_reg_hi = static_cast<std::uint8_t>(view.segment_reg >> 8U);
    hot.width_class = operand_hot_width_class(view.bit_width);
    hot.reserved[0] = 0;
    hot.reserved[1] = 0;
}

bool view_needs_cold(const packed_operand_view_t& view,
                     std::uint8_t width_class) noexcept {
    return view.has_resolved_expression_value ||
        view.resolved_expression_value != 0 ||
        view.address_expression_id.valid() ||
        view.address_expression_kind != address_expression_kind_t::none ||
        view.address_resolution != target_resolution_t::unresolved_indirect ||
        (width_class == 0 && view.bit_width != 0) ||
        view.access_width_bits != 0 || view.element_width_bits != 0 ||
        view.address_components != address_component_none ||
        view.access_count != 0 || view.element_count != 0 ||
        view.visibility != 0 || view.encoding != 0 ||
        view.decoder_operand_id != 0 || view.address_width_bits != 0;
}

void fill_cold_from_view(const packed_operand_view_t& view,
                         std::uint32_t expression_ordinal,
                         operand_fact_cold_t& cold) noexcept {
    cold.resolved_expression_value = view.resolved_expression_value;
    cold.expression_ordinal = expression_ordinal;
    cold.bit_width = view.bit_width;
    cold.access_width_bits = view.access_width_bits;
    cold.element_width_bits = view.element_width_bits;
    cold.address_components = view.address_components;
    cold.access_count = view.access_count;
    cold.element_count = view.element_count;
    cold.address_expression = static_cast<std::uint8_t>(view.address_expression_kind);
    cold.address_resolution = static_cast<std::uint8_t>(view.address_resolution);
    cold.visibility = view.visibility;
    cold.encoding = view.encoding;
    cold.decoder_operand_id = view.decoder_operand_id;
    cold.address_width_bits = static_cast<std::uint8_t>(view.address_width_bits & 0xFFU);
    cold.flags = view.has_resolved_expression_value ? operand_cold_has_resolved_bit : 0;
    cold.reserved = 0;
}

std::uint32_t domain_release_mask(fact_domain_t domain) noexcept {
    return 1U << static_cast<std::uint32_t>(domain);
}

struct instruction_grouping_t {
    std::uint32_t operand_fact_begin = 0;
    std::uint32_t target_fact_begin = 0;
    std::uint16_t operand_fact_count = 0;
    std::uint16_t target_fact_count = 0;
};

static_assert(sizeof(instruction_grouping_t) == 12);

struct shard_fill_options_t {
    bool fill_instructions = true;
    bool fill_operands = true;
    bool fill_targets = true;
};

workspace_result_t<void> materialize_shard_rows(
    packed_analysis_shard_t& shard, analysis_snapshot_t& snapshot,
    std::uint64_t instruction_base, std::uint64_t operand_base,
    std::uint64_t target_base, std::uint64_t expression_base,
    instruction_grouping_t* grouping,
    std::vector<operand_fact_cold_t>& shard_cold,
    const shard_fill_options_t& options,
    const cancellation_token_t& cancel) {
    auto validated = shard.validate();
    if (!validated) {
        auto error = materialize_integrity_error(
            "tile decode packed shard validation failed");
        error.details.emplace_back("shard", std::to_string(shard.shard_id()));
        error.details.emplace_back("packed_code",
            std::to_string(static_cast<unsigned>(validated.error().code)));
        return workspace_result_t<void>::failure(std::move(error));
    }
    const auto view = shard.compatibility_view();
    const auto shard_id = shard.shard_id();
    const auto instruction_count =
        static_cast<std::uint64_t>(shard.instruction_count());
    const auto operand_count = static_cast<std::uint64_t>(shard.operand_count());
    const auto target_count = static_cast<std::uint64_t>(shard.target_fact_count());
    const auto expression_count =
        static_cast<std::uint64_t>(shard.address_expression_count());
    if (options.fill_operands)
        shard_cold.reserve(operand_count / 2 + 1);
    for (std::uint64_t index = 0; index < expression_count; ++index) {
        if ((index & 0xFFFULL) == 0 && cancel.stop_requested())
            return workspace_result_t<void>::failure(
                materialize_cancellation_error(cancel));
        const auto expression = shard.address_expression(
            static_cast<std::size_t>(index));
        if (!expression) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode address expression row is missing"));
        }
        address_expression_record_t record;
        record.components = expression->address_components;
        record.base_reg = expression->base_reg;
        record.index_reg = expression->index_reg;
        record.segment_reg = expression->segment_reg;
        record.kind = static_cast<std::uint8_t>(expression->kind);
        record.resolution = static_cast<std::uint8_t>(expression->resolution);
        record.scale = expression->scale;
        record.disp_class = displacement_width_class(expression->displacement);
        snapshot.address_expressions[
            static_cast<std::size_t>(expression_base + index)] = record;
    }
    std::uint64_t operand_cursor = 0;
    std::uint64_t target_cursor = 0;
    std::uint64_t polls = 0;
    for (std::uint64_t index = 0; index < instruction_count; ++index) {
        if (++polls >= kCancellationStride) {
            polls = 0;
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel));
        }
        auto instruction = view.instruction(static_cast<std::size_t>(index));
        if (!instruction) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode instruction compatibility row is missing"));
        }
        instruction->id = instruction_entity_tag | (instruction_base + index + 1ULL);
        const auto operand_first = operand_cursor;
        while (operand_cursor < operand_count) {
            if (++polls >= kCancellationStride) {
                polls = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
            }
            const auto packed_view = shard.operand(
                static_cast<std::size_t>(operand_cursor));
            if (!packed_view) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode operand row is missing"));
            }
            auto owner = resolve_instruction_owner(packed_view->instruction_id.value(),
                shard_id, instruction_count, "operand");
            if (!owner)
                return workspace_result_t<void>::failure(owner.error());
            if (owner.value() > index)
                break;
            if (owner.value() < index) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode operand rows are not grouped by instruction"));
            }
            if (options.fill_operands) {
                const auto global_operand = operand_base + operand_cursor;
                operand_fact_hot_t hot;
                fill_hot_from_view(*packed_view,
                    static_cast<std::uint32_t>(instruction_base + owner.value()), hot);
                if (view_needs_cold(*packed_view, hot.width_class)) {
                    std::uint32_t expression_ordinal = 0;
                    if (packed_view->address_expression_id.valid()) {
                        auto expression = resolve_packed_ordinal(
                            packed_view->address_expression_id.value(),
                            packed_entity_domain_t::address_expression, shard_id,
                            expression_count, "operand");
                        if (!expression)
                            return workspace_result_t<void>::failure(expression.error());
                        expression_ordinal = static_cast<std::uint32_t>(
                            expression_base + expression.value());
                    }
                    operand_fact_cold_t cold;
                    fill_cold_from_view(*packed_view, expression_ordinal, cold);
                    shard_cold.push_back(cold);
                    hot.cold_index = static_cast<std::uint32_t>(shard_cold.size());
                }
                snapshot.operand_facts.hot[static_cast<std::size_t>(global_operand)] = hot;
            }
            ++operand_cursor;
        }
        const auto operand_group = operand_cursor - operand_first;
        if (operand_group > (std::numeric_limits<std::uint16_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode operand count exceeds Compact IR capacity"));
        }
        if (operand_base + operand_first >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode operand table exceeds Compact IR capacity"));
        }
        instruction->operand_fact_begin =
            static_cast<std::uint32_t>(operand_base + operand_first);
        instruction->operand_fact_count = static_cast<std::uint16_t>(operand_group);
        const auto target_first = target_cursor;
        while (target_cursor < target_count) {
            if (++polls >= kCancellationStride) {
                polls = 0;
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
            }
            auto target = view.target_fact(static_cast<std::size_t>(target_cursor));
            if (!target) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode target compatibility row is missing"));
            }
            auto owner = resolve_instruction_owner(target->instruction_id,
                shard_id, instruction_count, "target");
            if (!owner)
                return workspace_result_t<void>::failure(owner.error());
            if (owner.value() > index)
                break;
            if (owner.value() < index) {
                return workspace_result_t<void>::failure(materialize_integrity_error(
                    "tile decode target rows are not grouped by instruction"));
            }
            if (options.fill_targets) {
                target->instruction_id = instruction_entity_tag |
                    (instruction_base + static_cast<std::uint64_t>(owner.value()) + 1ULL);
                if (target->operand_fact_id != 0) {
                    const auto shard_target = shard.target_fact(
                        static_cast<std::size_t>(target_cursor));
                    if (shard_target && shard_target->operand_id.valid()) {
                        auto operand_ordinal = resolve_packed_ordinal(
                            shard_target->operand_id.value(),
                            packed_entity_domain_t::operand, shard_id, operand_count,
                            "target");
                        if (!operand_ordinal)
                            return workspace_result_t<void>::failure(
                                operand_ordinal.error());
                        target->operand_fact_id = operand_entity_tag |
                            (operand_base + operand_ordinal.value() - 1ULL);
                    } else {
                        target->operand_fact_id = 0;
                    }
                }
                snapshot.target_facts[
                    static_cast<std::size_t>(target_base + target_cursor)] =
                    std::move(*target);
            }
            ++target_cursor;
        }
        const auto target_group = target_cursor - target_first;
        if (target_group > (std::numeric_limits<std::uint16_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode target count exceeds Compact IR capacity"));
        }
        if (target_base + target_first >
            (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_limit_error(
                "tile decode target table exceeds Compact IR capacity"));
        }
        instruction->target_fact_begin =
            static_cast<std::uint32_t>(target_base + target_first);
        instruction->target_fact_count = static_cast<std::uint16_t>(target_group);
        if (grouping != nullptr) {
            auto& group = grouping[instruction_base + index];
            group.operand_fact_begin = instruction->operand_fact_begin;
            group.operand_fact_count = instruction->operand_fact_count;
            group.target_fact_begin = instruction->target_fact_begin;
            group.target_fact_count = instruction->target_fact_count;
        }
        if (options.fill_instructions) {
            snapshot.instructions[static_cast<std::size_t>(instruction_base + index)] =
                std::move(*instruction);
        }
    }
    if (operand_cursor != operand_count) {
        return workspace_result_t<void>::failure(materialize_integrity_error(
            "tile decode operand rows are not grouped by instruction"));
    }
    if (target_cursor != target_count) {
        return workspace_result_t<void>::failure(materialize_integrity_error(
            "tile decode target rows are not grouped by instruction"));
    }
    std::uint32_t release_mask = 0;
    if (options.fill_instructions)
        release_mask |= domain_release_mask(fact_domain_t::instructions);
    if (options.fill_operands)
        release_mask |= domain_release_mask(fact_domain_t::operand_facts);
    if (options.fill_targets)
        release_mask |= domain_release_mask(fact_domain_t::target_facts);
    if (release_mask != 0)
        shard.release_domains(release_mask);
    return workspace_result_t<void>::success();
}

class staging_page_encoder_t final {
public:
    staging_page_encoder_t(fact_domain_t domain, packed_page_type_t page_type,
                           std::uint64_t record_total,
                           const std::shared_ptr<paged_fact_staging_t>& staging,
                           const cancellation_token_t& cancel)
        : domain_(domain), staging_(staging), cancel_(cancel) {
        const auto header = encode_packed_domain_stream_header(page_type, record_total);
        content_.insert(content_.end(), header.begin(), header.end());
        content_.reserve(static_cast<std::size_t>(content_capacity()));
    }

    static constexpr std::uint64_t content_capacity() noexcept {
        return (256ULL << 10) - packed_page_header_size - packed_record_page_prefix_size;
    }

    workspace_result_t<void> begin_record(const std::optional<address_t>& address) {
        if (content_.size() == content_capacity()) {
            auto flushed = flush();
            if (!flushed)
                return flushed;
        }
        if (page_record_count_ == (std::numeric_limits<std::uint32_t>::max)() ||
            records_started_ == (std::numeric_limits<std::uint32_t>::max)()) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode staged page record ordinal overflows"));
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

    workspace_result_t<void> append(const std::uint8_t* data, std::size_t size) {
        if (!data && size != 0) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode staged page stream received a null byte range"));
        }
        for (std::size_t offset = 0; offset < size;) {
            if (cancel_.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel_));
            if (content_.size() == content_capacity()) {
                auto flushed = flush();
                if (!flushed)
                    return flushed;
            }
            const auto count = (std::min)(
                size - offset,
                static_cast<std::size_t>(content_capacity()) - content_.size());
            content_.insert(content_.end(), data + offset, data + offset + count);
            offset += count;
        }
        return workspace_result_t<void>::success();
    }

    workspace_result_t<void> append_u64(std::uint64_t value) {
        std::array<std::uint8_t, sizeof(value)> bytes{};
        for (unsigned shift = 0; shift < 64; shift += 8)
            bytes[shift / 8] = static_cast<std::uint8_t>(value >> shift);
        return append(bytes.data(), bytes.size());
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
        paged_fact_page_meta_t meta;
        meta.ordinal_begin = prefix.ordinal_begin;
        meta.record_count = prefix.record_count;
        meta.address_value_min = prefix.address_value_min;
        meta.address_value_max = prefix.address_value_max;
        auto staged = staging_->stage_page(domain_, std::move(payload), meta, cancel_);
        if (!staged)
            return staged;
        page_ordinal_begin_ = records_started_;
        page_record_count_ = 0;
        address_seen_ = false;
        address_min_ = 0;
        address_max_ = 0;
        content_.clear();
        return workspace_result_t<void>::success();
    }

    fact_domain_t domain_;
    std::shared_ptr<paged_fact_staging_t> staging_;
    const cancellation_token_t& cancel_;
    std::vector<std::uint8_t> content_;
    std::uint32_t page_ordinal_begin_ = 0;
    std::uint32_t page_record_count_ = 0;
    std::uint32_t records_started_ = 0;
    bool address_seen_ = false;
    std::uint64_t address_min_ = 0;
    std::uint64_t address_max_ = 0;
};

workspace_result_t<void> stream_instruction_pages(
    packed_analysis_shard_t& shard, staging_page_encoder_t& encoder,
    std::uint64_t instruction_base, std::uint64_t instruction_count,
    const instruction_grouping_t* grouping, const cancellation_token_t& cancel) {
    std::uint64_t polls = 0;
    for (std::uint64_t index = 0; index < instruction_count; ++index) {
        if (++polls >= kCancellationStride) {
            polls = 0;
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel));
        }
        const auto view = shard.instruction(static_cast<std::size_t>(index));
        if (!view) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode instruction row is missing"));
        }
        instruction_record_t record;
        record.id = instruction_entity_tag | (instruction_base + index + 1ULL);
        record.address = view->address;
        record.length = view->length;
        record.mnemonic_id = view->mnemonic_id;
        record.opcode_id = view->opcode_id;
        record.flow_flags = static_cast<std::uint16_t>(view->flow_flags);
        const auto& group = grouping[instruction_base + index];
        record.operand_fact_begin = group.operand_fact_begin;
        record.operand_fact_count = group.operand_fact_count;
        record.target_fact_begin = group.target_fact_begin;
        record.target_fact_count = group.target_fact_count;
        record.provenance = view->provenance;
        record.confidence = view->confidence;
        record.coverage = view->coverage;
        record.stable_source_id = view->stable_source_id;
        auto bytes = encode_packed_instruction_record(record);
        auto begun = encoder.begin_record(record.address);
        if (!begun)
            return begun;
        auto appended = encoder.append(bytes.data(), bytes.size());
        if (!appended)
            return appended;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> stream_operand_pages(
    packed_analysis_shard_t& shard, staging_page_encoder_t& encoder,
    std::uint64_t instruction_base, std::uint64_t instruction_count,
    std::uint64_t operand_base, std::uint64_t operand_count,
    std::uint64_t expression_base, std::uint64_t expression_count,
    const cancellation_token_t& cancel) {
    const auto shard_id = shard.shard_id();
    std::uint64_t polls = 0;
    for (std::uint64_t index = 0; index < operand_count; ++index) {
        if (++polls >= kCancellationStride) {
            polls = 0;
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel));
        }
        const auto view = shard.operand(static_cast<std::size_t>(index));
        if (!view) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode operand row is missing"));
        }
        auto owner = resolve_instruction_owner(view->instruction_id.value(),
            shard_id, instruction_count, "operand");
        if (!owner)
            return workspace_result_t<void>::failure(owner.error());
        operand_fact_t record;
        record.id = operand_entity_tag | (operand_base + index);
        record.instruction_id = instruction_entity_tag |
            (instruction_base + owner.value() + 1ULL);
        record.displacement = view->has_displacement ? view->displacement : 0;
        record.immediate = view->has_displacement ? 0 : view->immediate;
        record.resolved_expression_value = view->resolved_expression_value;
        record.bit_width = view->bit_width;
        record.access_width_bits = view->access_width_bits;
        record.element_width_bits = view->element_width_bits;
        record.reg = view->reg;
        record.segment_reg = view->segment_reg;
        record.base_reg = view->base_reg;
        record.index_reg = view->index_reg;
        record.address_components = view->address_components;
        record.access_count = view->access_count;
        record.element_count = view->element_count;
        record.address_width_bits = view->address_width_bits;
        record.operand_index = view->operand_index;
        record.decoder_operand_id = view->decoder_operand_id;
        record.kind = view->kind;
        record.access = view->access;
        record.visibility = view->visibility;
        record.encoding = view->encoding;
        record.memory_type = view->memory_type;
        record.access_width = view->access_width;
        record.scale = view->scale;
        record.relative = view->relative;
        record.signed_value = view->signed_value;
        record.has_displacement = view->has_displacement;
        record.has_resolved_expression_value = view->has_resolved_expression_value;
        record.address_expression = view->address_expression_kind;
        record.address_resolution = view->address_resolution;
        if (view->address_expression_id.valid()) {
            auto expression = resolve_packed_ordinal(
                view->address_expression_id.value(),
                packed_entity_domain_t::address_expression, shard_id,
                expression_count, "operand");
            if (!expression)
                return workspace_result_t<void>::failure(expression.error());
            record.address_expression_id = address_expression_entity_tag |
                (expression_base + expression.value());
        }
        auto bytes = encode_packed_operand_record(record);
        auto begun = encoder.begin_record(std::nullopt);
        if (!begun)
            return begun;
        auto appended = encoder.append(bytes.data(), bytes.size());
        if (!appended)
            return appended;
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> stream_target_pages(
    packed_analysis_shard_t& shard, staging_page_encoder_t& encoder,
    std::uint64_t instruction_base, std::uint64_t instruction_count,
    std::uint64_t operand_base, std::uint64_t operand_count,
    std::uint64_t target_count, std::uint64_t expression_base,
    std::uint64_t expression_count, const cancellation_token_t& cancel) {
    const auto shard_id = shard.shard_id();
    std::uint64_t polls = 0;
    for (std::uint64_t index = 0; index < target_count; ++index) {
        if (++polls >= kCancellationStride) {
            polls = 0;
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel));
        }
        const auto view = shard.target_fact(static_cast<std::size_t>(index));
        if (!view) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode target row is missing"));
        }
        auto owner = resolve_instruction_owner(view->instruction_id.value(),
            shard_id, instruction_count, "target");
        if (!owner)
            return workspace_result_t<void>::failure(owner.error());
        target_fact_t record;
        record.instruction_id = instruction_entity_tag |
            (instruction_base + owner.value() + 1ULL);
        if (view->operand_id.valid()) {
            auto operand_ordinal = resolve_packed_ordinal(
                view->operand_id.value(), packed_entity_domain_t::operand,
                shard_id, operand_count, "target");
            if (!operand_ordinal)
                return workspace_result_t<void>::failure(operand_ordinal.error());
            record.operand_fact_id = operand_entity_tag |
                (operand_base + operand_ordinal.value() - 1ULL);
        }
        if (view->address_expression_id.valid()) {
            auto expression = resolve_packed_ordinal(
                view->address_expression_id.value(),
                packed_entity_domain_t::address_expression, shard_id,
                expression_count, "target");
            if (!expression)
                return workspace_result_t<void>::failure(expression.error());
            record.address_expression_id = address_expression_entity_tag |
                (expression_base + expression.value());
        }
        record.target = view->target;
        record.kind = view->kind;
        record.resolution = view->resolution;
        record.operand_index = view->operand_index;
        record.access_width_bits = view->access_width_bits;
        record.access_count = static_cast<std::uint8_t>(view->access_count);
        record.direct = view->direct;
        record.is_external = view->is_external;
        auto bytes = encode_packed_target_record(record);
        auto begun = encoder.begin_record(record.target);
        if (!begun)
            return begun;
        auto appended = encoder.append(bytes.data(), bytes.size());
        if (!appended)
            return appended;
    }
    return workspace_result_t<void>::success();
}

}

namespace decode_materializer {

workspace_result_t<void> materialize(
    tile_decode_orchestration_result_t& decoded, analysis_snapshot_t& snapshot,
    std::uint64_t remaining_budget_bytes, std::uint32_t workers,
    const cancellation_token_t& cancel) {
    auto bases = compute_shard_bases(decoded.packed_shards);
    if (!bases)
        return workspace_result_t<void>::failure(bases.error());
    auto ordinals = bases.take_value();
    std::array<fact_domain_projection_t, fact_domain_count> projections{};
    projections[static_cast<std::size_t>(fact_domain_t::instructions)] = {
        ordinals.instruction_total,
        static_cast<std::uint64_t>(sizeof(instruction_record_t))};
    projections[static_cast<std::size_t>(fact_domain_t::operand_facts)] = {
        ordinals.operand_total, kOperandProjectedRecordBytes};
    projections[static_cast<std::size_t>(fact_domain_t::target_facts)] = {
        ordinals.target_total,
        static_cast<std::uint64_t>(sizeof(target_fact_t))};
    auto residency_plan = fact_residency_select(projections,
        fact_resident_budget_bytes(host_memory_envelope()));
    snapshot.residency_plan = residency_plan;
    snapshot.paged_domain_counts = {};
    snapshot.paged_staging.reset();
    snapshot.persisted_page_source.source.reset();
    snapshot.instructions.clear();
    snapshot.operand_facts.clear();
    snapshot.target_facts.clear();
    snapshot.address_expressions.clear();
    const bool paged_instructions =
        residency_plan.domains[static_cast<std::size_t>(
            fact_domain_t::instructions)].mode == fact_residency_mode_t::paged;
    const bool paged_operands =
        residency_plan.domains[static_cast<std::size_t>(
            fact_domain_t::operand_facts)].mode == fact_residency_mode_t::paged;
    const bool paged_targets =
        residency_plan.domains[static_cast<std::size_t>(
            fact_domain_t::target_facts)].mode == fact_residency_mode_t::paged;
    std::shared_ptr<paged_fact_staging_t> staging_handle;
    if (residency_plan.any_paged()) {
        auto staging = paged_fact_staging_t::create(
            governor_subsystem_budget_fields(
                host_memory_envelope()).persistence_staging_bytes,
            staging_page_encoder_t::content_capacity());
        if (!staging)
            return workspace_result_t<void>::failure(staging.error());
        staging_handle = staging.take_value();
    }
    if (!paged_instructions) {
        resize_uninitialized(snapshot.instructions,
            static_cast<std::size_t>(ordinals.instruction_total));
    }
    if (!paged_operands) {
        resize_uninitialized(snapshot.operand_facts.hot,
            static_cast<std::size_t>(ordinals.operand_total));
    }
    if (!paged_targets) {
        resize_uninitialized(snapshot.target_facts,
            static_cast<std::size_t>(ordinals.target_total));
    }
    resize_uninitialized(snapshot.address_expressions,
        static_cast<std::size_t>(ordinals.expression_total));
    std::vector<instruction_grouping_t> grouping;
    if (paged_instructions) {
        grouping.resize(static_cast<std::size_t>(ordinals.instruction_total));
    }
    shard_fill_options_t fill_options;
    fill_options.fill_instructions = !paged_instructions;
    fill_options.fill_operands = !paged_operands;
    fill_options.fill_targets = !paged_targets;
    const auto shard_ranges =
        parallel_shards(decoded.packed_shards.size(), workers);
    std::vector<std::vector<operand_fact_cold_t>> shard_colds(
        decoded.packed_shards.size());
    auto materialized = parallel_run_shards(shard_ranges,
        [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
            for (std::size_t shard_index = range.begin; shard_index < range.end;
                 ++shard_index) {
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
                auto consumed = materialize_shard_rows(
                    decoded.packed_shards[shard_index], snapshot,
                    ordinals.instruction_bases[shard_index],
                    ordinals.operand_bases[shard_index],
                    ordinals.target_bases[shard_index],
                    ordinals.expression_bases[shard_index],
                    grouping.empty() ? nullptr : grouping.data(),
                    shard_colds[shard_index], fill_options, cancel);
                if (!consumed)
                    return consumed;
            }
            return workspace_result_t<void>::success();
        }, cancel);
    if (!materialized)
        return materialized;
    if (!paged_operands) {
        std::uint64_t cold_total = 0;
        for (const auto& cold : shard_colds) {
            if (!checked_add_u64(cold_total,
                    static_cast<std::uint64_t>(cold.size()), cold_total)) {
                return workspace_result_t<void>::failure(make_workspace_error(
                    workspace_error_code_t::range_overflow,
                    "tile decode cold operand accounting overflows", "decode_merge"));
            }
        }
        resize_uninitialized(snapshot.operand_facts.cold,
            static_cast<std::size_t>(cold_total));
        std::vector<std::uint64_t> cold_bases(decoded.packed_shards.size(), 0);
        std::uint64_t cold_base = 0;
        for (std::size_t shard_index = 0;
             shard_index < decoded.packed_shards.size(); ++shard_index) {
            cold_bases[shard_index] = cold_base;
            auto& cold = shard_colds[shard_index];
            if (!cold.empty()) {
                std::memcpy(snapshot.operand_facts.cold.data() + cold_base,
                            cold.data(), cold.size() * sizeof(operand_fact_cold_t));
                cold_base += cold.size();
            }
            std::vector<operand_fact_cold_t>().swap(cold);
        }
        auto remapped = parallel_run_shards(shard_ranges,
            [&](std::size_t, parallel_shard_t range) -> workspace_result_t<void> {
                for (std::size_t shard_index = range.begin; shard_index < range.end;
                     ++shard_index) {
                    const auto operand_begin = static_cast<std::size_t>(
                        ordinals.operand_bases[shard_index]);
                    const auto operand_end = static_cast<std::size_t>(
                        ordinals.operand_bases[shard_index] +
                        decoded.packed_shards[shard_index].operand_count());
                    for (std::size_t index = operand_begin; index < operand_end;
                         ++index) {
                        auto& hot = snapshot.operand_facts.hot[index];
                        if (hot.cold_index != 0) {
                            hot.cold_index = static_cast<std::uint32_t>(
                                cold_bases[shard_index] + hot.cold_index);
                        }
                    }
                }
                return workspace_result_t<void>::success();
            }, cancel);
        if (!remapped)
            return remapped;
    }
    std::vector<std::uint64_t> shard_instruction_counts(
        decoded.packed_shards.size());
    std::vector<std::uint64_t> shard_operand_counts(decoded.packed_shards.size());
    std::vector<std::uint64_t> shard_expression_counts(decoded.packed_shards.size());
    for (std::size_t shard_index = 0;
         shard_index < decoded.packed_shards.size(); ++shard_index) {
        shard_instruction_counts[shard_index] =
            decoded.packed_shards[shard_index].instruction_count();
        shard_operand_counts[shard_index] =
            decoded.packed_shards[shard_index].operand_count();
        shard_expression_counts[shard_index] =
            decoded.packed_shards[shard_index].address_expression_count();
    }
    if (residency_plan.any_paged()) {
        for (const auto domain : fact_domain_page_priority) {
            if (cancel.stop_requested())
                return workspace_result_t<void>::failure(
                    materialize_cancellation_error(cancel));
            const auto mode =
                residency_plan.domains[static_cast<std::size_t>(domain)].mode;
            if (mode != fact_residency_mode_t::paged)
                continue;
            if (domain != fact_domain_t::instructions &&
                domain != fact_domain_t::operand_facts &&
                domain != fact_domain_t::target_facts)
                continue;
            std::uint64_t record_total = 0;
            packed_page_type_t page_type = packed_page_type_t::instructions;
            if (domain == fact_domain_t::instructions) {
                record_total = ordinals.instruction_total;
                page_type = packed_page_type_t::instructions;
            } else if (domain == fact_domain_t::operand_facts) {
                record_total = ordinals.operand_total;
                page_type = packed_page_type_t::operands;
            } else {
                record_total = ordinals.target_total;
                page_type = packed_page_type_t::target_facts;
            }
            staging_page_encoder_t encoder(domain, page_type, record_total,
                                           staging_handle, cancel);
            for (std::size_t shard_index = 0;
                 shard_index < decoded.packed_shards.size(); ++shard_index) {
                if (cancel.stop_requested())
                    return workspace_result_t<void>::failure(
                        materialize_cancellation_error(cancel));
                auto& shard = decoded.packed_shards[shard_index];
                workspace_result_t<void> streamed =
                    workspace_result_t<void>::success();
                if (domain == fact_domain_t::instructions) {
                    streamed = stream_instruction_pages(
                        shard, encoder, ordinals.instruction_bases[shard_index],
                        shard_instruction_counts[shard_index], grouping.data(), cancel);
                } else if (domain == fact_domain_t::operand_facts) {
                    streamed = stream_operand_pages(
                        shard, encoder, ordinals.instruction_bases[shard_index],
                        shard_instruction_counts[shard_index],
                        ordinals.operand_bases[shard_index],
                        shard_operand_counts[shard_index],
                        ordinals.expression_bases[shard_index],
                        shard_expression_counts[shard_index], cancel);
                } else {
                    streamed = stream_target_pages(
                        shard, encoder, ordinals.instruction_bases[shard_index],
                        shard_instruction_counts[shard_index],
                        ordinals.operand_bases[shard_index],
                        shard_operand_counts[shard_index],
                        static_cast<std::uint64_t>(shard.target_fact_count()),
                        ordinals.expression_bases[shard_index],
                        shard_expression_counts[shard_index], cancel);
                }
                if (!streamed)
                    return streamed;
                shard.release_domains(domain_release_mask(domain));
                if (domain == fact_domain_t::target_facts)
                    shard.release();
            }
            if (domain == fact_domain_t::instructions) {
                auto counted = encoder.append_u64(
                    static_cast<std::uint64_t>(decoded.delay_slot_counts.size()));
                if (!counted)
                    return counted;
                std::uint64_t polls = 0;
                for (const std::uint8_t value : decoded.delay_slot_counts) {
                    if (++polls >= kCancellationStride) {
                        polls = 0;
                        if (cancel.stop_requested())
                            return workspace_result_t<void>::failure(
                                materialize_cancellation_error(cancel));
                    }
                    auto begun = encoder.begin_record(std::nullopt);
                    if (!begun)
                        return begun;
                    auto appended = encoder.append(&value, sizeof(value));
                    if (!appended)
                        return appended;
                }
            }
            auto finished = encoder.finish();
            if (!finished)
                return finished;
            auto contiguous = staging_handle->validate_contiguous(domain);
            if (!contiguous)
                return contiguous;
        }
        snapshot.paged_domain_counts[static_cast<std::size_t>(
            fact_domain_t::instructions)] = paged_instructions
            ? ordinals.instruction_total : 0;
        snapshot.paged_domain_counts[static_cast<std::size_t>(
            fact_domain_t::operand_facts)] = paged_operands
            ? ordinals.operand_total : 0;
        snapshot.paged_domain_counts[static_cast<std::size_t>(
            fact_domain_t::target_facts)] = paged_targets
            ? ordinals.target_total : 0;
        if (paged_instructions &&
            staging_handle->record_count(fact_domain_t::instructions) !=
                ordinals.instruction_total +
                    static_cast<std::uint64_t>(decoded.delay_slot_counts.size())) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode staged instruction count does not match the decode"));
        }
        if (paged_operands &&
            staging_handle->record_count(fact_domain_t::operand_facts) !=
                ordinals.operand_total) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode staged operand count does not match the decode"));
        }
        if (paged_targets &&
            staging_handle->record_count(fact_domain_t::target_facts) !=
                ordinals.target_total) {
            return workspace_result_t<void>::failure(materialize_integrity_error(
                "tile decode staged target count does not match the decode"));
        }
    }
    std::uint64_t resident_required = 0;
    std::uint64_t term = 0;
    if (!paged_instructions &&
        (!checked_mul_u64(ordinals.instruction_total,
             static_cast<std::uint64_t>(sizeof(instruction_record_t)), term) ||
         !checked_add_u64(resident_required, term, resident_required))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    if (!paged_operands &&
        (!checked_mul_u64(static_cast<std::uint64_t>(snapshot.operand_facts.hot.size()),
             static_cast<std::uint64_t>(sizeof(operand_fact_hot_t)), term) ||
         !checked_add_u64(resident_required, term, resident_required) ||
         !checked_mul_u64(static_cast<std::uint64_t>(snapshot.operand_facts.cold.size()),
             static_cast<std::uint64_t>(sizeof(operand_fact_cold_t)), term) ||
         !checked_add_u64(resident_required, term, resident_required))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    if (!paged_targets &&
        (!checked_mul_u64(ordinals.target_total,
             static_cast<std::uint64_t>(sizeof(target_fact_t)), term) ||
         !checked_add_u64(resident_required, term, resident_required))) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    if (!checked_add_u64(resident_required,
            static_cast<std::uint64_t>(decoded.delay_slot_counts.size()),
            resident_required)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    if (!checked_mul_u64(ordinals.expression_total,
            static_cast<std::uint64_t>(sizeof(address_expression_record_t)), term) ||
        !checked_add_u64(resident_required, term, resident_required) ||
        !checked_add_u64(resident_required,
            static_cast<std::uint64_t>(grouping.size() * sizeof(instruction_grouping_t)),
            resident_required) ||
        !checked_add_u64(resident_required,
            staging_handle ? staging_handle->resident_bytes() : 0,
            resident_required)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::range_overflow,
            "tile decode memory accounting overflows", "memory_budget"));
    }
    if (resident_required > remaining_budget_bytes) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decoded snapshot exceeds analysis memory budget even with paged residency",
            "decode_merge"));
    }
    if (!working_set_governor_t::instance().check(
            working_set_metrics::subsystem_t::resident_facts, resident_required)) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "decoded snapshot exceeds the working-set governor resident-facts budget",
            "decode_merge"));
    }
    const std::uint64_t expected_delay_slots = paged_instructions
        ? ordinals.instruction_total
        : static_cast<std::uint64_t>(snapshot.instructions.size());
    if (static_cast<std::uint64_t>(decoded.delay_slot_counts.size()) !=
        expected_delay_slots) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "tile decode delay-slot metadata is not instruction-aligned",
            "decode_merge"));
    }
    snapshot.delay_slot_counts = std::move(decoded.delay_slot_counts);
    snapshot.paged_staging = std::move(staging_handle);
    decoded.packed_shards.clear();
    return workspace_result_t<void>::success();
}

}

}
