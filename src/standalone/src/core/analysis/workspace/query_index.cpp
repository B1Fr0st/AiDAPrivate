#include "query_index.hpp"

#include "../provider_snapshot.hpp"
#include "checked_range.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <mutex>
#include <new>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

constexpr std::uint32_t kMaximumPageSize = 1U << 20;
constexpr std::uint32_t kMaximumQueryBytes = 16U * 1024U * 1024U;
constexpr std::uint32_t kMaximumBytePatternBytes = 1U * 1024U * 1024U;
constexpr std::uint64_t kMaximumBytesScannedPerPage = 8ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::uint32_t kMaximumByteScanWindowBytes = 64U * 1024U * 1024U;
constexpr std::uint64_t kMaximumRegexCandidates = 1ULL << 30;
constexpr std::uint64_t kMaximumQueryElapsedNs = 10ULL * 1000ULL * 1000ULL * 1000ULL;

static_assert(std::variant_size_v<search_query_t> == 6);
static_assert(std::is_same_v<std::variant_alternative_t<0, search_query_t>,
    literal_search_query_t>);
static_assert(std::is_same_v<std::variant_alternative_t<1, search_query_t>,
    regex_search_query_t>);
static_assert(std::is_same_v<std::variant_alternative_t<2, search_query_t>,
    byte_search_query_t>);
static_assert(std::is_same_v<std::variant_alternative_t<3, search_query_t>,
    instruction_search_query_t>);
static_assert(std::is_same_v<std::variant_alternative_t<4, search_query_t>,
    entity_search_query_t>);
static_assert(std::is_same_v<std::variant_alternative_t<5, search_query_t>,
    address_search_query_t>);

class fingerprint_builder_t final {
public:
    void add_byte(std::uint8_t value) noexcept {
        value_ ^= value;
        value_ *= 1099511628211ULL;
    }

    void add_bool(bool value) noexcept {
        add_byte(value ? 1U : 0U);
    }

    void add_u64(std::uint64_t value) noexcept {
        for (std::uint32_t shift = 0; shift < 64U; shift += 8U)
            add_byte(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }

    void add_bytes(const std::uint8_t* data, std::size_t size) noexcept {
        add_u64(size);
        for (std::size_t index = 0; index < size; ++index)
            add_byte(data[index]);
    }

    void add_string(std::string_view value) noexcept {
        add_bytes(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
    }

    void add_address(const address_t& address) noexcept {
        add_byte(static_cast<std::uint8_t>(address.space));
        add_u64(address.value);
        add_byte(static_cast<std::uint8_t>(address.architecture));
        add_byte(static_cast<std::uint8_t>(address.mode));
    }

    std::uint64_t finish() const noexcept {
        return value_ == 0 ? 1 : value_;
    }

private:
    std::uint64_t value_ = 1469598103934665603ULL;
};

class siphash_builder_t final {
public:
    explicit siphash_builder_t(const std::array<std::uint64_t, 2>& key) noexcept
        : v0_(0x736f6d6570736575ULL ^ key[0]),
          v1_(0x646f72616e646f6dULL ^ key[1]),
          v2_(0x6c7967656e657261ULL ^ key[0]),
          v3_(0x7465646279746573ULL ^ key[1]) {}

    void add_byte(std::uint8_t value) noexcept {
        tail_ |= static_cast<std::uint64_t>(value) << ((length_ & 7ULL) * 8ULL);
        ++length_;
        if ((length_ & 7ULL) == 0) {
            compress(tail_);
            tail_ = 0;
        }
    }

    void add_bool(bool value) noexcept {
        add_byte(value ? 1U : 0U);
    }

    void add_u64(std::uint64_t value) noexcept {
        for (std::uint32_t shift = 0; shift < 64U; shift += 8U)
            add_byte(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }

    void add_bytes(const std::uint8_t* data, std::size_t size) noexcept {
        add_u64(size);
        for (std::size_t index = 0; index < size; ++index)
            add_byte(data[index]);
    }

    void add_string(std::string_view value) noexcept {
        add_bytes(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
    }

    void add_address(const address_t& address) noexcept {
        add_byte(static_cast<std::uint8_t>(address.space));
        add_u64(address.value);
        add_byte(static_cast<std::uint8_t>(address.architecture));
        add_byte(static_cast<std::uint8_t>(address.mode));
    }

    std::uint64_t finish() noexcept {
        compress(tail_ | ((length_ & 0xffULL) << 56ULL));
        v2_ ^= 0xffULL;
        round();
        round();
        round();
        round();
        const auto value = v0_ ^ v1_ ^ v2_ ^ v3_;
        return value == 0 ? 1 : value;
    }

private:
    static std::uint64_t rotate_left(std::uint64_t value, std::uint32_t bits) noexcept {
        return (value << bits) | (value >> (64U - bits));
    }

    void round() noexcept {
        v0_ += v1_;
        v1_ = rotate_left(v1_, 13U);
        v1_ ^= v0_;
        v0_ = rotate_left(v0_, 32U);
        v2_ += v3_;
        v3_ = rotate_left(v3_, 16U);
        v3_ ^= v2_;
        v0_ += v3_;
        v3_ = rotate_left(v3_, 21U);
        v3_ ^= v0_;
        v2_ += v1_;
        v1_ = rotate_left(v1_, 17U);
        v1_ ^= v2_;
        v2_ = rotate_left(v2_, 32U);
    }

    void compress(std::uint64_t value) noexcept {
        v3_ ^= value;
        round();
        round();
        v0_ ^= value;
    }

    std::uint64_t v0_ = 0;
    std::uint64_t v1_ = 0;
    std::uint64_t v2_ = 0;
    std::uint64_t v3_ = 0;
    std::uint64_t tail_ = 0;
    std::uint64_t length_ = 0;
};

search_query_kind_t query_kind(const search_query_t& query) noexcept {
    return static_cast<search_query_kind_t>(query.index());
}

template <typename Builder>
void add_query_to_hash(Builder& hash, const search_query_t& query) noexcept {
    hash.add_byte(static_cast<std::uint8_t>(query_kind(query)));
    std::visit([&](const auto& value) noexcept {
        using value_t = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<value_t, literal_search_query_t>) {
            hash.add_string(value.text);
            hash.add_bool(value.case_sensitive);
        } else if constexpr (std::is_same_v<value_t, regex_search_query_t>) {
            hash.add_string(value.pattern);
            hash.add_bool(value.options.case_sensitive);
            hash.add_bool(value.options.multiline);
            hash.add_bool(value.options.dot_all);
            hash.add_bool(value.options.extended);
            hash.add_bool(value.options.literal);
        } else if constexpr (std::is_same_v<value_t, byte_search_query_t>) {
            hash.add_bytes(value.pattern.data(), value.pattern.size());
            hash.add_bytes(value.mask.data(), value.mask.size());
            hash.add_u64(value.begin_offset);
            hash.add_bool(value.end_offset.has_value());
            if (value.end_offset)
                hash.add_u64(*value.end_offset);
        } else if constexpr (std::is_same_v<value_t, instruction_search_query_t>) {
            hash.add_bool(value.filter.opcode_id.has_value());
            if (value.filter.opcode_id)
                hash.add_u64(*value.filter.opcode_id);
            hash.add_bool(value.filter.immediate.has_value());
            if (value.filter.immediate)
                hash.add_u64(*value.filter.immediate);
            hash.add_u64(value.filter.required_flow_flags);
            hash.add_u64(value.filter.forbidden_flow_flags);
            hash.add_bool(value.filter.begin.has_value());
            if (value.filter.begin)
                hash.add_address(*value.filter.begin);
            hash.add_bool(value.filter.end.has_value());
            if (value.filter.end)
                hash.add_address(*value.filter.end);
        } else if constexpr (std::is_same_v<value_t, entity_search_query_t>) {
            hash.add_bool(value.filter.kind.has_value());
            if (value.filter.kind)
                hash.add_byte(static_cast<std::uint8_t>(*value.filter.kind));
            hash.add_bool(value.filter.entity_id.has_value());
            if (value.filter.entity_id)
                hash.add_u64(*value.filter.entity_id);
        } else if constexpr (std::is_same_v<value_t, address_search_query_t>) {
            hash.add_address(value.begin);
            hash.add_address(value.end);
        }
    }, query);
}

std::uint64_t query_fingerprint(const search_query_t& query) noexcept {
    fingerprint_builder_t hash;
    add_query_to_hash(hash, query);
    return hash.finish();
}

std::uint64_t query_binding(const search_query_t& query,
    const std::array<std::uint64_t, 2>& key) noexcept {
    siphash_builder_t hash(key);
    hash.add_u64(0x3159525141444941ULL);
    add_query_to_hash(hash, query);
    return hash.finish();
}

std::uint64_t cursor_integrity_tag(const std::array<std::uint64_t, 2>& key,
    const search_generation_identity_t& identity, std::uint64_t binding,
    std::uint64_t fingerprint, std::uint64_t position,
    std::uint64_t matches_consumed) noexcept {
    siphash_builder_t hash(key);
    hash.add_u64(0x3152554341444941ULL);
    hash.add_bytes(identity.binary_id.bytes.data(), identity.binary_id.bytes.size());
    hash.add_bytes(identity.load_profile_hash.bytes.data(),
        identity.load_profile_hash.bytes.size());
    hash.add_bool(identity.provider_content_hash.has_value());
    if (identity.provider_content_hash) {
        hash.add_bytes(identity.provider_content_hash->bytes.data(),
            identity.provider_content_hash->bytes.size());
    }
    hash.add_u64(identity.generation);
    hash.add_u64(identity.analysis_revision);
    hash.add_u64(identity.overlay_revision);
    hash.add_u64(identity.provider_size);
    hash.add_u64(binding);
    hash.add_u64(fingerprint);
    hash.add_u64(position);
    hash.add_u64(matches_consumed);
    return hash.finish();
}

workspace_error_t query_stop_error(const cancellation_token_t& cancel,
    bool elapsed_deadline) {
    if (elapsed_deadline || cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "search query exceeded its bounded deadline", "query_index");
        error.deadline = true;
        error.cancellation = cancel.stop_requested();
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "search query was cancelled", "query_index");
    error.cancellation = true;
    return error;
}

query_outcome_t outcome_for_error(const workspace_error_t& error) noexcept {
    switch (error.code) {
    case workspace_error_code_t::invalid_argument:
    case workspace_error_code_t::stale_generation:
    case workspace_error_code_t::substitution_rejected:
        return query_outcome_t::invalid;
    case workspace_error_code_t::cancelled:
        return query_outcome_t::cancelled;
    case workspace_error_code_t::deadline_exceeded:
        return query_outcome_t::deadline;
    case workspace_error_code_t::limit_exceeded:
        return query_outcome_t::limited;
    default:
        return query_outcome_t::failed;
    }
}

std::optional<search_hit_t> materialize_hit(
    const std::optional<search_record_view_t>& record) {
    if (!record)
        return std::nullopt;
    search_hit_t hit;
    hit.kind = record->kind;
    hit.entity_id = record->entity_id;
    hit.address = record->address;
    if (!record->text.empty())
        hit.text.assign(record->text.data(), record->text.size());
    hit.numeric_value = record->numeric_value;
    return hit;
}

std::uint64_t saturating_add(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    return rhs > std::numeric_limits<std::uint64_t>::max() - lhs
        ? std::numeric_limits<std::uint64_t>::max() : lhs + rhs;
}

std::uint8_t popcount8(std::uint8_t value) noexcept {
    value = static_cast<std::uint8_t>(value - ((value >> 1U) & 0x55U));
    value = static_cast<std::uint8_t>((value & 0x33U) + ((value >> 2U) & 0x33U));
    return static_cast<std::uint8_t>((value + (value >> 4U)) & 0x0fU);
}

}

struct query_index_t::impl_t {
    search_generation_handle_t generation;
    std::shared_ptr<const provider_snapshot_t> provider;
    query_index_limits_t limits;
    query_telemetry_hook_t telemetry;
    std::array<std::uint64_t, 2> cursor_integrity_key{};
    mutable std::recursive_mutex telemetry_mutex;

    void emit(const query_telemetry_t& value) const noexcept {
        if (!telemetry)
            return;
        try {
            std::lock_guard<std::recursive_mutex> lock(telemetry_mutex);
            telemetry(value);
        } catch (...) {
        }
    }

    query_cursor_t make_cursor(std::uint64_t fingerprint, std::uint64_t binding,
        std::uint64_t position, std::uint64_t matches_consumed) const noexcept {
        query_cursor_t cursor;
        cursor.generation = generation.identity();
        cursor.query_fingerprint = fingerprint;
        cursor.position = position;
        cursor.matches_consumed = matches_consumed;
        cursor.integrity_tag = cursor_integrity_tag(cursor_integrity_key,
            cursor.generation, binding, fingerprint, position, matches_consumed);
        return cursor;
    }

    bool cursor_is_valid(const query_cursor_t& cursor,
        std::uint64_t binding) const noexcept {
        if (cursor.integrity_tag == 0)
            return false;
        const auto expected = cursor_integrity_tag(cursor_integrity_key,
            cursor.generation, binding, cursor.query_fingerprint,
            cursor.position, cursor.matches_consumed);
        return cursor.integrity_tag == expected;
    }

    query_page_t convert_indexed_page(search_page_t page,
        std::uint64_t fingerprint, std::uint64_t binding) const {
        query_page_t result;
        result.hits = std::move(page.hits);
        result.total = page.total;
        result.total_is_exact = true;
        result.truncated = page.truncated;
        if (page.truncated) {
            result.next = make_cursor(fingerprint, binding,
                page.next_offset, page.next_offset);
        }
        return result;
    }

    workspace_result_t<query_page_t> text_query(std::string_view pattern,
        bool case_sensitive, bool regex_mode, const regex_compile_options_t& regex_options,
        const query_page_request_t& page, const cancellation_token_t& cancel,
        std::chrono::steady_clock::time_point deadline, std::uint64_t fingerprint,
        std::uint64_t binding, query_telemetry_t& telemetry_value) const {
        if (pattern.empty() || pattern.size() > limits.max_query_bytes) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                "text query is outside the allowed byte range", "query_index");
            error.size = pattern.size();
            error.details.emplace_back("maximum", std::to_string(limits.max_query_bytes));
            return workspace_result_t<query_page_t>::failure(std::move(error));
        }
        const auto* index = generation.get();
        if (!index) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "search generation handle is stale", "query_index"));
        }
        const bool use_regex = regex_mode || !case_sensitive;
        std::optional<regex_match_session_t> session;
        if (use_regex) {
            if (index->text_record_count() > limits.max_regex_candidates) {
                return workspace_result_t<query_page_t>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "regular-expression candidate count exceeds its bound",
                        "query_index"));
            }
            auto options = regex_options;
            if (!regex_mode) {
                options = {};
                options.case_sensitive = false;
                options.literal = true;
            }
            auto compiled = regex_query_t::compile(pattern, options, limits.regex);
            if (!compiled)
                return workspace_result_t<query_page_t>::failure(compiled.error());
            auto created = compiled.value()->create_session(cancel, deadline);
            if (!created)
                return workspace_result_t<query_page_t>::failure(created.error());
            session.emplace(created.take_value());
        }

        const std::uint64_t offset = page.cursor ? page.cursor->position : 0;
        query_page_t result;
        result.hits.reserve(page.limit);
        const auto interval = static_cast<std::size_t>(
            std::max<std::uint32_t>(1U, limits.cancellation_check_interval));
        for (std::size_t candidate = 0; candidate < index->text_record_count(); ++candidate) {
            if ((candidate % interval) == 0) {
                ++telemetry_value.cancellation_checks;
                if (cancel.stop_requested())
                    return workspace_result_t<query_page_t>::failure(
                        query_stop_error(cancel, false));
                if (std::chrono::steady_clock::now() >= deadline)
                    return workspace_result_t<query_page_t>::failure(
                        query_stop_error(cancel, true));
            }
            ++telemetry_value.candidates_examined;
            const auto record = index->text_record(candidate);
            if (!record) {
                return workspace_result_t<query_page_t>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "packed text reference cannot be resolved", "query_index"));
            }
            bool matched = false;
            if (session) {
                auto match = session->match(record->text);
                telemetry_value.regex_engine_steps = session->engine_steps();
                if (!match) {
                    if (match.error().code == workspace_error_code_t::invalid_argument) {
                        ++telemetry_value.invalid_utf_subjects;
                        continue;
                    }
                    return workspace_result_t<query_page_t>::failure(match.error());
                }
                matched = match.value().matched;
            } else {
                matched = record->text.find(pattern) != std::string_view::npos;
            }
            if (!matched)
                continue;
            const auto ordinal = result.total++;
            telemetry_value.matches = saturating_add(telemetry_value.matches, 1);
            if (ordinal < offset || result.hits.size() >= page.limit)
                continue;
            auto hit = materialize_hit(record);
            if (!hit) {
                return workspace_result_t<query_page_t>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "packed text result cannot be materialized", "query_index"));
            }
            result.hits.push_back(std::move(*hit));
        }
        if (page.cursor && offset >= result.total) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "text-query cursor position exceeds the exact result set",
                    "query_index"));
        }
        const auto next_offset = offset >= result.total
            ? result.total : offset + result.hits.size();
        result.truncated = next_offset < result.total;
        if (result.truncated) {
            result.next = make_cursor(fingerprint, binding,
                next_offset, next_offset);
        }
        return workspace_result_t<query_page_t>::success(std::move(result));
    }

    workspace_result_t<query_page_t> byte_query(const byte_search_query_t& query,
        const query_page_request_t& page, const cancellation_token_t& cancel,
        std::chrono::steady_clock::time_point deadline, std::uint64_t fingerprint,
        std::uint64_t binding, query_telemetry_t& telemetry_value) const {
        if (!provider) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::provider_unavailable,
                    "byte search requires an immutable provider snapshot", "query_index"));
        }
        if (query.pattern.empty() || query.pattern.size() > limits.max_byte_pattern_bytes) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                "byte-search pattern is outside the allowed byte range", "query_index");
            error.size = query.pattern.size();
            error.details.emplace_back("maximum",
                std::to_string(limits.max_byte_pattern_bytes));
            return workspace_result_t<query_page_t>::failure(std::move(error));
        }
        if (!query.mask.empty() && query.mask.size() != query.pattern.size()) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "byte-search mask length does not match its pattern", "query_index"));
        }
        std::vector<std::uint8_t> mask(query.pattern.size(), 0xffU);
        if (!query.mask.empty())
            mask = query.mask;
        std::size_t anchor = 0;
        std::uint8_t anchor_bits = 0;
        for (std::size_t index = 0; index < mask.size(); ++index) {
            const auto bits = popcount8(mask[index]);
            if (bits > anchor_bits) {
                anchor = index;
                anchor_bits = bits;
            }
        }
        if (anchor_bits == 0) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "byte-search mask must constrain at least one bit", "query_index"));
        }
        if (query.pattern.size() > limits.max_bytes_scanned_per_page) {
            auto error = make_workspace_error(workspace_error_code_t::limit_exceeded,
                "byte-search pattern cannot make progress within the scan budget",
                "query_index");
            error.size = query.pattern.size();
            error.details.emplace_back("maximum",
                std::to_string(limits.max_bytes_scanned_per_page));
            return workspace_result_t<query_page_t>::failure(std::move(error));
        }
        const std::uint64_t end = query.end_offset.value_or(provider->size());
        if (query.begin_offset > end || end > provider->size() ||
            query.pattern.size() > end - query.begin_offset) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::out_of_range,
                    "byte-search range is outside the provider snapshot", "query_index"));
        }
        const auto candidate_end = end - query.pattern.size() + 1ULL;
        std::uint64_t position = page.cursor ? page.cursor->position : query.begin_offset;
        std::uint64_t consumed = page.cursor ? page.cursor->matches_consumed : 0;
        if (position < query.begin_offset || position > candidate_end ||
            (page.cursor && position == candidate_end)) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "byte-search cursor position is outside its query range", "query_index"));
        }
        if (page.cursor && consumed > position - query.begin_offset) {
            return workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "byte-search cursor match count exceeds its scanned prefix",
                    "query_index"));
        }

        query_page_t result;
        result.hits.reserve(page.limit);
        std::uint64_t page_matches = 0;
        std::uint64_t next_position = position;
        const auto pattern_size = static_cast<std::uint64_t>(query.pattern.size());
        const auto overlap = pattern_size - 1ULL;
        std::vector<std::uint8_t> buffer;
        const auto maximum_buffer = static_cast<std::uint64_t>(limits.byte_scan_window_bytes) +
            overlap;
        buffer.reserve(static_cast<std::size_t>(maximum_buffer));
        while (next_position < candidate_end) {
            ++telemetry_value.cancellation_checks;
            if (cancel.stop_requested())
                return workspace_result_t<query_page_t>::failure(
                    query_stop_error(cancel, false));
            if (std::chrono::steady_clock::now() >= deadline)
                return workspace_result_t<query_page_t>::failure(
                    query_stop_error(cancel, true));
            const auto remaining_budget = limits.max_bytes_scanned_per_page -
                telemetry_value.bytes_scanned;
            if (remaining_budget <= overlap) {
                result.total = saturating_add(consumed, page_matches);
                result.total_is_exact = false;
                result.truncated = true;
                result.next = make_cursor(fingerprint, binding,
                    next_position, result.total);
                return workspace_result_t<query_page_t>::success(std::move(result));
            }
            std::uint64_t primary = std::min<std::uint64_t>(
                limits.byte_scan_window_bytes, candidate_end - next_position);
            primary = std::min(primary, remaining_budget - overlap);
            const std::uint64_t read_size = primary + overlap;
            buffer.resize(static_cast<std::size_t>(read_size));
            auto read = provider->read_exact(next_position, buffer.data(), read_size, cancel);
            if (!read)
                return workspace_result_t<query_page_t>::failure(read.error());
            telemetry_value.bytes_scanned = saturating_add(
                telemetry_value.bytes_scanned, read_size);
            for (std::uint64_t local = 0; local < primary; ++local) {
                if ((local % limits.cancellation_check_interval) == 0) {
                    ++telemetry_value.cancellation_checks;
                    if (cancel.stop_requested())
                        return workspace_result_t<query_page_t>::failure(
                            query_stop_error(cancel, false));
                    if (std::chrono::steady_clock::now() >= deadline)
                        return workspace_result_t<query_page_t>::failure(
                            query_stop_error(cancel, true));
                }
                ++telemetry_value.candidates_examined;
                const auto local_index = static_cast<std::size_t>(local);
                if ((buffer[local_index + anchor] & mask[anchor]) !=
                    (query.pattern[anchor] & mask[anchor]))
                    continue;
                bool matched = true;
                for (std::size_t byte = 0; byte < query.pattern.size(); ++byte) {
                    if ((buffer[local_index + byte] & mask[byte]) !=
                        (query.pattern[byte] & mask[byte])) {
                        matched = false;
                        break;
                    }
                }
                if (!matched)
                    continue;
                const auto absolute = next_position + local;
                telemetry_value.matches = saturating_add(telemetry_value.matches, 1);
                if (result.hits.size() >= page.limit) {
                    result.total = saturating_add(saturating_add(consumed, page_matches), 1);
                    result.total_is_exact = false;
                    result.truncated = true;
                    result.next = make_cursor(fingerprint, binding, position,
                        saturating_add(consumed, page_matches));
                    return workspace_result_t<query_page_t>::success(std::move(result));
                }
                search_hit_t hit;
                hit.kind = search_entity_kind_t::byte_sequence;
                hit.address = generation.get()->file_offset_address(absolute);
                hit.numeric_value = query.pattern.size();
                result.hits.push_back(std::move(hit));
                ++page_matches;
                position = absolute + 1ULL;
            }
            next_position += primary;
            position = next_position;
        }
        result.total = saturating_add(consumed, page_matches);
        result.total_is_exact = true;
        result.truncated = false;
        return workspace_result_t<query_page_t>::success(std::move(result));
    }
};

query_index_t::query_index_t(std::unique_ptr<impl_t> impl) noexcept
    : impl_(std::move(impl)) {}

query_index_t::~query_index_t() = default;

workspace_result_t<std::shared_ptr<const query_index_t>> query_index_t::build(
    std::shared_ptr<const search_index_t> index,
    std::shared_ptr<const provider_snapshot_t> provider,
    const query_index_limits_t& limits,
    query_telemetry_hook_t telemetry) {
    if (!index) {
        return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "query index requires a search index", "query_index"));
    }
    try {
        return build(index->generation_handle(), std::move(provider), limits,
            std::move(telemetry));
    } catch (const std::bad_weak_ptr&) {
        return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::integrity_failure,
                "query index search ownership is not immutable", "query_index"));
    }
}

workspace_result_t<std::shared_ptr<const query_index_t>> query_index_t::build(
    search_generation_handle_t generation,
    std::shared_ptr<const provider_snapshot_t> provider,
    const query_index_limits_t& limits,
    query_telemetry_hook_t telemetry) {
    try {
        if (!generation.valid()) {
            return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "query index requires an immutable search generation", "query_index"));
        }
        const auto* search = generation.get();
        if (!search) {
            return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "query index search generation is unavailable", "query_index"));
        }
        if (limits.max_page_size == 0 || limits.max_page_size > kMaximumPageSize ||
            limits.max_page_size > search->limits().max_results_per_query ||
            limits.max_query_bytes == 0 || limits.max_query_bytes > kMaximumQueryBytes ||
            limits.max_byte_pattern_bytes == 0 ||
            limits.max_byte_pattern_bytes > kMaximumBytePatternBytes ||
            limits.max_bytes_scanned_per_page == 0 ||
            limits.max_bytes_scanned_per_page > kMaximumBytesScannedPerPage ||
            limits.byte_scan_window_bytes == 0 ||
            limits.byte_scan_window_bytes > kMaximumByteScanWindowBytes ||
            limits.byte_scan_window_bytes > limits.max_bytes_scanned_per_page ||
            limits.max_regex_candidates == 0 ||
            limits.max_regex_candidates > kMaximumRegexCandidates ||
            limits.cancellation_check_interval == 0 ||
            limits.max_query_elapsed_ns == 0 ||
            limits.max_query_elapsed_ns > kMaximumQueryElapsedNs) {
            return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "query-index resource limits are invalid", "query_index"));
        }
        auto regex_limits = regex_query_t::validate_limits(limits.regex);
        if (!regex_limits)
            return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                regex_limits.error());
        if (provider) {
            const auto& expected = generation.identity();
            const auto& actual = provider->identity();
            if (expected.provider_size == 0 || !expected.provider_content_hash) {
                return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::substitution_rejected,
                        "search generation lacks a complete byte-provider identity",
                        "query_index"));
            }
            if (!actual.immutable_snapshot || provider->generation() != expected.generation) {
                return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::stale_generation,
                        "byte provider does not belong to the search generation",
                        "query_index"));
            }
            if (provider->size() != expected.provider_size) {
                return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::substitution_rejected,
                        "byte provider size does not match the search generation",
                        "query_index"));
            }
            if (!actual.content_sha256 ||
                *expected.provider_content_hash != *actual.content_sha256) {
                return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::substitution_rejected,
                        "byte provider content identity does not match the search generation",
                        "query_index"));
            }
            auto source_valid = provider->validate_source();
            if (!source_valid) {
                return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
                    source_valid.error());
            }
        }
        const auto cursor_integrity_key = search->cursor_integrity_key();
        auto impl = std::make_unique<impl_t>();
        impl->generation = std::move(generation);
        impl->provider = std::move(provider);
        impl->limits = limits;
        impl->telemetry = std::move(telemetry);
        impl->cursor_integrity_key = cursor_integrity_key;
        return workspace_result_t<std::shared_ptr<const query_index_t>>::success(
            std::shared_ptr<const query_index_t>(new query_index_t(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<const query_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "query-index allocation exceeded available memory", "query_index"));
    }
}

const search_generation_identity_t& query_index_t::identity() const noexcept {
    return impl_->generation.identity();
}

const search_generation_handle_t& query_index_t::generation_handle() const noexcept {
    return impl_->generation;
}

const query_index_limits_t& query_index_t::limits() const noexcept {
    return impl_->limits;
}

bool query_index_t::has_byte_provider() const noexcept {
    return impl_->provider != nullptr;
}

workspace_result_t<void> query_index_t::validate_cursor(
    const search_query_t& query_value,
    const query_cursor_t& cursor) const {
    try {
        if (query_value.valueless_by_exception()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "search query has no active operation", "query_index.cursor"));
        }
        if (!impl_->generation.valid() ||
            cursor.generation != impl_->generation.identity()) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "query cursor does not belong to this immutable query generation",
                "query_index.cursor"));
        }
        const auto fingerprint = query_fingerprint(query_value);
        if (cursor.query_fingerprint != fingerprint) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::stale_generation,
                "query cursor belongs to a different query",
                "query_index.cursor"));
        }
        const auto binding = query_binding(query_value, impl_->cursor_integrity_key);
        if (!impl_->cursor_is_valid(cursor, binding)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "query cursor integrity validation failed", "query_index.cursor"));
        }
        if (query_kind(query_value) != search_query_kind_t::bytes &&
            (cursor.position == 0 ||
             cursor.matches_consumed != cursor.position)) {
            return workspace_result_t<void>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "query cursor progress is structurally invalid",
                "query_index.cursor"));
        }
        return workspace_result_t<void>::success();
    } catch (const std::bad_alloc&) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "cursor validation allocation exceeded available memory",
            "query_index.cursor"));
    } catch (const std::length_error&) {
        return workspace_result_t<void>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "cursor validation exceeds container limits", "query_index.cursor"));
    }
}

workspace_result_t<query_page_t> query_index_t::query_literal(
    const literal_search_query_t& query_value,
    const query_page_request_t& page,
    const cancellation_token_t& cancel) const {
    return query(search_query_t{query_value}, page, cancel);
}

workspace_result_t<query_page_t> query_index_t::query_regex(
    const regex_search_query_t& query_value,
    const query_page_request_t& page,
    const cancellation_token_t& cancel) const {
    return query(search_query_t{query_value}, page, cancel);
}

workspace_result_t<query_page_t> query_index_t::query_bytes(
    const byte_search_query_t& query_value,
    const query_page_request_t& page,
    const cancellation_token_t& cancel) const {
    return query(search_query_t{query_value}, page, cancel);
}

workspace_result_t<query_page_t> query_index_t::query_instruction(
    const instruction_search_query_t& query_value,
    const query_page_request_t& page,
    const cancellation_token_t& cancel) const {
    return query(search_query_t{query_value}, page, cancel);
}

workspace_result_t<query_page_t> query_index_t::query_entity(
    const entity_search_query_t& query_value,
    const query_page_request_t& page,
    const cancellation_token_t& cancel) const {
    return query(search_query_t{query_value}, page, cancel);
}

workspace_result_t<query_page_t> query_index_t::query_address(
    const address_search_query_t& query_value,
    const query_page_request_t& page,
    const cancellation_token_t& cancel) const {
    return query(search_query_t{query_value}, page, cancel);
}

workspace_result_t<query_page_t> query_index_t::query(const search_query_t& query_value,
    const query_page_request_t& page, const cancellation_token_t& cancel) const {
    query_telemetry_t telemetry;
    telemetry.kind = search_query_kind_t::invalid;
    telemetry.generation = impl_->generation.identity().generation;
    const auto started = analysis_metrics_t::steady_now_ns();
    const auto finish = [&](workspace_result_t<query_page_t> result) {
        const auto finished = analysis_metrics_t::steady_now_ns();
        telemetry.elapsed_ns = finished >= started ? finished - started : 0;
        if (result) {
            telemetry.outcome = query_outcome_t::success;
            telemetry.matches = result.value().total;
            telemetry.returned = result.value().hits.size();
            telemetry.total_is_exact = result.value().total_is_exact;
        } else {
            telemetry.outcome = outcome_for_error(result.error());
        }
        impl_->emit(telemetry);
        return result;
    };
    try {
        if (query_value.valueless_by_exception()) {
            return finish(workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "search query has no active operation", "query_index")));
        }
        telemetry.kind = query_kind(query_value);
        telemetry.query_fingerprint = query_fingerprint(query_value);
        const auto binding = query_binding(query_value, impl_->cursor_integrity_key);
        if (!impl_->generation.valid()) {
            return finish(workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "query index generation is stale", "query_index")));
        }
        if (page.limit == 0 || page.limit > impl_->limits.max_page_size) {
            auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
                "query page size is outside the allowed range", "query_index");
            error.details.emplace_back("maximum",
                std::to_string(impl_->limits.max_page_size));
            return finish(workspace_result_t<query_page_t>::failure(std::move(error)));
        }
        if (page.cursor &&
            (page.cursor->generation != impl_->generation.identity() ||
             page.cursor->query_fingerprint != telemetry.query_fingerprint)) {
            return finish(workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "query cursor does not belong to this immutable query generation",
                    "query_index")));
        }
        if (page.cursor && !impl_->cursor_is_valid(*page.cursor, binding)) {
            return finish(workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "query cursor integrity validation failed", "query_index")));
        }
        if (page.cursor && telemetry.kind != search_query_kind_t::bytes &&
            (page.cursor->position == 0 ||
             page.cursor->matches_consumed != page.cursor->position)) {
            return finish(workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "query cursor progress is structurally invalid", "query_index")));
        }
        if (cancel.stop_requested()) {
            return finish(workspace_result_t<query_page_t>::failure(
                query_stop_error(cancel, false)));
        }
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::nanoseconds(impl_->limits.max_query_elapsed_ns);
        const auto* search = impl_->generation.get();
        if (!search) {
            return finish(workspace_result_t<query_page_t>::failure(
                make_workspace_error(workspace_error_code_t::stale_generation,
                    "query search generation is unavailable", "query_index")));
        }
        const auto offset = page.cursor ? page.cursor->position : 0;
        const auto indexed_result = [&](workspace_result_t<search_page_t> result) {
            if (!result)
                return finish(workspace_result_t<query_page_t>::failure(result.error()));
            auto indexed_page = result.take_value();
            telemetry.candidates_examined = saturating_add(
                telemetry.candidates_examined, indexed_page.candidates_examined);
            telemetry.cancellation_checks = saturating_add(
                telemetry.cancellation_checks, indexed_page.cancellation_checks);
            if (page.cursor && offset >= indexed_page.total) {
                return finish(workspace_result_t<query_page_t>::failure(
                    make_workspace_error(workspace_error_code_t::invalid_argument,
                        "query cursor position exceeds the exact result set",
                        "query_index")));
            }
            return finish(workspace_result_t<query_page_t>::success(
                impl_->convert_indexed_page(std::move(indexed_page),
                    telemetry.query_fingerprint, binding)));
        };
        switch (telemetry.kind) {
        case search_query_kind_t::literal: {
            const auto& value = std::get<literal_search_query_t>(query_value);
            regex_compile_options_t options;
            auto result = impl_->text_query(value.text, value.case_sensitive, false, options,
                page, cancel, deadline, telemetry.query_fingerprint, binding, telemetry);
            return finish(std::move(result));
        }
        case search_query_kind_t::regex: {
            const auto& value = std::get<regex_search_query_t>(query_value);
            auto result = impl_->text_query(value.pattern, value.options.case_sensitive,
                true, value.options, page, cancel, deadline,
                telemetry.query_fingerprint, binding, telemetry);
            return finish(std::move(result));
        }
        case search_query_kind_t::bytes: {
            auto result = impl_->byte_query(std::get<byte_search_query_t>(query_value),
                page, cancel, deadline, telemetry.query_fingerprint, binding, telemetry);
            return finish(std::move(result));
        }
        case search_query_kind_t::instruction: {
            const auto& value = std::get<instruction_search_query_t>(query_value);
            return indexed_result(search->find_instruction(value.filter, offset,
                page.limit, cancel, deadline));
        }
        case search_query_kind_t::entity: {
            const auto& value = std::get<entity_search_query_t>(query_value);
            return indexed_result(search->find_entity(value.filter, offset,
                page.limit, cancel, deadline));
        }
        case search_query_kind_t::address: {
            const auto& value = std::get<address_search_query_t>(query_value);
            return indexed_result(search->find_address_range(value.begin, value.end,
                offset, page.limit, cancel, deadline));
        }
        case search_query_kind_t::invalid:
            break;
        }
        return finish(workspace_result_t<query_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "query kind is invalid", "query_index")));
    } catch (const std::bad_alloc&) {
        return finish(workspace_result_t<query_page_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "query allocation exceeded available memory", "query_index")));
    } catch (const std::length_error&) {
        return finish(workspace_result_t<query_page_t>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "query allocation exceeds container limits", "query_index")));
    }
}

}
