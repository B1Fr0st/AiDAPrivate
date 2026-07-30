#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "search_index.hpp"

#include "checked_range.hpp"
#include "parallel_pass.hpp"
#include "pe_image.hpp"

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#include <windows.h>
#include <bcrypt.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <iterator>
#include <limits>
#include <new>
#include <stdexcept>
#include <system_error>
#include <unordered_map>
#include <utility>

#if !defined(AIDA_IMGUI_STUDIO_PREVIEW)
#pragma comment(lib, "bcrypt.lib")
#endif

namespace aida::analysis {
namespace {

struct packed_string_id_t {
    std::uint32_t value = 0;

    bool valid() const noexcept {
        return value != 0;
    }
};

struct packed_address_t {
    std::uint64_t value = 0;
    std::uint32_t metadata = 0;
};

struct packed_search_record_t {
    entity_id_t entity_id = 0;
    std::uint64_t numeric_value = 0;
    packed_address_t address;
    packed_string_id_t text;
    packed_string_id_t normalized_text;
    std::uint32_t auxiliary_flags = 0;
    search_entity_kind_t kind = search_entity_kind_t::symbol;
};

struct packed_text_reference_t {
    std::uint32_t record = 0;
    packed_string_id_t normalized;
};

struct packed_key32_reference_t {
    std::uint32_t key = 0;
    std::uint32_t record = 0;
};

struct packed_key64_reference_t {
    std::uint64_t key = 0;
    std::uint32_t record = 0;
};

struct packed_trigram_span_t {
    std::uint32_t key = 0;
    std::uint32_t begin = 0;
    std::uint32_t count = 0;
};

struct interned_string_pool_t {
    std::vector<std::uint32_t> offsets;
    std::vector<std::uint32_t> lengths;
    std::vector<char> bytes;

    std::optional<std::string_view> lookup(packed_string_id_t id) const noexcept {
        if (!id.valid())
            return std::nullopt;
        const auto index = static_cast<std::size_t>(id.value - 1U);
        if (index >= offsets.size() || index >= lengths.size())
            return std::nullopt;
        const auto offset = static_cast<std::size_t>(offsets[index]);
        const auto length = static_cast<std::size_t>(lengths[index]);
        if (offset > bytes.size() || length > bytes.size() - offset)
            return std::nullopt;
        if (length == 0)
            return std::string_view{};
        return std::string_view(bytes.data() + offset, length);
    }
};

class interned_string_builder_t final {
public:
    workspace_result_t<packed_string_id_t> intern(std::string_view value) {
        const std::string key(value);
        const auto found = index_.find(key);
        if (found != index_.end())
            return workspace_result_t<packed_string_id_t>::success(found->second);
        if (values_.size() >= std::numeric_limits<std::uint32_t>::max() ||
            value.size() > std::numeric_limits<std::uint32_t>::max()) {
            return workspace_result_t<packed_string_id_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index string pool exceeds packed identifier limits",
                    "search_index"));
        }
        const packed_string_id_t id{static_cast<std::uint32_t>(values_.size() + 1U)};
        values_.push_back(key);
        index_.emplace(values_.back(), id);
        return workspace_result_t<packed_string_id_t>::success(id);
    }

    const std::vector<std::string>& values() const noexcept {
        return values_;
    }

private:
    std::vector<std::string> values_;
    std::unordered_map<std::string, packed_string_id_t> index_;
};

workspace_result_t<interned_string_pool_t> freeze_string_values(
    const std::vector<std::string>& values) {
    std::uint64_t total = 0;
    for (const auto& value : values) {
        std::uint64_t updated = 0;
        if (!checked_add_u64(total, value.size(), updated) ||
            updated > std::numeric_limits<std::uint32_t>::max()) {
            return workspace_result_t<interned_string_pool_t>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index string payload exceeds packed offset limits",
                    "search_index"));
        }
        total = updated;
    }
    interned_string_pool_t pool;
    pool.offsets.reserve(values.size());
    pool.lengths.reserve(values.size());
    pool.bytes.reserve(static_cast<std::size_t>(total));
    for (const auto& value : values) {
        pool.offsets.push_back(static_cast<std::uint32_t>(pool.bytes.size()));
        pool.lengths.push_back(static_cast<std::uint32_t>(value.size()));
        pool.bytes.insert(pool.bytes.end(), value.begin(), value.end());
    }
    return workspace_result_t<interned_string_pool_t>::success(std::move(pool));
}

packed_address_t pack_address(const address_t& address) noexcept {
    const auto metadata = static_cast<std::uint32_t>(address.space) |
        (static_cast<std::uint32_t>(address.architecture) << 8U) |
        (static_cast<std::uint32_t>(address.mode) << 16U);
    return packed_address_t{address.value, metadata};
}

address_t unpack_address(const packed_address_t& packed) noexcept {
    address_t address;
    address.space = static_cast<address_space_id_t>(packed.metadata & 0xffU);
    address.value = packed.value;
    address.architecture = static_cast<architecture_id_t>((packed.metadata >> 8U) & 0xffU);
    address.mode = static_cast<architecture_mode_t>((packed.metadata >> 16U) & 0xffU);
    return address;
}

bool packed_address_less(const packed_address_t& lhs, const packed_address_t& rhs) noexcept {
    return unpack_address(lhs) < unpack_address(rhs);
}

bool packed_address_equal(const packed_address_t& lhs, const packed_address_t& rhs) noexcept {
    return lhs.value == rhs.value && lhs.metadata == rhs.metadata;
}

search_generation_identity_t snapshot_identity(const analysis_snapshot_t& snapshot) noexcept {
    search_generation_identity_t result;
    result.binary_id = snapshot.binary_id;
    result.load_profile_hash = snapshot.load_profile_hash;
    result.generation = snapshot.generation;
    result.analysis_revision = snapshot.analysis_revision;
    result.overlay_revision = snapshot.overlay_revision;
    if (snapshot.normalized_image) {
        result.provider_size = snapshot.normalized_image->provider_size;
        if (!snapshot.normalized_image->provider_content_hash.empty())
            result.provider_content_hash = snapshot.normalized_image->provider_content_hash;
    }
    return result;
}

std::string normalize_text(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    bool previous_space = false;
    for (const auto raw : text) {
        const auto value = static_cast<unsigned char>(raw);
        if (value < 0x80U && std::isspace(value) != 0) {
            if (!result.empty() && !previous_space)
                result.push_back(' ');
            previous_space = true;
            continue;
        }
        previous_space = false;
        result.push_back(value < 0x80U
            ? static_cast<char>(std::tolower(value)) : static_cast<char>(value));
    }
    while (!result.empty() && result.back() == ' ')
        result.pop_back();
    return result;
}

std::uint32_t trigram_key(const char* value) noexcept {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(value[0])) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(value[1])) << 8U) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(value[2])) << 16U);
}

workspace_error_t stop_error(const cancellation_token_t& cancel, const char* phase,
    bool elapsed_deadline = false) {
    if (elapsed_deadline || cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "search operation exceeded its deadline", phase);
        error.cancellation = cancel.cancellation_requested();
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "search operation cancelled", phase);
    error.cancellation = true;
    return error;
}

workspace_result_t<void> validate_page(std::uint32_t limit,
    std::uint32_t maximum, const char* phase) {
    if (limit == 0 || limit > maximum) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
            "search page limit is outside the allowed range", phase);
        error.details.emplace_back("maximum", std::to_string(maximum));
        return workspace_result_t<void>::failure(std::move(error));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_filter_range(const std::optional<address_t>& begin,
    const std::optional<address_t>& end, const char* phase) {
    if (begin.has_value() != end.has_value()) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "instruction address filter requires both range endpoints", phase));
    }
    if (!begin)
        return workspace_result_t<void>::success();
    if (*end < *begin || begin->space != end->space ||
        begin->architecture != end->architecture || begin->mode != end->mode) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "instruction address filter range is invalid", phase));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> validate_running(const cancellation_token_t& cancel,
    search_deadline_t deadline, const char* phase) {
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(stop_error(cancel, phase));
    if (deadline && std::chrono::steady_clock::now() >= *deadline)
        return workspace_result_t<void>::failure(stop_error(cancel, phase, true));
    return workspace_result_t<void>::success();
}

bool address_matches_range(const address_t& address,
    const std::optional<address_t>& begin, const std::optional<address_t>& end) noexcept {
    return !begin || (! (address < *begin) && address < *end);
}

bool record_less(const packed_search_record_t& lhs,
                 const packed_search_record_t& rhs) noexcept {
    if (!packed_address_equal(lhs.address, rhs.address))
        return packed_address_less(lhs.address, rhs.address);
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.entity_id != rhs.entity_id)
        return lhs.entity_id < rhs.entity_id;
    if (lhs.text.value != rhs.text.value)
        return lhs.text.value < rhs.text.value;
    if (lhs.normalized_text.value != rhs.normalized_text.value)
        return lhs.normalized_text.value < rhs.normalized_text.value;
    if (lhs.numeric_value != rhs.numeric_value)
        return lhs.numeric_value < rhs.numeric_value;
    return lhs.auxiliary_flags < rhs.auxiliary_flags;
}

std::uint64_t vector_bytes(std::size_t capacity, std::size_t element_size) noexcept {
    if (capacity != 0 && element_size > std::numeric_limits<std::uint64_t>::max() / capacity)
        return std::numeric_limits<std::uint64_t>::max();
    return static_cast<std::uint64_t>(capacity) * static_cast<std::uint64_t>(element_size);
}

template <typename RefAt, typename Predicate, typename Materialize>
workspace_result_t<search_page_t> filtered_page(std::size_t candidate_count,
    RefAt&& ref_at, Predicate&& predicate, Materialize&& materialize,
    std::uint64_t offset, std::uint32_t limit, std::uint32_t cancellation_interval,
    const cancellation_token_t& cancel, search_deadline_t deadline, const char* phase) {
    search_page_t page;
    page.hits.reserve(limit);
    const auto interval = static_cast<std::size_t>(std::max<std::uint32_t>(1U,
        cancellation_interval));
    for (std::size_t index = 0; index < candidate_count; ++index) {
        if ((index % interval) == 0) {
            ++page.cancellation_checks;
            if (cancel.stop_requested())
                return workspace_result_t<search_page_t>::failure(stop_error(cancel, phase));
            if (deadline && std::chrono::steady_clock::now() >= *deadline)
                return workspace_result_t<search_page_t>::failure(
                    stop_error(cancel, phase, true));
        }
        ++page.candidates_examined;
        const auto reference = ref_at(index);
        if (!predicate(reference))
            continue;
        const auto ordinal = page.total++;
        if (ordinal < offset || page.hits.size() >= limit)
            continue;
        auto hit = materialize(reference);
        if (!hit) {
            return workspace_result_t<search_page_t>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "search index contains an invalid packed reference", phase));
        }
        page.hits.push_back(std::move(*hit));
    }
    page.next_offset = offset >= page.total ? page.total : offset + page.hits.size();
    page.truncated = page.next_offset < page.total;
    return workspace_result_t<search_page_t>::success(std::move(page));
}

constexpr std::uint32_t kSerializedSearchMagic = 0x58444953U;
constexpr std::uint64_t kSerializedSearchMaximumBytes = 8ULL << 30;

class search_blob_writer_t final {
public:
    search_blob_writer_t(const search_index_t::serialized_sink_t& sink,
                         const cancellation_token_t& cancel)
        : sink_(sink), cancel_(cancel) {}

    void u8(std::uint8_t value) { append(&value, sizeof(value)); }
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
    template <std::size_t Size>
    void fixed(const std::array<std::uint8_t, Size>& value) {
        append(value.data(), value.size());
    }
    void bytes(const void* data, std::size_t size) {
        u64(size);
        append(static_cast<const std::uint8_t*>(data), size);
    }
    bool failed() const noexcept { return error_.has_value(); }
    std::uint64_t size() const noexcept { return size_; }
    workspace_result_t<void> finish() {
        poll();
        if (error_)
            return workspace_result_t<void>::failure(*error_);
        return workspace_result_t<void>::success();
    }

private:
    void poll() {
        if (!error_ && cancel_.stop_requested())
            error_ = stop_error(cancel_, "search_index.serialize");
    }
    void append(const std::uint8_t* data, std::size_t size) {
        if (error_)
            return;
        if ((!data && size != 0) ||
            size > kSerializedSearchMaximumBytes - size_) {
            error_ = make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "serialized search index exceeds its bounded byte limit",
                "search_index.serialize");
            return;
        }
        for (std::size_t offset = 0; offset < size;) {
            poll();
            if (error_)
                return;
            const auto count = (std::min)(size - offset,
                                          static_cast<std::size_t>(64U << 10));
            try {
                auto written = sink_(data + offset, count);
                if (!written) {
                    error_ = written.error();
                    return;
                }
            } catch (const std::bad_alloc&) {
                error_ = make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "serialized search sink exhausted its memory budget",
                    "search_index.serialize");
                return;
            } catch (const std::exception& exception) {
                error_ = make_workspace_error(
                    workspace_error_code_t::persistence_failure,
                    std::string("serialized search sink failed: ") + exception.what(),
                    "search_index.serialize");
                return;
            } catch (...) {
                error_ = make_workspace_error(
                    workspace_error_code_t::persistence_failure,
                    "serialized search sink failed",
                    "search_index.serialize");
                return;
            }
            offset += count;
            size_ += count;
        }
    }

    const search_index_t::serialized_sink_t& sink_;
    const cancellation_token_t& cancel_;
    std::uint64_t size_ = 0;
    std::optional<workspace_error_t> error_;
};

class search_blob_reader_t final {
public:
    search_blob_reader_t(const std::vector<std::uint8_t>& input,
                         const cancellation_token_t& cancel)
        : input_(input), cancel_(cancel) {}

    std::uint8_t u8() {
        const auto* value = take(1);
        return value ? value[0] : 0;
    }
    std::uint32_t u32() {
        const auto* value = take(4);
        if (!value)
            return 0;
        std::uint32_t result = 0;
        for (unsigned shift = 0; shift < 32; shift += 8)
            result |= static_cast<std::uint32_t>(value[shift / 8]) << shift;
        return result;
    }
    std::uint64_t u64() {
        const auto* value = take(8);
        if (!value)
            return 0;
        std::uint64_t result = 0;
        for (unsigned shift = 0; shift < 64; shift += 8)
            result |= static_cast<std::uint64_t>(value[shift / 8]) << shift;
        return result;
    }
    template <std::size_t Size>
    std::array<std::uint8_t, Size> fixed() {
        std::array<std::uint8_t, Size> result{};
        const auto* value = take(Size);
        if (value)
            std::memcpy(result.data(), value, Size);
        return result;
    }
    std::vector<char> bytes(std::uint64_t maximum) {
        const auto size = u64();
        if (failed() || size > maximum || size > remaining() ||
            size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
            fail("serialized search byte range exceeds its bounded input");
            return {};
        }
        std::vector<char> result;
        result.resize(static_cast<std::size_t>(size));
        if (size != 0) {
            const auto* value = take(static_cast<std::size_t>(size));
            if (value)
                std::memcpy(result.data(), value, result.size());
        }
        return result;
    }
    std::size_t count(std::uint64_t maximum,
                      std::size_t minimum_bytes_per_record) {
        const auto value = u64();
        std::uint64_t minimum_bytes = 0;
        if (failed() || value > maximum ||
            !checked_mul_u64(value, minimum_bytes_per_record, minimum_bytes) ||
            minimum_bytes > remaining() ||
            value > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
            fail("serialized search record count exceeds its bounded input");
            return 0;
        }
        return static_cast<std::size_t>(value);
    }
    bool failed() const noexcept { return error_.has_value(); }
    void reject(std::string message) { fail(std::move(message)); }
    workspace_result_t<void> finish() {
        if (!error_ && cancel_.stop_requested())
            error_ = stop_error(cancel_, "search_index.restore");
        if (!error_ && offset_ != input_.size())
            fail("serialized search index contains trailing bytes");
        if (error_)
            return workspace_result_t<void>::failure(*error_);
        return workspace_result_t<void>::success();
    }

private:
    std::uint64_t remaining() const noexcept {
        return static_cast<std::uint64_t>(input_.size() - offset_);
    }
    const std::uint8_t* take(std::size_t size) {
        if (error_)
            return nullptr;
        if (cancel_.stop_requested()) {
            error_ = stop_error(cancel_, "search_index.restore");
            return nullptr;
        }
        if (size > input_.size() - offset_) {
            fail("serialized search index is truncated");
            return nullptr;
        }
        const auto* result = input_.data() + offset_;
        offset_ += size;
        return result;
    }
    void fail(std::string message) {
        if (!error_)
            error_ = make_workspace_error(workspace_error_code_t::integrity_failure,
                                          std::move(message),
                                          "search_index.restore");
    }

    const std::vector<std::uint8_t>& input_;
    const cancellation_token_t& cancel_;
    std::size_t offset_ = 0;
    std::optional<workspace_error_t> error_;
};

}

struct search_index_t::impl_t {
    std::shared_ptr<const analysis_snapshot_t> snapshot;
    std::weak_ptr<const analysis_snapshot_t> snapshot_owner;
    search_generation_identity_t identity;
    architecture_id_t architecture = architecture_id_t::unknown;
    architecture_mode_t architecture_mode = architecture_mode_t::unknown;
    std::array<std::uint64_t, 2> cursor_integrity_key{};
    std::vector<data_candidate_record_t> data_candidates;
    std::vector<switch_record_t> switches;
    std::vector<type_candidate_record_t> types;
    std::shared_ptr<analysis_metrics_t> metrics;
    search_index_limits_t limits;
    interned_string_pool_t strings;
    std::vector<packed_search_record_t> records;
    std::vector<packed_text_reference_t> text_references;
    std::vector<std::uint32_t> address_references;
    std::vector<std::uint32_t> entity_kind_references;
    std::vector<std::uint32_t> entity_id_references;
    std::vector<std::uint32_t> instruction_references;
    std::vector<packed_key32_reference_t> opcode_references;
    std::vector<packed_key64_reference_t> immediate_references;
    std::vector<packed_trigram_span_t> trigram_spans;
    std::vector<std::uint32_t> trigram_postings;
    search_index_size_t accounting;

    std::optional<search_record_view_t> view(std::uint32_t reference) const noexcept {
        if (reference >= records.size())
            return std::nullopt;
        const auto& record = records[reference];
        search_record_view_t result;
        result.kind = record.kind;
        result.entity_id = record.entity_id;
        result.address = unpack_address(record.address);
        result.numeric_value = record.numeric_value;
        result.auxiliary_flags = record.auxiliary_flags;
        if (record.text.valid()) {
            const auto text = strings.lookup(record.text);
            if (!text)
                return std::nullopt;
            result.text = *text;
        }
        return result;
    }

    std::optional<search_hit_t> hit(std::uint32_t reference) const {
        const auto record = view(reference);
        if (!record)
            return std::nullopt;
        search_hit_t result;
        result.kind = record->kind;
        result.entity_id = record->entity_id;
        result.address = record->address;
        if (record->text.empty())
            result.text.clear();
        else
            result.text.assign(record->text.data(), record->text.size());
        result.numeric_value = record->numeric_value;
        return result;
    }

    std::optional<std::uint32_t> instruction_reference(entity_id_t id) const noexcept {
        const auto first = std::lower_bound(entity_id_references.begin(),
            entity_id_references.end(), id,
            [&](std::uint32_t reference, entity_id_t value) {
                return records[reference].entity_id < value;
            });
        for (auto current = first; current != entity_id_references.end(); ++current) {
            const auto& record = records[*current];
            if (record.entity_id != id)
                break;
            if (record.kind == search_entity_kind_t::instruction)
                return *current;
        }
        return std::nullopt;
    }

    const packed_trigram_span_t* trigram(std::uint32_t key) const noexcept {
        const auto found = std::lower_bound(trigram_spans.begin(), trigram_spans.end(), key,
            [](const packed_trigram_span_t& span, std::uint32_t value) {
                return span.key < value;
            });
        return found != trigram_spans.end() && found->key == key ? &*found : nullptr;
    }
};

bool search_generation_identity_t::valid() const noexcept {
    return !binary_id.empty() && !load_profile_hash.empty() && generation != 0 &&
        analysis_revision != 0;
}

bool operator==(const search_generation_identity_t& lhs,
                const search_generation_identity_t& rhs) noexcept {
    return lhs.binary_id == rhs.binary_id && lhs.load_profile_hash == rhs.load_profile_hash &&
        lhs.provider_content_hash == rhs.provider_content_hash &&
        lhs.generation == rhs.generation &&
        lhs.analysis_revision == rhs.analysis_revision &&
        lhs.overlay_revision == rhs.overlay_revision && lhs.provider_size == rhs.provider_size;
}

bool operator!=(const search_generation_identity_t& lhs,
                const search_generation_identity_t& rhs) noexcept {
    return !(lhs == rhs);
}

search_generation_handle_t::search_generation_handle_t(
    search_generation_identity_t identity, std::shared_ptr<const search_index_t> index)
    : identity_(std::move(identity)), index_(std::move(index)) {}

bool search_generation_handle_t::valid() const noexcept {
    return index_ && identity_.valid() && index_->identity() == identity_;
}

search_generation_handle_t::operator bool() const noexcept {
    return valid();
}

const search_generation_identity_t& search_generation_handle_t::identity() const noexcept {
    return identity_;
}

const search_index_t* search_generation_handle_t::get() const noexcept {
    return valid() ? index_.get() : nullptr;
}

const std::shared_ptr<const search_index_t>&
search_generation_handle_t::shared_index() const noexcept {
    return index_;
}

search_index_t::search_index_t(std::unique_ptr<impl_t> impl) : impl_(std::move(impl)) {}
search_index_t::~search_index_t() = default;

workspace_result_t<std::shared_ptr<search_index_t>> search_index_t::build(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    std::vector<data_candidate_record_t> data_candidates,
    std::vector<switch_record_t> switches,
    std::vector<type_candidate_record_t> types,
    std::shared_ptr<analysis_metrics_t> metrics,
    const search_index_limits_t& limits,
    const cancellation_token_t& cancel) {
    try {
        if (!snapshot) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "search index requires an analysis snapshot", "search_index"));
        }
        if (snapshot->binary_id.empty() || snapshot->load_profile_hash.empty() ||
            snapshot->generation == 0 || snapshot->analysis_revision == 0 ||
            (!snapshot->normalized_image && !snapshot->image)) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "search index snapshot identity or revision is incomplete",
                    "search_index"));
        }
        if (limits.max_entries == 0 || limits.max_trigram_postings == 0 ||
            limits.max_indexed_text_bytes == 0 || limits.max_index_bytes == 0 ||
            limits.max_query_bytes == 0 || limits.max_query_bytes > 16U * 1024U * 1024U ||
            limits.max_results_per_query == 0 ||
            limits.max_results_per_query > (1U << 20) ||
            limits.cancellation_check_interval == 0 ||
            limits.max_entries > std::numeric_limits<std::uint32_t>::max() ||
            snapshot->instructions.size() > std::numeric_limits<std::uint32_t>::max()) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::invalid_argument,
                    "search index limits or compact instruction count are invalid",
                    "search_index"));
        }
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                stop_error(cancel, "search_index"));

        std::uint64_t prospective_entries = 0;
        const std::array<std::uint64_t, 6> entry_counts{
            snapshot->symbols.size(), snapshot->strings.size(), snapshot->instructions.size(),
            data_candidates.size(), switches.size(), types.size()};
        for (const auto count : entry_counts) {
            std::uint64_t updated = 0;
            if (!checked_add_u64(prospective_entries, count, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "search-index entry count overflows", "search_index"));
            }
            prospective_entries = updated;
        }
        if (prospective_entries > limits.max_entries ||
            prospective_entries > std::numeric_limits<std::uint32_t>::max()) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index entry count exceeds analysis budget", "search_index"));
        }
        std::uint64_t minimum_bytes = 0;
        if (!checked_mul_u64(prospective_entries,
                sizeof(packed_search_record_t) + sizeof(std::uint32_t) * 3ULL,
                minimum_bytes) || minimum_bytes > limits.max_index_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index base storage exceeds memory budget", "search_index"));
        }

        auto impl = std::make_unique<impl_t>();
        impl->snapshot = std::move(snapshot);
        impl->snapshot_owner = impl->snapshot;
        impl->identity = snapshot_identity(*impl->snapshot);
        if (impl->snapshot->normalized_image) {
            impl->architecture = impl->snapshot->normalized_image->architecture;
            impl->architecture_mode = impl->snapshot->normalized_image->architecture_mode;
        } else if (impl->snapshot->image) {
            impl->architecture = impl->snapshot->image->architecture();
            impl->architecture_mode = impl->snapshot->image->architecture_mode();
        }
#if defined(AIDA_IMGUI_STUDIO_PREVIEW)
        impl->cursor_integrity_key = {0xCBF29CE484222325ULL, 0x9E3779B97F4A7C15ULL};
        const auto mix_cursor_byte = [&impl](std::uint8_t value) {
            impl->cursor_integrity_key[0] ^= value;
            impl->cursor_integrity_key[0] *= 0x100000001B3ULL;
            impl->cursor_integrity_key[1] ^= impl->cursor_integrity_key[0] + value;
            impl->cursor_integrity_key[1] *= 0x9E3779B185EBCA87ULL;
        };
        for (const auto value : impl->identity.binary_id.bytes)
            mix_cursor_byte(value);
        for (const auto value : impl->identity.load_profile_hash.bytes)
            mix_cursor_byte(value);
        for (std::size_t shift = 0; shift < 64; shift += 8) {
            mix_cursor_byte(static_cast<std::uint8_t>(impl->identity.generation >> shift));
            mix_cursor_byte(static_cast<std::uint8_t>(impl->identity.analysis_revision >> shift));
            mix_cursor_byte(static_cast<std::uint8_t>(impl->identity.overlay_revision >> shift));
        }
        if (impl->cursor_integrity_key[0] == 0 && impl->cursor_integrity_key[1] == 0)
            impl->cursor_integrity_key[1] = 1;
#else
        const auto random_status = BCryptGenRandom(nullptr,
            reinterpret_cast<PUCHAR>(impl->cursor_integrity_key.data()),
            static_cast<ULONG>(sizeof(impl->cursor_integrity_key)),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(random_status) ||
            (impl->cursor_integrity_key[0] == 0 && impl->cursor_integrity_key[1] == 0)) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "search cursor integrity entropy is unavailable", "search_index"));
        }
#endif
        impl->data_candidates = std::move(data_candidates);
        impl->switches = std::move(switches);
        impl->types = std::move(types);
        impl->metrics = std::move(metrics);
        impl->limits = limits;
        impl->records.reserve(static_cast<std::size_t>(prospective_entries));

        const std::uint32_t worker_count = parallel_worker_count();

        struct record_task_t {
            std::uint32_t class_index = 0;
            std::size_t begin = 0;
            std::size_t end = 0;
            std::size_t stream_begin = 0;
            std::vector<packed_search_record_t> records;
            interned_string_builder_t strings;
            std::vector<std::uint32_t> local_to_global;
            std::uint64_t indexed_text_bytes = 0;
            std::uint64_t source_text_bytes = 0;
        };

        const std::array<std::size_t, 6> class_sizes{
            impl->snapshot->symbols.size(), impl->snapshot->strings.size(),
            impl->types.size(), impl->snapshot->instructions.size(),
            impl->data_candidates.size(), impl->switches.size()};
        std::vector<record_task_t> tasks;
        {
            std::size_t stream_cursor = 0;
            for (std::size_t class_index = 0; class_index < class_sizes.size(); ++class_index) {
                const auto shards = parallel_shards(class_sizes[class_index], worker_count);
                for (const auto& shard : shards) {
                    record_task_t task;
                    task.class_index = static_cast<std::uint32_t>(class_index);
                    task.begin = shard.begin;
                    task.end = shard.end;
                    task.stream_begin = stream_cursor;
                    stream_cursor += shard.end - shard.begin;
                    tasks.push_back(std::move(task));
                }
            }
        }

        const auto run_record_task = [&](record_task_t& task) -> workspace_result_t<void> {
            task.records.reserve(task.end - task.begin);
            std::uint64_t cancellation_checks = 0;
            for (std::size_t index = task.begin; index < task.end; ++index) {
                if (++cancellation_checks >= limits.cancellation_check_interval) {
                    cancellation_checks = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<void>::failure(
                            stop_error(cancel, "search_index"));
                }
                search_entity_kind_t kind = search_entity_kind_t::symbol;
                entity_id_t entity_id = 0;
                address_t address;
                std::uint64_t numeric_value = 0;
                std::uint32_t auxiliary_flags = 0;
                std::string_view text;
                switch (task.class_index) {
                case 0: {
                    const auto& symbol = impl->snapshot->symbols[index];
                    kind = symbol.kind == symbol_kind_t::function
                        ? search_entity_kind_t::function : search_entity_kind_t::symbol;
                    entity_id = symbol.id;
                    address = symbol.address;
                    text = symbol.name;
                    break;
                }
                case 1: {
                    const auto& string = impl->snapshot->strings[index];
                    kind = search_entity_kind_t::string;
                    entity_id = string.id;
                    address = string.address;
                    numeric_value = string.byte_length;
                    auxiliary_flags = static_cast<std::uint32_t>(string.encoding);
                    text = string.value;
                    break;
                }
                case 2: {
                    const auto& type = impl->types[index];
                    kind = search_entity_kind_t::type_candidate;
                    entity_id = type.id;
                    address = type.address;
                    auxiliary_flags = static_cast<std::uint32_t>(type.kind);
                    text = type.display_name.empty()
                        ? std::string_view(type.canonical_type)
                        : std::string_view(type.display_name);
                    break;
                }
                case 3: {
                    const auto& instruction = impl->snapshot->instructions[index];
                    kind = search_entity_kind_t::instruction;
                    entity_id = instruction.id;
                    address = instruction.address;
                    numeric_value = instruction.opcode_id;
                    auxiliary_flags = instruction.flow_flags;
                    break;
                }
                case 4: {
                    const auto& data = impl->data_candidates[index];
                    kind = search_entity_kind_t::data_candidate;
                    entity_id = data.id;
                    address = data.address;
                    numeric_value = data.size;
                    auxiliary_flags = static_cast<std::uint32_t>(data.kind);
                    break;
                }
                default: {
                    const auto& dispatch = impl->switches[index];
                    kind = search_entity_kind_t::switch_dispatch;
                    entity_id = dispatch.id;
                    address = dispatch.dispatch;
                    numeric_value = dispatch.case_targets.size();
                    auxiliary_flags = dispatch.entry_size;
                    break;
                }
                }
                if (entity_id == 0) {
                    return workspace_result_t<void>::failure(
                        make_workspace_error(workspace_error_code_t::integrity_failure,
                            "search-index entity has no stable identifier", "search_index"));
                }
                packed_search_record_t record;
                record.kind = kind;
                record.entity_id = entity_id;
                record.address = pack_address(address);
                record.numeric_value = numeric_value;
                record.auxiliary_flags = auxiliary_flags;
                if (!text.empty()) {
                    const auto normalized = normalize_text(text);
                    std::uint64_t referenced = text.size();
                    if (!normalized.empty() &&
                        !checked_add_u64(referenced, normalized.size(), referenced)) {
                        return workspace_result_t<void>::failure(
                            make_workspace_error(workspace_error_code_t::range_overflow,
                                "search-index text accounting overflows", "search_index"));
                    }
                    std::uint64_t updated = 0;
                    if (!checked_add_u64(task.indexed_text_bytes, referenced, updated) ||
                        updated > limits.max_indexed_text_bytes ||
                        updated > limits.max_index_bytes) {
                        return workspace_result_t<void>::failure(
                            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                "search-index text budget exceeded", "search_index"));
                    }
                    task.indexed_text_bytes = updated;
                    if (!checked_add_u64(task.source_text_bytes, text.size(), updated)) {
                        return workspace_result_t<void>::failure(
                            make_workspace_error(workspace_error_code_t::range_overflow,
                                "search-index source text accounting overflows", "search_index"));
                    }
                    task.source_text_bytes = updated;
                    auto display_id = task.strings.intern(text);
                    if (!display_id)
                        return workspace_result_t<void>::failure(display_id.error());
                    record.text = display_id.take_value();
                    if (!normalized.empty()) {
                        auto normalized_id = task.strings.intern(normalized);
                        if (!normalized_id)
                            return workspace_result_t<void>::failure(normalized_id.error());
                        record.normalized_text = normalized_id.take_value();
                    }
                }
                task.records.push_back(record);
            }
            return workspace_result_t<void>::success();
        };

        const auto task_shards = parallel_shards(tasks.size(), worker_count);
        auto packed = parallel_run_shards(task_shards,
            [&](std::size_t, const parallel_shard_t& shard) {
                for (std::size_t task_index = shard.begin; task_index < shard.end; ++task_index) {
                    auto result = run_record_task(tasks[task_index]);
                    if (!result)
                        return result;
                }
                return workspace_result_t<void>::success();
            }, cancel);
        if (!packed)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(packed.error());

        std::uint64_t indexed_text_bytes = 0;
        std::uint64_t source_text_bytes = 0;
        for (const auto& task : tasks) {
            std::uint64_t updated = 0;
            if (!checked_add_u64(indexed_text_bytes, task.indexed_text_bytes, updated) ||
                updated > limits.max_indexed_text_bytes ||
                updated > limits.max_index_bytes) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "search-index text budget exceeded", "search_index"));
            }
            indexed_text_bytes = updated;
            if (!checked_add_u64(source_text_bytes, task.source_text_bytes, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "search-index source text accounting overflows", "search_index"));
            }
            source_text_bytes = updated;
        }
        impl->accounting.source_text_bytes = source_text_bytes;
        impl->accounting.referenced_text_bytes = indexed_text_bytes;

        std::vector<std::string> global_values;
        {
            std::unordered_map<std::string, packed_string_id_t> global_index;
            std::uint64_t merge_checks = 0;
            for (auto& task : tasks) {
                const auto& local_values = task.strings.values();
                task.local_to_global.reserve(local_values.size());
                for (const auto& value : local_values) {
                    if (++merge_checks >= limits.cancellation_check_interval) {
                        merge_checks = 0;
                        if (cancel.stop_requested()) {
                            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                                stop_error(cancel, "search_index"));
                        }
                    }
                    const auto found = global_index.find(value);
                    if (found != global_index.end()) {
                        task.local_to_global.push_back(found->second.value);
                        continue;
                    }
                    if (global_values.size() >= std::numeric_limits<std::uint32_t>::max()) {
                        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                "search-index string pool exceeds packed identifier limits",
                                "search_index"));
                    }
                    const auto global_id = static_cast<std::uint32_t>(global_values.size() + 1U);
                    global_values.push_back(value);
                    global_index.emplace(global_values.back(), packed_string_id_t{global_id});
                    task.local_to_global.push_back(global_id);
                }
            }
        }

        auto frozen = freeze_string_values(global_values);
        if (!frozen)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(frozen.error());
        impl->strings = frozen.take_value();
        global_values = std::vector<std::string>{};
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                stop_error(cancel, "search_index"));

        impl->records.resize(static_cast<std::size_t>(prospective_entries));
        auto remapped = parallel_run_shards(task_shards,
            [&](std::size_t, const parallel_shard_t& shard) {
                for (std::size_t task_index = shard.begin; task_index < shard.end; ++task_index) {
                    auto& task = tasks[task_index];
                    for (auto& record : task.records) {
                        if (record.text.valid())
                            record.text.value = task.local_to_global[record.text.value - 1U];
                        if (record.normalized_text.valid()) {
                            record.normalized_text.value =
                                task.local_to_global[record.normalized_text.value - 1U];
                        }
                    }
                    std::move(task.records.begin(), task.records.end(),
                        impl->records.begin() + static_cast<std::ptrdiff_t>(task.stream_begin));
                    task.records = std::vector<packed_search_record_t>{};
                }
                return workspace_result_t<void>::success();
            }, cancel);
        if (!remapped)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(remapped.error());
        tasks.clear();
        tasks.shrink_to_fit();
        if (impl->records.size() != prospective_entries) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "search-index record count diverged during packing", "search_index"));
        }

        parallel_sort(impl->records.begin(), impl->records.end(), record_less, worker_count);

        impl->text_references.reserve(class_sizes[0] + class_sizes[1] + class_sizes[2]);
        impl->address_references.reserve(impl->records.size());
        impl->entity_kind_references.reserve(impl->records.size());
        impl->entity_id_references.reserve(impl->records.size());
        impl->instruction_references.reserve(impl->snapshot->instructions.size());
        impl->opcode_references.reserve(impl->snapshot->instructions.size());
        struct reference_slot_t {
            std::vector<std::uint32_t> address;
            std::vector<std::uint32_t> entity_kind;
            std::vector<std::uint32_t> entity_id;
            std::vector<std::uint32_t> instruction;
            std::vector<packed_key32_reference_t> opcode;
            std::vector<packed_text_reference_t> text;
        };
        const auto record_shards = parallel_shards(impl->records.size(), worker_count);
        std::vector<reference_slot_t> reference_slots(record_shards.size());
        auto emitted = parallel_run_shards(record_shards,
            [&](std::size_t shard_index, const parallel_shard_t& shard) {
                auto& slot = reference_slots[shard_index];
                std::uint64_t checks = 0;
                for (std::size_t index = shard.begin; index < shard.end; ++index) {
                    if (++checks >= limits.cancellation_check_interval) {
                        checks = 0;
                        if (cancel.stop_requested())
                            return workspace_result_t<void>::failure(
                                stop_error(cancel, "search_index"));
                    }
                    const auto reference = static_cast<std::uint32_t>(index);
                    const auto& record = impl->records[index];
                    slot.address.push_back(reference);
                    slot.entity_kind.push_back(reference);
                    slot.entity_id.push_back(reference);
                    if (record.normalized_text.valid())
                        slot.text.push_back(
                            packed_text_reference_t{reference, record.normalized_text});
                    if (record.kind == search_entity_kind_t::instruction) {
                        slot.instruction.push_back(reference);
                        slot.opcode.push_back(packed_key32_reference_t{
                            static_cast<std::uint32_t>(record.numeric_value), reference});
                    }
                }
                return workspace_result_t<void>::success();
            }, cancel);
        if (!emitted)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(emitted.error());
        for (auto& slot : reference_slots) {
            impl->address_references.insert(impl->address_references.end(),
                slot.address.begin(), slot.address.end());
            impl->entity_kind_references.insert(impl->entity_kind_references.end(),
                slot.entity_kind.begin(), slot.entity_kind.end());
            impl->entity_id_references.insert(impl->entity_id_references.end(),
                slot.entity_id.begin(), slot.entity_id.end());
            impl->instruction_references.insert(impl->instruction_references.end(),
                slot.instruction.begin(), slot.instruction.end());
            impl->opcode_references.insert(impl->opcode_references.end(),
                std::make_move_iterator(slot.opcode.begin()),
                std::make_move_iterator(slot.opcode.end()));
            impl->text_references.insert(impl->text_references.end(),
                std::make_move_iterator(slot.text.begin()),
                std::make_move_iterator(slot.text.end()));
        }
        reference_slots.clear();
        reference_slots.shrink_to_fit();
        std::sort(impl->address_references.begin(), impl->address_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                return record_less(impl->records[lhs], impl->records[rhs]);
            });
        parallel_sort(impl->entity_kind_references.begin(),
            impl->entity_kind_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                if (left.kind != right.kind)
                    return left.kind < right.kind;
                if (left.entity_id != right.entity_id)
                    return left.entity_id < right.entity_id;
                return lhs < rhs;
            }, worker_count);
        if (impl->entity_kind_references.size() >= 2) {
            const auto pair_shards = parallel_shards(
                impl->entity_kind_references.size() - 1U, worker_count);
            auto checked = parallel_validate_shards(pair_shards, 1,
                [&](std::size_t, const parallel_shard_t& shard) {
                    ordered_error_t result;
                    for (std::size_t pair = shard.begin; pair < shard.end; ++pair) {
                        const auto& previous =
                            impl->records[impl->entity_kind_references[pair]];
                        const auto& current =
                            impl->records[impl->entity_kind_references[pair + 1U]];
                        if (previous.kind == current.kind &&
                            previous.entity_id == current.entity_id) {
                            result.ordinal = pair;
                            result.error = make_workspace_error(
                                workspace_error_code_t::integrity_failure,
                                "search-index contains a duplicate final entity",
                                "search_index");
                            return result;
                        }
                    }
                    return result;
                }, cancel);
            if (!checked)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    checked.error());
        }
        parallel_sort(impl->entity_id_references.begin(),
            impl->entity_id_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                if (left.entity_id != right.entity_id)
                    return left.entity_id < right.entity_id;
                if (left.kind != right.kind)
                    return left.kind < right.kind;
                return lhs < rhs;
            }, worker_count);
        parallel_sort(impl->opcode_references.begin(), impl->opcode_references.end(),
            [](const packed_key32_reference_t& lhs, const packed_key32_reference_t& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.record < rhs.record;
            }, worker_count);

        impl->immediate_references.reserve(impl->snapshot->operand_facts.size());
        const auto operand_shards = parallel_shards(
            impl->snapshot->operand_facts.size(), worker_count);
        std::vector<std::vector<packed_key64_reference_t>> immediate_slots(
            operand_shards.size());
        auto immediates = parallel_run_shards(operand_shards,
            [&](std::size_t shard_index, const parallel_shard_t& shard) {
                std::uint64_t checks = 0;
                for (std::size_t index = shard.begin; index < shard.end; ++index) {
                    if (++checks >= limits.cancellation_check_interval) {
                        checks = 0;
                        if (cancel.stop_requested())
                            return workspace_result_t<void>::failure(
                                stop_error(cancel, "search_index"));
                    }
                    const auto& operand = impl->snapshot->operand_facts[index];
                    if (operand.kind != operand_kind_t::immediate)
                        continue;
                    const auto reference = impl->instruction_reference(operand.instruction_id);
                    if (!reference) {
                        return workspace_result_t<void>::failure(
                            make_workspace_error(workspace_error_code_t::integrity_failure,
                                "search-index immediate references an unknown instruction",
                                "search_index"));
                    }
                    immediate_slots[shard_index].push_back(
                        packed_key64_reference_t{operand.immediate, *reference});
                }
                return workspace_result_t<void>::success();
            }, cancel);
        if (!immediates)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                immediates.error());
        for (auto& slot : immediate_slots) {
            impl->immediate_references.insert(impl->immediate_references.end(),
                std::make_move_iterator(slot.begin()), std::make_move_iterator(slot.end()));
        }
        immediate_slots.clear();
        immediate_slots.shrink_to_fit();
        parallel_sort(impl->immediate_references.begin(), impl->immediate_references.end(),
            [](const packed_key64_reference_t& lhs, const packed_key64_reference_t& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.record < rhs.record;
            }, worker_count);
        if (!impl->immediate_references.empty()) {
            const auto equal = [](const packed_key64_reference_t& lhs,
                                  const packed_key64_reference_t& rhs) noexcept {
                return lhs.key == rhs.key && lhs.record == rhs.record;
            };
            auto unique_shards = parallel_shards(
                impl->immediate_references.size(), worker_count);
            for (auto& shard : unique_shards) {
                while (shard.begin < shard.end && shard.begin != 0 &&
                       equal(impl->immediate_references[shard.begin - 1U],
                             impl->immediate_references[shard.begin]))
                    ++shard.begin;
            }
            std::vector<std::vector<packed_key64_reference_t>> unique_slots(
                unique_shards.size());
            auto uniqued = parallel_run_shards(unique_shards,
                [&](std::size_t shard_index, const parallel_shard_t& shard) {
                    auto& output = unique_slots[shard_index];
                    output.reserve(shard.end - shard.begin);
                    for (std::size_t index = shard.begin; index < shard.end; ++index) {
                        if (index == shard.begin ||
                            !equal(impl->immediate_references[index - 1U],
                                   impl->immediate_references[index]))
                            output.push_back(impl->immediate_references[index]);
                    }
                    return workspace_result_t<void>::success();
                }, cancel);
            if (!uniqued)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    uniqued.error());
            const auto compaction_shards = parallel_shards(unique_slots.size(), worker_count);
            auto compacted = parallel_run_shards(compaction_shards,
                [&](std::size_t, const parallel_shard_t& shard) {
                    std::size_t position = 0;
                    for (std::size_t slot_index = 0; slot_index < shard.begin; ++slot_index)
                        position += unique_slots[slot_index].size();
                    for (std::size_t slot_index = shard.begin; slot_index < shard.end;
                         ++slot_index) {
                        auto& slot = unique_slots[slot_index];
                        std::move(slot.begin(), slot.end(),
                            impl->immediate_references.begin() +
                                static_cast<std::ptrdiff_t>(position));
                        position += slot.size();
                    }
                    return workspace_result_t<void>::success();
                }, cancel);
            if (!compacted)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    compacted.error());
            std::size_t unique_total = 0;
            for (const auto& slot : unique_slots)
                unique_total += slot.size();
            impl->immediate_references.resize(unique_total);
            unique_slots.clear();
            unique_slots.shrink_to_fit();
        }

        std::vector<std::uint32_t> normalized_ids;
        normalized_ids.reserve(impl->text_references.size());
        for (const auto& reference : impl->text_references)
            normalized_ids.push_back(reference.normalized.value);
        parallel_sort(normalized_ids.begin(), normalized_ids.end(),
            [](std::uint32_t lhs, std::uint32_t rhs) { return lhs < rhs; }, worker_count);
        normalized_ids.erase(std::unique(normalized_ids.begin(), normalized_ids.end()),
            normalized_ids.end());
        parallel_sort(normalized_ids.begin(), normalized_ids.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto left = impl->strings.lookup(packed_string_id_t{lhs})
                    .value_or(std::string_view{});
                const auto right = impl->strings.lookup(packed_string_id_t{rhs})
                    .value_or(std::string_view{});
                return left < right;
            }, worker_count);
        std::vector<std::uint32_t> normalized_ranks(impl->strings.offsets.size() + 1U, 0U);
        const auto rank_shards = parallel_shards(normalized_ids.size(), worker_count);
        auto ranked = parallel_run_shards(rank_shards,
            [&](std::size_t, const parallel_shard_t& shard) {
                for (std::size_t index = shard.begin; index < shard.end; ++index)
                    normalized_ranks[normalized_ids[index]] =
                        static_cast<std::uint32_t>(index);
                return workspace_result_t<void>::success();
            }, cancel);
        if (!ranked)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(ranked.error());
        normalized_ids.clear();
        normalized_ids.shrink_to_fit();
        parallel_sort(impl->text_references.begin(), impl->text_references.end(),
            [&](const packed_text_reference_t& lhs, const packed_text_reference_t& rhs) {
                const auto left_rank = normalized_ranks[lhs.normalized.value];
                const auto right_rank = normalized_ranks[rhs.normalized.value];
                if (left_rank != right_rank)
                    return left_rank < right_rank;
                return record_less(impl->records[lhs.record], impl->records[rhs.record]);
            }, worker_count);
        normalized_ranks.clear();
        normalized_ranks.shrink_to_fit();

        const auto text_shards = parallel_shards(impl->text_references.size(), worker_count);
        std::vector<std::vector<std::pair<std::uint32_t, std::uint32_t>>> trigram_runs(
            text_shards.size());
        auto generated = parallel_run_shards(text_shards,
            [&](std::size_t shard_index, const parallel_shard_t& shard) {
                auto& pairs = trigram_runs[shard_index];
                std::uint64_t checks = 0;
                for (std::size_t text_index = shard.begin; text_index < shard.end;
                     ++text_index) {
                    if (++checks >= limits.cancellation_check_interval) {
                        checks = 0;
                        if (cancel.stop_requested())
                            return workspace_result_t<void>::failure(
                                stop_error(cancel, "search_index"));
                    }
                    const auto text = impl->strings.lookup(
                        impl->text_references[text_index].normalized);
                    if (!text) {
                        return workspace_result_t<void>::failure(
                            make_workspace_error(workspace_error_code_t::integrity_failure,
                                "search-index text reference is invalid", "search_index"));
                    }
                    std::vector<std::uint32_t> keys;
                    if (text->size() >= 3)
                        keys.reserve(text->size() - 2U);
                    for (std::size_t offset = 0; offset + 3U <= text->size(); ++offset) {
                        if ((offset & 0x3ffU) == 0 && cancel.stop_requested())
                            return workspace_result_t<void>::failure(
                                stop_error(cancel, "search_index"));
                        keys.push_back(trigram_key(text->data() + offset));
                    }
                    std::sort(keys.begin(), keys.end());
                    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
                    if (pairs.size() > limits.max_trigram_postings ||
                        keys.size() > limits.max_trigram_postings - pairs.size()) {
                        return workspace_result_t<void>::failure(
                            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                "search-index posting budget exceeded", "search_index"));
                    }
                    for (const auto key : keys) {
                        pairs.emplace_back(key,
                            static_cast<std::uint32_t>(text_index));
                    }
                }
                std::sort(pairs.begin(), pairs.end());
                return workspace_result_t<void>::success();
            }, cancel);
        if (!generated)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                generated.error());

        std::uint64_t total_pairs = 0;
        for (const auto& run : trigram_runs) {
            std::uint64_t updated = 0;
            if (!checked_add_u64(total_pairs, run.size(), updated) ||
                updated > limits.max_trigram_postings) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "search-index posting budget exceeded", "search_index"));
            }
            total_pairs = updated;
        }
        impl->trigram_postings.reserve(static_cast<std::size_t>(total_pairs));
        impl->trigram_spans.reserve(static_cast<std::size_t>(total_pairs));
        if (total_pairs != 0) {
            const std::size_t run_count = trigram_runs.size();
            const auto exhausted = std::numeric_limits<std::size_t>::max();
            std::vector<std::size_t> cursors(run_count, 0);
            const auto run_greater = [&](std::size_t lhs, std::size_t rhs) {
                const bool lhs_done = cursors[lhs] >= trigram_runs[lhs].size();
                const bool rhs_done = cursors[rhs] >= trigram_runs[rhs].size();
                if (lhs_done != rhs_done)
                    return lhs_done;
                if (lhs_done)
                    return lhs > rhs;
                return trigram_runs[rhs][cursors[rhs]] <
                    trigram_runs[lhs][cursors[lhs]];
            };
            std::vector<std::size_t> loser(run_count, exhausted);
            const auto adjust = [&](std::size_t seed) {
                std::size_t node = (seed + run_count) / 2U;
                while (node >= 1U) {
                    if (loser[node] == exhausted || run_greater(loser[node], seed))
                        std::swap(loser[node], seed);
                    node /= 2U;
                }
                loser[0] = seed;
            };
            for (std::size_t seed = run_count; seed-- > 0;)
                adjust(seed);
            std::uint64_t merge_checks = 0;
            std::uint64_t emitted_count = 0;
            std::uint32_t span_key = 0;
            std::uint32_t span_begin = 0;
            bool span_open = false;
            while (emitted_count < total_pairs) {
                if (++merge_checks >= limits.cancellation_check_interval) {
                    merge_checks = 0;
                    if (cancel.stop_requested())
                        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                            stop_error(cancel, "search_index"));
                }
                const auto winner = loser[0];
                const auto pair = trigram_runs[winner][cursors[winner]];
                if (!span_open || pair.first != span_key) {
                    if (span_open) {
                        impl->trigram_spans.push_back(packed_trigram_span_t{span_key,
                            span_begin, static_cast<std::uint32_t>(
                                impl->trigram_postings.size() - span_begin)});
                    }
                    span_key = pair.first;
                    span_begin = static_cast<std::uint32_t>(impl->trigram_postings.size());
                    span_open = true;
                }
                impl->trigram_postings.push_back(pair.second);
                ++cursors[winner];
                adjust(winner);
                ++emitted_count;
            }
            if (span_open) {
                impl->trigram_spans.push_back(packed_trigram_span_t{span_key, span_begin,
                    static_cast<std::uint32_t>(impl->trigram_postings.size() - span_begin)});
            }
        }
        trigram_runs.clear();
        trigram_runs.shrink_to_fit();
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                stop_error(cancel, "search_index"));

        auto& accounting = impl->accounting;
        accounting.record_count = impl->records.size();
        accounting.text_reference_count = impl->text_references.size();
        accounting.address_reference_count = impl->address_references.size();
        accounting.entity_reference_count = impl->entity_kind_references.size();
        accounting.trigram_count = impl->trigram_spans.size();
        accounting.trigram_posting_count = impl->trigram_postings.size();
        accounting.string_count = impl->strings.offsets.size();
        accounting.unique_text_bytes = impl->strings.bytes.size();
        std::uint64_t memory_bytes = sizeof(impl_t);
        const std::array<std::uint64_t, 16> allocations{
            vector_bytes(impl->strings.offsets.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->strings.lengths.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->strings.bytes.capacity(), sizeof(char)),
            vector_bytes(impl->records.capacity(), sizeof(packed_search_record_t)),
            vector_bytes(impl->text_references.capacity(), sizeof(packed_text_reference_t)),
            vector_bytes(impl->address_references.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->entity_kind_references.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->entity_id_references.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->instruction_references.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->opcode_references.capacity(), sizeof(packed_key32_reference_t)),
            vector_bytes(impl->immediate_references.capacity(), sizeof(packed_key64_reference_t)),
            vector_bytes(impl->trigram_spans.capacity(), sizeof(packed_trigram_span_t)),
            vector_bytes(impl->trigram_postings.capacity(), sizeof(std::uint32_t)),
            vector_bytes(impl->data_candidates.capacity(), sizeof(data_candidate_record_t)),
            vector_bytes(impl->switches.capacity(), sizeof(switch_record_t)),
            vector_bytes(impl->types.capacity(), sizeof(type_candidate_record_t))};
        for (const auto allocation : allocations) {
            std::uint64_t updated = 0;
            if (allocation == std::numeric_limits<std::uint64_t>::max() ||
                !checked_add_u64(memory_bytes, allocation, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "search-index memory accounting overflows", "search_index"));
            }
            memory_bytes = updated;
        }
        for (const auto& dispatch : impl->switches) {
            std::uint64_t updated = 0;
            const auto bytes = vector_bytes(dispatch.case_targets.capacity(), sizeof(address_t));
            if (bytes == std::numeric_limits<std::uint64_t>::max() ||
                !checked_add_u64(memory_bytes, bytes, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "search-index switch accounting overflows", "search_index"));
            }
            memory_bytes = updated;
        }
        for (const auto& type : impl->types) {
            std::uint64_t updated = 0;
            const auto bytes = static_cast<std::uint64_t>(type.display_name.capacity()) +
                static_cast<std::uint64_t>(type.canonical_type.capacity());
            if (!checked_add_u64(memory_bytes, bytes, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::range_overflow,
                        "search-index type accounting overflows", "search_index"));
            }
            memory_bytes = updated;
        }
        if (memory_bytes > limits.max_index_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index memory budget exceeded", "search_index"));
        }
        accounting.memory_bytes = memory_bytes;
        if (impl->metrics) {
            impl->metrics->set(analysis_metric_t::indexed_bytes, memory_bytes);
            impl->metrics->add(analysis_metric_t::index_entries, accounting.record_count);
            impl->metrics->add(analysis_metric_t::index_trigram_postings,
                               accounting.trigram_posting_count);
            impl->metrics->add(analysis_metric_t::index_text_bytes,
                               accounting.source_text_bytes);
        }
        impl->snapshot.reset();
        return workspace_result_t<std::shared_ptr<search_index_t>>::success(
            std::shared_ptr<search_index_t>(new search_index_t(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "search-index allocation exceeded available memory", "search_index"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "search-index allocation exceeds container limits", "search_index"));
    } catch (const std::system_error&) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "search-index allocation exceeded available memory", "search_index"));
    }
}

workspace_result_t<std::uint64_t> search_index_t::serialized_size(
    const cancellation_token_t& cancel) const {
    std::uint64_t total = 0;
    const serialized_sink_t sink = [&](const std::uint8_t*, std::size_t size) {
        std::uint64_t updated = 0;
        if (!checked_add_u64(total, size, updated) ||
            updated > kSerializedSearchMaximumBytes) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                                     "serialized search index size exceeds its budget",
                                     "search_index.serialize"));
        }
        total = updated;
        return workspace_result_t<void>::success();
    };
    auto serialized = serialize_to(sink, cancel);
    if (!serialized)
        return workspace_result_t<std::uint64_t>::failure(serialized.error());
    return workspace_result_t<std::uint64_t>::success(total);
}

workspace_result_t<std::shared_ptr<search_index_t>> search_index_t::restore(
    std::shared_ptr<const analysis_snapshot_t> snapshot,
    std::vector<data_candidate_record_t> data_candidates,
    std::vector<switch_record_t> switches,
    std::vector<type_candidate_record_t> types,
    std::shared_ptr<analysis_metrics_t> metrics,
    const search_index_limits_t& limits,
    const std::vector<std::uint8_t>& serialized,
    const cancellation_token_t& cancel) {
    try {
        if (!snapshot || serialized.empty() ||
            static_cast<std::uint64_t>(serialized.size()) > kSerializedSearchMaximumBytes ||
            serialized.size() > limits.max_index_bytes ||
            (!snapshot->normalized_image && !snapshot->image) ||
            limits.max_entries == 0 ||
            limits.max_entries > std::numeric_limits<std::uint32_t>::max() ||
            limits.max_trigram_postings == 0 ||
            limits.max_indexed_text_bytes == 0 ||
            limits.max_index_bytes == 0 ||
            limits.max_query_bytes == 0 ||
            limits.max_query_bytes > 16U * 1024U * 1024U ||
            limits.max_results_per_query == 0 ||
            limits.max_results_per_query > (1U << 20) ||
            limits.cancellation_check_interval == 0 ||
            cancel.stop_requested()) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                cancel.stop_requested()
                    ? stop_error(cancel, "search_index.restore")
                    : make_workspace_error(workspace_error_code_t::invalid_argument,
                                           "serialized search restore input is invalid",
                                           "search_index.restore"));
        }
        constexpr std::size_t serialized_accounting_bytes = 11U * sizeof(std::uint64_t);
        const auto serialized_resident_bytes = vector_bytes(
            serialized.capacity(), sizeof(std::uint8_t));
        if (serialized.size() < serialized_accounting_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "serialized search accounting is truncated",
                                     "search_index.restore"));
        }
        const auto read_tail_u64 = [&](std::size_t offset) {
            std::uint64_t value = 0;
            for (unsigned shift = 0; shift < 64; shift += 8) {
                value |= static_cast<std::uint64_t>(serialized[offset + shift / 8])
                    << shift;
            }
            return value;
        };
        const auto declared_memory_bytes = read_tail_u64(
            serialized.size() - serialized_accounting_bytes);
        if (serialized_resident_bytes ==
                (std::numeric_limits<std::uint64_t>::max)() ||
            declared_memory_bytes == 0 ||
            declared_memory_bytes > limits.max_index_bytes ||
            serialized_resident_bytes >
                limits.max_index_bytes - declared_memory_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "serialized search restore exceeds its combined resident-memory budget",
                    "search_index.restore"));
        }
        search_blob_reader_t reader(serialized, cancel);
        if (reader.u32() != kSerializedSearchMagic ||
            reader.u32() != serialized_version) {
            reader.reject("serialized search header is invalid");
        }
        auto impl = std::make_unique<impl_t>();
        impl->identity.binary_id.bytes = reader.fixed<32>();
        impl->identity.load_profile_hash.bytes = reader.fixed<32>();
        const auto has_provider_hash = reader.u8();
        const auto provider_hash = reader.fixed<32>();
        if (has_provider_hash > 1U)
            reader.reject("serialized provider-hash marker is invalid");
        if (has_provider_hash != 0) {
            sha256_digest_t digest;
            digest.bytes = provider_hash;
            impl->identity.provider_content_hash = digest;
        } else if (std::any_of(provider_hash.begin(), provider_hash.end(),
                               [](std::uint8_t value) { return value != 0; })) {
            reader.reject("serialized absent provider hash is not canonical");
        }
        impl->identity.generation = reader.u64();
        impl->identity.analysis_revision = reader.u64();
        impl->identity.overlay_revision = reader.u64();
        impl->identity.provider_size = reader.u64();
        impl->architecture = static_cast<architecture_id_t>(reader.u8());
        impl->architecture_mode = static_cast<architecture_mode_t>(reader.u8());
        impl->cursor_integrity_key[0] = reader.u64();
        impl->cursor_integrity_key[1] = reader.u64();
        impl->limits.max_entries = reader.u64();
        impl->limits.max_trigram_postings = reader.u64();
        impl->limits.max_indexed_text_bytes = reader.u64();
        impl->limits.max_index_bytes = reader.u64();
        impl->limits.max_query_bytes = reader.u32();
        impl->limits.max_results_per_query = reader.u32();
        impl->limits.cancellation_check_interval = reader.u32();
        const auto expected_identity = snapshot_identity(*snapshot);
        const auto expected_architecture = snapshot->normalized_image
            ? snapshot->normalized_image->architecture
            : snapshot->image->architecture();
        const auto expected_architecture_mode = snapshot->normalized_image
            ? snapshot->normalized_image->architecture_mode
            : snapshot->image->architecture_mode();
        if (impl->identity != expected_identity ||
            !impl->identity.valid() ||
            impl->architecture != expected_architecture ||
            impl->architecture_mode != expected_architecture_mode ||
            (impl->cursor_integrity_key[0] == 0 &&
             impl->cursor_integrity_key[1] == 0) ||
            impl->limits.max_entries == 0 ||
            impl->limits.max_entries > limits.max_entries ||
            impl->limits.max_trigram_postings == 0 ||
            impl->limits.max_trigram_postings > limits.max_trigram_postings ||
            impl->limits.max_indexed_text_bytes == 0 ||
            impl->limits.max_indexed_text_bytes > limits.max_indexed_text_bytes ||
            impl->limits.max_index_bytes == 0 ||
            impl->limits.max_index_bytes > limits.max_index_bytes ||
            impl->limits.max_query_bytes == 0 ||
            impl->limits.max_query_bytes > limits.max_query_bytes ||
            impl->limits.max_results_per_query == 0 ||
            impl->limits.max_results_per_query > limits.max_results_per_query ||
            impl->limits.cancellation_check_interval == 0) {
            reader.reject("serialized search identity or limits are inconsistent");
        }

        const auto string_count = reader.count(
            impl->limits.max_entries * 2ULL, sizeof(std::uint32_t));
        impl->strings.offsets.reserve(string_count);
        for (std::size_t index = 0; index < string_count; ++index)
            impl->strings.offsets.push_back(reader.u32());
        const auto length_count = reader.count(
            impl->limits.max_entries * 2ULL, sizeof(std::uint32_t));
        impl->strings.lengths.reserve(length_count);
        for (std::size_t index = 0; index < length_count; ++index)
            impl->strings.lengths.push_back(reader.u32());
        impl->strings.bytes = reader.bytes(
            impl->limits.max_indexed_text_bytes);
        if (string_count != length_count) {
            reader.reject("serialized search string tables differ in length");
        }
        for (std::size_t index = 0; index < impl->strings.offsets.size(); ++index) {
            const auto offset = impl->strings.offsets[index];
            const auto length = impl->strings.lengths[index];
            if (offset > impl->strings.bytes.size() ||
                length > impl->strings.bytes.size() - offset) {
                reader.reject("serialized search string range is invalid");
                break;
            }
        }

        const auto record_count = reader.count(impl->limits.max_entries, 41U);
        impl->records.reserve(record_count);
        for (std::size_t index = 0; index < record_count; ++index) {
            packed_search_record_t record;
            record.entity_id = reader.u64();
            record.numeric_value = reader.u64();
            record.address.value = reader.u64();
            record.address.metadata = reader.u32();
            record.text.value = reader.u32();
            record.normalized_text.value = reader.u32();
            record.auxiliary_flags = reader.u32();
            record.kind = static_cast<search_entity_kind_t>(reader.u8());
            if (record.entity_id == 0 ||
                record.kind > search_entity_kind_t::byte_sequence ||
                (record.text.valid() && !impl->strings.lookup(record.text)) ||
                (record.normalized_text.valid() &&
                 !impl->strings.lookup(record.normalized_text))) {
                reader.reject("serialized search record is invalid");
                break;
            }
            impl->records.push_back(record);
        }
        const auto text_count = reader.count(impl->limits.max_entries, 8U);
        impl->text_references.reserve(text_count);
        for (std::size_t index = 0; index < text_count; ++index) {
            packed_text_reference_t reference;
            reference.record = reader.u32();
            reference.normalized.value = reader.u32();
            if (reference.record >= impl->records.size() ||
                !impl->strings.lookup(reference.normalized) ||
                impl->records[reference.record].normalized_text.value !=
                    reference.normalized.value) {
                reader.reject("serialized text reference is invalid");
                break;
            }
            impl->text_references.push_back(reference);
        }
        const auto read_u32_vector = [&](std::vector<std::uint32_t>& output,
                                         std::uint64_t maximum) {
            const auto count = reader.count(maximum, sizeof(std::uint32_t));
            output.reserve(count);
            for (std::size_t index = 0; index < count; ++index) {
                const auto reference = reader.u32();
                if (reference >= impl->records.size()) {
                    reader.reject("serialized packed reference is out of range");
                    return;
                }
                output.push_back(reference);
            }
        };
        read_u32_vector(impl->address_references, impl->limits.max_entries);
        read_u32_vector(impl->entity_kind_references, impl->limits.max_entries);
        read_u32_vector(impl->entity_id_references, impl->limits.max_entries);
        read_u32_vector(impl->instruction_references, impl->limits.max_entries);
        const auto opcode_count = reader.count(impl->limits.max_entries, 8U);
        impl->opcode_references.reserve(opcode_count);
        for (std::size_t index = 0; index < opcode_count; ++index) {
            packed_key32_reference_t reference{reader.u32(), reader.u32()};
            if (reference.record >= impl->records.size()) {
                reader.reject("serialized opcode reference is out of range");
                break;
            }
            impl->opcode_references.push_back(reference);
        }
        const auto immediate_count = reader.count(impl->limits.max_entries, 12U);
        impl->immediate_references.reserve(immediate_count);
        for (std::size_t index = 0; index < immediate_count; ++index) {
            packed_key64_reference_t reference{reader.u64(), reader.u32()};
            if (reference.record >= impl->records.size()) {
                reader.reject("serialized immediate reference is out of range");
                break;
            }
            impl->immediate_references.push_back(reference);
        }
        const auto trigram_count = reader.count(
            impl->limits.max_trigram_postings, 12U);
        impl->trigram_spans.reserve(trigram_count);
        for (std::size_t index = 0; index < trigram_count; ++index) {
            packed_trigram_span_t span{reader.u32(), reader.u32(), reader.u32()};
            impl->trigram_spans.push_back(span);
        }
        read_u32_vector(impl->trigram_postings,
                        impl->limits.max_trigram_postings);
        impl->accounting.memory_bytes = reader.u64();
        impl->accounting.source_text_bytes = reader.u64();
        impl->accounting.referenced_text_bytes = reader.u64();
        impl->accounting.unique_text_bytes = reader.u64();
        impl->accounting.record_count = reader.u64();
        impl->accounting.text_reference_count = reader.u64();
        impl->accounting.address_reference_count = reader.u64();
        impl->accounting.entity_reference_count = reader.u64();
        impl->accounting.trigram_count = reader.u64();
        impl->accounting.trigram_posting_count = reader.u64();
        impl->accounting.string_count = reader.u64();
        auto finished = reader.finish();
        if (!finished)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                finished.error());

        const auto reference_valid = [&](std::uint32_t reference) {
            return reference < impl->records.size();
        };
        const bool records_sorted = std::is_sorted(
            impl->records.begin(), impl->records.end(), record_less);
        const bool opcode_sorted = std::is_sorted(
            impl->opcode_references.begin(), impl->opcode_references.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key
                                          : lhs.record < rhs.record;
            });
        const bool immediate_sorted = std::is_sorted(
            impl->immediate_references.begin(), impl->immediate_references.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key
                                          : lhs.record < rhs.record;
            });
        const bool opcode_unique = std::adjacent_find(
            impl->opcode_references.begin(), impl->opcode_references.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.key == rhs.key && lhs.record == rhs.record;
            }) == impl->opcode_references.end();
        const bool immediate_unique = std::adjacent_find(
            impl->immediate_references.begin(),
            impl->immediate_references.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.key == rhs.key && lhs.record == rhs.record;
            }) == impl->immediate_references.end();
        const bool address_sorted = std::is_sorted(
            impl->address_references.begin(), impl->address_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                return record_less(impl->records[lhs], impl->records[rhs]);
            });
        const bool entity_kind_sorted = std::is_sorted(
            impl->entity_kind_references.begin(),
            impl->entity_kind_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                if (left.kind != right.kind)
                    return left.kind < right.kind;
                if (left.entity_id != right.entity_id)
                    return left.entity_id < right.entity_id;
                return lhs < rhs;
            });
        const bool entity_id_sorted = std::is_sorted(
            impl->entity_id_references.begin(),
            impl->entity_id_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                if (left.entity_id != right.entity_id)
                    return left.entity_id < right.entity_id;
                if (left.kind != right.kind)
                    return left.kind < right.kind;
                return lhs < rhs;
            });
        const bool instruction_sorted = std::is_sorted(
            impl->instruction_references.begin(),
            impl->instruction_references.end());
        const bool text_sorted = std::is_sorted(
            impl->text_references.begin(), impl->text_references.end(),
            [&](const auto& lhs, const auto& rhs) {
                const auto left = impl->strings.lookup(lhs.normalized)
                    .value_or(std::string_view{});
                const auto right = impl->strings.lookup(rhs.normalized)
                    .value_or(std::string_view{});
                if (left != right)
                    return left < right;
                return record_less(impl->records[lhs.record],
                                   impl->records[rhs.record]);
            });
        const bool text_records_unique = std::adjacent_find(
            impl->text_references.begin(), impl->text_references.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.record == rhs.record;
            }) == impl->text_references.end();
        bool trigram_valid = std::is_sorted(
            impl->trigram_spans.begin(), impl->trigram_spans.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.key < rhs.key; });
        std::uint64_t next_posting = 0;
        std::optional<std::uint32_t> previous_trigram;
        for (const auto& span : impl->trigram_spans) {
            const auto posting_begin_index = static_cast<std::size_t>(span.begin);
            const auto posting_count = static_cast<std::size_t>(span.count);
            if ((previous_trigram && *previous_trigram >= span.key) ||
                span.begin != next_posting || span.count == 0 ||
                posting_begin_index > impl->trigram_postings.size() ||
                posting_count > impl->trigram_postings.size() - posting_begin_index) {
                trigram_valid = false;
                break;
            }
            using posting_difference_t = std::vector<std::uint32_t>::difference_type;
            const auto posting_begin = impl->trigram_postings.cbegin() +
                static_cast<posting_difference_t>(posting_begin_index);
            const auto posting_end = posting_begin +
                static_cast<posting_difference_t>(posting_count);
            if (!std::is_sorted(posting_begin, posting_end) ||
                std::adjacent_find(posting_begin, posting_end) != posting_end) {
                trigram_valid = false;
                break;
            }
            previous_trigram = span.key;
            next_posting += span.count;
        }
        trigram_valid = trigram_valid &&
            next_posting == impl->trigram_postings.size();
        std::uint64_t expected_records = 0;
        const std::array<std::uint64_t, 6> source_counts{
            snapshot->symbols.size(), snapshot->strings.size(),
            snapshot->instructions.size(), data_candidates.size(),
            switches.size(), types.size()};
        bool source_count_valid = true;
        for (const auto count : source_counts) {
            std::uint64_t updated = 0;
            if (!checked_add_u64(expected_records, count, updated)) {
                source_count_valid = false;
                break;
            }
            expected_records = updated;
        }
        const auto references_unique = [](const auto& references) {
            return std::adjacent_find(references.begin(), references.end()) ==
                references.end();
        };
        const bool entity_keys_unique = std::adjacent_find(
            impl->entity_kind_references.begin(),
            impl->entity_kind_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                return left.kind == right.kind &&
                       left.entity_id == right.entity_id;
            }) == impl->entity_kind_references.end();
        if (!source_count_valid || expected_records != impl->records.size() ||
            !records_sorted || !address_sorted || !entity_kind_sorted ||
            !entity_id_sorted || !instruction_sorted || !text_sorted ||
            !text_records_unique ||
            !opcode_sorted ||
            !immediate_sorted || !opcode_unique || !immediate_unique ||
            !trigram_valid || !entity_keys_unique ||
            impl->address_references.size() != impl->records.size() ||
            impl->entity_kind_references.size() != impl->records.size() ||
            impl->entity_id_references.size() != impl->records.size() ||
            impl->instruction_references.size() !=
                snapshot->instructions.size() ||
            impl->opcode_references.size() != snapshot->instructions.size() ||
            !references_unique(impl->address_references) ||
            !references_unique(impl->entity_kind_references) ||
            !references_unique(impl->entity_id_references) ||
            !references_unique(impl->instruction_references) ||
            !std::all_of(impl->trigram_postings.begin(),
                         impl->trigram_postings.end(),
                         [&](std::uint32_t reference) {
                             return reference < impl->text_references.size();
                         }) ||
            !std::all_of(impl->address_references.begin(),
                         impl->address_references.end(), reference_valid) ||
            !std::all_of(impl->instruction_references.begin(),
                         impl->instruction_references.end(),
                         [&](std::uint32_t reference) {
                             return reference_valid(reference) &&
                                 impl->records[reference].kind ==
                                     search_entity_kind_t::instruction;
                         }) ||
            !std::all_of(impl->opcode_references.begin(),
                         impl->opcode_references.end(),
                         [&](const auto& reference) {
                             return reference_valid(reference.record) &&
                                 impl->records[reference.record].kind ==
                                     search_entity_kind_t::instruction &&
                                 impl->records[reference.record].numeric_value ==
                                     reference.key;
                         }) ||
            !std::all_of(impl->immediate_references.begin(),
                         impl->immediate_references.end(),
                         [&](const auto& reference) {
                             return reference_valid(reference.record) &&
                                 impl->records[reference.record].kind ==
                                     search_entity_kind_t::instruction;
                         }) ||
            impl->accounting.record_count != impl->records.size() ||
            impl->accounting.text_reference_count != impl->text_references.size() ||
            impl->accounting.address_reference_count != impl->address_references.size() ||
            impl->accounting.entity_reference_count != impl->entity_kind_references.size() ||
            impl->accounting.trigram_count != impl->trigram_spans.size() ||
            impl->accounting.trigram_posting_count != impl->trigram_postings.size() ||
            impl->accounting.string_count != impl->strings.offsets.size() ||
            impl->accounting.unique_text_bytes != impl->strings.bytes.size() ||
            impl->accounting.source_text_bytes >
                impl->limits.max_indexed_text_bytes ||
            impl->accounting.referenced_text_bytes >
                impl->limits.max_indexed_text_bytes ||
            impl->accounting.memory_bytes > impl->limits.max_index_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                                     "serialized search index invariants are inconsistent",
                                     "search_index.restore"));
        }
        impl->snapshot = snapshot;
        impl->snapshot_owner = snapshot;
        impl->data_candidates = std::move(data_candidates);
        impl->switches = std::move(switches);
        impl->types = std::move(types);
        impl->metrics = std::move(metrics);
        std::uint64_t restored_memory_bytes = sizeof(impl_t);
        const std::array<std::uint64_t, 16> restored_allocations{
            vector_bytes(impl->strings.offsets.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->strings.lengths.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->strings.bytes.capacity(), sizeof(char)),
            vector_bytes(impl->records.capacity(),
                         sizeof(packed_search_record_t)),
            vector_bytes(impl->text_references.capacity(),
                         sizeof(packed_text_reference_t)),
            vector_bytes(impl->address_references.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->entity_kind_references.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->entity_id_references.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->instruction_references.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->opcode_references.capacity(),
                         sizeof(packed_key32_reference_t)),
            vector_bytes(impl->immediate_references.capacity(),
                         sizeof(packed_key64_reference_t)),
            vector_bytes(impl->trigram_spans.capacity(),
                         sizeof(packed_trigram_span_t)),
            vector_bytes(impl->trigram_postings.capacity(),
                         sizeof(std::uint32_t)),
            vector_bytes(impl->data_candidates.capacity(),
                         sizeof(data_candidate_record_t)),
            vector_bytes(impl->switches.capacity(), sizeof(switch_record_t)),
            vector_bytes(impl->types.capacity(),
                         sizeof(type_candidate_record_t))};
        for (const auto allocation : restored_allocations) {
            std::uint64_t updated = 0;
            if (allocation == (std::numeric_limits<std::uint64_t>::max)() ||
                !checked_add_u64(restored_memory_bytes, allocation, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "restored search-index memory accounting overflows",
                        "search_index.restore"));
            }
            restored_memory_bytes = updated;
        }
        for (const auto& dispatch : impl->switches) {
            std::uint64_t updated = 0;
            const auto bytes = vector_bytes(
                dispatch.case_targets.capacity(), sizeof(address_t));
            if (bytes == (std::numeric_limits<std::uint64_t>::max)() ||
                !checked_add_u64(restored_memory_bytes, bytes, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "restored search-index switch accounting overflows",
                        "search_index.restore"));
            }
            restored_memory_bytes = updated;
        }
        for (const auto& type : impl->types) {
            std::uint64_t updated = 0;
            const auto bytes = static_cast<std::uint64_t>(
                type.display_name.capacity()) +
                static_cast<std::uint64_t>(type.canonical_type.capacity());
            if (!checked_add_u64(restored_memory_bytes, bytes, updated)) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(
                        workspace_error_code_t::range_overflow,
                        "restored search-index type accounting overflows",
                        "search_index.restore"));
            }
            restored_memory_bytes = updated;
        }
        std::uint64_t restored_peak_bytes = 0;
        if (!checked_add_u64(restored_memory_bytes, serialized_resident_bytes,
                             restored_peak_bytes) ||
            restored_memory_bytes > declared_memory_bytes ||
            restored_memory_bytes > impl->limits.max_index_bytes ||
            restored_peak_bytes > limits.max_index_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(
                    workspace_error_code_t::limit_exceeded,
                    "restored search-index resident-memory budget is exceeded",
                    "search_index.restore"));
        }
        impl->accounting.memory_bytes = restored_memory_bytes;
        if (impl->metrics)
            impl->metrics->set(analysis_metric_t::indexed_bytes,
                               restored_memory_bytes);
        impl->snapshot.reset();
        return workspace_result_t<std::shared_ptr<search_index_t>>::success(
            std::shared_ptr<search_index_t>(
                new search_index_t(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "serialized search restore exhausted memory",
                                 "search_index.restore"));
    } catch (const std::length_error&) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "serialized search restore exceeds container limits",
                                 "search_index.restore"));
    }
}

workspace_result_t<void> search_index_t::serialize_to(
    const serialized_sink_t& sink,
    const cancellation_token_t& cancel) const {
    if (!impl_ || !sink) {
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "search serialization requires an index and byte sink",
                                 "search_index.serialize"));
    }
    if (cancel.stop_requested())
        return workspace_result_t<void>::failure(
            stop_error(cancel, "search_index.serialize"));
    search_blob_writer_t writer(sink, cancel);
    writer.u32(kSerializedSearchMagic);
    writer.u32(serialized_version);
    writer.fixed(impl_->identity.binary_id.bytes);
    writer.fixed(impl_->identity.load_profile_hash.bytes);
    writer.u8(impl_->identity.provider_content_hash ? 1U : 0U);
    if (impl_->identity.provider_content_hash)
        writer.fixed(impl_->identity.provider_content_hash->bytes);
    else
        writer.fixed(std::array<std::uint8_t, 32>{});
    writer.u64(impl_->identity.generation);
    writer.u64(impl_->identity.analysis_revision);
    writer.u64(impl_->identity.overlay_revision);
    writer.u64(impl_->identity.provider_size);
    writer.u8(static_cast<std::uint8_t>(impl_->architecture));
    writer.u8(static_cast<std::uint8_t>(impl_->architecture_mode));
    writer.u64(impl_->cursor_integrity_key[0]);
    writer.u64(impl_->cursor_integrity_key[1]);
    writer.u64(impl_->limits.max_entries);
    writer.u64(impl_->limits.max_trigram_postings);
    writer.u64(impl_->limits.max_indexed_text_bytes);
    writer.u64(impl_->limits.max_index_bytes);
    writer.u32(impl_->limits.max_query_bytes);
    writer.u32(impl_->limits.max_results_per_query);
    writer.u32(impl_->limits.cancellation_check_interval);

    writer.u64(impl_->strings.offsets.size());
    for (const auto value : impl_->strings.offsets)
        writer.u32(value);
    writer.u64(impl_->strings.lengths.size());
    for (const auto value : impl_->strings.lengths)
        writer.u32(value);
    writer.bytes(impl_->strings.bytes.data(), impl_->strings.bytes.size());

    writer.u64(impl_->records.size());
    for (const auto& record : impl_->records) {
        writer.u64(record.entity_id);
        writer.u64(record.numeric_value);
        writer.u64(record.address.value);
        writer.u32(record.address.metadata);
        writer.u32(record.text.value);
        writer.u32(record.normalized_text.value);
        writer.u32(record.auxiliary_flags);
        writer.u8(static_cast<std::uint8_t>(record.kind));
    }
    writer.u64(impl_->text_references.size());
    for (const auto& reference : impl_->text_references) {
        writer.u32(reference.record);
        writer.u32(reference.normalized.value);
    }
    const auto write_u32_vector = [&](const std::vector<std::uint32_t>& values) {
        writer.u64(values.size());
        for (const auto value : values)
            writer.u32(value);
    };
    write_u32_vector(impl_->address_references);
    write_u32_vector(impl_->entity_kind_references);
    write_u32_vector(impl_->entity_id_references);
    write_u32_vector(impl_->instruction_references);
    writer.u64(impl_->opcode_references.size());
    for (const auto& reference : impl_->opcode_references) {
        writer.u32(reference.key);
        writer.u32(reference.record);
    }
    writer.u64(impl_->immediate_references.size());
    for (const auto& reference : impl_->immediate_references) {
        writer.u64(reference.key);
        writer.u32(reference.record);
    }
    writer.u64(impl_->trigram_spans.size());
    for (const auto& span : impl_->trigram_spans) {
        writer.u32(span.key);
        writer.u32(span.begin);
        writer.u32(span.count);
    }
    write_u32_vector(impl_->trigram_postings);
    writer.u64(impl_->accounting.memory_bytes);
    writer.u64(impl_->accounting.source_text_bytes);
    writer.u64(impl_->accounting.referenced_text_bytes);
    writer.u64(impl_->accounting.unique_text_bytes);
    writer.u64(impl_->accounting.record_count);
    writer.u64(impl_->accounting.text_reference_count);
    writer.u64(impl_->accounting.address_reference_count);
    writer.u64(impl_->accounting.entity_reference_count);
    writer.u64(impl_->accounting.trigram_count);
    writer.u64(impl_->accounting.trigram_posting_count);
    writer.u64(impl_->accounting.string_count);
    auto finished = writer.finish();
    if (finished && impl_->metrics)
        impl_->metrics->add(analysis_metric_t::index_serialized_bytes, writer.size());
    return finished;
}

search_generation_identity_t search_index_t::identity() const noexcept {
    return impl_->identity;
}

search_generation_handle_t search_index_t::generation_handle() const {
    return search_generation_handle_t(identity(), shared_from_this());
}

std::uint64_t search_index_t::generation() const noexcept {
    return impl_->identity.generation;
}

const binary_id_t& search_index_t::binary_id() const noexcept {
    return impl_->identity.binary_id;
}

const sha256_digest_t& search_index_t::load_profile_hash() const noexcept {
    return impl_->identity.load_profile_hash;
}

std::uint64_t search_index_t::analysis_revision() const noexcept {
    return impl_->identity.analysis_revision;
}

std::uint64_t search_index_t::overlay_revision() const noexcept {
    return impl_->identity.overlay_revision;
}

bool search_index_t::matches(
    const std::shared_ptr<const analysis_snapshot_t>& snapshot) const noexcept {
    return snapshot && impl_->identity == snapshot_identity(*snapshot) &&
        !impl_->snapshot_owner.owner_before(snapshot) &&
        !snapshot.owner_before(impl_->snapshot_owner);
}

bool search_index_t::matches(std::uint64_t generation_value,
    std::uint64_t analysis_revision_value, std::uint64_t overlay_revision_value) const noexcept {
    return impl_->identity.generation == generation_value &&
        impl_->identity.analysis_revision == analysis_revision_value &&
        impl_->identity.overlay_revision == overlay_revision_value;
}

bool search_index_t::matches(const binary_id_t& binary_id_value,
    const sha256_digest_t& load_profile_hash_value, std::uint64_t generation_value,
    std::uint64_t analysis_revision_value, std::uint64_t overlay_revision_value) const noexcept {
    return impl_->identity.binary_id == binary_id_value &&
        impl_->identity.load_profile_hash == load_profile_hash_value &&
        matches(generation_value, analysis_revision_value, overlay_revision_value);
}

workspace_result_t<void> search_index_t::verify_identity(
    const binary_id_t& expected_binary_id,
    const sha256_digest_t& expected_load_profile_hash) const {
    if (impl_->identity.binary_id != expected_binary_id)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::substitution_rejected,
                "search index binary_id does not match the expected workspace identity",
                "search_index"));
    if (impl_->identity.load_profile_hash != expected_load_profile_hash)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::substitution_rejected,
                "search index load_profile_hash does not match the expected workspace identity",
                "search_index"));
    return workspace_result_t<void>::success();
}

const search_index_limits_t& search_index_t::limits() const noexcept {
    return impl_->limits;
}

const std::vector<data_candidate_record_t>& search_index_t::data_candidates() const noexcept {
    return impl_->data_candidates;
}

const std::vector<switch_record_t>& search_index_t::switches() const noexcept {
    return impl_->switches;
}

const std::vector<type_candidate_record_t>& search_index_t::types() const noexcept {
    return impl_->types;
}

std::uint64_t search_index_t::memory_bytes() const noexcept {
    return impl_->accounting.memory_bytes;
}

search_index_size_t search_index_t::size_accounting() const noexcept {
    return impl_->accounting;
}

analysis_metrics_snapshot_t search_index_t::metrics() const noexcept {
    return impl_->metrics ? impl_->metrics->snapshot() : analysis_metrics_snapshot_t{};
}

std::size_t search_index_t::record_count() const noexcept {
    return impl_->records.size();
}

std::size_t search_index_t::text_record_count() const noexcept {
    return impl_->text_references.size();
}

address_t search_index_t::file_offset_address(std::uint64_t offset) const noexcept {
    address_t address;
    address.space = address_space_id_t::file_offset;
    address.value = offset;
    address.architecture = impl_->architecture;
    address.mode = impl_->architecture_mode;
    return address;
}

std::optional<search_record_view_t> search_index_t::record(std::size_t index) const noexcept {
    if (index > std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;
    return impl_->view(static_cast<std::uint32_t>(index));
}

std::optional<search_record_view_t> search_index_t::text_record(std::size_t index) const noexcept {
    if (index >= impl_->text_references.size())
        return std::nullopt;
    return impl_->view(impl_->text_references[index].record);
}

const std::array<std::uint64_t, 2>&
search_index_t::cursor_integrity_key() const noexcept {
    return impl_->cursor_integrity_key;
}

workspace_result_t<search_page_t> search_index_t::find_text(const std::string& text,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel,
    search_deadline_t deadline) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "search_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    if (text.empty() || text.size() > impl_->limits.max_query_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
            "text search query is outside the allowed byte range", "search_index");
        error.details.emplace_back("maximum", std::to_string(impl_->limits.max_query_bytes));
        return workspace_result_t<search_page_t>::failure(std::move(error));
    }
    auto running = validate_running(cancel, deadline, "search_index");
    if (!running)
        return workspace_result_t<search_page_t>::failure(running.error());
    const auto normalized = normalize_text(text);
    if (normalized.empty()) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "text search requires a non-empty query", "search_index"));
    }
    const packed_trigram_span_t* candidates = nullptr;
    if (normalized.size() >= 3) {
        std::vector<std::uint32_t> keys;
        keys.reserve(normalized.size() - 2U);
        for (std::size_t index = 0; index + 3U <= normalized.size(); ++index) {
            if ((index & 0x3ffU) == 0) {
                if (cancel.stop_requested())
                    return workspace_result_t<search_page_t>::failure(
                        stop_error(cancel, "search_index"));
                if (deadline && std::chrono::steady_clock::now() >= *deadline)
                    return workspace_result_t<search_page_t>::failure(
                        stop_error(cancel, "search_index", true));
            }
            keys.push_back(trigram_key(normalized.data() + index));
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        for (const auto key : keys) {
            const auto span = impl_->trigram(key);
            if (!span)
                return workspace_result_t<search_page_t>::success(search_page_t{});
            if (!candidates || span->count < candidates->count)
                candidates = span;
        }
    }
    const auto candidate_count = candidates
        ? static_cast<std::size_t>(candidates->count) : impl_->text_references.size();
    const auto reference_at = [&](std::size_t index) {
        return candidates
            ? impl_->trigram_postings[static_cast<std::size_t>(candidates->begin) + index]
            : static_cast<std::uint32_t>(index);
    };
    const auto predicate = [&](std::uint32_t text_reference) {
        if (text_reference >= impl_->text_references.size())
            return false;
        const auto indexed = impl_->strings.lookup(
            impl_->text_references[text_reference].normalized);
        return indexed && indexed->find(normalized) != std::string_view::npos;
    };
    const auto materialize = [&](std::uint32_t text_reference) {
        if (text_reference >= impl_->text_references.size())
            return std::optional<search_hit_t>{};
        return impl_->hit(impl_->text_references[text_reference].record);
    };
    return filtered_page(candidate_count, reference_at, predicate, materialize,
        offset, limit, impl_->limits.cancellation_check_interval, cancel,
        deadline, "search_index");
}

workspace_result_t<search_page_t> search_index_t::find_opcode(std::uint32_t opcode_id,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel,
    search_deadline_t deadline) const {
    search_instruction_filter_t filter;
    filter.opcode_id = opcode_id;
    return find_instruction(filter, offset, limit, cancel, deadline);
}

workspace_result_t<search_page_t> search_index_t::find_immediate(std::uint64_t value,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel,
    search_deadline_t deadline) const {
    search_instruction_filter_t filter;
    filter.immediate = value;
    return find_instruction(filter, offset, limit, cancel, deadline);
}

workspace_result_t<search_page_t> search_index_t::find_instruction(
    const search_instruction_filter_t& filter, std::uint64_t offset,
    std::uint32_t limit, const cancellation_token_t& cancel,
    search_deadline_t deadline) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "query_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    valid = validate_filter_range(filter.begin, filter.end, "query_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    if ((filter.required_flow_flags & filter.forbidden_flow_flags) != 0) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "instruction flow requirements contradict exclusions", "query_index"));
    }
    auto running = validate_running(cancel, deadline, "query_index");
    if (!running)
        return workspace_result_t<search_page_t>::failure(running.error());

    const packed_key32_reference_t* opcode_begin = nullptr;
    std::size_t opcode_count = 0;
    if (filter.opcode_id) {
        const auto first = std::lower_bound(impl_->opcode_references.begin(),
            impl_->opcode_references.end(), *filter.opcode_id,
            [](const packed_key32_reference_t& reference, std::uint32_t key) {
                return reference.key < key;
            });
        const auto last = std::upper_bound(first, impl_->opcode_references.end(),
            *filter.opcode_id,
            [](std::uint32_t key, const packed_key32_reference_t& reference) {
                return key < reference.key;
            });
        if (first != last) {
            opcode_begin = &*first;
            opcode_count = static_cast<std::size_t>(last - first);
        }
    }
    const packed_key64_reference_t* immediate_begin = nullptr;
    std::size_t immediate_count = 0;
    if (filter.immediate) {
        const auto first = std::lower_bound(impl_->immediate_references.begin(),
            impl_->immediate_references.end(), *filter.immediate,
            [](const packed_key64_reference_t& reference, std::uint64_t key) {
                return reference.key < key;
            });
        const auto last = std::upper_bound(first, impl_->immediate_references.end(),
            *filter.immediate,
            [](std::uint64_t key, const packed_key64_reference_t& reference) {
                return key < reference.key;
            });
        if (first != last) {
            immediate_begin = &*first;
            immediate_count = static_cast<std::size_t>(last - first);
        }
    }
    if ((filter.opcode_id && opcode_count == 0) ||
        (filter.immediate && immediate_count == 0))
        return workspace_result_t<search_page_t>::success(search_page_t{});

    enum class source_t : std::uint8_t { instructions, opcodes, immediates };
    source_t source = source_t::instructions;
    std::size_t candidate_count = impl_->instruction_references.size();
    if (filter.opcode_id && opcode_count < candidate_count) {
        source = source_t::opcodes;
        candidate_count = opcode_count;
    }
    if (filter.immediate && immediate_count < candidate_count) {
        source = source_t::immediates;
        candidate_count = immediate_count;
    }
    const auto reference_at = [&](std::size_t index) {
        if (source == source_t::opcodes)
            return opcode_begin[index].record;
        if (source == source_t::immediates)
            return immediate_begin[index].record;
        return impl_->instruction_references[index];
    };
    const auto has_opcode = [&](std::uint32_t reference) {
        if (!filter.opcode_id)
            return true;
        return std::binary_search(impl_->opcode_references.begin(),
            impl_->opcode_references.end(),
            packed_key32_reference_t{*filter.opcode_id, reference},
            [](const packed_key32_reference_t& lhs, const packed_key32_reference_t& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.record < rhs.record;
            });
    };
    const auto has_immediate = [&](std::uint32_t reference) {
        if (!filter.immediate)
            return true;
        return std::binary_search(impl_->immediate_references.begin(),
            impl_->immediate_references.end(),
            packed_key64_reference_t{*filter.immediate, reference},
            [](const packed_key64_reference_t& lhs, const packed_key64_reference_t& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.record < rhs.record;
            });
    };
    const auto predicate = [&](std::uint32_t reference) {
        if (reference >= impl_->records.size())
            return false;
        const auto& record = impl_->records[reference];
        if (record.kind != search_entity_kind_t::instruction || !has_opcode(reference) ||
            !has_immediate(reference))
            return false;
        if ((record.auxiliary_flags & filter.required_flow_flags) !=
            filter.required_flow_flags)
            return false;
        if ((record.auxiliary_flags & filter.forbidden_flow_flags) != 0)
            return false;
        return address_matches_range(unpack_address(record.address), filter.begin, filter.end);
    };
    const auto materialize = [&](std::uint32_t reference) {
        auto hit = impl_->hit(reference);
        if (hit && filter.immediate)
            hit->numeric_value = *filter.immediate;
        return hit;
    };
    return filtered_page(candidate_count, reference_at, predicate, materialize,
        offset, limit, impl_->limits.cancellation_check_interval, cancel,
        deadline, "query_index");
}

workspace_result_t<search_page_t> search_index_t::find_entity(
    const search_entity_filter_t& filter, std::uint64_t offset,
    std::uint32_t limit, const cancellation_token_t& cancel,
    search_deadline_t deadline) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "query_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    if (filter.kind && *filter.kind > search_entity_kind_t::byte_sequence) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "entity search kind is invalid", "query_index"));
    }
    if (filter.entity_id && *filter.entity_id == 0) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "entity search identifier is invalid", "query_index"));
    }
    auto running = validate_running(cancel, deadline, "query_index");
    if (!running)
        return workspace_result_t<search_page_t>::failure(running.error());

    const std::vector<std::uint32_t>* references = &impl_->address_references;
    std::size_t begin_index = 0;
    std::size_t candidate_count = references->size();
    if (filter.kind) {
        references = &impl_->entity_kind_references;
        const auto first = std::lower_bound(references->begin(), references->end(), *filter.kind,
            [&](std::uint32_t reference, search_entity_kind_t kind) {
                return impl_->records[reference].kind < kind;
            });
        const auto last = std::upper_bound(first, references->end(), *filter.kind,
            [&](search_entity_kind_t kind, std::uint32_t reference) {
                return kind < impl_->records[reference].kind;
            });
        begin_index = static_cast<std::size_t>(first - references->begin());
        candidate_count = static_cast<std::size_t>(last - first);
    } else if (filter.entity_id) {
        references = &impl_->entity_id_references;
        const auto first = std::lower_bound(references->begin(), references->end(),
            *filter.entity_id, [&](std::uint32_t reference, entity_id_t id) {
                return impl_->records[reference].entity_id < id;
            });
        const auto last = std::upper_bound(first, references->end(), *filter.entity_id,
            [&](entity_id_t id, std::uint32_t reference) {
                return id < impl_->records[reference].entity_id;
            });
        begin_index = static_cast<std::size_t>(first - references->begin());
        candidate_count = static_cast<std::size_t>(last - first);
    }
    const auto reference_at = [&](std::size_t index) {
        return (*references)[begin_index + index];
    };
    const auto predicate = [&](std::uint32_t reference) {
        if (reference >= impl_->records.size())
            return false;
        const auto& record = impl_->records[reference];
        return (!filter.kind || record.kind == *filter.kind) &&
            (!filter.entity_id || record.entity_id == *filter.entity_id);
    };
    const auto materialize = [&](std::uint32_t reference) {
        return impl_->hit(reference);
    };
    return filtered_page(candidate_count, reference_at, predicate, materialize,
        offset, limit, impl_->limits.cancellation_check_interval, cancel,
        deadline, "query_index");
}

workspace_result_t<search_page_t> search_index_t::find_address_range(
    const address_t& begin, const address_t& end, std::uint64_t offset,
    std::uint32_t limit, const cancellation_token_t& cancel,
    search_deadline_t deadline) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "search_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    if (end < begin || begin.space != end.space ||
        begin.architecture != end.architecture || begin.mode != end.mode) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "address search range is invalid", "search_index"));
    }
    auto running = validate_running(cancel, deadline, "search_index");
    if (!running)
        return workspace_result_t<search_page_t>::failure(running.error());
    const auto first = std::lower_bound(impl_->address_references.begin(),
        impl_->address_references.end(), begin,
        [&](std::uint32_t reference, const address_t& address) {
            return unpack_address(impl_->records[reference].address) < address;
        });
    const auto last = std::lower_bound(first, impl_->address_references.end(), end,
        [&](std::uint32_t reference, const address_t& address) {
            return unpack_address(impl_->records[reference].address) < address;
        });
    const auto begin_index = static_cast<std::size_t>(first - impl_->address_references.begin());
    const auto count = static_cast<std::size_t>(last - first);
    const auto reference_at = [&](std::size_t index) {
        return impl_->address_references[begin_index + index];
    };
    const auto predicate = [](std::uint32_t) { return true; };
    const auto materialize = [&](std::uint32_t reference) {
        return impl_->hit(reference);
    };
    return filtered_page(count, reference_at, predicate, materialize,
        offset, limit, impl_->limits.cancellation_check_interval, cancel,
        deadline, "search_index");
}

}
