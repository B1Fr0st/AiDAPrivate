#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "search_index.hpp"

#include "checked_range.hpp"
#include "pe_image.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

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

    workspace_result_t<interned_string_pool_t> freeze() && {
        std::uint64_t total = 0;
        for (const auto& value : values_) {
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
        pool.offsets.reserve(values_.size());
        pool.lengths.reserve(values_.size());
        pool.bytes.reserve(static_cast<std::size_t>(total));
        for (const auto& value : values_) {
            pool.offsets.push_back(static_cast<std::uint32_t>(pool.bytes.size()));
            pool.lengths.push_back(static_cast<std::uint32_t>(value.size()));
            pool.bytes.insert(pool.bytes.end(), value.begin(), value.end());
        }
        return workspace_result_t<interned_string_pool_t>::success(std::move(pool));
    }

private:
    std::vector<std::string> values_;
    std::unordered_map<std::string, packed_string_id_t> index_;
};

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
        impl->data_candidates = std::move(data_candidates);
        impl->switches = std::move(switches);
        impl->types = std::move(types);
        impl->metrics = std::move(metrics);
        impl->limits = limits;
        impl->records.reserve(static_cast<std::size_t>(prospective_entries));

        std::uint64_t cancellation_checks = 0;
        const auto stopped = [&]() noexcept {
            if (++cancellation_checks < limits.cancellation_check_interval)
                return false;
            cancellation_checks = 0;
            return cancel.stop_requested();
        };
        interned_string_builder_t string_builder;
        std::uint64_t indexed_text_bytes = 0;
        auto add_record = [&](search_entity_kind_t kind, entity_id_t entity_id,
                              const address_t& address, std::uint64_t numeric_value,
                              std::uint32_t auxiliary_flags,
                              std::string_view text) -> workspace_result_t<void> {
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
                if (!checked_add_u64(indexed_text_bytes, referenced, updated) ||
                    updated > limits.max_indexed_text_bytes ||
                    updated > limits.max_index_bytes) {
                    return workspace_result_t<void>::failure(
                        make_workspace_error(workspace_error_code_t::limit_exceeded,
                            "search-index text budget exceeded", "search_index"));
                }
                indexed_text_bytes = updated;
                if (!checked_add_u64(impl->accounting.source_text_bytes,
                        text.size(), updated)) {
                    return workspace_result_t<void>::failure(
                        make_workspace_error(workspace_error_code_t::range_overflow,
                            "search-index source text accounting overflows", "search_index"));
                }
                impl->accounting.source_text_bytes = updated;
                impl->accounting.referenced_text_bytes = indexed_text_bytes;
                auto display_id = string_builder.intern(text);
                if (!display_id)
                    return workspace_result_t<void>::failure(display_id.error());
                record.text = display_id.take_value();
                if (!normalized.empty()) {
                    auto normalized_id = string_builder.intern(normalized);
                    if (!normalized_id)
                        return workspace_result_t<void>::failure(normalized_id.error());
                    record.normalized_text = normalized_id.take_value();
                }
            }
            impl->records.push_back(record);
            return workspace_result_t<void>::success();
        };

        impl->text_references.reserve(impl->snapshot->symbols.size() +
            impl->snapshot->strings.size() + impl->types.size());
        for (const auto& symbol : impl->snapshot->symbols) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            const auto kind = symbol.kind == symbol_kind_t::function
                ? search_entity_kind_t::function : search_entity_kind_t::symbol;
            auto added = add_record(kind, symbol.id, symbol.address, 0, 0, symbol.name);
            if (!added)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
        }
        for (const auto& string : impl->snapshot->strings) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            auto added = add_record(search_entity_kind_t::string, string.id, string.address,
                string.byte_length, static_cast<std::uint32_t>(string.encoding), string.value);
            if (!added)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
        }
        for (const auto& type : impl->types) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            const std::string_view text = type.display_name.empty()
                ? std::string_view(type.canonical_type) : std::string_view(type.display_name);
            auto added = add_record(search_entity_kind_t::type_candidate, type.id,
                type.address, 0, static_cast<std::uint32_t>(type.kind), text);
            if (!added)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
        }
        for (const auto& instruction : impl->snapshot->instructions) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            auto added = add_record(search_entity_kind_t::instruction, instruction.id,
                instruction.address, instruction.opcode_id, instruction.flow_flags, {});
            if (!added)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
        }
        for (const auto& data : impl->data_candidates) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            auto added = add_record(search_entity_kind_t::data_candidate, data.id,
                data.address, data.size, static_cast<std::uint32_t>(data.kind), {});
            if (!added)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
        }
        for (const auto& dispatch : impl->switches) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            auto added = add_record(search_entity_kind_t::switch_dispatch, dispatch.id,
                dispatch.dispatch, dispatch.case_targets.size(), dispatch.entry_size, {});
            if (!added)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
        }
        if (impl->records.size() != prospective_entries) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::integrity_failure,
                    "search-index record count diverged during packing", "search_index"));
        }

        auto frozen = std::move(string_builder).freeze();
        if (!frozen)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(frozen.error());
        impl->strings = frozen.take_value();
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                stop_error(cancel, "search_index"));

        std::sort(impl->records.begin(), impl->records.end(), record_less);

        impl->address_references.reserve(impl->records.size());
        impl->entity_kind_references.reserve(impl->records.size());
        impl->entity_id_references.reserve(impl->records.size());
        impl->instruction_references.reserve(impl->snapshot->instructions.size());
        impl->opcode_references.reserve(impl->snapshot->instructions.size());
        for (std::size_t index = 0; index < impl->records.size(); ++index) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            const auto reference = static_cast<std::uint32_t>(index);
            const auto& record = impl->records[index];
            impl->address_references.push_back(reference);
            impl->entity_kind_references.push_back(reference);
            impl->entity_id_references.push_back(reference);
            if (record.normalized_text.valid())
                impl->text_references.push_back(
                    packed_text_reference_t{reference, record.normalized_text});
            if (record.kind == search_entity_kind_t::instruction) {
                impl->instruction_references.push_back(reference);
                impl->opcode_references.push_back(packed_key32_reference_t{
                    static_cast<std::uint32_t>(record.numeric_value), reference});
            }
        }
        std::sort(impl->address_references.begin(), impl->address_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                return record_less(impl->records[lhs], impl->records[rhs]);
            });
        std::sort(impl->entity_kind_references.begin(), impl->entity_kind_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                if (left.kind != right.kind)
                    return left.kind < right.kind;
                if (left.entity_id != right.entity_id)
                    return left.entity_id < right.entity_id;
                return lhs < rhs;
            });
        for (std::size_t index = 1; index < impl->entity_kind_references.size(); ++index) {
            const auto& previous = impl->records[impl->entity_kind_references[index - 1U]];
            const auto& current = impl->records[impl->entity_kind_references[index]];
            if (previous.kind == current.kind && previous.entity_id == current.entity_id) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "search-index contains a duplicate final entity", "search_index"));
            }
        }
        std::sort(impl->entity_id_references.begin(), impl->entity_id_references.end(),
            [&](std::uint32_t lhs, std::uint32_t rhs) {
                const auto& left = impl->records[lhs];
                const auto& right = impl->records[rhs];
                if (left.entity_id != right.entity_id)
                    return left.entity_id < right.entity_id;
                if (left.kind != right.kind)
                    return left.kind < right.kind;
                return lhs < rhs;
            });
        std::sort(impl->opcode_references.begin(), impl->opcode_references.end(),
            [](const packed_key32_reference_t& lhs, const packed_key32_reference_t& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.record < rhs.record;
            });

        impl->immediate_references.reserve(impl->snapshot->operand_facts.size());
        for (const auto& operand : impl->snapshot->operand_facts) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            if (operand.kind != operand_kind_t::immediate)
                continue;
            const auto reference = impl->instruction_reference(operand.instruction_id);
            if (!reference) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "search-index immediate references an unknown instruction",
                        "search_index"));
            }
            impl->immediate_references.push_back(
                packed_key64_reference_t{operand.immediate, *reference});
        }
        std::sort(impl->immediate_references.begin(), impl->immediate_references.end(),
            [](const packed_key64_reference_t& lhs, const packed_key64_reference_t& rhs) {
                return lhs.key != rhs.key ? lhs.key < rhs.key : lhs.record < rhs.record;
            });
        impl->immediate_references.erase(std::unique(impl->immediate_references.begin(),
            impl->immediate_references.end(),
            [](const packed_key64_reference_t& lhs, const packed_key64_reference_t& rhs) {
                return lhs.key == rhs.key && lhs.record == rhs.record;
            }), impl->immediate_references.end());

        std::sort(impl->text_references.begin(), impl->text_references.end(),
            [&](const packed_text_reference_t& lhs, const packed_text_reference_t& rhs) {
                const auto left = impl->strings.lookup(lhs.normalized).value_or(std::string_view{});
                const auto right = impl->strings.lookup(rhs.normalized).value_or(std::string_view{});
                if (left != right)
                    return left < right;
                return record_less(impl->records[lhs.record], impl->records[rhs.record]);
            });

        std::vector<std::pair<std::uint32_t, std::uint32_t>> trigram_pairs;
        for (std::size_t text_index = 0; text_index < impl->text_references.size(); ++text_index) {
            if (stopped())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel, "search_index"));
            const auto text = impl->strings.lookup(impl->text_references[text_index].normalized);
            if (!text) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::integrity_failure,
                        "search-index text reference is invalid", "search_index"));
            }
            std::vector<std::uint32_t> keys;
            if (text->size() >= 3)
                keys.reserve(text->size() - 2U);
            for (std::size_t offset = 0; offset + 3U <= text->size(); ++offset) {
                if ((offset & 0x3ffU) == 0 && cancel.stop_requested())
                    return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                        stop_error(cancel, "search_index"));
                keys.push_back(trigram_key(text->data() + offset));
            }
            std::sort(keys.begin(), keys.end());
            keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
            if (keys.size() > limits.max_trigram_postings - trigram_pairs.size()) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "search-index posting budget exceeded", "search_index"));
            }
            for (const auto key : keys)
                trigram_pairs.emplace_back(key, static_cast<std::uint32_t>(text_index));
        }
        std::sort(trigram_pairs.begin(), trigram_pairs.end());
        impl->trigram_postings.reserve(trigram_pairs.size());
        impl->trigram_spans.reserve(trigram_pairs.size());
        std::size_t pair_index = 0;
        while (pair_index < trigram_pairs.size()) {
            const auto key = trigram_pairs[pair_index].first;
            const auto begin = static_cast<std::uint32_t>(impl->trigram_postings.size());
            do {
                impl->trigram_postings.push_back(trigram_pairs[pair_index].second);
                ++pair_index;
            } while (pair_index < trigram_pairs.size() &&
                     trigram_pairs[pair_index].first == key);
            const auto count = static_cast<std::uint32_t>(
                impl->trigram_postings.size() - begin);
            impl->trigram_spans.push_back(packed_trigram_span_t{key, begin, count});
        }
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
        if (impl->metrics)
            impl->metrics->set(analysis_metric_t::indexed_bytes, memory_bytes);
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
    }
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
