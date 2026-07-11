#include "search_index.hpp"

#include "checked_range.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <unordered_map>

namespace aida::analysis {
namespace {

constexpr std::uint64_t kInstructionEntityTag = 1ULL << 56;
constexpr std::uint64_t kEntityIndexMask = kInstructionEntityTag - 1ULL;

struct indexed_text_t {
    search_hit_t hit;
    std::string normalized;
};

workspace_error_t stop_error(const cancellation_token_t& cancel) {
    if (cancel.deadline_exceeded()) {
        auto error = make_workspace_error(workspace_error_code_t::deadline_exceeded,
            "search-index operation exceeded its deadline", "search_index");
        error.cancellation = true;
        error.deadline = true;
        return error;
    }
    auto error = make_workspace_error(workspace_error_code_t::cancelled,
        "search-index operation cancelled", "search_index");
    error.cancellation = true;
    return error;
}

std::string normalize_text(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    bool previous_space = false;
    for (const auto raw : text) {
        const auto value = static_cast<unsigned char>(raw);
        if (value < 0x80 && std::isspace(value)) {
            if (!result.empty() && !previous_space)
                result.push_back(' ');
            previous_space = true;
            continue;
        }
        previous_space = false;
        result.push_back(value < 0x80
            ? static_cast<char>(std::tolower(value)) : static_cast<char>(value));
    }
    while (!result.empty() && result.back() == ' ')
        result.pop_back();
    return result;
}

std::uint32_t trigram_key(const char* value) noexcept {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(value[0])) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(value[1])) << 8) |
        (static_cast<std::uint32_t>(static_cast<unsigned char>(value[2])) << 16);
}

std::optional<std::uint32_t> instruction_index_for_id(
    entity_id_t id, const std::vector<instruction_record_t>& instructions) noexcept {
    if ((id & ~kEntityIndexMask) != kInstructionEntityTag)
        return std::nullopt;
    const auto encoded = id & kEntityIndexMask;
    if (encoded == 0 || encoded > instructions.size())
        return std::nullopt;
    const auto index = static_cast<std::uint32_t>(encoded - 1ULL);
    return instructions[index].id == id ? std::optional<std::uint32_t>(index)
                                         : std::nullopt;
}

bool hit_less(const search_hit_t& lhs, const search_hit_t& rhs) noexcept {
    if (lhs.address != rhs.address)
        return lhs.address < rhs.address;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.entity_id != rhs.entity_id)
        return lhs.entity_id < rhs.entity_id;
    return lhs.text < rhs.text;
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

template <typename Getter>
workspace_result_t<search_page_t> page_indices(const std::vector<std::uint32_t>& indexes,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel,
    Getter&& getter) {
    search_page_t page;
    page.total = indexes.size();
    if (offset >= indexes.size()) {
        page.next_offset = indexes.size();
        return workspace_result_t<search_page_t>::success(std::move(page));
    }
    const auto available = static_cast<std::uint64_t>(indexes.size()) - offset;
    const auto count = std::min<std::uint64_t>(available, limit);
    page.hits.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        if ((index & 0x3FFULL) == 0 && cancel.stop_requested())
            return workspace_result_t<search_page_t>::failure(stop_error(cancel));
        page.hits.push_back(getter(indexes[static_cast<std::size_t>(offset + index)]));
    }
    page.next_offset = offset + count;
    page.truncated = page.next_offset < page.total;
    return workspace_result_t<search_page_t>::success(std::move(page));
}

}

struct search_index_t::impl_t {
    std::shared_ptr<const analysis_snapshot_t> snapshot;
    std::vector<data_candidate_record_t> data_candidates;
    std::vector<switch_record_t> switches;
    std::vector<type_candidate_record_t> types;
    std::shared_ptr<analysis_metrics_t> metrics;
    search_index_limits_t limits;
    std::vector<indexed_text_t> text_entries;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> trigrams;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> opcodes;
    std::unordered_map<std::uint64_t, std::vector<std::uint32_t>> immediates;
    std::vector<search_hit_t> address_entries;
    std::uint64_t memory_bytes = 0;
};

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
    std::uint64_t cancellation_checks = 0;
    auto should_stop = [&]() noexcept {
        if (++cancellation_checks < limits.cancellation_check_interval)
            return false;
        cancellation_checks = 0;
        return cancel.stop_requested();
    };
    auto impl = std::make_unique<impl_t>();
    impl->snapshot = std::move(snapshot);
    impl->data_candidates = std::move(data_candidates);
    impl->switches = std::move(switches);
    impl->types = std::move(types);
    impl->metrics = std::move(metrics);
    impl->limits = limits;
    std::uint64_t prospective_entries = 0;
    const std::uint64_t entry_counts[] = {
        impl->snapshot->symbols.size(), impl->snapshot->strings.size(),
        impl->snapshot->instructions.size(), impl->data_candidates.size(),
        impl->switches.size(), impl->types.size()
    };
    for (const auto count : entry_counts) {
        std::uint64_t updated = 0;
        if (!checked_add_u64(prospective_entries, count, updated)) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::range_overflow,
                    "search-index entry count overflows", "search_index"));
        }
        prospective_entries = updated;
    }
    if (prospective_entries > limits.max_entries) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "search-index entry count exceeds analysis budget", "search_index"));
    }
    std::uint64_t minimum_entry_bytes = 0;
    if (!checked_mul_u64(prospective_entries, sizeof(search_hit_t),
            minimum_entry_bytes) || minimum_entry_bytes > limits.max_index_bytes) {
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                "search-index base storage exceeds memory budget", "search_index"));
    }
    impl->text_entries.reserve(impl->snapshot->symbols.size() +
        impl->snapshot->strings.size() + impl->types.size());
    impl->address_entries.reserve(static_cast<std::size_t>(prospective_entries));
    std::uint64_t live_index_bytes = minimum_entry_bytes;
    auto charge_live_bytes = [&](std::uint64_t count, std::uint64_t item_size,
                                 const char* message) -> workspace_result_t<void> {
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_mul_u64(count, item_size, bytes) ||
            !checked_add_u64(live_index_bytes, bytes, updated) ||
            updated > limits.max_index_bytes) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    message, "search_index"));
        }
        live_index_bytes = updated;
        return workspace_result_t<void>::success();
    };
    auto charged = charge_live_bytes(impl->text_entries.capacity(),
        sizeof(indexed_text_t), "search-index text storage exceeds memory budget");
    if (charged)
        charged = charge_live_bytes(impl->data_candidates.capacity(),
            sizeof(data_candidate_record_t),
            "search-index data storage exceeds memory budget");
    if (charged)
        charged = charge_live_bytes(impl->switches.capacity(), sizeof(switch_record_t),
            "search-index switch storage exceeds memory budget");
    if (charged)
        charged = charge_live_bytes(impl->types.capacity(), sizeof(type_candidate_record_t),
            "search-index type storage exceeds memory budget");
    if (!charged)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(charged.error());
    for (const auto& dispatch : impl->switches) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        charged = charge_live_bytes(dispatch.case_targets.capacity(), sizeof(address_t),
            "search-index switch targets exceed memory budget");
        if (!charged)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(charged.error());
    }
    for (const auto& type : impl->types) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        charged = charge_live_bytes(type.display_name.capacity() +
            type.canonical_type.capacity(), 1,
            "search-index type text exceeds memory budget");
        if (!charged)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(charged.error());
    }
    std::uint64_t indexed_text_bytes = 0;
    auto add_text = [&](search_hit_t hit) -> workspace_result_t<void> {
        indexed_text_t entry;
        entry.hit = std::move(hit);
        entry.normalized = normalize_text(entry.hit.text);
        if (entry.normalized.empty())
            return workspace_result_t<void>::success();
        std::uint64_t updated = 0;
        if (!checked_add_u64(indexed_text_bytes, entry.normalized.size(), updated) ||
            updated > limits.max_indexed_text_bytes || updated > limits.max_index_bytes) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index text budget exceeded", "search_index"));
        }
        indexed_text_bytes = updated;
        auto storage = charge_live_bytes(entry.hit.text.capacity() +
            entry.normalized.capacity(), 1,
            "search-index normalized text exceeds memory budget");
        if (!storage)
            return storage;
        impl->text_entries.push_back(std::move(entry));
        return workspace_result_t<void>::success();
    };
    for (const auto& symbol : impl->snapshot->symbols) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        search_hit_t hit;
        hit.kind = symbol.kind == symbol_kind_t::function
            ? search_entity_kind_t::function : search_entity_kind_t::symbol;
        hit.entity_id = symbol.id;
        hit.address = symbol.address;
        hit.text = symbol.name;
        auto added = add_text(std::move(hit));
        if (!added)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
    }
    for (const auto& string : impl->snapshot->strings) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        search_hit_t hit;
        hit.kind = search_entity_kind_t::string;
        hit.entity_id = string.id;
        hit.address = string.address;
        hit.text = string.value;
        auto added = add_text(std::move(hit));
        if (!added)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
    }
    for (const auto& type : impl->types) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        search_hit_t hit;
        hit.kind = search_entity_kind_t::type_candidate;
        hit.entity_id = type.id;
        hit.address = type.address;
        hit.text = type.display_name.empty() ? type.canonical_type : type.display_name;
        auto added = add_text(std::move(hit));
        if (!added)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(added.error());
    }
    std::sort(impl->text_entries.begin(), impl->text_entries.end(),
        [](const indexed_text_t& lhs, const indexed_text_t& rhs) {
            if (lhs.normalized != rhs.normalized)
                return lhs.normalized < rhs.normalized;
            return hit_less(lhs.hit, rhs.hit);
        });
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
    std::uint64_t postings = 0;
    for (std::size_t entry_index = 0; entry_index < impl->text_entries.size(); ++entry_index) {
        if ((entry_index % std::max<std::uint32_t>(1, limits.cancellation_check_interval)) == 0 &&
            cancel.stop_requested()) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        }
        const auto& text = impl->text_entries[entry_index].normalized;
        std::vector<std::uint32_t> entry_keys;
        const auto key_count = text.size() >= 3 ? text.size() - 2 : 0;
        std::uint64_t key_bytes = 0;
        std::uint64_t peak_bytes = 0;
        if (!checked_mul_u64(key_count, sizeof(std::uint32_t), key_bytes) ||
            !checked_add_u64(live_index_bytes, key_bytes, peak_bytes) ||
            peak_bytes > limits.max_index_bytes) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index trigram working storage exceeds memory budget",
                    "search_index"));
        }
        entry_keys.reserve(key_count);
        for (std::size_t offset = 0; offset + 3 <= text.size(); ++offset) {
            if ((offset & 0x3FFULL) == 0 && cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel));
            entry_keys.push_back(trigram_key(text.data() + offset));
        }
        if (cancel.stop_requested())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        std::sort(entry_keys.begin(), entry_keys.end());
        entry_keys.erase(std::unique(entry_keys.begin(), entry_keys.end()), entry_keys.end());
        for (const auto key : entry_keys) {
            if (++postings > limits.max_trigram_postings) {
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    make_workspace_error(workspace_error_code_t::limit_exceeded,
                        "search-index posting budget exceeded", "search_index"));
            }
            const auto existing = impl->trigrams.find(key);
            if (existing == impl->trigrams.end()) {
                auto node_storage = charge_live_bytes(1,
                    sizeof(std::pair<const std::uint32_t, std::vector<std::uint32_t>>) +
                        sizeof(void*) * 3ULL,
                    "search-index trigram nodes exceed memory budget");
                if (!node_storage)
                    return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                        node_storage.error());
            }
            auto posting_storage = charge_live_bytes(2, sizeof(std::uint32_t),
                "search-index trigram postings exceed memory budget");
            if (!posting_storage)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    posting_storage.error());
            auto& values = impl->trigrams[key];
            const auto posting_index = static_cast<std::uint32_t>(entry_index);
            if (values.empty() || values.back() != posting_index)
                values.push_back(posting_index);
        }
        auto address_text_storage = charge_live_bytes(
            impl->text_entries[entry_index].hit.text.capacity(), 1,
            "search-index address text exceeds memory budget");
        if (!address_text_storage)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                address_text_storage.error());
        impl->address_entries.push_back(impl->text_entries[entry_index].hit);
    }
    for (std::size_t index = 0; index < impl->snapshot->instructions.size(); ++index) {
        if ((index % std::max<std::uint32_t>(1,
                limits.cancellation_check_interval)) == 0 && cancel.stop_requested()) {
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                stop_error(cancel));
        }
        const auto& instruction = impl->snapshot->instructions[index];
        const auto opcode_found = impl->opcodes.find(instruction.opcode_id);
        if (opcode_found == impl->opcodes.end()) {
            auto node_storage = charge_live_bytes(1,
                sizeof(std::pair<const std::uint32_t, std::vector<std::uint32_t>>) +
                    sizeof(void*) * 3ULL,
                "search-index opcode nodes exceed memory budget");
            if (!node_storage)
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    node_storage.error());
        }
        auto posting_storage = charge_live_bytes(2, sizeof(std::uint32_t),
            "search-index opcode postings exceed memory budget");
        if (!posting_storage)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                posting_storage.error());
        impl->opcodes[instruction.opcode_id].push_back(static_cast<std::uint32_t>(index));
        search_hit_t hit;
        hit.kind = search_entity_kind_t::instruction;
        hit.entity_id = instruction.id;
        hit.address = instruction.address;
        hit.numeric_value = instruction.opcode_id;
        impl->address_entries.push_back(std::move(hit));
    }
    std::uint64_t operand_checks = 0;
    for (const auto& operand : impl->snapshot->operand_facts) {
        if (++operand_checks >= limits.cancellation_check_interval) {
            operand_checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel));
        }
        if (operand.kind != operand_kind_t::immediate)
            continue;
        const auto found = instruction_index_for_id(operand.instruction_id,
            impl->snapshot->instructions);
        if (found) {
            const auto immediate_found = impl->immediates.find(operand.immediate);
            if (immediate_found == impl->immediates.end()) {
                auto node_storage = charge_live_bytes(1,
                    sizeof(std::pair<const std::uint64_t, std::vector<std::uint32_t>>) +
                        sizeof(void*) * 3ULL,
                    "search-index immediate nodes exceed memory budget");
                if (!node_storage)
                    return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                        node_storage.error());
            }
            auto& values = impl->immediates[operand.immediate];
            if (values.empty() || values.back() != *found) {
                auto posting_storage = charge_live_bytes(2, sizeof(std::uint32_t),
                    "search-index immediate postings exceed memory budget");
                if (!posting_storage)
                    return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                        posting_storage.error());
                values.push_back(*found);
            }
        }
    }
    for (const auto& data : impl->data_candidates) {
        if (++operand_checks >= limits.cancellation_check_interval) {
            operand_checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel));
        }
        search_hit_t hit;
        hit.kind = search_entity_kind_t::data_candidate;
        hit.entity_id = data.id;
        hit.address = data.address;
        hit.numeric_value = data.size;
        impl->address_entries.push_back(std::move(hit));
    }
    for (const auto& dispatch : impl->switches) {
        if (++operand_checks >= limits.cancellation_check_interval) {
            operand_checks = 0;
            if (cancel.stop_requested())
                return workspace_result_t<std::shared_ptr<search_index_t>>::failure(
                    stop_error(cancel));
        }
        search_hit_t hit;
        hit.kind = search_entity_kind_t::switch_dispatch;
        hit.entity_id = dispatch.id;
        hit.address = dispatch.dispatch;
        hit.numeric_value = dispatch.case_targets.size();
        impl->address_entries.push_back(std::move(hit));
    }
    std::sort(impl->address_entries.begin(), impl->address_entries.end(), hit_less);
    if (cancel.stop_requested())
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
    std::uint64_t estimated_bytes = indexed_text_bytes;
    auto add_bytes = [&](std::uint64_t count, std::uint64_t item_size)
        -> workspace_result_t<void> {
        std::uint64_t bytes = 0;
        std::uint64_t updated = 0;
        if (!checked_mul_u64(count, item_size, bytes) ||
            !checked_add_u64(estimated_bytes, bytes, updated) ||
            updated > limits.max_index_bytes) {
            return workspace_result_t<void>::failure(
                make_workspace_error(workspace_error_code_t::limit_exceeded,
                    "search-index memory budget exceeded", "search_index"));
        }
        estimated_bytes = updated;
        return workspace_result_t<void>::success();
    };
    auto memory_result = add_bytes(impl->text_entries.capacity(), sizeof(indexed_text_t));
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    memory_result = add_bytes(impl->address_entries.capacity(), sizeof(search_hit_t));
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    memory_result = add_bytes(impl->data_candidates.capacity(), sizeof(data_candidate_record_t));
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    memory_result = add_bytes(impl->switches.capacity(), sizeof(switch_record_t));
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    memory_result = add_bytes(impl->types.capacity(), sizeof(type_candidate_record_t));
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    for (const auto& entry : impl->text_entries) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(entry.hit.text.capacity() + entry.normalized.capacity(), 1);
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    for (const auto& hit : impl->address_entries) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(hit.text.capacity(), 1);
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    memory_result = add_bytes(impl->trigrams.bucket_count(), sizeof(void*));
    if (memory_result)
        memory_result = add_bytes(impl->opcodes.bucket_count(), sizeof(void*));
    if (memory_result)
        memory_result = add_bytes(impl->immediates.bucket_count(), sizeof(void*));
    if (!memory_result)
        return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    for (const auto& entry : impl->trigrams) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(1, sizeof(entry) + sizeof(void*) * 2ULL);
        if (memory_result)
            memory_result = add_bytes(entry.second.capacity(), sizeof(std::uint32_t));
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    for (const auto& entry : impl->opcodes) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(1, sizeof(entry) + sizeof(void*) * 2ULL);
        if (memory_result)
            memory_result = add_bytes(entry.second.capacity(), sizeof(std::uint32_t));
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    for (const auto& entry : impl->immediates) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(1, sizeof(entry) + sizeof(void*) * 2ULL);
        if (memory_result)
            memory_result = add_bytes(entry.second.capacity(), sizeof(std::uint32_t));
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    for (const auto& dispatch : impl->switches) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(dispatch.case_targets.capacity(), sizeof(address_t));
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    for (const auto& type : impl->types) {
        if (should_stop())
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(stop_error(cancel));
        memory_result = add_bytes(type.display_name.capacity() + type.canonical_type.capacity(), 1);
        if (!memory_result)
            return workspace_result_t<std::shared_ptr<search_index_t>>::failure(memory_result.error());
    }
    impl->memory_bytes = estimated_bytes;
    if (impl->metrics)
        impl->metrics->set(analysis_metric_t::indexed_bytes, estimated_bytes);
    return workspace_result_t<std::shared_ptr<search_index_t>>::success(
        std::shared_ptr<search_index_t>(new search_index_t(std::move(impl))));
}

std::uint64_t search_index_t::generation() const noexcept {
    return impl_->snapshot->generation;
}

const binary_id_t& search_index_t::binary_id() const noexcept {
    return impl_->snapshot->binary_id;
}

const sha256_digest_t& search_index_t::load_profile_hash() const noexcept {
    return impl_->snapshot->load_profile_hash;
}

std::uint64_t search_index_t::analysis_revision() const noexcept {
    return impl_->snapshot->analysis_revision;
}

std::uint64_t search_index_t::overlay_revision() const noexcept {
    return impl_->snapshot->overlay_revision;
}

bool search_index_t::matches(
    const std::shared_ptr<const analysis_snapshot_t>& snapshot_value) const noexcept {
    return snapshot_value && impl_->snapshot == snapshot_value &&
        impl_->snapshot->binary_id == snapshot_value->binary_id &&
        impl_->snapshot->load_profile_hash == snapshot_value->load_profile_hash &&
        impl_->snapshot->generation == snapshot_value->generation &&
        impl_->snapshot->analysis_revision == snapshot_value->analysis_revision &&
        impl_->snapshot->overlay_revision == snapshot_value->overlay_revision;
}

bool search_index_t::matches(std::uint64_t generation,
    std::uint64_t analysis_revision, std::uint64_t overlay_revision) const noexcept {
    return impl_->snapshot->generation == generation &&
        impl_->snapshot->analysis_revision == analysis_revision &&
        impl_->snapshot->overlay_revision == overlay_revision;
}

bool search_index_t::matches(const binary_id_t& binary_id_value,
    const sha256_digest_t& load_profile_hash_value, std::uint64_t generation_value,
    std::uint64_t analysis_revision_value, std::uint64_t overlay_revision_value) const noexcept {
    return impl_->snapshot->binary_id == binary_id_value &&
        impl_->snapshot->load_profile_hash == load_profile_hash_value &&
        matches(generation_value, analysis_revision_value, overlay_revision_value);
}

workspace_result_t<void> search_index_t::verify_identity(
    const binary_id_t& expected_binary_id,
    const sha256_digest_t& expected_load_profile_hash) const {
    if (impl_->snapshot->binary_id != expected_binary_id)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::substitution_rejected,
                "search index binary_id does not match the expected workspace identity",
                "search_index"));
    if (impl_->snapshot->load_profile_hash != expected_load_profile_hash)
        return workspace_result_t<void>::failure(
            make_workspace_error(workspace_error_code_t::substitution_rejected,
                "search index load_profile_hash does not match the expected workspace identity",
                "search_index"));
    return workspace_result_t<void>::success();
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
    return impl_->memory_bytes;
}

analysis_metrics_snapshot_t search_index_t::metrics() const noexcept {
    return impl_->metrics ? impl_->metrics->snapshot() : analysis_metrics_snapshot_t{};
}

workspace_result_t<search_page_t> search_index_t::find_text(const std::string& text,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "search_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    if (text.empty() || text.size() > impl_->limits.max_query_bytes) {
        auto error = make_workspace_error(workspace_error_code_t::invalid_argument,
            "text search query is outside the allowed byte range", "search_index");
        error.details.emplace_back("maximum",
            std::to_string(impl_->limits.max_query_bytes));
        return workspace_result_t<search_page_t>::failure(std::move(error));
    }
    const auto normalized = normalize_text(text);
    if (normalized.empty()) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "text search requires a non-empty query", "search_index"));
    }
    const std::vector<std::uint32_t>* candidates = nullptr;
    if (normalized.size() >= 3) {
        std::vector<std::uint32_t> keys;
        keys.reserve(normalized.size() - 2);
        for (std::size_t index = 0; index + 3 <= normalized.size(); ++index) {
            if ((index & 0x3FFULL) == 0 && cancel.stop_requested())
                return workspace_result_t<search_page_t>::failure(stop_error(cancel));
            keys.push_back(trigram_key(normalized.data() + index));
        }
        std::sort(keys.begin(), keys.end());
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        for (const auto key : keys) {
            const auto found = impl_->trigrams.find(key);
            if (found == impl_->trigrams.end())
                return workspace_result_t<search_page_t>::success({});
            if (!candidates || found->second.size() < candidates->size())
                candidates = &found->second;
        }
    }
    search_page_t page;
    page.hits.reserve(limit);
    const auto candidate_count = candidates ? candidates->size() : impl_->text_entries.size();
    for (std::size_t candidate_index = 0; candidate_index < candidate_count;
         ++candidate_index) {
        if ((candidate_index % std::max<std::uint32_t>(1,
                impl_->limits.cancellation_check_interval)) == 0 &&
            cancel.stop_requested()) {
            return workspace_result_t<search_page_t>::failure(stop_error(cancel));
        }
        const auto index = candidates ? (*candidates)[candidate_index]
            : static_cast<std::uint32_t>(candidate_index);
        if (index < impl_->text_entries.size() &&
            impl_->text_entries[index].normalized.find(normalized) != std::string::npos) {
            const auto match_index = page.total++;
            if (match_index >= offset && page.hits.size() < limit)
                page.hits.push_back(impl_->text_entries[index].hit);
        }
    }
    if (offset >= page.total)
        page.next_offset = page.total;
    else
        page.next_offset = offset + page.hits.size();
    page.truncated = page.next_offset < page.total;
    return workspace_result_t<search_page_t>::success(std::move(page));
}

workspace_result_t<search_page_t> search_index_t::find_opcode(std::uint32_t opcode_id,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "search_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    const auto found = impl_->opcodes.find(opcode_id);
    if (found == impl_->opcodes.end())
        return workspace_result_t<search_page_t>::success({});
    return page_indices(found->second, offset, limit, cancel, [&](std::uint32_t index) {
        search_hit_t hit;
        if (index < impl_->snapshot->instructions.size()) {
            const auto& instruction = impl_->snapshot->instructions[index];
            hit.kind = search_entity_kind_t::instruction;
            hit.entity_id = instruction.id;
            hit.address = instruction.address;
            hit.numeric_value = instruction.opcode_id;
        }
        return hit;
    });
}

workspace_result_t<search_page_t> search_index_t::find_immediate(std::uint64_t value,
    std::uint64_t offset, std::uint32_t limit, const cancellation_token_t& cancel) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "search_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    const auto found = impl_->immediates.find(value);
    if (found == impl_->immediates.end())
        return workspace_result_t<search_page_t>::success({});
    return page_indices(found->second, offset, limit, cancel, [&](std::uint32_t index) {
        search_hit_t hit;
        if (index < impl_->snapshot->instructions.size()) {
            const auto& instruction = impl_->snapshot->instructions[index];
            hit.kind = search_entity_kind_t::instruction;
            hit.entity_id = instruction.id;
            hit.address = instruction.address;
            hit.numeric_value = value;
        }
        return hit;
    });
}

workspace_result_t<search_page_t> search_index_t::find_address_range(
    const address_t& begin, const address_t& end, std::uint64_t offset,
    std::uint32_t limit, const cancellation_token_t& cancel) const {
    auto valid = validate_page(limit, impl_->limits.max_results_per_query, "search_index");
    if (!valid)
        return workspace_result_t<search_page_t>::failure(valid.error());
    if (end < begin || begin.space != end.space ||
        begin.architecture != end.architecture || begin.mode != end.mode) {
        return workspace_result_t<search_page_t>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                "address search range is invalid", "search_index"));
    }
    const auto first = std::lower_bound(impl_->address_entries.begin(),
        impl_->address_entries.end(), begin,
        [](const search_hit_t& hit, const address_t& address) {
            return hit.address < address;
        });
    const auto finish = std::lower_bound(first, impl_->address_entries.end(), end,
        [](const search_hit_t& hit, const address_t& address) {
            return hit.address < address;
        });
    search_page_t page;
    page.total = static_cast<std::uint64_t>(finish - first);
    if (offset >= page.total) {
        page.next_offset = page.total;
        return workspace_result_t<search_page_t>::success(std::move(page));
    }
    const auto count = std::min<std::uint64_t>(page.total - offset, limit);
    page.hits.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        if ((index & 0x3FFULL) == 0 && cancel.stop_requested())
            return workspace_result_t<search_page_t>::failure(stop_error(cancel));
        page.hits.push_back(*(first + static_cast<std::ptrdiff_t>(offset + index)));
    }
    page.next_offset = offset + count;
    page.truncated = page.next_offset < page.total;
    return workspace_result_t<search_page_t>::success(std::move(page));
}

}
