#include "target_resolver.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <mutex>
#include <utility>

namespace aida::standalone::mcp::compat {

namespace {

constexpr std::size_t k_max_bin_name_bytes = 1024;

std::string_view stable_code_for(target_resolution_error_code_t code) noexcept {
    switch (code) {
    case target_resolution_error_code_t::none:
        return "ok";
    case target_resolution_error_code_t::invalid_target_record:
        return "target_record_invalid";
    case target_resolution_error_code_t::invalid_selector:
        return "target_selector_invalid";
    case target_resolution_error_code_t::target_selection_required:
        return "target_selection_required";
    case target_resolution_error_code_t::target_not_found:
        return "target_not_found";
    case target_resolution_error_code_t::target_ambiguous:
        return "target_ambiguous";
    case target_resolution_error_code_t::target_generation_stale:
        return "target_generation_stale";
    case target_resolution_error_code_t::target_pid_reused:
        return "target_pid_reused";
    case target_resolution_error_code_t::target_retired:
        return "target_retired";
    }
    return "target_resolver_unknown";
}

bool nonzero_range(std::uint64_t base, std::uint64_t size) noexcept {
    return base != 0 && size != 0 && size <= (std::numeric_limits<std::uint64_t>::max)() - base;
}

}

target_resolution_t::target_resolution_t(target_record_t target,
                                          std::uint64_t resolver_revision) noexcept
    : target_(std::move(target)), resolver_revision_(resolver_revision) {}

bool target_resolution_t::valid() const noexcept {
    return target_.target_id != 0 && target_.pid != 0 && target_.process_creation_identity != 0 &&
        target_.generation != 0 && target_.revision != 0 && resolver_revision_ != 0;
}

const target_record_t& target_resolution_t::target() const noexcept {
    return target_;
}

std::uint64_t target_resolution_t::resolver_revision() const noexcept {
    return resolver_revision_;
}

target_resolution_result_t::target_resolution_result_t(target_resolution_t value) noexcept
    : value_(std::move(value)) {}

target_resolution_result_t::target_resolution_result_t(target_resolution_error_t error) noexcept
    : error_(error) {}

target_resolution_result_t target_resolution_result_t::success(target_resolution_t value) noexcept {
    return target_resolution_result_t(std::move(value));
}

target_resolution_result_t target_resolution_result_t::failure(target_resolution_error_t error) noexcept {
    return target_resolution_result_t(error);
}

bool target_resolution_result_t::has_value() const noexcept {
    return value_.has_value();
}

target_resolution_result_t::operator bool() const noexcept {
    return has_value();
}

const target_resolution_t& target_resolution_result_t::value() const noexcept {
    return *value_;
}

target_resolution_t target_resolution_result_t::take_value() && noexcept {
    return std::move(*value_);
}

const target_resolution_error_t& target_resolution_result_t::error() const noexcept {
    return error_;
}

target_execution_pin_t::target_execution_pin_t(std::shared_lock<std::shared_mutex> lock,
                                               target_resolution_t resolution) noexcept
    : lock_(std::move(lock)), resolution_(std::move(resolution)) {}

bool target_execution_pin_t::owns_pin() const noexcept {
    return lock_.owns_lock() && resolution_.valid();
}

const target_resolution_t& target_execution_pin_t::resolution() const noexcept {
    return resolution_;
}

const target_record_t& target_execution_pin_t::target() const noexcept {
    return resolution_.target();
}

bool target_execution_pin_result_t::has_value() const noexcept {
    return pin.owns_pin();
}

target_execution_pin_result_t::operator bool() const noexcept {
    return has_value();
}

bool target_resolver_status_t::succeeded() const noexcept {
    return !error;
}

target_resolver_status_t::operator bool() const noexcept {
    return succeeded();
}

target_resolution_error_t target_resolver_t::make_error(target_resolution_error_code_t code,
                                                         std::uint64_t expected,
                                                         std::uint64_t actual) noexcept {
    return {code, stable_code_for(code), expected, actual};
}

bool target_resolver_t::valid_record(const target_record_t& record) noexcept {
    if (record.target_id == 0 || record.pid == 0 || record.process_creation_identity == 0 ||
        record.bin_name.empty() || record.bin_name.size() > k_max_bin_name_bytes || record.generation == 0 ||
        record.attach_generation == 0) {
        return false;
    }
    if (!record.live) {
        return record.live_capture_base == 0 && record.live_capture_size == 0 &&
            !record.live_snapshot_permitted && record.live_snapshot_maximum_bytes == 0;
    }
    if (!nonzero_range(record.live_capture_base, record.live_capture_size)) {
        return false;
    }
    if (!record.live_snapshot_permitted) {
        return record.live_snapshot_maximum_bytes == 0;
    }
    return record.live_snapshot_maximum_bytes != 0 &&
        record.live_snapshot_maximum_bytes <= record.live_capture_size;
}

bool target_resolver_t::valid_selector(const target_selector_t& selector) noexcept {
    if (selector.pid && *selector.pid == 0) {
        return false;
    }
    if (selector.bin_name &&
        (selector.bin_name->empty() || selector.bin_name->size() > k_max_bin_name_bytes)) {
        return false;
    }
    return true;
}

std::string target_resolver_t::canonical_bin_name(std::string_view value) {
    const auto separator = value.find_last_of("\\/");
    if (separator != std::string_view::npos) {
        value.remove_prefix(separator + 1);
    }
    std::string canonical;
    canonical.reserve(value.size());
    for (const char character : value) {
        canonical.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }
    return canonical;
}

bool target_resolver_t::record_matches_pid(const target_record_t& record,
                                           const target_selector_t& selector) noexcept {
    return !selector.pid || record.pid == *selector.pid;
}

bool target_resolver_t::record_matches_exact_name(const target_record_t& record,
                                                  std::string_view canonical_name) noexcept {
    return canonical_name.empty() || canonical_bin_name(record.bin_name) == canonical_name;
}

bool target_resolver_t::record_matches_substring(const target_record_t& record,
                                                 std::string_view canonical_name) noexcept {
    return canonical_name.empty() ||
        canonical_bin_name(record.bin_name).find(canonical_name) != std::string::npos;
}

target_resolver_status_t target_resolver_t::publish(target_record_t record) {
    if (!valid_record(record)) {
        return {make_error(target_resolution_error_code_t::invalid_target_record)};
    }
    record.bin_name = canonical_bin_name(record.bin_name);
    if (record.bin_name.empty()) {
        return {make_error(target_resolution_error_code_t::invalid_target_record)};
    }

    std::unique_lock execution_lock(execution_mutex_);
    std::unique_lock lock(mutex_);
    for (auto iterator = active_.begin(); iterator != active_.end();) {
        if (iterator->second.pid == record.pid &&
            iterator->second.process_creation_identity != record.process_creation_identity) {
            retired_[iterator->first] = {
                make_error(target_resolution_error_code_t::target_pid_reused,
                           iterator->second.process_creation_identity,
                           record.process_creation_identity)};
            iterator = active_.erase(iterator);
        } else {
            ++iterator;
        }
    }
    const auto target_id = record.target_id;
    record.revision = next_revision_++;
    active_[target_id] = std::move(record);
    retired_.erase(target_id);
    return {};
}

target_resolver_status_t target_resolver_t::retire(std::uint64_t target_id) {
    if (target_id == 0) {
        return {make_error(target_resolution_error_code_t::invalid_target_record)};
    }
    std::unique_lock execution_lock(execution_mutex_);
    std::unique_lock lock(mutex_);
    const auto iterator = active_.find(target_id);
    if (iterator == active_.end()) {
        return {make_error(target_resolution_error_code_t::target_not_found)};
    }
    retired_[target_id] = {make_error(target_resolution_error_code_t::target_retired)};
    active_.erase(iterator);
    return {};
}

target_resolution_result_t target_resolver_t::resolve(
    const target_selector_t& selector, std::optional<std::uint64_t> expected_generation,
    target_resolution_options_t options) const {
    if (!valid_selector(selector)) {
        return target_resolution_result_t::failure(
            make_error(target_resolution_error_code_t::invalid_selector));
    }
    if (expected_generation && *expected_generation == 0) {
        return target_resolution_result_t::failure(
            make_error(target_resolution_error_code_t::target_generation_stale, 1, 0));
    }

    const auto canonical_name = selector.bin_name ? canonical_bin_name(*selector.bin_name) : std::string{};
    if (selector.bin_name && canonical_name.empty()) {
        return target_resolution_result_t::failure(
            make_error(target_resolution_error_code_t::invalid_selector));
    }

    std::shared_lock lock(mutex_);
    std::vector<const target_record_t*> candidates;
    candidates.reserve(active_.size());
    for (const auto& [target_id, record] : active_) {
        if (record_matches_pid(record, selector)) {
            candidates.push_back(&record);
        }
    }
    if (selector.bin_name) {
        std::vector<const target_record_t*> exact;
        exact.reserve(candidates.size());
        for (const auto* record : candidates) {
            if (record_matches_exact_name(*record, canonical_name)) {
                exact.push_back(record);
            }
        }
        if (!exact.empty()) {
            candidates = std::move(exact);
        } else if (options.allow_unique_substring) {
            candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                [&canonical_name](const target_record_t* record) {
                    return !record_matches_substring(*record, canonical_name);
                }), candidates.end());
        } else {
            candidates.clear();
        }
    }
    if (candidates.empty()) {
        return target_resolution_result_t::failure(
            make_error(target_resolution_error_code_t::target_not_found));
    }
    if (candidates.size() > 1) {
        const auto code = !selector.pid && !selector.bin_name && options.require_selector_when_multiple
            ? target_resolution_error_code_t::target_selection_required
            : target_resolution_error_code_t::target_ambiguous;
        return target_resolution_result_t::failure(
            make_error(code, 1, candidates.size()));
    }

    const auto& selected = *candidates.front();
    if (expected_generation && selected.generation != *expected_generation) {
        return target_resolution_result_t::failure(
            make_error(target_resolution_error_code_t::target_generation_stale,
                       *expected_generation, selected.generation));
    }
    return target_resolution_result_t::success(target_resolution_t(selected, selected.revision));
}

target_resolver_status_t target_resolver_t::validate_current(
    const target_resolution_t& resolution, std::optional<std::uint64_t> expected_generation) const {
    if (!resolution.valid()) {
        return {make_error(target_resolution_error_code_t::invalid_target_record)};
    }
    if (expected_generation && *expected_generation == 0) {
        return {make_error(target_resolution_error_code_t::target_generation_stale, 1, 0)};
    }

    std::shared_lock lock(mutex_);
    const auto active = active_.find(resolution.target().target_id);
    if (active == active_.end()) {
        const auto retired = retired_.find(resolution.target().target_id);
        if (retired != retired_.end()) {
            return {retired->second.error};
        }
        return {make_error(target_resolution_error_code_t::target_retired)};
    }
    const auto& current = active->second;
    if (current.pid != resolution.target().pid ||
        current.process_creation_identity != resolution.target().process_creation_identity) {
        return {make_error(target_resolution_error_code_t::target_pid_reused,
                           resolution.target().process_creation_identity,
                           current.process_creation_identity)};
    }
    if (current.generation != resolution.target().generation ||
        (expected_generation && current.generation != *expected_generation)) {
        return {make_error(target_resolution_error_code_t::target_generation_stale,
                           expected_generation.value_or(resolution.target().generation),
                           current.generation)};
    }
    if (current.revision != resolution.target().revision ||
        current.revision != resolution.resolver_revision()) {
        return {make_error(target_resolution_error_code_t::target_retired,
                           resolution.target().revision, current.revision)};
    }
    return {};
}

target_execution_pin_result_t target_resolver_t::pin_current(
    const target_resolution_t& resolution,
    std::optional<std::uint64_t> expected_generation) const {
    std::shared_lock execution_lock(execution_mutex_);
    const auto current = validate_current(resolution, expected_generation);
    if (!current) {
        return {{}, current.error};
    }
    return {target_execution_pin_t(std::move(execution_lock), resolution), {}};
}

std::vector<target_record_t> target_resolver_t::snapshot() const {
    std::shared_lock lock(mutex_);
    std::vector<target_record_t> records;
    records.reserve(active_.size());
    for (const auto& [target_id, record] : active_) {
        records.push_back(record);
    }
    std::sort(records.begin(), records.end(), [](const target_record_t& left,
                                                 const target_record_t& right) {
        return left.target_id < right.target_id;
    });
    return records;
}

}
