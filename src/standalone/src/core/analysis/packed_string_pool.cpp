#include "packed_string_pool.hpp"

#include <algorithm>
#include <limits>

namespace aida::analysis {
namespace {

packed_store_error_t make_error(packed_store_error_code_t code, std::string_view phase,
                                std::uint64_t subject = 0, std::uint64_t expected = 0,
                                std::uint64_t actual = 0) noexcept
{
    return packed_store_error_t{code, phase, 0, subject, expected, actual};
}

std::uint64_t vector_payload_bytes(std::size_t size, std::size_t element_size) noexcept
{
    return static_cast<std::uint64_t>(size) * static_cast<std::uint64_t>(element_size);
}

std::uint64_t vector_reserved_bytes(std::size_t capacity, std::size_t element_size) noexcept
{
    return static_cast<std::uint64_t>(capacity) * static_cast<std::uint64_t>(element_size);
}

}

packed_store_result_t<packed_string_pool_t>
packed_string_pool_t::build_deterministic(std::vector<std::string> values)
{
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return build_preserving_order(values);
}

packed_store_result_t<packed_string_pool_t>
packed_string_pool_t::build_preserving_order(const std::vector<std::string>& values)
{
    if (values.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
        return packed_store_result_t<packed_string_pool_t>::failure(make_error(
            packed_store_error_code_t::string_too_large, "string_pool", 0,
            (std::numeric_limits<std::uint32_t>::max)(), values.size()));
    }

    std::uint64_t total_bytes = 0;
    for (const auto& value : values) {
        if (value.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
            return packed_store_result_t<packed_string_pool_t>::failure(make_error(
                packed_store_error_code_t::string_too_large, "string_pool", 0,
                (std::numeric_limits<std::uint32_t>::max)(), value.size()));
        }
        if (total_bytes > (std::numeric_limits<std::uint32_t>::max)() - value.size()) {
            return packed_store_result_t<packed_string_pool_t>::failure(make_error(
                packed_store_error_code_t::string_too_large, "string_pool", 0,
                (std::numeric_limits<std::uint32_t>::max)(), total_bytes + value.size()));
        }
        total_bytes += value.size();
    }

    packed_string_pool_t pool;
    pool.offsets_.reserve(values.size());
    pool.lengths_.reserve(values.size());
    pool.bytes_.reserve(static_cast<std::size_t>(total_bytes));
    for (const auto& value : values) {
        pool.offsets_.push_back(static_cast<std::uint32_t>(pool.bytes_.size()));
        pool.lengths_.push_back(static_cast<std::uint32_t>(value.size()));
        pool.bytes_.insert(pool.bytes_.end(), value.begin(), value.end());
    }
    return packed_store_result_t<packed_string_pool_t>::success(std::move(pool));
}

std::uint32_t packed_string_pool_t::size() const noexcept
{
    return static_cast<std::uint32_t>(offsets_.size());
}

std::optional<std::string_view> packed_string_pool_t::lookup(packed_string_id_t id) const noexcept
{
    if (!id.valid())
        return std::nullopt;
    const std::size_t index = static_cast<std::size_t>(id.value() - 1U);
    if (index >= offsets_.size() || index >= lengths_.size())
        return std::nullopt;
    const std::size_t offset = offsets_[index];
    const std::size_t length = lengths_[index];
    if (offset > bytes_.size() || length > bytes_.size() - offset)
        return std::nullopt;
    if (length == 0)
        return std::string_view();
    return std::string_view(bytes_.data() + offset, length);
}

packed_store_result_t<void> packed_string_pool_t::validate() const noexcept
{
    if (offsets_.size() != lengths_.size()) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_string_pool, "string_pool", 0, offsets_.size(),
            lengths_.size()));
    }
    std::uint32_t previous_end = 0;
    for (std::size_t index = 0; index < offsets_.size(); ++index) {
        const std::uint32_t offset = offsets_[index];
        const std::uint32_t length = lengths_[index];
        if (offset < previous_end || offset > bytes_.size() || length > bytes_.size() - offset) {
            return packed_store_result_t<void>::failure(make_error(
                packed_store_error_code_t::invalid_string_pool, "string_pool", index + 1U,
                bytes_.size(), static_cast<std::uint64_t>(offset) + length));
        }
        previous_end = offset + length;
    }
    if (!offsets_.empty() && previous_end != bytes_.size()) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_string_pool, "string_pool", offsets_.size(),
            bytes_.size(), previous_end));
    }
    if (offsets_.empty() && !bytes_.empty()) {
        return packed_store_result_t<void>::failure(make_error(
            packed_store_error_code_t::invalid_string_pool, "string_pool", 0, 0,
            bytes_.size()));
    }
    return packed_store_result_t<void>::success();
}

packed_string_pool_size_t packed_string_pool_t::size_accounting() const noexcept
{
    const auto payload = vector_payload_bytes(offsets_.size(), sizeof(std::uint32_t)) +
        vector_payload_bytes(lengths_.size(), sizeof(std::uint32_t)) +
        vector_payload_bytes(bytes_.size(), sizeof(char));
    const auto reserved = vector_reserved_bytes(offsets_.capacity(), sizeof(std::uint32_t)) +
        vector_reserved_bytes(lengths_.capacity(), sizeof(std::uint32_t)) +
        vector_reserved_bytes(bytes_.capacity(), sizeof(char));
    return packed_string_pool_size_t{offsets_.size(), payload, reserved};
}

packed_store_result_t<packed_string_id_t> packed_string_pool_builder_t::intern(std::string_view value)
{
    const std::string key(value);
    const auto existing = index_.find(key);
    if (existing != index_.end())
        return packed_store_result_t<packed_string_id_t>::success(existing->second);
    if (key.size() > static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) ||
        values_.size() >= static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())) {
        return packed_store_result_t<packed_string_id_t>::failure(make_error(
            packed_store_error_code_t::string_too_large, "string_pool_builder", 0,
            (std::numeric_limits<std::uint32_t>::max)(), key.size()));
    }
    const auto id = packed_string_id_t(static_cast<std::uint32_t>(values_.size() + 1U));
    values_.push_back(key);
    index_.emplace(values_.back(), id);
    return packed_store_result_t<packed_string_id_t>::success(id);
}

packed_store_result_t<packed_string_pool_t> packed_string_pool_builder_t::freeze() const
{
    return packed_string_pool_t::build_preserving_order(values_);
}

std::uint32_t packed_string_pool_builder_t::size() const noexcept
{
    return static_cast<std::uint32_t>(values_.size());
}

}
