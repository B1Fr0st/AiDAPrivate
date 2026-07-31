#pragma once

#include "string_arena.hpp"

namespace aida::analysis {

inline string_arena_t::string_arena_t(std::uint64_t max_bytes, std::uint64_t max_strings) noexcept
    : max_bytes_(max_bytes), max_strings_(max_strings)
{
    entries_.push_back(entry_t{});
}

inline std::uint64_t string_arena_t::hash_bytes(std::string_view value) noexcept
{
    std::uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    hash ^= value.size();
    hash *= 1099511628211ULL;
    return hash;
}

inline string_arena_t::id_type string_arena_t::intern(std::string_view value) noexcept
{
    if (value.empty())
        return null_id;
    if (value.size() > max_bytes_ ||
        static_cast<std::uint64_t>(entries_.size()) >= max_strings_) {
        ++dropped_strings_;
        return null_id;
    }
    const std::uint64_t hash = hash_bytes(value);
    const auto bucket = buckets_.find(hash);
    if (bucket != buckets_.end()) {
        for (const id_type candidate : bucket->second) {
            if (view(candidate) == value)
                return candidate;
        }
    }
    if (value.size() > max_bytes_ - bytes_.size()) {
        ++dropped_strings_;
        return null_id;
    }
    const std::uint64_t offset = bytes_.size();
    bytes_.insert(bytes_.end(), value.begin(), value.end());
    const id_type id = static_cast<id_type>(entries_.size());
    entries_.push_back(entry_t{static_cast<std::uint32_t>(offset),
                               static_cast<std::uint32_t>(value.size())});
    buckets_[hash].push_back(id);
    return id;
}

inline std::string_view string_arena_t::view(id_type id) const noexcept
{
    if (id >= entries_.size())
        return {};
    const entry_t& entry = entries_[id];
    if (entry.length == 0)
        return {};
    return std::string_view(bytes_.data() + entry.offset, entry.length);
}

inline std::string string_arena_t::str(id_type id) const
{
    const std::string_view value = view(id);
    return std::string(value.data(), value.size());
}

inline bool string_arena_t::contains(id_type id) const noexcept
{
    return id < entries_.size();
}

inline std::uint64_t string_arena_t::size() const noexcept
{
    return entries_.size();
}

inline std::uint64_t string_arena_t::byte_size() const noexcept
{
    return bytes_.size();
}

inline std::uint64_t string_arena_t::reserved_bytes() const noexcept
{
    return static_cast<std::uint64_t>(bytes_.capacity()) +
        static_cast<std::uint64_t>(entries_.capacity()) * sizeof(entry_t);
}

inline std::uint64_t string_arena_t::max_bytes() const noexcept
{
    return max_bytes_;
}

inline std::uint64_t string_arena_t::dropped_strings() const noexcept
{
    return dropped_strings_;
}

inline bool string_arena_t::full() const noexcept
{
    return bytes_.size() >= max_bytes_ ||
        static_cast<std::uint64_t>(entries_.size()) >= max_strings_;
}

inline void string_arena_t::reserve(std::uint64_t bytes, std::uint64_t strings)
{
    bytes_.reserve(static_cast<std::size_t>(bytes));
    entries_.reserve(static_cast<std::size_t>(strings));
    buckets_.reserve(static_cast<std::size_t>(strings));
}

inline void string_arena_t::clear() noexcept
{
    bytes_.clear();
    entries_.clear();
    entries_.push_back(entry_t{});
    buckets_.clear();
    dropped_strings_ = 0;
}

}
