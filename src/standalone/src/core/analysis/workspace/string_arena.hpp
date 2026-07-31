#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aida::analysis {

class string_arena_t final {
public:
    using id_type = std::uint32_t;

    static constexpr id_type null_id = 0;
    static constexpr std::uint64_t default_max_bytes = 1ULL << 30;
    static constexpr std::uint64_t default_max_strings = (1ULL << 31) - 1ULL;

    explicit string_arena_t(std::uint64_t max_bytes = default_max_bytes,
                            std::uint64_t max_strings = default_max_strings) noexcept;

    string_arena_t(const string_arena_t&) = delete;
    string_arena_t& operator=(const string_arena_t&) = delete;
    string_arena_t(string_arena_t&&) noexcept = default;
    string_arena_t& operator=(string_arena_t&&) noexcept = default;

    id_type intern(std::string_view value) noexcept;
    std::string_view view(id_type id) const noexcept;
    std::string str(id_type id) const;
    bool contains(id_type id) const noexcept;

    std::uint64_t size() const noexcept;
    std::uint64_t byte_size() const noexcept;
    std::uint64_t reserved_bytes() const noexcept;
    std::uint64_t max_bytes() const noexcept;
    std::uint64_t dropped_strings() const noexcept;
    bool full() const noexcept;

    void reserve(std::uint64_t bytes, std::uint64_t strings);
    void clear() noexcept;

private:
    struct entry_t final {
        std::uint32_t offset = 0;
        std::uint32_t length = 0;
    };

    static std::uint64_t hash_bytes(std::string_view value) noexcept;

    std::vector<char> bytes_;
    std::vector<entry_t> entries_;
    std::unordered_map<std::uint64_t, std::vector<id_type>> buckets_;
    std::uint64_t max_bytes_ = default_max_bytes;
    std::uint64_t max_strings_ = default_max_strings;
    std::uint64_t dropped_strings_ = 0;
};

}

#include "string_arena.cpp"
