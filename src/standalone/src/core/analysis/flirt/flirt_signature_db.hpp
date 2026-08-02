#pragma once

#include "../workspace/byte_provider.hpp"
#include "../workspace/workspace_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aida::analysis::flirt {

inline constexpr std::uint32_t k_afdb_magic = 0x31534641u;
inline constexpr std::uint32_t k_afdb_version = 1u;
inline constexpr std::size_t k_afdb_header_bytes = 60;
inline constexpr std::size_t k_afdb_entry_bytes = 64;
inline constexpr std::size_t k_afdb_max_pattern_bytes = 32;
inline constexpr std::size_t k_afdb_min_pattern_bytes = 16;
inline constexpr std::size_t k_afdb_prefix_bytes = 8;
inline constexpr std::uint32_t k_afdb_max_entries = 1u << 20;
inline constexpr std::uint32_t k_afdb_min_significant_bits = 12;

inline constexpr std::uint16_t k_afdb_sig_flag_noreturn = 0x0001u;
inline constexpr std::uint16_t k_afdb_sig_flag_crt_runtime = 0x0002u;
inline constexpr std::uint16_t k_afdb_sig_flag_stl = 0x0004u;

std::uint16_t crc16_ccitt_false(const std::uint8_t* data, std::size_t size) noexcept;

struct flirt_db_build_entry_t {
    std::uint64_t prefix8 = 0;
    std::uint8_t pattern_len = 0;
    std::uint32_t mask = 0;
    std::uint8_t bytes[k_afdb_max_pattern_bytes]{};
    std::uint16_t tail_crc16 = 0;
    std::uint32_t func_size = 0;
    std::string name;
    std::uint16_t sig_flags = 0;
};

struct flirt_db_entry_view_t {
    std::uint64_t prefix8 = 0;
    std::uint8_t pattern_len = 0;
    std::uint32_t mask = 0;
    const std::uint8_t* bytes = nullptr;
    std::uint16_t tail_crc16 = 0;
    std::uint32_t func_size = 0;
    std::string_view name;
    std::uint16_t sig_flags = 0;
    std::uint32_t index = 0;
};

class flirt_signature_db_t {
public:
    static std::shared_ptr<const flirt_signature_db_t> load_embedded();
    static workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>
        load_from_file(const std::string& utf8_path);
    static workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>
        load_from_blob(const std::uint8_t* data, std::size_t size,
                       std::string_view source_label);

    std::uint32_t entry_count() const noexcept { return entry_count_; }
    bool empty() const noexcept { return entry_count_ == 0; }
    const std::string& toolset() const noexcept { return toolset_; }
    const std::string& source_label() const noexcept { return source_label_; }

    bool entry(std::uint32_t index, flirt_db_entry_view_t& out) const noexcept;
    std::pair<std::uint32_t, std::uint32_t> bucket(std::uint64_t prefix8) const noexcept;
    std::size_t bucket_count() const noexcept { return buckets_.size(); }
    std::size_t largest_bucket() const noexcept { return largest_bucket_; }

private:
    std::vector<std::uint8_t> blob_;
    std::string toolset_;
    std::string source_label_;
    std::uint32_t entry_count_ = 0;
    std::uint32_t entries_offset_ = 0;
    std::uint32_t string_offset_ = 0;
    std::uint32_t string_bytes_ = 0;
    std::unordered_map<std::uint64_t, std::pair<std::uint32_t, std::uint32_t>> buckets_;
    std::size_t largest_bucket_ = 0;
};

workspace_result_t<std::vector<std::uint8_t>>
serialize_afdb(const std::vector<flirt_db_build_entry_t>& entries,
               std::string_view toolset);

}
