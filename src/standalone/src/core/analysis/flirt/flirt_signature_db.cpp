#include "flirt_signature_db.hpp"

#include "flirt_signature_db_seed.hpp"

#include "../../../helpers/diag_log.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace aida::analysis::flirt {
namespace {

std::uint32_t read_u32_le(const std::uint8_t* p) noexcept
{
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

std::uint16_t read_u16_le(const std::uint8_t* p) noexcept
{
    std::uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

std::uint64_t read_u64_le(const std::uint8_t* p) noexcept
{
    std::uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

void write_u16_le(std::uint8_t* p, std::uint16_t v) noexcept
{
    std::memcpy(p, &v, sizeof(v));
}

void write_u32_le(std::uint8_t* p, std::uint32_t v) noexcept
{
    std::memcpy(p, &v, sizeof(v));
}

void write_u64_le(std::uint8_t* p, std::uint64_t v) noexcept
{
    std::memcpy(p, &v, sizeof(v));
}

std::uint32_t popcount32(std::uint32_t v) noexcept
{
    v -= (v >> 1) & 0x55555555u;
    v = (v & 0x33333333u) + ((v >> 2) & 0x33333333u);
    return (((v + (v >> 4)) & 0x0F0F0F0Fu) * 0x01010101u) >> 24;
}

bool name_bytes_valid(const std::uint8_t* p, std::size_t size) noexcept
{
    if (size == 0 || size > 240)
        return false;
    for (std::size_t i = 0; i < size; ++i)
        if (p[i] < 0x21 || p[i] > 0x7E)
            return false;
    return true;
}

}

std::uint16_t crc16_ccitt_false(const std::uint8_t* data, std::size_t size) noexcept
{
    std::uint16_t crc = 0xFFFFu;
    for (std::size_t i = 0; i < size; ++i) {
        crc = static_cast<std::uint16_t>(crc ^ static_cast<std::uint16_t>(data[i] << 8));
        for (int bit = 0; bit < 8; ++bit)
            crc = static_cast<std::uint16_t>((crc & 0x8000u) != 0
                ? static_cast<std::uint16_t>((crc << 1) ^ 0x1021u)
                : static_cast<std::uint16_t>(crc << 1));
    }
    return crc;
}

workspace_result_t<std::vector<std::uint8_t>>
serialize_afdb(const std::vector<flirt_db_build_entry_t>& entries,
               std::string_view toolset)
{
    if (entries.size() > k_afdb_max_entries)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "FLIRT database entry count exceeds the format limit", "flirt.serialize"));
    struct normalized_entry_t {
        flirt_db_build_entry_t entry;
        std::uint32_t name_off = 0;
    };
    std::vector<normalized_entry_t> normalized;
    normalized.reserve(entries.size());
    for (const auto& source : entries) {
        normalized_entry_t item;
        item.entry = source;
        if (item.entry.pattern_len < k_afdb_min_pattern_bytes ||
            item.entry.pattern_len > k_afdb_max_pattern_bytes)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "FLIRT database entry pattern length is outside [16,32]", "flirt.serialize"));
        if (popcount32(item.entry.mask) < k_afdb_min_significant_bits)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "FLIRT database entry has fewer than 12 significant mask bits", "flirt.serialize"));
        if ((item.entry.mask & 0xFFu) != 0xFFu)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "FLIRT database entry prefix is not wildcard-free", "flirt.serialize"));
        for (std::size_t i = 0; i < k_afdb_max_pattern_bytes; ++i)
            if ((item.entry.mask & (1u << i)) == 0)
                item.entry.bytes[i] = 0;
        std::memcpy(&item.entry.prefix8, item.entry.bytes, sizeof(item.entry.prefix8));
        std::uint8_t tail[k_afdb_max_pattern_bytes]{};
        for (std::size_t i = k_afdb_prefix_bytes; i < item.entry.pattern_len; ++i)
            if ((item.entry.mask & (1u << i)) != 0)
                tail[i] = item.entry.bytes[i];
        item.entry.tail_crc16 = crc16_ccitt_false(
            tail + k_afdb_prefix_bytes, item.entry.pattern_len - k_afdb_prefix_bytes);
        if (!name_bytes_valid(reinterpret_cast<const std::uint8_t*>(item.entry.name.data()),
                              item.entry.name.size()))
            return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
                workspace_error_code_t::invalid_argument,
                "FLIRT database entry name is not printable ASCII", "flirt.serialize"));
        normalized.push_back(std::move(item));
    }
    std::sort(normalized.begin(), normalized.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.entry.prefix8 != rhs.entry.prefix8)
            return lhs.entry.prefix8 < rhs.entry.prefix8;
        if (lhs.entry.name != rhs.entry.name)
            return lhs.entry.name < rhs.entry.name;
        if (lhs.entry.mask != rhs.entry.mask)
            return lhs.entry.mask < rhs.entry.mask;
        return std::memcmp(lhs.entry.bytes, rhs.entry.bytes, k_afdb_max_pattern_bytes) < 0;
    });
    std::uint64_t string_bytes = 0;
    for (auto& item : normalized) {
        item.name_off = static_cast<std::uint32_t>(string_bytes);
        string_bytes += item.entry.name.size();
        if (string_bytes > 0xFFFFFFFFull)
            return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
                workspace_error_code_t::limit_exceeded,
                "FLIRT database string blob exceeds the format limit", "flirt.serialize"));
    }
    const std::uint64_t total = k_afdb_header_bytes +
        static_cast<std::uint64_t>(normalized.size()) * k_afdb_entry_bytes + string_bytes;
    if (total > 0xFFFFFFFFull)
        return workspace_result_t<std::vector<std::uint8_t>>::failure(make_workspace_error(
            workspace_error_code_t::limit_exceeded,
            "FLIRT database blob exceeds the format limit", "flirt.serialize"));
    std::vector<std::uint8_t> blob(static_cast<std::size_t>(total), 0);
    write_u32_le(blob.data(), k_afdb_magic);
    write_u32_le(blob.data() + 4, k_afdb_version);
    write_u32_le(blob.data() + 8, static_cast<std::uint32_t>(normalized.size()));
    write_u32_le(blob.data() + 12, static_cast<std::uint32_t>(string_bytes));
    const std::size_t toolset_len = (std::min<std::size_t>)(toolset.size(), 31);
    if (toolset_len != 0)
        std::memcpy(blob.data() + 16, toolset.data(), toolset_len);
    std::size_t cursor = k_afdb_header_bytes;
    for (const auto& item : normalized) {
        std::uint8_t* record = blob.data() + cursor;
        write_u64_le(record, item.entry.prefix8);
        record[8] = item.entry.pattern_len;
        write_u32_le(record + 9, item.entry.mask);
        std::memcpy(record + 13, item.entry.bytes, k_afdb_max_pattern_bytes);
        write_u16_le(record + 45, item.entry.tail_crc16);
        write_u32_le(record + 47, item.entry.func_size);
        write_u32_le(record + 51, item.name_off);
        write_u16_le(record + 55, static_cast<std::uint16_t>(item.entry.name.size()));
        write_u16_le(record + 57, item.entry.sig_flags);
        cursor += k_afdb_entry_bytes;
    }
    for (const auto& item : normalized) {
        std::memcpy(blob.data() + cursor, item.entry.name.data(), item.entry.name.size());
        cursor += item.entry.name.size();
    }
    return workspace_result_t<std::vector<std::uint8_t>>::success(std::move(blob));
}

workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>
flirt_signature_db_t::load_from_blob(const std::uint8_t* data, std::size_t size,
                                     std::string_view source_label)
{
    auto reject = [](const char* message) {
        return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::failure(
            make_workspace_error(workspace_error_code_t::malformed_image, message,
                                 "flirt.db.load"));
    };
    if (!data || size < k_afdb_header_bytes)
        return reject("FLIRT database blob is smaller than its header");
    if (read_u32_le(data) != k_afdb_magic)
        return reject("FLIRT database magic is invalid");
    if (read_u32_le(data + 4) != k_afdb_version)
        return reject("FLIRT database version is unsupported");
    const std::uint32_t entry_count = read_u32_le(data + 8);
    const std::uint32_t string_bytes = read_u32_le(data + 12);
    if (entry_count > k_afdb_max_entries)
        return reject("FLIRT database entry count exceeds the limit");
    const std::uint64_t expected = k_afdb_header_bytes +
        static_cast<std::uint64_t>(entry_count) * k_afdb_entry_bytes + string_bytes;
    if (expected != size)
        return reject("FLIRT database size does not match its header");
    if (read_u32_le(data + 48) != 0 || read_u32_le(data + 52) != 0 ||
        read_u32_le(data + 56) != 0)
        return reject("FLIRT database reserved header fields are nonzero");
    auto db = std::shared_ptr<flirt_signature_db_t>(new flirt_signature_db_t());
    db->blob_.assign(data, data + size);
    db->entry_count_ = entry_count;
    db->entries_offset_ = k_afdb_header_bytes;
    db->string_offset_ = static_cast<std::uint32_t>(k_afdb_header_bytes +
        static_cast<std::uint64_t>(entry_count) * k_afdb_entry_bytes);
    db->string_bytes_ = string_bytes;
    db->source_label_.assign(source_label.data(), source_label.size());
    const char* toolset_raw = reinterpret_cast<const char*>(data + 16);
    std::size_t toolset_len = 0;
    while (toolset_len < 32 && toolset_raw[toolset_len] != '\0')
        ++toolset_len;
    db->toolset_.assign(toolset_raw, toolset_len);

    std::uint64_t previous_prefix = 0;
    std::uint32_t previous_name_off = 0;
    bool have_previous = false;
    for (std::uint32_t index = 0; index < entry_count; ++index) {
        const std::uint8_t* record = db->blob_.data() + db->entries_offset_ +
            static_cast<std::size_t>(index) * k_afdb_entry_bytes;
        const std::uint64_t prefix8 = read_u64_le(record);
        const std::uint8_t pattern_len = record[8];
        const std::uint32_t mask = read_u32_le(record + 9);
        const std::uint8_t* bytes = record + 13;
        const std::uint32_t name_off = read_u32_le(record + 51);
        const std::uint16_t name_len = read_u16_le(record + 55);
        if (pattern_len < k_afdb_min_pattern_bytes || pattern_len > k_afdb_max_pattern_bytes)
            return reject("FLIRT database entry pattern length is outside [16,32]");
        if (popcount32(mask) < k_afdb_min_significant_bits)
            return reject("FLIRT database entry has fewer than 12 significant mask bits");
        if ((mask & 0xFFu) != 0xFFu)
            return reject("FLIRT database entry prefix is not wildcard-free");
        if (std::memcmp(&prefix8, bytes, sizeof(prefix8)) != 0)
            return reject("FLIRT database entry prefix does not match its first bytes");
        for (std::size_t i = 0; i < k_afdb_max_pattern_bytes; ++i)
            if ((mask & (1u << i)) == 0 && bytes[i] != 0)
                return reject("FLIRT database entry stores bytes under wildcard mask bits");
        std::uint8_t tail[k_afdb_max_pattern_bytes]{};
        for (std::size_t i = k_afdb_prefix_bytes; i < pattern_len; ++i)
            if ((mask & (1u << i)) != 0)
                tail[i] = bytes[i];
        if (crc16_ccitt_false(tail + k_afdb_prefix_bytes, pattern_len - k_afdb_prefix_bytes) !=
            read_u16_le(record + 45))
            return reject("FLIRT database entry tail CRC is invalid");
        if (name_off > string_bytes || name_len > string_bytes - name_off)
            return reject("FLIRT database entry name escapes the string blob");
        if (!name_bytes_valid(db->blob_.data() + db->string_offset_ + name_off, name_len))
            return reject("FLIRT database entry name is not printable ASCII");
        for (std::size_t i = 0; i < 5; ++i)
            if (record[59 + i] != 0)
                return reject("FLIRT database entry reserved bytes are nonzero");
        if (have_previous &&
            (prefix8 < previous_prefix ||
             (prefix8 == previous_prefix && name_off < previous_name_off)))
            return reject("FLIRT database entries are not sorted");
        previous_prefix = prefix8;
        previous_name_off = name_off;
        have_previous = true;
        auto bucket_it = db->buckets_.find(prefix8);
        if (bucket_it == db->buckets_.end())
            db->buckets_.emplace(prefix8, std::pair<std::uint32_t, std::uint32_t>{index, 1});
        else
            ++bucket_it->second.second;
    }
    for (const auto& [prefix, range] : db->buckets_)
        db->largest_bucket_ = (std::max<std::size_t>)(db->largest_bucket_, range.second);
    return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::success(
        std::move(db));
}

std::shared_ptr<const flirt_signature_db_t> flirt_signature_db_t::load_embedded()
{
    static const std::shared_ptr<const flirt_signature_db_t> cached = [] {
        auto loaded = load_from_blob(k_afdb_seed_blob, k_afdb_seed_blob_size, "embedded");
        if (!loaded) {
            diag::log_tagged_fmt("flirt", "embedded_db_rejected error=%s",
                                 loaded.error().message.c_str());
            return std::shared_ptr<const flirt_signature_db_t>{};
        }
        return loaded.take_value();
    }();
    return cached;
}

workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>
flirt_signature_db_t::load_from_file(const std::string& utf8_path)
{
    const bool absolute = utf8_path.size() > 2 &&
        ((utf8_path[1] == ':' && (utf8_path[2] == '\\' || utf8_path[2] == '/')) ||
         (utf8_path[0] == '/' && utf8_path[1] != '/'));
    if (!absolute || utf8_path.find("..") != std::string::npos ||
        utf8_path.rfind("\\\\", 0) == 0 || utf8_path.rfind("//", 0) == 0)
        return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::failure(
            make_workspace_error(workspace_error_code_t::invalid_argument,
                                 "FLIRT database path must be an absolute local path",
                                 "flirt.db.load"));
    auto opened = mapped_file_provider_t::open(utf8_path);
    if (!opened)
        return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::failure(
            std::move(opened.error()));
    auto provider = opened.take_value();
    if (provider->size() > (std::uint64_t{256} << 20))
        return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::failure(
            make_workspace_error(workspace_error_code_t::limit_exceeded,
                                 "FLIRT database file exceeds 256MB", "flirt.db.load"));
    auto bytes = provider->read_vector(0, provider->size(), std::uint64_t{256} << 20);
    if (!bytes)
        return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::failure(
            std::move(bytes.error()));
    auto loaded = load_from_blob(bytes.value().data(), bytes.value().size(), utf8_path);
    if (!loaded)
        return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::failure(
            std::move(loaded.error()));
    return workspace_result_t<std::shared_ptr<const flirt_signature_db_t>>::success(
        loaded.take_value());
}

bool flirt_signature_db_t::entry(std::uint32_t index, flirt_db_entry_view_t& out) const noexcept
{
    if (index >= entry_count_)
        return false;
    const std::uint8_t* record = blob_.data() + entries_offset_ +
        static_cast<std::size_t>(index) * k_afdb_entry_bytes;
    out.prefix8 = read_u64_le(record);
    out.pattern_len = record[8];
    out.mask = read_u32_le(record + 9);
    out.bytes = record + 13;
    out.tail_crc16 = read_u16_le(record + 45);
    out.func_size = read_u32_le(record + 47);
    const std::uint32_t name_off = read_u32_le(record + 51);
    const std::uint16_t name_len = read_u16_le(record + 55);
    out.name = std::string_view(
        reinterpret_cast<const char*>(blob_.data() + string_offset_ + name_off), name_len);
    out.sig_flags = read_u16_le(record + 57);
    out.index = index;
    return true;
}

std::pair<std::uint32_t, std::uint32_t>
flirt_signature_db_t::bucket(std::uint64_t prefix8) const noexcept
{
    const auto found = buckets_.find(prefix8);
    if (found == buckets_.end())
        return {0, 0};
    return found->second;
}

}
