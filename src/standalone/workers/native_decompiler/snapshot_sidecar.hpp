#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace aida::analysis::native_worker::snapshot_sidecar {

inline constexpr std::uint32_t k_magic = 0x43534941U;
inline constexpr std::uint32_t k_version = 1U;
inline constexpr std::uint64_t k_max_bytes = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::uint32_t k_max_records = 1U << 20;
inline constexpr std::uint32_t k_max_name_bytes = 1024U;
inline constexpr std::uint32_t k_max_module_bytes = 512U;
inline constexpr std::uint32_t k_max_prototype_bytes = 4096U;
inline constexpr std::uint32_t k_flag_is_64bit = 1U;

enum class name_kind_t : std::uint8_t {
    unknown = 0,
    function = 1,
    import = 2,
    export_ = 3,
    data = 4,
    label = 5
};

struct name_record_t {
    std::uint64_t rva = 0;
    name_kind_t kind = name_kind_t::unknown;
    bool is_noreturn = false;
    std::string name;
};

struct import_record_t {
    std::uint64_t iat_rva = 0;
    std::uint64_t thunk_rva = 0;
    std::uint32_t ordinal = 0;
    bool delayed = false;
    bool is_noreturn = false;
    std::string module;
    std::string name;
};

struct prototype_record_t {
    std::uint64_t rva = 0;
    std::uint8_t confidence = 0;
    bool is_noreturn = false;
    std::string name;
    std::string prototype;
};

struct sidecar_t {
    bool is_64bit = true;
    std::vector<name_record_t> names;
    std::vector<import_record_t> imports;
    std::vector<std::uint64_t> noreturn;
    std::vector<prototype_record_t> prototypes;
    std::uint8_t feedback_digest[32]{};
};

inline void append_u8(std::string& out, std::uint8_t value)
{
    out.push_back(static_cast<char>(value));
}

inline void append_u16(std::string& out, std::uint16_t value)
{
    append_u8(out, static_cast<std::uint8_t>(value));
    append_u8(out, static_cast<std::uint8_t>(value >> 8U));
}

inline void append_u32(std::string& out, std::uint32_t value)
{
    for (std::uint32_t shift = 0; shift < 32U; shift += 8U)
        append_u8(out, static_cast<std::uint8_t>(value >> shift));
}

inline void append_u64(std::string& out, std::uint64_t value)
{
    for (std::uint32_t shift = 0; shift < 64U; shift += 8U)
        append_u8(out, static_cast<std::uint8_t>(value >> shift));
}

inline void append_bytes(std::string& out, std::string_view value)
{
    out.append(value.data(), value.size());
}

inline std::uint64_t fnv1a64(const void* data, std::size_t size, std::uint64_t seed) noexcept
{
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint64_t hash = seed;
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

inline bool bounded_count(std::uint64_t count) noexcept
{
    return count <= k_max_records;
}

inline std::string encode(const sidecar_t& sidecar)
{
    if (!bounded_count(sidecar.names.size()) || !bounded_count(sidecar.imports.size()) ||
        !bounded_count(sidecar.noreturn.size()) || !bounded_count(sidecar.prototypes.size()))
        return {};
    std::string out;
    out.reserve(4096);
    append_u32(out, k_magic);
    append_u32(out, k_version);
    append_u32(out, sidecar.is_64bit ? k_flag_is_64bit : 0U);
    append_u32(out, 0U);
    append_u32(out, static_cast<std::uint32_t>(sidecar.names.size()));
    append_u32(out, static_cast<std::uint32_t>(sidecar.imports.size()));
    append_u32(out, static_cast<std::uint32_t>(sidecar.noreturn.size()));
    append_u32(out, static_cast<std::uint32_t>(sidecar.prototypes.size()));
    append_bytes(out, std::string_view(
        reinterpret_cast<const char*>(sidecar.feedback_digest), sizeof(sidecar.feedback_digest)));
    for (const auto& record : sidecar.names) {
        if (record.name.empty() || record.name.size() > k_max_name_bytes)
            return {};
        append_u64(out, record.rva);
        append_u8(out, static_cast<std::uint8_t>(record.kind));
        append_u8(out, record.is_noreturn ? 1U : 0U);
        append_u16(out, 0U);
        append_u32(out, static_cast<std::uint32_t>(record.name.size()));
        append_bytes(out, record.name);
    }
    for (const auto& record : sidecar.imports) {
        if (record.module.size() > k_max_module_bytes || record.name.size() > k_max_name_bytes)
            return {};
        append_u64(out, record.iat_rva);
        append_u64(out, record.thunk_rva);
        append_u32(out, record.ordinal);
        append_u32(out, (record.delayed ? 1U : 0U) | (record.is_noreturn ? 2U : 0U));
        append_u32(out, static_cast<std::uint32_t>(record.module.size()));
        append_u32(out, static_cast<std::uint32_t>(record.name.size()));
        append_bytes(out, record.module);
        append_bytes(out, record.name);
    }
    for (const auto& rva : sidecar.noreturn)
        append_u64(out, rva);
    for (const auto& record : sidecar.prototypes) {
        if (record.prototype.empty() || record.prototype.size() > k_max_prototype_bytes ||
            record.name.size() > k_max_name_bytes)
            return {};
        append_u64(out, record.rva);
        append_u8(out, record.confidence);
        append_u8(out, record.is_noreturn ? 1U : 0U);
        append_u16(out, 0U);
        append_u32(out, static_cast<std::uint32_t>(record.name.size()));
        append_u32(out, static_cast<std::uint32_t>(record.prototype.size()));
        append_bytes(out, record.name);
        append_bytes(out, record.prototype);
    }
    if (out.size() > k_max_bytes)
        return {};
    append_u64(out, fnv1a64(out.data(), out.size(), 14695981039346656037ULL));
    return out;
}

class reader_t final {
public:
    reader_t(const void* data, std::size_t size)
        : bytes_(static_cast<const char*>(data), size) {}

    bool complete() const noexcept { return valid_ && offset_ == bytes_.size(); }

    bool u8(std::uint8_t& value) noexcept
    {
        if (!valid_ || remaining() < 1) {
            valid_ = false;
            return false;
        }
        value = static_cast<std::uint8_t>(bytes_[offset_++]);
        return true;
    }

    bool u16(std::uint16_t& value) noexcept
    {
        std::uint8_t low = 0;
        std::uint8_t high = 0;
        if (!u8(low) || !u8(high))
            return false;
        value = static_cast<std::uint16_t>(low | (static_cast<std::uint16_t>(high) << 8U));
        return true;
    }

    bool u32(std::uint32_t& value) noexcept
    {
        value = 0;
        for (std::uint32_t shift = 0; shift < 32U; shift += 8U) {
            std::uint8_t byte = 0;
            if (!u8(byte))
                return false;
            value |= static_cast<std::uint32_t>(byte) << shift;
        }
        return true;
    }

    bool u64(std::uint64_t& value) noexcept
    {
        value = 0;
        for (std::uint32_t shift = 0; shift < 64U; shift += 8U) {
            std::uint8_t byte = 0;
            if (!u8(byte))
                return false;
            value |= static_cast<std::uint64_t>(byte) << shift;
        }
        return true;
    }

    bool bounded_string(std::string& value, std::uint32_t maximum)
    {
        std::uint32_t size = 0;
        if (!u32(size) || size > maximum || remaining() < size) {
            valid_ = false;
            return false;
        }
        try {
            value.assign(bytes_.data() + offset_, size);
        } catch (...) {
            valid_ = false;
            return false;
        }
        offset_ += size;
        return true;
    }

    bool raw_bytes(void* output, std::size_t size) noexcept
    {
        if (!valid_ || remaining() < size) {
            valid_ = false;
            return false;
        }
        if (size != 0)
            std::memcpy(output, bytes_.data() + offset_, size);
        offset_ += size;
        return true;
    }

private:
    std::size_t remaining() const noexcept
    {
        return offset_ <= bytes_.size() ? bytes_.size() - offset_ : 0;
    }

    std::string_view bytes_;
    std::size_t offset_ = 0;
    bool valid_ = true;
};

inline std::optional<sidecar_t> decode(const void* data, std::size_t size)
{
    if (!data || size < 72 || size > k_max_bytes)
        return std::nullopt;
    const std::uint64_t expected = fnv1a64(data, size - 8, 14695981039346656037ULL);
    std::uint64_t trailing = 0;
    std::memcpy(&trailing, static_cast<const char*>(data) + size - 8, sizeof(trailing));
    if (trailing != expected)
        return std::nullopt;
    reader_t reader(data, size - 8);
    sidecar_t sidecar;
    std::uint32_t magic = 0;
    std::uint32_t version = 0;
    std::uint32_t flags = 0;
    std::uint32_t reserved = 0;
    std::uint32_t name_count = 0;
    std::uint32_t import_count = 0;
    std::uint32_t noreturn_count = 0;
    std::uint32_t prototype_count = 0;
    if (!reader.u32(magic) || magic != k_magic || !reader.u32(version) || version != k_version ||
        !reader.u32(flags) || !reader.u32(reserved) ||
        !reader.u32(name_count) || !bounded_count(name_count) ||
        !reader.u32(import_count) || !bounded_count(import_count) ||
        !reader.u32(noreturn_count) || !bounded_count(noreturn_count) ||
        !reader.u32(prototype_count) || !bounded_count(prototype_count) ||
        !reader.raw_bytes(sidecar.feedback_digest, sizeof(sidecar.feedback_digest)))
        return std::nullopt;
    sidecar.is_64bit = (flags & k_flag_is_64bit) != 0;
    try {
        sidecar.names.reserve(name_count);
        sidecar.imports.reserve(import_count);
        sidecar.noreturn.reserve(noreturn_count);
        sidecar.prototypes.reserve(prototype_count);
    } catch (...) {
        return std::nullopt;
    }
    for (std::uint32_t index = 0; index < name_count; ++index) {
        name_record_t record;
        std::uint8_t kind = 0;
        std::uint8_t noreturn = 0;
        std::uint16_t padding = 0;
        if (!reader.u64(record.rva) || !reader.u8(kind) || !reader.u8(noreturn) ||
            noreturn > 1U || !reader.u16(padding) ||
            !reader.bounded_string(record.name, k_max_name_bytes) || record.name.empty() ||
            kind > static_cast<std::uint8_t>(name_kind_t::label))
            return std::nullopt;
        record.kind = static_cast<name_kind_t>(kind);
        record.is_noreturn = noreturn != 0;
        sidecar.names.push_back(std::move(record));
    }
    for (std::uint32_t index = 0; index < import_count; ++index) {
        import_record_t record;
        std::uint32_t record_flags = 0;
        if (!reader.u64(record.iat_rva) || !reader.u64(record.thunk_rva) ||
            !reader.u32(record.ordinal) || !reader.u32(record_flags) || record_flags > 3U ||
            !reader.bounded_string(record.module, k_max_module_bytes) ||
            !reader.bounded_string(record.name, k_max_name_bytes))
            return std::nullopt;
        record.delayed = (record_flags & 1U) != 0;
        record.is_noreturn = (record_flags & 2U) != 0;
        sidecar.imports.push_back(std::move(record));
    }
    for (std::uint32_t index = 0; index < noreturn_count; ++index) {
        std::uint64_t rva = 0;
        if (!reader.u64(rva))
            return std::nullopt;
        sidecar.noreturn.push_back(rva);
    }
    for (std::uint32_t index = 0; index < prototype_count; ++index) {
        prototype_record_t record;
        std::uint8_t noreturn = 0;
        std::uint16_t padding = 0;
        if (!reader.u64(record.rva) || !reader.u8(record.confidence) ||
            !reader.u8(noreturn) || noreturn > 1U || !reader.u16(padding) ||
            !reader.bounded_string(record.name, k_max_name_bytes) ||
            !reader.bounded_string(record.prototype, k_max_prototype_bytes) ||
            record.prototype.empty())
            return std::nullopt;
        record.is_noreturn = noreturn != 0;
        sidecar.prototypes.push_back(std::move(record));
    }
    if (!reader.complete())
        return std::nullopt;
    return sidecar;
}

}
