#pragma once

#include "decompiler_contracts.hpp"

#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace aida::analysis::isolated_worker_codec {

inline constexpr std::size_t k_max_payload_bytes = 256U * 1024U * 1024U;
inline constexpr std::size_t k_max_string_bytes = 16U * 1024U * 1024U;
inline constexpr std::size_t k_max_vector_elements = 4U * 1024U * 1024U;

class writer_t final {
public:
    bool valid() const noexcept { return valid_; }

    void u8(const std::uint8_t value) { append(&value, sizeof(value)); }

    void u16(const std::uint16_t value)
    {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            u8(static_cast<std::uint8_t>(value >> (index * 8U)));
    }

    void u32(const std::uint32_t value)
    {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            u8(static_cast<std::uint8_t>(value >> (index * 8U)));
    }

    void u64(const std::uint64_t value)
    {
        for (std::size_t index = 0; index < sizeof(value); ++index)
            u8(static_cast<std::uint8_t>(value >> (index * 8U)));
    }

    void i32(const std::int32_t value) { u32(static_cast<std::uint32_t>(value)); }
    void i64(const std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }
    void boolean(const bool value) { u8(value ? 1U : 0U); }

    template <typename Enum>
    void enumeration(const Enum value)
    {
        static_assert(std::is_enum_v<Enum>);
        using underlying_t = std::underlying_type_t<Enum>;
        if constexpr (sizeof(underlying_t) <= sizeof(std::uint8_t))
            u8(static_cast<std::uint8_t>(value));
        else if constexpr (sizeof(underlying_t) <= sizeof(std::uint16_t))
            u16(static_cast<std::uint16_t>(value));
        else if constexpr (sizeof(underlying_t) <= sizeof(std::uint32_t))
            u32(static_cast<std::uint32_t>(value));
        else
            u64(static_cast<std::uint64_t>(value));
    }

    void digest(const sha256_digest_t& value) { append(value.bytes.data(), value.bytes.size()); }

    void string(const std::string_view value)
    {
        if (value.size() > k_max_string_bytes || value.size() > (std::numeric_limits<std::uint32_t>::max)()) {
            valid_ = false;
            return;
        }
        u32(static_cast<std::uint32_t>(value.size()));
        append(value.data(), value.size());
    }

    void bytes(const std::vector<std::uint8_t>& value)
    {
        if (value.size() > k_max_payload_bytes || value.size() > (std::numeric_limits<std::uint32_t>::max)()) {
            valid_ = false;
            return;
        }
        u32(static_cast<std::uint32_t>(value.size()));
        append(value.data(), value.size());
    }

    template <typename T, typename Encoder>
    void vector(const std::vector<T>& values, Encoder&& encode)
    {
        if (values.size() > k_max_vector_elements || values.size() > (std::numeric_limits<std::uint32_t>::max)()) {
            valid_ = false;
            return;
        }
        u32(static_cast<std::uint32_t>(values.size()));
        for (const auto& value : values) {
            encode(*this, value);
            if (!valid_)
                return;
        }
    }

    template <typename T, typename Encoder>
    void optional(const std::optional<T>& value, Encoder&& encode)
    {
        boolean(value.has_value());
        if (value)
            encode(*this, *value);
    }

    std::string take()
    {
        if (!valid_)
            return {};
        return std::move(bytes_);
    }

private:
    void append(const void* data, const std::size_t size)
    {
        if (!valid_ || size > k_max_payload_bytes || bytes_.size() > k_max_payload_bytes - size) {
            valid_ = false;
            return;
        }
        if (size != 0)
            bytes_.append(static_cast<const char*>(data), size);
    }

    std::string bytes_;
    bool valid_ = true;
};

class reader_t final {
public:
    explicit reader_t(const std::string_view bytes) : bytes_(bytes) {}

    bool complete() const noexcept { return valid_ && offset_ == bytes_.size(); }

    bool u8(std::uint8_t& value)
    {
        if (!read(&value, sizeof(value)))
            return false;
        return true;
    }

    bool u16(std::uint16_t& value)
    {
        value = 0;
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            std::uint8_t byte = 0;
            if (!u8(byte))
                return false;
            value |= static_cast<std::uint16_t>(byte) << (index * 8U);
        }
        return true;
    }

    bool u32(std::uint32_t& value)
    {
        value = 0;
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            std::uint8_t byte = 0;
            if (!u8(byte))
                return false;
            value |= static_cast<std::uint32_t>(byte) << (index * 8U);
        }
        return true;
    }

    bool u64(std::uint64_t& value)
    {
        value = 0;
        for (std::size_t index = 0; index < sizeof(value); ++index) {
            std::uint8_t byte = 0;
            if (!u8(byte))
                return false;
            value |= static_cast<std::uint64_t>(byte) << (index * 8U);
        }
        return true;
    }

    bool i32(std::int32_t& value)
    {
        std::uint32_t raw = 0;
        if (!u32(raw))
            return false;
        value = static_cast<std::int32_t>(raw);
        return true;
    }

    bool i64(std::int64_t& value)
    {
        std::uint64_t raw = 0;
        if (!u64(raw))
            return false;
        value = static_cast<std::int64_t>(raw);
        return true;
    }

    bool boolean(bool& value)
    {
        std::uint8_t raw = 0;
        if (!u8(raw) || raw > 1U) {
            valid_ = false;
            return false;
        }
        value = raw != 0;
        return true;
    }

    template <typename Enum>
    bool enumeration(Enum& value)
    {
        static_assert(std::is_enum_v<Enum>);
        using underlying_t = std::underlying_type_t<Enum>;
        if constexpr (sizeof(underlying_t) <= sizeof(std::uint8_t)) {
            std::uint8_t raw = 0;
            if (!u8(raw))
                return false;
            value = static_cast<Enum>(raw);
        } else if constexpr (sizeof(underlying_t) <= sizeof(std::uint16_t)) {
            std::uint16_t raw = 0;
            if (!u16(raw))
                return false;
            value = static_cast<Enum>(raw);
        } else if constexpr (sizeof(underlying_t) <= sizeof(std::uint32_t)) {
            std::uint32_t raw = 0;
            if (!u32(raw))
                return false;
            value = static_cast<Enum>(raw);
        } else {
            std::uint64_t raw = 0;
            if (!u64(raw))
                return false;
            value = static_cast<Enum>(raw);
        }
        return true;
    }

    bool digest(sha256_digest_t& value) { return read(value.bytes.data(), value.bytes.size()); }

    bool string(std::string& value)
    {
        std::uint32_t size = 0;
        if (!u32(size) || size > k_max_string_bytes || remaining() < size) {
            valid_ = false;
            return false;
        }
        value.assign(bytes_.data() + offset_, size);
        offset_ += size;
        return true;
    }

    bool bytes(std::vector<std::uint8_t>& value)
    {
        std::uint32_t size = 0;
        if (!u32(size) || size > k_max_payload_bytes || remaining() < size) {
            valid_ = false;
            return false;
        }
        value.assign(reinterpret_cast<const std::uint8_t*>(bytes_.data() + offset_),
            reinterpret_cast<const std::uint8_t*>(bytes_.data() + offset_ + size));
        offset_ += size;
        return true;
    }

    template <typename T, typename Decoder>
    bool vector(std::vector<T>& values, Decoder&& decode)
    {
        std::uint32_t count = 0;
        if (!u32(count) || count > k_max_vector_elements) {
            valid_ = false;
            return false;
        }
        try {
            values.clear();
            values.reserve(count);
            for (std::uint32_t index = 0; index < count; ++index) {
                T value{};
                if (!decode(*this, value)) {
                    valid_ = false;
                    return false;
                }
                values.push_back(std::move(value));
            }
        } catch (...) {
            valid_ = false;
            return false;
        }
        return true;
    }

    template <typename T, typename Decoder>
    bool optional(std::optional<T>& value, Decoder&& decode)
    {
        bool present = false;
        if (!boolean(present))
            return false;
        if (!present) {
            value.reset();
            return true;
        }
        T decoded{};
        if (!decode(*this, decoded)) {
            valid_ = false;
            return false;
        }
        value = std::move(decoded);
        return true;
    }

private:
    std::size_t remaining() const noexcept
    {
        return offset_ <= bytes_.size() ? bytes_.size() - offset_ : 0;
    }

    bool read(void* output, const std::size_t size)
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

    std::string_view bytes_;
    std::size_t offset_ = 0;
    bool valid_ = true;
};

inline void write_provider_identity(writer_t& writer, const decompiler_provider_identity_t& value)
{
    writer.enumeration(value.provider);
    writer.string(value.provider_name);
    writer.string(value.provider_version);
    writer.digest(value.provider_binary_hash);
    writer.string(value.worker_build_id);
    writer.digest(value.worker_build_hash);
}

inline bool read_provider_identity(reader_t& reader, decompiler_provider_identity_t& value)
{
    return reader.enumeration(value.provider) && reader.string(value.provider_name) &&
        reader.string(value.provider_version) && reader.digest(value.provider_binary_hash) &&
        reader.string(value.worker_build_id) && reader.digest(value.worker_build_hash);
}

inline void write_language_identity(writer_t& writer, const decompiler_language_identity_t& value)
{
    writer.string(value.language_id);
    writer.string(value.language_version);
    writer.string(value.compiler_spec_id);
    writer.digest(value.language_spec_hash);
    writer.enumeration(value.architecture);
    writer.enumeration(value.mode);
    writer.enumeration(value.endian);
}

inline bool read_language_identity(reader_t& reader, decompiler_language_identity_t& value)
{
    return reader.string(value.language_id) && reader.string(value.language_version) &&
        reader.string(value.compiler_spec_id) && reader.digest(value.language_spec_hash) &&
        reader.enumeration(value.architecture) && reader.enumeration(value.mode) &&
        reader.enumeration(value.endian);
}

inline void write_entity(writer_t& writer, const decompiler_entity_key_t& value)
{
    writer.string(serialize_decompiler_entity_key(value));
}

inline bool read_entity(reader_t& reader, decompiler_entity_key_t& value)
{
    std::string bytes;
    if (!reader.string(bytes))
        return false;
    auto decoded = deserialize_decompiler_entity_key(bytes);
    if (!decoded.valid() || !decoded.value)
        return false;
    value = std::move(*decoded.value);
    return true;
}

}
