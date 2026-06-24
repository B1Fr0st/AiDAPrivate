#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace aida::hardware_id::v2
{
    constexpr std::size_t kFactorCount = 9;
    constexpr std::uint8_t kFactorIdSmbiosUuid       = 1;
    constexpr std::uint8_t kFactorIdBaseboardSerial  = 2;
    constexpr std::uint8_t kFactorIdChassisSerial    = 3;
    constexpr std::uint8_t kFactorIdDiskSerial       = 4;
    constexpr std::uint8_t kFactorIdCpuidBrand       = 6;
    constexpr std::uint8_t kFactorIdMachineGuid      = 7;
    constexpr std::uint8_t kFactorIdInstallationGuid = 8;
    constexpr std::uint8_t kFactorIdTpmEkSha256      = 9;

    constexpr std::uint32_t kHwidVersion = 2;

    struct factor_record_t
    {
        std::uint8_t                  id = 0;
        std::vector<std::uint8_t>     bytes;
        std::array<std::uint8_t, 32>  factor_hash{};
        bool                          collected = false;
    };

    struct collection_t
    {
        std::array<std::uint8_t, 32>             hwid_hash{};
        std::array<factor_record_t, kFactorCount> factors{};
        bool                                     tpm_present = false;
        std::uint32_t                            factor_present_mask = 0;
        std::uint64_t                            collected_at_ms = 0;
    };

    bool collect(collection_t& out, std::string& last_error) noexcept;

    bool hash_only(std::array<std::uint8_t, 32>& out_hash,
                   std::string& last_error) noexcept;

    bool factor_hashes(std::array<std::array<std::uint8_t, 32>, kFactorCount>& out,
                       std::string& last_error) noexcept;

    bool hwid_factor_count_changed(
        const std::array<std::array<std::uint8_t, 32>, kFactorCount>& a,
        const std::array<std::array<std::uint8_t, 32>, kFactorCount>& b,
        std::uint32_t& out_changed_count) noexcept;

    std::string hash_to_hex(const std::array<std::uint8_t, 32>& hash) noexcept;
}
