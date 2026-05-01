#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace aida::hardware_id
{
    struct anchor_set_t
    {
        std::string smbios_uuid;
        std::string baseboard_serial;
        std::string disk_vpd_serial;
        std::string machine_guid;
        std::string efi_boot_guid;
        std::string primary_mac;
        std::string cpu_topology;
        std::string volume_serial;
        std::uint64_t boot_nonce = 0;
        bool         valid_count = false;
        int          collected_anchor_count = 0;
    };

    struct composite_t
    {
        std::string hardware_id_sha256;
        std::string smbios_uuid_hash;
        std::string baseboard_serial_hash;
        std::string disk_vpd_hash;
        std::string machine_guid_hash;
        int         anchor_count = 0;
    };

    struct tpm_attest_t
    {
        bool         present = false;
        std::string  ek_pub_sha256;
        std::string  pcr_composite_sha256;
        std::string  hwid_component_sha256;
        std::vector<std::array<unsigned char, 32>> pcr_values;
        std::vector<unsigned char> ek_pub_der;
    };

    anchor_set_t collect_user_mode() noexcept;

    bool collect_from_driver(anchor_set_t& out) noexcept;

    composite_t hash_anchors(const anchor_set_t& anchors) noexcept;

    std::string canonical_string(const anchor_set_t& anchors) noexcept;

    bool collect_tpm_attestation(tpm_attest_t& out) noexcept;

    composite_t hash_anchors_with_tpm(const anchor_set_t& anchors,
                                      const tpm_attest_t& tpm) noexcept;
}
