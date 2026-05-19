#pragma once

#include <cstdint>
#include <string>

namespace aida::license_state
{
    enum status_e : uint8_t
    {
        status_unset     = 0,
        status_pending   = 1,
        status_valid     = 2,
        status_degraded  = 3,
        status_suspended = 4,
        status_revoked   = 5
    };

    enum flag_bits_e : uint8_t
    {
        flag_arc_loaded       = 0x01,
        flag_driver_attached  = 0x02,
        flag_heartbeat_ok     = 0x04,
        flag_reserved_3       = 0x08,
        flag_reserved_4       = 0x10,
        flag_reserved_5       = 0x20,
        flag_reserved_6       = 0x40,
        flag_reserved_7       = 0x80
    };

#pragma pack(push, 1)
    struct license_state_t
    {
        uint8_t  version;
        uint8_t  status;
        uint8_t  tier;
        uint8_t  flags;
        uint8_t  reserved[4];
        uint64_t session_epoch;
        uint64_t magic_a;
        uint64_t magic_b;
        uint64_t magic_c;
        uint8_t  mac[16];
    };
#pragma pack(pop)

    static_assert(sizeof(license_state_t) == 56, "license_state_t layout drift");

    bool initialize();

    bool is_initialized();

    bool set_state(const license_state_t& new_state, std::string& last_error);

    bool read_state(license_state_t& out, std::string& last_error);

    bool is_valid_or_degraded();

    bool is_arc_loaded();

    bool is_driver_attached();

    bool is_heartbeat_ok();

    bool is_license_pending_activation();

    uint8_t current_tier();

    uint64_t current_session_epoch();

    bool transition_to(status_e new_status, std::string& last_error);

    bool set_flags(uint8_t set_mask, uint8_t clear_mask, std::string& last_error);

    bool set_tier(uint8_t tier, std::string& last_error);

    bool bump_session_epoch(uint64_t& out_new_epoch, std::string& last_error);

    void shutdown();

    bool materialize_state_secret(uint8_t out_secret[32]);

    bool recheck_image_hash();

    bool image_binding_active();
}
