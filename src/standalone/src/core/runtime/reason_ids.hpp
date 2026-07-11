#pragma once

#include <cstdint>

namespace aida::reason_ids
{
    enum reason_e : uint64_t
    {
        reason_id_arc_bind_proof_hmac_failed        = 0xCF4A485D414059ACULL,
        reason_id_arc_bind_proof_mismatch           = 0xE4B33B9524827443ULL,
        reason_id_arc_code_hash_mismatch            = 0xB346C28A8C64527FULL,
        reason_id_arc_debugger                      = 0xFFA7666AC0656EA3ULL,
        reason_id_arc_heartbeat_hmac_failed         = 0xCBE35DD5CBE02FAEULL,
        reason_id_arc_honey                         = 0x06276B43FFF5FACBULL,
        reason_id_arc_hostile_driver                = 0x0323C9252C7659B5ULL,
        reason_id_arc_hwid_mismatch                 = 0xAAF4D602384B53A5ULL,
        reason_id_arc_no_bind_secret                = 0xF728213DC215F1C8ULL,
        reason_id_arc_no_device                     = 0xD319CFED6C46B016ULL,
        reason_id_arc_no_driver                     = 0x96947779BD6B1642ULL,
        reason_id_arc_qpc_rollback                  = 0xE46C1353DAE13BC3ULL,
        reason_id_arc_required                      = 0x623F1B7308BC6305ULL,
        reason_id_arc_self_hash_mismatch            = 0xC6B0596364D798E8ULL,
        reason_id_arc_vtable_tampered               = 0x13BE77CB7DE7E83FULL,
        reason_id_block_chain_runtime               = 0x6E2C28C931BD38FFULL,
        reason_id_call_obfuscation_tamper           = 0x6D42341AC9EFAF97ULL,
        reason_id_code_integrity_mismatch           = 0x29C4FE7259EF2971ULL,
        reason_id_code_integrity_runtime            = 0x9ECC1719FF3CECABULL,
        reason_id_debugger_at_startup               = 0xE75EA00956FADB5CULL,
        reason_id_debugger_attached                 = 0xBF62BEC389C09A1FULL,
        reason_id_debugger_runtime                  = 0x2722683F760E49B5ULL,
        reason_id_emulation_detected                = 0xFB30218D52C0B65EULL,
        reason_id_ghost_veh_unhooked                = 0xD5B7DACBF0983130ULL,
        reason_id_hardware_breakpoint_in_code       = 0x4E404EF1009FB577ULL,
        reason_id_hijacked_hypervisor               = 0x60AEC6412D4EAA3CULL,
        reason_id_hook_at_startup                   = 0xDF339F61F2C519B0ULL,
        reason_id_hook_runtime                      = 0x054B9D70BD435141ULL,
        reason_id_iat_hook_detected                 = 0xFFF36644D3EE5120ULL,
        reason_id_integrity_chain_stale             = 0xEA4BC8A3EDD04358ULL,
        reason_id_kernel_debugger_active            = 0x7C9477D532D3631DULL,
        reason_id_kernel_debugger_at_startup        = 0x533AF91F34AE02DCULL,
        reason_id_kernel_debugger_runtime           = 0x18B018F4B101C035ULL,
        reason_id_kernel_detection_active           = 0x625EB5FE9D3F06CBULL,
        reason_id_license_killed                    = 0xAB52443C6CA4997CULL,
        reason_id_nanomite_table_tamper             = 0x3870E2CC7FA371DBULL,
        reason_id_page_exec_arc_denied              = 0xC41CC469FE73A405ULL,
        reason_id_page_exec_gate_blocked            = 0x6DA6DBA76B26C8B7ULL,
        reason_id_page_exec_integrity_fail          = 0xD21C62982B5093F3ULL,
        reason_id_page_mac_periodic_mismatch        = 0x7FAE12A66A3814F7ULL,
        reason_id_page_not_resident                 = 0x9F0618D917C4EF8DULL,
        reason_id_page_offset_oob                   = 0x0CD104CCA93BC7C3ULL,
        reason_id_re_detected                       = 0x12DE2DA6C4368B7BULL,
        reason_id_re_tool_loaded_binary             = 0x719A61071B26F47FULL,
        reason_id_re_watchdog_stall                 = 0x06893EA7B196FB03ULL,
        reason_id_reattest_failure                  = 0x849017B5A195F9F4ULL,
        reason_id_server_page_tampered              = 0xCACF31E6BA4D055DULL,
        reason_id_stolen_basic_block_tamper         = 0x3DD40E11EABFD2E7ULL,
        reason_id_unpack_timing_anomaly             = 0x5A072B6917FD4A84ULL,
        reason_id_unsupported_hypervisor            = 0x594833E8744DEAE4ULL,
        reason_id_vm_at_startup                     = 0x69D17A7E1AADF526ULL,
        reason_id_vm_integrity_check_failed         = 0x708A56680EA0EA15ULL,
        reason_id_watchdog_worker_anomaly           = 0x00EF44B5A3F0B513ULL,
        reason_id_watchdog_workers_stalled          = 0x0F55DAA8A90D32BAULL,
        reason_id_writable_code_page                = 0x88E3AEC4746DCB93ULL,
        reason_id_honeypot_canary_patched_bsod      = 0x44681B8D2EA8B609ULL,
        reason_id_honeypot_string_external_access   = 0x202CE233A58F6D1CULL
    };

    constexpr uint64_t fnv1a_const(const char* s, uint64_t h = 0xcbf29ce484222325ULL) noexcept
    {
        return (s[0] == '\0') ? h : fnv1a_const(s + 1, (h ^ static_cast<uint64_t>(static_cast<uint8_t>(s[0]))) * 0x100000001b3ULL);
    }

    inline uint64_t reason_id_from_string(const char* s) noexcept
    {
        if (s == nullptr) return 0;
        uint64_t h = 0xcbf29ce484222325ULL;
        while (*s)
        {
            h ^= static_cast<uint64_t>(static_cast<uint8_t>(*s));
            h *= 0x100000001b3ULL;
            ++s;
        }
        return h;
    }

    inline void reason_id_to_short_string(uint64_t id, char out[9]) noexcept
    {
        static const char digits[] = "0123456789abcdef";
        uint32_t high = static_cast<uint32_t>(id >> 32);
        for (int i = 7; i >= 0; --i)
        {
            out[i] = digits[high & 0x0F];
            high >>= 4;
        }
        out[8] = '\0';
    }
}
