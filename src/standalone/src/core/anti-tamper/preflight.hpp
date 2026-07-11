#pragma once

#include <windows.h>
#include <cstdint>
#include <cstring>

#include "webhook.hpp"
#include "integrity.hpp"
#include "reloc_mask.hpp"
#include "../runtime/standalone_driver.hpp"
#include "../../helpers/diag_log.hpp"
#include "../runtime/reason_ids.hpp"

namespace anti_tamper {
namespace preflight {

__forceinline bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

inline bool check_sentinel_driver()
{
    bool driver_loaded = driver_bridge::is_loaded();
    bool kernel_driver = driver_bridge::using_kernel_driver();

    webhook::write_log_critical_fmt("preflight",
        "sentinel_check loaded=%d kernel=%d",
        driver_loaded ? 1 : 0,
        kernel_driver ? 1 : 0);

    if (!driver_loaded || !kernel_driver)
    {
        diag::log_tagged_critical("preflight",
            "sentinel_driver_not_available");
        return false;
    }

    return true;
}

inline bool check_text_section_hash()
{
    auto& snap = state::get().code_snap;
    if (snap.text_base == 0 || snap.text_size == 0)
    {
        diag::log_tagged_critical("preflight",
            "text_hash_no_snapshot");
        return false;
    }

    uint8_t computed_hash[32] = {};
    if (!integrity::get_current_text_sha256(computed_hash))
    {
        diag::log_tagged_critical("preflight",
            "text_hash_compute_failed");
        return false;
    }

    bool match = constant_time_compare(computed_hash, snap.text_sha256, 32);

    {
        char computed_hex[65];
        char expected_hex[65];
        for (int i = 0; i < 32; ++i)
        {
            _snprintf_s(computed_hex + i * 2, 3, 2, "%02x", computed_hash[i]);
            _snprintf_s(expected_hex + i * 2, 3, 2, "%02x", snap.text_sha256[i]);
        }
        computed_hex[64] = '\0';
        expected_hex[64] = '\0';

        webhook::write_log_critical_fmt("preflight",
            "text_hash_check computed=%s expected=%s match=%d",
            computed_hex, expected_hex, match ? 1 : 0);
    }

    return match;
}

inline bool run_preflight_checks()
{
    webhook::write_log_critical("preflight", "preflight_checks_begin");
    diag::log_tagged_critical("preflight", "preflight_checks_begin");

    if (!check_sentinel_driver())
    {
        MessageBoxA(nullptr,
            "AiDA protection driver not available",
            "AiDA",
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
        webhook::write_log_critical("preflight",
            "preflight_failed_sentinel_unavailable_exiting");
        diag::log_tagged_critical("preflight",
            "preflight_failed_sentinel_unavailable_exiting");
        ExitProcess(1);
    }

    if (!check_text_section_hash())
    {
        MessageBoxA(nullptr,
            "AiDA binary integrity check failed",
            "AiDA",
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
        webhook::write_log_critical("preflight",
            "preflight_failed_text_hash_mismatch_exiting");
        diag::log_tagged_critical("preflight",
            "preflight_failed_text_hash_mismatch_exiting");
        ExitProcess(1);
    }

    webhook::write_log_critical("preflight", "preflight_checks_passed");
    diag::log_tagged_critical("preflight", "preflight_checks_passed");
    return true;
}

}
}
