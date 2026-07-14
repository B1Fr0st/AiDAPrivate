#include "anti_tamper_integrity_harness.hpp"

#include "../../../../src/core/anti-tamper/anti_hook.hpp"

#include <array>

namespace aida::c03::security
{
bool run_prologue_policy_cases(std::string& failure)
{
    std::array<uint8_t, 32> trusted{};
    std::array<uint8_t, 32> patched{};
    trusted.fill(0x41);
    patched.fill(0x42);
    constexpr uint32_t trusted_crc = 0x1234abcd;

    if (!record_policy_case(anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, true, trusted.data(), true,
            trusted_crc, true, trusted_crc),
            "valid_prologue_evidence_rejected", failure)) {
        return false;
    }

    if (!record_policy_case(!anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, true, patched.data(), true,
            trusted_crc, true, trusted_crc),
            "synchronized_current_crc_patch_accepted", failure)) {
        return false;
    }

    constexpr uint32_t patched_crc = 0x55aa55aa;
    if (!record_policy_case(!anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, true, trusted.data(), true,
            patched_crc, true, patched_crc),
            "current_vs_current_crc_accepted_without_baseline", failure)) {
        return false;
    }

    if (!record_policy_case(!anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, false, trusted.data(), true,
            trusted_crc, true, trusted_crc)
        && !anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, true, trusted.data(), false,
            trusted_crc, true, trusted_crc)
        && !anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, true, trusted.data(), true,
            trusted_crc, false, trusted_crc),
            "prologue_read_failure_did_not_fail_closed", failure)) {
        return false;
    }

    if (!record_policy_case(!anti_tamper::anti_hook::detail::prologue_evidence_matches_baseline(
            trusted.data(), trusted_crc, true, trusted.data(), true,
            trusted_crc, true, patched_crc),
            "kernel_crc_mismatch_accepted", failure)) {
        return false;
    }

    return true;
}
}
