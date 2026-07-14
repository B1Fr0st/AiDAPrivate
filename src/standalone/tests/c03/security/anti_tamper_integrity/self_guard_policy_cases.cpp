#include "anti_tamper_integrity_harness.hpp"

#include "../../../../src/core/anti-tamper/self_guard.hpp"

#include <array>
#include <cstring>

namespace aida::c03::security
{
bool run_self_guard_policy_cases(std::string& failure)
{
    constexpr uint32_t now = 1000;
    self_guard::aida_blocklist_entry_t entry{};
    memcpy(entry.name_pattern, "x64dbg", 7);
    entry.flags = self_guard::BL_MATCH_NAME;
    if (!record_policy_case(self_guard::validate_blocklist_entry(entry)
        && self_guard::blocklist_entry_matches(
            entry, "C:\\Tools\\X64DBG.EXE", nullptr, nullptr, now),
            "name_only_blocklist_did_not_match", failure)) {
        return false;
    }

    std::array<uint8_t, 32> expected_hash{};
    std::array<uint8_t, 32> other_hash{};
    expected_hash.fill(0x5a);
    other_hash.fill(0xa5);
    entry = {};
    memcpy(entry.image_hash, expected_hash.data(), expected_hash.size());
    entry.flags = self_guard::BL_MATCH_HASH;
    if (!record_policy_case(self_guard::validate_blocklist_entry(entry)
        && self_guard::blocklist_entry_matches(
            entry, {}, expected_hash.data(), nullptr, now)
        && !self_guard::blocklist_entry_matches(
            entry, {}, other_hash.data(), nullptr, now),
            "hash_only_blocklist_policy_failed", failure)) {
        return false;
    }

    std::array<uint8_t, 16> expected_watermark{};
    std::array<uint8_t, 16> other_watermark{};
    expected_watermark.fill(0x33);
    other_watermark.fill(0xcc);
    entry = {};
    memcpy(entry.watermark, expected_watermark.data(), expected_watermark.size());
    entry.flags = self_guard::BL_MATCH_WATERMARK;
    if (!record_policy_case(self_guard::validate_blocklist_entry(entry)
        && self_guard::blocklist_entry_matches(
            entry, {}, nullptr, expected_watermark.data(), now)
        && !self_guard::blocklist_entry_matches(
            entry, {}, nullptr, other_watermark.data(), now),
            "watermark_only_blocklist_policy_failed", failure)) {
        return false;
    }

    entry = {};
    memcpy(entry.name_pattern, "windbg", 7);
    memcpy(entry.image_hash, expected_hash.data(), expected_hash.size());
    memcpy(entry.watermark, expected_watermark.data(), expected_watermark.size());
    entry.flags = self_guard::BL_MATCH_ALL;
    if (!record_policy_case(self_guard::blocklist_entry_matches(
            entry, "WinDbgX.exe", nullptr, nullptr, now),
            "mixed_flags_did_not_preserve_independent_name_match", failure)) {
        return false;
    }

    entry.expires_at = 1;
    if (!record_policy_case(!self_guard::blocklist_entry_matches(entry, "windbg.exe", nullptr,
            nullptr, 1 + self_guard::kSevenDaysSeconds + 1),
            "expired_blocklist_entry_matched", failure)) {
        return false;
    }

    entry = {};
    memset(entry.name_pattern, 'a', sizeof(entry.name_pattern));
    entry.flags = self_guard::BL_MATCH_NAME;
    if (!record_policy_case(!self_guard::validate_blocklist_entry(entry)
        && !self_guard::blocklist_entry_matches(
            entry, "aaaaaaaa", nullptr, nullptr, now),
            "unterminated_name_pattern_accepted", failure)) {
        return false;
    }

    entry = {};
    memcpy(entry.name_pattern, "ida", 4);
    entry.flags = self_guard::BL_MATCH_NAME | 0x80000000u;
    if (!record_policy_case(!self_guard::validate_blocklist_entry(entry)
        && !self_guard::blocklist_entry_matches(
            entry, "ida.exe", nullptr, nullptr, now),
            "unknown_blocklist_flags_accepted", failure)) {
        return false;
    }

    return true;
}
}
