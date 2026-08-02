#pragma once

#include "flirt_signature_db.hpp"

#include "../workspace/byte_provider.hpp"
#include "../workspace/compact_ir.hpp"
#include "../workspace/pe_image.hpp"
#include "../workspace/workspace_types.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace aida::analysis::flirt {

inline constexpr std::uint8_t k_flirt_status_completed = 0;
inline constexpr std::uint8_t k_flirt_status_db_absent = 1;
inline constexpr std::uint8_t k_flirt_status_cancelled = 2;
inline constexpr std::uint8_t k_flirt_status_invalid = 3;

inline constexpr std::uint8_t k_flirt_tier_exact_size = 1;
inline constexpr std::uint8_t k_flirt_tier_exact_crc = 2;
inline constexpr std::uint8_t k_flirt_tier_pattern_only = 3;

struct flirt_scan_limits_t {
    std::uint64_t max_functions = 2000000;
    std::uint32_t max_candidates_per_function = 64;
    std::uint32_t max_pattern_bytes = k_afdb_max_pattern_bytes;
    std::uint32_t workers = 0;
    bool relocation_check = true;
};

struct flirt_match_t {
    std::uint64_t rva = 0;
    std::string name;
    std::uint8_t tier = 0;
    std::uint8_t confidence = 0;
    std::uint32_t db_entry = 0;
    bool is_noreturn = false;
};

struct flirt_scan_result_t {
    std::vector<flirt_match_t> matches;
    std::uint64_t functions_considered = 0;
    std::uint64_t functions_skipped_thunk = 0;
    std::uint64_t functions_skipped_short = 0;
    std::uint64_t candidates_tested = 0;
    std::uint64_t ambiguous = 0;
    std::uint64_t rejected_reloc = 0;
    std::uint8_t status = k_flirt_status_invalid;
    double elapsed_ms = 0.0;
};

struct flirt_scan_request_t {
    const analysis_snapshot_t* snapshot = nullptr;
    const workspace_image_t* image = nullptr;
    const pe_image_t* pe = nullptr;
    std::shared_ptr<const byte_provider_t> provider;
    const flirt_signature_db_t* db = nullptr;
    flirt_scan_limits_t limits;
};

workspace_result_t<flirt_scan_result_t>
flirt_scan(const flirt_scan_request_t& request, const cancellation_token_t& cancel);

}
