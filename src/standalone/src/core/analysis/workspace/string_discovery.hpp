#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <vector>

namespace aida::analysis {

struct string_discovery_limits_t {
    std::uint64_t max_strings = 1ULL << 24;
    std::uint64_t max_scan_bytes = 1ULL << 34;
    std::uint64_t max_result_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint64_t max_string_bytes = 1ULL << 20;
    std::uint64_t max_string_value_bytes = 1ULL << 20;
    std::uint64_t read_window_bytes = 4ULL * 1024ULL * 1024ULL;
    std::uint32_t minimum_code_points = 4;
    std::uint32_t cancellation_check_interval = 4096;
    bool scan_ascii = true;
    bool scan_utf8 = true;
    bool scan_utf16_le = true;
    bool scan_executable_regions = true;
    bool require_null_terminator = false;
};

struct string_discovery_result_t {
    std::vector<string_record_t> strings;
    std::uint64_t bytes_scanned = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
    std::uint64_t rejected_invalid_sequences = 0;
    std::uint64_t rejected_oversized_strings = 0;
    std::uint64_t rejected_unterminated_strings = 0;
    std::uint64_t duplicate_strings = 0;
    std::uint64_t shard_merge_ns = 0;
};

class string_discovery_t final {
public:
    static workspace_result_t<string_discovery_result_t> discover(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const string_discovery_limits_t& limits = {},
        const cancellation_token_t& cancel = {});
};

}
