#pragma once

#include "flirt_signature_db.hpp"

#include "../workspace/workspace_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace aida::analysis::flirt {

struct flirt_db_builder_options_t {
    std::vector<std::string> library_paths;
    bool strip_static = false;
    std::string toolset = "msvc143-x64-release";
};

struct flirt_db_builder_stats_t {
    std::uint64_t libraries_loaded = 0;
    std::uint64_t members_parsed = 0;
    std::uint64_t code_sections = 0;
    std::uint64_t symbols_seen = 0;
    std::uint64_t dropped_short = 0;
    std::uint64_t dropped_prefix = 0;
    std::uint64_t dropped_mask = 0;
    std::uint64_t deduped = 0;
    std::uint64_t collisions_kept = 0;
    std::uint64_t signatures_emitted = 0;
    std::vector<std::string> library_names;
};

workspace_result_t<std::vector<std::string>> discover_msvc_static_libs();

workspace_result_t<flirt_db_builder_stats_t>
build_flirt_db_entries(const flirt_db_builder_options_t& options,
                       std::vector<flirt_db_build_entry_t>& out_entries,
                       const cancellation_token_t& cancel = {});

workspace_result_t<std::string>
write_flirt_seed_header(const std::vector<std::uint8_t>& blob,
                        const std::string& toolset,
                        std::uint32_t entry_count,
                        const std::string& utf8_output_path);

}
