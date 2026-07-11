#pragma once

#include "analysis_workspace.hpp"
#include "overlay_journal.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace aida::analysis {

struct patched_export_options_t {
    bool allow_overwrite = false;
    std::uint64_t chunk_size = 4ULL * 1024ULL * 1024ULL;
};

struct patched_export_result_t {
    std::string destination_path;
    std::uint64_t bytes_written = 0;
    std::uint64_t patched_bytes = 0;
    std::uint64_t patch_records = 0;
    std::uint64_t overlay_revision = 0;
    sha256_digest_t output_hash;
};

class patched_export_t final {
public:
    static workspace_result_t<patched_export_result_t> export_copy(
        const std::shared_ptr<analysis_workspace_t>& workspace,
        const std::string& destination_path,
        const patched_export_options_t& options = {},
        const cancellation_token_t& cancel = {});
};

}
