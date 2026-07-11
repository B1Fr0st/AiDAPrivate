#pragma once

#include "byte_provider.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace aida::analysis {

struct macho_parse_limits_t {
    std::uint32_t max_load_commands = 65536;
    std::uint32_t max_segments = 65536;
    std::uint32_t max_sections = 1U << 20;
    std::uint32_t max_sections_per_segment = 65536;
    std::uint32_t max_symbols = 1U << 20;
    std::uint32_t max_dylib_dependencies = 65536;
    std::uint32_t max_imports = 1U << 20;
    std::uint32_t max_exports = 1U << 20;
    std::uint32_t max_relocations = 1U << 22;
    std::uint32_t max_bind_entries = 1U << 20;
    std::uint32_t max_rebase_entries = 1U << 20;
    std::uint32_t max_function_starts = 1U << 20;
    std::uint32_t max_data_in_code_entries = 1U << 20;
    std::uint32_t max_export_trie_nodes = 1U << 20;
    std::uint32_t max_export_trie_depth = 256;
    std::uint32_t max_chained_fixup_imports = 1U << 20;
    std::uint32_t max_chained_fixup_pages = 1U << 18;
    std::uint32_t max_chained_fixup_steps = 1U << 22;
    std::uint32_t max_metadata_symbols = 1U << 20;
    std::uint32_t max_thread_states = 1024;
    std::uint32_t max_fat_slices = 256;
    std::uint64_t max_string_bytes = 64ULL * 1024ULL * 1024ULL;
    std::uint64_t max_linkedit_blob_bytes = 256ULL * 1024ULL * 1024ULL;
    std::uint64_t max_total_metadata_bytes = 512ULL * 1024ULL * 1024ULL;
};

struct fat_slice_t {
    std::int32_t cputype = 0;
    std::int32_t cpusubtype = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t align = 0;
    architecture_id_t architecture = architecture_id_t::unknown;
    std::shared_ptr<const workspace_image_t> image;
};

struct fat_image_t {
    bool is_64bit = false;
    endian_t endian = endian_t::big;
    std::uint32_t magic = 0;
    std::vector<fat_slice_t> slices;
};

workspace_result_t<std::shared_ptr<const workspace_image_t>>
parse_macho(const byte_provider_t& provider,
            const cancellation_token_t& cancel = {});

workspace_result_t<std::shared_ptr<const workspace_image_t>>
parse_macho(const byte_provider_t& provider,
            const macho_parse_limits_t& limits,
            const cancellation_token_t& cancel = {});

workspace_result_t<fat_image_t>
parse_fat_macho(const byte_provider_t& provider,
                const cancellation_token_t& cancel = {});

workspace_result_t<fat_image_t>
parse_fat_macho(const byte_provider_t& provider,
                const macho_parse_limits_t& limits,
                const cancellation_token_t& cancel = {});

}
