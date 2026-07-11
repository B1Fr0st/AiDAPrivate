#pragma once

#include "byte_provider.hpp"
#include "compact_ir.hpp"
#include "workspace_types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace aida::analysis {

enum class function_seed_kind_t : std::uint8_t {
    image_entry = 0,
    tls_callback,
    export_entry,
    unwind_range,
    debug_symbol,
    load_config_entry,
    relocation_target,
    direct_call_target,
    validated_gap_target
};

struct function_seed_t {
    address_t address;
    std::optional<address_t> known_end;
    function_seed_kind_t kind = function_seed_kind_t::validated_gap_target;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
    std::uint64_t stable_source_id = 0;
    std::string name;
    bool noreturn = false;
};

struct switch_record_t {
    entity_id_t id = 0;
    entity_id_t function_id = 0;
    address_t dispatch;
    address_t table;
    std::optional<address_t> default_target;
    std::vector<address_t> case_targets;
    std::uint8_t entry_size = 0;
    bool relative_entries = false;
    fact_provenance_t provenance = fact_provenance_t::unknown;
    std::uint8_t confidence = 0;
};

struct function_recovery_limits_t {
    std::uint64_t max_blocks = 1ULL << 26;
    std::uint64_t max_functions = 1ULL << 24;
    std::uint64_t max_function_memberships = 1ULL << 27;
    std::uint64_t max_edges = 1ULL << 27;
    std::uint64_t max_switches = 1ULL << 20;
    std::uint64_t max_result_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
    std::uint32_t max_switch_cases = 4096;
    std::uint32_t max_blocks_per_function = 1U << 20;
    std::uint32_t cancellation_check_interval = 1024;
};

struct block_recovery_result_t {
    std::vector<basic_block_record_t> blocks;
    std::vector<edge_record_t> edges;
    std::uint64_t storage_bytes = 0;
};

struct function_recovery_result_t {
    std::vector<basic_block_record_t> blocks;
    std::vector<function_record_t> functions;
    std::vector<function_chunk_record_t> function_chunks;
    std::vector<function_block_membership_record_t> function_block_memberships;
    std::vector<edge_record_t> edges;
    std::vector<switch_record_t> switches;
    std::uint64_t bytes_read = 0;
    std::uint64_t mapped_bytes = 0;
    std::uint64_t provider_leases = 0;
    std::uint64_t storage_bytes = 0;
};

class function_recovery_t final {
public:
    static workspace_result_t<block_recovery_result_t> build_blocks(
        const workspace_image_t& image,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<target_fact_t>& targets,
        const std::vector<function_seed_t>& seeds,
        const function_recovery_limits_t& limits,
        const cancellation_token_t& cancel);

    static workspace_result_t<function_recovery_result_t> recover_functions(
        const workspace_image_t& image,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<function_seed_t>& seeds,
        block_recovery_result_t blocks,
        const function_recovery_limits_t& limits,
        const cancellation_token_t& cancel);

    static workspace_result_t<function_recovery_result_t> finalize_cfg_calls(
        const workspace_image_t& image,
        const byte_provider_t& provider,
        const std::vector<instruction_record_t>& instructions,
        const std::vector<operand_fact_t>& operands,
        const std::vector<target_fact_t>& targets,
        function_recovery_result_t functions,
        const function_recovery_limits_t& limits,
        const cancellation_token_t& cancel);
};

}
