#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <ida.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

constexpr const char* k_chain_extraction_schema = "aida_chain_extraction_v1";

enum class layer_state_t
{
    ok,
    skipped,
    failed,
    timeout,
    unavailable,
    truncated
};

struct extraction_options_t
{
    bool include_bytes = true;
    bool include_xrefs = true;
    bool include_types = true;
    bool include_ctree = true;
    bool include_microcode = true;
    bool include_effects = true;
    bool include_xref_indexes = true;
    bool force_refresh = false;
    std::size_t max_instructions = 4096;
    std::size_t max_basic_blocks = 1024;
    std::size_t max_xrefs_per_address = 64;
    std::size_t max_ctree_nodes = 4096;
    std::size_t max_microcode_instructions = 4096;
    std::size_t max_pseudocode_lines = 512;
    std::size_t max_batch_functions = 128;
    std::size_t max_module_items = 200000;
    std::uint64_t timeout_ms = 0;
    std::vector<std::string> microcode_maturities = {"calls", "glbopt3", "lvars"};
};

struct layer_status_t
{
    std::string layer;
    layer_state_t state = layer_state_t::skipped;
    std::string reason;
    std::string exception_class;
    std::vector<std::string> fallback_layers;
    std::string cutoff_reason;
    std::uint64_t elapsed_ms = 0;
    std::size_t emitted = 0;
    std::size_t total = 0;
    bool cache_hit = false;
    bool timeout = false;
    bool cancelled = false;
    nlohmann::json diagnostics = nlohmann::json::object();
};

struct module_identity_t
{
    std::string module_id;
    std::string module_name;
    std::string input_path;
    std::string input_md5;
    std::string input_sha256;
    std::string processor;
    std::uint64_t image_base = 0;
    std::uint64_t min_ea = 0;
    std::uint64_t max_ea = 0;
    std::uint32_t pointer_width_bits = 0;
    bool big_endian = false;
};

struct address_identity_t
{
    module_identity_t module;
    std::uint64_t ea = 0;
    std::uint64_t rva = 0;
    bool has_rva = false;
    std::string segment_name;
    std::string segment_class;
    std::uint32_t segment_permissions = 0;
    std::string symbol_name;
    std::string demangled_name;
    std::uint64_t function_ea = 0;
    std::uint64_t function_rva = 0;
    std::string function_name;
    std::string api_confidence = "exact";
};

struct segment_fact_t
{
    std::string name;
    std::string klass;
    std::uint64_t start_ea = 0;
    std::uint64_t end_ea = 0;
    std::uint64_t start_rva = 0;
    std::uint64_t end_rva = 0;
    std::uint32_t permissions = 0;
    std::uint32_t type = 0;
};

struct xref_fact_t
{
    address_identity_t from;
    address_identity_t to;
    bool is_code = false;
    bool user = false;
    std::uint32_t type = 0;
    std::string direction;
    std::string source_disasm;
};

struct operand_fact_t
{
    int index = -1;
    std::string type;
    std::string value_ref = "unknown";
    std::string address_expr;
    std::string alias_class = "unknown";
    std::string type_ref;
    std::uint32_t type_id = 0;
    std::uint32_t dtype = 0;
    std::uint32_t width_bits = 0;
    std::int32_t offb = 0;
    std::int32_t offo = 0;
    std::uint64_t reg = 0;
    std::uint64_t phrase = 0;
    std::uint64_t value = 0;
    std::uint64_t address = 0;
    std::uint64_t specval = 0;
    std::uint32_t flags = 0;
    bool shown = true;
    std::string text;
    address_identity_t address_identity;
};

struct instruction_fact_t
{
    address_identity_t location;
    std::uint32_t itype = 0;
    std::uint32_t feature_flags = 0;
    std::uint64_t item_flags = 0;
    std::uint32_t size = 0;
    std::string mnemonic;
    std::string disassembly;
    std::string bytes_hex;
    std::vector<operand_fact_t> operands;
    nlohmann::json raw_effects = nlohmann::json::array();
    std::vector<std::string> register_uses;
    std::vector<std::string> register_defs;
    std::vector<xref_fact_t> xrefs_from;
    std::vector<xref_fact_t> xrefs_to;
    std::vector<std::uint64_t> branch_targets;
    std::int64_t stack_delta = 0;
    std::uint64_t fallthrough_ea = 0;
    bool has_fallthrough = false;
    bool is_call = false;
    bool is_return = false;
    bool is_branch = false;
    bool is_indirect = false;
    bool is_conditional = false;
    bool is_noreturn = false;
    bool block_end = false;
    bool unknown_effect = false;
};

struct basic_block_fact_t
{
    std::size_t id = 0;
    address_identity_t start;
    address_identity_t end;
    std::vector<std::uint64_t> instruction_eas;
    std::vector<std::size_t> predecessors;
    std::vector<std::size_t> successors;
    nlohmann::json edges = nlohmann::json::array();
    std::string terminal_kind;
    bool is_return = false;
    bool is_noreturn = false;
};

struct call_fact_t
{
    address_identity_t callsite;
    address_identity_t target;
    std::string kind;
    std::string callee_name;
    std::string resolution_quality = "unresolved";
    std::vector<std::string> target_preconditions;
    bool resolved = false;
    bool does_return = true;
    std::string confidence;
    std::vector<operand_fact_t> arguments;
};

struct branch_fact_t
{
    address_identity_t branch;
    std::string kind;
    std::string predicate_text;
    std::vector<address_identity_t> targets;
    std::uint64_t true_target_ea = 0;
    std::uint64_t false_target_ea = 0;
    std::vector<std::size_t> ctree_parent_ids;
    bool conditional = false;
};

struct type_fact_t
{
    bool present = false;
    bool is_function = false;
    bool is_noreturn = false;
    std::string type_text;
    std::string return_type;
    std::vector<std::string> arguments;
    std::vector<std::string> spoiled_registers;
    nlohmann::json argument_details = nlohmann::json::array();
    nlohmann::json local_variables = nlohmann::json::array();
    nlohmann::json stack_variables = nlohmann::json::array();
    nlohmann::json referenced_udts = nlohmann::json::array();
    nlohmann::json referenced_enums = nlohmann::json::array();
    nlohmann::json udt_layouts = nlohmann::json::array();
    nlohmann::json member_offsets = nlohmann::json::array();
    nlohmann::json dependencies = nlohmann::json::array();
};

struct ctree_node_fact_t
{
    std::size_t id = 0;
    address_identity_t location;
    std::string op;
    std::string role;
    std::string text;
    std::string type_text;
    std::string value_kind = "unknown";
    std::string callee_text;
    std::vector<std::string> argument_texts;
    std::vector<std::string> lvar_refs;
    nlohmann::json member_refs = nlohmann::json::array();
    nlohmann::json object_refs = nlohmann::json::array();
    nlohmann::json constants = nlohmann::json::array();
    std::size_t true_child_id = static_cast<std::size_t>(-1);
    std::size_t false_child_id = static_cast<std::size_t>(-1);
    std::vector<std::size_t> parent_ids;
    std::vector<std::uint64_t> parent_eas;
    bool is_call = false;
    bool is_assignment = false;
    bool is_branch = false;
    bool is_return = false;
    bool is_switch = false;
    bool is_loop = false;
    bool is_memory_ref = false;
};

struct ctree_fact_t
{
    layer_status_t status;
    std::vector<std::string> pseudocode_lines;
    nlohmann::json locals = nlohmann::json::array();
    std::vector<ctree_node_fact_t> nodes;
    nlohmann::json branch_facts = nlohmann::json::array();
    nlohmann::json call_facts = nlohmann::json::array();
    nlohmann::json assignment_facts = nlohmann::json::array();
    nlohmann::json memory_facts = nlohmann::json::array();
};

struct microcode_fact_t
{
    layer_status_t status;
    std::string maturity;
    nlohmann::json blocks = nlohmann::json::array();
    nlohmann::json calls = nlohmann::json::array();
    nlohmann::json use_def = nlohmann::json::array();
    nlohmann::json effects = nlohmann::json::array();
};

struct extraction_cache_status_t
{
    std::string schema = k_chain_extraction_schema;
    std::string key;
    std::string lookup_state = "miss";
    std::string invalidation_reason;
    bool hit = false;
    bool persistent = false;
    bool force_refresh = false;
    std::size_t memory_entries = 0;
    std::size_t memory_bytes = 0;
    std::size_t persistent_bytes = 0;
    std::uint64_t hits = 0;
    std::uint64_t misses = 0;
    std::uint64_t persistent_hits = 0;
    std::uint64_t stores = 0;
};

struct function_identity_t
{
    address_identity_t start;
    address_identity_t end;
    std::uint64_t size = 0;
    std::uint32_t flags = 0;
    bool does_return = true;
    bool is_thunk = false;
    bool is_tail = false;
    std::string byte_digest;
    std::string type_digest;
    std::string cache_key;
};

struct function_snapshot_t
{
    function_identity_t identity;
    extraction_cache_status_t cache;
    std::vector<layer_status_t> statuses;
    std::vector<instruction_fact_t> instructions;
    std::vector<basic_block_fact_t> basic_blocks;
    std::vector<xref_fact_t> xrefs_from;
    std::vector<xref_fact_t> xrefs_to;
    nlohmann::json xref_from_index = nlohmann::json::object();
    nlohmann::json xref_to_index = nlohmann::json::object();
    std::vector<call_fact_t> calls;
    std::vector<branch_fact_t> branches;
    nlohmann::json effects = nlohmann::json::array();
    type_fact_t type;
    ctree_fact_t ctree;
    std::vector<microcode_fact_t> microcode;
    nlohmann::json diagnostics = nlohmann::json::object();
    bool complete = false;
};

struct module_snapshot_t
{
    module_identity_t identity;
    std::vector<segment_fact_t> segments;
    std::vector<address_identity_t> entries;
    std::vector<address_identity_t> imports;
    nlohmann::json function_index = nlohmann::json::array();
    nlohmann::json mapped_items = nlohmann::json::array();
    nlohmann::json symbol_index = nlohmann::json::array();
    nlohmann::json xref_from_index = nlohmann::json::object();
    nlohmann::json xref_to_index = nlohmann::json::object();
    nlohmann::json resolver_index = nlohmann::json::object();
    extraction_cache_status_t cache;
    std::vector<layer_status_t> statuses;
};

struct function_batch_result_t
{
    module_identity_t module;
    std::vector<function_snapshot_t> functions;
    std::vector<layer_status_t> statuses;
    bool complete = false;
    bool cancelled = false;
    bool timeout = false;
    std::string reason;
};

module_snapshot_t extract_module_snapshot(const extraction_options_t& options = {});
function_snapshot_t extract_function_snapshot(ea_t ea, const extraction_options_t& options = {});
function_batch_result_t extract_function_batch(const std::vector<ea_t>& functions, const extraction_options_t& options = {});
nlohmann::json extraction_cache_status();
void clear_extraction_cache();
nlohmann::json build_cross_binary_resolver_index(const nlohmann::json& module_facts);
nlohmann::json resolve_cross_binary_reference(const nlohmann::json& module_facts, const nlohmann::json& reference);

nlohmann::json to_json(layer_state_t state);
nlohmann::json to_json(const layer_status_t& status);
nlohmann::json to_json(const module_identity_t& identity);
nlohmann::json to_json(const address_identity_t& identity);
nlohmann::json to_json(const segment_fact_t& segment);
nlohmann::json to_json(const xref_fact_t& xref);
nlohmann::json to_json(const operand_fact_t& operand);
nlohmann::json to_json(const instruction_fact_t& instruction);
nlohmann::json to_json(const basic_block_fact_t& block);
nlohmann::json to_json(const call_fact_t& call);
nlohmann::json to_json(const branch_fact_t& branch);
nlohmann::json to_json(const type_fact_t& type);
nlohmann::json to_json(const ctree_node_fact_t& node);
nlohmann::json to_json(const ctree_fact_t& ctree);
nlohmann::json to_json(const microcode_fact_t& microcode);
nlohmann::json to_json(const extraction_cache_status_t& cache);
nlohmann::json to_json(const function_identity_t& identity);
nlohmann::json to_json(const function_snapshot_t& snapshot);
nlohmann::json to_json(const module_snapshot_t& snapshot);
nlohmann::json to_json(const function_batch_result_t& batch);

}
}
}
