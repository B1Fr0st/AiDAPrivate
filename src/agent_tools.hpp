#pragma once

#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <map>

#include <ida.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <frame.hpp>
#include <typeinf.hpp>
#include <kernwin.hpp>
#include <hexrays.hpp>
#include <search.hpp>
#include <entry.hpp>
#include <lines.hpp>
#include <auto.hpp>
#include <nlohmann/json.hpp>

namespace agent_tools
{

struct tool_result_t
{
    bool success = false;
    std::string output;
    nlohmann::json data;
    // Stable, machine-branchable error code populated by the new error() overload below.
    // Canonical codes (extensible — agents are expected to treat unknown codes as fatal):
    //   bad_param | addr_not_in_code | no_function_at_addr | index_empty
    //   decompile_failed | microcode_failed | taint_no_path | smt_unsat
    //   timeout | not_implemented | binary_kind_mismatch | analysis_not_settled
    //   unknown
    // The legacy single-arg error() leaves this empty for backward compatibility.
    std::string error_code;
    static tool_result_t ok(const std::string& msg, const nlohmann::json& data = {});
    static tool_result_t error(const std::string& msg);
    // New overload — defined inline to avoid adding a definition to agent_tools.cpp in Slice A.
    // Coexists with the single-arg error() so existing callers and the existing .cpp definition
    // continue to resolve unchanged.
    static inline tool_result_t error(const std::string& msg, const std::string& code)
    {
        tool_result_t r;
        r.success = false;
        r.output = msg;
        r.error_code = code;
        return r;
    }
};

struct tool_param_t
{
    std::string name;
    std::string type;
    std::string description;
    bool required = true;
    std::vector<std::string> enum_values;
    nlohmann::json items_schema;
};

struct tool_definition_t
{
    std::string name;
    std::string category;
    std::string description;
    std::vector<tool_param_t> parameters;
    std::function<tool_result_t(const nlohmann::json&)> handler;
    bool read_only = true;
    // --- Slice A extensions (data-driven tool metadata) -----------------------
    // JSON Schema describing the shape of tool_result_t::data for this tool.
    // Empty when shape is variable; non-empty (and non-wildcard) where it is stable
    // so the agent can validate or strongly type the response.
    nlohmann::json output_schema;
    // Replaces the hard-coded is_destructive_tool() string list in mcp_server.cpp.
    // Destructive = mutates IDB state in a way that cannot be transparently undone
    // (writes/patches/renames/applies types/deletes). Read-only tools must keep
    // this false.
    bool destructive = false;
    // Replaces the hard-coded is_idempotent_tool() string list in mcp_server.cpp.
    // Deterministic = same arguments + same IDB state produce identical results.
    // Gates MCP dedup/cache layers. Tools that observe wall time, external state,
    // or random scheduling must set this false.
    bool deterministic = true;
    // Names of engines (e.g. "graphrag", "taint_engine", "microcode_engine",
    // "cfg_engine", "kernel_engine", "surface_engine", "symbolic_engine",
    // "smt_solver") that must be warm before the handler is invoked. Empty means
    // no precondition. The MCP layer is responsible for warming or short-circuiting
    // with error_code="index_empty".
    std::vector<std::string> required_indices;
};

class ToolRegistry
{
public:
    static ToolRegistry& instance();

    void register_tool(const tool_definition_t& tool);
    const tool_definition_t* get_tool(const std::string& name) const;
    std::vector<std::string> get_tool_names() const;
    std::vector<const tool_definition_t*> get_tools_by_category(const std::string& category) const;
    std::vector<const tool_definition_t*> get_all_tools() const;
    nlohmann::json generate_tools_schema() const;
    std::string generate_tools_description() const;
    tool_result_t execute_tool(const std::string& name, const nlohmann::json& params);
    // Slice B1: batched serial execution. Iterates `calls` in order. When
    // `stop_on_error` is true the iteration halts at the first failure.
    // If `out` is non-null every per-call result is appended in order
    // (including the failing one). Returns aggregate ok with summary text
    // when all succeeded, otherwise returns the first failing result so the
    // caller has a stable error_code to branch on.
    tool_result_t execute_tool_batch(
        const std::vector<std::pair<std::string, nlohmann::json>>& calls,
        bool stop_on_error,
        std::vector<tool_result_t>* out);

private:
    ToolRegistry() = default;
    std::map<std::string, tool_definition_t> _tools;
};

void initialize_all_tools();

namespace function_tools
{
    tool_result_t get_function(const nlohmann::json& params);
    tool_result_t list_functions(const nlohmann::json& params);
    tool_result_t decompile_function(const nlohmann::json& params);
    tool_result_t disassemble_function(const nlohmann::json& params);
    tool_result_t get_xrefs_to(const nlohmann::json& params);
    tool_result_t get_xrefs_from(const nlohmann::json& params);
    tool_result_t get_stack_frame(const nlohmann::json& params);
    tool_result_t define_function(const nlohmann::json& params);
    tool_result_t rename_function(const nlohmann::json& params);
    tool_result_t set_function_signature(const nlohmann::json& params);
    tool_result_t build_call_graph(const nlohmann::json& params);
    tool_result_t get_basic_blocks(const nlohmann::json& params);

    void register_tools();
}

namespace memory_tools
{
    tool_result_t read_bytes(const nlohmann::json& params);
    tool_result_t read_integer(const nlohmann::json& params);
    tool_result_t read_string(const nlohmann::json& params);
    tool_result_t read_global(const nlohmann::json& params);
    tool_result_t patch_bytes(const nlohmann::json& params);
    tool_result_t make_code(const nlohmann::json& params);
    tool_result_t make_data(const nlohmann::json& params);
    tool_result_t undefine(const nlohmann::json& params);
    tool_result_t list_globals(const nlohmann::json& params);

    void register_tools();
}

namespace comment_tools
{
    tool_result_t set_comment(const nlohmann::json& params);
    tool_result_t set_repeatable_comment(const nlohmann::json& params);
    tool_result_t set_function_comment(const nlohmann::json& params);
    tool_result_t get_comment(const nlohmann::json& params);
    tool_result_t set_extra_comment(const nlohmann::json& params);
    tool_result_t rename_variable(const nlohmann::json& params);

    void register_tools();
}

namespace type_tools
{
    tool_result_t declare_type(const nlohmann::json& params);
    tool_result_t apply_type(const nlohmann::json& params);
    tool_result_t infer_type(const nlohmann::json& params);
    tool_result_t search_structs(const nlohmann::json& params);
    tool_result_t get_struct(const nlohmann::json& params);
    tool_result_t create_struct(const nlohmann::json& params);
    tool_result_t add_struct_member(const nlohmann::json& params);
    tool_result_t get_struct_field_xrefs(const nlohmann::json& params);
    tool_result_t create_stack_var(const nlohmann::json& params);
    tool_result_t delete_stack_var(const nlohmann::json& params);
    tool_result_t read_struct_field(const nlohmann::json& params);
    tool_result_t list_types(const nlohmann::json& params);
    tool_result_t create_enum(const nlohmann::json& params);

    void register_tools();
}

namespace import_tools
{
    tool_result_t list_imports(const nlohmann::json& params);
    tool_result_t list_exports(const nlohmann::json& params);
    tool_result_t get_import(const nlohmann::json& params);
    void register_tools();
}

namespace search_tools
{
    tool_result_t search_strings(const nlohmann::json& params);
    tool_result_t find_bytes(const nlohmann::json& params);
    tool_result_t find_instructions(const nlohmann::json& params);
    tool_result_t find_immediate(const nlohmann::json& params);
    void register_tools();
}


namespace segment_tools
{
    tool_result_t list_segments(const nlohmann::json& params);
    tool_result_t get_segment(const nlohmann::json& params);
    tool_result_t create_segment(const nlohmann::json& params);
    void register_tools();
}

namespace binary_tools
{
    tool_result_t get_binary_info(const nlohmann::json& params);
    // Slice B7 — canonical merged binary identity/capability tool.
    tool_result_t binary_fingerprint(const nlohmann::json& params);
    void register_tools();
}

namespace meta_tools
{
    // Slice B2 — orchestrator that runs N tool calls serially or in parallel.
    tool_result_t tool_batch_call(const nlohmann::json& params);
    // Slice B3 — hardcoded hunt-type → workflow planner.
    tool_result_t plan_the_hunt(const nlohmann::json& params);
    // Slice B4 — engine population / IDB readiness snapshot.
    tool_result_t index_status(const nlohmann::json& params);
    // Slice B5 — warm named engines.
    tool_result_t build_index(const nlohmann::json& params);
    // Slice B6 — netnode-backed session scratch (set/get/append/list/delete).
    tool_result_t session_scratch(const nlohmann::json& params);
    // Slice B8 — pre-auth-likely entrypoint enumeration.
    tool_result_t list_remote_entrypoints(const nlohmann::json& params);
    // Slice B9 — expose mcp_output_cache_t to MCP agents.
    tool_result_t list_outputs(const nlohmann::json& params);
    // Slice B10 — keyword→tool capability map.
    tool_result_t ask_capability(const nlohmann::json& params);
    // Slice B11 — example arguments / sample result per tool.
    tool_result_t sample_tool_io(const nlohmann::json& params);

    void register_tools();
}

// Slice C12 — taint-engine MCP surface (forward declared mirror of meta_tools).
namespace sdk_underused_tools
{
    void register_tools();
}

namespace taint_tools_ext
{
    void register_tools();
}

// Slice H6-H12, H16 — graphrag MCP extensions (bulk decompile, string triangulation,
// bulk semantic analysis, structured filter, external-entries enumeration,
// security delta cursor, pre-auth taint, dispatch table extraction).
namespace graphrag_tools_ext
{
    void register_tools();
}

// Slice H13-H14 — binary-level extensions (registry list + IAT capability map).
namespace binary_tools_ext
{
    void register_tools();
}

namespace python_tools
{
    tool_result_t execute_python(const nlohmann::json& params);
    void register_tools();
}

namespace aida_ida_batch_tools
{
    void register_tools();
}

namespace navigation_tools
{
    tool_result_t jump_to_address(const nlohmann::json& params);
    tool_result_t get_current_address(const nlohmann::json& params);
    tool_result_t demangle_name(const nlohmann::json& params);
    tool_result_t wait_for_analysis(const nlohmann::json& params);
    tool_result_t delete_function(const nlohmann::json& params);
    tool_result_t set_decompiler_comment(const nlohmann::json& params);
    tool_result_t batch_rename(const nlohmann::json& params);
    tool_result_t get_address_info(const nlohmann::json& params);
    void register_tools();
}

namespace analysis_tools
{
    tool_result_t detect_obfuscation_patterns(const nlohmann::json& params);
    tool_result_t analyze_control_flow(const nlohmann::json& params);
    tool_result_t get_function_complexity(const nlohmann::json& params);
    tool_result_t analyze_string_decryption(const nlohmann::json& params);
    tool_result_t analyze_indirect_calls(const nlohmann::json& params);
    tool_result_t find_crypto_constants(const nlohmann::json& params);
    tool_result_t analyze_data_flow(const nlohmann::json& params);
    tool_result_t detect_anti_analysis(const nlohmann::json& params);
    tool_result_t analyze_pe_headers(const nlohmann::json& params);
    tool_result_t analyze_entropy(const nlohmann::json& params);
    tool_result_t detect_hooks(const nlohmann::json& params);
    tool_result_t detect_direct_syscalls(const nlohmann::json& params);
    tool_result_t resolve_api_hashes(const nlohmann::json& params);
    tool_result_t reconstruct_vtable(const nlohmann::json& params);
    tool_result_t classify_memory_pages(const nlohmann::json& params);
    tool_result_t detect_vm_handler_pattern(const nlohmann::json& params);
    tool_result_t map_vm_handler_table(const nlohmann::json& params);
    void register_tools();
}

namespace deobfuscation_tools
{
    tool_result_t nop_junk_instructions(const nlohmann::json& params);
    tool_result_t resolve_opaque_predicates(const nlohmann::json& params);
    tool_result_t patch_anti_debug(const nlohmann::json& params);
    tool_result_t decode_strings_in_function(const nlohmann::json& params);
    tool_result_t rebuild_function(const nlohmann::json& params);
    tool_result_t identify_protector(const nlohmann::json& params);
    tool_result_t deobfuscate_control_flow(const nlohmann::json& params);
    tool_result_t reconstruct_imports(const nlohmann::json& params);
    tool_result_t unpack_section(const nlohmann::json& params);
    tool_result_t full_deobfuscation_pass(const nlohmann::json& params);
    tool_result_t devirtualize_function(const nlohmann::json& params);
    void register_tools();
}

namespace graphrag_tools
{
    tool_result_t get_semantic_analysis(const nlohmann::json& params);
    tool_result_t search_semantic(const nlohmann::json& params);
    tool_result_t get_similar_functions(const nlohmann::json& params);
    tool_result_t get_call_context(const nlohmann::json& params);
    tool_result_t get_taint_paths(const nlohmann::json& params);
    tool_result_t get_community_info(const nlohmann::json& params);
    tool_result_t run_security_analysis(const nlohmann::json& params);
    tool_result_t run_taint_analysis(const nlohmann::json& params);
    tool_result_t detect_communities(const nlohmann::json& params);
    tool_result_t analyze_network_flow(const nlohmann::json& params);
    tool_result_t get_graph_stats(const nlohmann::json& params);
    tool_result_t get_security_overview(const nlohmann::json& params);
    tool_result_t get_activity_analysis(const nlohmann::json& params);
    tool_result_t get_all_communities(const nlohmann::json& params);
    void register_tools();
}

namespace helpers
{
    std::optional<ea_t> parse_address(const std::string& addr_str);
    std::vector<ea_t> parse_addresses(const nlohmann::json& param);
    std::string get_pseudocode(ea_t ea);
    std::string get_disassembly(ea_t start, ea_t end);
    std::string format_address(ea_t ea);
    std::string get_name_or_address(ea_t ea);
}

}
