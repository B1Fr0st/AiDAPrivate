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
#include <dbg.hpp>
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
    static tool_result_t ok(const std::string& msg, const nlohmann::json& data = {});
    static tool_result_t error(const std::string& msg);
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
    tool_result_t get_callees(const nlohmann::json& params);
    tool_result_t get_callers(const nlohmann::json& params);
    tool_result_t get_stack_frame(const nlohmann::json& params);
    tool_result_t analyze_function(const nlohmann::json& params);
    tool_result_t define_function(const nlohmann::json& params);
    tool_result_t rename_function(const nlohmann::json& params);
    tool_result_t get_function_signature(const nlohmann::json& params);
    tool_result_t set_function_signature(const nlohmann::json& params);
    tool_result_t build_call_graph(const nlohmann::json& params);
    tool_result_t export_function(const nlohmann::json& params);
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
    tool_result_t patch_instruction(const nlohmann::json& params);
    tool_result_t make_code(const nlohmann::json& params);
    tool_result_t make_data(const nlohmann::json& params);
    tool_result_t undefine(const nlohmann::json& params);
    tool_result_t list_globals(const nlohmann::json& params);
    tool_result_t convert_number(const nlohmann::json& params);
    
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
    tool_result_t rename_address(const nlohmann::json& params);
    
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
    tool_result_t get_enum(const nlohmann::json& params);
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
    tool_result_t search_text(const nlohmann::json& params);
    tool_result_t advanced_search(const nlohmann::json& params);
    void register_tools();
}

namespace debugger_tools
{
    tool_result_t get_debugger_state(const nlohmann::json& params);
    tool_result_t start_process(const nlohmann::json& params);
    tool_result_t exit_process(const nlohmann::json& params);
    tool_result_t attach_process(const nlohmann::json& params);
    tool_result_t detach_process(const nlohmann::json& params);
    tool_result_t continue_execution(const nlohmann::json& params);
    tool_result_t run_to_address(const nlohmann::json& params);
    tool_result_t step_into(const nlohmann::json& params);
    tool_result_t step_over(const nlohmann::json& params);
    tool_result_t step_out(const nlohmann::json& params);
    tool_result_t suspend(const nlohmann::json& params);
    tool_result_t list_breakpoints(const nlohmann::json& params);
    tool_result_t add_breakpoint(const nlohmann::json& params);
    tool_result_t delete_breakpoint(const nlohmann::json& params);
    tool_result_t toggle_breakpoint(const nlohmann::json& params);
    tool_result_t get_registers(const nlohmann::json& params);
    tool_result_t set_register(const nlohmann::json& params);
    tool_result_t get_call_stack(const nlohmann::json& params);
    tool_result_t read_memory(const nlohmann::json& params);
    tool_result_t write_memory(const nlohmann::json& params);
    tool_result_t get_threads(const nlohmann::json& params);
    tool_result_t select_thread(const nlohmann::json& params);
    tool_result_t get_modules(const nlohmann::json& params);
    
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
    tool_result_t get_idb_info(const nlohmann::json& params);
    void register_tools();
}

namespace python_tools
{
    tool_result_t execute_python(const nlohmann::json& params);
    void register_tools();
}

namespace navigation_tools
{
    tool_result_t jump_to_address(const nlohmann::json& params);
    tool_result_t get_current_address(const nlohmann::json& params);
    tool_result_t demangle_name(const nlohmann::json& params);
    tool_result_t wait_for_analysis(const nlohmann::json& params);
    tool_result_t get_entry_points(const nlohmann::json& params);
    tool_result_t delete_function(const nlohmann::json& params);
    tool_result_t set_decompiler_comment(const nlohmann::json& params);
    tool_result_t batch_rename(const nlohmann::json& params);
    tool_result_t get_address_info(const nlohmann::json& params);
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