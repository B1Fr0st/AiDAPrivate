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
    tool_result_t get_processes(const nlohmann::json& params);
    tool_result_t continue_execution(const nlohmann::json& params);
    tool_result_t run_to_address(const nlohmann::json& params);
    tool_result_t step_into(const nlohmann::json& params);
    tool_result_t step_over(const nlohmann::json& params);
    tool_result_t step_out(const nlohmann::json& params);
    tool_result_t suspend(const nlohmann::json& params);
    tool_result_t wait_for_event(const nlohmann::json& params);
    tool_result_t list_breakpoints(const nlohmann::json& params);
    tool_result_t add_breakpoint(const nlohmann::json& params);
    tool_result_t delete_breakpoint(const nlohmann::json& params);
    tool_result_t toggle_breakpoint(const nlohmann::json& params);
    tool_result_t set_breakpoint_condition(const nlohmann::json& params);
    tool_result_t add_hardware_breakpoint(const nlohmann::json& params);
    tool_result_t get_registers(const nlohmann::json& params);
    tool_result_t set_register(const nlohmann::json& params);
    tool_result_t get_call_stack(const nlohmann::json& params);
    tool_result_t read_memory(const nlohmann::json& params);
    tool_result_t write_memory(const nlohmann::json& params);
    tool_result_t get_memory_map(const nlohmann::json& params);
    tool_result_t get_threads(const nlohmann::json& params);
    tool_result_t select_thread(const nlohmann::json& params);
    tool_result_t suspend_thread(const nlohmann::json& params);
    tool_result_t resume_thread(const nlohmann::json& params);
    tool_result_t get_modules(const nlohmann::json& params);
    tool_result_t enable_tracing(const nlohmann::json& params);
    tool_result_t get_trace_events(const nlohmann::json& params);
    tool_result_t get_trace_status(const nlohmann::json& params);
    tool_result_t clear_trace_events(const nlohmann::json& params);
    tool_result_t set_trace_size_tool(const nlohmann::json& params);
    tool_result_t get_exceptions(const nlohmann::json& params);
    tool_result_t set_debugger_options_tool(const nlohmann::json& params);
    tool_result_t get_debugger_event_log(const nlohmann::json& params);
    tool_result_t clear_debugger_event_log(const nlohmann::json& params);
    tool_result_t analyze_breakpoint_context(const nlohmann::json& params);
    tool_result_t trace_virtual_dispatch(const nlohmann::json& params);
    tool_result_t snapshot_execution_state(const nlohmann::json& params);
    tool_result_t compare_execution_states(const nlohmann::json& params);
    tool_result_t detect_vm_handler_pattern(const nlohmann::json& params);
    tool_result_t map_vm_handler_table(const nlohmann::json& params);

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
    void register_tools();
}

namespace driver_tools
{
    tool_result_t driver_connect(const nlohmann::json& params);
    tool_result_t driver_status(const nlohmann::json& params);
    tool_result_t driver_attach(const nlohmann::json& params);
    tool_result_t driver_read_memory(const nlohmann::json& params);
    tool_result_t driver_write_memory(const nlohmann::json& params);
    tool_result_t driver_dump_module(const nlohmann::json& params);
    tool_result_t driver_scan_pattern(const nlohmann::json& params);
    tool_result_t driver_read_string(const nlohmann::json& params);
    tool_result_t driver_read_pointer_chain(const nlohmann::json& params);
    tool_result_t driver_enumerate_modules(const nlohmann::json& params);
    tool_result_t driver_enumerate_kernel_modules(const nlohmann::json& params);
    tool_result_t driver_dump_kernel_module(const nlohmann::json& params);
    tool_result_t driver_read_kernel_memory(const nlohmann::json& params);
    tool_result_t driver_write_kernel_memory(const nlohmann::json& params);
    tool_result_t driver_allocate_memory(const nlohmann::json& params);
    tool_result_t driver_free_memory(const nlohmann::json& params);
    tool_result_t driver_call_function(const nlohmann::json& params);


    tool_result_t driver_get_thread_context(const nlohmann::json& params);
    tool_result_t driver_set_thread_context(const nlohmann::json& params);
    tool_result_t driver_enumerate_threads(const nlohmann::json& params);
    tool_result_t driver_suspend_thread(const nlohmann::json& params);
    tool_result_t driver_resume_thread(const nlohmann::json& params);
    tool_result_t driver_query_memory(const nlohmann::json& params);
    tool_result_t driver_protect_memory(const nlohmann::json& params);
    tool_result_t driver_enumerate_memory_regions(const nlohmann::json& params);
    tool_result_t driver_read_peb(const nlohmann::json& params);
    tool_result_t driver_spoof_debug_flags(const nlohmann::json& params);
    tool_result_t driver_set_hw_breakpoint(const nlohmann::json& params);
    tool_result_t driver_clear_hw_breakpoint(const nlohmann::json& params);
    tool_result_t driver_resolve_export(const nlohmann::json& params);
    tool_result_t driver_virtual_to_physical(const nlohmann::json& params);

    tool_result_t driver_defer_action(const nlohmann::json& params);
    tool_result_t driver_list_deferred_actions(const nlohmann::json& params);
    tool_result_t driver_cancel_deferred_action(const nlohmann::json& params);
    tool_result_t driver_get_deferred_results(const nlohmann::json& params);

    void register_tools();


    struct deferred_action_result_t
    {
        std::string action_type;
        bool success = false;
        std::string message;
        nlohmann::json data;
    };

    enum class deferred_status
    {
        pending,
        watching,
        triggered,
        completed,
        failed,
        cancelled,
        timed_out
    };

    struct deferred_action_t
    {
        int id = 0;
        std::string condition_type;
        std::string target_name;

        struct queued_tool_call_t
        {
            std::string tool_name;
            nlohmann::json params;
        };
        std::vector<queued_tool_call_t> tool_calls;

        int timeout_seconds = 300;
        int poll_interval_ms = 50;

        std::atomic<deferred_status> status{deferred_status::pending};
        std::string trigger_info;
        std::vector<deferred_action_result_t> results;
        std::string error;
        std::chrono::steady_clock::time_point created;
        std::chrono::steady_clock::time_point triggered_at;
    };

    class DeferredActionManager
    {
    public:
        static DeferredActionManager& instance();

        int register_action(std::unique_ptr<deferred_action_t> action);
        bool cancel_action(int id);
        const deferred_action_t* get_action(int id) const;
        std::vector<const deferred_action_t*> get_all_actions() const;
        void shutdown();

        bool poll_kernel_module_load(const std::string& target, std::uint64_t& out_base, std::uint32_t& out_size, std::string& out_name, std::string& out_path);
        bool poll_process_start(const std::string& target, std::uint32_t& out_pid);

    private:
        DeferredActionManager() = default;
        ~DeferredActionManager();

        void watcher_thread_func(int action_id);
        std::string resolve_template(const std::string& value, const nlohmann::json& context);
        nlohmann::json resolve_params(const nlohmann::json& params, const nlohmann::json& context);
        void execute_deferred_tools(deferred_action_t& action, const nlohmann::json& context);

        mutable std::mutex _mutex;
        std::map<int, std::unique_ptr<deferred_action_t>> _actions;
        std::map<int, std::thread> _watchers;
        int _next_id = 1;
        std::atomic<bool> _shutdown{false};
    };
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
