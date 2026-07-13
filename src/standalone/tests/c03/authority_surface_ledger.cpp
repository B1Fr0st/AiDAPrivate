#include "authority_surface_ledger.hpp"

#include <array>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aida::tests::c03 {
namespace {

using names_t = std::vector<std::string_view>;

constexpr std::array<std::string_view, 88> k_upstream_tool_names = {
    "add_bookmark", "analyze_batch", "analyze_component", "analyze_function", "append_comments", "basic_blocks", "callees", "callgraph", "dbg_add_bp", "dbg_bps", "dbg_continue", "dbg_delete_bp", "dbg_exit", "dbg_gpregs", "dbg_gpregs_remote", "dbg_read", "dbg_regs", "dbg_regs_all", "dbg_regs_named", "dbg_regs_named_remote", "dbg_regs_remote", "dbg_run_to", "dbg_set_bp_condition", "dbg_stacktrace", "dbg_start", "dbg_status", "dbg_step_into", "dbg_step_over", "dbg_toggle_bp", "dbg_write", "declare_stack", "declare_type", "decompile", "define_code", "define_func", "delete_stack", "diff_before_after", "disasm", "entity_query", "enum_upsert", "export_funcs", "find", "find_bytes", "find_regex", "find_xref_signatures", "force_recompile", "func_profile", "func_query", "get_bytes", "get_global_value", "get_int", "get_string", "idb_save", "imports", "imports_query", "infer_types", "insn_query", "int_convert", "list_funcs", "list_globals", "lookup_funcs", "make_data", "make_signature", "make_signature_for_function", "make_signature_for_range", "patch", "patch_asm", "put_int", "py_eval", "py_exec_file", "read_struct", "rename", "search_structs", "search_text", "server_health", "set_comments", "set_op_type", "set_type", "stack_frame", "survey_binary", "trace_data_flow", "type_apply_batch", "type_inspect", "type_query", "undefine", "xref_query", "xrefs_to", "xrefs_to_field"
};

constexpr std::array<std::string_view, 4> k_aida_extensions = {
    "analyze_funcs", "find_insns", "calculator", "calculate"
};

constexpr std::string_view k_archive_version = "2.0.0";
constexpr std::string_view k_archive_license = "MIT";
constexpr std::string_view k_archive_sha256 =
    "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7";

authority_surface_ledger_result_t fail(std::string failure) {
    return {false, std::move(failure)};
}

bool insert_unique(const names_t& names, std::unordered_set<std::string_view>& output) {
    for (const auto name : names) {
        if (name.empty() || !output.insert(name).second) return false;
    }
    return true;
}

authority_surface_ledger_result_t validate_surface(const names_t& upstream, const names_t& exclusions,
                                                   const names_t& local_compatibility,
                                                   const names_t& extensions) {
    std::unordered_set<std::string_view> upstream_set;
    if (!insert_unique(upstream, upstream_set) || upstream.size() != 88U || upstream_set.size() != 88U)
        return fail("upstream tool surface must contain 88 unique names");
    if (exclusions.size() != 1U || exclusions.front() != "py_eval" || upstream_set.find("py_eval") == upstream_set.end())
        return fail("py_eval must be the only excluded upstream tool");
    std::unordered_set<std::string_view> local_set;
    if (!insert_unique(local_compatibility, local_set) || local_set.size() != 1U ||
        local_set.find("list_instances") == local_set.end())
        return fail("list_instances must be the only proxy-local compatibility tool");
    names_t compatibility;
    compatibility.reserve(upstream.size());
    for (const auto name : upstream) {
        if (name != "py_eval") compatibility.push_back(name);
    }
    compatibility.insert(compatibility.end(), local_compatibility.begin(), local_compatibility.end());
    std::unordered_set<std::string_view> compatibility_set;
    if (!insert_unique(compatibility, compatibility_set) || compatibility.size() != 88U || compatibility_set.size() != 88U)
        return fail("required compatibility surface must contain 88 unique names");
    std::unordered_set<std::string_view> extension_set;
    if (!insert_unique(extensions, extension_set) || extension_set.size() != 4U)
        return fail("AiDA extension surface must contain four unique names");
    constexpr std::array<std::string_view, 4> expected_extensions = {
        "analyze_funcs", "find_insns", "calculator", "calculate"
    };
    for (const auto name : expected_extensions) {
        if (extension_set.find(name) == extension_set.end()) return fail("AiDA extension surface is incomplete");
        if (compatibility_set.find(name) != compatibility_set.end()) return fail("AiDA extension collides with compatibility surface");
    }
    compatibility_set.insert(extension_set.begin(), extension_set.end());
    if (compatibility_set.size() != 92U) return fail("compatibility-plus-extension union must contain 92 names");
    return {true, {}};
}

}

authority_surface_ledger_result_t run_authority_surface_ledger_harness() {
    if (k_archive_license != "MIT") return fail("pinned archive license must be MIT");
    if (k_archive_version != "2.0.0") return fail("pinned archive version must be 2.0.0");
    if (k_archive_sha256 != "3F7E7D9F534E3534C191D21251BBF0788DB14376C659488EA61681D48BC8D0F7")
        return fail("pinned archive SHA-256 fingerprint must match the authority ledger");
    const names_t upstream(k_upstream_tool_names.begin(), k_upstream_tool_names.end());
    const names_t exclusions = {"py_eval"};
    const names_t local_compatibility = {"list_instances"};
    const names_t extensions(k_aida_extensions.begin(), k_aida_extensions.end());
    const auto accepted = validate_surface(upstream, exclusions, local_compatibility, extensions);
    if (!accepted.passed) return accepted;
    auto duplicate = upstream;
    duplicate.back() = duplicate.front();
    if (validate_surface(duplicate, exclusions, local_compatibility, extensions).passed)
        return fail("duplicate upstream tool fixture was accepted");
    auto missing = upstream;
    missing.pop_back();
    if (validate_surface(missing, exclusions, local_compatibility, extensions).passed)
        return fail("missing upstream tool fixture was accepted");
    const names_t missing_local_compatibility;
    if (validate_surface(upstream, exclusions, missing_local_compatibility, extensions).passed)
        return fail("missing list_instances fixture was accepted");
    const names_t wrong_exclusions = {"py_eval", "py_exec_file"};
    if (validate_surface(upstream, wrong_exclusions, local_compatibility, extensions).passed)
        return fail("multiple excluded tool fixture was accepted");
    const names_t colliding_extensions = {"analyze_funcs", "find_insns", "calculator", "get_bytes"};
    if (validate_surface(upstream, exclusions, local_compatibility, colliding_extensions).passed)
        return fail("colliding extension fixture was accepted");
    return {true, {}};
}

}
