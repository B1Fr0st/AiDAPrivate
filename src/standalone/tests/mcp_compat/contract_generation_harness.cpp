#include "contract_generation_harness.hpp"
#include "../c03/assertion_telemetry/assertion_telemetry.hpp"

#include "../../src/core/mcp/compat/ida_contracts_generated.hpp"

#include <string_view>

namespace aida::standalone::tests::mcp_compat {

namespace {

bool is_sha256(std::string_view value) {
    if (value.size() != 64) {
        return false;
    }
    for (const char character : value) {
        if ((character < '0' || character > '9') && (character < 'A' || character > 'F')) {
            return false;
        }
    }
    return true;
}

bool contains_forbidden_resource(std::string_view value) {
    return value.find("ida://") != std::string_view::npos;
}

bool contains_external_schema_reference(std::string_view value) {
    if (value.find("\"$schema\"") != std::string_view::npos ||
        value.find("\"$id\"") != std::string_view::npos) {
        return true;
    }
    const auto reference = value.find("\"$ref\"");
    if (reference == std::string_view::npos) {
        return false;
    }
    const auto separator = value.find(':', reference + 6U);
    if (separator == std::string_view::npos) {
        return true;
    }
    const auto quote = value.find('"', separator + 1U);
    if (quote == std::string_view::npos) {
        return true;
    }
    return quote + 2U >= value.size() || value.substr(quote + 1U, 2U) != "#/";
}

bool valid_effect_lock_pair(
    mcp::compat::contract_effect_t effect,
    mcp::compat::contract_lock_t lock) {
    using mcp::compat::contract_effect_t;
    using mcp::compat::contract_lock_t;
    switch (effect) {
    case contract_effect_t::workspace_read:
        return lock == contract_lock_t::workspace_shared;
    case contract_effect_t::workspace_checkpoint:
        return lock == contract_lock_t::workspace_checkpoint;
    case contract_effect_t::workspace_overlay_mutation:
        return lock == contract_lock_t::workspace_overlay_transaction;
    case contract_effect_t::debugger_read:
    case contract_effect_t::debugger_control:
    case contract_effect_t::debugger_write:
        return lock == contract_lock_t::debugger_lane;
    case contract_effect_t::isolated_python:
        return lock == contract_lock_t::python_worker;
    case contract_effect_t::registry_read:
        return lock == contract_lock_t::registry_read;
    }
    return false;
}

bool expected_read_only_for_effect(
    mcp::compat::contract_effect_t effect) {
    using mcp::compat::contract_effect_t;
    switch (effect) {
    case contract_effect_t::workspace_read:
    case contract_effect_t::registry_read:
    case contract_effect_t::debugger_read:
        return true;
    case contract_effect_t::workspace_checkpoint:
    case contract_effect_t::workspace_overlay_mutation:
    case contract_effect_t::debugger_control:
    case contract_effect_t::debugger_write:
    case contract_effect_t::isolated_python:
        return false;
    }
    return false;
}

}

bool run_contract_generation_harness(std::string& failure) {
    using namespace mcp::compat;

    static_assert(k_archive_tool_count == 88);
    static_assert(k_compatibility_tool_count == 88);
    static_assert(k_aida_extension_count == 4);
    static_assert(k_union_tool_count == 92);
    static_assert(k_compatibility_tool_count + k_aida_extension_count == k_union_tool_count);

    const auto reject = [&failure](std::string_view message) {
		aida::analysis::c03_test::assertion_telemetry::record_assertion(false, message, __FILE__, __LINE__);
        failure.assign(message.data(), message.size());
        return false;
    };

    if (!is_sha256(k_pinned_archive_sha256) || !is_sha256(k_generated_contract_ledger_sha256) ||
        !is_sha256(k_generated_effect_ledger_sha256) || !is_sha256(k_generated_archive_manifest_sha256)) {
        return reject("generated contract hashes are malformed");
    }
    if (k_pinned_archive_sha256 != "77FB255DEF04BA8ABD3D6BFA306916FA27597CF369D2863C4614ECFFEA288F0C") {
        return reject("pinned archive SHA-256 does not match the expected canonical value 77FB255DEF04BA8ABD3D6BFA306916FA27597CF369D2863C4614ECFFEA288F0C");
    }
    if (k_generated_contract_ledger_sha256.empty()) {
        return reject("generated contract ledger SHA-256 is empty");
    }
    {
        bool all_zero = true;
        bool all_same = true;
        const char first_char = k_generated_contract_ledger_sha256[0];
        for (const char c : k_generated_contract_ledger_sha256) {
            if (c != '0') all_zero = false;
            if (c != first_char) all_same = false;
        }
        if (all_zero || all_same) {
            return reject("generated contract ledger SHA-256 is a degenerate constant, not a genuine hash of the contract descriptors");
        }
    }
    if (k_generated_effect_ledger_sha256.empty()) {
        return reject("generated effect ledger SHA-256 is empty");
    }
    {
        bool effect_all_zero = true;
        bool effect_all_same = true;
        const char effect_first_char = k_generated_effect_ledger_sha256[0];
        for (const char c : k_generated_effect_ledger_sha256) {
            if (c != '0') effect_all_zero = false;
            if (c != effect_first_char) effect_all_same = false;
        }
        if (effect_all_zero || effect_all_same) {
            return reject("generated effect ledger SHA-256 is a degenerate constant, not a genuine hash of the effect descriptors");
        }
    }
    if (k_generated_effect_ledger_sha256 == k_generated_contract_ledger_sha256) {
        return reject("generated effect ledger SHA-256 must not equal the contract ledger SHA-256");
    }
    if (k_generated_effect_ledger_sha256 == k_generated_archive_manifest_sha256) {
        return reject("generated effect ledger SHA-256 must not equal the archive manifest SHA-256");
    }
    if (contract_count() != k_compatibility_tool_count) {
        return reject("generated compatibility contract count is incorrect");
    }
    if (k_aida_extension_names[0] != "analyze_funcs" || k_aida_extension_names[1] != "find_insns" ||
        k_aida_extension_names[2] != "calculator" || k_aida_extension_names[3] != "calculate") {
        return reject("generated AiDA extension ledger differs from the required surface");
    }

    std::size_t archive_backed = 0;
    std::size_t proxy_local = 0;
    std::string_view prior_name;
    for (std::size_t index = 0; index < contract_count(); ++index) {
        const auto& contract = contracts()[index];
        if (contract.name.empty() || (!prior_name.empty() && prior_name >= contract.name)) {
            return reject("generated compatibility contract names are not unique and sorted");
        }
        prior_name = contract.name;
        if (contract.name == "py_eval" || contains_forbidden_resource(contract.name) ||
            contains_forbidden_resource(contract.description) || contains_forbidden_resource(contract.input_schema_json) ||
            contains_forbidden_resource(contract.output_schema_json) || contains_forbidden_resource(contract.annotations_json)) {
            return reject("generated compatibility table contains an excluded MCP surface");
        }
        if (contains_external_schema_reference(contract.input_schema_json) ||
            contains_external_schema_reference(contract.output_schema_json) ||
            contains_external_schema_reference(contract.annotations_json)) {
            return reject("generated compatibility table contains an external schema, file, or network reference");
        }
        if (contract.description.empty() || contract.input_schema_json.empty() || contract.output_schema_json.empty() || contract.annotations_json.empty() || contract.adapter_symbol.empty()) {
            return reject("generated compatibility contract is missing required metadata");
        }
        if (!valid_effect_lock_pair(contract.effect, contract.lock)) {
            return reject("generated effect ledger has an invalid lock policy");
        }
        if (contract.read_only != expected_read_only_for_effect(contract.effect)) {
            return reject("generated contract read_only flag is inconsistent with its effect class");
        }
        if (contract.target_dependent != (contract.accepts_pid && contract.accepts_bin_name)) {
            return reject("generated target routing fields are inconsistent");
        }
        if (contract.name == "int_convert" || contract.name == "list_instances") {
            if (contract.target_dependent || contract.accepts_pid || contract.accepts_bin_name) {
                return reject("target-independent compatibility contract has routing fields");
            }
        } else if (!contract.target_dependent) {
            return reject("target-dependent compatibility contract is missing routing fields");
        }
        if (contract.archive_backed) {
            ++archive_backed;
            if (contract.source_line == 0 || contract.source_path == "proxy-local") {
                return reject("archive-backed compatibility contract lacks source provenance");
            }
        } else {
            ++proxy_local;
            if (contract.name != "list_instances" || contract.source_path != "proxy-local" || contract.source_line != 0) {
                return reject("unexpected proxy-local compatibility contract");
            }
        }
    }
    if (archive_backed != 87 || proxy_local != 1 || find_contract("py_eval") != nullptr ||
        find_contract("list_instances") == nullptr) {
        return reject("archive exclusion or proxy-local instance contract is incorrect");
    }
    const auto* list_instances = find_contract("list_instances");
    if (list_instances == nullptr || list_instances->target_dependent || list_instances->accepts_pid ||
        list_instances->accepts_bin_name || list_instances->input_schema_json.find("\"pid\"") != std::string_view::npos ||
        list_instances->input_schema_json.find("\"bin_name\"") != std::string_view::npos) {
        return reject("list_instances must remain proxy-local and target-independent");
    }
    const auto* declare_stack = find_contract("declare_stack");
    const auto* delete_stack = find_contract("delete_stack");
    if (declare_stack == nullptr || delete_stack == nullptr ||
        declare_stack->effect != contract_effect_t::workspace_overlay_mutation ||
        delete_stack->effect != contract_effect_t::workspace_overlay_mutation ||
        declare_stack->lock != contract_lock_t::workspace_overlay_transaction ||
        delete_stack->lock != contract_lock_t::workspace_overlay_transaction ||
        declare_stack->read_only || delete_stack->read_only) {
        return reject("stack compatibility mutation lacks overlay transaction policy");
    }
    const auto* idb_save = find_contract("idb_save");
    if (idb_save == nullptr || idb_save->effect != contract_effect_t::workspace_checkpoint ||
        idb_save->lock != contract_lock_t::workspace_checkpoint || idb_save->read_only ||
        idb_save->description.find("workspace") == std::string_view::npos ||
        idb_save->description.find("checkpoint") == std::string_view::npos ||
        idb_save->description.find("IDB") != std::string_view::npos ||
        idb_save->input_schema_json.find("Optional destination path") != std::string_view::npos ||
        idb_save->input_schema_json.find("current IDB path") != std::string_view::npos ||
        idb_save->output_schema_json.find("filesystem destination") == std::string_view::npos ||
        idb_save->annotations_json.find("IdbSaveResult") != std::string_view::npos ||
        idb_save->annotations_json.find("WorkspaceCheckpointResult") == std::string_view::npos) {
        return reject("idb_save must describe AiDA workspace checkpoint and flush semantics");
    }
    const auto* py_exec_file = find_contract("py_exec_file");
    if (py_exec_file == nullptr) {
        return reject("py_exec_file contract is missing from the compatibility table");
    }
    if (!py_exec_file->archive_backed) {
        return reject("py_exec_file must be archive-backed with source provenance");
    }
    if (py_exec_file->source_path == "proxy-local") {
        return reject("py_exec_file source_path must not be proxy-local");
    }
    if (!py_exec_file->accepts_pid || !py_exec_file->accepts_bin_name || !py_exec_file->target_dependent) {
        return reject("py_exec_file must be target-dependent with accepts_pid and accepts_bin_name");
    }
    for (const auto extension : k_aida_extension_names) {
        if (find_contract(extension) != nullptr) {
            return reject("AiDA extension overlaps the compatibility contract table");
        }
    }
    failure.clear();
	aida::analysis::c03_test::assertion_telemetry::record_assertion(
		true, "generated MCP contract inventory satisfied", __FILE__, __LINE__);
    return true;
}

}
