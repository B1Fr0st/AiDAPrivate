#include "typed_ast_v2.hpp"

#include "../../../helpers/diag_log.hpp"
#include "../builtin_typelib.hpp"
#include "type_graph_builder.hpp"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <type_traits>
#include <utility>

namespace aida::analysis {
namespace {

struct penalty_scope_t {
    bool& flag;
    bool previous;
    explicit penalty_scope_t(bool& f) noexcept : flag(f), previous(f) { flag = true; }
    ~penalty_scope_t() { flag = previous; }
    penalty_scope_t(const penalty_scope_t&) = delete;
    penalty_scope_t& operator=(const penalty_scope_t&) = delete;
};

bool is_expression_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind == typed_pseudocode_ast_node_kind_t::assignment_expression ||
           kind == typed_pseudocode_ast_node_kind_t::unary_expression ||
           kind == typed_pseudocode_ast_node_kind_t::binary_expression ||
           kind == typed_pseudocode_ast_node_kind_t::cast_expression ||
           kind == typed_pseudocode_ast_node_kind_t::call_expression ||
           kind == typed_pseudocode_ast_node_kind_t::member_expression ||
           kind == typed_pseudocode_ast_node_kind_t::index_expression ||
           kind == typed_pseudocode_ast_node_kind_t::identifier ||
           kind == typed_pseudocode_ast_node_kind_t::literal ||
           kind == typed_pseudocode_ast_node_kind_t::unknown_expression;
}

bool is_statement_kind(const typed_pseudocode_ast_node_kind_t kind) noexcept
{
    return kind == typed_pseudocode_ast_node_kind_t::compound_statement ||
           kind == typed_pseudocode_ast_node_kind_t::declaration ||
           kind == typed_pseudocode_ast_node_kind_t::expression_statement ||
           kind == typed_pseudocode_ast_node_kind_t::if_statement ||
           kind == typed_pseudocode_ast_node_kind_t::while_statement ||
           kind == typed_pseudocode_ast_node_kind_t::do_while_statement ||
           kind == typed_pseudocode_ast_node_kind_t::for_statement ||
           kind == typed_pseudocode_ast_node_kind_t::switch_statement ||
           kind == typed_pseudocode_ast_node_kind_t::break_statement ||
           kind == typed_pseudocode_ast_node_kind_t::continue_statement ||
           kind == typed_pseudocode_ast_node_kind_t::return_statement ||
           kind == typed_pseudocode_ast_node_kind_t::throw_statement ||
           kind == typed_pseudocode_ast_node_kind_t::try_statement ||
           kind == typed_pseudocode_ast_node_kind_t::goto_statement ||
           kind == typed_pseudocode_ast_node_kind_t::label_statement ||
           kind == typed_pseudocode_ast_node_kind_t::comment_statement;
}

bool is_visible_text(const std::string& value) noexcept
{
    return !value.empty() && std::none_of(value.begin(), value.end(), [](const char character) {
        return character == '\r' || character == '\n' || character == '\0';
    });
}

bool is_unary_operator(const std::string& value) noexcept
{
    static const std::set<std::string> values{
        "!", "~", "+", "-", "*", "&", "++", "--"};
    return values.find(value) != values.end();
}

bool is_binary_operator(const std::string& value) noexcept
{
    static const std::set<std::string> values{
        "*", "/", "%", "+", "-", "<<", ">>", "<", "<=", ">", ">=", "==", "!=", "&", "^", "|", "&&", "||"};
    return values.find(value) != values.end();
}

source_coordinate_t translate_coordinate(const source_coordinate_t& value, const decompiler_coordinate_layer_t layer)
{
    auto result = value;
    result.layer = layer;
    if (layer != decompiler_coordinate_layer_t::document)
        result.document_range.reset();
    return result;
}

decompiler_diagnostic_t make_diagnostic(
    const decompiler_diagnostic_code_t code,
    std::string key,
    const std::uint32_t ordinal,
    const std::optional<source_coordinate_t>& coordinate = std::nullopt,
    const decompiler_diagnostic_severity_t severity = decompiler_diagnostic_severity_t::error,
    const std::uint8_t confidence = 100)
{
    decompiler_diagnostic_t result;
    result.severity = severity;
    result.code = code;
    result.localization_key = std::move(key);
    result.coordinate = coordinate;
    result.confidence = confidence;
    result.ordinal = ordinal;
    return result;
}

void append_validation_diagnostics(
    typed_ast_v2_build_result_t& result,
    const decompiler_contract_validation_t& validation)
{
    result.diagnostics.insert(result.diagnostics.end(), validation.diagnostics.begin(), validation.diagnostics.end());
}

std::string function_name(const decompiler_entity_key_t& entity)
{
    return std::visit([](const auto& identity) -> std::string {
        using identity_t = std::decay_t<decltype(identity)>;
        if constexpr (std::is_same_v<identity_t, native_decompiler_entity_identity_t>)
            return identity.canonical_symbol;
        else {
            if (identity.method_name == "<init>")
                return "constructor";
            if (identity.method_name == "<clinit>")
                return "static_initializer";
            return identity.method_name;
        }
    }, entity.identity);
}

struct conditional_descriptor_t {
    std::uint64_t true_successor = 0;
    bool negated = false;
};

std::optional<conditional_descriptor_t> conditional_descriptor(const std::string& value)
{
    constexpr std::string_view prefix = "condition.true=";
    constexpr std::string_view separator = ";negated=";
    if (value.size() <= prefix.size() ||
        value.compare(0, prefix.size(), prefix.data(), prefix.size()) != 0)
        return std::nullopt;
    const auto separator_offset = value.find(separator, prefix.size());
    if (separator_offset == std::string::npos)
        return std::nullopt;
    conditional_descriptor_t result;
    const char* begin = value.data() + prefix.size();
    const char* end = value.data() + separator_offset;
    const auto parsed = std::from_chars(begin, end, result.true_successor);
    if (parsed.ec != std::errc{} || parsed.ptr != end || result.true_successor == 0)
        return std::nullopt;
    const auto flag_offset = separator_offset + separator.size();
    if (flag_offset + 1U != value.size() || (value[flag_offset] != '0' && value[flag_offset] != '1'))
        return std::nullopt;
    result.negated = value[flag_offset] == '1';
    return result;
}

struct switch_case_entry_t {
    std::string value;
    std::uint64_t target_block = 0;
};

struct switch_descriptor_t {
    std::vector<switch_case_entry_t> cases;
    std::uint64_t default_target = 0;
};

std::optional<switch_descriptor_t> switch_descriptor(const std::string& value)
{
    constexpr std::string_view case_prefix = "case.";
    constexpr std::string_view default_prefix = "default=";
    if (value.empty() || value.find(case_prefix) == std::string::npos)
        return std::nullopt;
    switch_descriptor_t result;
    std::size_t pos = 0;
    while (pos < value.size()) {
        const auto sep = value.find(';', pos);
        const std::string token = sep == std::string::npos
            ? value.substr(pos) : value.substr(pos, sep - pos);
        if (token.compare(0, case_prefix.size(), case_prefix.data(), case_prefix.size()) == 0) {
            const auto eq = token.find('=', case_prefix.size());
            if (eq == std::string::npos)
                return std::nullopt;
            switch_case_entry_t entry;
            entry.value = token.substr(case_prefix.size(), eq - case_prefix.size());
            const auto begin = token.data() + eq + 1;
            const auto end = token.data() + token.size();
            const auto parsed = std::from_chars(begin, end, entry.target_block);
            if (parsed.ec != std::errc{} || parsed.ptr != end || entry.target_block == 0)
                return std::nullopt;
            result.cases.push_back(std::move(entry));
        } else if (token.compare(0, default_prefix.size(), default_prefix.data(), default_prefix.size()) == 0) {
            const auto begin = token.data() + default_prefix.size();
            const auto end = token.data() + token.size();
            const auto parsed = std::from_chars(begin, end, result.default_target);
            if (parsed.ec != std::errc{} || parsed.ptr != end || result.default_target == 0)
                return std::nullopt;
        }
        if (sep == std::string::npos)
            break;
        pos = sep + 1;
    }
    if (result.cases.empty())
        return std::nullopt;
    return result;
}

class ast_builder_t {
public:
    ast_builder_t(
        const hir_function_t& hir,
        const type_graph_t& type_graph,
        const typed_ast_v2_build_request_t& request,
        typed_ast_v2_build_result_t& result)
        : hir_(hir), type_graph_(type_graph), request_(request), result_(result)
    {
    }

    bool run()
    {
        if (!preflight())
            return false;
        initialize_ast();
        if (!append_declarations(hir_.parameters, true) || !append_declarations(hir_.locals, false))
            return false;
        if (!append_statements())
            return false;
        if (body_statement_ids_.empty()) {
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.empty_proven_body", body_coordinate_);
            return false;
        }
        ast_.nodes[0].child_ids = parameter_declaration_ids_;
        ast_.nodes[0].child_ids.push_back(ast_.body_node_id);
        ast_.nodes[1].child_ids = local_declaration_ids_;
        ast_.nodes[1].child_ids.insert(
            ast_.nodes[1].child_ids.end(), body_statement_ids_.begin(), body_statement_ids_.end());
        ast_.source_coordinates.reserve(hir_.source_coordinates.size() + hir_.blocks.size());
        for (const auto& coordinate : hir_.source_coordinates)
            ast_.source_coordinates.push_back(translate_coordinate(coordinate, decompiler_coordinate_layer_t::typed_ast));
        for (const auto& block : hir_.blocks)
            ast_.source_coordinates.push_back(translate_coordinate(block.coordinate, decompiler_coordinate_layer_t::typed_ast));
        append_diagnostics_and_unknowns();
        const auto validation = validate_typed_ast_v2_semantics(ast_, type_graph_);
        if (!validation.valid()) {
            append_validation_diagnostics(result_, validation);
            return false;
        }
        result_.ast = std::move(ast_);
        return true;
    }

private:
    enum class value_state_t : std::uint8_t {
        unvisited,
        active,
        complete
    };

    struct natural_loop_t {
        std::uint64_t header = 0;
        std::set<std::uint64_t> nodes;
        std::set<std::uint64_t> latches;
    };

    struct exception_region_t {
        std::uint64_t entry = 0;
        std::uint64_t continuation = 0;
        std::set<std::uint64_t> protected_blocks;
        std::vector<std::uint64_t> handler_entries;
        std::map<std::uint64_t, std::set<std::uint64_t>> handler_blocks;
    };

    bool preflight()
    {
        if (!(hir_.entity == type_graph_.entity) || hir_.type_graph_revision != type_graph_.revision) {
            fail(decompiler_diagnostic_code_t::malformed_type_graph, "decompiler.ast.v2.type_graph_revision");
            return false;
        }
        if (request_.limits.max_hir_values == 0 || request_.limits.max_ast_nodes < 3 ||
            request_.limits.max_expression_nesting == 0) {
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.invalid_limits");
            return false;
        }
        if (function_name(hir_.entity).empty()) {
            fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.ast.v2.function_name");
            return false;
        }
        for (const auto& type : type_graph_.nodes)
            types_.emplace(type.id, &type);
        if (types_.find(hir_.return_type_id) == types_.end()) {
            fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.return_type");
            return false;
        }
        for (const auto& block : hir_.blocks)
            blocks_.emplace(block.id, &block);
        std::size_t value_count = 0;
        for (const auto& block : hir_.blocks) {
            for (const auto& value : block.values) {
                if (++value_count > request_.limits.max_hir_values) {
                    fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.hir_value_limit", block.coordinate);
                    return false;
                }
                values_.emplace(value.id, &value);
                states_.emplace(value.id, value_state_t::unvisited);
                use_counts_.emplace(value.id, 0);
                if (types_.find(value.type_id) == types_.end()) {
                    fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.value_type", value.coordinate);
                    return false;
                }
            }
        }
        for (const auto& variable : hir_.parameters) {
            if (types_.find(variable.type_id) == types_.end()) {
                fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.parameter_type", variable.coordinate);
                return false;
            }
        }
        for (const auto& variable : hir_.locals) {
            if (types_.find(variable.type_id) == types_.end()) {
                fail(decompiler_diagnostic_code_t::unresolved_type, "decompiler.ast.v2.local_type", variable.coordinate);
                return false;
            }
        }
        for (const auto& entry : values_) {
            const auto* value = entry.second;
            for (const auto operand : value->operand_ids) {
                if (values_.find(operand) == values_.end()) {
                    fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.missing_operand", value->coordinate);
                    return false;
                }
                ++use_counts_[operand];
            }
        }
        for (const auto& entry : values_) {
            const auto id = entry.first;
            const auto* value = entry.second;
            if ((value->kind == hir_node_kind_t::assignment || value->kind == hir_node_kind_t::store ||
                 value->kind == hir_node_kind_t::return_value || value->kind == hir_node_kind_t::throw_value) &&
                use_counts_[id] != 0) {
                fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.terminal_value_use", value->coordinate);
                return false;
            }
            if (!supported_hir_kind(value->kind)) {
                record_degradation("decompiler.ast.v2.unstructured_control_flow", value->coordinate);
            }
        }
        if (!verify_control_flow())
            return false;
        if (degraded_)
            return true;
        if (!analyze_exception_regions()) {
            record_degradation(std::move(exception_analysis_failure_key_),
                exception_analysis_failure_coordinate_);
            exception_regions_.clear();
            handler_region_owners_.clear();
            return true;
        }
        return analyze_control_flow();
    }

    bool verify_control_flow()
    {
        for (const auto& entry : blocks_) {
            normal_predecessors_.try_emplace(entry.first);
            exception_predecessors_.try_emplace(entry.first);
        }
        for (const auto& block : hir_.blocks) {
            for (const auto successor : block.successor_ids) {
                if (std::binary_search(block.exception_successor_ids.begin(),
                        block.exception_successor_ids.end(), successor)) {
                    fail(decompiler_diagnostic_code_t::malformed_hir,
                        "decompiler.ast.v2.ambiguous_exception_edge", block.coordinate);
                    return false;
                }
                normal_predecessors_.at(successor).push_back(block.id);
            }
            for (const auto successor : block.exception_successor_ids) {
                if (successor == block.id) {
                    fail(decompiler_diagnostic_code_t::malformed_hir,
                        "decompiler.ast.v2.exception_self_edge", block.coordinate);
                    return false;
                }
                exception_predecessors_.at(successor).push_back(block.id);
                exception_handler_entries_.insert(successor);
            }
        }
        for (auto& entry : normal_predecessors_)
            std::sort(entry.second.begin(), entry.second.end());
        for (auto& entry : exception_predecessors_)
            std::sort(entry.second.begin(), entry.second.end());

        std::vector<std::uint64_t> entries;
        for (const auto& block : hir_.blocks) {
            std::vector<std::uint64_t> expected_predecessors;
            std::set_union(normal_predecessors_.at(block.id).begin(),
                normal_predecessors_.at(block.id).end(),
                exception_predecessors_.at(block.id).begin(),
                exception_predecessors_.at(block.id).end(),
                std::back_inserter(expected_predecessors));
            if (expected_predecessors != block.predecessor_ids) {
                record_degradation("decompiler.ast.v2.asymmetric_predecessor", block.coordinate);
            }
            if (expected_predecessors.empty())
                entries.push_back(block.id);
            for (const auto successor : block.successor_ids) {
                const auto target = blocks_.find(successor);
                if (target == blocks_.end() ||
                    !std::binary_search(target->second->predecessor_ids.begin(),
                        target->second->predecessor_ids.end(), block.id)) {
                    record_degradation("decompiler.ast.v2.asymmetric_successor", block.coordinate);
                }
            }
            for (const auto successor : block.exception_successor_ids) {
                const auto target = blocks_.find(successor);
                if (target == blocks_.end() ||
                    !std::binary_search(target->second->predecessor_ids.begin(),
                        target->second->predecessor_ids.end(), block.id)) {
                    record_degradation("decompiler.ast.v2.asymmetric_exception_successor", block.coordinate);
                }
            }
            std::size_t condition_count = 0;
            std::size_t switch_count = 0;
            bool terminal = false;
            for (const auto& value : block.values) {
                if (value.kind == hir_node_kind_t::conditional) {
                    ++condition_count;
                    const auto descriptor = conditional_descriptor(value.stable_value);
                    if (value.operand_ids.size() != 1 || !descriptor ||
                        !std::binary_search(block.successor_ids.begin(), block.successor_ids.end(),
                            descriptor->true_successor)) {
                        record_degradation("decompiler.ast.v2.unstructured_control_flow", value.coordinate);
                    }
                } else if (value.kind == hir_node_kind_t::switch_branch) {
                    ++switch_count;
                    if (value.operand_ids.empty()) {
                        record_degradation("decompiler.ast.v2.unstructured_control_flow", value.coordinate);
                    }
                } else if (value.kind == hir_node_kind_t::branch && !value.operand_ids.empty()) {
                    fail(decompiler_diagnostic_code_t::malformed_hir,
                        "decompiler.ast.v2.branch_payload", value.coordinate);
                    return false;
                }
                if (value.kind == hir_node_kind_t::return_value ||
                    value.kind == hir_node_kind_t::throw_value)
                    terminal = true;
            }
            const bool has_switch = switch_count > 0;
            if (has_switch) {
                if (condition_count != 0 || block.successor_ids.size() < 2 ||
                    (terminal && !block.successor_ids.empty())) {
                    record_degradation("decompiler.ast.v2.unstructured_control_flow", block.coordinate);
                }
            } else {
                if ((block.successor_ids.size() == 2 && condition_count != 1) ||
                    (block.successor_ids.size() != 2 && condition_count != 0) ||
                    (terminal && !block.successor_ids.empty())) {
                    record_degradation("decompiler.ast.v2.unstructured_control_flow", block.coordinate);
                }
            }
        }
        if (entries.size() != 1) {
            fail(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.ast.v2.entry_block_identity");
            return false;
        }
        entry_block_id_ = entries.front();
        std::set<std::uint64_t> reachable;
        std::vector<std::uint64_t> pending{entry_block_id_};
        while (!pending.empty()) {
            const auto id = pending.back();
            pending.pop_back();
            if (!reachable.insert(id).second)
                continue;
            const auto* block = blocks_.at(id);
            pending.insert(pending.end(), block->successor_ids.begin(),
                block->successor_ids.end());
            pending.insert(pending.end(), block->exception_successor_ids.begin(),
                block->exception_successor_ids.end());
        }
        if (!degraded_ && reachable.size() != blocks_.size()) {
            fail(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.ast.v2.unreachable_block");
            return false;
        }
        return true;
    }

    bool analyze_exception_regions()
    {
        std::set<std::uint64_t> protected_blocks;
        for (const auto& entry : blocks_) {
            if (!entry.second->exception_successor_ids.empty())
                protected_blocks.insert(entry.first);
        }
        for (const auto handler : exception_handler_entries_) {
            if (protected_blocks.find(handler) != protected_blocks.end()) {
                return fail_exception_analysis(
                    "decompiler.ast.v2.ambiguous_exception_overlap",
                    blocks_.at(handler)->coordinate);
            }
        }
        for (const auto block_id : protected_blocks) {
            const auto* block = blocks_.at(block_id);
            for (const auto successor : block->successor_ids) {
                if (protected_blocks.find(successor) != protected_blocks.end() &&
                    block->exception_successor_ids !=
                        blocks_.at(successor)->exception_successor_ids) {
                    return fail_exception_analysis(
                        "decompiler.ast.v2.ambiguous_exception_overlap",
                        block->coordinate);
                }
            }
        }

        std::set<std::uint64_t> unassigned = protected_blocks;
        std::set<std::uint64_t> claimed_handler_blocks;
        while (!unassigned.empty()) {
            const auto seed = *unassigned.begin();
            const auto handler_entries = blocks_.at(seed)->exception_successor_ids;
            std::set<std::uint64_t> component;
            std::vector<std::uint64_t> pending{seed};
            while (!pending.empty()) {
                const auto current = pending.back();
                pending.pop_back();
                if (unassigned.find(current) == unassigned.end() ||
                    blocks_.at(current)->exception_successor_ids != handler_entries ||
                    !component.insert(current).second)
                    continue;
                unassigned.erase(current);
                for (const auto successor : blocks_.at(current)->successor_ids) {
                    if (protected_blocks.find(successor) != protected_blocks.end())
                        pending.push_back(successor);
                }
                for (const auto predecessor : normal_predecessors_.at(current)) {
                    if (protected_blocks.find(predecessor) != protected_blocks.end())
                        pending.push_back(predecessor);
                }
            }

            std::vector<std::uint64_t> entries;
            std::set<std::uint64_t> continuations;
            for (const auto block_id : component) {
                const auto& predecessors = normal_predecessors_.at(block_id);
                if (block_id == entry_block_id_ ||
                    std::any_of(predecessors.begin(), predecessors.end(),
                        [&component](const std::uint64_t predecessor) {
                            return component.find(predecessor) == component.end();
                        }))
                    entries.push_back(block_id);
                for (const auto successor : blocks_.at(block_id)->successor_ids) {
                    if (component.find(successor) == component.end())
                        continuations.insert(successor);
                }
            }
            if (entries.size() != 1 || continuations.size() > 1) {
                return fail_exception_analysis(
                    "decompiler.ast.v2.ambiguous_exception_region",
                    blocks_.at(seed)->coordinate);
            }

            exception_region_t region;
            region.entry = entries.front();
            region.continuation = continuations.empty() ? 0 : *continuations.begin();
            region.protected_blocks = std::move(component);
            region.handler_entries = handler_entries;
            if (exception_handler_entries_.find(region.continuation) !=
                    exception_handler_entries_.end()) {
                return fail_exception_analysis(
                    "decompiler.ast.v2.ambiguous_exception_continuation",
                    blocks_.at(region.entry)->coordinate);
            }

            for (const auto handler : region.handler_entries) {
                const auto owner = handler_region_owners_.emplace(handler, region.entry);
                if (!owner.second) {
                    return fail_exception_analysis(
                        "decompiler.ast.v2.shared_exception_handler",
                        blocks_.at(handler)->coordinate);
                }
                std::set<std::uint64_t> handler_blocks;
                std::vector<std::uint64_t> handler_pending{handler};
                while (!handler_pending.empty()) {
                    const auto current = handler_pending.back();
                    handler_pending.pop_back();
                    if (current == region.continuation)
                        continue;
                    if (protected_blocks.find(current) != protected_blocks.end() ||
                        (current != handler && exception_handler_entries_.find(current) !=
                            exception_handler_entries_.end()) ||
                        claimed_handler_blocks.find(current) != claimed_handler_blocks.end()) {
                        return fail_exception_analysis(
                            "decompiler.ast.v2.ambiguous_exception_handler_body",
                            blocks_.at(current)->coordinate);
                    }
                    if (!handler_blocks.insert(current).second)
                        continue;
                    handler_pending.insert(handler_pending.end(),
                        blocks_.at(current)->successor_ids.begin(),
                        blocks_.at(current)->successor_ids.end());
                }
                for (const auto block_id : handler_blocks) {
                    const auto& predecessors = normal_predecessors_.at(block_id);
                    if (std::any_of(predecessors.begin(), predecessors.end(),
                            [&handler_blocks](const std::uint64_t predecessor) {
                                return handler_blocks.find(predecessor) ==
                                    handler_blocks.end();
                            })) {
                        return fail_exception_analysis(
                            "decompiler.ast.v2.ambiguous_exception_handler_merge",
                            blocks_.at(block_id)->coordinate);
                    }
                }
                claimed_handler_blocks.insert(handler_blocks.begin(),
                    handler_blocks.end());
                region.handler_blocks.emplace(handler, std::move(handler_blocks));
            }
            const auto inserted = exception_regions_.emplace(region.entry,
                std::move(region));
            if (!inserted.second) {
                return fail_exception_analysis(
                    "decompiler.ast.v2.ambiguous_exception_region",
                    blocks_.at(seed)->coordinate);
            }
        }
        return true;
    }

    bool analyze_control_flow()
    {
        std::set<std::uint64_t> all;
        for (const auto& entry : blocks_)
            all.insert(entry.first);
        std::set<std::uint64_t> normal_roots = exception_handler_entries_;
        normal_roots.insert(entry_block_id_);
        for (const auto& entry : blocks_) {
            if (normal_predecessors_.at(entry.first).empty() &&
                normal_roots.find(entry.first) == normal_roots.end()) {
                fail(decompiler_diagnostic_code_t::malformed_ast,
                    "decompiler.ast.v2.unreachable_block",
                    entry.second->coordinate);
                return false;
            }
        }
        for (const auto& entry : blocks_)
            dominators_[entry.first] = normal_roots.find(entry.first) !=
                normal_roots.end() ? std::set<std::uint64_t>{entry.first} : all;
        bool changed = true;
        std::size_t dom_iterations = 0;
        const std::size_t max_dom_iterations = blocks_.size() + 1;
        while (changed && dom_iterations < max_dom_iterations) {
            changed = false;
            ++dom_iterations;
            for (const auto& entry : blocks_) {
                const auto id = entry.first;
                const auto& predecessors = normal_predecessors_.at(id);
                if (normal_roots.find(id) != normal_roots.end())
                    continue;
                if (predecessors.empty()) {
                    fail(decompiler_diagnostic_code_t::malformed_ast,
                        "decompiler.ast.v2.unreachable_block", entry.second->coordinate);
                    return false;
                }
                auto intersection = dominators_.at(predecessors.front());
                for (std::size_t index = 1; index < predecessors.size(); ++index) {
                    std::set<std::uint64_t> next;
                    std::set_intersection(intersection.begin(), intersection.end(),
                        dominators_.at(predecessors[index]).begin(),
                        dominators_.at(predecessors[index]).end(),
                        std::inserter(next, next.begin()));
                    intersection = std::move(next);
                }
                intersection.insert(id);
                if (intersection != dominators_[id]) {
                    dominators_[id] = std::move(intersection);
                    changed = true;
                }
            }
        }
        for (const auto& entry : blocks_) {
            for (const auto successor : entry.second->successor_ids) {
                if (dominators_.at(entry.first).find(successor) ==
                    dominators_.at(entry.first).end())
                    continue;
                auto& loop = loops_[successor];
                loop.header = successor;
                loop.nodes.insert(successor);
                loop.nodes.insert(entry.first);
                loop.latches.insert(entry.first);
                std::vector<std::uint64_t> pending{entry.first};
                while (!pending.empty()) {
                    const auto id = pending.back();
                    pending.pop_back();
                    for (const auto predecessor : normal_predecessors_.at(id)) {
                        if (predecessor != successor &&
                            dominators_.at(predecessor).find(successor) !=
                                dominators_.at(predecessor).end() &&
                            loop.nodes.insert(predecessor).second)
                            pending.push_back(predecessor);
                    }
                }
            }
        }
        std::set<std::uint64_t> all_with_exit = all;
        all_with_exit.insert(0);
        postdominators_[0] = {0};
        for (const auto& entry : blocks_)
            postdominators_[entry.first] = all_with_exit;
        changed = true;
        std::size_t pdom_iterations = 0;
        const std::size_t max_pdom_iterations = blocks_.size() + 1;
        while (changed && pdom_iterations < max_pdom_iterations) {
            changed = false;
            ++pdom_iterations;
            for (auto iterator = blocks_.rbegin(); iterator != blocks_.rend(); ++iterator) {
                const auto id = iterator->first;
                std::vector<std::uint64_t> successors = iterator->second->successor_ids;
                if (successors.empty())
                    successors.push_back(0);
                auto intersection = postdominators_.at(successors.front());
                for (std::size_t index = 1; index < successors.size(); ++index) {
                    std::set<std::uint64_t> next;
                    std::set_intersection(intersection.begin(), intersection.end(),
                        postdominators_.at(successors[index]).begin(),
                        postdominators_.at(successors[index]).end(),
                        std::inserter(next, next.begin()));
                    intersection = std::move(next);
                }
                intersection.insert(id);
                if (intersection != postdominators_[id]) {
                    postdominators_[id] = std::move(intersection);
                    changed = true;
                }
            }
        }
        return true;
    }

    static bool supported_hir_kind(const hir_node_kind_t kind) noexcept
    {
        return kind == hir_node_kind_t::parameter || kind == hir_node_kind_t::local ||
               kind == hir_node_kind_t::literal || kind == hir_node_kind_t::reference ||
               kind == hir_node_kind_t::unary || kind == hir_node_kind_t::binary ||
               kind == hir_node_kind_t::cast || kind == hir_node_kind_t::assignment ||
               kind == hir_node_kind_t::load || kind == hir_node_kind_t::store ||
               kind == hir_node_kind_t::field || kind == hir_node_kind_t::index ||
               kind == hir_node_kind_t::call || kind == hir_node_kind_t::return_value ||
               kind == hir_node_kind_t::throw_value || kind == hir_node_kind_t::unknown ||
               kind == hir_node_kind_t::branch || kind == hir_node_kind_t::conditional ||
               kind == hir_node_kind_t::switch_branch || kind == hir_node_kind_t::phi;
    }

    void initialize_ast()
    {
        body_coordinate_ = translate_coordinate(blocks_.at(entry_block_id_)->coordinate,
            decompiler_coordinate_layer_t::typed_ast);
        ast_.entity = hir_.entity;
        ast_.hir_hash = result_.hir_hash;
        ast_.type_graph_hash = result_.type_graph_hash;
        ast_.root_node_id = append_node(
            typed_pseudocode_ast_node_kind_t::function_definition,
            hir_.return_type_id,
            {},
            function_name(hir_.entity),
            body_coordinate_,
            aggregate_confidence(),
            decompiler_fact_provenance_t::provider_semantics);
        ast_.body_node_id = append_node(
            typed_pseudocode_ast_node_kind_t::compound_statement,
            hir_.return_type_id,
            {},
            {},
            body_coordinate_,
            aggregate_confidence(),
            decompiler_fact_provenance_t::provider_semantics);
    }

    std::uint8_t aggregate_confidence() const noexcept
    {
        std::uint8_t result = 100;
        for (const auto& block : hir_.blocks) {
            for (const auto& value : block.values)
                result = std::min(result, value.confidence);
        }
        return result;
    }

    bool append_declarations(const std::vector<hir_variable_t>& variables, const bool parameter)
    {
        for (const auto& variable : variables) {
            const auto id = append_node(
                typed_pseudocode_ast_node_kind_t::declaration,
                variable.type_id,
                {},
                variable.stable_name,
                translate_coordinate(variable.coordinate, decompiler_coordinate_layer_t::typed_ast),
                variable.confidence,
                variable.provenance);
            if (id == 0)
                return false;
            if (parameter)
                parameter_declaration_ids_.push_back(id);
            else
                local_declaration_ids_.push_back(id);
        }
        return true;
    }

    bool append_statements()
    {
        precompute_goto_targets();
        if (degraded_)
            return append_degraded_function();
        if (!append_region(entry_block_id_, 0, nullptr, body_statement_ids_, 0))
            return false;
        if (emitted_blocks_.size() != blocks_.size())
            return append_degraded_leftovers();
        return true;
    }

    bool append_degraded_function()
    {
        const auto entry = blocks_.find(entry_block_id_);
        if (entry == blocks_.end()) {
            fail(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.ast.v2.entry_block_identity");
            return false;
        }
        emit_partial_diagnostic(
            first_failure_coordinate_ ? *first_failure_coordinate_
                                      : entry->second->coordinate,
            first_failure_key_.empty()
                ? "decompiler.ast.v2.unstructured_control_flow" : first_failure_key_);
        if (!emit_degraded_block(*entry->second, body_statement_ids_))
            return false;
        for (const auto& block_entry : blocks_) {
            if (block_entry.first == entry_block_id_)
                continue;
            if (!emit_degraded_block(*block_entry.second, body_statement_ids_))
                return false;
        }
        return true;
    }

    bool append_degraded_leftovers()
    {
        std::set<std::uint64_t> remaining;
        for (const auto& entry : blocks_) {
            if (emitted_blocks_.find(entry.first) == emitted_blocks_.end())
                remaining.insert(entry.first);
        }
        while (!remaining.empty()) {
            std::set<std::uint64_t> component;
            std::vector<std::uint64_t> pending{*remaining.begin()};
            while (!pending.empty()) {
                const auto id = pending.back();
                pending.pop_back();
                if (!component.insert(id).second)
                    continue;
                const auto* block = blocks_.at(id);
                for (const auto successor : block->successor_ids) {
                    if (remaining.find(successor) != remaining.end())
                        pending.push_back(successor);
                }
                for (const auto successor : block->exception_successor_ids) {
                    if (remaining.find(successor) != remaining.end())
                        pending.push_back(successor);
                }
                for (const auto predecessor : normal_predecessors_.at(id)) {
                    if (remaining.find(predecessor) != remaining.end())
                        pending.push_back(predecessor);
                }
            }
            for (const auto id : component)
                remaining.erase(id);
            emit_partial_diagnostic(blocks_.at(*component.begin())->coordinate,
                "decompiler.ast.v2.unstructured_control_flow");
            for (const auto id : component) {
                if (!emit_degraded_block(*blocks_.at(id), body_statement_ids_))
                    return false;
            }
        }
        return true;
    }

    bool emit_degraded_block(const hir_block_t& block, std::vector<std::uint64_t>& output)
    {
        penalty_scope_t penalty(penalty_active_);
        goto_target_blocks_.insert(block.id);
        const auto label = degraded_label_for_block(block);
        const auto label_id = append_node(
            typed_pseudocode_ast_node_kind_t::label_statement,
            hir_.return_type_id, {}, label,
            translate_coordinate(block.coordinate, decompiler_coordinate_layer_t::typed_ast),
            aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
        if (label_id == 0)
            return false;
        output.push_back(label_id);
        emitted_blocks_.insert(block.id);
        if (!append_block_statements(block, output))
            return false;
        if (const auto* switch_value = block_switch_value(block)) {
            if (!switch_value->operand_ids.empty()) {
                const auto selector = build_expression(switch_value->operand_ids.front(), 0);
                if (selector == 0)
                    return false;
                const auto selector_statement = append_node(
                    typed_pseudocode_ast_node_kind_t::expression_statement,
                    switch_value->type_id, {selector}, {},
                    translate_coordinate(switch_value->coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    switch_value->confidence, switch_value->provenance);
                if (selector_statement == 0)
                    return false;
                output.push_back(selector_statement);
            }
        }
        std::set<std::uint64_t> gated_successors;
        if (const auto* condition = block_condition(block)) {
            const auto descriptor = conditional_descriptor(condition->stable_value);
            if (descriptor && condition->operand_ids.size() == 1 &&
                std::binary_search(block.successor_ids.begin(), block.successor_ids.end(),
                    descriptor->true_successor)) {
                const auto gated_expression = condition_expression(*condition,
                    descriptor->true_successor);
                if (gated_expression == 0)
                    return false;
                std::vector<std::uint64_t> gated_statements;
                emit_goto(descriptor->true_successor, gated_statements, block.coordinate);
                const auto gated_body = append_compound(std::move(gated_statements),
                    block.coordinate);
                if (gated_body == 0)
                    return false;
                const auto gate = append_node(
                    typed_pseudocode_ast_node_kind_t::if_statement,
                    hir_.return_type_id, {gated_expression, gated_body}, {},
                    translate_coordinate(block.coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    condition->confidence, condition->provenance);
                if (gate == 0)
                    return false;
                output.push_back(gate);
                gated_successors.insert(descriptor->true_successor);
            }
        }
        for (const auto successor : block.successor_ids) {
            if (gated_successors.find(successor) != gated_successors.end())
                continue;
            emit_goto(successor, output, block.coordinate);
        }
        for (const auto successor : block.exception_successor_ids)
            emit_goto(successor, output, block.coordinate);
        return true;
    }

    bool emit_degraded_exception_region(const exception_region_t& region,
                                        std::vector<std::uint64_t>& output)
    {
        std::set<std::uint64_t> region_blocks = region.protected_blocks;
        for (const auto& handler : region.handler_blocks)
            region_blocks.insert(handler.second.begin(), handler.second.end());
        for (const auto block_id : region_blocks) {
            if (emitted_blocks_.find(block_id) != emitted_blocks_.end())
                continue;
            if (!emit_degraded_block(*blocks_.at(block_id), output))
                return false;
        }
        return true;
    }

    std::string degraded_label_for_block(const hir_block_t& block)
    {
        const auto existing = block_labels_.find(block.id);
        if (existing != block_labels_.end())
            return existing->second;
        char label[40]{};
        const auto address = block.coordinate.address_range
            ? block.coordinate.address_range->begin.value : block.id;
        std::snprintf(label, sizeof(label), "label_%llx",
            static_cast<unsigned long long>(address));
        block_labels_.emplace(block.id, label);
        return label;
    }

    void emit_partial_diagnostic(const source_coordinate_t& coordinate,
                                 const std::string& failure_key)
    {
        decompiler_diagnostic_t diagnostic;
        diagnostic.severity = decompiler_diagnostic_severity_t::warning;
        diagnostic.code = decompiler_diagnostic_code_t::partial_decompilation;
        diagnostic.localization_key = "decompiler.ast.v2.partial_decompilation";
        diagnostic.localization_arguments = {failure_key};
        diagnostic.coordinate = translate_coordinate(coordinate,
            decompiler_coordinate_layer_t::typed_ast);
        diagnostic.confidence = 100;
        diagnostic.ordinal = 0;
        partial_diagnostics_.push_back(std::move(diagnostic));
        ++degraded_region_count_;
    }

    const hir_value_t* block_condition(const hir_block_t& block) const noexcept
    {
        const auto iterator = std::find_if(block.values.begin(), block.values.end(),
            [](const hir_value_t& value) { return value.kind == hir_node_kind_t::conditional; });
        return iterator == block.values.end() ? nullptr : &*iterator;
    }

    const hir_value_t* block_switch_value(const hir_block_t& block) const noexcept
    {
        const auto iterator = std::find_if(block.values.begin(), block.values.end(),
            [](const hir_value_t& value) { return value.kind == hir_node_kind_t::switch_branch; });
        return iterator == block.values.end() ? nullptr : &*iterator;
    }

    bool emittable_statement(const hir_value_t& value) const
    {
        return value.kind == hir_node_kind_t::assignment ||
            value.kind == hir_node_kind_t::store ||
            value.kind == hir_node_kind_t::return_value ||
            value.kind == hir_node_kind_t::throw_value ||
            ((value.kind == hir_node_kind_t::call || value.kind == hir_node_kind_t::unknown) &&
             use_counts_.at(value.id) == 0);
    }

    bool block_has_emittable_statements(const hir_block_t& block) const
    {
        return std::any_of(block.values.begin(), block.values.end(),
            [this](const hir_value_t& value) { return emittable_statement(value); });
    }

    bool append_block_statements(const hir_block_t& block,
                                 std::vector<std::uint64_t>& output)
    {
        const hir_value_t* block_return = nullptr;
        if (block.successor_ids.empty() && block.exception_successor_ids.empty()) {
            for (const auto& value : block.values) {
                if (value.kind == hir_node_kind_t::return_value) {
                    block_return = &value;
                    break;
                }
            }
        }
        for (const auto& value : block.values) {
            std::uint64_t statement_id = 0;
            switch (value.kind) {
            case hir_node_kind_t::assignment:
            case hir_node_kind_t::store:
                statement_id = append_expression_statement(value);
                break;
            case hir_node_kind_t::return_value:
                statement_id = append_terminal_statement(value,
                    typed_pseudocode_ast_node_kind_t::return_statement);
                break;
            case hir_node_kind_t::throw_value:
                statement_id = append_terminal_statement(value,
                    typed_pseudocode_ast_node_kind_t::throw_statement);
                break;
            case hir_node_kind_t::call:
            case hir_node_kind_t::unknown:
                if (use_counts_.at(value.id) == 0)
                    statement_id = append_expression_statement(value);
                break;
            default:
                break;
            }
            if (failed_)
                return false;
            if (statement_id != 0)
                output.push_back(statement_id);
        }
        if (block_return) {
            const hir_value_t* tail_candidate = nullptr;
            if (block_return->operand_ids.size() == 1) {
                const auto operand = values_.find(block_return->operand_ids.front());
                if (operand != values_.end() && operand->second->kind == hir_node_kind_t::call)
                    tail_candidate = operand->second;
            }
            if (!tail_candidate) {
                for (const auto& value : block.values) {
                    if (value.kind == hir_node_kind_t::return_value ||
                        value.kind == hir_node_kind_t::throw_value)
                        continue;
                    if (!emittable_statement(value))
                        continue;
                    tail_candidate = value.kind == hir_node_kind_t::call ? &value : nullptr;
                }
            }
            if (tail_candidate) {
                const auto call_expression = expression_ids_.find(tail_candidate->id);
                if (call_expression != expression_ids_.end() &&
                    call_expression->second != 0 &&
                    call_expression->second <= ast_.nodes.size())
                    ast_.nodes[call_expression->second - 1].stable_text = "tail";
            }
        }
        return true;
    }

    std::uint64_t append_compound(std::vector<std::uint64_t> statements,
                                  const source_coordinate_t& coordinate)
    {
        return append_node(typed_pseudocode_ast_node_kind_t::compound_statement,
            hir_.return_type_id, std::move(statements), {},
            translate_coordinate(coordinate, decompiler_coordinate_layer_t::typed_ast),
            aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
    }

    std::uint8_t block_set_confidence(
        const std::set<std::uint64_t>& block_ids) const
    {
        std::uint8_t result = 100;
        for (const auto block_id : block_ids) {
            for (const auto& value : blocks_.at(block_id)->values)
                result = std::min(result, value.confidence);
        }
        return result;
    }

    decompiler_fact_provenance_t block_set_provenance(
        const std::set<std::uint64_t>& block_ids) const
    {
        std::optional<decompiler_fact_provenance_t> result;
        for (const auto block_id : block_ids) {
            for (const auto& value : blocks_.at(block_id)->values) {
                if (!result)
                    result = value.provenance;
                else if (*result != value.provenance)
                    return decompiler_fact_provenance_t::provider_semantics;
            }
        }
        return result.value_or(decompiler_fact_provenance_t::provider_semantics);
    }

    std::uint64_t append_exception_compound(
        std::vector<std::uint64_t> statements,
        const source_coordinate_t& coordinate,
        const std::set<std::uint64_t>& block_ids)
    {
        return append_node(typed_pseudocode_ast_node_kind_t::compound_statement,
            hir_.return_type_id, std::move(statements), {},
            translate_coordinate(coordinate,
                decompiler_coordinate_layer_t::typed_ast),
            block_set_confidence(block_ids), block_set_provenance(block_ids));
    }

    struct resolved_handler_type_t {
        std::string name;
        std::uint8_t confidence = 0;
        decompiler_fact_provenance_t provenance = decompiler_fact_provenance_t::provider_semantics;
    };

    static bool resolvable_handler_type_name(const decompiler_type_node_t& node) noexcept
    {
        if (node.display_name.empty() || node.display_name == "unknown")
            return false;
        constexpr std::string_view undefined_prefix = "undefined";
        if (node.display_name.compare(0, undefined_prefix.size(), undefined_prefix) == 0)
            return false;
        return node.kind == decompiler_type_kind_t::structure ||
            node.kind == decompiler_type_kind_t::union_type ||
            node.kind == decompiler_type_kind_t::class_type;
    }

    std::optional<resolved_handler_type_t> resolve_handler_type(const hir_block_t& handler_block) const
    {
        for (const auto& value : handler_block.values) {
            if (value.kind == hir_node_kind_t::literal ||
                value.kind == hir_node_kind_t::branch ||
                value.kind == hir_node_kind_t::conditional ||
                value.kind == hir_node_kind_t::switch_branch ||
                value.kind == hir_node_kind_t::phi ||
                value.confidence == 0)
                continue;
            const auto type = types_.find(value.type_id);
            if (type == types_.end())
                continue;
            const auto* node = type->second;
            if (resolvable_handler_type_name(*node)) {
                return resolved_handler_type_t{node->display_name,
                    (std::min)(value.confidence, node->confidence), node->provenance};
            }
            if (node->kind != decompiler_type_kind_t::pointer)
                continue;
            for (const auto& edge : type_graph_.edges) {
                if (edge.source_type_id != node->id ||
                    edge.kind != decompiler_type_edge_kind_t::pointee)
                    continue;
                const auto target = types_.find(edge.target_type_id);
                if (target == types_.end() || !resolvable_handler_type_name(*target->second))
                    continue;
                return resolved_handler_type_t{target->second->display_name,
                    (std::min)(value.confidence,
                        (std::min)(node->confidence, target->second->confidence)),
                    target->second->provenance};
            }
        }
        return std::nullopt;
    }

    std::uint64_t append_negation(const std::uint64_t expression,
                                  const hir_value_t& condition)
    {
        return append_node(typed_pseudocode_ast_node_kind_t::unary_expression,
            condition.type_id, {expression}, "!",
            translate_coordinate(condition.coordinate, decompiler_coordinate_layer_t::typed_ast),
            condition.confidence, condition.provenance);
    }

    std::uint64_t condition_expression(const hir_value_t& condition,
                                       const std::uint64_t desired_successor)
    {
        const auto descriptor = conditional_descriptor(condition.stable_value);
        if (!descriptor || condition.operand_ids.size() != 1) {
            fail(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.ast.v2.unstructured_control_flow", condition.coordinate);
            return 0;
        }
        auto expression = build_expression(condition.operand_ids.front(), 0);
        if (expression == 0)
            return 0;
        const bool negate = descriptor->negated !=
            (desired_successor != descriptor->true_successor);
        if (negate) {
            expression = append_negation(expression, condition);
            if (expression == 0)
                return 0;
        }
        return expression;
    }

    std::uint64_t nearest_common_postdominator(const std::uint64_t left,
                                               const std::uint64_t right,
                                               const std::uint64_t current) const
    {
        std::set<std::uint64_t> common;
        std::set_intersection(postdominators_.at(left).begin(), postdominators_.at(left).end(),
            postdominators_.at(right).begin(), postdominators_.at(right).end(),
            std::inserter(common, common.begin()));
        common.erase(current);
        std::uint64_t best = 0;
        std::size_t best_depth = 0;
        for (const auto candidate : common) {
            const auto depth = postdominators_.at(candidate).size();
            if (depth > best_depth || (depth == best_depth && candidate < best)) {
                best = candidate;
                best_depth = depth;
            }
        }
        return best;
    }

    std::uint64_t immediate_postdominator(const std::uint64_t block_id) const
    {
        const auto& pdoms = postdominators_.at(block_id);
        std::uint64_t best = 0;
        std::size_t best_depth = 0;
        for (const auto candidate : pdoms) {
            if (candidate == block_id)
                continue;
            const auto depth = postdominators_.at(candidate).size();
            if (depth > best_depth || (depth == best_depth && candidate < best)) {
                best = candidate;
                best_depth = depth;
            }
        }
        return best;
    }

    const typed_pseudocode_ast_node_t* node_by_id(const std::uint64_t id) const noexcept
    {
        if (id == 0 || id > ast_.nodes.size())
            return nullptr;
        return &ast_.nodes[id - 1];
    }

    std::string label_for_block(const std::uint64_t block_id)
    {
        auto existing = block_labels_.find(block_id);
        if (existing != block_labels_.end())
            return existing->second;
        std::string label = "label_" + std::to_string(block_id);
        block_labels_.emplace(block_id, label);
        return label;
    }

    std::uint64_t emit_goto(const std::uint64_t target_block,
                            std::vector<std::uint64_t>& output,
                            const source_coordinate_t& coordinate)
    {
        goto_target_blocks_.insert(target_block);
        const auto label = label_for_block(target_block);
        const auto id = append_node(
            typed_pseudocode_ast_node_kind_t::goto_statement,
            hir_.return_type_id, {}, label,
            translate_coordinate(coordinate, decompiler_coordinate_layer_t::typed_ast),
            aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
        if (id != 0)
            output.push_back(id);
        return id;
    }

    void emit_label_if_needed(const std::uint64_t block_id,
                              std::vector<std::uint64_t>& output)
    {
        if (goto_target_blocks_.find(block_id) == goto_target_blocks_.end())
            return;
        const auto label = label_for_block(block_id);
        const auto id = append_node(
            typed_pseudocode_ast_node_kind_t::label_statement,
            hir_.return_type_id, {}, label,
            translate_coordinate(blocks_.at(block_id)->coordinate,
                decompiler_coordinate_layer_t::typed_ast),
            aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
        if (id != 0)
            output.push_back(id);
    }

    void precompute_goto_targets()
    {
        for (const auto& entry : blocks_) {
            const auto* block = entry.second;
            const bool has_switch = block_switch_value(*block) != nullptr;
            if (!has_switch && block->successor_ids.size() > 2) {
                for (const auto successor : block->successor_ids)
                    goto_target_blocks_.insert(successor);
            }
            if (!has_switch && block->successor_ids.size() == 2 &&
                !block_condition(*block)) {
                for (const auto successor : block->successor_ids)
                    goto_target_blocks_.insert(successor);
            }
            if (normal_predecessors_.at(entry.first).size() > 2)
                goto_target_blocks_.insert(entry.first);
        }
    }

    bool append_switch(const hir_block_t& header,
                       std::vector<std::uint64_t>& output,
                       std::uint64_t& next)
    {
        const auto* switch_value = block_switch_value(header);
        if (!switch_value || switch_value->operand_ids.empty()) {
            fail(decompiler_diagnostic_code_t::malformed_ast,
                "decompiler.ast.v2.unstructured_control_flow", header.coordinate);
            return false;
        }
        emitted_blocks_.insert(header.id);
        if (!append_block_statements(header, output))
            return false;
        const auto selector = build_expression(switch_value->operand_ids.front(), 0);
        if (selector == 0)
            return false;
        const auto merge = immediate_postdominator(header.id);
        const auto descriptor = switch_descriptor(switch_value->stable_value);
        std::vector<std::uint64_t> switch_children{selector};
        std::set<std::uint64_t> handled_successors;
        builtin_typelib::equate_table_id_t case_table =
            builtin_typelib::equate_table_id_t::ntstatus;
        bool case_table_resolved = false;
        if (descriptor) {
            const auto selector_type = types_.find(switch_value->type_id);
            if (selector_type != types_.end()) {
                const auto& type_name = selector_type->second->canonical_name;
                if (type_name.find("NTSTATUS") != std::string::npos) {
                    case_table = builtin_typelib::equate_table_id_t::ntstatus;
                    case_table_resolved = true;
                } else if (type_name.find("HRESULT") != std::string::npos) {
                    case_table = builtin_typelib::equate_table_id_t::hresult;
                    case_table_resolved = true;
                }
            }
        }
        if (!case_table_resolved && descriptor && !descriptor->cases.empty()) {
            const auto parse_numeric = [](const std::string& raw, std::uint64_t& numeric) {
                const char* begin = raw.data();
                const char* end = begin + raw.size();
                auto parsed = std::from_chars(begin, end, numeric);
                if (parsed.ec == std::errc{} && parsed.ptr == end)
                    return true;
                if (raw.size() > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) {
                    parsed = std::from_chars(begin + 2, end, numeric, 16);
                    return parsed.ec == std::errc{} && parsed.ptr == end;
                }
                return false;
            };
            std::vector<std::uint64_t> case_values;
            case_values.reserve(descriptor->cases.size());
            for (const auto& entry : descriptor->cases) {
                std::uint64_t numeric = 0;
                if (parse_numeric(entry.value, numeric))
                    case_values.push_back(numeric);
            }
            if (case_values.size() >= 2) {
                std::size_t best_matches = 0;
                auto best_table = builtin_typelib::equate_table_id_t::ntstatus;
                for (std::uint8_t table_id = 1;
                     table_id <= static_cast<std::uint8_t>(builtin_typelib::equate_table_id_t::key_access);
                     ++table_id) {
                    const auto table = static_cast<builtin_typelib::equate_table_id_t>(table_id);
                    std::size_t matches = 0;
                    for (const auto value : case_values) {
                        std::string named;
                        if (builtin_typelib::lookup_equate_table(table, value, named))
                            ++matches;
                    }
                    if (matches > best_matches) {
                        best_matches = matches;
                        best_table = table;
                    }
                }
                if (best_matches >= 2 && best_matches * 5 >= case_values.size() * 3) {
                    case_table = best_table;
                    case_table_resolved = true;
                }
            }
        }
        const auto case_value_text = [case_table, case_table_resolved](
                const std::string& raw) {
            if (!case_table_resolved)
                return raw;
            std::uint64_t numeric = 0;
            const char* begin = raw.data();
            const char* end = begin + raw.size();
            auto parsed = std::from_chars(begin, end, numeric);
            if (parsed.ec != std::errc{} || parsed.ptr != end) {
                if (raw.size() > 2 && raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) {
                    parsed = std::from_chars(begin + 2, end, numeric, 16);
                    if (parsed.ec != std::errc{} || parsed.ptr != end)
                        return raw;
                } else {
                    return raw;
                }
            }
            std::string named;
            if (!builtin_typelib::lookup_equate_table(case_table, numeric, named))
                return raw;
            return named;
        };
        if (descriptor) {
            for (const auto& entry : descriptor->cases) {
                if (!std::binary_search(header.successor_ids.begin(),
                        header.successor_ids.end(), entry.target_block))
                    continue;
                if (emitted_blocks_.find(entry.target_block) != emitted_blocks_.end())
                    continue;
                handled_successors.insert(entry.target_block);
                const auto case_literal = append_node(
                    typed_pseudocode_ast_node_kind_t::literal,
                    switch_value->type_id, {}, case_value_text(entry.value),
                    translate_coordinate(switch_value->coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    switch_value->confidence, switch_value->provenance);
                if (case_literal == 0)
                    return false;
                std::vector<std::uint64_t> case_children{case_literal};
                if (entry.target_block != merge) {
                    if (!append_region(entry.target_block, merge,
                            nullptr, case_children, 0))
                        return false;
                }
                emit_switch_break_if_needed(entry.target_block, merge, case_children);
                const auto case_node = append_node(
                    typed_pseudocode_ast_node_kind_t::switch_case,
                    hir_.return_type_id, std::move(case_children), "case",
                    translate_coordinate(blocks_.at(entry.target_block)->coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                if (case_node == 0)
                    return false;
                switch_children.push_back(case_node);
            }
            if (descriptor->default_target != 0 &&
                std::binary_search(header.successor_ids.begin(),
                    header.successor_ids.end(), descriptor->default_target) &&
                emitted_blocks_.find(descriptor->default_target) == emitted_blocks_.end()) {
                handled_successors.insert(descriptor->default_target);
                std::vector<std::uint64_t> default_children;
                if (descriptor->default_target != merge) {
                    if (!append_region(descriptor->default_target, merge,
                            nullptr, default_children, 0))
                        return false;
                }
                const auto default_node = append_node(
                    typed_pseudocode_ast_node_kind_t::switch_case,
                    hir_.return_type_id, std::move(default_children), "default",
                    translate_coordinate(blocks_.at(descriptor->default_target)->coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                if (default_node == 0)
                    return false;
                switch_children.push_back(default_node);
            }
        } else {
            for (std::size_t index = 0; index < header.successor_ids.size(); ++index) {
                const auto target = header.successor_ids[index];
                if (emitted_blocks_.find(target) != emitted_blocks_.end())
                    continue;
                handled_successors.insert(target);
                if (index + 1 == header.successor_ids.size()) {
                    std::vector<std::uint64_t> default_children;
                    if (target != merge) {
                        if (!append_region(target, merge,
                                nullptr, default_children, 0))
                            return false;
                    }
                    const auto default_node = append_node(
                        typed_pseudocode_ast_node_kind_t::switch_case,
                        hir_.return_type_id, std::move(default_children), "default",
                        translate_coordinate(blocks_.at(target)->coordinate,
                            decompiler_coordinate_layer_t::typed_ast),
                        aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                    if (default_node == 0)
                        return false;
                    switch_children.push_back(default_node);
                } else {
                    const auto case_literal = append_node(
                        typed_pseudocode_ast_node_kind_t::literal,
                        switch_value->type_id, {}, std::to_string(index),
                        translate_coordinate(switch_value->coordinate,
                            decompiler_coordinate_layer_t::typed_ast),
                        switch_value->confidence, switch_value->provenance);
                    if (case_literal == 0)
                        return false;
                    std::vector<std::uint64_t> case_children{case_literal};
                    if (target != merge) {
                        if (!append_region(target, merge,
                                nullptr, case_children, 0))
                            return false;
                    }
                    emit_switch_break_if_needed(target, merge, case_children);
                    const auto case_node = append_node(
                        typed_pseudocode_ast_node_kind_t::switch_case,
                        hir_.return_type_id, std::move(case_children), "case",
                        translate_coordinate(blocks_.at(target)->coordinate,
                            decompiler_coordinate_layer_t::typed_ast),
                        aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                    if (case_node == 0)
                        return false;
                    switch_children.push_back(case_node);
                }
            }
        }
        for (const auto successor : header.successor_ids) {
            if (handled_successors.find(successor) == handled_successors.end() &&
                emitted_blocks_.find(successor) == emitted_blocks_.end()) {
                emit_goto(successor, switch_children, header.coordinate);
            }
        }
        std::string jump_table_text;
        if (!descriptor) {
            char jump_table[48]{};
            const auto header_address = header.coordinate.address_range
                ? header.coordinate.address_range->begin.value : header.id;
            std::snprintf(jump_table, sizeof(jump_table), "jump_table_%llx",
                static_cast<unsigned long long>(header_address));
            jump_table_text = jump_table;
        }
        const auto switch_node = append_node(
            typed_pseudocode_ast_node_kind_t::switch_statement,
            hir_.return_type_id, std::move(switch_children), std::move(jump_table_text),
            translate_coordinate(header.coordinate,
                decompiler_coordinate_layer_t::typed_ast),
            aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
        if (switch_node == 0)
            return false;
        output.push_back(switch_node);
        next = merge;
        return true;
    }

    void emit_switch_break_if_needed(const std::uint64_t case_target,
                                     const std::uint64_t merge,
                                     std::vector<std::uint64_t>& case_children)
    {
        if (merge == 0 || case_children.size() <= 1)
            return;
        const auto* last_stmt = node_by_id(case_children.back());
        if (last_stmt && (
            last_stmt->kind == typed_pseudocode_ast_node_kind_t::return_statement ||
            last_stmt->kind == typed_pseudocode_ast_node_kind_t::throw_statement ||
            last_stmt->kind == typed_pseudocode_ast_node_kind_t::break_statement ||
            last_stmt->kind == typed_pseudocode_ast_node_kind_t::goto_statement))
            return;
        const auto* block = blocks_.at(case_target);
        bool exits_to_merge = false;
        for (const auto successor : block->successor_ids) {
            if (successor == merge) {
                exits_to_merge = true;
                break;
            }
        }
        if (!exits_to_merge && block->successor_ids.size() == 1) {
            std::set<std::uint64_t> visited;
            std::vector<std::uint64_t> pending{block->successor_ids.front()};
            std::size_t bfs_iterations = 0;
            const std::size_t max_bfs_iterations = blocks_.size() + 1;
            while (!pending.empty() && bfs_iterations < max_bfs_iterations) {
                ++bfs_iterations;
                const auto id = pending.back();
                pending.pop_back();
                if (!visited.insert(id).second || id == merge)
                    continue;
                const auto* next_block = blocks_.at(id);
                for (const auto successor : next_block->successor_ids) {
                    if (successor == merge) {
                        exits_to_merge = true;
                        break;
                    }
                    pending.push_back(successor);
                }
                if (exits_to_merge)
                    break;
            }
        }
        if (!exits_to_merge)
            return;
        const auto break_id = append_node(
            typed_pseudocode_ast_node_kind_t::break_statement,
            hir_.return_type_id, {}, {},
            translate_coordinate(block->coordinate,
                decompiler_coordinate_layer_t::typed_ast),
            aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
        if (break_id != 0)
            case_children.push_back(break_id);
    }

    bool try_for_loop_conversion(const natural_loop_t& loop,
                                 const hir_value_t& header_condition,
                                 const std::uint64_t body_entry,
                                 const std::uint64_t exit,
                                 const std::uint64_t true_successor,
                                 std::vector<std::uint64_t>& output,
                                 std::uint64_t& next)
    {
        if (loop.latches.size() != 1)
            return false;
        const auto latch_id = *loop.latches.begin();
        const auto* latch = blocks_.at(latch_id);
        if (latch->successor_ids.size() != 1 ||
            latch->successor_ids.front() != loop.header)
            return false;
        if (block_has_emittable_statements(*latch)) {
            std::size_t emittable_count = 0;
            const hir_value_t* increment_value = nullptr;
            for (const auto& value : latch->values) {
                if (emittable_statement(value)) {
                    ++emittable_count;
                    if (value.kind == hir_node_kind_t::assignment)
                        increment_value = &value;
                }
            }
            if (emittable_count != 1 || !increment_value)
                return false;
            if (output.empty())
                return false;
            const auto* init_stmt = node_by_id(output.back());
            if (!init_stmt ||
                init_stmt->kind != typed_pseudocode_ast_node_kind_t::expression_statement ||
                init_stmt->child_ids.size() != 1)
                return false;
            const auto* init_expr = node_by_id(init_stmt->child_ids[0]);
            if (!init_expr ||
                init_expr->kind != typed_pseudocode_ast_node_kind_t::assignment_expression ||
                init_expr->child_ids.size() != 2)
                return false;
            const auto* init_lhs = node_by_id(init_expr->child_ids[0]);
            if (!init_lhs)
                return false;
            const auto increment_expr = build_expression(increment_value->id, 0);
            if (increment_expr == 0)
                return false;
            const auto* incr_node = node_by_id(increment_expr);
            if (!incr_node ||
                incr_node->kind != typed_pseudocode_ast_node_kind_t::assignment_expression ||
                incr_node->child_ids.size() != 2)
                return false;
            const auto* incr_lhs = node_by_id(incr_node->child_ids[0]);
            if (!incr_lhs ||
                incr_lhs->kind != init_lhs->kind ||
                incr_lhs->stable_text != init_lhs->stable_text)
                return false;
            const auto init_expr_id = init_stmt->child_ids[0];
            output.pop_back();
            emitted_blocks_.insert(latch_id);
            emitted_blocks_.insert(loop.header);
            const auto condition = condition_expression(header_condition, true_successor);
            if (condition == 0)
                return false;
            std::vector<std::uint64_t> statements;
            if (!append_region(body_entry, latch_id, &loop.nodes, statements, 0))
                return false;
            for (const auto block : loop.nodes) {
                if (block == latch_id)
                    continue;
                if (emitted_blocks_.find(block) == emitted_blocks_.end()) {
                    fail(decompiler_diagnostic_code_t::malformed_ast,
                        "decompiler.ast.v2.unstructured_control_flow",
                        blocks_.at(loop.header)->coordinate);
                    return false;
                }
            }
            const auto body = append_compound(std::move(statements),
                blocks_.at(loop.header)->coordinate);
            const auto statement = append_node(
                typed_pseudocode_ast_node_kind_t::for_statement,
                hir_.return_type_id,
                {init_expr_id, condition, increment_expr, body}, {},
                translate_coordinate(blocks_.at(loop.header)->coordinate,
                    decompiler_coordinate_layer_t::typed_ast),
                aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
            if (body == 0 || statement == 0)
                return false;
            output.push_back(statement);
            next = exit;
            return true;
        }
        return false;
    }

    bool append_exception_region(const exception_region_t& region,
                                 std::vector<std::uint64_t>& output,
                                 std::uint64_t& next)
    {
        std::vector<std::uint64_t> protected_statements;
        if (!append_region(region.entry, region.continuation,
                &region.protected_blocks, protected_statements, 0, region.entry))
            return false;
        for (const auto block_id : region.protected_blocks) {
            if (emitted_blocks_.find(block_id) == emitted_blocks_.end()) {
                fail(decompiler_diagnostic_code_t::malformed_ast,
                    "decompiler.ast.v2.unstructured_exception_region",
                    blocks_.at(block_id)->coordinate);
                return false;
            }
        }
        const auto protected_body = append_exception_compound(
            std::move(protected_statements), blocks_.at(region.entry)->coordinate,
            region.protected_blocks);
        if (protected_body == 0)
            return false;
        std::vector<std::uint64_t> children{protected_body};
        for (const auto handler : region.handler_entries) {
            const auto handler_blocks = region.handler_blocks.find(handler);
            if (handler_blocks == region.handler_blocks.end() ||
                handler_blocks->second.empty()) {
                fail(decompiler_diagnostic_code_t::malformed_ast,
                    "decompiler.ast.v2.missing_exception_handler_body",
                    blocks_.at(handler)->coordinate);
                return false;
            }
            std::vector<std::uint64_t> handler_statements;
            if (!append_region(handler, region.continuation,
                    &handler_blocks->second, handler_statements, 0, 0))
                return false;
            for (const auto block_id : handler_blocks->second) {
                if (emitted_blocks_.find(block_id) == emitted_blocks_.end()) {
                    fail(decompiler_diagnostic_code_t::malformed_ast,
                        "decompiler.ast.v2.unstructured_exception_handler",
                        blocks_.at(block_id)->coordinate);
                    return false;
                }
            }
            const auto handler_body = append_exception_compound(
                std::move(handler_statements), blocks_.at(handler)->coordinate,
                handler_blocks->second);
            const auto resolved_type = resolve_handler_type(*blocks_.at(handler));
            const auto handler_clause = append_node(
                typed_pseudocode_ast_node_kind_t::catch_clause,
                hir_.return_type_id,
                {handler_body},
                resolved_type ? resolved_type->name : "unknown_exception",
                translate_coordinate(blocks_.at(handler)->coordinate,
                    decompiler_coordinate_layer_t::typed_ast),
                resolved_type
                    ? (std::min)(block_set_confidence(handler_blocks->second),
                        resolved_type->confidence)
                    : block_set_confidence(handler_blocks->second),
                resolved_type ? resolved_type->provenance
                              : block_set_provenance(handler_blocks->second));
            if (handler_body == 0 || handler_clause == 0)
                return false;
            children.push_back(handler_clause);

            if (!resolved_type) {
                decompiler_unknown_t unknown;
                unknown.reason = decompiler_unknown_reason_t::unresolved_reference;
                unknown.stable_token = "exception.handler_type.block_" +
                    std::to_string(handler);
                unknown.coordinate = blocks_.at(handler)->coordinate;
                unknown.confidence = 0;
                unknown.provenance = decompiler_fact_provenance_t::provider_semantics;
                generated_unknowns_.push_back(std::move(unknown));
            }
        }
        const auto statement = append_node(
            typed_pseudocode_ast_node_kind_t::try_statement,
            hir_.return_type_id,
            std::move(children),
            {},
            translate_coordinate(blocks_.at(region.entry)->coordinate,
                decompiler_coordinate_layer_t::typed_ast),
            block_set_confidence(region.protected_blocks),
            decompiler_fact_provenance_t::provider_semantics);
        if (statement == 0)
            return false;
        output.push_back(statement);
        next = region.continuation;
        return true;
    }

    bool append_natural_loop(const natural_loop_t& loop,
                             std::vector<std::uint64_t>& output,
                             std::uint64_t& next)
    {
        const auto* header = blocks_.at(loop.header);
        const auto* header_condition = block_condition(*header);
        if (header_condition && header->successor_ids.size() == 2) {
            std::uint64_t body_entry = 0;
            std::uint64_t exit = 0;
            for (const auto successor : header->successor_ids) {
                if (loop.nodes.find(successor) != loop.nodes.end())
                    body_entry = successor;
                else
                    exit = successor;
            }
            if (body_entry == 0 || exit == 0 || block_has_emittable_statements(*header)) {
                fail(decompiler_diagnostic_code_t::malformed_ast,
                    "decompiler.ast.v2.unstructured_control_flow", header->coordinate);
                return false;
            }
            {
                std::uint64_t for_next = 0;
                if (try_for_loop_conversion(loop, *header_condition,
                        body_entry, exit, body_entry, output, for_next)) {
                    next = for_next;
                    return true;
                }
                if (failed_)
                    return false;
            }
            emitted_blocks_.insert(header->id);
            const auto condition = condition_expression(*header_condition, body_entry);
            if (condition == 0)
                return false;
            std::vector<std::uint64_t> statements;
            if (!append_region(body_entry, header->id, &loop.nodes, statements, 0))
                return false;
            for (const auto block : loop.nodes) {
                if (emitted_blocks_.find(block) == emitted_blocks_.end()) {
                    fail(decompiler_diagnostic_code_t::malformed_ast,
                        "decompiler.ast.v2.unstructured_control_flow", header->coordinate);
                    return false;
                }
            }
            const auto body = append_compound(std::move(statements), header->coordinate);
            const auto statement = append_node(
                typed_pseudocode_ast_node_kind_t::while_statement,
                hir_.return_type_id, {condition, body}, {},
                translate_coordinate(header->coordinate, decompiler_coordinate_layer_t::typed_ast),
                aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
            if (body == 0 || statement == 0)
                return false;
            output.push_back(statement);
            next = exit;
            return true;
        }
        if (loop.latches.size() == 1) {
            const auto latch_id = *loop.latches.begin();
            const auto* latch = blocks_.at(latch_id);
            const auto* latch_condition = block_condition(*latch);
            std::uint64_t exit = 0;
            if (latch_condition && latch->successor_ids.size() == 2 &&
                std::binary_search(latch->successor_ids.begin(), latch->successor_ids.end(),
                    loop.header)) {
                exit = latch->successor_ids.front() == loop.header
                    ? latch->successor_ids.back() : latch->successor_ids.front();
            }
            bool external_edge = false;
            for (const auto block_id : loop.nodes) {
                for (const auto successor : blocks_.at(block_id)->successor_ids) {
                    if (loop.nodes.find(successor) == loop.nodes.end() &&
                        !(block_id == latch_id && successor == exit))
                        external_edge = true;
                }
            }
            if (exit != 0 && !external_edge && !block_has_emittable_statements(*latch)) {
                std::vector<std::uint64_t> statements;
                if (!append_region(loop.header, latch_id, &loop.nodes, statements, loop.header))
                    return false;
                if (!emitted_blocks_.insert(latch_id).second) {
                    fail(decompiler_diagnostic_code_t::malformed_ast,
                        "decompiler.ast.v2.unstructured_control_flow", latch->coordinate);
                    return false;
                }
                const auto condition = condition_expression(*latch_condition, loop.header);
                const auto body = append_compound(std::move(statements), header->coordinate);
                const auto statement = append_node(
                    typed_pseudocode_ast_node_kind_t::do_while_statement,
                    hir_.return_type_id, {body, condition}, {},
                    translate_coordinate(header->coordinate, decompiler_coordinate_layer_t::typed_ast),
                    aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                if (condition == 0 || body == 0 || statement == 0)
                    return false;
                for (const auto block : loop.nodes) {
                    if (emitted_blocks_.find(block) == emitted_blocks_.end()) {
                        fail(decompiler_diagnostic_code_t::malformed_ast,
                            "decompiler.ast.v2.unstructured_control_flow", header->coordinate);
                        return false;
                    }
                }
                output.push_back(statement);
                next = exit;
                return true;
            }
        }
        return false;
    }

    bool append_region(std::uint64_t current,
                       const std::uint64_t stop,
                       const std::set<std::uint64_t>* allowed,
                       std::vector<std::uint64_t>& output,
                       const std::uint64_t ignored_loop_header,
                       const std::uint64_t ignored_exception_entry = 0)
    {
        std::set<std::uint64_t> local_visited;
        std::size_t region_iterations = 0;
        const std::size_t max_region_iterations = blocks_.size() * 2 + 1;
        while (current != 0 && current != stop) {
            if (++region_iterations > max_region_iterations) {
                if (current != 0 && current != stop)
                    emit_goto(current, output, blocks_.at(current)->coordinate);
                break;
            }
            emit_label_if_needed(current, output);
            if (local_visited.count(current)) {
                emit_goto(current, output, blocks_.at(current)->coordinate);
                return true;
            }
            local_visited.insert(current);
            if ((allowed && allowed->find(current) == allowed->end()) ||
                emitted_blocks_.find(current) != emitted_blocks_.end()) {
                emit_goto(current, output, blocks_.at(current)->coordinate);
                return true;
            }
            if (current != ignored_exception_entry) {
                const auto exception_region = exception_regions_.find(current);
                if (exception_region != exception_regions_.end()) {
                    const auto& region = exception_region->second;
                    const bool scope_ok = !allowed ||
                        (std::all_of(region.protected_blocks.begin(),
                             region.protected_blocks.end(),
                             [allowed](const std::uint64_t block_id) {
                                 return allowed->find(block_id) != allowed->end();
                             }) &&
                         (region.continuation == 0 ||
                          region.continuation == stop ||
                          allowed->find(region.continuation) != allowed->end()));
                    std::uint64_t next = 0;
                    if (scope_ok) {
                        const auto saved_emitted = emitted_blocks_;
                        const auto output_size = output.size();
                        const auto diag_count = result_.diagnostics.size();
                        if (append_exception_region(region, output, next)) {
                            current = next;
                            continue;
                        }
                        if (!failed_)
                            return false;
                        std::string region_key =
                            "decompiler.ast.v2.ambiguous_exception_region_scope";
                        if (result_.diagnostics.size() > diag_count)
                            region_key = result_.diagnostics.back().localization_key;
                        failed_ = false;
                        result_.diagnostics.resize(diag_count);
                        emitted_blocks_ = saved_emitted;
                        output.resize(output_size);
                        emit_partial_diagnostic(blocks_.at(region.entry)->coordinate,
                            region_key);
                        if (!emit_degraded_exception_region(region, output))
                            return false;
                        next = region.continuation;
                    } else {
                        emit_partial_diagnostic(blocks_.at(region.entry)->coordinate,
                            "decompiler.ast.v2.ambiguous_exception_region_scope");
                        if (!emit_degraded_exception_region(region, output))
                            return false;
                        next = region.continuation;
                    }
                    current = next;
                    continue;
                }
            }
            if (current != ignored_loop_header) {
                const auto loop = loops_.find(current);
                if (loop != loops_.end()) {
                    std::uint64_t next = 0;
                    const auto saved_emitted = emitted_blocks_;
                    const auto output_size = output.size();
                    const auto diag_count = result_.diagnostics.size();
                    if (!append_natural_loop(loop->second, output, next)) {
                        bool region_degraded = false;
                        if (failed_) {
                            region_degraded = true;
                            std::string region_key =
                                "decompiler.ast.v2.unstructured_control_flow";
                            if (result_.diagnostics.size() > diag_count)
                                region_key = result_.diagnostics.back().localization_key;
                            failed_ = false;
                            result_.diagnostics.resize(diag_count);
                            emitted_blocks_ = saved_emitted;
                            output.resize(output_size);
                            emit_partial_diagnostic(
                                blocks_.at(loop->second.header)->coordinate, region_key);
                        }
                        const auto* header_block = blocks_.at(current);
                        if (emitted_blocks_.find(current) != emitted_blocks_.end()) {
                            emit_goto(current, output, header_block->coordinate);
                            return true;
                        }
                        emitted_blocks_.insert(current);
                        std::optional<penalty_scope_t> penalty;
                        if (region_degraded)
                            penalty.emplace(penalty_active_);
                        if (!append_block_statements(*header_block, output))
                            return false;
                        if (header_block->successor_ids.empty())
                            return true;
                        for (std::size_t i = 1; i < header_block->successor_ids.size(); ++i)
                            emit_goto(header_block->successor_ids[i], output,
                                header_block->coordinate);
                        const auto fallthrough = header_block->successor_ids.front();
                        if (fallthrough == stop)
                            return true;
                        current = fallthrough;
                        continue;
                    }
                    current = next;
                    continue;
                }
            }
            const auto* block = blocks_.at(current);
            if (block_switch_value(*block)) {
                std::uint64_t next = 0;
                if (!append_switch(*block, output, next))
                    return false;
                current = next;
                continue;
            }
            emitted_blocks_.insert(current);
            if (!append_block_statements(*block, output))
                return false;
            if (block->successor_ids.empty())
                return true;
            if (block->successor_ids.size() == 1) {
                const auto successor = block->successor_ids.front();
                if (successor == stop)
                    return true;
                if (dominators_.at(current).find(successor) != dominators_.at(current).end()) {
                    emit_goto(successor, output, block->coordinate);
                    return true;
                }
                current = successor;
                continue;
            }
            if (block->successor_ids.size() > 2) {
                for (std::size_t i = 1; i < block->successor_ids.size(); ++i)
                    emit_goto(block->successor_ids[i], output, block->coordinate);
                const auto fallthrough = block->successor_ids.front();
                if (fallthrough == stop)
                    return true;
                current = fallthrough;
                continue;
            }
            const auto* condition_value = block_condition(*block);
            if (!condition_value) {
                for (std::size_t i = 1; i < block->successor_ids.size(); ++i)
                    emit_goto(block->successor_ids[i], output, block->coordinate);
                const auto fallthrough = block->successor_ids.front();
                if (fallthrough == stop)
                    return true;
                current = fallthrough;
                continue;
            }
            const auto descriptor = conditional_descriptor(condition_value->stable_value);
            if (!descriptor)
                return false;
            const auto true_successor = descriptor->true_successor;
            const auto false_successor = block->successor_ids.front() == true_successor
                ? block->successor_ids.back() : block->successor_ids.front();
            const auto join = nearest_common_postdominator(
                true_successor, false_successor, current);
            auto condition = condition_expression(*condition_value, true_successor);
            if (condition == 0)
                return false;
            std::vector<std::uint64_t> true_statements;
            std::vector<std::uint64_t> false_statements;
            if (true_successor != join &&
                !append_region(true_successor, join, allowed, true_statements, 0))
                return false;
            if (false_successor != join &&
                !append_region(false_successor, join, allowed, false_statements, 0))
                return false;
            if (true_statements.empty() && false_statements.empty()) {
                const auto statement = append_node(
                    typed_pseudocode_ast_node_kind_t::expression_statement,
                    condition_value->type_id, {condition}, {},
                    translate_coordinate(condition_value->coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    condition_value->confidence, condition_value->provenance);
                if (statement == 0)
                    return false;
                output.push_back(statement);
            } else {
                auto body_successor = true_successor;
                if (true_statements.empty()) {
                    condition = append_negation(condition, *condition_value);
                    if (condition == 0)
                        return false;
                    std::swap(true_statements, false_statements);
                    body_successor = false_successor;
                }
                const auto true_body = append_compound(std::move(true_statements),
                    blocks_.at(body_successor)->coordinate);
                std::vector<std::uint64_t> children{condition, true_body};
                if (!false_statements.empty()) {
                    const auto false_body = append_compound(std::move(false_statements),
                        blocks_.at(false_successor)->coordinate);
                    const auto alternate = append_node(
                        typed_pseudocode_ast_node_kind_t::else_clause,
                        hir_.return_type_id, {false_body}, {},
                        translate_coordinate(blocks_.at(false_successor)->coordinate,
                            decompiler_coordinate_layer_t::typed_ast),
                        aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                    if (false_body == 0 || alternate == 0)
                        return false;
                    children.push_back(alternate);
                }
                const auto statement = append_node(
                    typed_pseudocode_ast_node_kind_t::if_statement,
                    hir_.return_type_id, std::move(children), {},
                    translate_coordinate(block->coordinate,
                        decompiler_coordinate_layer_t::typed_ast),
                    aggregate_confidence(), decompiler_fact_provenance_t::provider_semantics);
                if (condition == 0 || true_body == 0 || statement == 0)
                    return false;
                output.push_back(statement);
            }
            current = join;
        }
        return true;
    }

    std::uint64_t append_expression_statement(const hir_value_t& value)
    {
        const auto expression = build_expression(value.id, 0);
        if (expression == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::expression_statement,
            value.type_id,
            {expression},
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_terminal_statement(
        const hir_value_t& value,
        const typed_pseudocode_ast_node_kind_t kind)
    {
        std::vector<std::uint64_t> children;
        if (value.operand_ids.size() == 1) {
            const auto expression = build_expression(value.operand_ids.front(), 0);
            if (expression == 0)
                return 0;
            children.push_back(expression);
        } else if (value.operand_ids.empty()) {
            const auto return_type = types_.find(hir_.return_type_id);
            if (kind != typed_pseudocode_ast_node_kind_t::return_statement ||
                return_type == types_.end() ||
                return_type->second->kind != decompiler_type_kind_t::void_type) {
                fail(decompiler_diagnostic_code_t::malformed_hir,
                    "decompiler.ast.v2.missing_terminal_value", value.coordinate);
                return 0;
            }
        } else {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.terminal_arity", value.coordinate);
            return 0;
        }
        return append_node(
            kind,
            value.type_id,
            std::move(children),
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t build_expression(const std::uint64_t value_id, const std::size_t depth)
    {
        if (depth >= request_.limits.max_expression_nesting) {
            const auto iterator = values_.find(value_id);
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.expression_nesting",
                 iterator == values_.end() ? std::optional<source_coordinate_t>{} : std::optional<source_coordinate_t>{iterator->second->coordinate});
            return 0;
        }
        const auto value_iterator = values_.find(value_id);
        if (value_iterator == values_.end()) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.expression_value");
            return 0;
        }
        const auto state_iterator = states_.find(value_id);
        if (state_iterator->second == value_state_t::complete)
            return expression_ids_.at(value_id);
        if (state_iterator->second == value_state_t::active) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.expression_cycle", value_iterator->second->coordinate);
            return 0;
        }
        state_iterator->second = value_state_t::active;
        const auto& value = *value_iterator->second;
        std::uint64_t node_id = 0;
        switch (value.kind) {
        case hir_node_kind_t::parameter:
        case hir_node_kind_t::local:
        case hir_node_kind_t::reference:
            node_id = append_leaf(value, typed_pseudocode_ast_node_kind_t::identifier);
            break;
        case hir_node_kind_t::literal:
            node_id = append_leaf(value, typed_pseudocode_ast_node_kind_t::literal);
            break;
        case hir_node_kind_t::unknown:
            node_id = append_leaf(value, typed_pseudocode_ast_node_kind_t::unknown_expression);
            break;
        case hir_node_kind_t::unary:
        case hir_node_kind_t::load:
            node_id = append_unary(value, depth);
            break;
        case hir_node_kind_t::binary:
            node_id = append_binary(value, depth);
            break;
        case hir_node_kind_t::cast:
            node_id = append_cast(value, depth);
            break;
        case hir_node_kind_t::assignment:
        case hir_node_kind_t::store:
            node_id = append_assignment(value, depth);
            break;
        case hir_node_kind_t::field:
            node_id = append_member(value, depth);
            break;
        case hir_node_kind_t::index:
            node_id = append_index(value, depth);
            break;
        case hir_node_kind_t::call:
            node_id = append_call(value, depth);
            break;
        default:
            fail(decompiler_diagnostic_code_t::malformed_ast, "decompiler.ast.v2.expression_kind", value.coordinate);
            break;
        }
        if (node_id == 0) {
            state_iterator->second = value_state_t::unvisited;
            return 0;
        }
        expression_ids_[value_id] = node_id;
        state_iterator->second = value_state_t::complete;
        return node_id;
    }

    std::uint64_t append_leaf(const hir_value_t& value, const typed_pseudocode_ast_node_kind_t kind)
    {
        if (!value.operand_ids.empty() || !is_visible_text(value.stable_value)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.leaf_payload", value.coordinate);
            return 0;
        }
        return append_node(
            kind,
            value.type_id,
            {},
            value.stable_value,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_unary(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 1) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.unary_arity", value.coordinate);
            return 0;
        }
        const std::string operation = value.kind == hir_node_kind_t::load ? "*" : value.stable_value;
        if (!is_unary_operator(operation)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.unary_operator", value.coordinate);
            return 0;
        }
        const auto operand = build_expression(value.operand_ids.front(), depth + 1);
        if (operand == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::unary_expression,
            value.type_id,
            {operand},
            operation,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_binary(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 2 || !is_binary_operator(value.stable_value)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.binary_payload", value.coordinate);
            return 0;
        }
        const auto left = build_expression(value.operand_ids[0], depth + 1);
        const auto right = build_expression(value.operand_ids[1], depth + 1);
        if (left == 0 || right == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::binary_expression,
            value.type_id,
            {left, right},
            value.stable_value,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_cast(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 1) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.cast_arity", value.coordinate);
            return 0;
        }
        const auto operand = build_expression(value.operand_ids.front(), depth + 1);
        if (operand == 0)
            return 0;
        if (value.stable_value == "copy")
            return operand;
        const auto type = types_.find(value.type_id);
        return append_node(
            typed_pseudocode_ast_node_kind_t::cast_expression,
            value.type_id,
            {operand},
            type->second->display_name,
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_assignment(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 2) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.assignment_arity", value.coordinate);
            return 0;
        }
        auto left = build_expression(value.operand_ids[0], depth + 1);
        const auto right = build_expression(value.operand_ids[1], depth + 1);
        if (left == 0 || right == 0)
            return 0;
        if (value.kind == hir_node_kind_t::store) {
            left = append_node(
                typed_pseudocode_ast_node_kind_t::unary_expression,
                value.type_id,
                {left},
                "*",
                translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
                value.confidence,
                value.provenance);
            if (left == 0)
                return 0;
        }
        return append_node(
            typed_pseudocode_ast_node_kind_t::assignment_expression,
            value.type_id,
            {left, right},
            "=",
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_member(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 1 || !is_visible_text(value.stable_value)) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.member_payload", value.coordinate);
            return 0;
        }
        const auto object = build_expression(value.operand_ids.front(), depth + 1);
        if (object == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::member_expression,
            value.type_id,
            {object},
            resolve_member_selector(value),
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::string resolve_member_selector(const hir_value_t& value) const
    {
        const auto offset = generated_field_selector_offset(value.stable_value);
        if (!offset.has_value())
            return value.stable_value;
        const auto object_entry = values_.find(value.operand_ids.front());
        if (object_entry == values_.end())
            return value.stable_value;
        std::uint64_t struct_type_id = object_entry->second->type_id;
        const auto* object_type = type_graph::find_type_node(type_graph_, struct_type_id);
        if (object_type != nullptr && object_type->kind == decompiler_type_kind_t::pointer) {
            const auto* pointee = type_graph::find_pointee_edge(type_graph_, struct_type_id);
            if (pointee == nullptr)
                return value.stable_value;
            struct_type_id = pointee->target_type_id;
            object_type = type_graph::find_type_node(type_graph_, struct_type_id);
        }
        if (object_type == nullptr ||
            (object_type->kind != decompiler_type_kind_t::structure && object_type->kind != decompiler_type_kind_t::union_type &&
             object_type->kind != decompiler_type_kind_t::class_type))
            return value.stable_value;
        const auto* member = type_graph::find_member_edge_by_offset(type_graph_, struct_type_id, *offset);
        if (member == nullptr || member->stable_name.empty() ||
            generated_field_selector_offset(member->stable_name).has_value())
            return value.stable_value;
        return member->stable_name;
    }

    static std::optional<std::uint64_t> generated_field_selector_offset(const std::string& selector)
    {
        std::size_t prefix_bytes = 0;
        int base = 10;
        if (selector.size() > 8 && selector.compare(0, 8, "field_0x") == 0) {
            prefix_bytes = 8;
            base = 16;
        } else if (selector.size() > 8 && selector.compare(0, 8, "field_0X") == 0) {
            prefix_bytes = 8;
            base = 16;
        } else if (selector.size() > 6 && selector.compare(0, 6, "field_") == 0) {
            prefix_bytes = 6;
        } else if (selector.size() > 5 && selector.compare(0, 5, "field") == 0) {
            prefix_bytes = 5;
        } else {
            return std::nullopt;
        }
        const std::string digits = selector.substr(prefix_bytes);
        if (digits.empty() || digits.size() > 16)
            return std::nullopt;
        std::uint64_t parsed = 0;
        for (const char character : digits) {
            const auto digit = base == 16
                ? (character >= '0' && character <= '9' ? character - '0'
                    : character >= 'a' && character <= 'f' ? character - 'a' + 10
                    : character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1)
                : (character >= '0' && character <= '9' ? character - '0' : -1);
            if (digit < 0)
                return std::nullopt;
            if (parsed > (std::numeric_limits<std::uint64_t>::max() - 15ULL) / 16ULL)
                return std::nullopt;
            parsed = parsed * static_cast<std::uint64_t>(base) + static_cast<std::uint64_t>(digit);
        }
        return parsed;
    }

    std::uint64_t append_index(const hir_value_t& value, const std::size_t depth)
    {
        if (value.operand_ids.size() != 2) {
            fail(decompiler_diagnostic_code_t::malformed_hir, "decompiler.ast.v2.index_arity", value.coordinate);
            return 0;
        }
        const auto object = build_expression(value.operand_ids[0], depth + 1);
        const auto index = build_expression(value.operand_ids[1], depth + 1);
        if (object == 0 || index == 0)
            return 0;
        return append_node(
            typed_pseudocode_ast_node_kind_t::index_expression,
            value.type_id,
            {object, index},
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_call(const hir_value_t& value, const std::size_t depth)
    {
        std::vector<std::uint64_t> children;
        if (value.operand_ids.empty()) {
            if (!is_visible_text(value.stable_value)) {
                fail(decompiler_diagnostic_code_t::unresolved_symbol, "decompiler.ast.v2.call_target", value.coordinate);
                return 0;
            }
            const auto callee = append_node(
                typed_pseudocode_ast_node_kind_t::identifier,
                value.type_id,
                {},
                value.stable_value,
                translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
                value.confidence,
                value.provenance);
            if (callee == 0)
                return 0;
            children.push_back(callee);
        } else {
            children.reserve(value.operand_ids.size());
            for (const auto operand_id : value.operand_ids) {
                const auto operand = build_expression(operand_id, depth + 1);
                if (operand == 0)
                    return 0;
                children.push_back(operand);
            }
        }
        return append_node(
            typed_pseudocode_ast_node_kind_t::call_expression,
            value.type_id,
            std::move(children),
            {},
            translate_coordinate(value.coordinate, decompiler_coordinate_layer_t::typed_ast),
            value.confidence,
            value.provenance);
    }

    std::uint64_t append_node(
        const typed_pseudocode_ast_node_kind_t kind,
        const std::uint64_t type_id,
        std::vector<std::uint64_t> children,
        std::string stable_text,
        source_coordinate_t coordinate,
        const std::uint8_t confidence,
        const decompiler_fact_provenance_t provenance)
    {
        if (ast_.nodes.size() >= request_.limits.max_ast_nodes || next_node_id_ == std::numeric_limits<std::uint64_t>::max()) {
            fail(decompiler_diagnostic_code_t::resource_limit, "decompiler.ast.v2.ast_node_limit", coordinate);
            return 0;
        }
        typed_pseudocode_ast_node_t node;
        node.id = next_node_id_++;
        node.kind = kind;
        node.type_id = type_id;
        node.child_ids = std::move(children);
        node.stable_text = std::move(stable_text);
        node.coordinate = std::move(coordinate);
        node.confidence = penalty_active_ ? penalize_confidence(confidence) : confidence;
        node.provenance = provenance;
        ast_.nodes.push_back(std::move(node));
        return ast_.nodes.back().id;
    }

    static std::uint8_t penalize_confidence(const std::uint8_t confidence) noexcept
    {
        return confidence > 25 ? static_cast<std::uint8_t>(confidence - 25) : std::uint8_t{1};
    }

    void append_diagnostics_and_unknowns()
    {
        std::uint32_t ordinal = 1;
        const auto append_diagnostics = [&ordinal, this](const std::vector<decompiler_diagnostic_t>& diagnostics) {
            for (const auto& diagnostic : diagnostics) {
                auto translated = diagnostic;
                translated.ordinal = ordinal++;
                if (translated.coordinate)
                    translated.coordinate = translate_coordinate(*translated.coordinate, decompiler_coordinate_layer_t::typed_ast);
                ast_.diagnostics.push_back(std::move(translated));
            }
        };
        append_diagnostics(hir_.diagnostics);
        append_diagnostics(type_graph_.diagnostics);
        append_diagnostics(partial_diagnostics_);
        const auto append_unknowns = [this](const std::vector<decompiler_unknown_t>& unknowns) {
            for (const auto& unknown : unknowns) {
                auto translated = unknown;
                translated.coordinate = translate_coordinate(unknown.coordinate, decompiler_coordinate_layer_t::typed_ast);
                ast_.unknowns.push_back(std::move(translated));
            }
        };
        append_unknowns(hir_.unknowns);
        append_unknowns(type_graph_.unknowns);
        append_unknowns(generated_unknowns_);
        result_.diagnostics = ast_.diagnostics;
        result_.unknowns = ast_.unknowns;
    }

    void fail(
        const decompiler_diagnostic_code_t code,
        std::string key,
        const std::optional<source_coordinate_t>& coordinate = std::nullopt)
    {
        if (failed_)
            return;
        failed_ = true;
        std::optional<source_coordinate_t> translated;
        if (coordinate)
            translated = translate_coordinate(*coordinate, decompiler_coordinate_layer_t::typed_ast);
        result_.diagnostics.push_back(make_diagnostic(code, std::move(key), next_diagnostic_ordinal_++, translated));
    }

    void record_degradation(std::string key,
                            const std::optional<source_coordinate_t>& coordinate)
    {
        if (degraded_)
            return;
        degraded_ = true;
        first_failure_key_ = std::move(key);
        if (coordinate)
            first_failure_coordinate_ = *coordinate;
    }

    bool fail_exception_analysis(std::string key, const source_coordinate_t& coordinate)
    {
        if (exception_analysis_failure_key_.empty()) {
            exception_analysis_failure_key_ = std::move(key);
            exception_analysis_failure_coordinate_ = coordinate;
        }
        return false;
    }

public:
    std::uint32_t degraded_region_count() const noexcept { return degraded_region_count_; }

private:
    const hir_function_t& hir_;
    const type_graph_t& type_graph_;
    const typed_ast_v2_build_request_t& request_;
    typed_ast_v2_build_result_t& result_;
    typed_pseudocode_ast_v2_t ast_;
    source_coordinate_t body_coordinate_;
    std::map<std::uint64_t, const decompiler_type_node_t*> types_;
    std::map<std::uint64_t, const hir_block_t*> blocks_;
    std::map<std::uint64_t, const hir_value_t*> values_;
    std::map<std::uint64_t, value_state_t> states_;
    std::map<std::uint64_t, std::uint64_t> expression_ids_;
    std::map<std::uint64_t, std::size_t> use_counts_;
    std::map<std::uint64_t, std::vector<std::uint64_t>> normal_predecessors_;
    std::map<std::uint64_t, std::vector<std::uint64_t>> exception_predecessors_;
    std::map<std::uint64_t, std::set<std::uint64_t>> dominators_;
    std::map<std::uint64_t, std::set<std::uint64_t>> postdominators_;
    std::map<std::uint64_t, natural_loop_t> loops_;
    std::map<std::uint64_t, exception_region_t> exception_regions_;
    std::map<std::uint64_t, std::uint64_t> handler_region_owners_;
    std::set<std::uint64_t> exception_handler_entries_;
    std::set<std::uint64_t> emitted_blocks_;
    std::set<std::uint64_t> goto_target_blocks_;
    std::map<std::uint64_t, std::string> block_labels_;
    std::vector<decompiler_unknown_t> generated_unknowns_;
    std::vector<std::uint64_t> parameter_declaration_ids_;
    std::vector<std::uint64_t> local_declaration_ids_;
    std::vector<std::uint64_t> body_statement_ids_;
    std::uint64_t entry_block_id_ = 0;
    std::uint64_t next_node_id_ = 1;
    std::uint32_t next_diagnostic_ordinal_ = 1;
    bool failed_ = false;
    bool degraded_ = false;
    bool penalty_active_ = false;
    std::uint32_t degraded_region_count_ = 0;
    std::string first_failure_key_;
    std::optional<source_coordinate_t> first_failure_coordinate_;
    std::string exception_analysis_failure_key_;
    std::optional<source_coordinate_t> exception_analysis_failure_coordinate_;
    std::vector<decompiler_diagnostic_t> partial_diagnostics_;
};

void append_semantic_error(
    decompiler_contract_validation_t& result,
    const typed_pseudocode_ast_node_t* node,
    const std::string& key,
    std::uint32_t& ordinal)
{
    result.diagnostics.push_back(make_diagnostic(
        decompiler_diagnostic_code_t::malformed_ast,
        key,
        ordinal++,
        node == nullptr ? std::nullopt : std::optional<source_coordinate_t>{node->coordinate}));
}

}

bool typed_ast_v2_build_result_t::succeeded() const noexcept
{
    return ast.has_value();
}

std::string typed_ast_v2_node_layout(const typed_pseudocode_ast_node_kind_t kind)
{
    switch (kind) {
    case typed_pseudocode_ast_node_kind_t::function_definition: return "parameter_declarations_then_body";
    case typed_pseudocode_ast_node_kind_t::compound_statement: return "ordered_statements";
    case typed_pseudocode_ast_node_kind_t::declaration: return "optional_initializer";
    case typed_pseudocode_ast_node_kind_t::expression_statement: return "expression";
    case typed_pseudocode_ast_node_kind_t::if_statement: return "condition_then_body_optional_else_clause";
    case typed_pseudocode_ast_node_kind_t::else_clause: return "body_or_if_statement";
    case typed_pseudocode_ast_node_kind_t::while_statement: return "condition_body";
    case typed_pseudocode_ast_node_kind_t::do_while_statement: return "body_condition";
    case typed_pseudocode_ast_node_kind_t::for_statement: return "initializer_condition_iteration_body";
    case typed_pseudocode_ast_node_kind_t::switch_statement: return "selector_ordered_cases";
    case typed_pseudocode_ast_node_kind_t::switch_case: return "case_value_then_statements_or_default_statements";
    case typed_pseudocode_ast_node_kind_t::break_statement: return "empty";
    case typed_pseudocode_ast_node_kind_t::continue_statement: return "empty";
    case typed_pseudocode_ast_node_kind_t::return_statement: return "optional_expression";
    case typed_pseudocode_ast_node_kind_t::throw_statement: return "optional_expression";
    case typed_pseudocode_ast_node_kind_t::try_statement: return "body_then_catches_or_finally";
    case typed_pseudocode_ast_node_kind_t::catch_clause: return "body";
    case typed_pseudocode_ast_node_kind_t::finally_clause: return "body";
    case typed_pseudocode_ast_node_kind_t::goto_statement: return "empty";
    case typed_pseudocode_ast_node_kind_t::label_statement: return "empty";
    case typed_pseudocode_ast_node_kind_t::assignment_expression: return "left_right";
    case typed_pseudocode_ast_node_kind_t::unary_expression: return "operand";
    case typed_pseudocode_ast_node_kind_t::binary_expression: return "left_right";
    case typed_pseudocode_ast_node_kind_t::cast_expression: return "operand";
    case typed_pseudocode_ast_node_kind_t::call_expression: return "callee_then_arguments";
    case typed_pseudocode_ast_node_kind_t::member_expression: return "object";
    case typed_pseudocode_ast_node_kind_t::index_expression: return "object_index";
    case typed_pseudocode_ast_node_kind_t::identifier: return "empty";
    case typed_pseudocode_ast_node_kind_t::literal: return "empty";
    case typed_pseudocode_ast_node_kind_t::unknown_expression: return "empty";
    case typed_pseudocode_ast_node_kind_t::comment_statement: return "empty";
    }
    return "invalid";
}

decompiler_contract_validation_t validate_typed_ast_v2_semantics(
    const typed_pseudocode_ast_v2_t& ast,
    const type_graph_t& type_graph)
{
    auto result = validate_typed_pseudocode_ast(ast);
    const auto type_validation = validate_type_graph(type_graph);
    result.diagnostics.insert(result.diagnostics.end(), type_validation.diagnostics.begin(), type_validation.diagnostics.end());
    if (!result.valid())
        return result;
    std::map<std::uint64_t, const typed_pseudocode_ast_node_t*> nodes;
    std::set<std::uint64_t> type_ids;
    for (const auto& node : ast.nodes)
        nodes.emplace(node.id, &node);
    for (const auto& type : type_graph.nodes)
        type_ids.insert(type.id);
    std::uint32_t ordinal = 1;
    const auto child = [&nodes](const typed_pseudocode_ast_node_t& node, const std::size_t index) {
        if (index >= node.child_ids.size())
            return static_cast<const typed_pseudocode_ast_node_t*>(nullptr);
        const auto iterator = nodes.find(node.child_ids[index]);
        return iterator == nodes.end() ? static_cast<const typed_pseudocode_ast_node_t*>(nullptr) : iterator->second;
    };
    const auto require_child_kind = [&child, &result, &ordinal](const typed_pseudocode_ast_node_t& node, const std::size_t index,
                                        const typed_pseudocode_ast_node_kind_t kind, const char* key) {
        const auto* value = child(node, index);
        if (value == nullptr || value->kind != kind)
            append_semantic_error(result, &node, key, ordinal);
    };
    const auto require_expression = [&child, &result, &ordinal](const typed_pseudocode_ast_node_t& node, const std::size_t index,
                                    const char* key) {
        const auto* value = child(node, index);
        if (value == nullptr || !is_expression_kind(value->kind))
            append_semantic_error(result, &node, key, ordinal);
    };
    const auto require_statement = [&child, &result, &ordinal](const typed_pseudocode_ast_node_t& node, const std::size_t index,
                                   const char* key) {
        const auto* value = child(node, index);
        if (value == nullptr || !is_statement_kind(value->kind))
            append_semantic_error(result, &node, key, ordinal);
    };
    if (!(ast.entity == type_graph.entity) || ast.type_graph_hash != stable_serialization_hash(type_graph))
        append_semantic_error(result, nullptr, "decompiler.ast.v2.type_graph_identity", ordinal);
    for (const auto& node : ast.nodes) {
        if (type_ids.find(node.type_id) == type_ids.end())
            append_semantic_error(result, &node, "decompiler.ast.v2.node_type", ordinal);
        switch (node.kind) {
        case typed_pseudocode_ast_node_kind_t::function_definition:
            if (node.child_ids.empty() || child(node, node.child_ids.size() - 1) == nullptr ||
                child(node, node.child_ids.size() - 1)->kind != typed_pseudocode_ast_node_kind_t::compound_statement ||
                !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.function_layout", ordinal);
            for (std::size_t index = 0; index + 1 < node.child_ids.size(); ++index)
                require_child_kind(node, index, typed_pseudocode_ast_node_kind_t::declaration, "decompiler.ast.v2.parameter_layout");
            break;
        case typed_pseudocode_ast_node_kind_t::compound_statement:
            for (std::size_t index = 0; index < node.child_ids.size(); ++index)
                require_statement(node, index, "decompiler.ast.v2.compound_statement");
            break;
        case typed_pseudocode_ast_node_kind_t::declaration:
            if (node.child_ids.size() > 1 || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.declaration_layout", ordinal);
            if (!node.child_ids.empty())
                require_expression(node, 0, "decompiler.ast.v2.declaration_initializer");
            break;
        case typed_pseudocode_ast_node_kind_t::expression_statement:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.expression_statement_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.expression_statement_expression");
            break;
        case typed_pseudocode_ast_node_kind_t::if_statement:
            if (node.child_ids.size() != 2 && node.child_ids.size() != 3)
                append_semantic_error(result, &node, "decompiler.ast.v2.if_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.if_condition");
            require_child_kind(node, 1, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.if_body");
            if (node.child_ids.size() == 3)
                require_child_kind(node, 2, typed_pseudocode_ast_node_kind_t::else_clause, "decompiler.ast.v2.if_else");
            break;
        case typed_pseudocode_ast_node_kind_t::else_clause:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.else_layout", ordinal);
            if (const auto* value = child(node, 0); value == nullptr ||
                (value->kind != typed_pseudocode_ast_node_kind_t::compound_statement && value->kind != typed_pseudocode_ast_node_kind_t::if_statement))
                append_semantic_error(result, &node, "decompiler.ast.v2.else_body", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::while_statement:
            if (node.child_ids.size() != 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.while_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.while_condition");
            require_child_kind(node, 1, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.while_body");
            break;
        case typed_pseudocode_ast_node_kind_t::do_while_statement:
            if (node.child_ids.size() != 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.do_while_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.do_while_body");
            require_expression(node, 1, "decompiler.ast.v2.do_while_condition");
            break;
        case typed_pseudocode_ast_node_kind_t::for_statement:
            if (node.child_ids.size() != 4)
                append_semantic_error(result, &node, "decompiler.ast.v2.for_layout", ordinal);
            if (const auto* value = child(node, 0); value == nullptr ||
                (value->kind != typed_pseudocode_ast_node_kind_t::declaration && !is_expression_kind(value->kind)))
                append_semantic_error(result, &node, "decompiler.ast.v2.for_initializer", ordinal);
            require_expression(node, 1, "decompiler.ast.v2.for_condition");
            require_expression(node, 2, "decompiler.ast.v2.for_iteration");
            require_child_kind(node, 3, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.for_body");
            break;
        case typed_pseudocode_ast_node_kind_t::switch_statement:
            if (node.child_ids.size() < 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.switch_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.switch_selector");
            for (std::size_t index = 1; index < node.child_ids.size(); ++index)
                require_child_kind(node, index, typed_pseudocode_ast_node_kind_t::switch_case, "decompiler.ast.v2.switch_case");
            break;
        case typed_pseudocode_ast_node_kind_t::switch_case:
            if (node.stable_text == "default") {
                if (node.child_ids.empty())
                    append_semantic_error(result, &node, "decompiler.ast.v2.default_body", ordinal);
                for (std::size_t index = 0; index < node.child_ids.size(); ++index)
                    require_statement(node, index, "decompiler.ast.v2.default_statement");
            } else {
                if (node.stable_text != "case" || node.child_ids.size() < 2)
                    append_semantic_error(result, &node, "decompiler.ast.v2.case_layout", ordinal);
                require_expression(node, 0, "decompiler.ast.v2.case_value");
                for (std::size_t index = 1; index < node.child_ids.size(); ++index)
                    require_statement(node, index, "decompiler.ast.v2.case_statement");
            }
            break;
        case typed_pseudocode_ast_node_kind_t::break_statement:
        case typed_pseudocode_ast_node_kind_t::continue_statement:
            if (!node.child_ids.empty())
                append_semantic_error(result, &node, "decompiler.ast.v2.empty_statement", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::goto_statement:
            if (!node.child_ids.empty() || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.goto_layout", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::comment_statement:
            if (!node.child_ids.empty() || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.comment_layout", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::label_statement:
            if (!node.child_ids.empty() || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.label_layout", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::return_statement:
        case typed_pseudocode_ast_node_kind_t::throw_statement:
            if (node.child_ids.size() > 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.terminal_layout", ordinal);
            if (!node.child_ids.empty())
                require_expression(node, 0, "decompiler.ast.v2.terminal_expression");
            break;
        case typed_pseudocode_ast_node_kind_t::try_statement:
            if (node.child_ids.size() < 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.try_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.try_body");
            for (std::size_t index = 1; index < node.child_ids.size(); ++index) {
                const auto* value = child(node, index);
                if (value == nullptr || (value->kind != typed_pseudocode_ast_node_kind_t::catch_clause &&
                    value->kind != typed_pseudocode_ast_node_kind_t::finally_clause))
                    append_semantic_error(result, &node, "decompiler.ast.v2.try_handler", ordinal);
            }
            break;
        case typed_pseudocode_ast_node_kind_t::catch_clause:
            if (node.child_ids.size() != 1 || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.catch_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.catch_body");
            break;
        case typed_pseudocode_ast_node_kind_t::finally_clause:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.finally_layout", ordinal);
            require_child_kind(node, 0, typed_pseudocode_ast_node_kind_t::compound_statement, "decompiler.ast.v2.finally_body");
            break;
        case typed_pseudocode_ast_node_kind_t::assignment_expression:
        case typed_pseudocode_ast_node_kind_t::binary_expression:
        case typed_pseudocode_ast_node_kind_t::index_expression:
            if (node.child_ids.size() != 2)
                append_semantic_error(result, &node, "decompiler.ast.v2.binary_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.binary_left");
            require_expression(node, 1, "decompiler.ast.v2.binary_right");
            if (node.kind == typed_pseudocode_ast_node_kind_t::binary_expression && !is_binary_operator(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.binary_operator", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::unary_expression:
        case typed_pseudocode_ast_node_kind_t::cast_expression:
        case typed_pseudocode_ast_node_kind_t::member_expression:
            if (node.child_ids.size() != 1)
                append_semantic_error(result, &node, "decompiler.ast.v2.unary_layout", ordinal);
            require_expression(node, 0, "decompiler.ast.v2.unary_operand");
            if (node.kind == typed_pseudocode_ast_node_kind_t::unary_expression && !is_unary_operator(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.unary_operator", ordinal);
            if ((node.kind == typed_pseudocode_ast_node_kind_t::cast_expression || node.kind == typed_pseudocode_ast_node_kind_t::member_expression) &&
                !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.named_expression", ordinal);
            break;
        case typed_pseudocode_ast_node_kind_t::call_expression:
            if (node.child_ids.empty())
                append_semantic_error(result, &node, "decompiler.ast.v2.call_layout", ordinal);
            for (std::size_t index = 0; index < node.child_ids.size(); ++index)
                require_expression(node, index, "decompiler.ast.v2.call_operand");
            break;
        case typed_pseudocode_ast_node_kind_t::identifier:
        case typed_pseudocode_ast_node_kind_t::literal:
        case typed_pseudocode_ast_node_kind_t::unknown_expression:
            if (!node.child_ids.empty() || !is_visible_text(node.stable_text))
                append_semantic_error(result, &node, "decompiler.ast.v2.leaf_layout", ordinal);
            break;
        }
    }
    return result;
}

typed_ast_v2_build_result_t build_typed_ast_v2(
    const hir_function_t& hir,
    const type_graph_t& type_graph,
    const typed_ast_v2_build_request_t& request)
{
    typed_ast_v2_build_result_t result;
    const auto hir_validation = validate_hir_function(hir);
    const auto type_validation = validate_type_graph(type_graph);
    if (!hir_validation.valid() || !type_validation.valid()) {
        append_validation_diagnostics(result, hir_validation);
        append_validation_diagnostics(result, type_validation);
        return result;
    }
    result.hir_hash = stable_serialization_hash(hir);
    result.type_graph_hash = stable_serialization_hash(type_graph);
    ast_builder_t builder(hir, type_graph, request, result);
    builder.run();
    result.partial = builder.degraded_region_count() != 0;
    if (result.succeeded() && builder.degraded_region_count() != 0) {
        diag::log_tagged_fmt("dec_ast",
            "typed_ast_v2_build partial=1 regions=%u nodes=%zu",
            builder.degraded_region_count(),
            result.ast ? result.ast->nodes.size() : static_cast<std::size_t>(0));
    }
    return result;
}

std::string serialize_typed_ast_v2(const typed_pseudocode_ast_v2_t& ast)
{
    return serialize_typed_pseudocode_ast(ast);
}

decompiler_contract_decode_result_t<typed_pseudocode_ast_v2_t> deserialize_typed_ast_v2(const std::string& bytes)
{
    return deserialize_typed_pseudocode_ast(bytes);
}

}
