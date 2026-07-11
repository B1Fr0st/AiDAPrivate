#include "advanced_cfg.hpp"

#include <algorithm>
#include <limits>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace aida::analysis {

namespace {

constexpr std::size_t no_index = (std::numeric_limits<std::size_t>::max)();

workspace_result_t<void> cfg_error(workspace_error_code_t code, const char* message,
                                   const char* phase) {
    return workspace_result_t<void>::failure(make_workspace_error(code, message, phase));
}

class cfg_poller_t {
public:
    explicit cfg_poller_t(const cancellation_token_t& cancel) : cancel_(cancel) {}

    workspace_result_t<void> poll(const char* phase, bool force = false) {
        if (!force && ((visits_++ & 255U) != 0))
            return workspace_result_t<void>::success();
        if (!cancel_.stop_requested())
            return workspace_result_t<void>::success();
        auto error = make_workspace_error(
            cancel_.deadline_exceeded() ? workspace_error_code_t::deadline_exceeded
                                        : workspace_error_code_t::cancelled,
            cancel_.deadline_exceeded() ? "advanced CFG deadline exceeded"
                                       : "advanced CFG cancelled",
            phase);
        error.deadline = cancel_.deadline_exceeded();
        error.cancellation = !error.deadline;
        return workspace_result_t<void>::failure(std::move(error));
    }

private:
    const cancellation_token_t& cancel_;
    std::uint64_t visits_ = 0;
};

bool same_domain(const address_t& lhs, const address_t& rhs) noexcept {
    return lhs.space == rhs.space && lhs.architecture == rhs.architecture && lhs.mode == rhs.mode;
}

bool address_in_block(const address_t& address, const basic_block_record_t& block) noexcept {
    return same_domain(address, block.start) && block.start.value <= address.value &&
           address.value < block.end.value;
}

bool valid_quality(fact_provenance_t provenance, std::uint8_t confidence) noexcept {
    return provenance <= fact_provenance_t::decompiler_feedback && confidence <= 100;
}

advanced_cfg_quality_t quality_from(fact_provenance_t provenance, std::uint8_t confidence) {
    advanced_cfg_quality_t quality;
    quality.provenance = provenance;
    quality.confidence = confidence;
    quality.contributor_count = 1;
    return quality;
}

bool quality_preferred(const advanced_cfg_quality_t& candidate,
                       const advanced_cfg_quality_t& existing) noexcept {
    if (candidate.confidence != existing.confidence)
        return candidate.confidence > existing.confidence;
    return provenance_rank(candidate.provenance) > provenance_rank(existing.provenance);
}

void merge_quality(advanced_cfg_quality_t& existing, const advanced_cfg_quality_t& candidate) {
    if (candidate.contributor_count == 0)
        return;
    if (existing.contributor_count == 0) {
        existing = candidate;
        return;
    }
    if (existing.provenance != candidate.provenance || existing.confidence != candidate.confidence)
        existing.conflicted = true;
    existing.contributor_count = existing.contributor_count >
        (std::numeric_limits<std::uint32_t>::max)() - candidate.contributor_count
        ? (std::numeric_limits<std::uint32_t>::max)()
        : existing.contributor_count + candidate.contributor_count;
    existing.conflicted = existing.conflicted || candidate.conflicted;
    if (quality_preferred(candidate, existing)) {
        existing.provenance = candidate.provenance;
        existing.confidence = candidate.confidence;
    }
}

bool block_less(const basic_block_record_t* lhs, const basic_block_record_t* rhs) noexcept {
    if (lhs->start != rhs->start)
        return lhs->start < rhs->start;
    if (lhs->end != rhs->end)
        return lhs->end < rhs->end;
    return lhs->id < rhs->id;
}

struct block_heap_order_t {
    bool operator()(const basic_block_record_t* lhs, const basic_block_record_t* rhs) const noexcept {
        return block_less(lhs, rhs);
    }
};

bool raw_edge_less(const edge_record_t* lhs, const edge_record_t* rhs) noexcept {
    if (lhs->source != rhs->source)
        return lhs->source < rhs->source;
    if (lhs->target != rhs->target)
        return lhs->target < rhs->target;
    if (lhs->kind != rhs->kind)
        return lhs->kind < rhs->kind;
    if (lhs->source_entity != rhs->source_entity)
        return lhs->source_entity < rhs->source_entity;
    if (lhs->target_entity != rhs->target_entity)
        return lhs->target_entity.value_or(0) < rhs->target_entity.value_or(0);
    return lhs->id < rhs->id;
}

struct edge_heap_order_t {
    bool operator()(const edge_record_t* lhs, const edge_record_t* rhs) const noexcept {
        return raw_edge_less(lhs, rhs);
    }
};

struct block_view_t {
    const basic_block_record_t* record = nullptr;
    const instruction_record_t* terminal_instruction = nullptr;
    bool instructions_complete = false;
};

struct function_view_t {
    const function_record_t* function = nullptr;
    std::vector<block_view_t> blocks;
    std::vector<const edge_record_t*> edges;
    std::unordered_map<entity_id_t, std::size_t> block_index_by_id;
    std::unordered_map<address_t, std::size_t, address_hash_t> block_index_by_address;
    std::uint64_t input_block_count = 0;
    std::uint64_t input_edge_count = 0;
    std::uint64_t input_instruction_count = 0;
    bool blocks_truncated = false;
    bool edges_truncated = false;
    bool instructions_truncated = false;
};

struct function_catalog_t {
    std::unordered_map<entity_id_t, const function_record_t*> by_id;
    std::unordered_map<address_t, const function_record_t*, address_hash_t> by_address;
};

struct evidence_writer_t {
    cfg_analysis_result_t& result;
    const advanced_cfg_budget_t& budget;
    std::uint64_t used = 0;

    bool reserve() {
        if (used >= budget.max_evidence) {
            result.bounded = true;
            return false;
        }
        ++used;
        return true;
    }

    void conflict(advanced_cfg_conflict_t conflict) {
        if (!reserve())
            return;
        result.conflicts.push_back(std::move(conflict));
    }
};

workspace_result_t<void> validate_budget(const advanced_cfg_budget_t& budget) {
    if (budget.max_blocks == 0 || budget.max_edges == 0 || budget.max_instructions == 0 ||
        budget.max_evidence == 0 || budget.max_dominator_iterations == 0 ||
        budget.max_blocks > advanced_cfg_max_blocks || budget.max_edges > advanced_cfg_max_edges ||
        budget.max_instructions > advanced_cfg_max_instructions ||
        budget.max_evidence > advanced_cfg_max_evidence ||
        budget.max_dominator_iterations > advanced_cfg_max_dominator_iterations) {
        return cfg_error(workspace_error_code_t::invalid_argument,
                         "advanced CFG budget is outside the supported bounds", "advanced_cfg.budget");
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<function_catalog_t> build_function_catalog(const analysis_snapshot_t& snapshot,
                                                               cfg_poller_t& poller) {
    function_catalog_t catalog;
    catalog.by_id.reserve(snapshot.functions.size());
    catalog.by_address.reserve(snapshot.functions.size());
    for (const auto& function : snapshot.functions) {
        auto stopped = poller.poll("advanced_cfg.catalog");
        if (!stopped)
            return workspace_result_t<function_catalog_t>::failure(stopped.error());
        if (function.id == 0 || function.end.value <= function.start.value ||
            !valid_quality(function.provenance, function.confidence)) {
            return workspace_result_t<function_catalog_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "function record is malformed", "advanced_cfg.catalog"));
        }
        if (!catalog.by_id.emplace(function.id, &function).second ||
            !catalog.by_address.emplace(function.start, &function).second) {
            return workspace_result_t<function_catalog_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "function catalog contains duplicate identities", "advanced_cfg.catalog"));
        }
    }
    return workspace_result_t<function_catalog_t>::success(std::move(catalog));
}

workspace_result_t<function_view_t> extract_function_view(const analysis_snapshot_t& snapshot,
                                                           std::uint64_t function_rva,
                                                           const advanced_cfg_budget_t& budget,
                                                           cfg_poller_t& poller) {
    const function_record_t* function = nullptr;
    for (const auto& candidate : snapshot.functions) {
        auto stopped = poller.poll("advanced_cfg.function_lookup");
        if (!stopped)
            return workspace_result_t<function_view_t>::failure(stopped.error());
        if (candidate.start.value != function_rva)
            continue;
        if (function != nullptr) {
            return workspace_result_t<function_view_t>::failure(make_workspace_error(
                workspace_error_code_t::target_ambiguous,
                "multiple function records share the requested address", "advanced_cfg.function_lookup"));
        }
        function = &candidate;
    }
    if (function == nullptr) {
        return workspace_result_t<function_view_t>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "requested function is absent from the analysis snapshot", "advanced_cfg.function_lookup"));
    }

    std::priority_queue<const basic_block_record_t*, std::vector<const basic_block_record_t*>,
                        block_heap_order_t> selected;
    function_view_t view;
    view.function = function;
    for (const auto& block : snapshot.blocks) {
        auto stopped = poller.poll("advanced_cfg.block_selection");
        if (!stopped)
            return workspace_result_t<function_view_t>::failure(stopped.error());
        if (block.function_id != function->id)
            continue;
        ++view.input_block_count;
        if (selected.size() < static_cast<std::size_t>(budget.max_blocks)) {
            selected.push(&block);
        } else if (block_less(&block, selected.top())) {
            selected.pop();
            selected.push(&block);
        }
    }
    if (view.input_block_count == 0) {
        return workspace_result_t<function_view_t>::failure(make_workspace_error(
            workspace_error_code_t::decode_failure,
            "function has no recovered basic blocks", "advanced_cfg.block_selection"));
    }
    view.blocks_truncated = view.input_block_count > selected.size();
    view.blocks.reserve(selected.size());
    while (!selected.empty()) {
        block_view_t block;
        block.record = selected.top();
        selected.pop();
        view.blocks.push_back(block);
    }
    std::sort(view.blocks.begin(), view.blocks.end(), [](const block_view_t& lhs,
                                                          const block_view_t& rhs) {
        return block_less(lhs.record, rhs.record);
    });

    std::uint64_t remaining_instructions = budget.max_instructions;
    for (std::size_t index = 0; index < view.blocks.size(); ++index) {
        auto& selected_block = view.blocks[index];
        const auto& block = *selected_block.record;
        auto stopped = poller.poll("advanced_cfg.block_validation");
        if (!stopped)
            return workspace_result_t<function_view_t>::failure(stopped.error());
        if (block.id == 0 || block.end.value <= block.start.value ||
            !same_domain(block.start, block.end) || !same_domain(block.start, function->start) ||
            block.instruction_count == 0 || !valid_quality(block.provenance, block.confidence) ||
            block.first_instruction > snapshot.instructions.size() ||
            block.instruction_count > snapshot.instructions.size() - block.first_instruction) {
            return workspace_result_t<function_view_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "basic-block record is malformed or incomplete", "advanced_cfg.block_validation"));
        }
        if (!view.block_index_by_id.emplace(block.id, index).second ||
            !view.block_index_by_address.emplace(block.start, index).second) {
            return workspace_result_t<function_view_t>::failure(make_workspace_error(
                workspace_error_code_t::integrity_failure,
                "basic-block identities are ambiguous", "advanced_cfg.block_validation"));
        }
        if (index != 0) {
            const auto& previous = *view.blocks[index - 1].record;
            if (same_domain(previous.start, block.start) && block.start.value < previous.end.value) {
                return workspace_result_t<function_view_t>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "basic-block ranges overlap", "advanced_cfg.block_validation"));
            }
        }
        if (view.input_instruction_count > (std::numeric_limits<std::uint64_t>::max)() -
            block.instruction_count) {
            return workspace_result_t<function_view_t>::failure(make_workspace_error(
                workspace_error_code_t::range_overflow,
                "basic-block instruction count overflows", "advanced_cfg.block_validation"));
        }
        view.input_instruction_count += block.instruction_count;
        for (std::uint32_t offset = 0; offset < block.instruction_count; ++offset) {
            stopped = poller.poll("advanced_cfg.instruction_validation");
            if (!stopped)
                return workspace_result_t<function_view_t>::failure(stopped.error());
            const auto instruction_index = static_cast<std::size_t>(block.first_instruction) + offset;
            const auto& instruction = snapshot.instructions[instruction_index];
            if (instruction.id == 0 || instruction.length == 0 ||
                !address_in_block(instruction.address, block) ||
                instruction.length > block.end.value - instruction.address.value ||
                !valid_quality(instruction.provenance, instruction.confidence) ||
                instruction.operand_fact_begin > snapshot.operand_facts.size() ||
                instruction.operand_fact_count >
                    snapshot.operand_facts.size() - instruction.operand_fact_begin ||
                instruction.target_fact_begin > snapshot.target_facts.size() ||
                instruction.target_fact_count >
                    snapshot.target_facts.size() - instruction.target_fact_begin) {
                return workspace_result_t<function_view_t>::failure(make_workspace_error(
                    workspace_error_code_t::integrity_failure,
                    "instruction record is malformed or incomplete", "advanced_cfg.instruction_validation"));
            }
            for (std::uint16_t operand = 0; operand < instruction.operand_fact_count; ++operand) {
                const auto fact_index = static_cast<std::size_t>(instruction.operand_fact_begin) + operand;
                const auto& fact = snapshot.operand_facts[fact_index];
                if (fact.instruction_id != instruction.id) {
                    return workspace_result_t<function_view_t>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "operand fact does not belong to its instruction", "advanced_cfg.instruction_validation"));
                }
            }
            for (std::uint16_t target = 0; target < instruction.target_fact_count; ++target) {
                const auto fact_index = static_cast<std::size_t>(instruction.target_fact_begin) + target;
                const auto& fact = snapshot.target_facts[fact_index];
                if (fact.instruction_id != instruction.id) {
                    return workspace_result_t<function_view_t>::failure(make_workspace_error(
                        workspace_error_code_t::integrity_failure,
                        "target fact does not belong to its instruction", "advanced_cfg.instruction_validation"));
                }
            }
        }
        if (block.instruction_count <= remaining_instructions) {
            remaining_instructions -= block.instruction_count;
            selected_block.instructions_complete = true;
            selected_block.terminal_instruction =
                &snapshot.instructions[static_cast<std::size_t>(block.first_instruction) +
                                       block.instruction_count - 1];
        } else {
            remaining_instructions = 0;
            view.instructions_truncated = true;
        }
    }
    view.instructions_truncated = view.instructions_truncated ||
        view.input_instruction_count > budget.max_instructions;

    std::priority_queue<const edge_record_t*, std::vector<const edge_record_t*>, edge_heap_order_t>
        edges;
    for (const auto& edge : snapshot.edges) {
        auto stopped = poller.poll("advanced_cfg.edge_selection");
        if (!stopped)
            return workspace_result_t<function_view_t>::failure(stopped.error());
        if (view.block_index_by_id.find(edge.source_entity) == view.block_index_by_id.end())
            continue;
        ++view.input_edge_count;
        if (edges.size() < static_cast<std::size_t>(budget.max_edges)) {
            edges.push(&edge);
        } else if (raw_edge_less(&edge, edges.top())) {
            edges.pop();
            edges.push(&edge);
        }
    }
    view.edges_truncated = view.input_edge_count > edges.size();
    view.edges.reserve(edges.size());
    while (!edges.empty()) {
        view.edges.push_back(edges.top());
        edges.pop();
    }
    std::sort(view.edges.begin(), view.edges.end(), raw_edge_less);
    return workspace_result_t<function_view_t>::success(std::move(view));
}

const function_record_t* resolve_function(const function_catalog_t& catalog,
                                          const std::optional<entity_id_t>& entity,
                                          const address_t& address) {
    if (entity) {
        const auto by_id = catalog.by_id.find(*entity);
        if (by_id != catalog.by_id.end())
            return by_id->second;
    }
    const auto by_address = catalog.by_address.find(address);
    return by_address == catalog.by_address.end() ? nullptr : by_address->second;
}

bool is_control_flow_edge(edge_kind_t kind) noexcept {
    return kind != edge_kind_t::call && kind != edge_kind_t::tail_call &&
           kind != edge_kind_t::return_edge;
}

bool append_cfg_edge(cfg_analysis_result_t& result, const advanced_cfg_budget_t& budget,
                     cfg_edge_fact_t edge) {
    if (result.cfg_edges.size() >= budget.max_edges) {
        result.bounded = true;
        return false;
    }
    result.cfg_edges.push_back(std::move(edge));
    return true;
}

bool same_cfg_edge_key(const cfg_edge_fact_t& lhs, const cfg_edge_fact_t& rhs) noexcept {
    return lhs.source_block_id == rhs.source_block_id &&
           lhs.target_block_id == rhs.target_block_id &&
           lhs.target_function_id == rhs.target_function_id && lhs.source == rhs.source &&
           lhs.target == rhs.target && lhs.kind == rhs.kind;
}

bool same_cfg_edge_endpoints(const cfg_edge_fact_t& lhs, const cfg_edge_fact_t& rhs) noexcept {
    return lhs.source_block_id == rhs.source_block_id &&
           lhs.target_block_id == rhs.target_block_id &&
           lhs.target_function_id == rhs.target_function_id && lhs.source == rhs.source &&
           lhs.target == rhs.target;
}

bool cfg_edge_less(const cfg_edge_fact_t& lhs, const cfg_edge_fact_t& rhs) noexcept {
    if (lhs.source != rhs.source)
        return lhs.source < rhs.source;
    if (lhs.target != rhs.target)
        return lhs.target < rhs.target;
    if (lhs.kind != rhs.kind)
        return lhs.kind < rhs.kind;
    if (lhs.source_block_id != rhs.source_block_id)
        return lhs.source_block_id < rhs.source_block_id;
    if (lhs.target_block_id.value_or(0) != rhs.target_block_id.value_or(0))
        return lhs.target_block_id.value_or(0) < rhs.target_block_id.value_or(0);
    if (lhs.target_function_id.value_or(0) != rhs.target_function_id.value_or(0))
        return lhs.target_function_id.value_or(0) < rhs.target_function_id.value_or(0);
    if (lhs.derived != rhs.derived)
        return lhs.derived < rhs.derived;
    return lhs.external_target < rhs.external_target;
}

bool has_cfg_edge(const std::vector<cfg_edge_fact_t>& edges, entity_id_t source,
                  const std::optional<entity_id_t>& target_block,
                  const std::optional<entity_id_t>& target_function,
                  edge_kind_t kind) {
    return std::any_of(edges.begin(), edges.end(), [&](const cfg_edge_fact_t& edge) {
        return edge.source_block_id == source && edge.target_block_id == target_block &&
               edge.target_function_id == target_function && edge.kind == kind;
    });
}

workspace_result_t<void> build_cfg_edges(const analysis_snapshot_t& snapshot,
                                         const function_view_t& view,
                                         const function_catalog_t& catalog,
                                         const advanced_cfg_budget_t& budget,
                                         cfg_analysis_result_t& result,
                                         evidence_writer_t& writer,
                                         cfg_poller_t& poller) {
    for (const auto* raw : view.edges) {
        auto stopped = poller.poll("advanced_cfg.edge_validation");
        if (!stopped)
            return stopped;
        const auto source_index = view.block_index_by_id.find(raw->source_entity);
        if (source_index == view.block_index_by_id.end())
            continue;
        const auto& source_block = *view.blocks[source_index->second].record;
        if (raw->id == 0 || !address_in_block(raw->source, source_block) ||
            !valid_quality(raw->provenance, raw->confidence)) {
            return cfg_error(workspace_error_code_t::integrity_failure,
                             "control-flow edge is malformed", "advanced_cfg.edge_validation");
        }
        cfg_edge_fact_t edge;
        edge.source_block_id = raw->source_entity;
        edge.source = raw->source;
        edge.target = raw->target;
        edge.kind = raw->kind;
        edge.quality = quality_from(raw->provenance, raw->confidence);
        if (raw->target_entity) {
            const auto target_block = view.block_index_by_id.find(*raw->target_entity);
            if (target_block != view.block_index_by_id.end())
                edge.target_block_id = *raw->target_entity;
        }
        if (const auto* target_function = resolve_function(catalog, raw->target_entity, raw->target))
            edge.target_function_id = target_function->id;
        if (!edge.target_block_id && is_control_flow_edge(edge.kind)) {
            const auto by_address = view.block_index_by_address.find(raw->target);
            if (by_address != view.block_index_by_address.end())
                edge.target_block_id = view.blocks[by_address->second].record->id;
        }
        edge.external_target = !edge.target_block_id && !edge.target_function_id &&
                               raw->target.value != 0;
        if (is_control_flow_edge(edge.kind) && !edge.target_block_id &&
            same_domain(raw->target, view.function->start) &&
            view.function->start.value <= raw->target.value &&
            raw->target.value < view.function->end.value && !view.blocks_truncated) {
            return cfg_error(workspace_error_code_t::decode_failure,
                             "internal control-flow target has no recovered basic block",
                             "advanced_cfg.edge_validation");
        }
        append_cfg_edge(result, budget, std::move(edge));
    }

    for (const auto& block_view : view.blocks) {
        auto stopped = poller.poll("advanced_cfg.derived_edges");
        if (!stopped)
            return stopped;
        const auto& block = *block_view.record;
        const auto* terminal = block_view.terminal_instruction;
        if (!block_view.instructions_complete || terminal == nullptr)
            continue;
        const auto instruction_quality = quality_from(terminal->provenance, terminal->confidence);
        if ((terminal->flow_flags & flow_fallthrough) != 0) {
            address_t next = block.end;
            const auto successor = view.block_index_by_address.find(next);
            if (successor != view.block_index_by_address.end()) {
                const auto target_id = view.blocks[successor->second].record->id;
                if (!has_cfg_edge(result.cfg_edges, block.id, target_id, std::nullopt,
                                  edge_kind_t::fallthrough)) {
                    cfg_edge_fact_t edge;
                    edge.source_block_id = block.id;
                    edge.target_block_id = target_id;
                    edge.source = terminal->address;
                    edge.target = next;
                    edge.kind = edge_kind_t::fallthrough;
                    edge.quality = instruction_quality;
                    edge.derived = true;
                    append_cfg_edge(result, budget, std::move(edge));
                }
            } else if (block.end.value < view.function->end.value && !view.blocks_truncated) {
                return cfg_error(workspace_error_code_t::decode_failure,
                                 "fallthrough target has no recovered basic block",
                                 "advanced_cfg.derived_edges");
            }
        }
        for (std::uint16_t index = 0; index < terminal->target_fact_count; ++index) {
            const auto fact_index = static_cast<std::size_t>(terminal->target_fact_begin) + index;
            const auto& target = snapshot.target_facts[fact_index];
            const auto block_target = view.block_index_by_address.find(target.target);
            const auto* function_target = resolve_function(catalog, std::nullopt, target.target);
            if (target.kind == target_kind_record_t::call) {
                const std::optional<entity_id_t> target_function = function_target
                    ? std::optional<entity_id_t>(function_target->id) : std::nullopt;
                if (!has_cfg_edge(result.cfg_edges, block.id, std::nullopt, target_function,
                                  edge_kind_t::call)) {
                    cfg_edge_fact_t edge;
                    edge.source_block_id = block.id;
                    edge.target_function_id = target_function;
                    edge.source = terminal->address;
                    edge.target = target.target;
                    edge.kind = edge_kind_t::call;
                    edge.quality = instruction_quality;
                    edge.derived = true;
                    edge.external_target = !target_function && target.target.value != 0;
                    append_cfg_edge(result, budget, std::move(edge));
                }
                continue;
            }
            if (target.kind != target_kind_record_t::branch)
                continue;
            if (block_target != view.block_index_by_address.end()) {
                const auto target_id = view.blocks[block_target->second].record->id;
                const auto kind = (terminal->flow_flags & flow_indirect) != 0
                    ? edge_kind_t::indirect
                    : ((terminal->flow_flags & flow_conditional) != 0
                        ? edge_kind_t::conditional_taken : edge_kind_t::unconditional);
                if (!has_cfg_edge(result.cfg_edges, block.id, target_id, std::nullopt, kind)) {
                    cfg_edge_fact_t edge;
                    edge.source_block_id = block.id;
                    edge.target_block_id = target_id;
                    edge.source = terminal->address;
                    edge.target = target.target;
                    edge.kind = kind;
                    edge.quality = instruction_quality;
                    edge.derived = true;
                    append_cfg_edge(result, budget, std::move(edge));
                }
                continue;
            }
            const bool local_target = same_domain(target.target, view.function->start) &&
                view.function->start.value <= target.target.value &&
                target.target.value < view.function->end.value;
            if (local_target && !view.blocks_truncated) {
                return cfg_error(workspace_error_code_t::decode_failure,
                                 "branch target inside the function has no recovered basic block",
                                 "advanced_cfg.derived_edges");
            }
            if (function_target != nullptr && function_target->id != view.function->id) {
                if (!has_cfg_edge(result.cfg_edges, block.id, std::nullopt,
                                  function_target->id, edge_kind_t::tail_call)) {
                    cfg_edge_fact_t edge;
                    edge.source_block_id = block.id;
                    edge.target_function_id = function_target->id;
                    edge.source = terminal->address;
                    edge.target = target.target;
                    edge.kind = edge_kind_t::tail_call;
                    edge.quality = instruction_quality;
                    edge.derived = true;
                    append_cfg_edge(result, budget, std::move(edge));
                }
            }
        }
    }

    std::sort(result.cfg_edges.begin(), result.cfg_edges.end(), cfg_edge_less);
    std::vector<cfg_edge_fact_t> merged;
    merged.reserve(result.cfg_edges.size());
    for (auto& edge : result.cfg_edges) {
        if (!merged.empty() && same_cfg_edge_key(merged.back(), edge)) {
            merge_quality(merged.back().quality, edge.quality);
            merged.back().derived = merged.back().derived && edge.derived;
            merged.back().external_target = merged.back().external_target || edge.external_target;
            continue;
        }
        if (!merged.empty() && same_cfg_edge_endpoints(merged.back(), edge) &&
            merged.back().kind != edge.kind) {
            advanced_cfg_conflict_t conflict;
            conflict.kind = advanced_cfg_conflict_kind_t::conflicting_edge_kind;
            conflict.rva = edge.source.value;
            conflict.source_entity = edge.source_block_id;
            conflict.target_entity = edge.target_block_id.value_or(edge.target_function_id.value_or(0));
            conflict.existing_edge_kind = merged.back().kind;
            conflict.candidate_edge_kind = edge.kind;
            conflict.existing_quality = merged.back().quality;
            conflict.candidate_quality = edge.quality;
            writer.conflict(std::move(conflict));
        }
        merged.push_back(std::move(edge));
    }
    result.cfg_edges = std::move(merged);
    return workspace_result_t<void>::success();
}

struct cfg_graph_t {
    std::vector<entity_id_t> nodes;
    std::vector<std::vector<std::size_t>> successors;
    std::vector<std::vector<std::size_t>> predecessors;
    std::unordered_map<entity_id_t, std::size_t> index_by_id;
    std::size_t entry = no_index;
};

cfg_graph_t build_graph(const function_view_t& view, const cfg_analysis_result_t& result) {
    cfg_graph_t graph;
    graph.nodes.reserve(view.blocks.size());
    for (const auto& block : view.blocks) {
        graph.index_by_id.emplace(block.record->id, graph.nodes.size());
        graph.nodes.push_back(block.record->id);
    }
    graph.successors.resize(graph.nodes.size());
    graph.predecessors.resize(graph.nodes.size());
    for (const auto& edge : result.cfg_edges) {
        if (!is_control_flow_edge(edge.kind) || !edge.target_block_id)
            continue;
        const auto source = graph.index_by_id.find(edge.source_block_id);
        const auto target = graph.index_by_id.find(*edge.target_block_id);
        if (source == graph.index_by_id.end() || target == graph.index_by_id.end())
            continue;
        graph.successors[source->second].push_back(target->second);
        graph.predecessors[target->second].push_back(source->second);
    }
    for (auto& successors : graph.successors) {
        std::sort(successors.begin(), successors.end());
        successors.erase(std::unique(successors.begin(), successors.end()), successors.end());
    }
    for (auto& predecessors : graph.predecessors) {
        std::sort(predecessors.begin(), predecessors.end());
        predecessors.erase(std::unique(predecessors.begin(), predecessors.end()), predecessors.end());
    }
    for (std::size_t index = 0; index < view.blocks.size(); ++index) {
        if (view.blocks[index].record->start == view.function->start) {
            graph.entry = index;
            break;
        }
    }
    if (graph.entry == no_index && !graph.nodes.empty())
        graph.entry = 0;
    return graph;
}

workspace_result_t<dominator_tree_t> compute_dominators(const cfg_graph_t& graph,
                                                         std::vector<std::size_t> roots,
                                                         bool post_dominator,
                                                         std::uint32_t iteration_limit,
                                                         cfg_poller_t& poller) {
    dominator_tree_t tree;
    tree.block_ids = graph.nodes;
    tree.immediate_dominators.assign(graph.nodes.size(), 0);
    tree.children.resize(graph.nodes.size());
    tree.reverse_post_order.assign(graph.nodes.size(), (std::numeric_limits<std::uint32_t>::max)());
    tree.reachable.assign(graph.nodes.size(), false);
    tree.block_count = graph.nodes.size();
    tree.post_dominator = post_dominator;
    if (roots.empty()) {
        tree.complete = false;
        return workspace_result_t<dominator_tree_t>::success(std::move(tree));
    }
    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end()), roots.end());
    const std::size_t virtual_root = graph.nodes.size();
    std::vector<std::vector<std::size_t>> successors = post_dominator
        ? graph.predecessors : graph.successors;
    std::vector<std::vector<std::size_t>> predecessors = post_dominator
        ? graph.successors : graph.predecessors;
    successors.resize(graph.nodes.size() + 1);
    predecessors.resize(graph.nodes.size() + 1);
    successors[virtual_root] = roots;
    for (const auto root : roots)
        predecessors[root].push_back(virtual_root);

    struct frame_t { std::size_t node = 0; std::size_t next = 0; };
    std::vector<bool> visited(graph.nodes.size() + 1, false);
    std::vector<frame_t> stack;
    std::vector<std::size_t> post_order;
    visited[virtual_root] = true;
    stack.push_back({virtual_root, 0});
    while (!stack.empty()) {
        auto stopped = poller.poll("advanced_cfg.dominator_traversal");
        if (!stopped)
            return workspace_result_t<dominator_tree_t>::failure(stopped.error());
        auto& frame = stack.back();
        if (frame.next < successors[frame.node].size()) {
            const auto successor = successors[frame.node][frame.next++];
            if (!visited[successor]) {
                visited[successor] = true;
                stack.push_back({successor, 0});
            }
            continue;
        }
        post_order.push_back(frame.node);
        stack.pop_back();
    }
    std::reverse(post_order.begin(), post_order.end());
    std::vector<std::size_t> rank(graph.nodes.size() + 1, no_index);
    for (std::size_t index = 0; index < post_order.size(); ++index)
        rank[post_order[index]] = index;
    std::vector<std::size_t> idom(graph.nodes.size() + 1, no_index);
    idom[virtual_root] = virtual_root;
    bool changed = true;
    std::uint32_t iterations = 0;
    while (changed && iterations < iteration_limit) {
        changed = false;
        ++iterations;
        for (const auto node : post_order) {
            auto stopped = poller.poll("advanced_cfg.dominator_iteration");
            if (!stopped)
                return workspace_result_t<dominator_tree_t>::failure(stopped.error());
            if (node == virtual_root)
                continue;
            std::size_t candidate = no_index;
            for (const auto predecessor : predecessors[node]) {
                if (idom[predecessor] == no_index)
                    continue;
                if (candidate == no_index) {
                    candidate = predecessor;
                    continue;
                }
                std::size_t left = candidate;
                std::size_t right = predecessor;
                while (left != right) {
                    while (rank[left] > rank[right])
                        left = idom[left];
                    while (rank[right] > rank[left])
                        right = idom[right];
                }
                candidate = left;
            }
            if (candidate != no_index && idom[node] != candidate) {
                idom[node] = candidate;
                changed = true;
            }
        }
    }
    tree.complete = !changed;
    for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
        tree.reachable[index] = idom[index] != no_index;
        if (rank[index] != no_index)
            tree.reverse_post_order[index] = static_cast<std::uint32_t>(rank[index]);
        if (idom[index] != no_index && idom[index] != virtual_root) {
            tree.immediate_dominators[index] = graph.nodes[idom[index]];
            tree.children[idom[index]].push_back(graph.nodes[index]);
        }
    }
    return workspace_result_t<dominator_tree_t>::success(std::move(tree));
}

bool dominates(const dominator_tree_t& tree, const cfg_graph_t& graph,
               std::size_t dominator, std::size_t node) {
    if (dominator >= tree.block_ids.size() || node >= tree.block_ids.size() ||
        !tree.reachable[dominator] || !tree.reachable[node]) {
        return false;
    }
    for (std::size_t steps = 0; steps <= tree.block_ids.size(); ++steps) {
        if (node == dominator)
            return true;
        const auto idom = tree.immediate_dominators[node];
        if (idom == 0)
            return false;
        const auto found = graph.index_by_id.find(idom);
        if (found == graph.index_by_id.end())
            return false;
        node = found->second;
    }
    return false;
}

advanced_cfg_quality_t edge_quality(const cfg_analysis_result_t& result, entity_id_t source,
                                    entity_id_t target) {
    advanced_cfg_quality_t quality;
    for (const auto& edge : result.cfg_edges) {
        if (edge.source_block_id == source && edge.target_block_id &&
            *edge.target_block_id == target) {
            merge_quality(quality, edge.quality);
        }
    }
    return quality;
}

workspace_result_t<void> derive_loops(const cfg_graph_t& graph, const dominator_tree_t& dominators,
                                      const std::vector<block_view_t>& blocks,
                                      cfg_analysis_result_t& result, evidence_writer_t& writer,
                                      cfg_poller_t& poller) {
    for (std::size_t source = 0; source < graph.nodes.size(); ++source) {
        for (const auto target : graph.successors[source]) {
            auto stopped = poller.poll("advanced_cfg.loop_detection");
            if (!stopped)
                return stopped;
            if (!dominates(dominators, graph, target, source))
                continue;
            if (!writer.reserve())
                return workspace_result_t<void>::success();
            std::vector<bool> in_loop(graph.nodes.size(), false);
            std::vector<std::size_t> worklist;
            in_loop[target] = true;
            worklist.push_back(source);
            while (!worklist.empty()) {
                stopped = poller.poll("advanced_cfg.loop_body");
                if (!stopped)
                    return stopped;
                const auto node = worklist.back();
                worklist.pop_back();
                if (in_loop[node])
                    continue;
                in_loop[node] = true;
                for (const auto predecessor : graph.predecessors[node])
                    worklist.push_back(predecessor);
            }
            loop_info_t loop;
            loop.header_block_id = graph.nodes[target];
            loop.back_edge_source_id = graph.nodes[source];
            loop.header_rva = blocks[target].record->start.value;
            loop.back_edge_source_rva = blocks[source].record->start.value;
            loop.quality = edge_quality(result, loop.back_edge_source_id, loop.header_block_id);
            loop.is_infinite = true;
            for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
                if (!in_loop[index])
                    continue;
                loop.body_blocks.push_back(graph.nodes[index]);
                for (const auto successor : graph.successors[index]) {
                    if (!in_loop[successor])
                        loop.is_infinite = false;
                }
            }
            result.loops.push_back(std::move(loop));
        }
    }
    std::sort(result.loops.begin(), result.loops.end(), [](const loop_info_t& lhs,
                                                            const loop_info_t& rhs) {
        if (lhs.header_rva != rhs.header_rva)
            return lhs.header_rva < rhs.header_rva;
        if (lhs.back_edge_source_rva != rhs.back_edge_source_rva)
            return lhs.back_edge_source_rva < rhs.back_edge_source_rva;
        if (lhs.header_block_id != rhs.header_block_id)
            return lhs.header_block_id < rhs.header_block_id;
        return lhs.back_edge_source_id < rhs.back_edge_source_id;
    });
    std::vector<std::uint32_t> depths(graph.nodes.size(), 0);
    for (std::size_t index = 0; index < result.loops.size(); ++index) {
        auto& loop = result.loops[index];
        loop.nesting_depth = 1;
        for (std::size_t other = 0; other < result.loops.size(); ++other) {
            if (index == other || result.loops[other].body_blocks.size() <= loop.body_blocks.size())
                continue;
            if (std::find(result.loops[other].body_blocks.begin(),
                          result.loops[other].body_blocks.end(), loop.header_block_id) !=
                result.loops[other].body_blocks.end()) {
                ++loop.nesting_depth;
            }
        }
        for (const auto id : loop.body_blocks) {
            const auto found = graph.index_by_id.find(id);
            if (found != graph.index_by_id.end())
                ++depths[found->second];
        }
    }
    for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
        loop_depth_fact_t depth;
        depth.block_id = graph.nodes[index];
        depth.depth = depths[index];
        result.loop_depths.push_back(depth);
    }
    result.loops_found = result.loops.size();
    return workspace_result_t<void>::success();
}

workspace_result_t<void> derive_reducibility(const cfg_graph_t& graph,
                                              cfg_analysis_result_t& result,
                                              evidence_writer_t& writer,
                                              cfg_poller_t& poller) {
    std::vector<bool> visited(graph.nodes.size(), false);
    std::vector<std::size_t> order;
    struct frame_t { std::size_t node = 0; std::size_t next = 0; };
    for (std::size_t start = 0; start < graph.nodes.size(); ++start) {
        if (visited[start])
            continue;
        std::vector<frame_t> stack;
        stack.push_back({start, 0});
        visited[start] = true;
        while (!stack.empty()) {
            auto stopped = poller.poll("advanced_cfg.reducibility_order");
            if (!stopped)
                return stopped;
            auto& frame = stack.back();
            if (frame.next < graph.successors[frame.node].size()) {
                const auto successor = graph.successors[frame.node][frame.next++];
                if (!visited[successor]) {
                    visited[successor] = true;
                    stack.push_back({successor, 0});
                }
                continue;
            }
            order.push_back(frame.node);
            stack.pop_back();
        }
    }
    std::vector<bool> assigned(graph.nodes.size(), false);
    for (auto iterator = order.rbegin(); iterator != order.rend(); ++iterator) {
        const auto start = *iterator;
        if (assigned[start])
            continue;
        std::vector<std::size_t> component;
        std::vector<std::size_t> stack{start};
        assigned[start] = true;
        while (!stack.empty()) {
            auto stopped = poller.poll("advanced_cfg.reducibility_component");
            if (!stopped)
                return stopped;
            const auto node = stack.back();
            stack.pop_back();
            component.push_back(node);
            for (const auto predecessor : graph.predecessors[node]) {
                if (!assigned[predecessor]) {
                    assigned[predecessor] = true;
                    stack.push_back(predecessor);
                }
            }
        }
        std::sort(component.begin(), component.end());
        bool cyclic = component.size() > 1;
        if (!cyclic && std::binary_search(graph.successors[component.front()].begin(),
                                           graph.successors[component.front()].end(),
                                           component.front())) {
            cyclic = true;
        }
        if (!cyclic)
            continue;
        std::vector<bool> member(graph.nodes.size(), false);
        for (const auto node : component)
            member[node] = true;
        reducibility_component_t fact;
        fact.cyclic = true;
        fact.quality = quality_from(fact_provenance_t::recursive_decode, 0);
        for (const auto node : component) {
            fact.block_ids.push_back(graph.nodes[node]);
            for (const auto predecessor : graph.predecessors[node]) {
                if (!member[predecessor]) {
                    fact.entry_block_ids.push_back(graph.nodes[node]);
                    break;
                }
            }
        }
        if (std::binary_search(component.begin(), component.end(), graph.entry) &&
            !std::binary_search(fact.entry_block_ids.begin(), fact.entry_block_ids.end(),
                                graph.nodes[graph.entry])) {
            fact.entry_block_ids.push_back(graph.nodes[graph.entry]);
        }
        std::sort(fact.entry_block_ids.begin(), fact.entry_block_ids.end());
        fact.entry_block_ids.erase(std::unique(fact.entry_block_ids.begin(), fact.entry_block_ids.end()),
                                   fact.entry_block_ids.end());
        fact.reducible = fact.entry_block_ids.size() <= 1;
        if (!fact.reducible)
            result.reducible = false;
        if (!writer.reserve())
            return workspace_result_t<void>::success();
        result.reducibility_components.push_back(std::move(fact));
    }
    return workspace_result_t<void>::success();
}

workspace_result_t<void> derive_switches(const analysis_snapshot_t& snapshot,
                                          const function_view_t& view,
                                          cfg_analysis_result_t& result,
                                          evidence_writer_t& writer,
                                          cfg_poller_t& poller) {
    for (const auto& block_view : view.blocks) {
        auto stopped = poller.poll("advanced_cfg.switches");
        if (!stopped)
            return stopped;
        const auto* instruction = block_view.terminal_instruction;
        if (!block_view.instructions_complete || instruction == nullptr ||
            (instruction->flow_flags & (flow_indirect | flow_branch)) !=
                (flow_indirect | flow_branch)) {
            continue;
        }
        recovered_switch_t recovered;
        recovered.dispatch_block_id = block_view.record->id;
        recovered.dispatch_rva = instruction->address.value;
        recovered.quality = quality_from(instruction->provenance, instruction->confidence);
        for (std::uint16_t operand = 0; operand < instruction->operand_fact_count; ++operand) {
            const auto fact_index = static_cast<std::size_t>(instruction->operand_fact_begin) + operand;
            const auto& fact = snapshot.operand_facts[fact_index];
            if (fact.kind != operand_kind_t::memory ||
                fact.address_expression != address_expression_kind_t::base_index_displacement ||
                !fact.has_resolved_expression_value) {
                continue;
            }
            recovered.table_rva = fact.resolved_expression_value;
            if (fact.access_width_bits == 8 || fact.access_width_bits == 16 ||
                fact.access_width_bits == 32 || fact.access_width_bits == 64) {
                recovered.entry_size = static_cast<std::uint8_t>(fact.access_width_bits / 8);
            }
            recovered.relative_entries = fact.relative ||
                fact.address_resolution == target_resolution_t::image_relative;
            break;
        }
        for (std::uint16_t target = 0; target < instruction->target_fact_count; ++target) {
            const auto fact_index = static_cast<std::size_t>(instruction->target_fact_begin) + target;
            const auto& fact = snapshot.target_facts[fact_index];
            if (fact.kind != target_kind_record_t::branch)
                continue;
            switch_case_t item;
            item.target_rva = fact.target.value;
            item.quality = recovered.quality;
            const auto block = view.block_index_by_address.find(fact.target);
            if (block != view.block_index_by_address.end()) {
                item.target_block_id = view.blocks[block->second].record->id;
            } else if (same_domain(fact.target, view.function->start) &&
                       view.function->start.value <= fact.target.value &&
                       fact.target.value < view.function->end.value && !view.blocks_truncated) {
                advanced_cfg_conflict_t conflict;
                conflict.kind = advanced_cfg_conflict_kind_t::switch_target_missing;
                conflict.rva = instruction->address.value;
                conflict.source_entity = block_view.record->id;
                conflict.existing_quality = recovered.quality;
                writer.conflict(std::move(conflict));
            }
            recovered.cases.push_back(std::move(item));
        }
        std::sort(recovered.cases.begin(), recovered.cases.end(), [](const switch_case_t& lhs,
                                                                      const switch_case_t& rhs) {
            if (lhs.target_rva != rhs.target_rva)
                return lhs.target_rva < rhs.target_rva;
            return lhs.target_block_id < rhs.target_block_id;
        });
        recovered.cases.erase(std::unique(recovered.cases.begin(), recovered.cases.end(),
            [](const switch_case_t& lhs, const switch_case_t& rhs) {
                return lhs.target_rva == rhs.target_rva && lhs.target_block_id == rhs.target_block_id;
            }), recovered.cases.end());
        for (const auto& edge : result.cfg_edges) {
            if (edge.source_block_id == block_view.record->id &&
                edge.kind == edge_kind_t::fallthrough && edge.target_block_id) {
                recovered.default_target_rva = edge.target.value;
                break;
            }
        }
        recovered.entry_count = recovered.cases.size();
        recovered.complete = recovered.table_rva.has_value() && recovered.entry_size != 0 &&
                             !recovered.cases.empty();
        if (!recovered.table_rva && recovered.cases.size() <= 1)
            continue;
        if (!writer.reserve())
            return workspace_result_t<void>::success();
        result.switches.push_back(std::move(recovered));
    }
    std::sort(result.switches.begin(), result.switches.end(), [](const recovered_switch_t& lhs,
                                                                  const recovered_switch_t& rhs) {
        if (lhs.dispatch_rva != rhs.dispatch_rva)
            return lhs.dispatch_rva < rhs.dispatch_rva;
        return lhs.dispatch_block_id < rhs.dispatch_block_id;
    });
    result.switches_found = result.switches.size();
    return workspace_result_t<void>::success();
}

bool callgraph_less(const callgraph_edge_t& lhs, const callgraph_edge_t& rhs) noexcept {
    if (lhs.call_site_rva != rhs.call_site_rva)
        return lhs.call_site_rva < rhs.call_site_rva;
    if (lhs.target_rva != rhs.target_rva)
        return lhs.target_rva < rhs.target_rva;
    if (lhs.source_block_id != rhs.source_block_id)
        return lhs.source_block_id < rhs.source_block_id;
    if (lhs.target_function_id.value_or(0) != rhs.target_function_id.value_or(0))
        return lhs.target_function_id.value_or(0) < rhs.target_function_id.value_or(0);
    if (lhs.is_tail_call != rhs.is_tail_call)
        return lhs.is_tail_call < rhs.is_tail_call;
    if (lhs.is_indirect != rhs.is_indirect)
        return lhs.is_indirect < rhs.is_indirect;
    return lhs.external_target < rhs.external_target;
}

bool same_callgraph_key(const callgraph_edge_t& lhs, const callgraph_edge_t& rhs) noexcept {
    return lhs.source_function_id == rhs.source_function_id &&
           lhs.source_block_id == rhs.source_block_id && lhs.target_function_id == rhs.target_function_id &&
           lhs.call_site_rva == rhs.call_site_rva && lhs.target_rva == rhs.target_rva &&
           lhs.is_tail_call == rhs.is_tail_call && lhs.is_indirect == rhs.is_indirect &&
           lhs.external_target == rhs.external_target;
}

workspace_result_t<void> derive_calls(const analysis_snapshot_t& snapshot,
                                      const function_view_t& view,
                                      const function_catalog_t& catalog,
                                      cfg_analysis_result_t& result,
                                      evidence_writer_t& writer,
                                      cfg_poller_t& poller) {
    const auto append_call = [&](callgraph_edge_t edge) {
        if (!writer.reserve())
            return false;
        result.callgraph_edges.push_back(std::move(edge));
        return true;
    };
    for (const auto& edge : result.cfg_edges) {
        auto stopped = poller.poll("advanced_cfg.callgraph_edges");
        if (!stopped)
            return stopped;
        if (edge.kind != edge_kind_t::call && edge.kind != edge_kind_t::tail_call)
            continue;
        callgraph_edge_t call;
        call.source_function_id = view.function->id;
        call.source_block_id = edge.source_block_id;
        call.target_function_id = edge.target_function_id;
        call.call_site_rva = edge.source.value;
        call.target_rva = edge.target.value;
        call.quality = edge.quality;
        call.is_tail_call = edge.kind == edge_kind_t::tail_call;
        call.is_indirect = edge.kind == edge_kind_t::indirect;
        call.external_target = edge.external_target;
        if (call.target_function_id) {
            const auto target = catalog.by_id.find(*call.target_function_id);
            call.target_noreturn = target != catalog.by_id.end() && target->second->noreturn;
        }
        if (!append_call(std::move(call)))
            break;
    }
    for (const auto& block_view : view.blocks) {
        auto stopped = poller.poll("advanced_cfg.callgraph_targets");
        if (!stopped)
            return stopped;
        const auto* instruction = block_view.terminal_instruction;
        if (!block_view.instructions_complete || instruction == nullptr)
            continue;
        const auto quality = quality_from(instruction->provenance, instruction->confidence);
        for (std::uint16_t index = 0; index < instruction->target_fact_count; ++index) {
            const auto fact_index = static_cast<std::size_t>(instruction->target_fact_begin) + index;
            const auto& target = snapshot.target_facts[fact_index];
            const auto* target_function = resolve_function(catalog, std::nullopt, target.target);
            const bool nonconditional_branch = (instruction->flow_flags & flow_branch) != 0 &&
                (instruction->flow_flags & (flow_conditional | flow_return)) == 0;
            const bool is_tail = target.kind == target_kind_record_t::branch && nonconditional_branch &&
                (!target_function || target_function->id != view.function->id);
            if (target.kind != target_kind_record_t::call && !is_tail)
                continue;
            callgraph_edge_t call;
            call.source_function_id = view.function->id;
            call.source_block_id = block_view.record->id;
            if (target_function)
                call.target_function_id = target_function->id;
            call.call_site_rva = instruction->address.value;
            call.target_rva = target.target.value;
            call.quality = quality;
            call.is_tail_call = is_tail;
            call.is_indirect = !target.direct;
            call.external_target = !target_function && target.target.value != 0;
            call.target_noreturn = target_function && target_function->noreturn;
            if (!append_call(std::move(call)))
                break;
        }
    }
    std::sort(result.callgraph_edges.begin(), result.callgraph_edges.end(), callgraph_less);
    std::vector<callgraph_edge_t> merged;
    merged.reserve(result.callgraph_edges.size());
    for (auto& edge : result.callgraph_edges) {
        if (!merged.empty() && same_callgraph_key(merged.back(), edge)) {
            merge_quality(merged.back().quality, edge.quality);
            merged.back().target_noreturn = merged.back().target_noreturn || edge.target_noreturn;
            continue;
        }
        merged.push_back(std::move(edge));
    }
    result.callgraph_edges = std::move(merged);
    result.callgraph_edges_found = result.callgraph_edges.size();
    return workspace_result_t<void>::success();
}

workspace_result_t<void> derive_tail_calls_and_noreturns(cfg_analysis_result_t& result,
                                                          evidence_writer_t& writer,
                                                          cfg_poller_t& poller) {
    std::unordered_map<entity_id_t, std::size_t> block_indices;
    for (std::size_t index = 0; index < result.basic_blocks.size(); ++index)
        block_indices.emplace(result.basic_blocks[index].id, index);
    for (const auto& call : result.callgraph_edges) {
        auto stopped = poller.poll("advanced_cfg.tail_calls");
        if (!stopped)
            return stopped;
        if (call.is_tail_call) {
            if (!writer.reserve())
                return workspace_result_t<void>::success();
            tail_call_info_t tail;
            tail.call_site_rva = call.call_site_rva;
            tail.target_rva = call.target_rva;
            tail.source_block_id = call.source_block_id;
            tail.target_function_id = call.target_function_id.value_or(0);
            tail.quality = call.quality;
            tail.is_direct = !call.is_indirect;
            tail.is_indirect = call.is_indirect;
            tail.external_target = call.external_target;
            result.tail_calls.push_back(std::move(tail));
        }
        if (!call.target_noreturn)
            continue;
        if (!writer.reserve())
            return workspace_result_t<void>::success();
        noreturn_effect_t effect;
        effect.source_block_id = call.source_block_id;
        effect.target_function_id = call.target_function_id.value_or(0);
        effect.call_site_rva = call.call_site_rva;
        effect.target_rva = call.target_rva;
        effect.quality = call.quality;
        effect.suppresses_fallthrough = std::any_of(result.cfg_edges.begin(), result.cfg_edges.end(),
            [&](const cfg_edge_fact_t& edge) {
                return edge.source_block_id == call.source_block_id &&
                       edge.kind == edge_kind_t::fallthrough;
            });
        result.noreturn_effects.push_back(std::move(effect));
        const auto block = block_indices.find(call.source_block_id);
        if (block != block_indices.end())
            result.basic_blocks[block->second].noreturn_terminator = true;
    }
    std::sort(result.tail_calls.begin(), result.tail_calls.end(), [](const tail_call_info_t& lhs,
                                                                      const tail_call_info_t& rhs) {
        if (lhs.call_site_rva != rhs.call_site_rva)
            return lhs.call_site_rva < rhs.call_site_rva;
        if (lhs.target_rva != rhs.target_rva)
            return lhs.target_rva < rhs.target_rva;
        return lhs.source_block_id < rhs.source_block_id;
    });
    result.tail_calls.erase(std::unique(result.tail_calls.begin(), result.tail_calls.end(),
        [](const tail_call_info_t& lhs, const tail_call_info_t& rhs) {
            return lhs.call_site_rva == rhs.call_site_rva && lhs.target_rva == rhs.target_rva &&
                   lhs.source_block_id == rhs.source_block_id &&
                   lhs.target_function_id == rhs.target_function_id;
        }), result.tail_calls.end());
    std::sort(result.noreturn_effects.begin(), result.noreturn_effects.end(),
        [](const noreturn_effect_t& lhs, const noreturn_effect_t& rhs) {
            if (lhs.call_site_rva != rhs.call_site_rva)
                return lhs.call_site_rva < rhs.call_site_rva;
            if (lhs.target_rva != rhs.target_rva)
                return lhs.target_rva < rhs.target_rva;
            return lhs.source_block_id < rhs.source_block_id;
        });
    result.noreturn_effects.erase(std::unique(result.noreturn_effects.begin(), result.noreturn_effects.end(),
        [](const noreturn_effect_t& lhs, const noreturn_effect_t& rhs) {
            return lhs.source_block_id == rhs.source_block_id && lhs.call_site_rva == rhs.call_site_rva &&
                   lhs.target_rva == rhs.target_rva && lhs.target_function_id == rhs.target_function_id;
        }), result.noreturn_effects.end());
    result.tail_calls_found = result.tail_calls.size();
    return workspace_result_t<void>::success();
}

workspace_result_t<void> derive_thunks(const function_view_t& view,
                                       const cfg_analysis_result_t& result,
                                       cfg_analysis_result_t& mutable_result,
                                       evidence_writer_t& writer,
                                       cfg_poller_t& poller) {
    auto stopped = poller.poll("advanced_cfg.thunks", true);
    if (!stopped)
        return stopped;
    const bool compact_shape = view.blocks.size() == 1 &&
        view.blocks.front().record->instruction_count <= 2 &&
        view.blocks.front().instructions_complete;
    if (!view.function->thunk && !compact_shape)
        return workspace_result_t<void>::success();
    const auto* terminal = view.blocks.front().terminal_instruction;
    if (terminal == nullptr || (terminal->flow_flags & (flow_branch | flow_call)) == 0)
        return workspace_result_t<void>::success();
    const auto transfer = std::find_if(result.callgraph_edges.begin(), result.callgraph_edges.end(),
        [&](const callgraph_edge_t& edge) { return edge.source_block_id == view.blocks.front().record->id; });
    if (transfer == result.callgraph_edges.end() && !view.function->thunk)
        return workspace_result_t<void>::success();
    if (!writer.reserve())
        return workspace_result_t<void>::success();
    thunk_info_t thunk;
    thunk.thunk_rva = view.function->start.value;
    thunk.thunk_size = view.function->end.value - view.function->start.value;
    thunk.quality = quality_from(view.function->provenance, view.function->confidence);
    merge_quality(thunk.quality, quality_from(terminal->provenance, terminal->confidence));
    thunk.inferred = !view.function->thunk;
    thunk.is_tail_call = (terminal->flow_flags & flow_branch) != 0 &&
                         (terminal->flow_flags & flow_conditional) == 0;
    thunk.is_import_thunk = (terminal->flow_flags & flow_indirect) != 0;
    if (transfer != result.callgraph_edges.end()) {
        thunk.target_rva = transfer->target_rva;
        thunk.target_function_id = transfer->target_function_id.value_or(0);
        merge_quality(thunk.quality, transfer->quality);
        thunk.is_tail_call = thunk.is_tail_call || transfer->is_tail_call;
        thunk.is_import_thunk = thunk.is_import_thunk || transfer->external_target;
    }
    mutable_result.thunks.push_back(std::move(thunk));
    mutable_result.thunks_found = mutable_result.thunks.size();
    return workspace_result_t<void>::success();
}

workspace_result_t<void> derive_exception_regions(const analysis_workspace_t& workspace,
                                                   const function_view_t& view,
                                                   cfg_analysis_result_t& result,
                                                   evidence_writer_t& writer,
                                                   cfg_poller_t& poller) {
    const auto image = workspace.image();
    if (image) {
        for (const auto& runtime : image->runtime_functions()) {
            auto stopped = poller.poll("advanced_cfg.exception_metadata");
            if (!stopped)
                return stopped;
            if (runtime.end_rva <= runtime.begin_rva || runtime.unwind_record_index >= image->unwind_records().size()) {
                return cfg_error(workspace_error_code_t::malformed_image,
                                 "runtime-function metadata is malformed", "advanced_cfg.exception_metadata");
            }
            if (view.function->start.value < runtime.begin_rva ||
                view.function->start.value >= runtime.end_rva)
                continue;
            const auto& unwind = image->unwind_records()[runtime.unwind_record_index];
            if (unwind.language_data_kind != pe_unwind_language_data_kind_t::c_specific_scope_table)
                continue;
            for (const auto& scope : unwind.language_scopes) {
                stopped = poller.poll("advanced_cfg.exception_scopes");
                if (!stopped)
                    return stopped;
                if (scope.end_rva <= scope.begin_rva) {
                    return cfg_error(workspace_error_code_t::malformed_image,
                                     "exception scope is malformed", "advanced_cfg.exception_scopes");
                }
                if (!writer.reserve())
                    return workspace_result_t<void>::success();
                exception_region_t region;
                region.try_start_rva = scope.begin_rva;
                region.try_end_rva = scope.end_rva;
                region.handler_rva = scope.handler_rva;
                region.jump_target_rva = scope.jump_target_rva;
                region.region_kind = exception_region_kind_t::c_specific_scope;
                region.quality = quality_from(fact_provenance_t::unwind_metadata,
                                              view.function->confidence);
                result.exception_regions.push_back(std::move(region));
            }
        }
    }
    for (const auto& edge : result.cfg_edges) {
        auto stopped = poller.poll("advanced_cfg.exception_edges");
        if (!stopped)
            return stopped;
        if (edge.kind != edge_kind_t::exception_edge)
            continue;
        const auto source = view.block_index_by_id.find(edge.source_block_id);
        if (source == view.block_index_by_id.end())
            continue;
        if (!writer.reserve())
            return workspace_result_t<void>::success();
        exception_region_t region;
        region.try_start_rva = view.blocks[source->second].record->start.value;
        region.try_end_rva = view.blocks[source->second].record->end.value;
        region.handler_rva = edge.target.value;
        region.region_kind = exception_region_kind_t::cfg_exception_edge;
        region.quality = edge.quality;
        result.exception_regions.push_back(std::move(region));
    }
    std::sort(result.exception_regions.begin(), result.exception_regions.end(),
        [](const exception_region_t& lhs, const exception_region_t& rhs) {
            if (lhs.try_start_rva != rhs.try_start_rva)
                return lhs.try_start_rva < rhs.try_start_rva;
            if (lhs.try_end_rva != rhs.try_end_rva)
                return lhs.try_end_rva < rhs.try_end_rva;
            if (lhs.handler_rva != rhs.handler_rva)
                return lhs.handler_rva < rhs.handler_rva;
            return lhs.region_kind < rhs.region_kind;
        });
    result.exception_regions.erase(std::unique(result.exception_regions.begin(), result.exception_regions.end(),
        [](const exception_region_t& lhs, const exception_region_t& rhs) {
            return lhs.try_start_rva == rhs.try_start_rva && lhs.try_end_rva == rhs.try_end_rva &&
                   lhs.handler_rva == rhs.handler_rva && lhs.jump_target_rva == rhs.jump_target_rva &&
                   lhs.region_kind == rhs.region_kind;
        }), result.exception_regions.end());
    return workspace_result_t<void>::success();
}

}

workspace_result_t<cfg_analysis_result_t>
    analyze_advanced_cfg(const analysis_workspace_t& workspace,
                         std::uint64_t function_rva,
                         const advanced_cfg_budget_t& budget,
                         const cancellation_token_t& cancel) {
    auto valid_budget = validate_budget(budget);
    if (!valid_budget)
        return workspace_result_t<cfg_analysis_result_t>::failure(valid_budget.error());
    cfg_poller_t poller(cancel);
    auto stopped = poller.poll("advanced_cfg.start", true);
    if (!stopped)
        return workspace_result_t<cfg_analysis_result_t>::failure(stopped.error());
    const auto snapshot = workspace.snapshot();
    if (!snapshot) {
        return workspace_result_t<cfg_analysis_result_t>::failure(make_workspace_error(
            workspace_error_code_t::target_not_found,
            "advanced CFG requires a published analysis snapshot", "advanced_cfg.start"));
    }
    if (!snapshot->baseline_complete) {
        return workspace_result_t<cfg_analysis_result_t>::failure(make_workspace_error(
            workspace_error_code_t::decode_failure,
            "advanced CFG requires a complete baseline snapshot", "advanced_cfg.start"));
    }
    if (snapshot->binary_id != workspace.identity().binary_id() ||
        snapshot->load_profile_hash != workspace.identity().load_profile_hash()) {
        return workspace_result_t<cfg_analysis_result_t>::failure(make_workspace_error(
            workspace_error_code_t::integrity_failure,
            "analysis snapshot identity does not match its workspace", "advanced_cfg.start"));
    }
    auto catalog = build_function_catalog(*snapshot, poller);
    if (!catalog)
        return workspace_result_t<cfg_analysis_result_t>::failure(catalog.error());
    auto view = extract_function_view(*snapshot, function_rva, budget, poller);
    if (!view)
        return workspace_result_t<cfg_analysis_result_t>::failure(view.error());

    cfg_analysis_result_t result;
    result.function_rva = function_rva;
    result.input_block_count = view.value().input_block_count;
    result.input_edge_count = view.value().input_edge_count;
    result.function_noreturn = view.value().function->noreturn;
    result.bounded = view.value().blocks_truncated || view.value().edges_truncated ||
                     view.value().instructions_truncated;
    result.key.binary_id = snapshot->binary_id;
    result.key.load_profile_hash = snapshot->load_profile_hash;
    result.key.function_address = view.value().function->start;
    result.key.architecture = view.value().function->start.architecture == architecture_id_t::unknown
        ? workspace.identity().architecture() : view.value().function->start.architecture;
    result.key.architecture_mode = view.value().function->start.mode == architecture_mode_t::unknown
        ? workspace.identity().architecture_mode() : view.value().function->start.mode;
    result.key.address_space = view.value().function->start.space;
    result.key.generation = snapshot->generation;
    result.key.analysis_revision = snapshot->analysis_revision;
    result.key.overlay_revision = snapshot->overlay_revision;
    evidence_writer_t writer{result, budget};
    if (result.bounded) {
        advanced_cfg_conflict_t conflict;
        conflict.kind = advanced_cfg_conflict_kind_t::truncated_input;
        conflict.rva = function_rva;
        writer.conflict(std::move(conflict));
    }
    for (const auto& block_view : view.value().blocks) {
        basic_block_fact_t block;
        block.id = block_view.record->id;
        block.function_id = block_view.record->function_id;
        block.start = block_view.record->start;
        block.end = block_view.record->end;
        block.instruction_count = block_view.record->instruction_count;
        block.quality = quality_from(block_view.record->provenance, block_view.record->confidence);
        const auto* terminal = block_view.terminal_instruction;
        block.terminal = terminal != nullptr &&
            (terminal->flow_flags & (flow_return | flow_terminal | flow_interrupt)) != 0;
        result.basic_blocks.push_back(std::move(block));
    }
    result.block_count = result.basic_blocks.size();

    auto built_edges = build_cfg_edges(*snapshot, view.value(), catalog.value(), budget, result, writer, poller);
    if (!built_edges)
        return workspace_result_t<cfg_analysis_result_t>::failure(built_edges.error());
    result.edge_count = result.cfg_edges.size();
    auto graph = build_graph(view.value(), result);
    if (graph.entry == no_index) {
        return workspace_result_t<cfg_analysis_result_t>::failure(make_workspace_error(
            workspace_error_code_t::decode_failure,
            "advanced CFG has no entry block", "advanced_cfg.graph"));
    }
    for (std::size_t index = 0; index < result.basic_blocks.size(); ++index)
        result.basic_blocks[index].terminal = result.basic_blocks[index].terminal ||
                                               graph.successors[index].empty();
    if (view.value().blocks[graph.entry].record->start != view.value().function->start) {
        advanced_cfg_conflict_t conflict;
        conflict.kind = advanced_cfg_conflict_kind_t::entry_block_missing;
        conflict.rva = function_rva;
        conflict.source_entity = graph.nodes[graph.entry];
        writer.conflict(std::move(conflict));
    }
    auto dominators = compute_dominators(graph, {graph.entry}, false,
                                         budget.max_dominator_iterations, poller);
    if (!dominators)
        return workspace_result_t<cfg_analysis_result_t>::failure(dominators.error());
    result.dominator_tree = dominators.take_value();
    for (std::size_t index = 0; index < result.basic_blocks.size(); ++index)
        result.basic_blocks[index].reachable = result.dominator_tree.reachable[index];
    if (!result.dominator_tree.complete) {
        result.bounded = true;
        advanced_cfg_conflict_t conflict;
        conflict.kind = advanced_cfg_conflict_kind_t::dominance_iteration_limit;
        conflict.rva = function_rva;
        writer.conflict(std::move(conflict));
    }
    std::vector<std::size_t> exits;
    for (std::size_t index = 0; index < graph.nodes.size(); ++index) {
        if (graph.successors[index].empty())
            exits.push_back(index);
    }
    auto post_dominators = compute_dominators(graph, std::move(exits), true,
                                              budget.max_dominator_iterations, poller);
    if (!post_dominators)
        return workspace_result_t<cfg_analysis_result_t>::failure(post_dominators.error());
    result.post_dominator_tree = post_dominators.take_value();
    if (!result.post_dominator_tree.complete) {
        advanced_cfg_conflict_t conflict;
        conflict.kind = advanced_cfg_conflict_kind_t::post_dominance_without_exit;
        conflict.rva = function_rva;
        writer.conflict(std::move(conflict));
    }
    auto loops = derive_loops(graph, result.dominator_tree, view.value().blocks, result, writer, poller);
    if (!loops)
        return workspace_result_t<cfg_analysis_result_t>::failure(loops.error());
    auto reducibility = derive_reducibility(graph, result, writer, poller);
    if (!reducibility)
        return workspace_result_t<cfg_analysis_result_t>::failure(reducibility.error());
    for (auto& loop : result.loops) {
        for (const auto& component : result.reducibility_components) {
            if (std::find(component.block_ids.begin(), component.block_ids.end(),
                          loop.header_block_id) != component.block_ids.end()) {
                loop.reducible = component.reducible;
                break;
            }
        }
    }
    auto switches = derive_switches(*snapshot, view.value(), result, writer, poller);
    if (!switches)
        return workspace_result_t<cfg_analysis_result_t>::failure(switches.error());
    auto calls = derive_calls(*snapshot, view.value(), catalog.value(), result, writer, poller);
    if (!calls)
        return workspace_result_t<cfg_analysis_result_t>::failure(calls.error());
    auto effects = derive_tail_calls_and_noreturns(result, writer, poller);
    if (!effects)
        return workspace_result_t<cfg_analysis_result_t>::failure(effects.error());
    auto thunks = derive_thunks(view.value(), result, result, writer, poller);
    if (!thunks)
        return workspace_result_t<cfg_analysis_result_t>::failure(thunks.error());
    auto exceptions = derive_exception_regions(workspace, view.value(), result, writer, poller);
    if (!exceptions)
        return workspace_result_t<cfg_analysis_result_t>::failure(exceptions.error());
    std::sort(result.conflicts.begin(), result.conflicts.end(), [](const advanced_cfg_conflict_t& lhs,
                                                                    const advanced_cfg_conflict_t& rhs) {
        if (lhs.kind != rhs.kind)
            return lhs.kind < rhs.kind;
        if (lhs.rva != rhs.rva)
            return lhs.rva < rhs.rva;
        if (lhs.source_entity != rhs.source_entity)
            return lhs.source_entity < rhs.source_entity;
        return lhs.target_entity < rhs.target_entity;
    });
    return workspace_result_t<cfg_analysis_result_t>::success(std::move(result));
}

workspace_result_t<cfg_analysis_result_t>
    analyze_advanced_cfg(const analysis_workspace_t& workspace,
                         std::uint64_t function_rva,
                         const cancellation_token_t& cancel) {
    return analyze_advanced_cfg(workspace, function_rva, advanced_cfg_budget_t{}, cancel);
}

}
