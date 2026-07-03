#include "chain_path_trace.hpp"

#include <algorithm>
#include <chrono>
#include <deque>
#include <map>
#include <set>
#include <unordered_map>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

using nlohmann::json;

std::uint64_t now_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

layer_status_t status_for(const std::string& layer,
                          layer_state_t state,
                          const std::string& reason,
                          std::uint64_t start,
                          std::size_t emitted,
                          std::size_t total)
{
    layer_status_t s;
    s.layer = layer;
    s.state = state;
    s.reason = reason;
    s.elapsed_ms = now_ms() - start;
    s.emitted = emitted;
    s.total = total;
    return s;
}

bool block_contains(const basic_block_fact_t& block, std::uint64_t ea)
{
    if (block.start.ea == 0 || block.end.ea == 0)
        return false;
    return ea >= block.start.ea && ea < block.end.ea;
}

std::size_t find_block_for_ea(const function_snapshot_t& snapshot, std::uint64_t ea)
{
    for (const auto& block : snapshot.basic_blocks)
    {
        if (block_contains(block, ea))
            return block.id;
        if (std::find(block.instruction_eas.begin(), block.instruction_eas.end(), ea) != block.instruction_eas.end())
            return block.id;
    }
    return static_cast<std::size_t>(-1);
}

std::unordered_map<std::uint64_t, const instruction_fact_t*> instruction_index(const function_snapshot_t& snapshot)
{
    std::unordered_map<std::uint64_t, const instruction_fact_t*> out;
    for (const auto& ins : snapshot.instructions)
        out.emplace(ins.location.ea, &ins);
    return out;
}

std::unordered_map<std::uint64_t, std::vector<extracted_side_effect_t>> effects_by_ea(const function_snapshot_t& snapshot)
{
    std::unordered_map<std::uint64_t, std::vector<extracted_side_effect_t>> out;
    for (auto& effect : classify_side_effects(snapshot))
        out[effect.location.ea].push_back(std::move(effect));
    return out;
}

std::vector<const call_fact_t*> calls_at(const function_snapshot_t& snapshot, std::uint64_t ea)
{
    std::vector<const call_fact_t*> out;
    for (const auto& call : snapshot.calls)
    {
        if (call.callsite.ea == ea)
            out.push_back(&call);
    }
    return out;
}

std::vector<const branch_fact_t*> branches_at(const function_snapshot_t& snapshot, std::uint64_t ea)
{
    std::vector<const branch_fact_t*> out;
    for (const auto& branch : snapshot.branches)
    {
        if (branch.branch.ea == ea)
            out.push_back(&branch);
    }
    return out;
}

std::vector<std::size_t> bfs_blocks(const function_snapshot_t& snapshot,
                                    std::size_t entry_block,
                                    std::size_t target_block,
                                    const path_trace_options_t& options,
                                    bool& cutoff)
{
    cutoff = false;
    std::unordered_map<std::size_t, const basic_block_fact_t*> blocks;
    for (const auto& block : snapshot.basic_blocks)
        blocks.emplace(block.id, &block);
    std::deque<std::size_t> q;
    std::set<std::size_t> seen;
    std::unordered_map<std::size_t, std::size_t> parent;
    q.push_back(entry_block);
    seen.insert(entry_block);
    while (!q.empty())
    {
        if (seen.size() > options.max_blocks)
        {
            cutoff = true;
            break;
        }
        std::size_t cur = q.front();
        q.pop_front();
        if (cur == target_block)
            break;
        auto it = blocks.find(cur);
        if (it == blocks.end())
            continue;
        for (std::size_t succ : it->second->successors)
        {
            if (!seen.insert(succ).second)
                continue;
            parent.emplace(succ, cur);
            q.push_back(succ);
        }
    }
    if (seen.find(target_block) == seen.end())
        return {};
    std::vector<std::size_t> path;
    for (std::size_t cur = target_block;; cur = parent[cur])
    {
        path.push_back(cur);
        if (cur == entry_block)
            break;
    }
    std::reverse(path.begin(), path.end());
    return path;
}

std::string step_kind_for(const instruction_fact_t& ins)
{
    if (ins.is_return)
        return "return";
    if (ins.is_call)
        return ins.is_indirect ? "indirect_call" : "call";
    if (ins.is_branch)
        return ins.is_conditional ? "conditional_branch" : "branch";
    return "instruction";
}

void append_unresolved_for_instruction(const instruction_fact_t& ins,
                                       path_trace_t& trace,
                                       const path_trace_options_t& options)
{
    if (trace.unresolved_edges.size() >= options.max_unresolved_edges)
        return;
    if (!ins.is_indirect)
        return;
    unresolved_edge_t edge;
    edge.location = ins.location;
    edge.kind = ins.is_call ? "indirect_call" : "indirect_branch";
    edge.reason = "target_not_state_proven";
    edge.evidence = ins.disassembly;
    trace.unresolved_edges.push_back(std::move(edge));
}

void append_branch_blocker(const branch_fact_t& branch,
                           std::uint64_t chosen_start,
                           path_trace_t& trace)
{
    if (!branch.conditional)
        return;
    branch_blocker_t blocker;
    blocker.branch = branch.branch;
    blocker.predicate_text = branch.predicate_text;
    blocker.required_edge = chosen_start == 0 ? "unknown_successor" : std::to_string(chosen_start);
    blocker.reason = "conditional_branch_requires_path_direction";
    for (const auto& target : branch.targets)
    {
        if (target.ea != chosen_start)
            blocker.alternatives.push_back(target);
    }
    trace.branch_blockers.push_back(std::move(blocker));
}

}

path_trace_t trace_path_corridor(const function_snapshot_t& snapshot,
                                 std::uint64_t entry_ea,
                                 std::uint64_t target_ea,
                                 const path_trace_options_t& options)
{
    path_trace_t trace;
    const std::uint64_t start = now_ms();
    trace.entry = snapshot.identity.start;
    trace.target = snapshot.identity.start;
    for (const auto& ins : snapshot.instructions)
    {
        if (ins.location.ea == entry_ea)
            trace.entry = ins.location;
        if (ins.location.ea == target_ea)
            trace.target = ins.location;
    }
    const std::size_t entry_block = find_block_for_ea(snapshot, entry_ea);
    const std::size_t target_block = find_block_for_ea(snapshot, target_ea);
    if (entry_block == static_cast<std::size_t>(-1) || target_block == static_cast<std::size_t>(-1))
    {
        trace.reason = "entry_or_target_not_in_function";
        trace.statuses.push_back(status_for("path_corridor", layer_state_t::failed, trace.reason, start, 0, snapshot.basic_blocks.size()));
        return trace;
    }
    bool cutoff = false;
    trace.block_path = bfs_blocks(snapshot, entry_block, target_block, options, cutoff);
    if (trace.block_path.empty())
    {
        trace.reached = false;
        trace.complete = !cutoff;
        trace.reason = cutoff ? "reachable_set_incomplete" : "path_target_unreachable";
        trace.statuses.push_back(status_for("path_corridor",
                                            cutoff ? layer_state_t::truncated : layer_state_t::ok,
                                            trace.reason,
                                            start,
                                            0,
                                            snapshot.basic_blocks.size()));
        return trace;
    }
    const auto insn_index = instruction_index(snapshot);
    auto effect_index = effects_by_ea(snapshot);
    std::map<std::size_t, const basic_block_fact_t*> block_index;
    for (const auto& block : snapshot.basic_blocks)
        block_index.emplace(block.id, &block);
    std::uint64_t next_block_start = 0;
    for (std::size_t path_i = 0; path_i < trace.block_path.size(); ++path_i)
    {
        std::size_t block_id = trace.block_path[path_i];
        auto block_it = block_index.find(block_id);
        if (block_it == block_index.end() || block_it->second == nullptr)
            continue;
        const basic_block_fact_t* block = block_it->second;
        if (path_i + 1 < trace.block_path.size())
        {
            auto next_it = block_index.find(trace.block_path[path_i + 1]);
            next_block_start = next_it != block_index.end() ? next_it->second->start.ea : 0;
        }
        else
        {
            next_block_start = 0;
        }
        for (std::uint64_t ea : block->instruction_eas)
        {
            if (trace.steps.size() >= options.max_steps)
            {
                trace.reason = "step_limit_reached";
                trace.statuses.push_back(status_for("path_corridor", layer_state_t::truncated, trace.reason, start, trace.steps.size(), snapshot.instructions.size()));
                trace.complete = false;
                return trace;
            }
            if (block_id == entry_block && ea < entry_ea)
                continue;
            auto ins_it = insn_index.find(ea);
            if (ins_it == insn_index.end())
                continue;
            const instruction_fact_t& ins = *ins_it->second;
            path_step_t step;
            step.index = trace.steps.size();
            step.block_id = block_id;
            step.location = ins.location;
            step.kind = step_kind_for(ins);
            step.text = ins.disassembly;
            step.before_target = ea <= target_ea;
            step.terminal = ins.is_return || ins.is_noreturn;
            for (const call_fact_t* call : calls_at(snapshot, ea))
                step.calls.push_back(*call);
            for (const branch_fact_t* branch : branches_at(snapshot, ea))
            {
                step.branches.push_back(*branch);
                append_branch_blocker(*branch, next_block_start, trace);
            }
            auto eff_it = effect_index.find(ea);
            if (eff_it != effect_index.end())
                step.side_effects = eff_it->second;
            append_unresolved_for_instruction(ins, trace, options);
            trace.steps.push_back(std::move(step));
            if (ea == target_ea)
            {
                trace.reached = true;
                trace.complete = trace.unresolved_edges.empty();
                trace.reason = trace.complete ? "target_reached" : "target_reached_with_unresolved_edges";
                trace.statuses.push_back(status_for("path_corridor",
                                                    trace.complete ? layer_state_t::ok : layer_state_t::truncated,
                                                    trace.reason,
                                                    start,
                                                    trace.steps.size(),
                                                    snapshot.instructions.size()));
                return trace;
            }
        }
    }
    trace.reached = false;
    trace.complete = false;
    trace.reason = "target_not_emitted_in_path";
    trace.statuses.push_back(status_for("path_corridor", layer_state_t::failed, trace.reason, start, trace.steps.size(), snapshot.instructions.size()));
    return trace;
}

nlohmann::json to_json(const path_step_t& step)
{
    json branches = json::array();
    for (const auto& branch : step.branches)
        branches.push_back(to_json(branch));
    json calls = json::array();
    for (const auto& call : step.calls)
        calls.push_back(to_json(call));
    json effects = json::array();
    for (const auto& effect : step.side_effects)
        effects.push_back(to_json(effect));
    return json{{"index", step.index},
                {"block_id", step.block_id},
                {"location", to_json(step.location)},
                {"kind", step.kind},
                {"text", step.text},
                {"branches", std::move(branches)},
                {"calls", std::move(calls)},
                {"side_effects", std::move(effects)},
                {"before_target", step.before_target},
                {"terminal", step.terminal}};
}

nlohmann::json to_json(const unresolved_edge_t& edge)
{
    return json{{"location", to_json(edge.location)},
                {"kind", edge.kind},
                {"reason", edge.reason},
                {"evidence", edge.evidence}};
}

nlohmann::json to_json(const branch_blocker_t& blocker)
{
    json alternatives = json::array();
    for (const auto& alt : blocker.alternatives)
        alternatives.push_back(to_json(alt));
    return json{{"branch", to_json(blocker.branch)},
                {"predicate_text", blocker.predicate_text},
                {"alternatives", std::move(alternatives)},
                {"required_edge", blocker.required_edge},
                {"reason", blocker.reason}};
}

nlohmann::json to_json(const path_trace_t& trace)
{
    json steps = json::array();
    for (const auto& step : trace.steps)
        steps.push_back(to_json(step));
    json unresolved = json::array();
    for (const auto& edge : trace.unresolved_edges)
        unresolved.push_back(to_json(edge));
    json blockers = json::array();
    for (const auto& blocker : trace.branch_blockers)
        blockers.push_back(to_json(blocker));
    json statuses = json::array();
    for (const auto& status : trace.statuses)
        statuses.push_back(to_json(status));
    return json{{"entry", to_json(trace.entry)},
                {"target", to_json(trace.target)},
                {"reached", trace.reached},
                {"complete", trace.complete},
                {"reason", trace.reason},
                {"block_path", trace.block_path},
                {"steps", std::move(steps)},
                {"unresolved_edges", std::move(unresolved)},
                {"branch_blockers", std::move(blockers)},
                {"statuses", std::move(statuses)}};
}

}
}
}
