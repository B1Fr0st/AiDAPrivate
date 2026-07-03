#include "chain_trigger_trace.hpp"

#include <algorithm>
#include <chrono>

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

std::string lower_ascii(std::string s)
{
    for (char& c : s)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    }
    return s;
}

bool contains_ci(const std::string& haystack, const std::string& needle)
{
    if (needle.empty())
        return false;
    return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
}

layer_status_t make_status(const std::string& reason, std::uint64_t start, std::size_t emitted, std::size_t total, layer_state_t state)
{
    layer_status_t status;
    status.layer = "trigger_trace";
    status.state = state;
    status.reason = reason;
    status.elapsed_ms = now_ms() - start;
    status.emitted = emitted;
    status.total = total;
    return status;
}

address_identity_t target_identity(const function_snapshot_t& snapshot, std::uint64_t target_ea)
{
    for (const auto& ins : snapshot.instructions)
    {
        if (ins.location.ea == target_ea)
            return ins.location;
    }
    return snapshot.identity.start;
}

std::vector<std::uint64_t> candidates_for_root(const function_snapshot_t& snapshot, const trigger_root_t& root)
{
    std::vector<std::uint64_t> out;
    if (root.ea != 0)
    {
        out.push_back(root.ea);
        return out;
    }
    if (root.kind == "lifecycle" || root.kind == "entry")
        out.push_back(snapshot.identity.start.ea);
    for (const auto& call : snapshot.calls)
    {
        if (contains_ci(call.callee_name, root.name) || contains_ci(call.callsite.symbol_name, root.name))
            out.push_back(call.callsite.ea);
    }
    for (const auto& ins : snapshot.instructions)
    {
        if (contains_ci(ins.disassembly, root.name) || contains_ci(ins.location.symbol_name, root.name))
            out.push_back(ins.location.ea);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

trigger_attempt_t attempt_from_candidate(const function_snapshot_t& snapshot,
                                         const trigger_root_t& root,
                                         std::uint64_t candidate,
                                         std::uint64_t target_ea,
                                         const path_trace_options_t& options)
{
    trigger_attempt_t attempt;
    attempt.root = root;
    attempt.root_resolved = false;
    for (const auto& ins : snapshot.instructions)
    {
        if (ins.location.ea == candidate)
        {
            attempt.resolved_entry = ins.location;
            attempt.root_resolved = true;
            break;
        }
    }
    if (!attempt.root_resolved && candidate == snapshot.identity.start.ea)
    {
        attempt.resolved_entry = snapshot.identity.start;
        attempt.root_resolved = true;
    }
    if (!attempt.root_resolved)
    {
        attempt.reason = "root_candidate_not_in_snapshot";
        return attempt;
    }
    attempt.path = trace_path_corridor(snapshot, candidate, target_ea, options);
    attempt.target_reached = attempt.path.reached;
    attempt.reason = attempt.path.reason;
    return attempt;
}

}

trigger_trace_t trace_trigger_to_target(const function_snapshot_t& snapshot,
                                        const std::vector<trigger_root_t>& roots,
                                        std::uint64_t target_ea,
                                        const path_trace_options_t& options)
{
    const std::uint64_t start = now_ms();
    trigger_trace_t trace;
    trace.target = target_identity(snapshot, target_ea);
    if (roots.empty())
    {
        trace.reason = "no_trigger_roots";
        trace.statuses.push_back(make_status(trace.reason, start, 0, 0, layer_state_t::failed));
        return trace;
    }
    for (const trigger_root_t& root : roots)
    {
        std::vector<std::uint64_t> candidates = candidates_for_root(snapshot, root);
        if (candidates.empty())
        {
            trigger_attempt_t attempt;
            attempt.root = root;
            attempt.reason = "root_unresolved";
            trace.attempts.push_back(std::move(attempt));
            unresolved_edge_t edge;
            edge.location = snapshot.identity.start;
            edge.kind = root.kind;
            edge.reason = "trigger_root_unresolved";
            edge.evidence = root.name.empty() ? root.evidence : root.name;
            trace.unresolved_edges.push_back(std::move(edge));
            continue;
        }
        for (std::uint64_t candidate : candidates)
        {
            trigger_attempt_t attempt = attempt_from_candidate(snapshot, root, candidate, target_ea, options);
            if (attempt.path.reached)
            {
                trace.reached = true;
                trace.complete = attempt.path.complete;
                trace.reason = attempt.path.reason;
                trace.unresolved_edges.insert(trace.unresolved_edges.end(), attempt.path.unresolved_edges.begin(), attempt.path.unresolved_edges.end());
                trace.branch_blockers.insert(trace.branch_blockers.end(), attempt.path.branch_blockers.begin(), attempt.path.branch_blockers.end());
                trace.attempts.push_back(std::move(attempt));
                trace.statuses.push_back(make_status(trace.reason,
                                                     start,
                                                     trace.attempts.size(),
                                                     roots.size(),
                                                     trace.complete ? layer_state_t::ok : layer_state_t::truncated));
                return trace;
            }
            trace.unresolved_edges.insert(trace.unresolved_edges.end(), attempt.path.unresolved_edges.begin(), attempt.path.unresolved_edges.end());
            trace.branch_blockers.insert(trace.branch_blockers.end(), attempt.path.branch_blockers.begin(), attempt.path.branch_blockers.end());
            trace.attempts.push_back(std::move(attempt));
        }
    }
    trace.reached = false;
    trace.complete = trace.unresolved_edges.empty();
    trace.reason = trace.complete ? "trigger_path_not_reached" : "trigger_path_incomplete";
    trace.statuses.push_back(make_status(trace.reason,
                                         start,
                                         trace.attempts.size(),
                                         roots.size(),
                                         trace.complete ? layer_state_t::ok : layer_state_t::truncated));
    return trace;
}

nlohmann::json to_json(const trigger_root_t& root)
{
    return json{{"kind", root.kind},
                {"ea", root.ea == 0 ? std::string() : std::to_string(root.ea)},
                {"name", root.name},
                {"evidence", root.evidence}};
}

nlohmann::json to_json(const trigger_attempt_t& attempt)
{
    return json{{"root", to_json(attempt.root)},
                {"resolved_entry", to_json(attempt.resolved_entry)},
                {"root_resolved", attempt.root_resolved},
                {"target_reached", attempt.target_reached},
                {"reason", attempt.reason},
                {"path", to_json(attempt.path)}};
}

nlohmann::json to_json(const trigger_trace_t& trace)
{
    json attempts = json::array();
    for (const auto& attempt : trace.attempts)
        attempts.push_back(to_json(attempt));
    json unresolved = json::array();
    for (const auto& edge : trace.unresolved_edges)
        unresolved.push_back(to_json(edge));
    json blockers = json::array();
    for (const auto& blocker : trace.branch_blockers)
        blockers.push_back(to_json(blocker));
    json statuses = json::array();
    for (const auto& status : trace.statuses)
        statuses.push_back(to_json(status));
    return json{{"target", to_json(trace.target)},
                {"reached", trace.reached},
                {"complete", trace.complete},
                {"reason", trace.reason},
                {"attempts", std::move(attempts)},
                {"unresolved_edges", std::move(unresolved)},
                {"branch_blockers", std::move(blockers)},
                {"statuses", std::move(statuses)}};
}

}
}
}
