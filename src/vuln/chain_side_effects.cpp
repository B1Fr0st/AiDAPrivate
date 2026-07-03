#include "chain_side_effects.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>

namespace aida
{
namespace vuln
{
namespace chain
{

namespace
{

using nlohmann::json;

std::string lower_ascii(std::string s)
{
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool contains_any(const std::string& s, const std::vector<std::string>& needles)
{
    const std::string l = lower_ascii(s);
    for (const std::string& needle : needles)
    {
        if (l.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

bool operand_is_memory(const operand_fact_t& op)
{
    return op.type == "mem" || op.type == "displ" || op.type == "phrase";
}

bool operand_is_immediate(const operand_fact_t& op)
{
    return op.type == "imm";
}

value_expr_t value_from_operand(const operand_fact_t& op)
{
    value_expr_t out;
    out.kind = op.type.empty() ? "unknown" : op.type;
    out.text = op.text;
    out.width_bits = op.width_bits;
    out.location = op.address_identity;
    out.confidence = op.type == "unknown" || op.type.empty() ? "inconclusive" : "exact";
    if (operand_is_immediate(op))
    {
        out.concrete = true;
        out.concrete_value = op.value;
        out.value_origin = op.value == 0 ? "constant_zero" : "constant_nonzero";
    }
    else if (operand_is_memory(op))
    {
        out.value_origin = "copied_from_memory";
    }
    else if (op.type == "reg")
    {
        out.value_origin = "derived";
    }
    return out;
}

value_expr_t unknown_value(const address_identity_t& location, const std::string& text)
{
    value_expr_t out;
    out.location = location;
    out.text = text;
    return out;
}

side_effect_t make_effect(side_effect_kind_t kind,
                          const instruction_fact_t& ins,
                          const std::string& operation,
                          const std::string& reason)
{
    side_effect_t effect;
    effect.kind = kind;
    effect.location = ins.location;
    effect.operation = operation;
    effect.provenance = ins.disassembly;
    effect.reason = reason;
    return effect;
}

void append_read_write_effects(const instruction_fact_t& ins, std::vector<side_effect_t>& out)
{
    const std::string mnemonic = lower_ascii(ins.mnemonic);
    if (ins.operands.empty())
        return;
    const bool store_like = contains_any(mnemonic, {"mov", "stos", "xchg", "cmpxchg", "xadd", "add", "sub", "and", "or", "xor", "inc", "dec"});
    const bool load_like = contains_any(mnemonic, {"mov", "lea", "lods", "cmp", "test", "add", "sub", "and", "or", "xor"});
    if (store_like && operand_is_memory(ins.operands.front()))
    {
        side_effect_t effect = make_effect(side_effect_kind_t::write, ins, mnemonic, "memory_destination_operand");
        effect.destination = value_from_operand(ins.operands.front());
        if (ins.operands.size() > 1)
            effect.source = value_from_operand(ins.operands[1]);
        else
            effect.source = unknown_value(ins.location, ins.disassembly);
        if (contains_any(mnemonic, {"stos"}) && ins.operands.size() <= 1)
            effect.source.value_origin = "derived";
        out.push_back(std::move(effect));
    }
    for (std::size_t i = store_like ? 1 : 0; i < ins.operands.size(); ++i)
    {
        const operand_fact_t& op = ins.operands[i];
        if (!operand_is_memory(op))
            continue;
        if (!load_like && !ins.is_call && !ins.is_branch)
            continue;
        side_effect_t effect = make_effect(side_effect_kind_t::read, ins, mnemonic, "memory_source_operand");
        effect.source = value_from_operand(op);
        out.push_back(std::move(effect));
    }
}

side_effect_kind_t helper_kind(const std::string& name)
{
    if (contains_any(name, {"memset", "rtlzeromemory", "zeromemory", "bzero"}))
        return side_effect_kind_t::memory_set;
    if (contains_any(name, {"memcpy", "memmove", "rtlmove", "rtlcopymemory", "copy_memory", "copybytes"}))
        return side_effect_kind_t::memory_copy;
    if (contains_any(name, {"exallocate", "allocate", "malloc", "new", "heapalloc", "poolalloc"}))
        return side_effect_kind_t::allocation;
    if (contains_any(name, {"exfree", "free", "delete", "heapfree", "poolfree"}))
        return side_effect_kind_t::free_object;
    if (contains_any(name, {"interlocked", "cmpxchg", "xadd", "lock"}))
        return side_effect_kind_t::interlocked;
    if (contains_any(name, {"insertheadlist", "inserttaillist", "removeentrylist", "removelist", "list_entry"}))
        return side_effect_kind_t::list_operation;
    if (contains_any(name, {"obfreference", "obdereference", "reference", "dereference", "addref", "release"}))
        return side_effect_kind_t::refcount;
    if (contains_any(name, {"callback", "dispatch", "notify", "invoke", "callout"}))
        return side_effect_kind_t::callback_dispatch;
    if (contains_any(name, {"fastfail", "bugcheck", "failfast", "__report_gsfailure", "abort"}))
        return side_effect_kind_t::poisoned_terminal;
    return side_effect_kind_t::direct_call;
}

void append_call_effect(const call_fact_t& call, std::vector<side_effect_t>& out)
{
    side_effect_t effect;
    effect.kind = call.kind == "indirect" ? side_effect_kind_t::indirect_call : helper_kind(call.callee_name);
    effect.location = call.callsite;
    effect.operation = call.callee_name.empty() ? call.kind : call.callee_name;
    effect.provenance = call.callsite.symbol_name;
    effect.reason = call.resolved ? "resolved_call_target" : "unresolved_call_target";
    effect.unresolved = !call.resolved || call.kind == "indirect";
    effect.terminal = !call.does_return || effect.kind == side_effect_kind_t::poisoned_terminal;
    if (!call.arguments.empty())
        effect.destination = value_from_operand(call.arguments[0]);
    if (call.arguments.size() > 1)
        effect.source = value_from_operand(call.arguments[1]);
    if (call.arguments.size() > 2)
        effect.size = value_from_operand(call.arguments[2]);
    if (effect.kind == side_effect_kind_t::memory_set)
    {
        effect.source.value_origin = "constant_zero";
        if (call.arguments.size() > 1 && call.arguments[1].type == "imm" && call.arguments[1].value != 0)
            effect.source.value_origin = "constant_nonzero";
    }
    if (effect.kind == side_effect_kind_t::memory_copy)
        effect.source.value_origin = "copied_from_memory";
    if (effect.kind == side_effect_kind_t::indirect_call)
        effect.tags.push_back("indirect_target_required");
    out.push_back(std::move(effect));
}

void append_branch_effect(const branch_fact_t& branch, std::vector<side_effect_t>& out)
{
    side_effect_t effect;
    effect.kind = branch.kind == "return" ? side_effect_kind_t::return_value : side_effect_kind_t::branch;
    effect.location = branch.branch;
    effect.operation = branch.kind;
    effect.provenance = branch.predicate_text;
    effect.reason = branch.conditional ? "branch_predicate" : "control_transfer";
    if (branch.kind == "return")
        effect.terminal = true;
    out.push_back(std::move(effect));
}

void append_instruction_specials(const instruction_fact_t& ins, std::vector<side_effect_t>& out)
{
    const std::string m = lower_ascii(ins.mnemonic + " " + ins.disassembly);
    if (contains_any(m, {"lock", "xadd", "cmpxchg", "xchg"}))
    {
        side_effect_t effect = make_effect(side_effect_kind_t::interlocked, ins, ins.mnemonic, "atomic_instruction");
        if (!ins.operands.empty())
            effect.destination = value_from_operand(ins.operands.front());
        if (ins.operands.size() > 1)
            effect.source = value_from_operand(ins.operands[1]);
        out.push_back(std::move(effect));
    }
    if (contains_any(m, {"int 29h", "__fastfail", "ud2", "int 3"}))
    {
        side_effect_t effect = make_effect(side_effect_kind_t::poisoned_terminal, ins, ins.mnemonic, "poisoned_terminal_instruction");
        effect.terminal = true;
        out.push_back(std::move(effect));
    }
}

}

std::vector<side_effect_t> classify_side_effects(const function_snapshot_t& snapshot)
{
    std::vector<side_effect_t> out;
    std::set<std::string> seen;
    for (const instruction_fact_t& ins : snapshot.instructions)
    {
        const std::size_t before = out.size();
        append_read_write_effects(ins, out);
        append_instruction_specials(ins, out);
        for (std::size_t i = before; i < out.size(); ++i)
            out[i].source_layer = "raw";
    }
    for (const call_fact_t& call : snapshot.calls)
        append_call_effect(call, out);
    for (const branch_fact_t& branch : snapshot.branches)
        append_branch_effect(branch, out);
    std::vector<side_effect_t> deduped;
    deduped.reserve(out.size());
    for (auto& effect : out)
    {
        std::ostringstream key;
        key << static_cast<int>(effect.kind) << ':' << effect.location.ea << ':' << effect.operation << ':' << effect.destination.text << ':' << effect.source.text << ':' << effect.reason;
        if (!seen.insert(key.str()).second)
            continue;
        deduped.push_back(std::move(effect));
    }
    return deduped;
}

nlohmann::json to_json(side_effect_kind_t kind)
{
    switch (kind)
    {
    case side_effect_kind_t::read:              return "read";
    case side_effect_kind_t::write:             return "write";
    case side_effect_kind_t::interlocked:       return "interlocked";
    case side_effect_kind_t::memory_copy:       return "memory_copy";
    case side_effect_kind_t::memory_set:        return "memory_set";
    case side_effect_kind_t::allocation:        return "allocation";
    case side_effect_kind_t::free_object:       return "free";
    case side_effect_kind_t::refcount:          return "refcount";
    case side_effect_kind_t::list_operation:    return "list_operation";
    case side_effect_kind_t::callback_dispatch: return "callback_dispatch";
    case side_effect_kind_t::direct_call:       return "direct_call";
    case side_effect_kind_t::indirect_call:     return "indirect_call";
    case side_effect_kind_t::branch:            return "branch";
    case side_effect_kind_t::return_value:      return "return";
    case side_effect_kind_t::poisoned_terminal: return "poisoned_terminal";
    case side_effect_kind_t::unknown:           return "unknown";
    }
    return "unknown";
}

nlohmann::json to_json(const value_expr_t& value)
{
    return json{{"kind", value.kind},
                {"text", value.text},
                {"value_origin", value.value_origin},
                {"width_bits", value.width_bits},
                {"location", to_json(value.location)},
                {"concrete", value.concrete},
                {"concrete_value", value.concrete ? std::to_string(value.concrete_value) : std::string()},
                {"confidence", value.confidence}};
}

nlohmann::json to_json(const side_effect_t& effect)
{
    return json{{"kind", to_json(effect.kind)},
                {"location", to_json(effect.location)},
                {"destination", to_json(effect.destination)},
                {"source", to_json(effect.source)},
                {"size", to_json(effect.size)},
                {"operation", effect.operation},
                {"source_layer", effect.source_layer},
                {"provenance", effect.provenance},
                {"reason", effect.reason},
                {"terminal", effect.terminal},
                {"unresolved", effect.unresolved},
                {"tags", effect.tags}};
}

}
}
}
