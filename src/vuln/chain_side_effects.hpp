#pragma once

#include "chain_extraction.hpp"

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace aida
{
namespace vuln
{
namespace chain
{

enum class extracted_side_effect_kind_t
{
    read,
    write,
    interlocked,
    memory_copy,
    memory_set,
    allocation,
    free_object,
    refcount,
    list_operation,
    callback_dispatch,
    direct_call,
    indirect_call,
    branch,
    return_value,
    poisoned_terminal,
    unknown
};

struct value_expr_t
{
    std::string kind = "unknown";
    std::string text;
    std::string value_origin = "unknown";
    std::string address_expr;
    std::string alias_class;
    std::string type_ref;
    std::uint32_t width_bits = 0;
    std::uint64_t provenance_ea = 0;
    address_identity_t location;
    bool concrete = false;
    std::uint64_t concrete_value = 0;
    std::string confidence = "inconclusive";
    bool controlled_by_input = false;
};

struct extracted_side_effect_t
{
    extracted_side_effect_kind_t kind = extracted_side_effect_kind_t::unknown;
    address_identity_t location;
    value_expr_t destination;
    value_expr_t source;
    value_expr_t size;
    std::string operation;
    std::string source_layer = "raw";
    std::string provenance;
    std::string reason;
    bool terminal = false;
    bool unresolved = false;
    std::vector<std::string> tags;
};

std::vector<extracted_side_effect_t> classify_side_effects(const function_snapshot_t& snapshot);

nlohmann::json to_json(extracted_side_effect_kind_t kind);
nlohmann::json to_json(const value_expr_t& value);
nlohmann::json to_json(const extracted_side_effect_t& effect);

}
}
}
