#pragma once

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace mcp_standalone::ida_compat
{
    using json = nlohmann::json;

    inline const std::vector<std::string>& read_only_tool_names()
    {
        static const std::vector<std::string> names = {
            "lookup_funcs", "int_convert", "list_funcs", "list_globals",
            "imports", "decompile", "disasm", "xrefs_to", "xrefs_to_field",
            "callees", "get_bytes", "get_int", "get_string", "get_global_value",
            "stack_frame", "read_struct", "search_structs", "find_regex",
            "find_bytes", "find_insns", "find", "basic_blocks",
            "export_funcs", "callgraph", "list_instances", "calculator", "calculate"
        };
        return names;
    }

    inline const std::vector<std::string>& mutation_tool_names()
    {
        static const std::vector<std::string> names = {
            "add_bookmark", "set_comments", "patch_asm", "declare_type",
            "define_func", "define_code", "undefine", "declare_stack",
            "delete_stack", "set_type", "infer_types", "analyze_funcs",
            "rename", "patch", "put_int"
        };
        return names;
    }

    inline const std::vector<std::string>& target_dependent_tool_names()
    {
        static const std::vector<std::string> names = {
            "lookup_funcs", "list_funcs", "list_globals", "imports", "decompile",
            "disasm", "xrefs_to", "xrefs_to_field", "callees", "get_bytes",
            "get_int", "get_string", "get_global_value", "stack_frame", "read_struct",
            "search_structs", "find_regex", "find_bytes", "find_insns", "find",
            "basic_blocks", "export_funcs", "callgraph", "add_bookmark", "set_comments",
            "patch_asm", "declare_type", "define_func", "define_code", "undefine",
            "declare_stack", "delete_stack", "set_type", "infer_types", "analyze_funcs",
            "rename", "patch", "put_int"
        };
        return names;
    }

    inline bool is_read_only_tool(const std::string& tool_name)
    {
        const auto& names = read_only_tool_names();
        return std::find(names.begin(), names.end(), tool_name) != names.end();
    }

    inline bool is_mutation_tool(const std::string& tool_name)
    {
        const auto& names = mutation_tool_names();
        return std::find(names.begin(), names.end(), tool_name) != names.end();
    }

    inline bool is_target_dependent_tool(const std::string& tool_name)
    {
        const auto& names = target_dependent_tool_names();
        return std::find(names.begin(), names.end(), tool_name) != names.end();
    }

    inline json scalar_or_array_schema(json scalar_schema, std::size_t max_items)
    {
        json array_schema = {
            {"type", "array"},
            {"items", scalar_schema},
            {"maxItems", max_items}
        };
        return {
            {"oneOf", json::array({
                std::move(scalar_schema),
                std::move(array_schema)
            })}
        };
    }

    inline const json& get_all_schemas()
    {
        static const json schemas = []() {
            json s;

            s["lookup_funcs"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "names": {"type": "array", "items": {"type": "string"}, "maxItems": 1000},
                    "addresses": {"type": "array", "items": {"type": "string"}, "maxItems": 1000},
                    "name": {"type": "string"},
                    "address": {"type": "string"}
                },
                "additionalProperties": false
            })");

            s["int_convert"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                    "from_format": {"type": "string", "enum": ["hex", "decimal", "octal", "binary", "ascii"]},
                    "to_format": {"type": "string", "enum": ["hex", "decimal", "octal", "binary", "ascii"]},
                    "size": {"type": "integer", "minimum": 1, "maximum": 8},
                    "signed": {"type": "boolean"}
                },
                "required": ["value"],
                "additionalProperties": false
            })");

            s["list_funcs"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
                    "filter": {"type": "string"}
                },
                "additionalProperties": false
            })");

            s["list_globals"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
                    "filter": {"type": "string"}
                },
                "additionalProperties": false
            })");

            s["imports"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "module": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000}
                },
                "additionalProperties": false
            })");

            s["decompile"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "use_cache": {"type": "boolean", "default": true}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["disasm"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "max_instructions": {"type": "integer", "minimum": 1, "maximum": 50000, "default": 100},
                    "start_line": {"type": "integer", "minimum": 0, "default": 0},
                    "end_line": {"type": "integer", "minimum": 0}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["xrefs_to"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    "kind": {"type": "string", "enum": ["all", "code", "call", "read", "write", "address", "relocation"]}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["xrefs_to_field"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "struct_name": {"type": "string"},
                    "field_name": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "required": ["struct_name", "field_name"],
                "additionalProperties": false
            })");

            s["callees"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "include_indirect": {"type": "boolean", "default": false}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["get_bytes"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 65536},
                    "hex": {"type": "boolean", "default": true}
                },
                "required": ["address", "size"],
                "additionalProperties": false
            })");

            s["get_int"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 8, "default": 4},
                    "signed": {"type": "boolean", "default": false},
                    "endian": {"type": "string", "enum": ["little", "big"], "default": "little"}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["get_string"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "max_length": {"type": "integer", "minimum": 1, "maximum": 65536, "default": 4096},
                    "encoding": {"type": "string", "enum": ["auto", "ascii", "utf8", "utf16_le"], "default": "auto"}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["get_global_value"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 8, "default": 8},
                    "as_type": {"type": "string", "enum": ["int", "uint", "hex", "bytes", "ascii", "ptr"], "default": "hex"}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["stack_frame"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "include_saved_regs": {"type": "boolean", "default": true}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["read_struct"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "struct_name": {"type": "string"},
                    "max_depth": {"type": "integer", "minimum": 0, "maximum": 16, "default": 4},
                    "fields": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 256,
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "minLength": 1, "maxLength": 256},
                                "offset": {"oneOf": [{"type": "string"}, {"type": "integer", "minimum": 0}]},
                                "type": {"type": "string", "minLength": 1, "maxLength": 64},
                                "size": {"oneOf": [{"type": "string"}, {"type": "integer", "minimum": 1, "maximum": 1048576}]}
                            },
                            "required": ["name", "offset", "type"],
                            "additionalProperties": false
                        }
                    },
                    "size": {"oneOf": [{"type": "string"}, {"type": "integer", "minimum": 1, "maximum": 1048576}]},
                    "target": {"type": "string", "enum": ["auto", "guest", "host"]},
                    "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 300000}
                },
                "required": ["address"],
                "oneOf": [
                    {"required": ["struct_name"], "not": {"required": ["fields"]}},
                    {"required": ["fields"], "not": {"required": ["struct_name"]}}
                ],
                "additionalProperties": false
            })");

            s["search_structs"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "additionalProperties": false
            })");

            s["find_regex"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "scope": {"type": "string", "enum": ["all", "functions", "strings", "symbols", "code"], "default": "all"},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100}
                },
                "required": ["pattern"],
                "additionalProperties": false
            })");

            s["find_bytes"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "hex_pattern": {"type": "string"},
                    "mask": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100}
                },
                "required": ["hex_pattern"],
                "additionalProperties": false
            })");

            s["find_insns"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "mnemonic": {"type": "string"},
                    "operand_pattern": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100}
                },
                "required": ["mnemonic"],
                "additionalProperties": false
            })");

            s["find"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "kind": {"type": "string", "enum": ["all", "function", "symbol", "string", "instruction", "data"], "default": "all"},
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100}
                },
                "required": ["query"],
                "additionalProperties": false
            })");

            s["basic_blocks"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "include_instructions": {"type": "boolean", "default": false}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["export_funcs"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "minimum": 0, "default": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 1000},
                    "filter": {"type": "string"}
                },
                "additionalProperties": false
            })");

            s["callgraph"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "depth": {"type": "integer", "minimum": 0, "maximum": 10, "default": 1},
                    "direction": {"type": "string", "enum": ["callers", "callees", "both"], "default": "both"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 500}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["add_bookmark"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "name": {"type": "string", "maxLength": 4096},
                    "comment": {"type": "string", "maxLength": 65536}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["set_comments"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "maxItems": 4096,
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {"type": "string"},
                                "comment": {"type": "string", "maxLength": 65536}
                            },
                            "required": ["address", "comment"],
                            "additionalProperties": false
                        }
                    },
                    "address": {"type": "string"},
                    "comment": {"type": "string", "maxLength": 65536}
                },
                "additionalProperties": false
            })");

            s["patch_asm"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "assembly": {"type": "string", "maxLength": 65536},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "assembly"],
                "additionalProperties": false
            })");

            s["declare_type"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "maxLength": 4096},
                    "definition": {"type": "string", "maxLength": 65536},
                    "is_struct": {"type": "boolean", "default": true},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["name", "definition"],
                "additionalProperties": false
            })");

            s["define_func"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "end": {"type": "string"},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["define_code"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 16777216},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "size"],
                "additionalProperties": false
            })");

            s["undefine"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 16777216},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "size"],
                "additionalProperties": false
            })");

            s["declare_stack"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "items": {
                        "type": "array",
                        "maxItems": 4096,
                        "items": {
                            "type": "object",
                            "properties": {
                                "offset": {"type": "integer"},
                                "name": {"type": "string", "maxLength": 4096},
                                "type": {"type": "string", "maxLength": 65536},
                                "size": {"type": "integer", "minimum": 1}
                            },
                            "required": ["offset", "name", "type"],
                            "additionalProperties": false
                        }
                    },
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["delete_stack"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "offsets": {
                        "type": "array",
                        "maxItems": 4096,
                        "items": {"type": "integer"}
                    },
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "offsets"],
                "additionalProperties": false
            })");

            s["set_type"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "type": {"type": "string", "maxLength": 65536},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "type"],
                "additionalProperties": false
            })");

            s["infer_types"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "items": {
                        "type": "array",
                        "maxItems": 4096,
                        "items": {"type": "string"}
                    },
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "additionalProperties": false
            })");

            s["analyze_funcs"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "maxItems": 4096,
                        "items": {"type": "string"}
                    },
                    "address": {"type": "string"},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "additionalProperties": false
            })");

            s["rename"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "name": {"type": "string", "maxLength": 4096},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "name"],
                "additionalProperties": false
            })");

            s["patch"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "bytes": {"type": "string", "maxLength": 1048576},
                    "hex_string": {"type": "string", "maxLength": 2097152},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address"],
                "additionalProperties": false
            })");

            s["put_int"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "address": {"type": "string"},
                    "value": {"type": "string"},
                    "size": {"type": "integer", "minimum": 1, "maximum": 8, "default": 4},
                    "endian": {"type": "string", "enum": ["little", "big"], "default": "little"},
                    "dry_run": {"type": "boolean", "default": false},
                    "expected_revision": {"type": "integer", "minimum": 0},
                    "idempotency_key": {"type": "string", "maxLength": 256}
                },
                "required": ["address", "value"],
                "additionalProperties": false
            })");

            s["calculate"] = json::parse(R"({
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "expression": {"type": "string", "maxLength": 4096},
                    "bits": {
                        "oneOf": [
                            {"type": "integer", "minimum": 1, "maximum": 65536},
                            {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                        ]
                    },
                    "width": {
                        "oneOf": [
                            {"type": "integer", "minimum": 1, "maximum": 65536},
                            {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                        ]
                    },
                    "signed": {
                        "oneOf": [
                            {"type": "boolean"},
                            {"type": "string", "pattern": "^(?:[sS][iI][gG][nN][eE][dD]|[uU][nN][sS][iI][gG][nN][eE][dD])$"}
                        ]
                    },
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 128,
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "expression": {"type": "string", "maxLength": 4096},
                                "bits": {
                                    "oneOf": [
                                        {"type": "integer", "minimum": 1, "maximum": 65536},
                                        {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                    ]
                                },
                                "width": {
                                    "oneOf": [
                                        {"type": "integer", "minimum": 1, "maximum": 65536},
                                        {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                    ]
                                },
                                "signed": {
                                    "oneOf": [
                                        {"type": "boolean"},
                                        {"type": "string", "pattern": "^(?:[sS][iI][gG][nN][eE][dD]|[uU][nN][sS][iI][gG][nN][eE][dD])$"}
                                    ]
                                },
                                "format": {"type": "string", "enum": ["decimal", "hex", "octal", "oct", "binary", "bin", "all"], "default": "hex"}
                            },
                            "required": ["expression"],
                            "additionalProperties": false
                        }
                    },
                    "variables": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "format": {"type": "string", "enum": ["decimal", "hex", "octal", "oct", "binary", "bin", "all"], "default": "hex"},
                    "mapping": {
                        "type": "object",
                        "properties": {
                            "image_base": {
                                "oneOf": [
                                    {"type": "integer", "minimum": 0},
                                    {"type": "string", "minLength": 1, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                ]
                            },
                            "sections": {
                                "type": "array",
                                "maxItems": 1024,
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "va_start": {
                                            "oneOf": [
                                                {"type": "integer", "minimum": 0},
                                                {"type": "string", "minLength": 1, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                            ]
                                        },
                                        "rva_start": {
                                            "oneOf": [
                                                {"type": "integer", "minimum": 0},
                                                {"type": "string", "minLength": 1, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                            ]
                                        },
                                        "virtual_size": {
                                            "oneOf": [
                                                {"type": "integer", "minimum": 0},
                                                {"type": "string", "minLength": 1, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                            ]
                                        },
                                        "raw_offset": {
                                            "oneOf": [
                                                {"type": "integer", "minimum": 0},
                                                {"type": "string", "minLength": 1, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                            ]
                                        },
                                        "raw_size": {
                                            "oneOf": [
                                                {"type": "integer", "minimum": 0},
                                                {"type": "string", "minLength": 1, "pattern": "^\\+?(?:[0-9](?:_?[0-9])*|0[xX][0-9A-Fa-f](?:_?[0-9A-Fa-f])*|0[oO][0-7](?:_?[0-7])*|0[bB][01](?:_?[01])*)$"}
                                            ]
                                        }
                                    },
                                    "required": ["virtual_size", "raw_offset", "raw_size"],
                                    "anyOf": [
                                        {"required": ["rva_start"]},
                                        {"required": ["va_start"]}
                                    ],
                                    "additionalProperties": false
                                }
                            }
                        },
                        "additionalProperties": false
                    }
                },
                "anyOf": [
                    {"required": ["expression"]},
                    {"required": ["items"]}
                ],
                "additionalProperties": false
            })");

            s["calculator"] = s["calculate"];

            s["list_instances"] = json::parse(R"({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            })");

            const json calculator_integer_value = {
                {"oneOf", json::array({
                    json{{"type", "integer"}},
                    json{{"type", "string"}, {"minLength", 1}, {"maxLength", 65536}}
                })}
            };
            const json calculator_variable_value = {
                {"oneOf", json::array({
                    json{{"type", "integer"}},
                    json{{"type", "string"}, {"minLength", 1}, {"maxLength", 65536}},
                    json{
                        {"type", "object"},
                        {"properties", {
                            {"integer", calculator_integer_value},
                            {"bytes", json{{"type", "string"}, {"maxLength", 2097152}}},
                            {"ascii", json{{"type", "string"}, {"maxLength", 1048576}}},
                            {"utf8", json{{"type", "string"}, {"maxLength", 1048576}}}
                        }},
                        {"anyOf", json::array({
                            json{{"required", json::array({"integer"})}},
                            json{{"required", json::array({"bytes"})}},
                            json{{"required", json::array({"ascii"})}},
                            json{{"required", json::array({"utf8"})}}
                        })},
                        {"additionalProperties", false}
                    }
                })}
            };
            const json calculator_variables = {
                {"type", "object"},
                {"propertyNames", json{{"pattern", "^[A-Za-z_][A-Za-z0-9_]*$"}}},
                {"additionalProperties", calculator_variable_value}
            };
            const json calculator_mapping = s["calculate"]["properties"]["mapping"];
            s["calculate"]["properties"]["variables"] = calculator_variables;
            s["calculate"]["properties"]["items"]["items"]["properties"]["variables"] =
                calculator_variables;
            s["calculate"]["properties"]["items"]["items"]["properties"]["mapping"] =
                calculator_mapping;

            const json selector_bin_name = {
                {"type", "string"},
                {"minLength", 1},
                {"maxLength", 32768}
            };
            const json selector_pid = {
                {"type", "integer"},
                {"minimum", 1},
                {"maximum", 4294967295ULL}
            };
            const json aida_tx = {
                {"oneOf", json::array({
                    json{{"type", "string"}, {"minLength", 1}, {"maxLength", 256}},
                    json{
                        {"type", "object"},
                        {"properties", {
                            {"id", json{{"type", "string"}, {"minLength", 1}, {"maxLength", 256}}},
                            {"transaction_id", json{{"type", "string"}, {"minLength", 1}, {"maxLength", 256}}},
                            {"expected_revision", json{{"type", "integer"}, {"minimum", 0}}},
                            {"idempotency_key", json{{"type", "string"}, {"minLength", 1}, {"maxLength", 256}}},
                            {"dry_run", json{{"type", "boolean"}}}
                        }},
                        {"additionalProperties", false}
                    }
                })}
            };

            for (const auto& tool_name : target_dependent_tool_names()) {
                auto& properties = s.at(tool_name).at("properties");
                properties["bin_name"] = selector_bin_name;
                properties["pid"] = selector_pid;
            }

            for (const auto& tool_name : mutation_tool_names())
                s.at(tool_name).at("properties")["aida_tx"] = aida_tx;

            s["lookup_funcs"]["properties"]["names"] = scalar_or_array_schema(
                s["lookup_funcs"]["properties"]["names"]["items"], 1000);
            s["lookup_funcs"]["properties"]["addresses"] = scalar_or_array_schema(
                s["lookup_funcs"]["properties"]["addresses"]["items"], 1000);
            s["set_comments"]["properties"]["items"] = scalar_or_array_schema(
                s["set_comments"]["properties"]["items"]["items"], 4096);
            s["declare_stack"]["properties"]["items"] = scalar_or_array_schema(
                s["declare_stack"]["properties"]["items"]["items"], 4096);
            s["delete_stack"]["properties"]["offsets"] = scalar_or_array_schema(
                json{{"type", "integer"}}, 4096);
            s["infer_types"]["properties"]["items"] = scalar_or_array_schema(
                s["infer_types"]["properties"]["items"]["items"], 4096);
            s["analyze_funcs"]["properties"]["items"] = scalar_or_array_schema(
                s["analyze_funcs"]["properties"]["items"]["items"], 4096);
            s["calculate"]["properties"]["items"] = scalar_or_array_schema(
                s["calculate"]["properties"]["items"]["items"], 128);
            s["calculator"] = s["calculate"];

            return s;
        }();
        return schemas;
    }

    inline const json* find_schema(const std::string& tool_name)
    {
        const auto& s = get_all_schemas();
        auto it = s.find(tool_name);
        if (it == s.end())
            return nullptr;
        return &(*it);
    }

    inline std::vector<std::string> get_read_only_tool_names()
    {
        return read_only_tool_names();
    }

    inline std::vector<std::string> get_mutation_tool_names()
    {
        return mutation_tool_names();
    }

    inline json tool_metadata(const std::string& tool_name)
    {
        return {
            {"read_only", is_read_only_tool(tool_name)},
            {"mutating", is_mutation_tool(tool_name)},
            {"target_dependent", is_target_dependent_tool(tool_name)}
        };
    }
}
